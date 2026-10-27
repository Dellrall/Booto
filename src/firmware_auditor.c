/**
 * @file firmware_auditor.c
 * @brief Read-only host firmware audit: Secure Boot keys (efivars), PKfail, dbx, DMA protection.
 *
 * Everything here is hostile-input parsing of data owned by firmware. Files are only ever
 * opened O_RDONLY; nothing is written to efivars, ACPI or sysfs.
 */
#include "firmware_auditor.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define EFI_GLOBAL_GUID         "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_IMAGE_SECURITY_GUID "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define READ_CAP                (1024u * 1024u)
#define EFIVAR_ATTR_SIZE        4u
#define SIGLIST_HDR_SIZE        28u
#define SIG_OWNER_SIZE          16u
#define DMAR_FLAGS_OFFSET       37u
#define DMAR_PLATFORM_OPT_IN    0x04u

/* GUIDs as stored on disk: first three fields little-endian. */
static const uint8_t GUID_CERT_SHA256[16] = {
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28
};
static const uint8_t GUID_CERT_X509[16] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

static const char *const TEST_KEY_MARKERS[] = { "DO NOT TRUST", "DO NOT SHIP" };

static const char *const CHECK_NAMES[FW_CHECK_COUNT] = {
    "Secure Boot on",
    "Setup mode off",
    "Platform key",
    "No test keys (PKfail)",
    "Revocation list (dbx)",
    "IOMMU described (DMAR/IVRS)",
    "Thunderbolt DMA protection",
};

typedef struct {
    int sha256_count;
    int x509_count;
    const char *test_marker;    /* first marker found in any X.509 entry, or NULL */
    char first_cn[128];         /* CN of the first X.509 entry, if cheaply found */
} siglist_stats_t;

typedef struct {
    int err;                    /* 0 or errno */
    uint8_t *buf;               /* whole file, attributes included */
    size_t len;
} efivar_t;

static void set_check(fw_check_t *c, fw_result_t r, const char *detail) {
    c->result = r;
    snprintf(c->detail, sizeof(c->detail), "%s", detail);
}

static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Reads a whole file sequentially (efivarfs cannot seek). Returns 0 or an errno. */
static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;

    size_t size = 0, alloc = 4096;
    uint8_t *buf = malloc(alloc);
    int err = buf ? 0 : ENOMEM;
    while (!err) {
        if (size == alloc) {
            if (alloc >= READ_CAP) { err = EFBIG; break; }
            uint8_t *nb = realloc(buf, alloc * 2);
            if (!nb) { err = ENOMEM; break; }
            buf = nb;
            alloc *= 2;
        }
        ssize_t n = read(fd, buf + size, alloc - size);
        if (n < 0) {
            if (errno != EINTR) err = errno;
            continue;
        }
        if (n == 0) break;
        size += (size_t)n;
    }
    close(fd);
    if (err) {
        free(buf);
        return err;
    }
    *out = buf;
    *out_len = size;
    return 0;
}

static efivar_t read_efivar(const char *dir, const char *name, const char *guid) {
    efivar_t v = { 0, NULL, 0 };
    char path[4096];
    int w = snprintf(path, sizeof(path), "%s/%s-%s", dir, name, guid);
    if (w < 0 || (size_t)w >= sizeof(path)) {
        v.err = ENAMETOOLONG;
        return v;
    }
    v.err = read_file(path, &v.buf, &v.len);
    if (!v.err && v.len < EFIVAR_ATTR_SIZE) {
        free(v.buf);
        v.buf = NULL;
        v.len = 0;
        v.err = EIO;
    }
    return v;
}

static const uint8_t *efivar_data(const efivar_t *v) { return v->buf + EFIVAR_ATTR_SIZE; }
static size_t efivar_data_len(const efivar_t *v) { return v->len - EFIVAR_ATTR_SIZE; }

/* First commonName (OID 2.5.4.3) followed by a short-form string; good enough for display. */
static void extract_cn(const uint8_t *d, size_t len, char *out, size_t out_size) {
    static const uint8_t cn_oid[3] = { 0x55, 0x04, 0x03 };
    for (size_t i = 0; len >= 5 && i <= len - 5; i++) {
        if (memcmp(d + i, cn_oid, sizeof(cn_oid)) != 0) continue;
        uint8_t tag = d[i + 3];
        size_t n = d[i + 4];
        bool string_tag = tag == 0x0c || tag == 0x13 || tag == 0x14 || tag == 0x16;
        if (!string_tag || n == 0 || n >= 128 || n > len - i - 5) return;
        if (n >= out_size) n = out_size - 1;
        for (size_t k = 0; k < n; k++) {
            uint8_t ch = d[i + 5 + k];
            out[k] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
        }
        out[n] = '\0';
        return;
    }
}

/*
 * Walks a buffer of EFI_SIGNATURE_LIST entries. Returns false on the first malformed list;
 * stats then cover only the lists parsed before it. Never reads outside [d, d + len).
 */
static bool parse_siglists(const uint8_t *d, size_t len, siglist_stats_t *st) {
    size_t off = 0;
    while (off < len) {
        if (len - off < SIGLIST_HDR_SIZE) return false;
        const uint8_t *list = d + off;
        uint32_t list_size = rd_le32(list + 16);
        uint32_t hdr_size = rd_le32(list + 20);
        uint32_t sig_size = rd_le32(list + 24);
        if (list_size < SIGLIST_HDR_SIZE || list_size > len - off) return false;
        if (hdr_size > list_size - SIGLIST_HDR_SIZE) return false;
        size_t body = list_size - SIGLIST_HDR_SIZE - hdr_size;
        if (sig_size <= SIG_OWNER_SIZE || body % sig_size != 0) return false;

        bool is_sha256 = memcmp(list, GUID_CERT_SHA256, 16) == 0;
        bool is_x509 = memcmp(list, GUID_CERT_X509, 16) == 0;
        const uint8_t *sig = list + SIGLIST_HDR_SIZE + hdr_size;
        for (size_t k = 0; k < body / sig_size; k++, sig += sig_size) {
            if (is_sha256) {
                st->sha256_count++;
            } else if (is_x509) {
                const uint8_t *cert = sig + SIG_OWNER_SIZE;
                size_t cert_len = sig_size - SIG_OWNER_SIZE;
                if (st->x509_count == 0) extract_cn(cert, cert_len, st->first_cn, sizeof(st->first_cn));
                st->x509_count++;
                for (size_t m = 0; !st->test_marker && m < sizeof(TEST_KEY_MARKERS) / sizeof(TEST_KEY_MARKERS[0]); m++) {
                    if (memmem(cert, cert_len, TEST_KEY_MARKERS[m], strlen(TEST_KEY_MARKERS[m])))
                        st->test_marker = TEST_KEY_MARKERS[m];
                }
            }
        }
        off += list_size;
    }
    return true;
}

/* SecureBoot / SetupMode: one byte, good value passes, its opposite fails. */
static void check_flag_var(fw_check_t *c, const char *dir, const char *name, uint8_t good,
                           const char *pass_msg, const char *fail_msg) {
    efivar_t v = read_efivar(dir, name, EFI_GLOBAL_GUID);
    if (v.err) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "Could not read %s: %s.", name, strerror(v.err));
    } else if (efivar_data_len(&v) < 1) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "%s is empty.", name);
    } else if (efivar_data(&v)[0] == good) {
        set_check(c, FW_RESULT_PASS, pass_msg);
    } else if (efivar_data(&v)[0] == (good ? 0 : 1)) {
        set_check(c, FW_RESULT_FAIL, fail_msg);
    } else {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "%s has unexpected value %u.", name,
                 (unsigned)efivar_data(&v)[0]);
    }
    free(v.buf);
}

static void check_platform_key(fw_check_t *c, const efivar_t *pk) {
    if (pk->err == ENOENT) {
        set_check(c, FW_RESULT_FAIL, "No platform key enrolled.");
        return;
    }
    if (pk->err) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "Could not read PK: %s.", strerror(pk->err));
        return;
    }
    siglist_stats_t st;
    memset(&st, 0, sizeof(st));
    if (!parse_siglists(efivar_data(pk), efivar_data_len(pk), &st)) {
        set_check(c, FW_RESULT_FAIL, "Platform key list is malformed.");
    } else if (st.x509_count == 0) {
        set_check(c, FW_RESULT_FAIL, "No platform key enrolled.");
    } else if (st.first_cn[0]) {
        c->result = FW_RESULT_PASS;
        snprintf(c->detail, sizeof(c->detail), "Enrolled: \"%s\".", st.first_cn);
    } else {
        c->result = FW_RESULT_PASS;
        snprintf(c->detail, sizeof(c->detail), "%d certificate%s.", st.x509_count,
                 st.x509_count == 1 ? "" : "s");
    }
}

static void check_test_keys(fw_check_t *c, const efivar_t *const vars[], const char *const names[], size_t n) {
    size_t unreadable = 0;
    for (size_t i = 0; i < n; i++) {
        if (vars[i]->err == ENOENT) continue;
        if (vars[i]->err) {
            unreadable++;
            continue;
        }
        siglist_stats_t st;
        memset(&st, 0, sizeof(st));
        (void)parse_siglists(efivar_data(vars[i]), efivar_data_len(vars[i]), &st);
        if (st.test_marker) {
            c->result = FW_RESULT_FAIL;
            snprintf(c->detail, sizeof(c->detail),
                     "%s contains a test key (\"%s\"): the private key is public (PKfail).",
                     names[i], st.test_marker);
            return;
        }
    }
    if (unreadable == n)
        set_check(c, FW_RESULT_UNKNOWN, "Could not read PK, KEK or db.");
    else if (unreadable)
        set_check(c, FW_RESULT_PASS, "No test keys in the readable key databases.");
    else
        set_check(c, FW_RESULT_PASS, "No test keys in PK, KEK or db.");
}

static void check_dbx(fw_check_t *c, const efivar_t *dbx) {
    static const char empty_msg[] = "The revocation list is empty: known-vulnerable bootloaders can still boot.";
    if (dbx->err == ENOENT) {
        set_check(c, FW_RESULT_FAIL, empty_msg);
        return;
    }
    if (dbx->err) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "Could not read dbx: %s.", strerror(dbx->err));
        return;
    }
    siglist_stats_t st;
    memset(&st, 0, sizeof(st));
    if (!parse_siglists(efivar_data(dbx), efivar_data_len(dbx), &st)) {
        set_check(c, FW_RESULT_FAIL, "Revocation list is malformed.");
    } else if (st.sha256_count == 0) {
        set_check(c, FW_RESULT_FAIL, empty_msg);
    } else {
        c->result = FW_RESULT_PASS;
        snprintf(c->detail, sizeof(c->detail), "%d revoked hashes.", st.sha256_count);
    }
}

static void check_iommu(fw_check_t *c, const char *acpi_dir) {
    static const char *const tables[2] = { "DMAR", "IVRS" };
    static const char *const labels[2] = { "Intel VT-d (DMAR)", "AMD-Vi (IVRS)" };
    int errs[2];
    for (size_t i = 0; i < 2; i++) {
        char path[4096];
        int w = snprintf(path, sizeof(path), "%s/%s", acpi_dir, tables[i]);
        if (w < 0 || (size_t)w >= sizeof(path)) {
            errs[i] = ENAMETOOLONG;
            continue;
        }
        uint8_t *buf;
        size_t len;
        errs[i] = read_file(path, &buf, &len);
        if (errs[i]) continue;
        c->result = FW_RESULT_PASS;
        if (i == 0 && len > DMAR_FLAGS_OFFSET)
            snprintf(c->detail, sizeof(c->detail), "%s; platform DMA opt-in flag is %s.", labels[i],
                     (buf[DMAR_FLAGS_OFFSET] & DMAR_PLATFORM_OPT_IN) ? "set" : "not set");
        else
            snprintf(c->detail, sizeof(c->detail), "%s.", labels[i]);
        free(buf);
        return;
    }
    if (errs[0] == ENOENT && errs[1] == ENOENT) {
        set_check(c, FW_RESULT_FAIL, "Firmware describes no IOMMU: DMA attacks are not blocked.");
        return;
    }
    int e = errs[0] != ENOENT ? errs[0] : errs[1];
    if (e == EACCES || e == EPERM) {
        set_check(c, FW_RESULT_UNKNOWN, "Needs root to read ACPI tables.");
    } else {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "Could not read ACPI tables: %s.", strerror(e));
    }
}

static bool is_domain_entry(const char *name) {
    if (strncmp(name, "domain", 6) != 0 || name[6] == '\0') return false;
    for (const char *p = name + 6; *p; p++)
        if (*p < '0' || *p > '9') return false;
    return true;
}

static void check_thunderbolt(fw_check_t *c, const char *tb_dir) {
    DIR *d = opendir(tb_dir);
    if (!d) {
        if (errno == ENOENT || errno == ENOTDIR) {
            set_check(c, FW_RESULT_NA, "No Thunderbolt controller.");
        } else {
            c->result = FW_RESULT_UNKNOWN;
            snprintf(c->detail, sizeof(c->detail), "Could not list Thunderbolt devices: %s.", strerror(errno));
        }
        return;
    }
    int domains = 0, off = 0, unreadable = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!is_domain_entry(de->d_name)) continue;
        domains++;
        char path[4096];
        int w = snprintf(path, sizeof(path), "%s/%s/iommu_dma_protection", tb_dir, de->d_name);
        uint8_t *buf = NULL;
        size_t len = 0;
        if (w < 0 || (size_t)w >= sizeof(path) || read_file(path, &buf, &len) != 0 || len == 0)
            unreadable++;
        else if (buf[0] == '0')
            off++;
        else if (buf[0] != '1')
            unreadable++;
        free(buf);
    }
    closedir(d);

    /* Every domain must be protected; one unprotected controller is enough for a DMA attack. */
    if (domains == 0)
        set_check(c, FW_RESULT_NA, "No Thunderbolt controller.");
    else if (off)
        set_check(c, FW_RESULT_FAIL, "Thunderbolt DMA protection is off.");
    else if (unreadable)
        set_check(c, FW_RESULT_UNKNOWN, "Could not read Thunderbolt DMA protection state.");
    else
        set_check(c, FW_RESULT_PASS, "Thunderbolt DMA protection is on.");
}

booto_error_t firmware_audit(const firmware_paths_t *paths, firmware_report_t *out) {
    if (!out) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    const char *efi = (paths && paths->efivars_dir) ? paths->efivars_dir : "/sys/firmware/efi/efivars";
    const char *acpi = (paths && paths->acpi_tables_dir) ? paths->acpi_tables_dir : "/sys/firmware/acpi/tables";
    const char *tb = (paths && paths->thunderbolt_dir) ? paths->thunderbolt_dir : "/sys/bus/thunderbolt/devices";

    struct stat sb;
    out->uefi_boot = stat(efi, &sb) == 0 && S_ISDIR(sb.st_mode);
    fw_check_t *ck = out->checks;
    if (!out->uefi_boot) {
        for (int i = FW_CHECK_SECURE_BOOT; i <= FW_CHECK_DBX; i++)
            set_check(&ck[i], FW_RESULT_NA, "Booted in BIOS mode: no UEFI variables.");
    } else {
        check_flag_var(&ck[FW_CHECK_SECURE_BOOT], efi, "SecureBoot", 1, "Secure Boot is enabled.",
                       "Secure Boot is off: unsigned bootloaders can run.");
        check_flag_var(&ck[FW_CHECK_SETUP_MODE], efi, "SetupMode", 0, "Setup mode is off: key changes need the platform key.",
                       "Setup mode is on: any software can enrol its own keys.");

        efivar_t pk = read_efivar(efi, "PK", EFI_GLOBAL_GUID);
        efivar_t kek = read_efivar(efi, "KEK", EFI_GLOBAL_GUID);
        efivar_t db = read_efivar(efi, "db", EFI_IMAGE_SECURITY_GUID);
        efivar_t dbx = read_efivar(efi, "dbx", EFI_IMAGE_SECURITY_GUID);
        const efivar_t *const key_vars[3] = { &pk, &kek, &db };
        static const char *const key_names[3] = { "PK", "KEK", "db" };

        check_platform_key(&ck[FW_CHECK_PLATFORM_KEY], &pk);
        check_test_keys(&ck[FW_CHECK_TEST_KEYS], key_vars, key_names, 3);
        check_dbx(&ck[FW_CHECK_DBX], &dbx);

        free(pk.buf);
        free(kek.buf);
        free(db.buf);
        free(dbx.buf);
    }
    check_iommu(&ck[FW_CHECK_IOMMU], acpi);
    check_thunderbolt(&ck[FW_CHECK_THUNDERBOLT_DMA], tb);

    for (int i = 0; i < FW_CHECK_COUNT; i++) {
        if (ck[i].result == FW_RESULT_FAIL) out->fail_count++;
        else if (ck[i].result == FW_RESULT_UNKNOWN) out->unknown_count++;
    }
    return BOOTO_OK;
}

const char *firmware_check_name(fw_check_id_t id) {
    return (size_t)id < FW_CHECK_COUNT ? CHECK_NAMES[id] : "?";
}

const char *firmware_result_str(fw_result_t r) {
    switch (r) {
    case FW_RESULT_PASS: return "pass";
    case FW_RESULT_FAIL: return "fail";
    case FW_RESULT_UNKNOWN: return "unknown";
    case FW_RESULT_NA: return "n/a";
    }
    return "?";
}
