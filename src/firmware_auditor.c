/**
 * @file firmware_auditor.c
 * @brief Read-only host firmware audit: Secure Boot keys (efivars), PKfail, dbx, DMA protection,
 *        silicon locks (MSRs via /dev/cpu/N/msr, PCI config space via sysfs).
 *
 * Everything here is hostile-input parsing of data owned by firmware. Files are only ever
 * opened O_RDONLY; nothing is written to efivars, ACPI, sysfs, PCI config space or MSRs.
 * Register layouts come from the Intel SDM, Intel PCH datasheets and AMD PPRs.
 */
#include "firmware_auditor.h"
#include "crypto_utils.h"
#include "disk_mount.h"

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
#define SHIM_LOCK_GUID          "605dab50-e046-4300-abb6-3dd810dd8b23"
#define READ_CAP                (1024u * 1024u)
#define EFIVAR_ATTR_SIZE        4u
#define SIGLIST_HDR_SIZE        28u
#define SIG_OWNER_SIZE          16u
#define DMAR_FLAGS_OFFSET       37u
#define DMAR_PLATFORM_OPT_IN    0x04u

#define MSR_MTRRCAP             0xFEu
#define MTRRCAP_SMRR            (1ull << 11)
#define MSR_SMRR_PHYSMASK       0x1F3u
#define SMRR_VALID              (1ull << 11)
#define MSR_AMD_HWCR            0xC0010015u
#define HWCR_SMMLOCK            1ull
#define MSR_AMD_SMM_MASK        0xC0010113u
#define SMM_MASK_TVALID         (1ull << 1)
#define PCI_UNPRIV_CONFIG_LEN   64u     /* sysfs serves only the standard header to non-root */
#define PCI_CLASS_HOST_BRIDGE   0x0600u
#define PCI_CLASS_ISA_BRIDGE    0x0601u
#define PCI_CLASS_SPI           0x0C80u
#define SMRAMC_OFFSET           0x88u   /* host bridge, Sandy Bridge and newer (337345 §3.29) */
#define SMRAM_MCH_OFFSET        0x9Du   /* host bridge, Core 2-era memory controller hubs (319970 §5.1.28) */
#define SMRAMC_D_LCK            0x10u
#define BIOS_CNTL_OFFSET        0xDCu   /* SPI 00:1f.5 (100-series+) or LPC 00:1f.0 (ICH6 to 9-series) */
#define BC_BLE                  0x02u
#define BC_SMM_BWP              0x20u

/* MSR numbers are file offsets into /dev/cpu/N/msr; AMD ones exceed 2^31. */
_Static_assert(sizeof(off_t) >= 8, "off_t must hold 64-bit MSR offsets");

typedef enum { CPU_OTHER, CPU_INTEL, CPU_AMD } cpu_vendor_t;

/* Intel family-6 client CPUs whose host bridge has SMRAMC at 0x88: Sandy Bridge through Raptor Lake.
 * Unlisted models (Atom SoCs, HEDT/server, Meteor Lake and newer) report unknown rather than guess. */
static const uint8_t SMRAMC_88_MODELS[] = {
    0x2A, 0x3A,                         /* Sandy Bridge, Ivy Bridge */
    0x3C, 0x45, 0x46, 0x3D, 0x47,       /* Haswell, Broadwell */
    0x4E, 0x5E, 0x8E, 0x9E, 0xA5, 0xA6, /* Skylake, Kaby/Coffee/Whiskey/Comet Lake */
    0x66, 0x7D, 0x7E, 0x8C, 0x8D, 0xA7, /* Cannon, Ice, Tiger, Rocket Lake */
    0x97, 0x9A, 0xB7, 0xBA, 0xBF,       /* Alder Lake, Raptor Lake */
};

/* Core 2-era memory controller hubs (945 to 4 Series): SMRAM at 0x9D. Device IDs from pci.ids;
 * offset verified in the 4 Series datasheet, assumed for the earlier hubs of the same lineage. */
static const uint16_t MCH_SMRAM_9D[] = {
    0x2770, 0x27A0, 0x27AC, 0x2970, 0x2980, 0x2990, 0x29A0, 0x29B0, 0x29C0, 0x29D0,
    0x29E0, 0x2A00, 0x2A10, 0x2A40, 0x2E00, 0x2E10, 0x2E20, 0x2E30, 0x2E40, 0x2E90,
};

/* Pre-100-series LPC bridges (00:1f.0) that hold BIOS_CNTL at 0xDC. SMM_BWP (bit 5) first appears
 * in the 5 Series (322169); on ICH6-ICH10 bits 7:5 are reserved (ICH9: 316972 §13.1.30). */
typedef struct {
    uint16_t first, last;
    bool smm_bwp;
} lpc_range_t;
static const lpc_range_t LEGACY_LPC[] = {
    { 0x2640, 0x2642, false },  /* ICH6 */
    { 0x27B0, 0x27BD, false },  /* ICH7, NM10 */
    { 0x2810, 0x2815, false },  /* ICH8 */
    { 0x2912, 0x2919, false },  /* ICH9 */
    { 0x3A14, 0x3A1A, false },  /* ICH10 */
    { 0x3B00, 0x3B1F, true },   /* 5 Series / 3400 */
    { 0x1C40, 0x1C5F, true },   /* 6 Series / C200 */
    { 0x1E40, 0x1E5F, true },   /* 7 Series */
    { 0x8C40, 0x8C5F, true },   /* 8 Series / C220 */
    { 0x9C40, 0x9C47, true },   /* 8 Series LP */
    { 0x8CC0, 0x8CDF, true },   /* 9 Series */
    { 0x9CC0, 0x9CCF, true },   /* 9 Series LP */
};

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

/* Substrings of the CNs distros ship in shim's vendor cert or enroll as MOKs. Anything else was enrolled locally. */
static const char *const KNOWN_MOK_SIGNERS[] = {
    "Fedora", "Red Hat", "CentOS", "Canonical", "Ubuntu", "Debian", "SUSE", "openSUSE",
    "Oracle", "AlmaLinux", "Rocky", "Microsoft", NULL
};

static const char *const CHECK_NAMES[FW_CHECK_COUNT] = {
    "Secure Boot on",
    "Setup mode off",
    "Platform key",
    "No test keys (PKfail)",
    "Revocation list (dbx)",
    "Shim MOK keys known",
    "IOMMU described (DMAR/IVRS)",
    "Thunderbolt DMA protection",
    "SMM locked",
    "SMRAM range protected",
    "BIOS write protection",
    "Boot measurements (TPM)",
};

typedef struct {
    int sha256_count;
    int x509_count;
    const char *test_marker;    /* first marker found in any X.509 entry, or NULL */
    char first_cn[128];         /* CN of the first X.509 entry, if cheaply found */
    const char *const *known;   /* if set: NULL-terminated CN substrings; others go to unknown_cn */
    char unknown_cn[128];       /* first X.509 CN matching none of known ("?" if it has no CN) */
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
                if (st->known && !st->unknown_cn[0]) {
                    char cn[128] = "";
                    extract_cn(cert, cert_len, cn, sizeof(cn));
                    bool ok = false;
                    for (size_t m = 0; cn[0] && !ok && st->known[m]; m++) ok = strstr(cn, st->known[m]) != NULL;
                    if (!ok) snprintf(st->unknown_cn, sizeof(st->unknown_cn), "%s", cn[0] ? cn : "?");
                }
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
    } else {
        const uint8_t *data = efivar_data(&v);
        uint8_t val = data[0];
        if (val == good) {
            set_check(c, FW_RESULT_PASS, pass_msg);
        } else if (val == (good ? 0 : 1)) {
            set_check(c, FW_RESULT_FAIL, fail_msg);
        } else {
            c->result = FW_RESULT_UNKNOWN;
            snprintf(c->detail, sizeof(c->detail), "%s has unexpected value %u.", name, (unsigned)val);
        }
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

/* shim's MokListRT: keys and hashes shim trusts on top of db. An attacker who enrolls one boots unsigned code. */
static void check_mok(fw_check_t *c, const efivar_t *mok) {
    // shortcut: reads efivarfs only; shim 15.7+ may publish large lists under /sys/firmware/efi/mok-variables instead
    if (mok->err == ENOENT) {
        set_check(c, FW_RESULT_NA, "No shim MOK list.");
        return;
    }
    if (mok->err) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail), "Could not read MokListRT: %s.", strerror(mok->err));
        return;
    }
    siglist_stats_t st;
    memset(&st, 0, sizeof(st));
    st.known = KNOWN_MOK_SIGNERS;
    if (!parse_siglists(efivar_data(mok), efivar_data_len(mok), &st)) {
        set_check(c, FW_RESULT_FAIL, "MOK list is malformed.");
    } else if (st.sha256_count) {
        c->result = FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail), "MOK list trusts %d binary hash%s without a signature.",
                 st.sha256_count, st.sha256_count == 1 ? "" : "es");
    } else if (st.unknown_cn[0]) {
        c->result = FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail), "Unknown MOK key \"%.80s\": check it was enrolled on purpose.",
                 st.unknown_cn);
    } else if (st.x509_count == 0) {
        set_check(c, FW_RESULT_NA, "MOK list is empty.");
    } else {
        c->result = FW_RESULT_PASS;
        snprintf(c->detail, sizeof(c->detail), "%d distro key%s, first \"%.80s\".", st.x509_count,
                 st.x509_count == 1 ? "" : "s", st.first_cn);
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

static bool is_number(const char *s) {
    if (*s == '\0') return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

static bool is_domain_entry(const char *name) {
    return strncmp(name, "domain", 6) == 0 && is_number(name + 6);
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

typedef struct {
    int cpus;   /* CPUs read */
    int set;    /* CPUs with every requested bit set */
    int err;    /* 0 or errno */
} msr_scan_t;

/* Reads one MSR on every CPU under dir (<dir>/<N>/msr) and counts CPUs with all `bits` set. */
static msr_scan_t msr_scan(const char *dir, uint32_t msr, uint64_t bits) {
    msr_scan_t s = { 0, 0, 0 };
    DIR *d = opendir(dir);
    if (!d) {
        s.err = errno;
        return s;
    }
    struct dirent *de;
    while (!s.err && (de = readdir(d)) != NULL) {
        if (!is_number(de->d_name)) continue;
        char path[4096];
        int w = snprintf(path, sizeof(path), "%s/%s/msr", dir, de->d_name);
        if (w < 0 || (size_t)w >= sizeof(path)) {
            s.err = ENAMETOOLONG;
            break;
        }
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            s.err = errno;
            break;
        }
        uint64_t v = 0;
        ssize_t n = pread(fd, &v, sizeof(v), (off_t)msr);
        if (n != (ssize_t)sizeof(v)) s.err = n < 0 ? errno : EIO;   /* the msr driver returns EIO on #GP */
        close(fd);
        if (s.err) break;
        s.cpus++;
        if ((v & bits) == bits) s.set++;
    }
    closedir(d);
    if (!s.err && s.cpus == 0) s.err = ENOENT;
    return s;
}

static void set_msr_error(fw_check_t *c, int err, uint32_t msr) {
    c->result = FW_RESULT_UNKNOWN;
    if (err == ENOENT || err == ENXIO)
        snprintf(c->detail, sizeof(c->detail), "CPU registers not available: load the msr kernel module.");
    else if (err == EACCES || err == EPERM)
        snprintf(c->detail, sizeof(c->detail), "Needs root to read CPU registers.");
    else if (err == EIO)
        snprintf(c->detail, sizeof(c->detail), "CPU refused to read register 0x%X.", (unsigned)msr);
    else
        snprintf(c->detail, sizeof(c->detail), "Could not read CPU registers: %s.", strerror(err));
}

/* PASS when `bit` is set in `msr` on every CPU; one unprotected CPU is enough for an attacker. */
static void check_msr_bit(fw_check_t *c, const char *dir, uint32_t msr, uint64_t bit,
                          const char *pass_msg, const char *fail_msg) {
    msr_scan_t s = msr_scan(dir, msr, bit);
    if (s.err) {
        set_msr_error(c, s.err, msr);
    } else if (s.set == s.cpus) {
        set_check(c, FW_RESULT_PASS, pass_msg);
    } else {
        c->result = FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail), "%s on %d of %d CPUs.", fail_msg, s.cpus - s.set, s.cpus);
    }
}

/* Reads an Intel PCI function's config space; on failure returns NULL and, if c is set, says why. */
static uint8_t *read_intel_pci(fw_check_t *c, const char *pci_dir, const char *bdf, uint16_t class_code,
                               const char *absent_msg, size_t *len) {
    char path[4096];
    int w = snprintf(path, sizeof(path), "%s/%s/config", pci_dir, bdf);
    uint8_t *buf = NULL;
    *len = 0;
    int err = (w < 0 || (size_t)w >= sizeof(path)) ? ENAMETOOLONG : read_file(path, &buf, len);
    char why[160] = "";
    if (err == ENOENT)
        snprintf(why, sizeof(why), "%s", absent_msg);
    else if (err == EACCES || err == EPERM)
        snprintf(why, sizeof(why), "Needs root to read chipset registers.");
    else if (err)
        snprintf(why, sizeof(why), "Could not read PCI %s: %s.", bdf, strerror(err));
    else if (*len < 0x0C || buf[0] != 0x86 || buf[1] != 0x80 ||
             buf[0x0B] != (uint8_t)(class_code >> 8) || buf[0x0A] != (uint8_t)class_code)
        snprintf(why, sizeof(why), "PCI %s is not the expected Intel device.", bdf);
    if (why[0] == '\0') return buf;
    free(buf);
    if (c) set_check(c, FW_RESULT_UNKNOWN, why);
    return NULL;
}

static uint16_t pci_device_id(const uint8_t *cfg) {
    return (uint16_t)(cfg[2] | (cfg[3] << 8));
}

/* Config byte `off`; non-root sysfs readers only get the 64-byte header. */
static bool pci_cfg_byte(fw_check_t *c, const uint8_t *cfg, size_t len, size_t off, uint8_t *val) {
    if (len > off) {
        *val = cfg[off];
        return true;
    }
    set_check(c, FW_RESULT_UNKNOWN, len == PCI_UNPRIV_CONFIG_LEN ? "Needs root to read chipset registers."
                                                                  : "Chipset config space is too short.");
    return false;
}

static size_t smram_offset(uint16_t host_bridge, long family, long model) {
    for (size_t i = 0; i < sizeof(MCH_SMRAM_9D) / sizeof(MCH_SMRAM_9D[0]); i++)
        if (MCH_SMRAM_9D[i] == host_bridge) return SMRAM_MCH_OFFSET;
    if (family == 6)
        for (size_t i = 0; i < sizeof(SMRAMC_88_MODELS); i++)
            if (SMRAMC_88_MODELS[i] == model) return SMRAMC_OFFSET;
    return 0;
}

/* Returns true when the result rests on an unconfirmed layout (older-chipset table or unrecognised chipset). */
static bool check_intel_smm_lock(fw_check_t *c, const char *pci_dir, long family, long model) {
    size_t len;
    uint8_t *cfg = read_intel_pci(c, pci_dir, "0000:00:00.0", PCI_CLASS_HOST_BRIDGE,
                                  "No Intel host bridge at 00:00.0.", &len);
    if (!cfg) return false;
    uint16_t did = pci_device_id(cfg);
    size_t off = smram_offset(did, family, model);
    uint8_t smram;
    if (off == 0) {
        c->result = FW_RESULT_UNKNOWN;
        snprintf(c->detail, sizeof(c->detail),
                 "Chipset not recognised (host bridge 8086:%04x, CPU model %ld): SMRAM lock location unknown.",
                 (unsigned)did, model);
    } else if (pci_cfg_byte(c, cfg, len, off, &smram)) {
        c->result = (smram & SMRAMC_D_LCK) ? FW_RESULT_PASS : FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail), (smram & SMRAMC_D_LCK)
                 ? "SMRAM is locked (D_LCK at 0x%02X)." : "SMRAM is not locked (D_LCK at 0x%02X): the OS can change SMM code.",
                 (unsigned)off);
    }
    free(cfg);
    return off != SMRAMC_OFFSET;
}

static void check_intel_smrr(fw_check_t *c, const char *msr_dir) {
    msr_scan_t cap = msr_scan(msr_dir, MSR_MTRRCAP, MTRRCAP_SMRR);
    if (cap.err)
        set_msr_error(c, cap.err, MSR_MTRRCAP);
    else if (cap.set != cap.cpus)
        set_check(c, FW_RESULT_FAIL, "CPU has no SMRR: SMRAM can be attacked through the cache.");
    else
        check_msr_bit(c, msr_dir, MSR_SMRR_PHYSMASK, SMRR_VALID, "SMRR protects SMRAM.", "SMRR is not set up");
}

static const lpc_range_t *legacy_lpc(uint16_t did) {
    for (size_t i = 0; i < sizeof(LEGACY_LPC) / sizeof(LEGACY_LPC[0]); i++)
        if (did >= LEGACY_LPC[i].first && did <= LEGACY_LPC[i].last) return &LEGACY_LPC[i];
    return NULL;
}

/* BIOS_CNTL lives on the LPC bridge up to the 9 Series and on the SPI controller from the 100 Series.
 * Returns true when an older-chipset table entry was used. */
static bool check_intel_bios_wp(fw_check_t *c, const char *pci_dir) {
    size_t len;
    const lpc_range_t *legacy = NULL;
    uint8_t *cfg = read_intel_pci(NULL, pci_dir, "0000:00:1f.0", PCI_CLASS_ISA_BRIDGE, "", &len);
    if (cfg) legacy = legacy_lpc(pci_device_id(cfg));
    if (!legacy) {
        free(cfg);
        cfg = read_intel_pci(c, pci_dir, "0000:00:1f.5", PCI_CLASS_SPI,
                             "SPI controller hidden by firmware, or chipset not recognised.", &len);
        if (!cfg) return false;
    }
    uint8_t bc;
    if (pci_cfg_byte(c, cfg, len, BIOS_CNTL_OFFSET, &bc)) {
        bool ble = (bc & BC_BLE) != 0, bwp = (bc & BC_SMM_BWP) != 0;
        if (legacy && !legacy->smm_bwp) {
            set_check(c, FW_RESULT_FAIL, ble
                      ? "BIOS lock on, but this chipset has no SMM write protection: the lock can be raced (CVE-2014-8273)."
                      : "The OS can rewrite the firmware: BIOS lock off, and this chipset has no SMM write protection.");
        } else if (ble && bwp) {
            set_check(c, FW_RESULT_PASS, "BIOS lock and SMM write protection are on.");
        } else {
            c->result = FW_RESULT_FAIL;
            snprintf(c->detail, sizeof(c->detail), "The OS can rewrite the firmware: BIOS lock %s, SMM write protection %s.",
                     ble ? "on" : "off", bwp ? "on" : "off");
        }
    }
    free(cfg);
    return legacy != NULL;
}

/* Value of the first "key<blanks>: N" line, or -1; skips longer keys such as "model name". */
static long cpuinfo_number(const char *s, const char *key) {
    size_t klen = strlen(key);
    for (const char *line = s; line; line = strchr(line, '\n'), line = line ? line + 1 : NULL) {
        if (strncmp(line, key, klen) != 0) continue;
        const char *p = line + klen;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ':') return strtol(p + 1, NULL, 10);
    }
    return -1;
}

static void check_silicon(fw_check_t *ck, bool *unconfirmed, const char *cpuinfo, const char *msr_dir,
                          const char *pci_dir) {
    fw_check_t *const silicon[3] = { &ck[FW_CHECK_SMM_LOCK], &ck[FW_CHECK_SMRAM_RANGE], &ck[FW_CHECK_BIOS_WP] };
    uint8_t *buf;
    size_t len;
    int err = read_file(cpuinfo, &buf, &len);
    char *text = err ? NULL : realloc(buf, len + 1);
    if (!err && !text) {
        free(buf);
        err = ENOMEM;
    }
    if (err) {
        for (size_t i = 0; i < 3; i++) {
            silicon[i]->result = FW_RESULT_UNKNOWN;
            snprintf(silicon[i]->detail, sizeof(silicon[i]->detail), "Could not identify the CPU: %s.", strerror(err));
        }
        return;
    }
    text[len] = '\0';
    cpu_vendor_t vendor = strstr(text, "GenuineIntel") ? CPU_INTEL
                        : strstr(text, "AuthenticAMD") ? CPU_AMD : CPU_OTHER;
    bool vm = strstr(text, " hypervisor") != NULL;
    long family = cpuinfo_number(text, "cpu family"), model = cpuinfo_number(text, "model");
    free(text);

    if (vendor == CPU_OTHER) {
        for (size_t i = 0; i < 3; i++) set_check(silicon[i], FW_RESULT_NA, "Not an Intel or AMD CPU.");
    } else if (vm) {
        /* Hypervisors emulate or zero these registers, so any answer would be fiction. */
        for (size_t i = 0; i < 3; i++)
            set_check(silicon[i], FW_RESULT_UNKNOWN, "Virtual machine: silicon registers are emulated.");
    } else if (vendor == CPU_INTEL) {
        bool smm = check_intel_smm_lock(silicon[0], pci_dir, family, model);
        check_intel_smrr(silicon[1], msr_dir);
        bool bwp = check_intel_bios_wp(silicon[2], pci_dir);
        *unconfirmed = smm || bwp;
    } else {
        check_msr_bit(silicon[0], msr_dir, MSR_AMD_HWCR, HWCR_SMMLOCK, "SMM is locked (HWCR.SmmLock).",
                      "SMM is not locked (HWCR.SmmLock)");
        check_msr_bit(silicon[1], msr_dir, MSR_AMD_SMM_MASK, SMM_MASK_TVALID, "TSEG protects SMRAM.",
                      "TSEG protection is off");
        set_check(silicon[2], FW_RESULT_NA, "Checked on Intel only: AMD flash protection needs MMIO.");
    }
}

/* ---- TPM event log (TCG PC Client Platform Firmware Profile, crypto-agile format) ---------- */

#define EV_NO_ACTION        3u
#define TPM_ALG_SHA256      0x000Bu
#define TPM_REPLAY_PCRS     8   /* firmware PCRs 0-7 */
#define TPM_MAX_ALGS        8

typedef enum { REPLAY_OK, REPLAY_MALFORMED, REPLAY_NO_SHA256 } replay_result_t;

static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Replays the SHA-256 bank of the log into pcr[0..7]. Every length is checked against the
 * bytes left before it is used; the log is firmware-written, so any inconsistency is MALFORMED. */
static replay_result_t tpm_replay(const uint8_t *d, size_t len, uint8_t pcr[TPM_REPLAY_PCRS][32]) {
    memset(pcr, 0, TPM_REPLAY_PCRS * 32);
    /* First entry: legacy TCG_PCR_EVENT (pcr, type, sha1[20], size) holding the Spec ID event:
     * signature[16], platformClass, versions[4], numberOfAlgorithms, {algId, digestSize}[]. */
    if (len < 32) return REPLAY_MALFORMED;
    uint32_t spec_size = rd_le32(d + 28);
    if (rd_le32(d) != 0 || rd_le32(d + 4) != EV_NO_ACTION || spec_size > len - 32 || spec_size < 28 ||
        memcmp(d + 32, "Spec ID Event03", 16) != 0)
        return REPLAY_MALFORMED;
    const uint8_t *spec = d + 32;
    uint32_t nalg = rd_le32(spec + 24);
    if (nalg == 0 || nalg > TPM_MAX_ALGS || (spec_size - 28) / 4 < nalg) return REPLAY_MALFORMED;
    uint16_t alg_id[TPM_MAX_ALGS], alg_size[TPM_MAX_ALGS];
    bool has_sha256 = false;
    for (uint32_t i = 0; i < nalg; i++) {
        alg_id[i] = rd_le16(spec + 28 + 4 * i);
        alg_size[i] = rd_le16(spec + 30 + 4 * i);
        if (alg_size[i] == 0 || alg_size[i] > 64) return REPLAY_MALFORMED;
        if (alg_id[i] == TPM_ALG_SHA256) {
            if (alg_size[i] != 32) return REPLAY_MALFORMED;
            has_sha256 = true;
        }
    }
    if (!has_sha256) return REPLAY_NO_SHA256;

    /* Then TCG_PCR_EVENT2 entries: pcr, type, count, {algId, digest}[count], size, event[size]. */
    size_t off = 32 + (size_t)spec_size;
    bool pcr0_extended = false;
    while (off < len) {
        if (len - off < 12) return REPLAY_MALFORMED;
        uint32_t idx = rd_le32(d + off), type = rd_le32(d + off + 4), count = rd_le32(d + off + 8);
        if (type == 0 && count == 0) break;     /* zero padding after the last event */
        if (count != nalg) return REPLAY_MALFORMED;
        off += 12;
        const uint8_t *digest256 = NULL;
        for (uint32_t c = 0; c < count; c++) {
            if (len - off < 2) return REPLAY_MALFORMED;
            uint16_t alg = rd_le16(d + off);
            size_t dsize = 0;
            for (uint32_t i = 0; i < nalg; i++)
                if (alg_id[i] == alg) dsize = alg_size[i];
            if (dsize == 0 || len - off - 2 < dsize) return REPLAY_MALFORMED;
            if (alg == TPM_ALG_SHA256) digest256 = d + off + 2;
            off += 2 + dsize;
        }
        if (len - off < 4) return REPLAY_MALFORMED;
        uint32_t ev_size = rd_le32(d + off);
        off += 4;
        if (ev_size > len - off) return REPLAY_MALFORMED;
        const uint8_t *ev = d + off;
        off += ev_size;

        if (type == EV_NO_ACTION) {
            /* Not extended; "StartupLocality" sets PCR0's starting value (locality in the last byte). */
            if (idx == 0 && !pcr0_extended && ev_size >= 17 && memcmp(ev, "StartupLocality", 16) == 0)
                pcr[0][31] = ev[16];
            continue;
        }
        if (idx >= TPM_REPLAY_PCRS) continue;
        if (!digest256) return REPLAY_MALFORMED;
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, pcr[idx], 32);
        sha256_update(&ctx, digest256, 32);
        sha256_final(&ctx, pcr[idx]);
        if (idx == 0) pcr0_extended = true;
    }
    return REPLAY_OK;
}

/* sysfs pcr-sha256/<n>: 64 hex digits (the kernel prints uppercase), then a newline. */
static int read_pcr(const char *tpm_dir, int n, uint8_t out[32]) {
    char path[4096];
    int w = snprintf(path, sizeof(path), "%s/pcr-sha256/%d", tpm_dir, n);
    if (w < 0 || (size_t)w >= sizeof(path)) return ENAMETOOLONG;
    uint8_t *buf;
    size_t len;
    int err = read_file(path, &buf, &len);
    if (err) return err;
    if (len < 64) err = EIO;
    for (size_t i = 0; i < 32 && !err; i++) {
        int hi = hex_nibble((char)buf[2 * i]), lo = hex_nibble((char)buf[2 * i + 1]);
        if (hi < 0 || lo < 0) err = EIO;
        else out[i] = (uint8_t)(hi << 4 | lo);
    }
    free(buf);
    return err;
}

static void check_tpm_log(fw_check_t *c, const char *tpm_dir, const char *log_path) {
    struct stat sb;
    if (stat(tpm_dir, &sb) != 0) {
        set_check(c, FW_RESULT_NA, "No TPM.");
        return;
    }
    uint8_t *log;
    size_t len;
    int err = read_file(log_path, &log, &len);
    if (err) {
        c->result = FW_RESULT_UNKNOWN;
        if (err == EACCES || err == EPERM)
            snprintf(c->detail, sizeof(c->detail), "Needs root to read the TPM event log.");
        else if (err == ENOENT)
            snprintf(c->detail, sizeof(c->detail), "Firmware provided no TPM event log.");
        else
            snprintf(c->detail, sizeof(c->detail), "Could not read the TPM event log: %s.", strerror(err));
        return;
    }
    uint8_t replay[TPM_REPLAY_PCRS][32];
    replay_result_t r = tpm_replay(log, len, replay);
    free(log);
    if (r == REPLAY_MALFORMED) {
        set_check(c, FW_RESULT_FAIL, "TPM event log is malformed: boot measurements cannot be verified.");
        return;
    }
    if (r == REPLAY_NO_SHA256) {
        set_check(c, FW_RESULT_UNKNOWN, "TPM event log has no SHA-256 measurements.");
        return;
    }
    char bad[32] = "";
    size_t bad_len = 0;
    uint8_t pcr0[32] = { 0 };
    for (int i = 0; i < TPM_REPLAY_PCRS; i++) {
        uint8_t actual[32];
        err = read_pcr(tpm_dir, i, actual);
        if (err) {
            c->result = FW_RESULT_UNKNOWN;
            snprintf(c->detail, sizeof(c->detail), "Could not read TPM PCR %d (SHA-256 bank): %s.", i, strerror(err));
            return;
        }
        if (i == 0) memcpy(pcr0, actual, sizeof(pcr0));
        if (memcmp(actual, replay[i], 32) != 0) {
            int w = snprintf(bad + bad_len, sizeof(bad) - bad_len, bad_len ? ", %d" : "%d", i);
            if (w > 0 && (size_t)w < sizeof(bad) - bad_len) bad_len += (size_t)w;
        }
    }
    if (bad_len) {
        c->result = FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail),
                 "PCR %s do not match the event log: boot measurements were altered or the log is incomplete.", bad);
        return;
    }
    c->result = FW_RESULT_PASS;
    snprintf(c->detail, sizeof(c->detail),
             "Event log matches PCR 0-7; firmware digest (PCR0) %02x%02x%02x%02x%02x%02x%02x%02x...",
             pcr0[0], pcr0[1], pcr0[2], pcr0[3], pcr0[4], pcr0[5], pcr0[6], pcr0[7]);
}

booto_error_t firmware_audit(const firmware_paths_t *paths, firmware_report_t *out) {
    if (!out) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    const char *efi = (paths && paths->efivars_dir) ? paths->efivars_dir : "/sys/firmware/efi/efivars";
    const char *acpi = (paths && paths->acpi_tables_dir) ? paths->acpi_tables_dir : "/sys/firmware/acpi/tables";
    const char *tb = (paths && paths->thunderbolt_dir) ? paths->thunderbolt_dir : "/sys/bus/thunderbolt/devices";
    const char *cpuinfo = (paths && paths->cpuinfo_path) ? paths->cpuinfo_path : "/proc/cpuinfo";
    const char *msr = (paths && paths->msr_dir) ? paths->msr_dir : "/dev/cpu";
    const char *pci = (paths && paths->pci_devices_dir) ? paths->pci_devices_dir : "/sys/bus/pci/devices";
    const char *tpm = (paths && paths->tpm_dir) ? paths->tpm_dir : "/sys/class/tpm/tpm0";
    const char *tpm_log = (paths && paths->tpm_log_path) ? paths->tpm_log_path
                                                         : "/sys/kernel/security/tpm0/binary_bios_measurements";

    struct stat sb;
    out->uefi_boot = stat(efi, &sb) == 0 && S_ISDIR(sb.st_mode);
    fw_check_t *ck = out->checks;
    if (!out->uefi_boot) {
        for (int i = FW_CHECK_SECURE_BOOT; i <= FW_CHECK_MOK; i++)
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
        efivar_t mok = read_efivar(efi, "MokListRT", SHIM_LOCK_GUID);
        check_mok(&ck[FW_CHECK_MOK], &mok);
        free(mok.buf);

        free(pk.buf);
        free(kek.buf);
        free(db.buf);
        free(dbx.buf);
    }
    check_iommu(&ck[FW_CHECK_IOMMU], acpi);
    check_thunderbolt(&ck[FW_CHECK_THUNDERBOLT_DMA], tb);
    check_silicon(ck, &out->chipset_unconfirmed, cpuinfo, msr, pci);
    check_tpm_log(&ck[FW_CHECK_TPM_LOG], tpm, tpm_log);

    for (int i = 0; i < FW_CHECK_COUNT; i++) {
        if (ck[i].result == FW_RESULT_FAIL) out->fail_count++;
        else if (ck[i].result == FW_RESULT_UNKNOWN) out->unknown_count++;
    }
    return BOOTO_OK;
}

#define NVRAM_BLOB_MIN     4096u
#define NVRAM_BLOB_ENTROPY 7.5

/* Why this variable data looks like hidden code, or NULL. */
static const char *nvram_suspect(const uint8_t *d, size_t len) {
    for (size_t i = 0; i + 0x40 <= len; i++) {
        if (d[i] == 0x7f && memcmp(d + i, "\x7f" "ELF", 4) == 0) return "holds an ELF executable";
        if (d[i] != 'M' || d[i + 1] != 'Z') continue;
        uint32_t lfanew = rd_le32(d + i + 0x3c);
        if (lfanew <= len - i - 4 && memcmp(d + i + lfanew, "PE\0\0", 4) == 0) return "holds a PE executable";
    }
    if (len < NVRAM_BLOB_MIN) return NULL;
    siglist_stats_t st;
    memset(&st, 0, sizeof(st));
    if (parse_siglists(d, len, &st)) return NULL;   /* PK/KEK/db/dbx/MokList: certificates and hashes are meant to look random */
    size_t hist[256] = { 0 };
    for (size_t i = 0; i < len; i++) hist[d[i]]++;
    return entropy_bits(hist, len) > NVRAM_BLOB_ENTROPY ? "large packed or encrypted blob" : NULL;
}

booto_error_t firmware_nvram_scan(const char *efivars_dir, fw_nvram_report_t *out) {
    if (!out) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    const char *dir = efivars_dir ? efivars_dir : "/sys/firmware/efi/efivars";
    DIR *dp = opendir(dir);
    if (!dp) return BOOTO_ERR_NOT_FOUND;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char path[4096];
        int w = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        uint8_t *buf = NULL;
        size_t len = 0;
        if (w < 0 || (size_t)w >= sizeof(path) || read_file(path, &buf, &len) != 0) {
            out->unreadable++;
            continue;
        }
        out->vars_scanned++;
        const char *why = len > EFIVAR_ATTR_SIZE ? nvram_suspect(buf + EFIVAR_ATTR_SIZE, len - EFIVAR_ATTR_SIZE) : NULL;
        if (why && out->count < FW_NVRAM_MAX_FINDINGS) {
            fw_nvram_finding_t *f = &out->findings[out->count++];
            snprintf(f->name, sizeof(f->name), "%s", de->d_name);
            snprintf(f->reason, sizeof(f->reason), "%s", why);
            f->size = len - EFIVAR_ATTR_SIZE;
        }
        free(buf);
    }
    closedir(dp);
    return BOOTO_OK;
}

booto_error_t firmware_spi_dump(const char *out_path, char sha256_hex[65]) {
    if (!out_path || !sha256_hex) return BOOTO_ERR_INVALID_ARG;
    sha256_hex[0] = '\0';
    const char *const argv[] = { "flashrom", "-p", "internal", "-r", out_path, NULL };
    int status = 0;
    booto_error_t e = disk_exec_argv(argv, NULL, 0, &status);
    if (e == BOOTO_ERR_NOT_FOUND) return e;
    if (e != BOOTO_OK) return BOOTO_ERR_IO;
    return sha256_file_hex(out_path, sha256_hex) ? BOOTO_OK : BOOTO_ERR_IO;
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
