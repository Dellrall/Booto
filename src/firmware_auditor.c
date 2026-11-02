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
#define PCI_CLASS_SPI           0x0C80u
#define SMRAMC_OFFSET           0x88u   /* host bridge 00:00.0 */
#define SMRAMC_D_LCK            0x10u
#define BIOS_CNTL_OFFSET        0xDCu   /* SPI controller 00:1f.5, Intel 100-series and newer */
#define BC_BLE                  0x02u
#define BC_SMM_BWP              0x20u

/* MSR numbers are file offsets into /dev/cpu/N/msr; AMD ones exceed 2^31. */
_Static_assert(sizeof(off_t) >= 8, "off_t must hold 64-bit MSR offsets");

typedef enum { CPU_OTHER, CPU_INTEL, CPU_AMD } cpu_vendor_t;

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
    "SMM locked",
    "SMRAM range protected",
    "BIOS write protection",
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

/* Reads byte `off` of an Intel PCI function's config space; on failure sets c and returns false. */
static bool read_intel_pci_byte(fw_check_t *c, const char *pci_dir, const char *bdf, uint16_t class_code,
                                size_t off, const char *absent_msg, uint8_t *val) {
    char path[4096];
    int w = snprintf(path, sizeof(path), "%s/%s/config", pci_dir, bdf);
    uint8_t *buf = NULL;
    size_t len = 0;
    int err = (w < 0 || (size_t)w >= sizeof(path)) ? ENAMETOOLONG : read_file(path, &buf, &len);
    c->result = FW_RESULT_UNKNOWN;
    if (err == ENOENT) {
        snprintf(c->detail, sizeof(c->detail), "%s", absent_msg);
    } else if (err == EACCES || err == EPERM) {
        snprintf(c->detail, sizeof(c->detail), "Needs root to read chipset registers.");
    } else if (err) {
        snprintf(c->detail, sizeof(c->detail), "Could not read PCI %s: %s.", bdf, strerror(err));
    } else if (len < 0x0C || buf[0] != 0x86 || buf[1] != 0x80 ||
               buf[0x0B] != (uint8_t)(class_code >> 8) || buf[0x0A] != (uint8_t)class_code) {
        snprintf(c->detail, sizeof(c->detail), "PCI %s is not the expected Intel device.", bdf);
    } else if (len <= off) {
        snprintf(c->detail, sizeof(c->detail), "%s", len == PCI_UNPRIV_CONFIG_LEN
                 ? "Needs root to read chipset registers." : "Chipset config space is too short.");
    } else {
        *val = buf[off];
        free(buf);
        return true;
    }
    free(buf);
    return false;
}

/* shortcut: SMRAMC at 00:00.0+0x88 holds for Core host bridges (Sandy Bridge and newer); older
 * chipsets and Atom SoCs place it elsewhere. Add host-bridge device IDs if those must be supported. */
static void check_intel_smm_lock(fw_check_t *c, const char *pci_dir) {
    uint8_t smramc;
    if (!read_intel_pci_byte(c, pci_dir, "0000:00:00.0", PCI_CLASS_HOST_BRIDGE, SMRAMC_OFFSET,
                             "No Intel host bridge at 00:00.0.", &smramc))
        return;
    if (smramc & SMRAMC_D_LCK)
        set_check(c, FW_RESULT_PASS, "SMRAM is locked (SMRAMC.D_LCK).");
    else
        set_check(c, FW_RESULT_FAIL, "SMRAM is not locked (SMRAMC.D_LCK): the OS can change SMM code.");
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

/* shortcut: pre-100-series chipsets keep BIOS_CNTL on the LPC bridge (00:1f.0), which is not
 * read here because 00:1f.0+0xDC means something else on newer PCHs; add device IDs if needed. */
static void check_intel_bios_wp(fw_check_t *c, const char *pci_dir) {
    uint8_t bc;
    if (!read_intel_pci_byte(c, pci_dir, "0000:00:1f.5", PCI_CLASS_SPI, BIOS_CNTL_OFFSET,
                             "SPI controller hidden by firmware, or chipset older than Intel 100 series.", &bc))
        return;
    if ((bc & BC_BLE) && (bc & BC_SMM_BWP)) {
        set_check(c, FW_RESULT_PASS, "BIOS lock and SMM write protection are on.");
    } else {
        c->result = FW_RESULT_FAIL;
        snprintf(c->detail, sizeof(c->detail), "The OS can rewrite the firmware: BIOS lock %s, SMM write protection %s.",
                 (bc & BC_BLE) ? "on" : "off", (bc & BC_SMM_BWP) ? "on" : "off");
    }
}

static void check_silicon(fw_check_t *ck, const char *cpuinfo, const char *msr_dir, const char *pci_dir) {
    fw_check_t *const silicon[3] = { &ck[FW_CHECK_SMM_LOCK], &ck[FW_CHECK_SMRAM_RANGE], &ck[FW_CHECK_BIOS_WP] };
    uint8_t *buf;
    size_t len;
    int err = read_file(cpuinfo, &buf, &len);
    if (err) {
        for (size_t i = 0; i < 3; i++) {
            silicon[i]->result = FW_RESULT_UNKNOWN;
            snprintf(silicon[i]->detail, sizeof(silicon[i]->detail), "Could not identify the CPU: %s.", strerror(err));
        }
        return;
    }
    cpu_vendor_t vendor = memmem(buf, len, "GenuineIntel", 12) ? CPU_INTEL
                        : memmem(buf, len, "AuthenticAMD", 12) ? CPU_AMD : CPU_OTHER;
    bool vm = memmem(buf, len, " hypervisor", 11) != NULL;
    free(buf);

    if (vendor == CPU_OTHER) {
        for (size_t i = 0; i < 3; i++) set_check(silicon[i], FW_RESULT_NA, "Not an Intel or AMD CPU.");
    } else if (vm) {
        /* Hypervisors emulate or zero these registers, so any answer would be fiction. */
        for (size_t i = 0; i < 3; i++)
            set_check(silicon[i], FW_RESULT_UNKNOWN, "Virtual machine: silicon registers are emulated.");
    } else if (vendor == CPU_INTEL) {
        check_intel_smm_lock(silicon[0], pci_dir);
        check_intel_smrr(silicon[1], msr_dir);
        check_intel_bios_wp(silicon[2], pci_dir);
    } else {
        check_msr_bit(silicon[0], msr_dir, MSR_AMD_HWCR, HWCR_SMMLOCK, "SMM is locked (HWCR.SmmLock).",
                      "SMM is not locked (HWCR.SmmLock)");
        check_msr_bit(silicon[1], msr_dir, MSR_AMD_SMM_MASK, SMM_MASK_TVALID, "TSEG protects SMRAM.",
                      "TSEG protection is off");
        set_check(silicon[2], FW_RESULT_NA, "Checked on Intel only: AMD flash protection needs MMIO.");
    }
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
    check_silicon(ck, cpuinfo, msr, pci);

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
