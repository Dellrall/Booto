/**
 * @file test_firmware_auditor.c
 * @brief Unit tests for the host firmware audit on fake efivars/ACPI/Thunderbolt trees.
 */
#include "test_framework.h"
#include "firmware_auditor.h"
#include "crypto_utils.h"
#include "disk_mount.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define IMAGE_GUID  "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define SHIM_GUID   "605dab50-e046-4300-abb6-3dd810dd8b23"

static const uint8_t T_SHA256[16] = {
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28
};
static const uint8_t T_X509[16] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

static char g_root[64];
static char g_efi[96], g_acpi[96], g_tb[96], g_cpuinfo[96], g_msr[96], g_pci[96], g_tpm[96], g_tpmlog[96];
static firmware_paths_t g_paths;

#define CPUINFO_INTEL "vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Core(TM) i7-8550U\n" \
                      "model\t\t: 142\nflags\t\t: fpu vme msr\n"
#define CPUINFO_AMD   "vendor_id\t: AuthenticAMD\nflags\t\t: fpu vme msr\n"
#define CPUINFO_VM    "vendor_id\t: GenuineIntel\nflags\t\t: fpu vme msr hypervisor\n"

static void write_file(const char *path, const void *data, size_t len);

static void make_root(bool efi, bool acpi, bool tb) {
    snprintf(g_root, sizeof(g_root), "/tmp/booto_fw_XXXXXX");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        exit(1);
    }
    snprintf(g_efi, sizeof(g_efi), "%s/efivars", g_root);
    snprintf(g_acpi, sizeof(g_acpi), "%s/acpi", g_root);
    snprintf(g_tb, sizeof(g_tb), "%s/thunderbolt", g_root);
    if (efi) mkdir(g_efi, 0755);
    if (acpi) mkdir(g_acpi, 0755);
    if (tb) mkdir(g_tb, 0755);
    g_paths.efivars_dir = g_efi;
    g_paths.acpi_tables_dir = g_acpi;
    g_paths.thunderbolt_dir = g_tb;
    snprintf(g_cpuinfo, sizeof(g_cpuinfo), "%s/cpuinfo", g_root);
    snprintf(g_msr, sizeof(g_msr), "%s/cpu", g_root);
    snprintf(g_pci, sizeof(g_pci), "%s/pci", g_root);
    g_paths.cpuinfo_path = g_cpuinfo;
    g_paths.msr_dir = g_msr;
    g_paths.pci_devices_dir = g_pci;
    snprintf(g_tpm, sizeof(g_tpm), "%s/tpm", g_root);
    snprintf(g_tpmlog, sizeof(g_tpmlog), "%s/tpmlog", g_root);
    g_paths.tpm_dir = g_tpm;          /* absent unless a test builds it: "No TPM." */
    g_paths.tpm_log_path = g_tpmlog;
    /* Default: a CPU the silicon checks do not cover, so they report n/a. */
    write_file(g_cpuinfo, "vendor_id\t: OtherVendor\n", 24);
}

static void remove_tree(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            char child[512];
            snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
            remove_tree(child);
        }
        closedir(d);
        rmdir(path);
    } else {
        unlink(path);
    }
}

static void write_file(const char *path, const void *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return;
    if (len && fwrite(data, 1, len, fp) != len) perror("fwrite");
    fclose(fp);
}

/* efivarfs layout: 4-byte attributes, then the payload. */
static void write_var(const char *name, const char *guid, const uint8_t *data, size_t len) {
    uint8_t buf[4096];
    static const uint8_t attrs[4] = { 0x07, 0x00, 0x00, 0x00 };
    if (len > sizeof(buf) - 4) return;
    memcpy(buf, attrs, 4);
    if (len) memcpy(buf + 4, data, len);
    char path[256];
    snprintf(path, sizeof(path), "%s/%s-%s", g_efi, name, guid);
    write_file(path, buf, len + 4);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Appends one EFI_SIGNATURE_LIST with `count` copies of sig_data; returns new length. */
static size_t append_siglist(uint8_t *buf, size_t off, const uint8_t type[16],
                             const uint8_t *sig_data, size_t sig_len, size_t count) {
    uint32_t sig_size = (uint32_t)(16 + sig_len);
    memcpy(buf + off, type, 16);
    put_le32(buf + off + 16, (uint32_t)(28 + count * sig_size));
    put_le32(buf + off + 20, 0);
    put_le32(buf + off + 24, sig_size);
    off += 28;
    for (size_t i = 0; i < count; i++) {
        memset(buf + off, 0xab, 16);    /* owner GUID */
        memcpy(buf + off + 16, sig_data, sig_len);
        off += sig_size;
    }
    return off;
}

/* Fake DER fragment: some bytes, then commonName OID + UTF8String. */
static size_t make_cert(uint8_t *out, const char *cn, const char *extra) {
    size_t n = 0;
    static const uint8_t head[] = { 0x30, 0x82, 0x01, 0x00, 0x31, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c };
    memcpy(out, head, sizeof(head));
    n = sizeof(head);
    out[n++] = (uint8_t)strlen(cn);
    memcpy(out + n, cn, strlen(cn));
    n += strlen(cn);
    if (extra) {
        memcpy(out + n, extra, strlen(extra));
        n += strlen(extra);
    }
    return n;
}

static void write_cert_var(const char *name, const char *guid, const char *cn, const char *extra) {
    uint8_t cert[256], list[512];
    size_t clen = make_cert(cert, cn, extra);
    size_t len = append_siglist(list, 0, T_X509, cert, clen, 1);
    write_var(name, guid, list, len);
}

static void write_dbx(size_t hashes) {
    uint8_t hash[32], list[1024];
    memset(hash, 0x5a, sizeof(hash));
    size_t len = hashes ? append_siglist(list, 0, T_SHA256, hash, sizeof(hash), hashes) : 0;
    write_var("dbx", IMAGE_GUID, list, len);
}

static void write_byte_var(const char *name, uint8_t v) {
    write_var(name, GLOBAL_GUID, &v, 1);
}

static void write_dmar(uint8_t flags) {
    uint8_t dmar[40];
    memset(dmar, 0, sizeof(dmar));
    memcpy(dmar, "DMAR", 4);
    dmar[37] = flags;
    char path[160];
    snprintf(path, sizeof(path), "%s/DMAR", g_acpi);
    write_file(path, dmar, sizeof(dmar));
}

static void write_tb_domain(const char *value) {
    char path[192];
    snprintf(path, sizeof(path), "%s/domain0", g_tb);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/domain0/iommu_dma_protection", g_tb);
    write_file(path, value, strlen(value));
}

static void write_cpuinfo(const char *text) {
    write_file(g_cpuinfo, text, strlen(text));
}

/* Stands in for /dev/cpu/N/msr: a sparse file where the MSR number is the byte offset. */
static void write_msr(int cpu, uint32_t msr, uint64_t val) {
    char path[192];
    mkdir(g_msr, 0755);
    snprintf(path, sizeof(path), "%s/%d", g_msr, cpu);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/%d/msr", g_msr, cpu);
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return;
    if (pwrite(fd, &val, sizeof(val), (off_t)msr) != (ssize_t)sizeof(val)) perror("pwrite");
    close(fd);
}

/* Intel PCI function 8086:did config space of `len` bytes with byte `off` = val. */
static void write_pci(const char *bdf, uint16_t did, uint16_t class_code, size_t len, size_t off, uint8_t val) {
    uint8_t cfg[256];
    memset(cfg, 0, sizeof(cfg));
    cfg[0] = 0x86;
    cfg[1] = 0x80;
    cfg[2] = (uint8_t)did;
    cfg[3] = (uint8_t)(did >> 8);
    cfg[0x0A] = (uint8_t)class_code;
    cfg[0x0B] = (uint8_t)(class_code >> 8);
    if (off < sizeof(cfg)) cfg[off] = val;
    char path[192];
    mkdir(g_pci, 0755);
    snprintf(path, sizeof(path), "%s/%s", g_pci, bdf);
    mkdir(path, 0755);
    snprintf(path, sizeof(path), "%s/%s/config", g_pci, bdf);
    write_file(path, cfg, len);
}

static void build_intel_silicon(bool d_lck, uint8_t bios_cntl) {
    write_cpuinfo(CPUINFO_INTEL);
    write_pci("0000:00:00.0", 0x5914, 0x0600, 256, 0x88, d_lck ? 0x1A : 0x0A);
    write_pci("0000:00:1f.5", 0x9D24, 0x0C80, 256, 0xDC, bios_cntl);
}

/* ---- TPM event log fixture (crypto-agile: SHA-1 + SHA-256 banks) ---- */

static size_t put32(uint8_t *p, size_t off, uint32_t v) {
    put_le32(p + off, v);
    return off + 4;
}

static size_t put16(uint8_t *p, size_t off, uint16_t v) {
    p[off] = (uint8_t)v;
    p[off + 1] = (uint8_t)(v >> 8);
    return off + 2;
}

/* Appends one TCG_PCR_EVENT2 whose SHA-1 and SHA-256 digests are fill bytes. */
static size_t put_event2(uint8_t *p, size_t off, uint32_t pcr, uint32_t type, uint8_t fill,
                         const void *ev, uint32_t ev_len) {
    off = put32(p, off, pcr);
    off = put32(p, off, type);
    off = put32(p, off, 2);
    off = put16(p, off, 0x0004);
    memset(p + off, fill, 20);
    off += 20;
    off = put16(p, off, 0x000B);
    memset(p + off, fill, 32);
    off += 32;
    off = put32(p, off, ev_len);
    if (ev_len) memcpy(p + off, ev, ev_len);
    return off + ev_len;
}

static void extend(uint8_t pcr[32], uint8_t fill) {
    uint8_t d[32];
    memset(d, fill, sizeof(d));
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, pcr, 32);
    sha256_update(&ctx, d, 32);
    sha256_final(&ctx, pcr);
}

static void write_pcr(int n, const uint8_t v[32]) {
    char path[160], hex[66];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02X", v[i]);
    hex[64] = '\n';
    snprintf(path, sizeof(path), "%s/pcr-sha256/%d", g_tpm, n);
    write_file(path, hex, 65);
}

/* Log: Spec ID (SHA-1, SHA-256), StartupLocality 3, PCR0 and PCR7 extends, a PCR9 extend (not a
 * firmware PCR, must be ignored), then zero padding. PCR files hold the matching values. */
static void build_tpm(bool with_sha256) {
    uint8_t log[1024];
    memset(log, 0, sizeof(log));
    size_t off = put32(log, 0, 0);
    off = put32(log, off, 3);                       /* EV_NO_ACTION */
    off += 20;                                      /* SHA-1 digest, zero */
    off = put32(log, off, 36);
    memcpy(log + off, "Spec ID Event03", 16);
    off += 16 + 8;                                  /* platformClass + versions */
    off = put32(log, off, 2);
    off = put16(log, off, 0x0004);
    off = put16(log, off, 20);
    off = put16(log, off, with_sha256 ? 0x000B : 0x000C);
    off = put16(log, off, with_sha256 ? 32 : 48);
    if (!with_sha256) {
        write_file(g_tpmlog, log, off);
        return;
    }
    static const char locality[] = "StartupLocality\0\x03";
    off = put_event2(log, off, 0, 3, 0x00, locality, 17);
    off = put_event2(log, off, 0, 0x80000008, 0xA1, "fw", 2);
    off = put_event2(log, off, 7, 0x800000E0, 0xB2, NULL, 0);
    off = put_event2(log, off, 9, 13, 0xC3, NULL, 0);
    write_file(g_tpmlog, log, off + 64);            /* trailing zero padding */

    uint8_t pcr[8][32];
    memset(pcr, 0, sizeof(pcr));
    pcr[0][31] = 3;
    extend(pcr[0], 0xA1);
    extend(pcr[7], 0xB2);
    char path[160];
    mkdir(g_tpm, 0755);
    snprintf(path, sizeof(path), "%s/pcr-sha256", g_tpm);
    mkdir(path, 0755);
    for (int i = 0; i < 8; i++) write_pcr(i, pcr[i]);
}

/* EFI_LOAD_OPTION with one file-path node; trunc > 0 cuts that many bytes off the end. */
static void write_boot_option(unsigned id, const char *desc, const char *path, size_t trunc) {
    uint8_t b[512];
    size_t n = 6, dlen = strlen(desc), plen = strlen(path);
    memset(b, 0, sizeof(b));
    b[0] = 1;                                          /* LOAD_OPTION_ACTIVE */
    for (size_t i = 0; i <= dlen; i++) { b[n++] = (uint8_t)desc[i]; b[n++] = 0; }
    size_t node_len = 4 + (plen + 1) * 2, fp_len = node_len + 4;
    b[4] = (uint8_t)fp_len;
    b[n] = 0x04; b[n + 1] = 0x04; b[n + 2] = (uint8_t)node_len;
    n += 4;
    for (size_t i = 0; i <= plen; i++) { b[n++] = (uint8_t)path[i]; b[n++] = 0; }
    b[n] = 0x7f; b[n + 1] = 0xff; b[n + 2] = 4;
    n += 4;
    char name[16];
    snprintf(name, sizeof(name), "Boot%04X", id);
    write_var(name, GLOBAL_GUID, b, n - trunc);
}

static void write_u16_var(const char *name, uint16_t v) {
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    write_var(name, GLOBAL_GUID, b, 2);
}

static void build_good_machine(void) {
    make_root(true, true, true);
    write_byte_var("SecureBoot", 1);
    write_byte_var("SetupMode", 0);
    write_cert_var("PK", GLOBAL_GUID, "Contoso PK", NULL);
    write_cert_var("KEK", GLOBAL_GUID, "Contoso KEK", NULL);
    write_cert_var("db", IMAGE_GUID, "Contoso CA", NULL);
    write_dbx(3);
    write_cert_var("MokListRT", SHIM_GUID, "Fedora Secure Boot CA", NULL);
    write_u16_var("BootOrder", 1);
    write_boot_option(1, "Fedora", "\\EFI\\fedora\\shimx64.efi", 0);
    write_dmar(0x04);
    write_tb_domain("1\n");
    build_intel_silicon(true, 0x2A);
    build_tpm(true);
    for (int cpu = 0; cpu < 2; cpu++) {
        write_msr(cpu, 0xFE, 1u << 11);
        write_msr(cpu, 0x1F3, 0xFF800800u);
    }
}

static void test_good_machine(void) {
    TEST_START("test_good_machine");
    build_good_machine();
    firmware_report_t r;
    booto_error_t err = firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(err, BOOTO_OK, "audit returns OK");
    ASSERT_TRUE(r.uefi_boot, "efivars dir means UEFI boot");
    for (int i = 0; i < FW_CHECK_COUNT; i++)
        ASSERT_INT_EQ(r.checks[i].result, FW_RESULT_PASS, firmware_check_name((fw_check_id_t)i));
    ASSERT_INT_EQ(r.fail_count, 0, "no failures");
    ASSERT_INT_EQ(r.unknown_count, 0, "no unknowns");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_PLATFORM_KEY].detail, "Contoso PK") != NULL, "PK CN in detail");
    ASSERT_STR_EQ(r.checks[FW_CHECK_DBX].detail, "3 revoked hashes.", "dbx count");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_IOMMU].detail, "DMAR") != NULL, "DMAR named");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_IOMMU].detail, "is set") != NULL, "opt-in flag reported");
    ASSERT_TRUE(!r.chipset_unconfirmed, "modern chipset needs no help request");
    TEST_PASS("test_good_machine");
}

static void test_mok_list(void) {
    TEST_START("test_mok_list");
    firmware_report_t r;
    build_good_machine();
    firmware_audit(&g_paths, &r);
    ASSERT_STR_EQ(r.checks[FW_CHECK_MOK].detail, "1 distro key, first \"Fedora Secure Boot CA\".", "distro MOK passes");

    write_cert_var("MokListRT", SHIM_GUID, "Evil Corp Signing", NULL);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_MOK].result, FW_RESULT_FAIL, "unknown MOK key fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_MOK].detail, "Evil Corp Signing") != NULL, "detail names the key");

    uint8_t hash[32], list[128];
    memset(hash, 0x11, sizeof(hash));
    write_var("MokListRT", SHIM_GUID, list, append_siglist(list, 0, T_SHA256, hash, sizeof(hash), 2));
    firmware_audit(&g_paths, &r);
    ASSERT_STR_EQ(r.checks[FW_CHECK_MOK].detail, "MOK list trusts 2 binary hashes without a signature.", "MOK hashes fail");

    char path[160];
    snprintf(path, sizeof(path), "%s/MokListRT-%s", g_efi, SHIM_GUID);
    unlink(path);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_MOK].result, FW_RESULT_NA, "no shim, no MOK list");
    TEST_PASS("test_mok_list");
}

static void test_boot_entry(void) {
    TEST_START("test_boot_entry");
    firmware_report_t r;
    build_good_machine();
    firmware_audit(&g_paths, &r);
    ASSERT_STR_EQ(r.checks[FW_CHECK_BOOT_ENTRY].detail, "Boots Boot0001 \"Fedora\" (\\EFI\\fedora\\shimx64.efi)",
                  "first BootOrder entry shown");

    write_u16_var("BootNext", 0x2a);
    write_boot_option(0x2a, "Updater", "\\EFI\\x\\y.efi", 0);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_BOOT_ENTRY].result, FW_RESULT_FAIL, "BootNext fails");
    ASSERT_STR_EQ(r.checks[FW_CHECK_BOOT_ENTRY].detail,
                  "BootNext is set: next boot runs Boot002A \"Updater\" (\\EFI\\x\\y.efi)", "BootNext target named");

    for (size_t t = 1; t < 40; t++) {             /* truncated options never read past the variable */
        write_boot_option(0x2a, "Updater", "\\EFI\\x\\y.efi", t);
        firmware_audit(&g_paths, &r);
    }
    ASSERT_INT_EQ(r.checks[FW_CHECK_BOOT_ENTRY].result, FW_RESULT_FAIL, "truncated option still reported");

    char path[160];
    snprintf(path, sizeof(path), "%s/BootNext-%s", g_efi, GLOBAL_GUID);
    unlink(path);
    snprintf(path, sizeof(path), "%s/BootOrder-%s", g_efi, GLOBAL_GUID);
    unlink(path);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_BOOT_ENTRY].result, FW_RESULT_NA, "no boot order is n/a");
    TEST_PASS("test_boot_entry");
}

static void test_pkfail(void) {
    TEST_START("test_pkfail");
    build_good_machine();
    write_cert_var("PK", GLOBAL_GUID, "DO NOT TRUST - AMI Test PK", NULL);
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(r.checks[FW_CHECK_TEST_KEYS].result, FW_RESULT_FAIL, "test key detected");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_TEST_KEYS].detail, "PK contains a test key (\"DO NOT TRUST\")") != NULL,
                "detail names var and marker");
    ASSERT_INT_EQ(r.checks[FW_CHECK_PLATFORM_KEY].result, FW_RESULT_PASS, "PK still enrolled");
    ASSERT_INT_EQ(r.fail_count, 1, "one failure");
    TEST_PASS("test_pkfail");
}

static void test_insecure_keys(void) {
    TEST_START("test_insecure_keys");
    make_root(true, true, true);
    write_byte_var("SecureBoot", 0);
    write_byte_var("SetupMode", 1);
    write_dbx(0);
    write_dmar(0);
    write_tb_domain("1\n");
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(r.checks[FW_CHECK_SECURE_BOOT].result, FW_RESULT_FAIL, "Secure Boot off");
    ASSERT_STR_EQ(r.checks[FW_CHECK_SECURE_BOOT].detail, "Secure Boot is off: unsigned bootloaders can run.", "SB detail");
    ASSERT_INT_EQ(r.checks[FW_CHECK_SETUP_MODE].result, FW_RESULT_FAIL, "setup mode on");
    ASSERT_INT_EQ(r.checks[FW_CHECK_PLATFORM_KEY].result, FW_RESULT_FAIL, "no PK");
    ASSERT_STR_EQ(r.checks[FW_CHECK_PLATFORM_KEY].detail, "No platform key enrolled.", "PK detail");
    ASSERT_INT_EQ(r.checks[FW_CHECK_DBX].result, FW_RESULT_FAIL, "empty dbx");
    ASSERT_STR_EQ(r.checks[FW_CHECK_DBX].detail,
                  "The revocation list is empty: known-vulnerable bootloaders can still boot.", "dbx detail");
    ASSERT_INT_EQ(r.checks[FW_CHECK_TEST_KEYS].result, FW_RESULT_PASS, "no keys, no test keys");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_IOMMU].detail, "not set") != NULL, "opt-in flag clear");
    ASSERT_INT_EQ(r.fail_count, 4, "four failures");
    TEST_PASS("test_insecure_keys");
}

static void test_bios_boot(void) {
    TEST_START("test_bios_boot");
    make_root(false, true, true);
    write_dmar(0);
    firmware_report_t r;
    booto_error_t err = firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(err, BOOTO_OK, "audit returns OK");
    ASSERT_TRUE(!r.uefi_boot, "no efivars means BIOS boot");
    for (int i = FW_CHECK_SECURE_BOOT; i <= FW_CHECK_DBX; i++) {
        ASSERT_INT_EQ(r.checks[i].result, FW_RESULT_NA, "efivar check is n/a");
        ASSERT_STR_EQ(r.checks[i].detail, "Booted in BIOS mode: no UEFI variables.", "BIOS detail");
    }
    ASSERT_INT_EQ(r.checks[FW_CHECK_IOMMU].result, FW_RESULT_PASS, "DMAR still checked");
    ASSERT_INT_EQ(r.checks[FW_CHECK_THUNDERBOLT_DMA].result, FW_RESULT_NA, "no domains");
    TEST_PASS("test_bios_boot");
}

static void test_no_iommu_no_thunderbolt(void) {
    TEST_START("test_no_iommu_no_thunderbolt");
    build_good_machine();
    char path[160];
    snprintf(path, sizeof(path), "%s/DMAR", g_acpi);
    unlink(path);
    remove_tree(g_tb);
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(r.checks[FW_CHECK_IOMMU].result, FW_RESULT_FAIL, "no DMAR/IVRS");
    ASSERT_STR_EQ(r.checks[FW_CHECK_IOMMU].detail, "Firmware describes no IOMMU: DMA attacks are not blocked.",
                  "IOMMU detail");
    ASSERT_INT_EQ(r.checks[FW_CHECK_THUNDERBOLT_DMA].result, FW_RESULT_NA, "no thunderbolt dir");
    ASSERT_STR_EQ(r.checks[FW_CHECK_THUNDERBOLT_DMA].detail, "No Thunderbolt controller.", "TB detail");
    ASSERT_INT_EQ(r.fail_count, 1, "only IOMMU fails");
    TEST_PASS("test_no_iommu_no_thunderbolt");
}

static void test_ivrs_and_tb_off(void) {
    TEST_START("test_ivrs_and_tb_off");
    build_good_machine();
    char path[160];
    snprintf(path, sizeof(path), "%s/DMAR", g_acpi);
    unlink(path);
    snprintf(path, sizeof(path), "%s/IVRS", g_acpi);
    write_file(path, "IVRS", 4);
    write_tb_domain("0\n");
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(r.checks[FW_CHECK_IOMMU].result, FW_RESULT_PASS, "IVRS present");
    ASSERT_STR_EQ(r.checks[FW_CHECK_IOMMU].detail, "AMD-Vi (IVRS).", "IVRS detail");
    ASSERT_INT_EQ(r.checks[FW_CHECK_THUNDERBOLT_DMA].result, FW_RESULT_FAIL, "TB protection off");
    TEST_PASS("test_ivrs_and_tb_off");
}

static void expect_malformed_dbx(const uint8_t *data, size_t len, const char *what) {
    make_root(true, false, false);
    write_var("dbx", IMAGE_GUID, data, len);
    write_var("PK", GLOBAL_GUID, data, len);
    firmware_report_t r;
    booto_error_t err = firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(err, BOOTO_OK, what);
    ASSERT_INT_EQ(r.checks[FW_CHECK_DBX].result, FW_RESULT_FAIL, what);
    ASSERT_STR_EQ(r.checks[FW_CHECK_DBX].detail, "Revocation list is malformed.", what);
    ASSERT_INT_EQ(r.checks[FW_CHECK_PLATFORM_KEY].result, FW_RESULT_FAIL, what);
}

static void test_garbage_siglists(void) {
    TEST_START("test_garbage_siglists");
    uint8_t hash[32], buf[256];
    memset(hash, 0x11, sizeof(hash));
    int before = g_tests_failed;

    /* Truncated: valid list cut mid-signature. */
    size_t len = append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 2);
    expect_malformed_dbx(buf, len - 10, "truncated list");

    /* Fewer than 28 header bytes left. */
    expect_malformed_dbx(buf, 20, "short header");

    /* List size smaller than the header. */
    append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    put_le32(buf + 16, 12);
    expect_malformed_dbx(buf, 48 + 28, "list size < header");

    /* Signature size 0. */
    append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    put_le32(buf + 24, 0);
    expect_malformed_dbx(buf, 48 + 28, "signature size 0");

    /* Sizes that overflow 32-bit arithmetic. */
    append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    put_le32(buf + 16, 0xffffffffu);
    expect_malformed_dbx(buf, 48 + 28, "list size overflow");
    append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    put_le32(buf + 20, 0xfffffff0u);
    expect_malformed_dbx(buf, 48 + 28, "header size overflow");
    append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    put_le32(buf + 24, 0xffffffffu);
    expect_malformed_dbx(buf, 48 + 28, "signature size overflow");

    /* Valid list followed by trailing garbage. */
    len = append_siglist(buf, 0, T_SHA256, hash, sizeof(hash), 1);
    memset(buf + len, 0xff, 7);
    expect_malformed_dbx(buf, len + 7, "trailing garbage");

    /* Pseudo-random garbage must never crash. */
    srand(1234);
    for (int iter = 0; iter < 200; iter++) {
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)rand();
        make_root(true, false, false);
        write_var("dbx", IMAGE_GUID, buf, (size_t)(rand() % (int)sizeof(buf)));
        write_var("db", IMAGE_GUID, buf, sizeof(buf));
        firmware_report_t r;
        booto_error_t err = firmware_audit(&g_paths, &r);
        remove_tree(g_root);
        ASSERT_INT_EQ(err, BOOTO_OK, "random garbage audits OK");
    }

    if (g_tests_failed == before) TEST_PASS("test_garbage_siglists");
}

static void test_intel_silicon_unlocked(void) {
    TEST_START("test_intel_silicon_unlocked");
    make_root(false, false, false);
    build_intel_silicon(false, 0x02);
    write_msr(0, 0xFE, 1u << 11);
    write_msr(0, 0x1F3, 1u << 11);
    write_msr(1, 0xFE, 1u << 11);
    write_msr(1, 0x1F3, 0);
    firmware_report_t r;
    firmware_audit(&g_paths, &r);

    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_FAIL, "D_LCK clear fails");
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMRAM_RANGE].result, FW_RESULT_FAIL, "SMRR missing on one CPU fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMRAM_RANGE].detail, "1 of 2 CPUs") != NULL, "names the CPU count");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_FAIL, "BLE without SMM_BWP fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_BIOS_WP].detail, "BIOS lock on, SMM write protection off") != NULL,
                "names the missing bit");

    /* Both locks on but BIOSWE still set: the flash is writable now. */
    build_intel_silicon(false, 0x23);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_FAIL, "BIOSWE set fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_BIOS_WP].detail, "BIOSWE") != NULL, "names BIOSWE");
    build_intel_silicon(false, 0x02);

    /* A CPU without SMRR support fails before the mask is consulted. */
    write_msr(0, 0xFE, 0);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMRAM_RANGE].result, FW_RESULT_FAIL, "no SMRR support fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMRAM_RANGE].detail, "no SMRR") != NULL, "says SMRR is unsupported");
    remove_tree(g_root);
    TEST_PASS("test_intel_silicon_unlocked");
}

static void test_amd_silicon(void) {
    TEST_START("test_amd_silicon");
    make_root(false, false, false);
    write_cpuinfo(CPUINFO_AMD);
    write_msr(0, 0xC0010015u, 1);
    write_msr(1, 0xC0010015u, 1);
    write_msr(0, 0xC0010113u, 0x3);
    write_msr(1, 0xC0010113u, 0x1);
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);

    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_PASS, "SmmLock on all CPUs passes");
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMRAM_RANGE].result, FW_RESULT_FAIL, "TValid clear on one CPU fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMRAM_RANGE].detail, "1 of 2 CPUs") != NULL, "names the CPU count");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_NA, "BIOS_CNTL is Intel only");
    TEST_PASS("test_amd_silicon");
}

static void test_silicon_unreadable(void) {
    TEST_START("test_silicon_unreadable");
    make_root(false, false, false);
    write_cpuinfo(CPUINFO_INTEL);
    write_pci("0000:00:00.0", 0x5914, 0x0600, 64, 0x3F, 0);   /* non-root sysfs view; no 00:1f.5; no msr dir */
    firmware_report_t r;
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_UNKNOWN, "64-byte config is unknown");
    ASSERT_STR_EQ(r.checks[FW_CHECK_SMM_LOCK].detail, "Needs root to read chipset registers.", "asks for root");
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMRAM_RANGE].result, FW_RESULT_UNKNOWN, "missing msr device is unknown");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMRAM_RANGE].detail, "msr kernel module") != NULL, "names the module");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_UNKNOWN, "hidden SPI controller is unknown");

    /* Fully readable registers inside a VM are still emulated: unknown, not pass. */
    build_intel_silicon(true, 0x2A);
    write_msr(0, 0xFE, 1u << 11);
    write_msr(0, 0x1F3, 1u << 11);
    write_cpuinfo(CPUINFO_VM);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    for (int i = FW_CHECK_SMM_LOCK; i <= FW_CHECK_BIOS_WP; i++)
        ASSERT_INT_EQ(r.checks[i].result, FW_RESULT_UNKNOWN, firmware_check_name((fw_check_id_t)i));
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMM_LOCK].detail, "Virtual machine") != NULL, "says why");
    TEST_PASS("test_silicon_unreadable");
}

static void test_legacy_chipsets(void) {
    TEST_START("test_legacy_chipsets");
    firmware_report_t r;

    /* Core 2 + ICH9: SMRAM at 0x9D on the memory controller hub; BIOS_CNTL on the LPC bridge without SMM_BWP. */
    make_root(false, false, false);
    write_cpuinfo("vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 23\n");
    write_pci("0000:00:00.0", 0x2E20, 0x0600, 256, 0x9D, 0x1A);   /* 0x88 stays 0: reading it would fail */
    write_pci("0000:00:1f.0", 0x2918, 0x0601, 256, 0xDC, 0x22);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_PASS, "MCH lock read at 0x9D");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMM_LOCK].detail, "0x9D") != NULL, "names the offset");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_FAIL, "ICH9 cannot block the race");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_BIOS_WP].detail, "CVE-2014-8273") != NULL, "names the race");
    ASSERT_TRUE(r.chipset_unconfirmed, "pre-2015 chipset asks for a dump");

    /* Sandy Bridge + 6 Series: SMRAMC at 0x88; BIOS_CNTL on the LPC bridge with SMM_BWP. */
    make_root(false, false, false);
    write_cpuinfo("vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 42\n");
    write_pci("0000:00:00.0", 0x0104, 0x0600, 256, 0x88, 0x1A);
    write_pci("0000:00:1f.0", 0x1C49, 0x0601, 256, 0xDC, 0x22);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_PASS, "SNB lock read at 0x88");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_PASS, "6 Series BLE + SMM_BWP passes");
    ASSERT_TRUE(r.chipset_unconfirmed, "6 Series LPC table asks for a dump");

    /* Bay Trail Atom: not in any table, so unknown rather than a guessed offset. */
    make_root(false, false, false);
    write_cpuinfo("vendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 55\n");
    write_pci("0000:00:00.0", 0x0F00, 0x0600, 256, 0x88, 0x1A);
    write_pci("0000:00:1f.0", 0x0F1C, 0x0601, 256, 0xDC, 0x22);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_SMM_LOCK].result, FW_RESULT_UNKNOWN, "unlisted CPU is unknown");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_SMM_LOCK].detail, "8086:0f00") != NULL, "names the host bridge");
    ASSERT_INT_EQ(r.checks[FW_CHECK_BIOS_WP].result, FW_RESULT_UNKNOWN, "unlisted LPC is unknown");
    ASSERT_TRUE(r.chipset_unconfirmed, "unrecognised chipset asks for a dump");
    TEST_PASS("test_legacy_chipsets");
}

static void test_tpm_log(void) {
    TEST_START("test_tpm_log");
    firmware_report_t r;

    make_root(false, false, false);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_TPM_LOG].result, FW_RESULT_NA, "no TPM is n/a");

    build_tpm(true);
    unlink(g_tpmlog);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_TPM_LOG].result, FW_RESULT_UNKNOWN, "missing log is unknown, never a pass");

    /* One PCR that does not match its replayed value fails and is named. */
    build_tpm(true);
    uint8_t wrong[32];
    memset(wrong, 0x5A, sizeof(wrong));
    write_pcr(7, wrong);
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_TPM_LOG].result, FW_RESULT_FAIL, "PCR mismatch fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_TPM_LOG].detail, "PCR 7 ") != NULL, "names the PCR");

    /* A log cut inside an event is malformed. */
    build_tpm(true);
    FILE *fp = fopen(g_tpmlog, "r+b");
    if (fp) {
        if (ftruncate(fileno(fp), 150) != 0) perror("ftruncate");
        fclose(fp);
    }
    firmware_audit(&g_paths, &r);
    ASSERT_INT_EQ(r.checks[FW_CHECK_TPM_LOG].result, FW_RESULT_FAIL, "truncated log fails");
    ASSERT_TRUE(strstr(r.checks[FW_CHECK_TPM_LOG].detail, "malformed") != NULL, "says malformed");

    build_tpm(false);
    firmware_audit(&g_paths, &r);
    remove_tree(g_root);
    ASSERT_INT_EQ(r.checks[FW_CHECK_TPM_LOG].result, FW_RESULT_UNKNOWN, "no SHA-256 bank is unknown");
    TEST_PASS("test_tpm_log");
}

static void test_real_host(void) {
    TEST_START("test_real_host");
    firmware_report_t r;
    ASSERT_INT_EQ(firmware_audit(NULL, NULL), BOOTO_ERR_INVALID_ARG, "NULL out rejected");
    ASSERT_INT_EQ(firmware_audit(NULL, &r), BOOTO_OK, "real host audit returns OK");
    for (int i = 0; i < FW_CHECK_COUNT; i++) {
        ASSERT_TRUE(r.checks[i].detail[0] != '\0', firmware_check_name((fw_check_id_t)i));
        ASSERT_TRUE(strcmp(firmware_result_str(r.checks[i].result), "?") != 0, "valid result");
    }
    TEST_PASS("test_real_host");
}

static void fill_random(uint8_t *d, size_t n) {
    uint32_t x = 0x9e3779b9u;
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        d[i] = (uint8_t)x;
    }
}

static const fw_nvram_finding_t *nvram_find(const fw_nvram_report_t *r, const char *prefix) {
    for (int i = 0; i < r->count; i++)
        if (strncmp(r->findings[i].name, prefix, strlen(prefix)) == 0) return &r->findings[i];
    return NULL;
}

static void test_nvram_scan(void) {
    TEST_START("test_nvram_scan");
    make_root(true, false, false);
    static uint8_t big[16384];
    char path[256];

    write_var("BootOrder", GLOBAL_GUID, (const uint8_t *)"\x01\x00\x02\x00", 4);
    uint8_t pe[256] = { 0 };
    memcpy(pe + 32, "MZ", 2);                 /* image hidden at an offset, not at byte 0 */
    put_le32(pe + 32 + 0x3c, 0x80);
    memcpy(pe + 32 + 0x80, "PE\0\0", 4);
    write_var("Payload", GLOBAL_GUID, pe, sizeof(pe));
    uint8_t mz_only[128] = { 'M', 'Z' };      /* "MZ" with no PE header is just data */
    write_var("Text", GLOBAL_GUID, mz_only, sizeof(mz_only));
    uint8_t elf[128] = { 0x7f, 'E', 'L', 'F' };
    write_var("Implant", GLOBAL_GUID, elf, sizeof(elf));

    memset(big, 0, 4);
    fill_random(big + 4, 8192);
    snprintf(path, sizeof(path), "%s/Blob-%s", g_efi, GLOBAL_GUID);
    write_file(path, big, 4 + 8192);

    static uint8_t cert[8192];               /* certificates look random too; a signature list must pass */
    fill_random(cert, sizeof(cert));
    size_t len = append_siglist(big, 4, T_X509, cert, sizeof(cert), 1);
    snprintf(path, sizeof(path), "%s/db-%s", g_efi, IMAGE_GUID);
    write_file(path, big, len);

    fw_nvram_report_t r;
    ASSERT_INT_EQ(firmware_nvram_scan(g_efi, &r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r.vars_scanned, 6, "Every variable is read");
    ASSERT_INT_EQ(r.count, 3, "Only the three hiding code are flagged");
    const fw_nvram_finding_t *f = nvram_find(&r, "Payload-");
    ASSERT_TRUE(f && strstr(f->reason, "PE"), "Embedded PE flagged");
    f = nvram_find(&r, "Implant-");
    ASSERT_TRUE(f && strstr(f->reason, "ELF"), "ELF flagged");
    f = nvram_find(&r, "Blob-");
    ASSERT_TRUE(f && f->size == 8192, "Random blob flagged with its size");
    ASSERT_TRUE(nvram_find(&r, "db-") == NULL, "Signature database is not flagged");

    ASSERT_INT_EQ(firmware_nvram_scan("/nonexistent/efivars", &r), BOOTO_ERR_NOT_FOUND, "Missing dir reported");
    remove_tree(g_root);
    TEST_PASS("test_nvram_scan");
}

static void test_spi_dump(void) {
    TEST_START("test_spi_dump");
    make_root(false, false, false);
    char tool[128], image[128], oldpath[4096], newpath[4352];
    snprintf(tool, sizeof(tool), "%s/flashrom", g_root);
    snprintf(image, sizeof(image), "%s/spi.bin", g_root);
    static const char script[] = "#!/bin/sh\n[ \"$1 $2 $3\" = \"-p internal -r\" ] || exit 1\nprintf flash > \"$4\"\n";
    write_file(tool, script, strlen(script));
    chmod(tool, 0755);
    snprintf(oldpath, sizeof(oldpath), "%s", getenv("PATH") ? getenv("PATH") : "/usr/bin:/bin");
    snprintf(newpath, sizeof(newpath), "%s:%s", g_root, oldpath);
    setenv("PATH", newpath, 1);

    char hex[65], want[65];
    bool bios_only = true;
    booto_error_t e = firmware_spi_dump(image, hex, &bios_only);
    sha256_buffer_hex((const uint8_t *)"flash", 5, want);
    ASSERT_INT_EQ(e, BOOTO_OK, "Dump succeeds with read-only flags");
    ASSERT_STR_EQ(hex, want, "Image is hashed");
    ASSERT_TRUE(!bios_only, "Full read is not marked BIOS-only");

    static const char locked[] = "#!/bin/sh\n[ \"$3 $4 $5 $6\" = \"--ifd -i bios -r\" ] || exit 1\nprintf flash > \"$7\"\n";
    write_file(tool, locked, strlen(locked));
    ASSERT_INT_EQ(firmware_spi_dump(image, hex, &bios_only), BOOTO_OK, "Locked chipset falls back to the BIOS region");
    ASSERT_TRUE(bios_only, "Fallback read is marked BIOS-only");
    ASSERT_STR_EQ(hex, want, "BIOS region is hashed");

    static const char failing[] = "#!/bin/sh\nexit 1\n";
    write_file(tool, failing, strlen(failing));
    ASSERT_INT_EQ(firmware_spi_dump(image, hex, &bios_only), BOOTO_ERR_IO, "flashrom failure is IO error");
    ASSERT_TRUE(hex[0] == '\0', "No hash on failure");

    setenv("PATH", g_root, 1);
    unlink(tool);
    ASSERT_INT_EQ(firmware_spi_dump(image, hex, &bios_only), BOOTO_ERR_NOT_FOUND, "Missing flashrom reported");
    setenv("PATH", oldpath, 1);
    remove_tree(g_root);
    TEST_PASS("test_spi_dump");
}

static void put_pe(uint8_t *at, uint16_t subsystem) {
    at[0] = 'M'; at[1] = 'Z'; at[0x3c] = 0x40;
    memcpy(at + 0x40, "PE\0\0", 4);
    at[0x40 + 24 + 68] = (uint8_t)subsystem;
}

static void test_spi_analyze(void) {
    TEST_START("test_spi_analyze");
    make_root(false, false, false);
    static uint8_t img[8192];
    memset(img, 0xff, sizeof(img));
    memcpy(img + 40, "_FVH", 4);
    memset(img + 512, 0, 256);
    put_pe(img + 512, 10);   /* EFI application: normal */

    uint8_t win[256] = { 0 };
    put_pe(win, 3);          /* Windows console binary hidden in an LZMA section */
    const char *const xz[] = { "xz", "--format=lzma", "-c", NULL };
    uint8_t *packed = NULL;
    size_t packed_len = 0;
    ASSERT_INT_EQ(disk_exec_capture(xz, win, sizeof(win), &packed, &packed_len, 4096), BOOTO_OK, "xz compresses test PE");
    static const uint8_t guid[16] = { 0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42,
                                      0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf };
    uint8_t *sec = img + 2048;
    size_t sec_len = 24 + packed_len;
    sec[0] = (uint8_t)sec_len; sec[1] = (uint8_t)(sec_len >> 8); sec[2] = 0; sec[3] = 0x02;
    memcpy(sec + 4, guid, 16);
    sec[20] = 24; sec[21] = 0; sec[22] = 1; sec[23] = 0;
    memcpy(sec + 24, packed, packed_len);
    free(packed);

    char path[128];
    snprintf(path, sizeof(path), "%s/spi.bin", g_root);
    write_file(path, img, sizeof(img));
    fw_spi_report_t r;
    ASSERT_INT_EQ(firmware_spi_analyze(path, &r), BOOTO_OK, "Image analyzed");
    ASSERT_INT_EQ(r.volumes, 1, "Firmware volume counted");
    ASSERT_INT_EQ(r.lzma_sections, 1, "LZMA section found");
    ASSERT_INT_EQ(r.lzma_inflated, 1, "LZMA section inflated");
    ASSERT_INT_EQ(r.pe_images, 2, "Raw and inflated PE counted");
    ASSERT_INT_EQ(r.windows_pe, 1, "Only the Windows PE is flagged");

    /* A section whose size runs past the image, or a corrupt stream, is skipped in bounds (ASan checks). */
    sec[1] = 0x7f;
    write_file(path, img, sizeof(img));
    ASSERT_INT_EQ(firmware_spi_analyze(path, &r), BOOTO_OK, "Oversized section tolerated");
    ASSERT_INT_EQ(r.lzma_sections, 0, "Oversized section not inflated");
    sec[1] = (uint8_t)(sec_len >> 8);
    sec[30] ^= 0xff;
    write_file(path, img, sizeof(img));
    ASSERT_INT_EQ(firmware_spi_analyze(path, &r), BOOTO_OK, "Corrupt stream tolerated");

    ASSERT_INT_EQ(firmware_spi_analyze("/nonexistent/spi.bin", &r), BOOTO_ERR_IO, "Missing image reported");
    remove_tree(g_root);
    TEST_PASS("test_spi_analyze");
}

int main(void) {
    printf("\n--- Running Firmware Auditor Tests ---\n");
    test_good_machine();
    test_pkfail();
    test_mok_list();
    test_boot_entry();
    test_insecure_keys();
    test_bios_boot();
    test_no_iommu_no_thunderbolt();
    test_ivrs_and_tb_off();
    test_garbage_siglists();
    test_intel_silicon_unlocked();
    test_amd_silicon();
    test_silicon_unreadable();
    test_legacy_chipsets();
    test_tpm_log();
    test_real_host();
    test_nvram_scan();
    test_spi_dump();
    test_spi_analyze();
    TEST_SUMMARY();
    return 0;
}
