/**
 * @file test_firmware_auditor.c
 * @brief Unit tests for the host firmware audit on fake efivars/ACPI/Thunderbolt trees.
 */
#include "test_framework.h"
#include "firmware_auditor.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define IMAGE_GUID  "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

static const uint8_t T_SHA256[16] = {
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40,
    0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28
};
static const uint8_t T_X509[16] = {
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72
};

static char g_root[64];
static char g_efi[96], g_acpi[96], g_tb[96], g_cpuinfo[96], g_msr[96], g_pci[96];
static firmware_paths_t g_paths;

#define CPUINFO_INTEL "vendor_id\t: GenuineIntel\nflags\t\t: fpu vme msr\n"
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

/* Intel PCI function config space of `len` bytes with byte `off` = val. */
static void write_pci(const char *bdf, uint16_t class_code, size_t len, size_t off, uint8_t val) {
    uint8_t cfg[256];
    memset(cfg, 0, sizeof(cfg));
    cfg[0] = 0x86;
    cfg[1] = 0x80;
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
    write_pci("0000:00:00.0", 0x0600, 256, 0x88, d_lck ? 0x1A : 0x0A);
    write_pci("0000:00:1f.5", 0x0C80, 256, 0xDC, bios_cntl);
}

static void build_good_machine(void) {
    make_root(true, true, true);
    write_byte_var("SecureBoot", 1);
    write_byte_var("SetupMode", 0);
    write_cert_var("PK", GLOBAL_GUID, "Contoso PK", NULL);
    write_cert_var("KEK", GLOBAL_GUID, "Contoso KEK", NULL);
    write_cert_var("db", IMAGE_GUID, "Contoso CA", NULL);
    write_dbx(3);
    write_dmar(0x04);
    write_tb_domain("1\n");
    build_intel_silicon(true, 0x2A);
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
    TEST_PASS("test_good_machine");
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
    write_pci("0000:00:00.0", 0x0600, 64, 0x3F, 0);   /* non-root sysfs view; no 00:1f.5; no msr dir */
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

int main(void) {
    printf("\n--- Running Firmware Auditor Tests ---\n");
    test_good_machine();
    test_pkfail();
    test_insecure_keys();
    test_bios_boot();
    test_no_iommu_no_thunderbolt();
    test_ivrs_and_tb_off();
    test_garbage_siglists();
    test_intel_silicon_unlocked();
    test_amd_silicon();
    test_silicon_unreadable();
    test_real_host();
    TEST_SUMMARY();
    return 0;
}
