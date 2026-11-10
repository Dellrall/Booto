/**
 * @file test_windows_boot.c
 * @brief Windows boot engine: root detection by any case, core files need a Microsoft signature.
 */
#include "test_framework.h"
#include "forensic_scan.h"
#include "windows_boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[] = "/tmp/test_booto_win_XXXXXX";

/* Minimal PE32+; with_cert adds a garbage certificate table, so its signature does not verify. */
static size_t build_pe(uint8_t *b, size_t cap, bool with_cert) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    b[coff] = 0x64; b[coff + 1] = 0x86;
    b[coff + 2] = 1;
    b[coff + 16] = 0xF0;
    b[opt] = 0x0b; b[opt + 1] = 0x02;
    b[opt + 61] = 0x02;                            // SizeOfHeaders = 0x200
    b[opt + 68] = 1;                               // IMAGE_SUBSYSTEM_NATIVE
    b[opt + 108] = 16;
    size_t sect = opt + 0xF0;
    b[sect + 17] = 0x01;
    b[sect + 21] = 0x02;
    for (size_t i = 0x200; i < 0x300; i++) b[i] = (uint8_t)i;
    if (!with_cert) return 0x300;
    size_t dir = opt + 112 + 32;
    b[dir + 1] = 0x03;
    b[dir + 4] = 0x80;
    memset(b + 0x300, 0xC5, 0x80);
    return 0x380;
}

static void put(const char *rel, const uint8_t *data, size_t len) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    FILE *fp = fopen(p, "wb");
    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
    }
}

static void mk(const char *rel) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    mkdir(p, 0700);
}

static bool has_finding(const winboot_scan_result_t *r, const char *file, const char *reason) {
    for (int i = 0; i < r->threats_detected; i++)
        if (strstr(r->findings[i].file_path, file) && strstr(r->findings[i].reason, reason)) return true;
    return false;
}

static void test_windows_root(void) {
    TEST_START("test_windows_root");
    ASSERT_TRUE(!winboot_is_windows_root(g_root), "Empty dir is not Windows");
    mk("WINDOWS");
    mk("WINDOWS/system32");
    mk("WINDOWS/system32/Drivers");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), false);
    put("WINDOWS/system32/NTOSKRNL.EXE", b, len);
    ASSERT_TRUE(winboot_is_windows_root(g_root), "Names match in any case");
    TEST_PASS("test_windows_root");
}

static void test_scan(void) {
    TEST_START("test_scan");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), false);
    put("WINDOWS/system32/Drivers/plain.sys", b, len);
    put("WINDOWS/system32/hal.dll", (const uint8_t *)"not a PE image", 14);
    len = build_pe(b, sizeof(b), true);
    put("WINDOWS/system32/Drivers/broken.SYS", b, len);
    put("WINDOWS/system32/Drivers/notes.txt", b, len);

    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r->files_checked, 4, "ntoskrnl, hal and two drivers checked; .txt ignored");
    ASSERT_TRUE(has_finding(r, "NTOSKRNL.EXE", "no embedded signature"), "Unsigned kernel flagged");
    ASSERT_TRUE(has_finding(r, "hal.dll", "not a valid PE"), "Non-PE core file flagged");
    ASSERT_TRUE(has_finding(r, "broken.SYS", "does not verify"), "Broken driver signature flagged");
    ASSERT_INT_EQ(r->threats_detected, 3, "Unsigned driver is not a finding");
    ASSERT_INT_EQ(r->drivers_unsigned, 1, "Unsigned driver counted");
    ASSERT_INT_EQ(winboot_scan_rootfs("/nonexistent", r), BOOTO_ERR_NOT_FOUND, "No Windows dir");
    free(r);
    TEST_PASS("test_scan");
}

/* Crypto-agile TCG log: Spec ID (SHA-256 only), then one EFI application event whose digest is `fill`. */
static size_t build_log(uint8_t *b, uint8_t fill) {
    memset(b, 0, 256);
    b[4] = 3;                                         // EV_NO_ACTION
    b[28] = 32;                                       // Spec ID event size
    memcpy(b + 32, "Spec ID Event03", 16);
    b[56] = 1;                                        // one algorithm
    b[60] = 0x0B; b[62] = 32;                         // SHA-256, 32 bytes
    size_t off = 64;
    b[off + 0] = 4;                                   // PCR 4
    b[off + 4] = 0x03; b[off + 7] = 0x80;             // EV_EFI_BOOT_SERVICES_APPLICATION
    b[off + 8] = 1;                                   // one digest
    b[off + 12] = 0x0B;
    memset(b + off + 14, fill, 32);
    return off + 14 + 32 + 4;                         // empty event data
}

static void test_measured_boot(void) {
    TEST_START("test_measured_boot");
    bool found = true;
    char name[64];
    ASSERT_INT_EQ(winboot_measured_has(g_root, "ab", &found, name, sizeof(name)), BOOTO_ERR_NOT_FOUND, "No log dir");
    mk("WINDOWS/Logs");
    mk("WINDOWS/Logs/MeasuredBoot");
    uint8_t b[256];
    size_t len = build_log(b, 0x11);
    put("WINDOWS/Logs/MeasuredBoot/0000000001-0000000000.log", b, len);
    len = build_log(b, 0xAB);
    put("WINDOWS/Logs/MeasuredBoot/0000000002-0000000000.log", b, len);

    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "ab");
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_OK, "Newest log parses");
    ASSERT_TRUE(found, "Hash measured by the last boot is found");
    ASSERT_STR_EQ(name, "0000000002-0000000000.log", "Newest log is used");
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "11");
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_OK, "Newest log parses");
    ASSERT_TRUE(!found, "Hash from an older boot only is not found");

    put("WINDOWS/Logs/MeasuredBoot/0000000003-0000000000.log", b, 40);
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_ERR_CORRUPT_DATA,
                  "Truncated log is malformed");
    TEST_PASS("test_measured_boot");
}

static void test_orchestrator(void) {
    TEST_START("test_orchestrator");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, NULL, NULL, NULL, NULL, r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_WINBOOT], SCAN_STATUS_OK, "Windows engine ran");
    ASSERT_INT_EQ(r->status[SCAN_MOD_KERNEL], SCAN_STATUS_SKIPPED, "Linux kernel engine skipped");
    ASSERT_INT_EQ(r->status[SCAN_MOD_PKG], SCAN_STATUS_SKIPPED, "Package engine skipped");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_THREATS, "Findings give THREATS");
    ASSERT_INT_EQ(forensic_scan_module_threats(r, SCAN_MOD_WINBOOT), 3, "Threats counted");
    free(r);
    TEST_PASS("test_orchestrator");
}

int main(void) {
    printf("\n--- Running Windows Boot Engine Tests ---\n");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        return 1;
    }
    test_windows_root();
    test_scan();
    test_orchestrator();
    test_measured_boot();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_root);
    TEST_SUMMARY();
    return 0;
}
