/**
 * @file test_forensic_scan.c
 * @brief Unit tests for the scan orchestrator: honest statuses and verdicts.
 */
#include "test_framework.h"
#include "forensic_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[] = "/tmp/test_booto_scan_XXXXXX";

static void mk(const char *rel) {
    char p[256];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    mkdir(p, 0700);
}

static void build_rootfs(void) {
    mk("etc");
    mk("lib");
    mk("lib/modules");
    mk("boot");
    mk("boot/efi");
    char p[256];
    snprintf(p, sizeof(p), "%s/etc/ld.so.preload", g_root);
    FILE *fp = fopen(p, "w");
    if (fp) fclose(fp);
}

static void test_rootfs_dir_scan(void) {
    TEST_START("test_rootfs_dir_scan");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, NULL, NULL, NULL, r), BOOTO_OK, "Scan must run");
    ASSERT_INT_EQ(r->mount_err, BOOTO_OK, "rootfs_dir needs no mount");
    ASSERT_TRUE(!r->mounted, "rootfs_dir must not be mounted");
    ASSERT_INT_EQ(r->status[SCAN_MOD_MBR], SCAN_STATUS_SKIPPED, "MBR skipped without raw device");
    ASSERT_INT_EQ(r->status[SCAN_MOD_EXT4], SCAN_STATUS_SKIPPED, "EXT4 skipped without raw device");
    ASSERT_INT_EQ(r->status[SCAN_MOD_INITRAMFS], SCAN_STATUS_SKIPPED, "Initramfs skipped when absent");
    ASSERT_INT_EQ(r->status[SCAN_MOD_PRELOAD], SCAN_STATUS_OK, "Preload must run");
    ASSERT_INT_EQ(r->status[SCAN_MOD_KERNEL], SCAN_STATUS_OK, "Kernel must run");
    ASSERT_INT_EQ(r->status[SCAN_MOD_UEFI], SCAN_STATUS_SKIPPED, "Empty boot/efi and no raw device: UEFI skipped");
    ASSERT_STR_EQ(r->note[SCAN_MOD_UEFI], "no EFI system partition found", "UEFI skip reason");
    ASSERT_STR_EQ(r->esp_dev, "", "No ESP recorded");
    ASSERT_INT_EQ(r->total_threats, 0, "Empty rootfs has no threats");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_CLEAN, "Engines that ran are OK, the rest honestly SKIPPED: CLEAN");

    forensic_case_summary_t sum;
    forensic_scan_fill_case_summary(r, "CASE-T", "tester", &sum);
    ASSERT_STR_EQ(sum.verdict, "CLEAN", "Summary verdict");
    ASSERT_STR_EQ(sum.module_status[SCAN_MOD_MBR], "SKIPPED", "Summary module status");
    free(r);
    TEST_PASS("test_rootfs_dir_scan");
}

/* Minimal signed-shaped PE32+ (copied from test_uefi_analyzer.c build_pe): headers 0x200, one 0x100 section, 0x80 cert table. */
static size_t build_pe(uint8_t *b, size_t cap) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    b[coff] = 0x64; b[coff + 1] = 0x86;
    b[coff + 2] = 1;                               // NumberOfSections
    b[coff + 16] = 0xF0;                           // SizeOfOptionalHeader
    b[opt] = 0x0b; b[opt + 1] = 0x02;
    b[opt + 60] = 0x00; b[opt + 61] = 0x02;        // SizeOfHeaders = 0x200
    b[opt + 64] = 0x11; b[opt + 65] = 0x22;        // CheckSum
    b[opt + 68] = 10;
    b[opt + 108] = 16;                             // NumberOfRvaAndSizes
    size_t sect = opt + 0xF0;
    b[sect + 17] = 0x01;                           // SizeOfRawData = 0x100
    b[sect + 21] = 0x02;                           // PointerToRawData = 0x200
    for (size_t i = 0x200; i < 0x300; i++) b[i] = (uint8_t)i;
    size_t dir = opt + 112 + 32;
    b[dir + 1] = 0x03;                             // cert table at file offset 0x300
    b[dir + 4] = 0x80;
    memset(b + 0x300, 0xC5, 0x80);
    return 0x380;
}

static void test_rootfs_esp_used(void) {
    TEST_START("test_rootfs_esp_used");
    mk("boot/efi/EFI");
    mk("boot/efi/EFI/BOOT");
    uint8_t pe[0x400];
    size_t len = build_pe(pe, sizeof(pe));
    char p[256];
    snprintf(p, sizeof(p), "%s/boot/efi/EFI/BOOT/BOOTX64.EFI", g_root);
    FILE *fp = fopen(p, "wb");
    ASSERT_TRUE(fp != NULL, "Create BOOTX64.EFI");
    size_t wr = fwrite(pe, 1, len, fp);
    fclose(fp);
    ASSERT_TRUE(wr == len, "Write BOOTX64.EFI");

    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, NULL, NULL, NULL, r), BOOTO_OK, "Scan must run");
    ASSERT_INT_EQ(r->status[SCAN_MOD_UEFI], SCAN_STATUS_OK, "UEFI runs on the rootfs ESP");
    ASSERT_INT_EQ(r->uefi.efi_files_scanned, 1, "One EFI file scanned");
    size_t n = strlen(r->esp_dev);
    ASSERT_TRUE(n >= 9 && strcmp(r->esp_dev + n - 9, "/boot/efi") == 0, "esp_dev is <root>/boot/efi");
    free(r);
    unlink(p);
    TEST_PASS("test_rootfs_esp_used");
}

static void test_unreadable_partition_table(void) {
    TEST_START("test_unreadable_partition_table");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run("/nonexistent/disk", NULL, NULL, NULL, NULL, r), BOOTO_OK, "Scan must run");
    ASSERT_INT_EQ(r->status[SCAN_MOD_UEFI], SCAN_STATUS_ERROR, "Unreadable partition table: UEFI error");
    ASSERT_TRUE(strncmp(r->note[SCAN_MOD_UEFI], "cannot read partition table:", 28) == 0, "UEFI error reason");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_INCOMPLETE, "UEFI error must be INCOMPLETE");
    free(r);
    TEST_PASS("test_unreadable_partition_table");
}

static void test_mount_failure_never_clean(void) {
    TEST_START("test_mount_failure_never_clean");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run("/nonexistent/dev", NULL, NULL, NULL, NULL, r), BOOTO_OK, "Scan must run");
    ASSERT_TRUE(r->mount_err != BOOTO_OK, "Mounting a nonexistent device must fail");
    ASSERT_TRUE(!r->mounted, "Nothing mounted");
    ASSERT_INT_EQ(r->status[SCAN_MOD_UEFI], SCAN_STATUS_ERROR, "UEFI error without rootfs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_KERNEL], SCAN_STATUS_ERROR, "Kernel error without rootfs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_INITRAMFS], SCAN_STATUS_ERROR, "Initramfs error without rootfs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_PRELOAD], SCAN_STATUS_ERROR, "Preload error without rootfs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_MBR], SCAN_STATUS_ERROR, "MBR error on missing device");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_INCOMPLETE, "Failed mount must be INCOMPLETE");
    free(r);
    TEST_PASS("test_mount_failure_never_clean");
}

static void test_all_disabled(void) {
    TEST_START("test_all_disabled");
    bool enabled[SCAN_MOD_COUNT] = {false};
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, enabled, NULL, NULL, r), BOOTO_OK, "Scan must run");
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        ASSERT_INT_EQ(r->status[i], SCAN_STATUS_SKIPPED, "Disabled module must be SKIPPED");
    }
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_INCOMPLETE, "Nothing ran -> INCOMPLETE");
    free(r);
    TEST_PASS("test_all_disabled");
}

static void test_invalid_args(void) {
    TEST_START("test_invalid_args");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, NULL, NULL, NULL, NULL, r), BOOTO_ERR_INVALID_ARG, "No target is invalid");
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, NULL, NULL, NULL, NULL), BOOTO_ERR_INVALID_ARG, "NULL out is invalid");
    free(r);
    TEST_PASS("test_invalid_args");
}

int main(void) {
    printf("\n--- Running Forensic Scan Orchestrator Tests ---\n");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        return 1;
    }
    build_rootfs();
    test_rootfs_dir_scan();
    if (geteuid() != 0) {
        test_mount_failure_never_clean();
        test_unreadable_partition_table();
    }
    test_rootfs_esp_used();
    test_all_disabled();
    test_invalid_args();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_root);
    TEST_SUMMARY();
    return 0;
}
