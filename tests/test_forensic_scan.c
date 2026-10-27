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
    ASSERT_INT_EQ(r->status[SCAN_MOD_UEFI], SCAN_STATUS_OK, "UEFI must run");
    ASSERT_INT_EQ(r->total_threats, 0, "Empty rootfs has no threats");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_CLEAN, "Empty rootfs with all runnable engines OK is CLEAN");

    forensic_case_summary_t sum;
    forensic_scan_fill_case_summary(r, "CASE-T", "tester", &sum);
    ASSERT_STR_EQ(sum.verdict, "CLEAN", "Summary verdict");
    ASSERT_STR_EQ(sum.module_status[SCAN_MOD_MBR], "SKIPPED", "Summary module status");
    free(r);
    TEST_PASS("test_rootfs_dir_scan");
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
    if (geteuid() != 0) test_mount_failure_never_clean();
    test_all_disabled();
    test_invalid_args();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_root);
    TEST_SUMMARY();
    return 0;
}
