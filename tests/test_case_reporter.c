/**
 * @file test_case_reporter.c
 * @brief Unit tests for cryptographic forensic case report generation (JSON & Markdown).
 */
#include "test_framework.h"
#include "case_reporter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_report_generation(void) {
    TEST_START("test_report_generation");

    system("mkdir -p /tmp/test_booto_cases");

    forensic_case_summary_t sum;
    memset(&sum, 0, sizeof(sum));
    snprintf(sum.case_id, sizeof(sum.case_id), "TEST-CASE-001");
    snprintf(sum.timestamp, sizeof(sum.timestamp), "2026-09-01 23:30:00 UTC");
    snprintf(sum.target_disk, sizeof(sum.target_disk), "/dev/nvme0n1p2");
    snprintf(sum.target_fs, sizeof(sum.target_fs), "ext4");
    snprintf(sum.examiner, sizeof(sum.examiner), "Unit Test Examiner");
    sum.kernel_threats_count = 1;
    sum.uefi_threats_count = 0;
    sum.initramfs_threats_count = 0;
    sum.preload_threats_count = 1;
    sum.ext4_hidden_inodes_count = 1;
    sum.total_threats = 3;
    snprintf(sum.highest_severity, sizeof(sum.highest_severity), "CRITICAL");

    char json_path[512];
    booto_error_t j_err = case_report_generate_json(&sum, "/tmp/test_booto_cases", json_path, sizeof(json_path));
    ASSERT_INT_EQ(j_err, BOOTO_OK, "JSON generation must return BOOTO_OK");
    ASSERT_TRUE(strstr(json_path, "TEST-CASE-001.json") != NULL, "JSON filename must match Case ID");

    char md_path[512];
    booto_error_t m_err = case_report_generate_markdown(&sum, "/tmp/test_booto_cases", md_path, sizeof(md_path));
    ASSERT_INT_EQ(m_err, BOOTO_OK, "Markdown generation must return BOOTO_OK");
    ASSERT_TRUE(strstr(md_path, "TEST-CASE-001.md") != NULL, "Markdown filename must match Case ID");

    char seal[65];
    booto_error_t s_err = case_report_sign_and_seal(md_path, seal);
    ASSERT_INT_EQ(s_err, BOOTO_OK, "Seal computation must return BOOTO_OK");
    ASSERT_TRUE(strlen(seal) == 64, "SHA-256 seal must be 64 characters");

    system("rm -rf /tmp/test_booto_cases");
    TEST_PASS("test_report_generation");
}

int main(void) {
    printf("\n--- Running Cryptographic Case Reporter Tests ---\n");
    test_report_generation();
    TEST_SUMMARY();
    return 0;
}
