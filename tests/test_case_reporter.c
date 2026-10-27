/**
 * @file test_case_reporter.c
 * @brief Unit tests for forensic case report generation (JSON & Markdown).
 */
#include "test_framework.h"
#include "case_reporter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_dir[] = "/tmp/test_booto_cases_XXXXXX";

static void fill_summary(forensic_case_summary_t *sum, const char *case_id) {
    memset(sum, 0, sizeof(*sum));
    snprintf(sum->case_id, sizeof(sum->case_id), "%s", case_id);
    snprintf(sum->timestamp, sizeof(sum->timestamp), "2026-09-01 23:30:00 UTC");
    snprintf(sum->target_disk, sizeof(sum->target_disk), "/dev/nvme0n1p2");
    snprintf(sum->target_fs, sizeof(sum->target_fs), "ext4");
    snprintf(sum->examiner, sizeof(sum->examiner), "Unit Test Examiner");
    sum->mbr_threats_count = 1;
    sum->total_threats = 1;
    snprintf(sum->highest_severity, sizeof(sum->highest_severity), "CRITICAL");
}

static void slurp(const char *path, char *buf, size_t size) {
    buf[0] = '\0';
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    size_t n = fread(buf, 1, size - 1, fp);
    buf[n] = '\0';
    fclose(fp);
}

static void test_report_generation(void) {
    TEST_START("test_report_generation");
    forensic_case_summary_t sum;
    fill_summary(&sum, "TEST-CASE-001");

    char json_path[512];
    ASSERT_INT_EQ(case_report_generate_json(&sum, g_dir, json_path, sizeof(json_path)), BOOTO_OK, "JSON generation must return BOOTO_OK");
    ASSERT_TRUE(strstr(json_path, "case_TEST-CASE-001.json") != NULL, "JSON filename must match Case ID");

    char md_path[512];
    ASSERT_INT_EQ(case_report_generate_markdown(&sum, g_dir, md_path, sizeof(md_path)), BOOTO_OK, "Markdown generation must return BOOTO_OK");

    char seal[65];
    ASSERT_INT_EQ(case_report_sign_and_seal(md_path, seal), BOOTO_OK, "Seal computation must return BOOTO_OK");
    ASSERT_TRUE(strlen(seal) == 64, "SHA-256 seal must be 64 characters");
    TEST_PASS("test_report_generation");
}

static void test_json_and_markdown_escaping(void) {
    TEST_START("test_json_and_markdown_escaping");
    forensic_case_summary_t sum;
    fill_summary(&sum, "ESC-1");
    snprintf(sum.examiner, sizeof(sum.examiner), "a\"b\\c\nd|e`f");

    char path[512], buf[4096];
    ASSERT_INT_EQ(case_report_generate_json(&sum, g_dir, path, sizeof(path)), BOOTO_OK, "JSON generation must succeed");
    slurp(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"examiner\": \"a\\\"b\\\\c\\nd|e`f\"") != NULL, "JSON must escape quote, backslash and newline");

    ASSERT_INT_EQ(case_report_generate_markdown(&sum, g_dir, path, sizeof(path)), BOOTO_OK, "Markdown generation must succeed");
    slurp(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "`a\"b\\c d\\|e'f`") != NULL, "Markdown cell must neutralise newline, pipe and backtick");
    TEST_PASS("test_json_and_markdown_escaping");
}

static void test_unsafe_case_id_rejected(void) {
    TEST_START("test_unsafe_case_id_rejected");
    const char *bad[] = {"../../etc/x", "a/b", "", "has space"};
    char path[512];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        forensic_case_summary_t sum;
        fill_summary(&sum, bad[i]);
        ASSERT_INT_EQ(case_report_generate_json(&sum, g_dir, path, sizeof(path)), BOOTO_ERR_INVALID_ARG, "Unsafe case ID must be rejected (JSON)");
        ASSERT_INT_EQ(case_report_generate_markdown(&sum, g_dir, path, sizeof(path)), BOOTO_ERR_INVALID_ARG, "Unsafe case ID must be rejected (MD)");
    }
    TEST_PASS("test_unsafe_case_id_rejected");
}

static void test_unwritable_dir_fails(void) {
    TEST_START("test_unwritable_dir_fails");
    forensic_case_summary_t sum;
    fill_summary(&sum, "NODIR");
    char path[512];
    ASSERT_INT_EQ(case_report_generate_json(&sum, "/nonexistent/booto", path, sizeof(path)), BOOTO_ERR_IO, "Missing output dir must return BOOTO_ERR_IO");
    TEST_PASS("test_unwritable_dir_fails");
}

int main(void) {
    printf("\n--- Running Forensic Case Reporter Tests ---\n");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 1;
    }
    test_report_generation();
    test_json_and_markdown_escaping();
    test_unsafe_case_id_rejected();
    test_unwritable_dir_fails();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_dir);
    TEST_SUMMARY();
    return 0;
}
