/**
 * @file test_preload_scanner.c
 * @brief Unit tests for userland LD_PRELOAD and PAM interceptor scanner.
 */
#include "test_framework.h"
#include "preload_scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[64];

static void make_root(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/booto_preload_XXXXXX");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        exit(1);
    }
    char etc[96];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    mkdir(etc, 0755);
}

static void write_etc_file(const char *name, const char *content) {
    char p[160];
    snprintf(p, sizeof(p), "%s/etc/%s", g_root, name);
    FILE *fp = fopen(p, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

static void remove_root(void) {
    static const char *names[] = { "ld.so.preload", "environment" };
    char p[160];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/etc/%s", g_root, names[i]);
        if (unlink(p) != 0) rmdir(p);
    }
    snprintf(p, sizeof(p), "%s/etc", g_root);
    rmdir(p);
    rmdir(g_root);
}

static void test_ld_preload_detection(void) {
    TEST_START("test_ld_preload_detection");
    make_root();
    write_etc_file("ld.so.preload", "/lib/x86_64-linux-gnu/libazazel.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "Must detect active LD_PRELOAD hook");
    ASSERT_STR_EQ(res.findings[0].target_library, "/lib/x86_64-linux-gnu/libazazel.so", "Library path");
    ASSERT_STR_EQ(res.findings[0].rule_id, "PRELOAD_ACTIVE_HOOK", "Rule ID");
    TEST_PASS("test_ld_preload_detection");
}

static void test_ld_preload_whitespace_tokens(void) {
    TEST_START("test_ld_preload_whitespace_tokens");
    make_root();
    write_etc_file("ld.so.preload", "a.so b.so\tc.so # comment d.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 3, "Every whitespace-separated entry, none from the comment");
    ASSERT_STR_EQ(res.findings[0].target_library, "a.so", "First token");
    ASSERT_STR_EQ(res.findings[1].target_library, "b.so", "Second token");
    ASSERT_STR_EQ(res.findings[2].target_library, "c.so", "Tab-separated token");
    TEST_PASS("test_ld_preload_whitespace_tokens");
}

static void test_ld_preload_long_line(void) {
    TEST_START("test_ld_preload_long_line");
    make_root();
    char line[1024];
    memset(line, ' ', sizeof(line));
    memcpy(line, "/lib/one.so", 11);
    memcpy(&line[700], "/lib/two.so", 11);
    line[711] = '\0';
    write_etc_file("ld.so.preload", line);

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 2, "Both entries of a >600-byte line must be reported");
    ASSERT_STR_EQ(res.findings[1].target_library, "/lib/two.so", "Entry past byte 600");
    TEST_PASS("test_ld_preload_long_line");
}

static void test_environment_ld_preload(void) {
    TEST_START("test_environment_ld_preload");
    make_root();
    write_etc_file("environment", "PATH=\"/usr/bin:/bin\"\n# LD_PRELOAD=/lib/commented.so\nLD_PRELOAD=/lib/evil.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "LD_PRELOAD in etc/environment must be detected");
    ASSERT_STR_EQ(res.findings[0].target_library, "/lib/evil.so", "Environment library");
    ASSERT_STR_EQ(res.findings[0].rule_id, "PRELOAD_ENV_HOOK", "Rule ID");
    TEST_PASS("test_environment_ld_preload");
}

static void test_unreadable_preload_is_error(void) {
    TEST_START("test_unreadable_preload_is_error");
    make_root();
    char p[160];
    snprintf(p, sizeof(p), "%s/etc/ld.so.preload", g_root);
    mkdir(p, 0755); // exists but read() fails with EISDIR, even as root

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_ERR_IO, "Unreadable ld.so.preload must not report clean");
    TEST_PASS("test_unreadable_preload_is_error");
}

int main(void) {
    printf("\n--- Running LD_PRELOAD & PAM Interceptor Tests ---\n");
    test_ld_preload_detection();
    test_ld_preload_whitespace_tokens();
    test_ld_preload_long_line();
    test_environment_ld_preload();
    test_unreadable_preload_is_error();
    TEST_SUMMARY();
    return 0;
}
