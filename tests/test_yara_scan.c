/**
 * @file test_yara_scan.c
 * @brief Unit tests for signed YARA rules: matches, refusal of unsigned or invalid rules, and the shipped rules.
 */
#include "test_framework.h"
#include "rules_fixture.h"
#include "yara_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_dir[64];
static char g_path[128];

static void write_rules(const char *text, bool sign) {
    snprintf(g_path, sizeof(g_path), "%s/%s", g_dir, YARA_RULES_FILE);
    FILE *f = fopen(g_path, "wb");
    if (f) {
        fwrite(text, 1, strlen(text), f);
        fclose(f);
    }
    char sig[160];
    snprintf(sig, sizeof(sig), "%s.sig", g_path);
    unlink(sig);
    if (sign) rules_fixture_sign(g_path, text, strlen(text));
    else rules_fixture_init();
    rules_reset_cache();
}

static const char *RULE_OK =
    "rule TEST_EVIL { meta: severity = \"HIGH\" description = \"evil marker\" "
    "strings: $a = \"EVILMARK\" condition: $a }";

static const uint8_t SAMPLE[] = "MZ....EVILMARK....";
static const uint8_t CLEAN[] = "MZ....nothing here";

static void test_signed_rules_match(void) {
    TEST_START("signed rules match the marked buffer only");
    write_rules(RULE_OK, true);
    yara_match_t m[YARA_MAX_MATCHES];
    int n = -1;
    ASSERT_INT_EQ(yara_scan_buffer(SAMPLE, sizeof(SAMPLE), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "scan ok");
    ASSERT_INT_EQ(n, 1, "one match");
    ASSERT_STR_EQ(m[0].rule, "TEST_EVIL", "rule id");
    ASSERT_STR_EQ(m[0].description, "evil marker", "description");
    ASSERT_INT_EQ(m[0].severity, SEVERITY_HIGH, "severity");
    ASSERT_INT_EQ(yara_scan_buffer(CLEAN, sizeof(CLEAN), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "clean scan ok");
    ASSERT_INT_EQ(n, 0, "no match on clean buffer");
    TEST_PASS("signed rules match the marked buffer only");
}

static void test_unsigned_rules_refused(void) {
    TEST_START("unsigned rules are refused, not ignored");
    write_rules(RULE_OK, false);
    yara_match_t m[YARA_MAX_MATCHES];
    int n = -1;
    ASSERT_INT_EQ(yara_rules_status(), BOOTO_ERR_CORRUPT_DATA, "status refused");
    ASSERT_INT_EQ(yara_scan_buffer(SAMPLE, sizeof(SAMPLE), m, YARA_MAX_MATCHES, &n), BOOTO_ERR_CORRUPT_DATA,
                  "scan refused");
    ASSERT_INT_EQ(n, 0, "no matches");
    TEST_PASS("unsigned rules are refused, not ignored");
}

static void test_rule_without_metas_refused(void) {
    TEST_START("a rule without severity/description metas is refused");
    write_rules("rule NO_META { strings: $a = \"EVILMARK\" condition: $a }", true);
    ASSERT_INT_EQ(yara_rules_status(), BOOTO_ERR_CORRUPT_DATA, "missing metas");
    write_rules("rule BAD_SEV { meta: severity = \"SCARY\" description = \"x\" condition: true }", true);
    ASSERT_INT_EQ(yara_rules_status(), BOOTO_ERR_CORRUPT_DATA, "invalid severity");
    write_rules("rule BROKEN { condition: $nope }", true);
    ASSERT_INT_EQ(yara_rules_status(), BOOTO_ERR_CORRUPT_DATA, "does not compile");
    TEST_PASS("a rule without severity/description metas is refused");
}

static void test_absent_rules_match_nothing(void) {
    TEST_START("no rules file: scans match nothing");
    unlink(g_path);
    rules_reset_cache();
    yara_match_t m[YARA_MAX_MATCHES];
    int n = -1;
    ASSERT_INT_EQ(yara_scan_buffer(SAMPLE, sizeof(SAMPLE), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "scan ok");
    ASSERT_INT_EQ(n, 0, "no matches");
    TEST_PASS("no rules file: scans match nothing");
}

/* The committed rules/bootkits.yar: signed with the release key, and its embedded-PE rule fires. */
static void test_shipped_rules(void) {
    TEST_START("shipped rules load and flag an embedded PE");
    rules_fixture_done();
    setenv("BOOTO_RULES_DIR", "rules", 1);
    rules_reset_cache();
    static uint8_t img[0x1000];
    const char stub[] = "This program cannot be run in DOS mode";
    memcpy(img, "MZ", 2);
    memcpy(img + 0x4E, stub, sizeof(stub) - 1);
    yara_match_t m[YARA_MAX_MATCHES];
    int n = -1;
    ASSERT_INT_EQ(yara_scan_buffer(img, sizeof(img), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "release-signed rules load");
    ASSERT_INT_EQ(n, 0, "own DOS stub is not an embedded PE");
    memcpy(img + 0x800, "MZ", 2);
    memcpy(img + 0x800 + 0x4E, stub, sizeof(stub) - 1);
    ASSERT_INT_EQ(yara_scan_buffer(img, sizeof(img), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "scan ok");
    ASSERT_INT_EQ(n, 1, "embedded PE flagged");
    ASSERT_STR_EQ(m[0].rule, "BOOTO_YARA_EMBEDDED_PE", "rule id");
    static const char ko[] = "\x7f" "ELF\0\0author=x\0description=LKM rootkit\0";
    ASSERT_INT_EQ(yara_scan_buffer((const uint8_t *)ko, sizeof(ko), m, YARA_MAX_MATCHES, &n), BOOTO_OK, "scan ok");
    ASSERT_INT_EQ(n, 1, "rootkit module info flagged");
    ASSERT_STR_EQ(m[0].rule, "BOOTO_YARA_LKM_ROOTKIT_MODINFO", "Linux rule id");
    TEST_PASS("shipped rules load and flag an embedded PE");
}

int main(void) {
    printf("\n--- Running YARA Rules Tests ---\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/booto_yara_XXXXXX");
    if (!mkdtemp(g_dir)) return 1;
    setenv("BOOTO_RULES_DIR", g_dir, 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    test_signed_rules_match();
    test_unsigned_rules_refused();
    test_rule_without_metas_refused();
    test_absent_rules_match_nothing();
    char sig[160];
    snprintf(sig, sizeof(sig), "%s.sig", g_path);
    unlink(sig);
    rmdir(g_dir);
    test_shipped_rules();
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    yara_scan_reset();
    TEST_SUMMARY();
    return 0;
}
