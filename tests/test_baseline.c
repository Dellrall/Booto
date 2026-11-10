/**
 * @file test_baseline.c
 * @brief Boot chain baseline: a scan records /boot, a later scan reports changed, missing and new files.
 */
#include "test_framework.h"
#include "baseline.h"
#include "forensic_scan.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[] = "/tmp/test_booto_baseline_XXXXXX";

static void put(const char *rel, const char *data) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    FILE *fp = fopen(p, "w");
    if (fp) {
        fputs(data, fp);
        fclose(fp);
    }
}

static int scan_into(baseline_t *b) {
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    if (!r) return -1;
    forensic_scan_set_baseline(b);
    booto_error_t e = forensic_scan_run(NULL, g_root, NULL, NULL, NULL, NULL, r);
    forensic_scan_set_baseline(NULL);
    free(r);
    return e == BOOTO_OK ? 0 : -1;
}

static void test_scan_records_and_compares(void) {
    TEST_START("test_scan_records_and_compares");
    char p[512];
    snprintf(p, sizeof(p), "%s/boot", g_root);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/boot/grub", g_root);
    mkdir(p, 0700);
    put("boot/vmlinuz", "kernel v1");
    put("boot/grub/grub.cfg", "menuentry");
    put("boot/old.img", "gone soon");

    baseline_t *a = calloc(1, sizeof(*a)), *b = calloc(1, sizeof(*b)), *c = calloc(1, sizeof(*c));
    ASSERT_TRUE(a && b && c, "Allocate baselines");
    ASSERT_INT_EQ(scan_into(a), 0, "First scan runs");
    ASSERT_INT_EQ(a->count, 3, "Every file under /boot is hashed");

    char file[512];
    snprintf(file, sizeof(file), "%s/base.txt", g_root);
    ASSERT_INT_EQ(baseline_write(a, file), BOOTO_OK, "Baseline written");
    ASSERT_INT_EQ(baseline_load(file, c), BOOTO_OK, "Baseline read back");
    ASSERT_INT_EQ(baseline_compare(a, c, NULL), 0, "Read-back equals what was written");

    put("boot/vmlinuz", "kernel v2 patched");
    snprintf(p, sizeof(p), "%s/boot/old.img", g_root);
    unlink(p);
    put("boot/grub/evil.mod", "implant");
    ASSERT_INT_EQ(scan_into(b), 0, "Second scan runs");
    ASSERT_INT_EQ(baseline_compare(c, b, NULL), 3, "One changed, one missing, one new");

    unlink(file);
    snprintf(p, sizeof(p), "%s/boot/grub/evil.mod", g_root); unlink(p);
    snprintf(p, sizeof(p), "%s/boot/grub/grub.cfg", g_root); unlink(p);
    snprintf(p, sizeof(p), "%s/boot/vmlinuz", g_root); unlink(p);
    snprintf(p, sizeof(p), "%s/boot/grub", g_root); rmdir(p);
    snprintf(p, sizeof(p), "%s/boot", g_root); rmdir(p);
    free(a), free(b), free(c);
    TEST_PASS("test_scan_records_and_compares");
}

static void test_parse_rejects_bad_lines(void) {
    TEST_START("test_parse_rejects_bad_lines");
    baseline_t *b = calloc(1, sizeof(*b));
    ASSERT_TRUE(b, "Allocate baseline");
    static const char *const bad[] = { "abc  short-hash\n", "unreadable\n", "unreadable label-one-space\n",
                                       "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef  upper\n" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_INT_EQ(baseline_parse(bad[i], strlen(bad[i]), b), BOOTO_ERR_CORRUPT_DATA, bad[i]);
    ASSERT_INT_EQ(baseline_parse("\n\n", 2, b), BOOTO_OK, "Blank lines are fine");
    ASSERT_INT_EQ(b->count, 0, "Blank file has no entries");

    baseline_add_hash(b, "esp/evil\nname", "unreadable");
    ASSERT_STR_EQ(b->e[0].label, "esp/evil?name", "A newline in a file name cannot split the line");
    free(b);
    TEST_PASS("test_parse_rejects_bad_lines");
}

int main(void) {
    logger_init(LOG_LEVEL_CRITICAL, NULL);
    printf("\n--- Running Boot Chain Baseline Tests ---\n");
    if (!mkdtemp(g_root)) return 1;
    test_scan_records_and_compares();
    test_parse_rejects_bad_lines();
    rmdir(g_root);
    TEST_SUMMARY();
    return 0;
}
