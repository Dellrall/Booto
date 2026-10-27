/**
 * @file test_rules_loader.c
 * @brief Unit tests for sealed JSON rules loading and built-in fallback.
 */
#include "test_framework.h"
#include "rules_loader.h"
#include "crypto_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *const RULE_FILES[] = {
    "uefi_dbx_revocations.json", "lkm_rootkit_signatures.json", "mbr_bootkit_signatures.json"
};

static void write_file(const char *dir, const char *name, const char *data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(data, 1, len, f);
    fclose(f);
}

/* Write <name> and, when seal is true, its sha256sum-format seal over the given bytes. */
static void write_rules(const char *dir, const char *name, const char *json, bool seal) {
    write_file(dir, name, json, strlen(json));
    if (!seal) return;
    char hex[65], line[700], seal_name[128];
    sha256_buffer_hex((const uint8_t *)json, strlen(json), hex);
    int n = snprintf(line, sizeof(line), "%s  %s/%s\n", hex, dir, name);
    snprintf(seal_name, sizeof(seal_name), "%s.sha256", name);
    write_file(dir, seal_name, line, (size_t)n);
}

/* Fresh temp dir as the only rules search location. */
static void use_temp_dir(char *dir_template) {
    if (!mkdtemp(dir_template)) return;
    setenv("BOOTO_RULES_DIR", dir_template, 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();
}

static void cleanup_dir(const char *dir) {
    char path[512];
    for (size_t i = 0; i < sizeof(RULE_FILES) / sizeof(RULE_FILES[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, RULE_FILES[i]);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%s.sha256", dir, RULE_FILES[i]);
        unlink(path);
    }
    rmdir(dir);
    rules_reset_cache();
}

static const char *VALID_LKM =
    "{ \"version\": 3, \"meta\": {\"nested\": [1, -2.5e3, true, false, null]},\n"
    "  \"signatures\": [\n"
    "    {\"name\": \"Test \\\"Kit\\\" \\u00e9\", \"rule_id\": \"LKM_T1\", \"severity\": \"HIGH\",\n"
    "     \"description\": \"line\\nbreak\", \"symbols\": [\"evil_a\", \"evil_b\"], \"extra\": {}},\n"
    "    {\"name\": \"Second\", \"rule_id\": \"LKM_T2\", \"severity\": \"LOW\",\n"
    "     \"description\": \"d\", \"symbols\": [\"x\"]}\n"
    "  ]\n}\n";

static const char *VALID_MBR =
    "{\"signatures\": [{\"name\": \"T\", \"rule_id\": \"MBR_T\", \"target\": \"vbr_sector\", \"severity\": \"CRITICAL\",\n"
    "  \"unknown_bootloader_only\": true, \"description\": \"d\", \"patterns_hex\": [\"DEad\", \"00ff10\"]}]}";

static void test_valid_sealed_file(void) {
    TEST_START("test_valid_sealed_file");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    write_rules(dir, "lkm_rootkit_signatures.json", VALID_LKM, true);
    write_rules(dir, "mbr_bootkit_signatures.json", VALID_MBR, true);

    const rules_lkm_set_t *lkm = NULL;
    booto_error_t err = rules_get_lkm(&lkm);
    const rules_mbr_set_t *mbr = NULL;
    booto_error_t merr = rules_get_mbr(&mbr);
    cleanup_dir(dir);

    ASSERT_INT_EQ(err, BOOTO_OK, "Sealed LKM rules must load");
    ASSERT_TRUE(lkm != NULL, "Set must not be NULL");
    ASSERT_INT_EQ(lkm->source, RULES_SOURCE_FILE, "Source must be FILE");
    ASSERT_INT_EQ(lkm->count, 2, "Two LKM entries expected");
    ASSERT_STR_EQ(lkm->entries[0].name, "Test \"Kit\" \xc3\xa9", "Escapes and \\u decode");
    ASSERT_STR_EQ(lkm->entries[0].description, "line\nbreak", "\\n decodes");
    ASSERT_INT_EQ(lkm->entries[0].symbol_count, 2, "Two symbols");
    ASSERT_STR_EQ(lkm->entries[0].symbols[1], "evil_b", "Second symbol");
    ASSERT_STR_EQ(lkm->entries[1].rule_id, "LKM_T2", "Second rule id");
    ASSERT_INT_EQ(rules_severity_level(lkm->entries[1].severity), 1, "LOW maps to 1");

    ASSERT_INT_EQ(merr, BOOTO_OK, "Sealed MBR rules must load");
    ASSERT_INT_EQ(mbr->count, 1, "One MBR entry");
    ASSERT_INT_EQ(mbr->entries[0].target, RULES_MBR_TARGET_VBR, "vbr_sector target");
    ASSERT_TRUE(mbr->entries[0].unknown_bootloader_only, "Flag parsed");
    ASSERT_INT_EQ(mbr->entries[0].pattern_count, 2, "Two patterns");
    ASSERT_INT_EQ((int)mbr->entries[0].pattern_len[1], 3, "Pattern length");
    ASSERT_TRUE(mbr->entries[0].patterns[0][0] == 0xDE && mbr->entries[0].patterns[0][1] == 0xAD, "Hex decoded");
    TEST_PASS("test_valid_sealed_file");
}

static void test_missing_seal(void) {
    TEST_START("test_missing_seal");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    write_rules(dir, "lkm_rootkit_signatures.json", VALID_LKM, false);
    const rules_lkm_set_t *lkm = NULL;
    booto_error_t err = rules_get_lkm(&lkm);
    cleanup_dir(dir);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Unsealed rules must be refused");
    ASSERT_TRUE(lkm == NULL, "No set on failure");
    TEST_PASS("test_missing_seal");
}

static void test_seal_mismatch(void) {
    TEST_START("test_seal_mismatch");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    write_rules(dir, "lkm_rootkit_signatures.json", VALID_LKM, true);
    char tampered[1024];
    snprintf(tampered, sizeof(tampered), "%s", VALID_LKM);
    tampered[strlen(tampered) - 3] = ' '; /* flip one byte after sealing */
    write_file(dir, "lkm_rootkit_signatures.json", tampered, strlen(tampered));
    const rules_lkm_set_t *lkm = NULL;
    booto_error_t err = rules_get_lkm(&lkm);
    cleanup_dir(dir);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Tampered rules must be refused");
    TEST_PASS("test_seal_mismatch");
}

static void test_malformed_json(void) {
    TEST_START("test_malformed_json");
    static const char *const BAD[] = {
        /* truncated */
        "{\"signatures\": [{\"name\": \"a\", \"rule_id\": \"b\", \"severity\": \"HIGH\", \"descr",
        /* trailing garbage */
        "{\"signatures\": []} x",
        /* name longer than its 64-byte field */
        "{\"signatures\": [{\"name\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        " \"rule_id\": \"b\", \"severity\": \"HIGH\", \"description\": \"d\", \"symbols\": [\"s\"]}]}",
        /* nesting deeper than 16 */
        "{\"x\": [[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]], \"signatures\": []}",
        /* invalid severity */
        "{\"signatures\": [{\"name\": \"a\", \"rule_id\": \"b\", \"severity\": \"SEVERE\", \"description\": \"d\", \"symbols\": [\"s\"]}]}",
        /* empty symbol would match everything */
        "{\"signatures\": [{\"name\": \"a\", \"rule_id\": \"b\", \"severity\": \"HIGH\", \"description\": \"d\", \"symbols\": [\"\"]}]}",
        /* trailing comma */
        "{\"signatures\": [],}",
        /* missing rules array */
        "{\"rules\": []}",
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        char dir[] = "/tmp/booto_rules_XXXXXX";
        use_temp_dir(dir);
        write_rules(dir, "lkm_rootkit_signatures.json", BAD[i], true);
        const rules_lkm_set_t *lkm = NULL;
        booto_error_t err = rules_get_lkm(&lkm);
        cleanup_dir(dir);
        if (err != BOOTO_ERR_CORRUPT_DATA) printf("    malformed case %zu accepted\n", i);
        ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Malformed JSON must be refused");
    }
    TEST_PASS("test_malformed_json");
}

static void test_absent_uses_builtin(void) {
    TEST_START("test_absent_uses_builtin");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    const rules_dbx_set_t *dbx = NULL;
    const rules_lkm_set_t *lkm = NULL;
    const rules_mbr_set_t *mbr = NULL;
    booto_error_t e1 = rules_get_dbx(&dbx);
    booto_error_t e2 = rules_get_lkm(&lkm);
    booto_error_t e3 = rules_get_mbr(&mbr);
    cleanup_dir(dir);
    ASSERT_TRUE(e1 == BOOTO_OK && e2 == BOOTO_OK && e3 == BOOTO_OK, "Absent rules fall back to built-ins");
    ASSERT_INT_EQ(dbx->source, RULES_SOURCE_BUILTIN, "DBX built-in");
    ASSERT_INT_EQ(lkm->source, RULES_SOURCE_BUILTIN, "LKM built-in");
    ASSERT_INT_EQ(mbr->source, RULES_SOURCE_BUILTIN, "MBR built-in");
    ASSERT_TRUE(dbx->count > 0 && lkm->count > 0 && mbr->count > 0, "Built-in tables non-empty");
    TEST_PASS("test_absent_uses_builtin");
}

/* Committed rules/ must load with their seals and equal the built-in tables exactly. */
static void test_repo_rules_match_builtin(void) {
    TEST_START("test_repo_rules_match_builtin");
    static rules_dbx_set_t file_dbx;
    static rules_lkm_set_t file_lkm;
    static rules_mbr_set_t file_mbr;
    const rules_dbx_set_t *dbx = NULL;
    const rules_lkm_set_t *lkm = NULL;
    const rules_mbr_set_t *mbr = NULL;

    setenv("BOOTO_RULES_DIR", "rules", 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();
    ASSERT_INT_EQ(rules_get_dbx(&dbx), BOOTO_OK, "Repo DBX rules load");
    ASSERT_INT_EQ(rules_get_lkm(&lkm), BOOTO_OK, "Repo LKM rules load");
    ASSERT_INT_EQ(rules_get_mbr(&mbr), BOOTO_OK, "Repo MBR rules load");
    ASSERT_INT_EQ(dbx->source, RULES_SOURCE_FILE, "DBX from file");
    ASSERT_INT_EQ(lkm->source, RULES_SOURCE_FILE, "LKM from file");
    ASSERT_INT_EQ(mbr->source, RULES_SOURCE_FILE, "MBR from file");
    file_dbx = *dbx;
    file_lkm = *lkm;
    file_mbr = *mbr;

    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    booto_error_t e1 = rules_get_dbx(&dbx);
    booto_error_t e2 = rules_get_lkm(&lkm);
    booto_error_t e3 = rules_get_mbr(&mbr);
    cleanup_dir(dir);
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    ASSERT_TRUE(e1 == BOOTO_OK && e2 == BOOTO_OK && e3 == BOOTO_OK, "Built-ins load");

    ASSERT_INT_EQ(file_dbx.count, dbx->count, "DBX counts equal");
    ASSERT_INT_EQ(file_lkm.count, lkm->count, "LKM counts equal");
    ASSERT_INT_EQ(file_mbr.count, mbr->count, "MBR counts equal");
    ASSERT_TRUE(memcmp(file_dbx.entries, dbx->entries, sizeof(dbx->entries)) == 0, "DBX entries identical");
    ASSERT_TRUE(memcmp(file_lkm.entries, lkm->entries, sizeof(lkm->entries)) == 0, "LKM entries identical");
    ASSERT_TRUE(memcmp(file_mbr.entries, mbr->entries, sizeof(mbr->entries)) == 0, "MBR entries identical");
    TEST_PASS("test_repo_rules_match_builtin");
}

int main(void) {
    printf("\n--- Running Rules Loader Tests ---\n");
    test_valid_sealed_file();
    test_missing_seal();
    test_seal_mismatch();
    test_malformed_json();
    test_absent_uses_builtin();
    test_repo_rules_match_builtin();
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    TEST_SUMMARY();
    return 0;
}
