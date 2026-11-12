/**
 * @file test_rules_loader.c
 * @brief Unit tests for signed JSON rules loading and built-in fallback.
 */
#include "test_framework.h"
#include "rules_loader.h"
#include "rules_fixture.h"

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

/* Write <name> and, when sign is true, its Ed25519 signature over the given bytes. */
static void write_rules(const char *dir, const char *name, const char *json, bool sign) {
    write_file(dir, name, json, strlen(json));
    if (!sign) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    rules_fixture_sign(path, json, strlen(json));
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
        snprintf(path, sizeof(path), "%s/%s.sig", dir, RULE_FILES[i]);
        unlink(path);
    }
    rmdir(dir);
    rules_fixture_done();
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

static void test_valid_signed_file(void) {
    TEST_START("test_valid_signed_file");
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
    TEST_PASS("test_valid_signed_file");
}

static void test_missing_signature(void) {
    TEST_START("test_missing_signature");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    write_rules(dir, "lkm_rootkit_signatures.json", VALID_LKM, false);
    const rules_lkm_set_t *lkm = NULL;
    booto_error_t err = rules_get_lkm(&lkm);
    cleanup_dir(dir);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Unsigned rules must be refused");
    ASSERT_TRUE(lkm == NULL, "No set on failure");
    TEST_PASS("test_missing_signature");
}

static void test_signature_mismatch(void) {
    TEST_START("test_signature_mismatch");
    char dir[] = "/tmp/booto_rules_XXXXXX";
    use_temp_dir(dir);
    write_rules(dir, "lkm_rootkit_signatures.json", VALID_LKM, true);
    char tampered[1024];
    snprintf(tampered, sizeof(tampered), "%s", VALID_LKM);
    tampered[strlen(tampered) - 3] = ' '; /* flip one byte after signing */
    write_file(dir, "lkm_rootkit_signatures.json", tampered, strlen(tampered));
    const rules_lkm_set_t *lkm = NULL;
    booto_error_t err = rules_get_lkm(&lkm);
    cleanup_dir(dir);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Tampered rules must be refused");
    TEST_PASS("test_signature_mismatch");
}

static void test_malformed_json(void) {
    TEST_START("test_malformed_json");
    static const char *const BAD[] = {
        /* truncated */
        "{\"signatures\": [{\"name\": \"a\", \"rule_id\": \"b\", \"severity\": \"HIGH\", \"descr",
        /* trailing garbage */
        "{\"signatures\": []} x",
        /* name longer than its 64-byte field */
        "{\"signatures\": [{\"name\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"rule_id\": \"b\", \"severity\": \"HIGH\", \"description\": \"d\", \"symbols\": [\"s\"]}]}",
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
    const rules_ioc_set_t *ioc = NULL;
    booto_error_t e1 = rules_get_dbx(&dbx);
    booto_error_t e2 = rules_get_lkm(&lkm);
    booto_error_t e3 = rules_get_mbr(&mbr);
    booto_error_t e4 = rules_get_ioc(&ioc);
    cleanup_dir(dir);
    ASSERT_TRUE(e1 == BOOTO_OK && e2 == BOOTO_OK && e3 == BOOTO_OK && e4 == BOOTO_OK, "Absent rules fall back to built-ins");
    ASSERT_TRUE(ioc->source == RULES_SOURCE_BUILTIN && ioc->count > 0, "IOC built-in non-empty");
    ASSERT_INT_EQ(dbx->source, RULES_SOURCE_BUILTIN, "DBX built-in");
    ASSERT_INT_EQ(lkm->source, RULES_SOURCE_BUILTIN, "LKM built-in");
    ASSERT_INT_EQ(mbr->source, RULES_SOURCE_BUILTIN, "MBR built-in");
    ASSERT_TRUE(dbx->count > 0 && lkm->count > 0 && mbr->count > 0, "Built-in tables non-empty");
    /* Real data, not placeholders: Ubuntu's shim 15 (revoked 2021, Authenticode hash verified against
     * Microsoft's list) must be present; the old fabricated "0123ef"-filler hashes must not. */
    bool real = false, fake = false;
    for (int i = 0; i < dbx->count; i++) {
        if (strcmp(dbx->entries[i].sha256, "007f4c95125713b112093e21663e2d23e3c1ae9ce4b5de0d58a297332336a2d8") == 0)
            real = true;
        if (strstr(dbx->entries[i].sha256, "0123ef89")) fake = true;
    }
    ASSERT_TRUE(real, "Revoked Ubuntu shim 15 is in the built-in dbx");
    ASSERT_TRUE(!fake, "No fabricated dbx hashes");
    TEST_PASS("test_absent_uses_builtin");
}

/* Committed rules/ must verify against the release key and equal the built-in tables exactly. */
static void test_repo_rules_match_builtin(void) {
    TEST_START("test_repo_rules_match_builtin");
    static rules_dbx_set_t file_dbx;
    static rules_lkm_set_t file_lkm;
    static rules_mbr_set_t file_mbr;
    static rules_ioc_set_t file_ioc;
    const rules_dbx_set_t *dbx = NULL;
    const rules_lkm_set_t *lkm = NULL;
    const rules_mbr_set_t *mbr = NULL;
    const rules_ioc_set_t *ioc = NULL;

    setenv("BOOTO_RULES_DIR", "rules", 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();
    ASSERT_INT_EQ(rules_get_dbx(&dbx), BOOTO_OK, "Repo DBX rules load");
    ASSERT_INT_EQ(rules_get_lkm(&lkm), BOOTO_OK, "Repo LKM rules load");
    ASSERT_INT_EQ(rules_get_mbr(&mbr), BOOTO_OK, "Repo MBR rules load");
    ASSERT_INT_EQ(rules_get_ioc(&ioc), BOOTO_OK, "Repo IOC rules load");
    ASSERT_INT_EQ(ioc->source, RULES_SOURCE_FILE, "IOC from file");
    file_ioc = *ioc;
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
    booto_error_t e4 = rules_get_ioc(&ioc);
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
    ASSERT_INT_EQ(e4, BOOTO_OK, "IOC built-ins load");
    ASSERT_INT_EQ(file_ioc.count, ioc->count, "IOC counts equal");
    ASSERT_TRUE(memcmp(file_ioc.entries, ioc->entries, sizeof(ioc->entries)) == 0, "IOC entries identical");
    TEST_PASS("test_repo_rules_match_builtin");
}

static void test_volatility(void) {
    TEST_START("test_volatility");
    static const char json[] =
        "[{\"Table Address\": 18446744071, \"Index\": 0, \"Handler Symbol\": \"sys_read\", \"__children\": []},\n"
        " {\"Index\": 1, \"Handler Symbol\": \"UNKNOWN\", \"__children\": []},\n"
        " {\"Address\": 1, \"Name\": \"diamorphine\\u001b[2J\", \"__children\": [\n"
        "   {\"Name\": \"child\", \"Live\": true, \"Note\": null, \"__children\": []}]}]\n";
    volatility_row_t rows[2];
    int n = -1;
    ASSERT_INT_EQ(rules_parse_volatility(json, sizeof(json) - 1, rows, 2, &n), BOOTO_OK, "Volatility JSON parsed");
    ASSERT_INT_EQ(n, 3, "known syscall handler not flagged; UNKNOWN, module and child flagged");
    ASSERT_STR_EQ(rows[0].detail, "Index=1, Handler Symbol=UNKNOWN", "UNKNOWN handler row");
    ASSERT_STR_EQ(rows[1].detail, "Name=child, Live=true, Note=null", "children come before their parent");
    ASSERT_INT_EQ(rules_parse_volatility("[]", 2, rows, 2, &n), BOOTO_OK, "empty output is clean");
    ASSERT_INT_EQ(n, 0, "nothing flagged");
    ASSERT_INT_EQ(rules_parse_volatility("Volatility 3 Framework", 22, rows, 2, &n), BOOTO_ERR_CORRUPT_DATA,
                  "text renderer output rejected");
    ASSERT_INT_EQ(rules_parse_volatility("[{\"a\": 1}] x", 13, rows, 2, &n), BOOTO_ERR_CORRUPT_DATA, "trailing junk");
    /* The module row (third) is past max: counted, not stored; its escape byte would be '?'. */
    volatility_row_t one[3];
    ASSERT_INT_EQ(rules_parse_volatility(json, sizeof(json) - 1, one, 3, &n), BOOTO_OK, "parsed again");
    ASSERT_TRUE(strchr(one[2].detail, 0x1b) == NULL && strstr(one[2].detail, "diamorphine?[2J") != NULL,
                "control bytes replaced");
    TEST_PASS("test_volatility");
}

int main(void) {
    printf("\n--- Running Rules Loader Tests ---\n");
    test_repo_rules_match_builtin(); /* first: the other tests swap in a throwaway key */
    test_volatility();
    test_valid_signed_file();
    test_missing_signature();
    test_signature_mismatch();
    test_malformed_json();
    test_absent_uses_builtin();
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    TEST_SUMMARY();
    return 0;
}
