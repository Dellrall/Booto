/**
 * @file test_reg_hive.c
 * @brief Registry hive reader: key walk by any case, "ri" indirect lists, inline and cell values, bad input.
 */
#include "test_framework.h"
#include "hive_fixture.h"
#include "reg_hive.h"

static uint8_t g_buf[0x2000];

static void test_walk(void) {
    TEST_START("test_walk");
    hv_t h;
    hv_init(&h, g_buf, sizeof(g_buf));
    uint32_t vals[] = { hv_dword(&h, "Start", 0), hv_string(&h, "ImagePath", "\\SystemRoot\\evil.sys"),
                        hv_string(&h, "", "default") };
    uint32_t svc = hv_key(&h, "Evil", NULL, 0, vals, 3);
    uint32_t svcs = hv_key(&h, "Services", &svc, 1, NULL, 0);
    uint32_t cur = hv_dword(&h, "Current", 1);
    uint32_t top[] = { hv_key(&h, "Select", NULL, 0, &cur, 1), hv_key(&h, "ControlSet001", &svcs, 1, NULL, 0) };
    size_t len = hv_root(&h, hv_key(&h, "ROOT", top, 2, NULL, 0));

    reg_hive_t hv;
    ASSERT_INT_EQ(reg_hive_open(g_buf, len, &hv), BOOTO_OK, "Hive opens");
    uint32_t root = reg_hive_root(&hv);
    uint32_t k = reg_hive_subkey(&hv, reg_hive_subkey(&hv, reg_hive_subkey(&hv, root, "controlset001"), "SERVICES"),
                                 "evil");
    ASSERT_TRUE(k != 0, "Path found in any case");
    uint32_t x = 9;
    ASSERT_TRUE(reg_hive_dword(&hv, k, "start", &x) && x == 0, "Inline DWORD read");
    char s[64];
    ASSERT_TRUE(reg_hive_string(&hv, k, "ImagePath", s, sizeof(s)), "String read");
    ASSERT_STR_EQ(s, "\\SystemRoot\\evil.sys", "UTF-16 string decoded");
    ASSERT_TRUE(reg_hive_string(&hv, k, "", s, sizeof(s)), "Default value read");
    ASSERT_STR_EQ(s, "default", "Default value decoded");
    ASSERT_TRUE(!reg_hive_dword(&hv, k, "ImagePath", &x), "String is not a DWORD");
    ASSERT_TRUE(!reg_hive_string(&hv, k, "Missing", s, sizeof(s)), "Missing value");
    ASSERT_INT_EQ(reg_hive_subkey(&hv, root, "Nope"), 0, "Missing key");
    char name[8];
    ASSERT_INT_EQ(reg_hive_subkey_at(&hv, root, 1, name, sizeof(name)), top[1], "Second child by index");
    ASSERT_STR_EQ(name, "Control", "Name truncated to the buffer");
    ASSERT_INT_EQ(reg_hive_subkey_at(&hv, root, 2, name, sizeof(name)), 0, "Index past the end");
    TEST_PASS("test_walk");
}

static void test_indirect(void) {
    TEST_START("test_indirect");
    hv_t h;
    hv_init(&h, g_buf, sizeof(g_buf));
    uint32_t a = hv_key(&h, "A", NULL, 0, NULL, 0), b = hv_key(&h, "B", NULL, 0, NULL, 0),
             c = hv_key(&h, "C", NULL, 0, NULL, 0);
    uint32_t li1, li2, ri;
    uint8_t *l = hv_cell(&h, 12, &li1);
    l[0] = 'l'; l[1] = 'i'; hv_put16(l + 2, 2); hv_put32(l + 4, a); hv_put32(l + 8, b);
    l = hv_cell(&h, 8, &li2);
    l[0] = 'l'; l[1] = 'i'; hv_put16(l + 2, 1); hv_put32(l + 4, c);
    l = hv_cell(&h, 12, &ri);
    l[0] = 'r'; l[1] = 'i'; hv_put16(l + 2, 2); hv_put32(l + 4, li1); hv_put32(l + 8, li2);
    uint32_t top = hv_key(&h, "ROOT", NULL, 0, NULL, 0);
    hv_put32(g_buf + 0x1000 + top + 4 + 0x14, 3);
    hv_put32(g_buf + 0x1000 + top + 4 + 0x1C, ri);
    size_t len = hv_root(&h, top);

    reg_hive_t hv;
    ASSERT_INT_EQ(reg_hive_open(g_buf, len, &hv), BOOTO_OK, "Hive opens");
    ASSERT_INT_EQ(reg_hive_subkey(&hv, top, "c"), c, "Key in the second list found");
    hv_put32(l + 8, ri); // the ri now points to itself
    ASSERT_INT_EQ(reg_hive_subkey(&hv, top, "c"), 0, "Self-referencing ri is not followed");
    TEST_PASS("test_indirect");
}

static void test_corrupt(void) {
    TEST_START("test_corrupt");
    hv_t h;
    hv_init(&h, g_buf, sizeof(g_buf));
    uint32_t v = hv_string(&h, "Long", "a value stored in its own cell");
    uint32_t k = hv_key(&h, "ROOT", NULL, 0, &v, 1);
    size_t len = hv_root(&h, k);
    reg_hive_t hv;
    ASSERT_INT_EQ(reg_hive_open(g_buf, 100, &hv), BOOTO_ERR_CORRUPT_DATA, "Too short");
    ASSERT_INT_EQ(reg_hive_open(NULL, len, &hv), BOOTO_ERR_INVALID_ARG, "No buffer");
    ASSERT_INT_EQ(reg_hive_open(g_buf, len, &hv), BOOTO_OK, "Hive opens");
    char s[64];
    hv_put32(g_buf + 0x1000 + v + 4 + 4, 0x7FFFFFF0u); // data size past its cell
    ASSERT_TRUE(!reg_hive_string(&hv, k, "Long", s, sizeof(s)), "Oversized data rejected");
    hv_put32(g_buf + 0x24, 0x7FFFFFF0u);
    ASSERT_INT_EQ(reg_hive_open(g_buf, len, &hv), BOOTO_ERR_CORRUPT_DATA, "Root past the end");
    g_buf[0] = 'x';
    ASSERT_INT_EQ(reg_hive_open(g_buf, len, &hv), BOOTO_ERR_CORRUPT_DATA, "No regf signature");
    TEST_PASS("test_corrupt");
}

int main(void) {
    printf("\n--- Running Registry Hive Tests ---\n");
    test_walk();
    test_indirect();
    test_corrupt();
    TEST_SUMMARY();
    return 0;
}
