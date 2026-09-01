/**
 * @file test_ext4_diff.c
 * @brief Unit tests for Raw Ext4 Inode vs VFS Differential Cross-View Scanner.
 */
#include "test_framework.h"
#include "ext4_diff.h"

static void test_ext4_diff_mock(void) {
    TEST_START("test_ext4_diff_mock");

    ext4_diff_result_t res;
    booto_error_t err = ext4_diff_mock(&res);

    ASSERT_INT_EQ(err, BOOTO_OK, "Differential mock scan must succeed");
    ASSERT_TRUE(res.hidden_inodes_count == 1, "Must detect 1 hidden unlinked inode");
    ASSERT_INT_EQ(res.hidden_inodes[0].inode_num, 1849201, "Hidden inode number must match");
    ASSERT_INT_EQ(res.hidden_inodes[0].links_count, 0, "Unlinked inode link count must be 0");

    TEST_PASS("test_ext4_diff_mock");
}

static void test_ext4_diff_scan_fallback(void) {
    TEST_START("test_ext4_diff_scan_fallback");

    ext4_diff_result_t res;
    // Scan non-existent device to test fallback handling
    booto_error_t err = ext4_diff_scan("/dev/null_fake_block", "/tmp", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Fallback execution must succeed");

    TEST_PASS("test_ext4_diff_scan_fallback");
}

int main(void) {
    printf("\n--- Running Raw Ext4 Differential Engine Tests ---\n");
    test_ext4_diff_mock();
    test_ext4_diff_scan_fallback();
    TEST_SUMMARY();
    return 0;
}
