/**
 * @file test_ext4_diff.c
 * @brief Unit tests for the raw Ext4 superblock statistics reader.
 */
#include "test_framework.h"
#include "ext4_diff.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Write a 2 KiB image with an ext4-like superblock at offset 1024. */
static void write_image(const char *path, uint32_t inodes, uint32_t free_inodes, uint16_t magic) {
    uint8_t img[2048];
    memset(img, 0, sizeof(img));
    memcpy(img + 1024 + 0, &inodes, 4);
    memcpy(img + 1024 + 16, &free_inodes, 4);
    memcpy(img + 1024 + 56, &magic, 2);
    FILE *fp = fopen(path, "wb");
    if (fp) {
        fwrite(img, 1, sizeof(img), fp);
        fclose(fp);
    }
}

static void test_ext4_stats_from_superblock(void) {
    TEST_START("test_ext4_stats_from_superblock");
    char path[] = "/tmp/booto_ext4_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0, "mkstemp");
    close(fd);

    ext4_diff_result_t res;
    write_image(path, 1000, 400, 0xEF53);
    ASSERT_INT_EQ(ext4_diff_scan(path, NULL, &res), BOOTO_OK, "Valid superblock must succeed");
    ASSERT_INT_EQ(res.total_disk_inodes, 1000, "Total inodes");
    ASSERT_INT_EQ(res.allocated_raw_inodes, 600, "Allocated = total - free");
    ASSERT_TRUE(!res.cross_view_performed, "Cross-view must be reported as not performed");

    write_image(path, 1000, 400, 0x1234);
    ASSERT_INT_EQ(ext4_diff_scan(path, NULL, &res), BOOTO_ERR_CORRUPT_DATA, "Non-ext4 magic must be rejected");

    write_image(path, 10, 20, 0xEF53);
    ASSERT_INT_EQ(ext4_diff_scan(path, NULL, &res), BOOTO_ERR_CORRUPT_DATA, "free > total must be rejected, not wrap");

    unlink(path);
    TEST_PASS("test_ext4_stats_from_superblock");
}

static void test_ext4_missing_device_fails(void) {
    TEST_START("test_ext4_missing_device_fails");
    ext4_diff_result_t res;
    ASSERT_INT_EQ(ext4_diff_scan("/nonexistent/booto_dev", NULL, &res), BOOTO_ERR_NOT_FOUND,
                  "Missing device must fail instead of fabricating results");
    TEST_PASS("test_ext4_missing_device_fails");
}

int main(void) {
    printf("\n--- Running Raw Ext4 Superblock Statistics Tests ---\n");
    test_ext4_stats_from_superblock();
    test_ext4_missing_device_fails();
    TEST_SUMMARY();
    return 0;
}
