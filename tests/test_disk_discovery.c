/**
 * @file test_disk_discovery.c
 * @brief Unit tests for storage discovery and forensic read-only mounter.
 */
#include "test_framework.h"
#include "disk_mount.h"

#include <string.h>

static void test_size_formatting(void) {
    TEST_START("test_size_formatting");
    char buf[32];

    disk_format_size(500ULL, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "500 B", "Format bytes");

    disk_format_size(1024ULL * 1024ULL * 50ULL, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "50.0 MB", "Format MB");

    disk_format_size(1024ULL * 1024ULL * 1024ULL * 512ULL, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "512.0 GB", "Format GB");

    TEST_PASS("test_size_formatting");
}

static void test_disk_enumeration(void) {
    TEST_START("test_disk_enumeration");
    disk_discovery_result_t res;
    booto_error_t err = disk_discover_partitions(&res, true);
    ASSERT_INT_EQ(err, BOOTO_OK, "Discovery must return BOOTO_OK");
    ASSERT_TRUE(res.count > 0, "Discovered partition count must be > 0");

    bool has_target = false;
    for (int i = 0; i < res.count; i++) {
        if (res.partitions[i].is_target) {
            has_target = true;
            break;
        }
    }
    ASSERT_TRUE(has_target, "At least one target partition must be flagged");
    TEST_PASS("test_disk_enumeration");
}

static void test_mock_mount_ro(void) {
    TEST_START("test_mock_mount_ro");
    booto_error_t m_err = disk_mount_ro("/dev/nvme0n1p2", "/tmp/test_mock_mnt", "ext4");
    ASSERT_INT_EQ(m_err, BOOTO_OK, "Mount RO must succeed (real or mock emulated)");

    booto_error_t u_err = disk_unmount("/tmp/test_mock_mnt");
    ASSERT_INT_EQ(u_err, BOOTO_OK, "Unmount must succeed");
    TEST_PASS("test_mock_mount_ro");
}

int main(void) {
    printf("\n--- Running Storage Discovery & Mount Tests ---\n");
    test_size_formatting();
    test_disk_enumeration();
    test_mock_mount_ro();
    TEST_SUMMARY();
    return 0;
}
