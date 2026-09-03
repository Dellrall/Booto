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

static void test_fs_magic_probing(void) {
    TEST_START("test_fs_magic_probing");

    const char *tmp_img = "/tmp/test_booto_fs_probe.img";
    char fs_type[32];
    char label[64];

    // 1. Test Ext4 Superblock Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t zero[1024] = {0};
        fwrite(zero, 1, sizeof(zero), fp); // Offset 0..1023

        uint8_t ext4_sb[1024] = {0};
        ext4_sb[56] = 0x53; // Magic 0xEF53 at offset 56
        ext4_sb[57] = 0xEF;
        memcpy(&ext4_sb[120], "RootUbuntu", 10); // Volume label
        fwrite(ext4_sb, 1, sizeof(ext4_sb), fp); // Offset 1024..2047
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "Ext4 probe return");
        ASSERT_STR_EQ(fs_type, "ext4", "Ext4 filesystem type");
        ASSERT_STR_EQ(label, "RootUbuntu", "Ext4 volume label");
    }

    // 2. Test FAT32 OEM Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t fat32[512] = {0};
        fat32[510] = 0x55;
        fat32[511] = 0xAA;
        memcpy(&fat32[82], "FAT32   ", 8);
        memcpy(&fat32[71], "BOOT_ESP   ", 11);
        fwrite(fat32, 1, sizeof(fat32), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "FAT32 probe return");
        ASSERT_STR_EQ(fs_type, "vfat", "FAT32 filesystem type");
        ASSERT_STR_EQ(label, "BOOT_ESP", "FAT32 volume label");
    }

    // 3. Test NTFS OEM Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t ntfs[512] = {0};
        memcpy(&ntfs[3], "NTFS    ", 8);
        ntfs[510] = 0x55;
        ntfs[511] = 0xAA;
        fwrite(ntfs, 1, sizeof(ntfs), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "NTFS probe return");
        ASSERT_STR_EQ(fs_type, "ntfs", "NTFS filesystem type");
    }

    // 4. Test XFS Superblock Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t xfs[512] = {0};
        memcpy(&xfs[0], "XFSB", 4);
        memcpy(&xfs[108], "XfsData     ", 12);
        fwrite(xfs, 1, sizeof(xfs), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "XFS probe return");
        ASSERT_STR_EQ(fs_type, "xfs", "XFS filesystem type");
        ASSERT_STR_EQ(label, "XfsData", "XFS volume label");
    }

    // 5. Test Btrfs Superblock Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        // Seek to 65536
        fseek(fp, 65536, SEEK_SET);
        uint8_t btrfs[1024] = {0};
        memcpy(&btrfs[64], "_BHRfS_M", 8);
        memcpy(&btrfs[299], "BtrfsRaid", 9);
        fwrite(btrfs, 1, sizeof(btrfs), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "Btrfs probe return");
        ASSERT_STR_EQ(fs_type, "btrfs", "Btrfs filesystem type");
        ASSERT_STR_EQ(label, "BtrfsRaid", "Btrfs volume label");
    }

    // 6. Test ISO9660 Volume Descriptor Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        // Seek to 32768
        fseek(fp, 32768, SEEK_SET);
        uint8_t iso[2048] = {0};
        iso[0] = 0x01; // Primary volume descriptor
        memcpy(&iso[1], "CD001", 5);
        memcpy(&iso[40], "BOOTO_LIVE                      ", 32);
        fwrite(iso, 1, sizeof(iso), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "ISO9660 probe return");
        ASSERT_STR_EQ(fs_type, "iso9660", "ISO9660 filesystem type");
        ASSERT_STR_EQ(label, "BOOTO_LIVE", "ISO9660 volume label");
    }

    // 7. Test LUKS2 Header Probing
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t luks2[512] = {0};
        memcpy(luks2, "LUKS\xba\xbe", 6);
        luks2[6] = 0x00; // Big-endian version 2
        luks2[7] = 0x02;
        fwrite(luks2, 1, sizeof(luks2), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "LUKS2 probe return");
        ASSERT_STR_EQ(fs_type, "crypto_LUKS", "LUKS2 filesystem type");
        ASSERT_STR_EQ(label, "Encrypted Volume (LUKS2)", "LUKS2 volume label");
    }

    // 8. Unknown / Raw Zero Disk
    {
        FILE *fp = fopen(tmp_img, "wb");
        ASSERT_TRUE(fp != NULL, "Create test probe image");
        uint8_t zero[512] = {0};
        fwrite(zero, 1, sizeof(zero), fp);
        fclose(fp);

        booto_error_t err = disk_probe_fs_magic(tmp_img, fs_type, sizeof(fs_type), label, sizeof(label));
        ASSERT_INT_EQ(err, BOOTO_OK, "Raw disk probe return");
        ASSERT_STR_EQ(fs_type, "unknown", "Unknown filesystem type");
    }

    remove(tmp_img);
    TEST_PASS("test_fs_magic_probing");
}

static void test_luks_open_and_close(void) {
    TEST_START("test_luks_open_and_close");

    booto_error_t o_err = disk_luks_open_ro("/dev/nvme0n1p3", "booto_mock_luks", "CorrectPassphrase123");
    ASSERT_INT_EQ(o_err, BOOTO_OK, "LUKS read-only open must succeed");

    booto_error_t c_err = disk_luks_close("booto_mock_luks");
    ASSERT_INT_EQ(c_err, BOOTO_OK, "LUKS close must succeed");

    TEST_PASS("test_luks_open_and_close");
}

int main(void) {
    printf("\n--- Running Storage Discovery & Mount Tests ---\n");
    test_size_formatting();
    test_disk_enumeration();
    test_mock_mount_ro();
    test_fs_magic_probing();
    test_luks_open_and_close();
    TEST_SUMMARY();
    return 0;
}
