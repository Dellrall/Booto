/**
 * @file test_disk_discovery.c
 * @brief Unit tests for storage discovery and forensic read-only mounter.
 */
#include "test_framework.h"
#include "disk_mount.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *const MOCK_UUIDS[] = {"e4a2c1f9-90b1-4f8a-a92c-8123ef459a01", "B849-1A2E", "7A4C89E14C899723"};

static int count_mock_entries(const disk_discovery_result_t *res) {
    int n = 0;
    for (int i = 0; i < res->count; i++) {
        for (size_t j = 0; j < sizeof(MOCK_UUIDS) / sizeof(MOCK_UUIDS[0]); j++) {
            if (strcmp(res->partitions[i].uuid, MOCK_UUIDS[j]) == 0) n++;
        }
    }
    return n;
}

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
    ASSERT_INT_EQ(count_mock_entries(&res), 3, "include_mock must append the full mock set");

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

static void test_discovery_without_mock(void) {
    TEST_START("test_discovery_without_mock");
    disk_discovery_result_t res;
    booto_error_t err = disk_discover_partitions(&res, false);
    ASSERT_INT_EQ(err, BOOTO_OK, "Discovery must return BOOTO_OK");
    // Real hosts may legitimately have /dev/sda1 etc., so identify mocks by their fixed UUIDs.
    ASSERT_INT_EQ(count_mock_entries(&res), 0, "No mock partitions without include_mock");
    TEST_PASS("test_discovery_without_mock");
}

static void test_nonroot_denied(void) {
    TEST_START("test_nonroot_denied");
    if (geteuid() == 0) {
        printf("    [SKIP] running as root\n");
        return;
    }
    ASSERT_INT_EQ(disk_mount_ro("/dev/nvme0n1p2", "/tmp/booto_never_created", "ext4"), BOOTO_ERR_PERMISSION_DENIED,
                  "Non-root mount must be denied");
    ASSERT_INT_EQ(disk_unmount("/tmp/booto_never_created"), BOOTO_ERR_PERMISSION_DENIED, "Non-root unmount must be denied");
    ASSERT_INT_EQ(disk_luks_open_ro("/dev/nvme0n1p3", "booto_mock_luks", "pw"), BOOTO_ERR_PERMISSION_DENIED,
                  "Non-root LUKS open must be denied");
    TEST_PASS("test_nonroot_denied");
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

static void test_luks_invalid_mapper_name(void) {
    TEST_START("test_luks_invalid_mapper_name");
    ASSERT_INT_EQ(disk_luks_open_ro("/dev/nvme0n1p3", "a b;rm", "pw"), BOOTO_ERR_INVALID_ARG, "Shell metachar name rejected");
    ASSERT_INT_EQ(disk_luks_open_ro("/dev/nvme0n1p3", "", "pw"), BOOTO_ERR_INVALID_ARG, "Empty name rejected");
    ASSERT_INT_EQ(disk_luks_close("a b;rm"), BOOTO_ERR_INVALID_ARG, "Close rejects bad name");
    TEST_PASS("test_luks_invalid_mapper_name");
}

static void test_exec_argv_stdin_verbatim(void) {
    TEST_START("test_exec_argv_stdin_verbatim");
    char dir[] = "/tmp/booto_exec_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");

    char payload[128];
    snprintf(payload, sizeof(payload), "x'; touch /tmp/booto_pwned_%ld; '\"$(id)", (long)getpid());
    char pwned[64];
    snprintf(pwned, sizeof(pwned), "/tmp/booto_pwned_%ld", (long)getpid());
    char file[64];
    snprintf(file, sizeof(file), "%s/payload", dir);

    FILE *fp = fopen(file, "wb");
    bool wrote = fp && fwrite(payload, 1, strlen(payload), fp) == strlen(payload);
    if (fp) fclose(fp);

    const char *const argv[] = {"cmp", "-s", "-", file, NULL};
    int status = -1;
    booto_error_t same = disk_exec_argv(argv, payload, strlen(payload), &status);
    booto_error_t diff = disk_exec_argv(argv, "different", 9, NULL);
    bool pwned_exists = access(pwned, F_OK) == 0;

    remove(file);
    rmdir(dir);
    remove(pwned);

    ASSERT_TRUE(wrote, "Payload file written");
    ASSERT_INT_EQ(same, BOOTO_OK, "Identical stdin bytes must match");
    ASSERT_INT_EQ(status, 0, "Exit status 0 reported");
    ASSERT_TRUE(diff != BOOTO_OK, "Different stdin bytes must not match");
    ASSERT_TRUE(!pwned_exists, "Shell metacharacters must never be interpreted");
    TEST_PASS("test_exec_argv_stdin_verbatim");
}

static void test_exec_argv_not_found(void) {
    TEST_START("test_exec_argv_not_found");
    const char *const argv[] = {"booto_definitely_missing_binary_xyz", NULL};
    int status = 0;
    ASSERT_INT_EQ(disk_exec_argv(argv, NULL, 0, &status), BOOTO_ERR_NOT_FOUND, "Missing binary -> NOT_FOUND");
    ASSERT_INT_EQ(status, 127, "Exit status 127");
    TEST_PASS("test_exec_argv_not_found");
}

static void test_ensure_private_dir(void) {
    TEST_START("test_ensure_private_dir");
    char parent[] = "/tmp/booto_privdir_XXXXXX";
    ASSERT_TRUE(mkdtemp(parent) != NULL, "mkdtemp");

    char created[96], link[96], open_dir[96];
    snprintf(created, sizeof(created), "%s/new", parent);
    snprintf(link, sizeof(link), "%s/link", parent);
    snprintf(open_dir, sizeof(open_dir), "%s/open", parent);

    booto_error_t c_err = disk_ensure_private_dir(created);
    struct stat st;
    bool is_0700 = lstat(created, &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0700;
    booto_error_t again = disk_ensure_private_dir(created);

    bool link_ok = symlink(created, link) == 0;
    booto_error_t l_err = disk_ensure_private_dir(link);

    bool open_ok = mkdir(open_dir, 0700) == 0 && chmod(open_dir, 0777) == 0;
    booto_error_t o_err = disk_ensure_private_dir(open_dir);

    remove(link);
    rmdir(created);
    rmdir(open_dir);
    rmdir(parent);

    ASSERT_INT_EQ(c_err, BOOTO_OK, "Creates missing dir");
    ASSERT_TRUE(is_0700, "Created dir has mode 0700");
    ASSERT_INT_EQ(again, BOOTO_OK, "Existing private dir accepted");
    ASSERT_TRUE(link_ok && open_ok, "Fixture setup");
    ASSERT_INT_EQ(l_err, BOOTO_ERR_PERMISSION_DENIED, "Symlink rejected");
    ASSERT_INT_EQ(o_err, BOOTO_ERR_PERMISSION_DENIED, "0777 dir rejected");
    TEST_PASS("test_ensure_private_dir");
}

int main(void) {
    printf("\n--- Running Storage Discovery & Mount Tests ---\n");
    test_size_formatting();
    test_disk_enumeration();
    test_discovery_without_mock();
    test_nonroot_denied();
    test_fs_magic_probing();
    test_luks_invalid_mapper_name();
    test_exec_argv_stdin_verbatim();
    test_exec_argv_not_found();
    test_ensure_private_dir();
    TEST_SUMMARY();
    return 0;
}
