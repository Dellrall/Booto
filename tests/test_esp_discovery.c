/**
 * @file test_esp_discovery.c
 * @brief Unit tests for ESP auto-discovery (GPT/MBR parsing and sysfs partition mapping).
 */
#include "test_framework.h"
#include "disk_mount.h"

#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint8_t ESP_GUID[16] = {0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                                     0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B};
static const uint8_t LINUX_GUID[16] = {0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                                       0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4};

#define ENTRIES 128u
#define ESIZE   128u

static uint32_t crc32(const uint8_t *p, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static void wr32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void wr64(uint8_t *p, uint64_t v) {
    wr32(p, (uint32_t)v);
    wr32(p + 4, (uint32_t)(v >> 32));
}

static void fix_header_crc(uint8_t *img, uint32_t ss) {
    uint8_t *h = img + ss;
    wr32(h + 16, 0);
    wr32(h + 16, crc32(h, 92));
}

/* Image: protective MBR, GPT header at LBA1, entries at LBA2; nparts entries, ESP at esp_idx. */
static uint8_t *build_gpt(uint32_t ss, int nparts, int esp_idx, size_t *len) {
    *len = (size_t)ss * 2 + ENTRIES * ESIZE;
    uint8_t *img = calloc(1, *len);
    if (!img) return NULL;
    img[446 + 4] = 0xEE;
    img[510] = 0x55;
    img[511] = 0xAA;
    uint8_t *e = img + (size_t)ss * 2;
    for (int i = 0; i < nparts; i++) memcpy(e + (size_t)i * ESIZE, i == esp_idx ? ESP_GUID : LINUX_GUID, 16);
    uint8_t *h = img + ss;
    memcpy(h, "EFI PART", 8);
    wr32(h + 8, 0x00010000u);
    wr32(h + 12, 92);
    wr64(h + 72, 2);
    wr32(h + 80, ENTRIES);
    wr32(h + 84, ESIZE);
    wr32(h + 88, crc32(e, ENTRIES * ESIZE));
    fix_header_crc(img, ss);
    return img;
}

static void test_gpt_esp_first(void) {
    TEST_START("test_gpt_esp_first");
    size_t len;
    uint8_t *img = build_gpt(512, 3, 0, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    uint32_t nums[DISK_MAX_ESP];
    int n = -1;
    booto_error_t err = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    free(img);
    ASSERT_INT_EQ(err, BOOTO_OK, "parse ok");
    ASSERT_INT_EQ(n, 1, "one ESP");
    ASSERT_INT_EQ(nums[0], 1, "ESP is partition 1");
    TEST_PASS("test_gpt_esp_first");
}

static void test_gpt_esp_third(void) {
    TEST_START("test_gpt_esp_third");
    size_t len;
    uint8_t *img = build_gpt(512, 3, 2, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    uint32_t nums[DISK_MAX_ESP];
    int n = -1;
    booto_error_t err = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    free(img);
    ASSERT_INT_EQ(err, BOOTO_OK, "parse ok");
    ASSERT_INT_EQ(n, 1, "one ESP");
    ASSERT_INT_EQ(nums[0], 3, "ESP is partition 3");
    TEST_PASS("test_gpt_esp_third");
}

static void test_gpt_header_crc_bad(void) {
    TEST_START("test_gpt_header_crc_bad");
    size_t len;
    uint8_t *img = build_gpt(512, 3, 0, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    img[512 + 16] ^= 0xFF;
    uint32_t nums[DISK_MAX_ESP];
    int n;
    booto_error_t err = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    free(img);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "header CRC mismatch");
    TEST_PASS("test_gpt_header_crc_bad");
}

static void test_gpt_array_crc_bad(void) {
    TEST_START("test_gpt_array_crc_bad");
    size_t len;
    uint8_t *img = build_gpt(512, 3, 0, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    img[1024 + ESIZE * 5] = 0x42; /* tamper an unused entry; header CRC still valid */
    uint32_t nums[DISK_MAX_ESP];
    int n;
    booto_error_t err = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    free(img);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "entry array CRC mismatch");
    TEST_PASS("test_gpt_array_crc_bad");
}

static void test_gpt_4096_file(void) {
    TEST_START("test_gpt_4096_file");
    size_t len;
    uint8_t *img = build_gpt(4096, 2, 1, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    char path[] = "/tmp/booto_esp_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) free(img);
    ASSERT_TRUE(fd >= 0, "mkstemp");
    ssize_t w = write(fd, img, len);
    close(fd);
    free(img);
    uint32_t nums[DISK_MAX_ESP];
    int n = -1;
    booto_error_t err = disk_find_esp_partitions(path, nums, DISK_MAX_ESP, &n);
    unlink(path);
    ASSERT_TRUE(w == (ssize_t)len, "write image");
    ASSERT_INT_EQ(err, BOOTO_OK, "find ok");
    ASSERT_INT_EQ(n, 1, "one ESP");
    ASSERT_INT_EQ(nums[0], 2, "ESP is partition 2");
    TEST_PASS("test_gpt_4096_file");
}

static void test_mbr_esp(void) {
    TEST_START("test_mbr_esp");
    uint8_t mbr[512] = {0};
    mbr[446 + 0 * 16 + 4] = 0x83;
    mbr[446 + 2 * 16 + 4] = 0xEF;
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    uint32_t nums[DISK_MAX_ESP];
    int n = -1;
    ASSERT_INT_EQ(disk_parse_esp_partitions(mbr, sizeof(mbr), 512, nums, DISK_MAX_ESP, &n), BOOTO_OK, "parse ok");
    ASSERT_INT_EQ(n, 1, "one ESP");
    ASSERT_INT_EQ(nums[0], 3, "ESP in slot 3");
    TEST_PASS("test_mbr_esp");
}

static void test_protective_without_gpt(void) {
    TEST_START("test_protective_without_gpt");
    uint8_t img[1024];
    memset(img, 0xA5, sizeof(img));
    memset(img + 446, 0, 64);
    img[446 + 4] = 0xEE;
    img[510] = 0x55;
    img[511] = 0xAA;
    uint32_t nums[DISK_MAX_ESP];
    int n;
    ASSERT_INT_EQ(disk_parse_esp_partitions(img, sizeof(img), 512, nums, DISK_MAX_ESP, &n), BOOTO_ERR_CORRUPT_DATA,
                  "protective MBR without GPT");
    TEST_PASS("test_protective_without_gpt");
}

static void test_no_table(void) {
    TEST_START("test_no_table");
    uint8_t img[1024] = {0};
    uint32_t nums[DISK_MAX_ESP];
    int n = -1;
    ASSERT_INT_EQ(disk_parse_esp_partitions(img, sizeof(img), 512, nums, DISK_MAX_ESP, &n), BOOTO_OK, "no table ok");
    ASSERT_INT_EQ(n, 0, "no ESP");
    TEST_PASS("test_no_table");
}

static void test_hostile_header(void) {
    TEST_START("test_hostile_header");
    size_t len;
    uint8_t *img = build_gpt(512, 3, 0, &len);
    ASSERT_TRUE(img != NULL, "alloc");
    uint32_t nums[DISK_MAX_ESP];
    int n;
    wr32(img + 512 + 80, 0xFFFFFFFFu);
    fix_header_crc(img, 512);
    booto_error_t e1 = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    wr32(img + 512 + 80, ENTRIES);
    wr64(img + 512 + 72, 0xFFFFFFFFFFFFFF00ull);
    fix_header_crc(img, 512);
    booto_error_t e2 = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    wr64(img + 512 + 72, 1000);
    fix_header_crc(img, 512);
    booto_error_t e3 = disk_parse_esp_partitions(img, len, 512, nums, DISK_MAX_ESP, &n);
    free(img);
    ASSERT_INT_EQ(e1, BOOTO_ERR_CORRUPT_DATA, "huge entry count");
    ASSERT_INT_EQ(e2, BOOTO_ERR_CORRUPT_DATA, "overflowing entry LBA");
    ASSERT_INT_EQ(e3, BOOTO_ERR_CORRUPT_DATA, "entry LBA past end");
    TEST_PASS("test_hostile_header");
}

static void test_sysfs_mapping(void) {
    TEST_START("test_sysfs_mapping");
    char out[256];
    ASSERT_INT_EQ(disk_partition_parent("/dev/../etc", out, sizeof(out)), BOOTO_ERR_INVALID_ARG, "reject ..");
    ASSERT_INT_EQ(disk_partition_parent("/dev/booto_nonexistent0p1", out, sizeof(out)), BOOTO_ERR_NOT_FOUND,
                  "nonexistent");

    DIR *d = opendir("/sys/class/block");
    if (!d) {
        printf("    note: /sys/class/block unavailable, round-trip skipped\n");
        TEST_PASS("test_sysfs_mapping");
        return;
    }
    char part[300] = "";
    unsigned num = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && part[0] == '\0') {
        if (de->d_name[0] == '.') continue;
        char p[512];
        snprintf(p, sizeof(p), "/sys/class/block/%s/partition", de->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        if (fscanf(f, "%u", &num) == 1) snprintf(part, sizeof(part), "/dev/%s", de->d_name);
        fclose(f);
    }
    closedir(d);
    if (part[0] == '\0') {
        printf("    note: no partitions in /sys/class/block, round-trip skipped\n");
        TEST_PASS("test_sysfs_mapping");
        return;
    }
    char parent[256], back[256];
    ASSERT_INT_EQ(disk_partition_parent(part, parent, sizeof(parent)), BOOTO_OK, "parent lookup");
    ASSERT_INT_EQ(disk_partition_by_number(parent, num, back, sizeof(back)), BOOTO_OK, "by_number lookup");
    ASSERT_STR_EQ(back, part, "round-trip");
    printf("    %s -> %s #%u\n", part, parent, num);
    TEST_PASS("test_sysfs_mapping");
}

int main(void) {
    printf("Running ESP discovery tests...\n");
    test_gpt_esp_first();
    test_gpt_esp_third();
    test_gpt_header_crc_bad();
    test_gpt_array_crc_bad();
    test_gpt_4096_file();
    test_mbr_esp();
    test_protective_without_gpt();
    test_no_table();
    test_hostile_header();
    test_sysfs_mapping();
    TEST_SUMMARY();
    return 0;
}
