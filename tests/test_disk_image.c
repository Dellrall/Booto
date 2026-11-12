/**
 * @file test_disk_image.c
 * @brief Tests for read-only raw disk imaging (--acquire).
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "disk_image.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_dir[] = "/tmp/test_booto_image_XXXXXX";

static void test_image_matches_source(void) {
    TEST_START("Image is a byte copy with a matching SHA-256 and seal file");
    char src[128], dst[128], seal[160], line[200], want[65];
    snprintf(src, sizeof(src), "%s/disk.raw", g_dir);
    snprintf(dst, sizeof(dst), "%s/disk.img", g_dir);
    FILE *fp = fopen(src, "wb");
    ASSERT_TRUE(fp != NULL, "create source");
    for (int i = 0; i < 3 * 1024 * 1024 + 123; i++) fputc(i * 7 & 0xff, fp);  // not a multiple of the chunk
    fclose(fp);

    disk_image_result_t r;
    ASSERT_INT_EQ(disk_image_acquire(src, dst, &r), BOOTO_OK, "acquire succeeds");
    ASSERT_TRUE(r.bytes == 3u * 1024 * 1024 + 123 && r.bad_bytes == 0, "all bytes copied, none bad");
    ASSERT_TRUE(sha256_file_hex(src, want), "hash source");
    ASSERT_STR_EQ(r.sha256, want, "image hash equals source hash");
    ASSERT_TRUE(sha256_file_hex(dst, want), "hash image");
    ASSERT_STR_EQ(r.sha256, want, "image file hash equals reported hash");
    snprintf(seal, sizeof(seal), "%s.sha256", dst);
    fp = fopen(seal, "r");
    ASSERT_TRUE(fp && fgets(line, sizeof(line), fp), "seal file written");
    fclose(fp);
    ASSERT_TRUE(strncmp(line, r.sha256, 64) == 0 && strstr(line, "  disk.img"), "seal in sha256sum format");

    ASSERT_TRUE(disk_image_acquire(src, dst, &r) != BOOTO_OK, "an existing image is never overwritten");
    ASSERT_TRUE(disk_image_acquire("/nonexistent/booto", "/tmp/x", &r) != BOOTO_OK, "missing source fails");
    TEST_PASS("Image is a byte copy with a matching SHA-256 and seal file");
}

int main(void) {
    printf("\n--- Running Disk Image Tests ---\n");
    if (!mkdtemp(g_dir)) return 1;
    test_image_matches_source();
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    if (system(cmd) != 0) printf("cleanup failed\n");
    TEST_SUMMARY();
}
