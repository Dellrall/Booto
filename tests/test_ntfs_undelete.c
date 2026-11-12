/**
 * @file test_ntfs_undelete.c
 * @brief Tests for NTFS deleted-file recovery (--undelete) on a synthetic volume.
 */
#include "test_framework.h"
#include "ntfs_undelete.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CS 4096u
#define RS 1024u
#define MFT_LCN 4u
#define DATA_LCN 10u

static uint8_t g_vol[64 * CS];
static char g_dir[] = "/tmp/test_booto_undel_XXXXXX";

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static uint8_t *rec(unsigned i) { return g_vol + MFT_LCN * CS + i * RS; }

static size_t g_off;

static void begin(unsigned i, uint16_t flags) {
    uint8_t *r = rec(i);
    memcpy(r, "FILE", 4);
    put16(r + 4, 0x30);
    put16(r + 6, 3);
    put16(r + 0x14, 0x38);
    put16(r + 0x16, flags);
    g_off = 0x38;
}

static uint8_t *attr(unsigned i, uint32_t type, uint32_t len, bool nonres) {
    uint8_t *a = rec(i) + g_off;
    len = (len + 7) & ~7u;
    put32(a, type);
    put32(a + 4, len);
    a[8] = nonres;
    g_off += len;
    return a;
}

static void resident(unsigned i, uint32_t type, const void *val, uint32_t n) {
    uint8_t *a = attr(i, type, 24 + n, false);
    put32(a + 0x10, n);
    put16(a + 0x14, 24);
    memcpy(a + 24, val, n);
}

static void file_name(unsigned i, const char *name) {
    uint8_t v[0x42 + 64] = {0};
    size_t n = strlen(name);
    v[0x40] = (uint8_t)n;
    v[0x41] = 1;
    for (size_t k = 0; k < n; k++) v[0x42 + 2 * k] = (uint8_t)name[k];
    resident(i, 0x30, v, (uint32_t)(0x42 + 2 * n));
}

static void nonresident(unsigned i, uint8_t clusters, uint8_t lcn, uint64_t size) {
    uint8_t *a = attr(i, 0x80, 0x48, true);
    put16(a + 0x20, 0x40);
    put64(a + 0x30, size);
    a[0x40] = 0x11, a[0x41] = clusters, a[0x42] = lcn;
}

/* End marker, then the update sequence: sector tails get USN 1, their bytes move to the array. */
static void end(unsigned i, bool bad_fixup) {
    uint8_t *r = rec(i);
    put32(r + g_off, 0xFFFFFFFFu);
    put32(r + 0x18, (uint32_t)g_off + 8);
    put16(r + 0x30, 1);
    memcpy(r + 0x32, r + 510, 2);
    memcpy(r + 0x34, r + 1022, 2);
    put16(r + 510, 1);
    put16(r + 1022, bad_fixup ? 2 : 1);
}

static void build_volume(const char *path) {
    memset(g_vol, 0, sizeof(g_vol));
    memcpy(g_vol + 3, "NTFS    ", 8);
    put16(g_vol + 0x0B, 512);
    g_vol[0x0D] = 8;
    put64(g_vol + 0x28, sizeof(g_vol) / 512);
    put64(g_vol + 0x30, MFT_LCN);
    g_vol[0x40] = 0xF6;  // 2^10 = 1024-byte records

    begin(0, 1), file_name(0, "$MFT"), nonresident(0, 2, MFT_LCN, 8 * RS), end(0, false);
    begin(1, 0), file_name(1, "note.txt"), resident(1, 0x80, "secret plan", 11), end(1, false);
    begin(2, 0), file_name(2, "big.bin"), nonresident(2, 2, DATA_LCN, 5000), end(2, false);
    begin(3, 1), file_name(3, "live.txt"), resident(3, 0x80, "in use", 6), end(3, false);
    begin(4, 0), resident(4, 0x20, "", 0), file_name(4, "split.dat"), resident(4, 0x80, "x", 1), end(4, false);
    begin(5, 0), file_name(5, "../evil"), resident(5, 0x80, "e", 1), end(5, false);
    begin(6, 0), file_name(6, "torn.txt"), resident(6, 0x80, "t", 1), end(6, true);
    for (unsigned k = 0; k < 5000; k++) g_vol[DATA_LCN * CS + k] = (uint8_t)(k * 13);

    FILE *fp = fopen(path, "wb");
    fwrite(g_vol, 1, sizeof(g_vol), fp);
    fclose(fp);
}

static size_t slurp(const char *name, uint8_t *buf, size_t n) {
    char p[256];
    snprintf(p, sizeof(p), "%s/out/%s", g_dir, name);
    FILE *fp = fopen(p, "rb");
    if (!fp) return 0;
    size_t got = fread(buf, 1, n, fp);
    fclose(fp);
    return got;
}

static void test_undelete(void) {
    TEST_START("Deleted NTFS files are recovered, live and torn records are not");
    char vol[160], out[160];
    snprintf(vol, sizeof(vol), "%s/ntfs.img", g_dir);
    snprintf(out, sizeof(out), "%s/out", g_dir);
    build_volume(vol);
    mkdir(out, 0700);
    ntfs_undelete_result_t r;
    ASSERT_INT_EQ(ntfs_undelete(vol, out, &r), BOOTO_OK, "undelete runs");
    ASSERT_TRUE(r.records == 8 && r.deleted == 4 && r.recovered == 3 && r.skipped == 1, "counts: 8 read, 4 deleted, 3 recovered, attribute list skipped");

    uint8_t buf[8192];
    ASSERT_TRUE(slurp("1_note.txt.recovered", buf, sizeof(buf)) == 11 && memcmp(buf, "secret plan", 11) == 0,
                "resident data recovered");
    ASSERT_TRUE(slurp("2_big.bin.recovered", buf, sizeof(buf)) == 5000 && memcmp(buf, g_vol + DATA_LCN * CS, 5000) == 0,
                "non-resident data recovered to its real size");
    ASSERT_TRUE(slurp("5_.._evil.recovered", buf, sizeof(buf)) == 1, "a path in the name stays inside the folder");
    ASSERT_TRUE(slurp("3_live.txt.recovered", buf, sizeof(buf)) == 0, "an in-use file is not copied");
    ASSERT_TRUE(slurp("6_torn.txt.recovered", buf, sizeof(buf)) == 0, "a record with bad fixups is ignored");

    struct stat st;
    snprintf(vol + strlen(g_dir), sizeof(vol) - strlen(g_dir), "/out/1_note.txt.recovered");
    ASSERT_TRUE(stat(vol, &st) == 0 && (st.st_mode & 0777) == 0400, "recovered files are read-only");

    snprintf(vol, sizeof(vol), "%s/ntfs.img", g_dir);
    ASSERT_INT_EQ(ntfs_undelete(vol, out, &r), BOOTO_OK, "second run");
    ASSERT_TRUE(r.recovered == 0, "existing recovered files are never overwritten");
    TEST_PASS("Deleted NTFS files are recovered, live and torn records are not");
}

static void test_not_ntfs(void) {
    TEST_START("A non-NTFS device is refused");
    char p[160];
    snprintf(p, sizeof(p), "%s/zero.img", g_dir);
    FILE *fp = fopen(p, "wb");
    for (int i = 0; i < 4096; i++) fputc(0, fp);
    fclose(fp);
    ntfs_undelete_result_t r;
    ASSERT_INT_EQ(ntfs_undelete(p, g_dir, &r), BOOTO_ERR_NOT_FOUND, "zeros are not NTFS");
    uint8_t one[RS] = "FILE";
    ntfs_record_t nr;
    ASSERT_INT_EQ(ntfs_parse_record(one, sizeof(one), &nr), BOOTO_ERR_CORRUPT_DATA, "record without fixups is corrupt");
    TEST_PASS("A non-NTFS device is refused");
}

int main(void) {
    printf("\n--- Running NTFS Undelete Tests ---\n");
    if (!mkdtemp(g_dir)) return 1;
    test_undelete();
    test_not_ntfs();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "chmod -R u+w %s && rm -rf %s", g_dir, g_dir);
    if (system(cmd) != 0) return 1;
    TEST_SUMMARY();
    return 0;
}
