/**
 * @file test_inspect.c
 * @brief Inspect capture: hashes, PE/ELF/MBR maps, hex rows, containment, and truncated PE headers.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "inspect.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inspect_sample_t g_s;

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static bool write_file(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(b, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

/* PE32+ x86-64 with .text (code, random bytes) and .data (zeros). */
static size_t make_pe(uint8_t *b, size_t cap) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z';
    put32(b + 0x3c, 0x80);
    memcpy(b + 0x80, "PE\0\0", 4);
    b[0x84] = 0x64; b[0x85] = 0x86;          /* machine x86-64 */
    b[0x86] = 2;                             /* two sections */
    b[0x94] = 0xf0;                          /* optional header size */
    b[0x98] = 0x0b; b[0x99] = 0x02;          /* PE32+ */
    uint8_t *sec = b + 0x98 + 0xf0;
    memcpy(sec, ".text", 5);
    put32(sec + 16, 0x1000); put32(sec + 20, 0x400); put32(sec + 36, 0x60000020);
    memcpy(sec + 40, ".data", 5);
    put32(sec + 56, 0x200); put32(sec + 60, 0x1400); put32(sec + 76, 0xC0000040);
    srand(7);
    for (size_t i = 0x400; i < 0x1400; i++) b[i] = (uint8_t)rand();
    return 0x1600;
}

static void test_pe_map_and_hashes(void) {
    TEST_START("test_pe_map_and_hashes");
    static uint8_t b[0x1600];
    size_t n = make_pe(b, sizeof(b));
    char path[] = "/tmp/booto_inspect_pe_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0 && write_file(path, b, n), "write PE fixture");
    close(fd);
    booto_error_t e = inspect_capture(NULL, path, 1u << 20, &g_s);
    char want[65];
    sha256_buffer_hex(b, n, want);
    unlink(path);
    ASSERT_INT_EQ(e, BOOTO_OK, "capture succeeds");
    ASSERT_STR_EQ(g_s.format, "PE32+ x86-64", "format");
    ASSERT_TRUE(g_s.len == n && g_s.file_size == n && g_s.hashed_len == n, "whole file kept and hashed");
    ASSERT_STR_EQ(g_s.sha256, want, "SHA-256 matches");
    ASSERT_INT_EQ(g_s.region_count, 2, "two sections");
    ASSERT_STR_EQ(g_s.regions[0].name, ".text", "first section name");
    ASSERT_TRUE(g_s.regions[0].exec && !g_s.regions[1].exec, "only .text is code");
    ASSERT_TRUE(g_s.regions[0].entropy > 7.5 && g_s.regions[1].entropy < 0.01, "random code high, zeros low");
    ASSERT_TRUE(inspect_entropy_char(g_s.regions[0].entropy) == '@' && inspect_entropy_char(0) == ' ', "scale ends");
    TEST_PASS("test_pe_map_and_hashes");
}

static void test_hex_row(void) {
    TEST_START("test_hex_row");
    char row[128];
    inspect_hex_row(&g_s, 0, row, sizeof(row));
    ASSERT_TRUE(strncmp(row, "00000000  4d 5a 00 00 00 00 00 00  00 00", 40) == 0, "offset and bytes");
    ASSERT_TRUE(strstr(row, "|MZ..............|") != NULL, "printable column");
    inspect_hex_row(&g_s, g_s.len, row, sizeof(row));
    ASSERT_STR_EQ(row, "", "past the end is empty");
    TEST_PASS("test_hex_row");
}

static void test_elf_and_mbr(void) {
    TEST_START("test_elf_and_mbr");
    ASSERT_INT_EQ(inspect_capture(NULL, "/proc/self/exe", 1u << 20, &g_s), BOOTO_OK, "capture own binary");
    ASSERT_TRUE(strncmp(g_s.format, "ELF64", 5) == 0, "ELF format");
    bool code = false;
    for (int i = 0; i < g_s.region_count; i++) code |= strcmp(g_s.regions[i].name, ".text") == 0 && g_s.regions[i].exec;
    ASSERT_TRUE(code, ".text found as code");

    static uint8_t m[4096];
    memset(m, 0, sizeof(m));
    m[510] = 0x55; m[511] = 0xAA;
    char path[] = "/tmp/booto_inspect_mbr_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0 && write_file(path, m, sizeof(m)), "write MBR fixture");
    close(fd);
    booto_error_t e = inspect_capture(NULL, path, sizeof(m), &g_s);
    unlink(path);
    ASSERT_INT_EQ(e, BOOTO_OK, "capture MBR");
    ASSERT_STR_EQ(g_s.format, "MBR boot sector", "MBR format");
    ASSERT_INT_EQ(g_s.region_count, 4, "boot code, table, signature, gap");
    TEST_PASS("test_elf_and_mbr");
}

static void test_symlink_escape_refused(void) {
    TEST_START("test_symlink_escape_refused");
    char dir[] = "/tmp/booto_inspect_root_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "make root");
    char link[64];
    snprintf(link, sizeof(link), "%s/evil", dir);
    ASSERT_TRUE(symlink("/etc/hostname", link) == 0, "plant symlink");
    booto_error_t e = inspect_capture(dir, link, 4096, &g_s);
    unlink(link);
    rmdir(dir);
    ASSERT_INT_EQ(e, BOOTO_ERR_PERMISSION_DENIED, "symlink out of the target is refused");
    TEST_PASS("test_symlink_escape_refused");
}

/* Every truncation and a hostile section count / header offset must stay inside the sample (ASan in CI). */
static void test_truncated_pe(void) {
    TEST_START("test_truncated_pe");
    static uint8_t b[0x1600];
    char path[] = "/tmp/booto_inspect_cut_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0, "temp file");
    close(fd);
    for (int variant = 0; variant < 3; variant++) {
        size_t n = make_pe(b, sizeof(b));
        if (variant == 1) { b[0x86] = 0xff; b[0x87] = 0xff; }
        if (variant == 2) put32(b + 0x3c, 0xfffffff0u);
        for (size_t cut = 0; cut <= 0x300; cut += 3) {
            ASSERT_TRUE(write_file(path, b, cut < n ? cut : n), "write cut");
            ASSERT_INT_EQ(inspect_capture(NULL, path, 1u << 20, &g_s), BOOTO_OK, "capture never fails on bad headers");
            ASSERT_TRUE(g_s.region_count <= INSPECT_MAX_REGIONS, "region cap holds");
        }
    }
    unlink(path);
    TEST_PASS("test_truncated_pe");
}

int main(void) {
    printf("--- Inspect ---\n");
    test_pe_map_and_hashes();
    test_hex_row();
    test_elf_and_mbr();
    test_symlink_escape_refused();
    test_truncated_pe();
    TEST_SUMMARY();
}
