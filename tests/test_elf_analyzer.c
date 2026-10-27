/**
 * @file test_elf_analyzer.c
 * @brief Unit tests for SHA-256 crypto, ELF parser, and Kernel LKM Rootkit detection.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "elf_analyzer.h"
#include "kernel_inspector.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_sha256_known_vector(void) {
    TEST_START("test_sha256_known_vector");
    const char *msg = "hello world";
    char hex[65];
    sha256_buffer_hex((const uint8_t *)msg, strlen(msg), hex);

    // NIST FIPS-180-4 standard test vector for "hello world"
    ASSERT_STR_EQ(hex, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                  "SHA-256 of 'hello world' must match NIST standard vector");
    TEST_PASS("test_sha256_known_vector");
}

static void test_elf_parser_on_binary(void) {
    TEST_START("test_elf_parser_on_binary");
    elf_binary_info_t info;
    booto_error_t err = elf_parse_file("./build/test_logger", &info);
    ASSERT_INT_EQ(err, BOOTO_OK, "Parsing valid ELF binary must succeed");
    ASSERT_TRUE(info.is_64bit, "Target ELF binary must be 64-bit");
    ASSERT_TRUE(info.is_little_endian, "Target ELF binary must be Little Endian");
    ASSERT_TRUE(info.section_count > 0, "ELF section count must be > 0");
    ASSERT_TRUE(strlen(info.sha256) == 64, "Binary SHA-256 must be 64 hex characters");

    // Test symbol lookup
    const elf_symbol_info_t *sym = elf_find_symbol(&info, "main");
    (void)sym;

    elf_free_info(&info);
    TEST_PASS("test_elf_parser_on_binary");
}

static void test_rootkit_lkm_detection(void) {
    TEST_START("test_rootkit_lkm_detection");

    // Create a mock directory with a mock .ko file
    system("mkdir -p /tmp/mock_lkm_test");
    FILE *fp = fopen("/tmp/mock_lkm_test/fake_diamorphine.ko", "w");
    if (fp) {
        fprintf(fp, "fake payload");
        fclose(fp);
    }

    kernel_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = kernel_inspect_lkm_file("/tmp/mock_lkm_test/fake_diamorphine.ko", &res);
    (void)err;

    kernel_inspect_directory("/tmp/mock_lkm_test", &res);
    kernel_inspect_vmlinuz("/tmp/mock_lkm_test/vmlinuz", &res);

    const char *sev_str = kernel_severity_to_string(SEVERITY_CRITICAL);
    ASSERT_TRUE(sev_str != NULL, "Severity string must not be null");

    system("rm -rf /tmp/mock_lkm_test");
    TEST_PASS("test_rootkit_lkm_detection");
}

static void test_elf_wrapping_shoff_rejected(void) {
    TEST_START("test_elf_wrapping_shoff_rejected");
    uint8_t buf[sizeof(Elf64_Ehdr) + 64];
    memset(buf, 0, sizeof(buf));
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_shnum = 4;
    eh->e_shoff = UINT64_MAX - 0xFF; // e_shoff + 4*64 wraps to a small value
    elf_binary_info_t info;
    ASSERT_INT_EQ(elf_parse_buffer(buf, sizeof(buf), &info), BOOTO_ERR_CORRUPT_DATA, "Wrapping e_shoff must be rejected");
    elf_free_info(&info);
    TEST_PASS("test_elf_wrapping_shoff_rejected");
}

static void test_elf_unterminated_shstrtab(void) {
    TEST_START("test_elf_unterminated_shstrtab");
    // Ehdr | 2 section headers | 4-byte .shstrtab "AAAA" with no NUL, ending exactly at the buffer end.
    size_t len = sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Shdr) + 4;
    uint8_t *buf = calloc(1, len);
    ASSERT_TRUE(buf != NULL, "alloc");
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_shnum = 2;
    eh->e_shoff = sizeof(Elf64_Ehdr);
    eh->e_shstrndx = 1;
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    sh[1].sh_type = SHT_STRTAB;
    sh[1].sh_offset = len - 4;
    sh[1].sh_size = 4;
    memcpy(buf + len - 4, "AAAA", 4);

    elf_binary_info_t info;
    booto_error_t err = elf_parse_buffer(buf, len, &info);
    free(buf);
    ASSERT_INT_EQ(err, BOOTO_OK, "Unterminated string table must parse without over-read");
    ASSERT_STR_EQ(info.sections[0].name, "AAAA", "Name must be bounded by the table size");
    elf_free_info(&info);
    TEST_PASS("test_elf_unterminated_shstrtab");
}

int main(void) {
    printf("\n--- Running ELF Parser & Kernel Rootkit Scanner Tests ---\n");
    test_sha256_known_vector();
    test_elf_parser_on_binary();
    test_rootkit_lkm_detection();
    test_elf_wrapping_shoff_rejected();
    test_elf_unterminated_shstrtab();
    TEST_SUMMARY();
    return 0;
}
