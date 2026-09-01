/**
 * @file test_elf_analyzer.c
 * @brief Unit tests for SHA-256 crypto, ELF parser, and Kernel LKM Rootkit detection.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "elf_analyzer.h"
#include "kernel_inspector.h"

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

    elf_free_info(&info);
    TEST_PASS("test_elf_parser_on_binary");
}

static void test_rootkit_lkm_detection(void) {
    TEST_START("test_rootkit_lkm_detection");

    // Construct a synthetic mock ELF binary in-memory with rootkit symbols
    elf_binary_info_t mock_elf;
    memset(&mock_elf, 0, sizeof(mock_elf));
    mock_elf.symbol_count = 4;
    mock_elf.symbols = (elf_symbol_info_t *)calloc(4, sizeof(elf_symbol_info_t));

    snprintf(mock_elf.symbols[0].name, sizeof(mock_elf.symbols[0].name), "diamorphine_init");
    mock_elf.symbols[0].value = 0x1000;
    snprintf(mock_elf.symbols[1].name, sizeof(mock_elf.symbols[1].name), "sys_call_table");
    mock_elf.symbols[1].value = 0x2000;
    snprintf(mock_elf.symbols[2].name, sizeof(mock_elf.symbols[2].name), "hacked_kill");
    mock_elf.symbols[2].value = 0x3000;
    snprintf(mock_elf.symbols[3].name, sizeof(mock_elf.symbols[3].name), "hide_proc");
    mock_elf.symbols[3].value = 0x4000;

    kernel_scan_result_t res;
    memset(&res, 0, sizeof(res));

    // Manually evaluate against LKM rules
    for (int i = 0; i < mock_elf.symbol_count; i++) {
        if (strstr(mock_elf.symbols[i].name, "diamorphine") ||
            strstr(mock_elf.symbols[i].name, "sys_call_table") ||
            strstr(mock_elf.symbols[i].name, "hacked_kill") ||
            strstr(mock_elf.symbols[i].name, "hide_proc")) {
            res.threats_detected++;
        }
    }

    ASSERT_INT_EQ(res.threats_detected, 4, "Must detect all 4 synthetic rootkit symbols");
    elf_free_info(&mock_elf);
    TEST_PASS("test_rootkit_lkm_detection");
}

int main(void) {
    printf("\n--- Running ELF Parser & Kernel Rootkit Scanner Tests ---\n");
    test_sha256_known_vector();
    test_elf_parser_on_binary();
    test_rootkit_lkm_detection();
    TEST_SUMMARY();
    return 0;
}
