/**
 * @file test_fuzz.c
 * @brief Defensive mutation-based fuzzing harness for Booto binary parsers.
 */
#include "test_framework.h"
#include "elf_analyzer.h"
#include "uefi_analyzer.h"
#include "initramfs_auditor.h"

#include <stdlib.h>
#include <string.h>

#define FUZZ_ITERATIONS 500

static void test_fuzz_elf_parser(void) {
    TEST_START("test_fuzz_elf_parser");

    uint8_t buffer[2048];
    srand(42); // Deterministic seed

    for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
        size_t len = (size_t)((unsigned int)rand() % (unsigned int)sizeof(buffer));

        // Fill with randomized mutated bytes
        for (size_t i = 0; i < len; i++) {
            buffer[i] = (uint8_t)((unsigned int)rand() % 256U);
        }

        // Occasionally inject valid ELF magic to test deeper parser branches
        if (iter % 3 == 0 && len >= 4) {
            buffer[0] = 0x7F;
            buffer[1] = 'E';
            buffer[2] = 'L';
            buffer[3] = 'F';
        }

        elf_binary_info_t info;
        booto_error_t err = elf_parse_buffer(buffer, len, &info);
        (void)err; // Must safely return error without crashing

        if (err == BOOTO_OK) {
            elf_free_info(&info);
        }
    }

    TEST_PASS("test_fuzz_elf_parser");
}

static void test_fuzz_uefi_parser(void) {
    TEST_START("test_fuzz_uefi_parser");

    uint8_t buffer[2048];
    srand(1337);

    for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
        size_t len = (size_t)((unsigned int)rand() % (unsigned int)sizeof(buffer));

        for (size_t i = 0; i < len; i++) {
            buffer[i] = (uint8_t)((unsigned int)rand() % 256U);
        }

        // Occasionally inject MZ header
        if (iter % 3 == 0 && len >= 2) {
            buffer[0] = 'M';
            buffer[1] = 'Z';
        }

        pe_efi_info_t info;
        booto_error_t err = uefi_parse_pe_buffer(buffer, len, &info);
        (void)err;
    }

    TEST_PASS("test_fuzz_uefi_parser");
}

static void test_fuzz_initramfs_parser(void) {
    TEST_START("test_fuzz_initramfs_parser");

    uint8_t buffer[2048];
    srand(9999);

    for (int iter = 0; iter < FUZZ_ITERATIONS; iter++) {
        size_t len = (size_t)((unsigned int)rand() % (unsigned int)sizeof(buffer));

        for (size_t i = 0; i < len; i++) {
            buffer[i] = (uint8_t)((unsigned int)rand() % 256U);
        }

        // Occasionally inject CPIO 070701 magic
        if (iter % 3 == 0 && len >= 6) {
            memcpy(buffer, "070701", 6);
        }

        initramfs_scan_result_t res;
        booto_error_t err = initramfs_audit_buffer(buffer, len, &res);
        (void)err;
    }

    TEST_PASS("test_fuzz_initramfs_parser");
}

int main(void) {
    printf("\n--- Running Defensive Parser Mutation Fuzzing Harness ---\n");
    test_fuzz_elf_parser();
    test_fuzz_uefi_parser();
    test_fuzz_initramfs_parser();
    TEST_SUMMARY();
    return 0;
}
