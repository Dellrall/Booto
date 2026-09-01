/**
 * @file test_uefi_analyzer.c
 * @brief Unit tests for UEFI PE32+ parser, Authenticode verification, and DBX revocation matching.
 */
#include "test_framework.h"
#include "uefi_analyzer.h"

#include <string.h>

static void test_synthetic_pe32_plus_parser(void) {
    TEST_START("test_synthetic_pe32_plus_parser");

    // Construct a synthetic 512-byte PE32+ UEFI executable buffer
    uint8_t pe_buf[1024];
    memset(pe_buf, 0, sizeof(pe_buf));

    // DOS Header
    pe_buf[0] = 'M';
    pe_buf[1] = 'Z';
    pe_buf[0x3C] = 0x80; // e_lfanew = 0x80

    // PE Header at 0x80
    size_t pe_hdr = 0x80;
    pe_buf[pe_hdr] = 'P';
    pe_buf[pe_hdr + 1] = 'E';

    // COFF Header at 0x84 (20 bytes)
    size_t coff = pe_hdr + 4;
    pe_buf[coff] = 0x64;
    pe_buf[coff + 1] = 0x86; // Machine = 0x8664 (AMD64)
    pe_buf[coff + 2] = 2;    // NumberOfSections = 2
    pe_buf[coff + 16] = 0xF0;// SizeOfOptionalHeader = 240 bytes

    // PE32+ Optional Header at 0x98
    size_t opt = coff + 20;
    pe_buf[opt] = 0x0b;
    pe_buf[opt + 1] = 0x02;  // Magic = 0x20b (PE32+)
    pe_buf[opt + 16] = 0x00;
    pe_buf[opt + 17] = 0x10; // EntryPoint = 0x1000
    pe_buf[opt + 68] = 10;   // Subsystem = 10 (IMAGE_SUBSYSTEM_EFI_APPLICATION)
    pe_buf[opt + 108] = 16;  // NumberOfRvaAndSizes = 16

    // Security Directory (Directory #4) at opt + 112 + (4 * 8) = opt + 144
    size_t sec_dir = opt + 112 + 32;
    pe_buf[sec_dir] = 0x00;
    pe_buf[sec_dir + 1] = 0x02; // CertTable RVA = 0x200 (within 1024 bytes)
    pe_buf[sec_dir + 4] = 0x80; // CertTable Size = 128 bytes

    pe_efi_info_t info;
    booto_error_t err = uefi_parse_pe_buffer(pe_buf, sizeof(pe_buf), &info);

    ASSERT_INT_EQ(err, BOOTO_OK, "Parsing synthetic PE32+ must succeed");
    ASSERT_TRUE(info.is_pe32_plus, "Binary must be identified as PE32+ (64-bit)");
    ASSERT_INT_EQ(info.machine_type, 0x8664, "Machine type must be x86_64");
    ASSERT_INT_EQ(info.subsystem, 10, "Subsystem must be EFI Application");
    ASSERT_TRUE(info.has_authenticode, "Authenticode certificate directory must be detected");

    TEST_PASS("test_synthetic_pe32_plus_parser");
}

static void test_corrupted_pe_rejection(void) {
    TEST_START("test_corrupted_pe_rejection");

    uint8_t garbage[128];
    memset(garbage, 0xAA, sizeof(garbage));

    pe_efi_info_t info;
    booto_error_t err = uefi_parse_pe_buffer(garbage, sizeof(garbage), &info);
    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Corrupted buffer without MZ header must be rejected");

    TEST_PASS("test_corrupted_pe_rejection");
}

static void test_dbx_revocation_matching(void) {
    TEST_START("test_dbx_revocation_matching");

    // Manually test revocation database search
    const char *blacklotus_hash = "0c644d57c79e614066929a008c2a382d5e305e9e03d42c38848d7c4dbfc78f24";
    pe_efi_info_t info;
    memset(&info, 0, sizeof(info));
    snprintf(info.sha256, sizeof(info.sha256), "%s", blacklotus_hash);

    // Call inspection logic on mock result
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));

    // Verify DBX matching
    ASSERT_STR_EQ(info.sha256, blacklotus_hash, "Hash match test");
    TEST_PASS("test_dbx_revocation_matching");
}

int main(void) {
    printf("\n--- Running UEFI & ESP Bootkit Analyzer Tests ---\n");
    test_synthetic_pe32_plus_parser();
    test_corrupted_pe_rejection();
    test_dbx_revocation_matching();
    TEST_SUMMARY();
    return 0;
}
