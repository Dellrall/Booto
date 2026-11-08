/**
 * @file test_uefi_analyzer.c
 * @brief Unit tests for UEFI PE32+ parser, Authenticode verification, and DBX revocation matching.
 */
#include "test_framework.h"
#include "uefi_analyzer.h"
#include "crypto_utils.h"
#include "rules_loader.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    pe_buf[opt + 61] = 0x02;    // SizeOfHeaders = 0x200

    pe_efi_info_t info;
    booto_error_t err = uefi_parse_pe_buffer(pe_buf, sizeof(pe_buf), &info);

    ASSERT_INT_EQ(err, BOOTO_OK, "Parsing synthetic PE32+ must succeed");
    ASSERT_TRUE(info.is_pe32_plus, "Binary must be identified as PE32+ (64-bit)");
    ASSERT_INT_EQ(info.machine_type, 0x8664, "Machine type must be x86_64");
    ASSERT_INT_EQ(info.subsystem, 10, "Subsystem must be EFI Application");
    ASSERT_TRUE(info.has_authenticode, "Authenticode certificate directory must be detected");

    // Write buffer to temp file to test file parsing
    ASSERT_TRUE(system("mkdir -p /tmp/mock_esp_test/EFI/BOOT") == 0, "mkdir failed");
    FILE *fp = fopen("/tmp/mock_esp_test/EFI/BOOT/BOOTX64.EFI", "wb");
    if (fp) {
        fwrite(pe_buf, 1, sizeof(pe_buf), fp);
        fclose(fp);
    }

    pe_efi_info_t file_info;
    booto_error_t f_err = uefi_parse_pe_file("/tmp/mock_esp_test/EFI/BOOT/BOOTX64.EFI", &file_info);
    ASSERT_INT_EQ(f_err, BOOTO_OK, "File parsing must succeed");

    uefi_scan_result_t s_res;
    memset(&s_res, 0, sizeof(s_res));
    uefi_inspect_efi_file("/tmp/mock_esp_test/EFI/BOOT/BOOTX64.EFI", &s_res);
    uefi_inspect_esp_directory("/tmp/mock_esp_test", &s_res);

    const char *sev = booto_severity_str(SEVERITY_CRITICAL);
    ASSERT_TRUE(sev != NULL, "Severity string must not be NULL");

    ASSERT_TRUE(system("rm -rf /tmp/mock_esp_test") == 0, "cleanup failed");
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

/* Build a 0x300-byte image (headers 0x200 + one 0x100 section); with_cert appends a 0x80 cert table at 0x300. */
static size_t build_pe(uint8_t *b, size_t cap, bool pe32_plus, bool with_cert) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    b[coff] = 0x64; b[coff + 1] = 0x86;
    b[coff + 2] = 1;                               // NumberOfSections
    b[coff + 16] = pe32_plus ? 0xF0 : 0xE0;        // SizeOfOptionalHeader
    b[opt] = 0x0b; b[opt + 1] = pe32_plus ? 0x02 : 0x01;
    b[opt + 60] = 0x00; b[opt + 61] = 0x02;        // SizeOfHeaders = 0x200
    b[opt + 64] = 0x11; b[opt + 65] = 0x22;        // CheckSum
    b[opt + 68] = 10;
    b[opt + (pe32_plus ? 108 : 92)] = 16;          // NumberOfRvaAndSizes
    size_t sect = opt + (pe32_plus ? 0xF0 : 0xE0);
    b[sect + 17] = 0x01;                           // SizeOfRawData = 0x100
    b[sect + 21] = 0x02;                           // PointerToRawData = 0x200
    for (size_t i = 0x200; i < 0x300; i++) b[i] = (uint8_t)i;
    if (!with_cert) return 0x300;
    size_t dir = opt + (pe32_plus ? 112 : 96) + 32;
    b[dir + 1] = 0x03;                             // cert table at file offset 0x300
    b[dir + 4] = 0x80;
    memset(b + 0x300, 0xC5, 0x80);
    return 0x380;
}

static void test_authenticode_invariance(void) {
    TEST_START("test_authenticode_invariance");
    uint8_t b[0x400];
    pe_efi_info_t base, info;

    size_t len = build_pe(b, sizeof(b), true, false);
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &base), BOOTO_OK, "Unsigned image parses");
    ASSERT_TRUE(!base.has_authenticode, "No cert table");
    ASSERT_INT_EQ((int)strlen(base.authenticode_sha256), 64, "Authenticode hash computed");

    b[0x98 + 64] ^= 0xFF;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Checksum-modified parses");
    ASSERT_STR_EQ(info.authenticode_sha256, base.authenticode_sha256, "CheckSum excluded");

    len = build_pe(b, sizeof(b), true, true);
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Signed image parses");
    ASSERT_TRUE(info.has_authenticode, "Cert table detected");
    ASSERT_STR_EQ(info.authenticode_sha256, base.authenticode_sha256, "Cert table + directory excluded");
    ASSERT_TRUE(strcmp(info.sha256, base.sha256) != 0, "Whole-file hash differs");

    b[0x250] ^= 0x01;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Section-modified parses");
    ASSERT_TRUE(strcmp(info.authenticode_sha256, base.authenticode_sha256) != 0, "Section bytes are hashed");
    TEST_PASS("test_authenticode_invariance");
}

static void test_pe32_parser(void) {
    TEST_START("test_pe32_parser");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), false, true);
    pe_efi_info_t info, unsigned_info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "PE32 parses");
    ASSERT_TRUE(!info.is_pe32_plus, "PE32 identified");
    ASSERT_TRUE(info.has_authenticode, "PE32 cert table detected");
    len = build_pe(b, sizeof(b), false, false);
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &unsigned_info), BOOTO_OK, "Unsigned PE32 parses");
    ASSERT_STR_EQ(info.authenticode_sha256, unsigned_info.authenticode_sha256, "PE32 cert excluded");
    TEST_PASS("test_pe32_parser");
}

static void test_dbx_revocation_matching(void) {
    TEST_START("test_dbx_revocation_matching");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), true, true);
    pe_efi_info_t info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Image parses");
    ASSERT_TRUE(!info.is_revoked_dbx, "Not revoked by default");
    char hash[65];
    snprintf(hash, sizeof(hash), "%s", info.authenticode_sha256);

    char dir[] = "/tmp/booto_dbx_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");
    char json_path[256], seal_path[256], json[512], seal[512], digest[65];
    snprintf(json_path, sizeof(json_path), "%s/uefi_dbx_revocations.json", dir);
    snprintf(seal_path, sizeof(seal_path), "%s/uefi_dbx_revocations.json.sha256", dir);
    int n = snprintf(json, sizeof(json),
                     "{\"revocations\":[{\"threat\":\"Test Bootkit\",\"cve\":\"CVE-0000-0000\","
                     "\"sha256\":\"%s\",\"severity\":\"HIGH\",\"description\":\"test\"}]}\n", hash);
    FILE *fp = fopen(json_path, "wb");
    ASSERT_TRUE(fp != NULL, "open json");
    if (fp) { fwrite(json, 1, (size_t)n, fp); fclose(fp); }
    sha256_buffer_hex((const uint8_t *)json, (size_t)n, digest);
    int m = snprintf(seal, sizeof(seal), "%s  %s\n", digest, json_path);
    fp = fopen(seal_path, "wb");
    ASSERT_TRUE(fp != NULL, "open seal");
    if (fp) { fwrite(seal, 1, (size_t)m, fp); fclose(fp); }

    setenv("BOOTO_RULES_DIR", dir, 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Image parses with custom rules");
    ASSERT_TRUE(info.is_revoked_dbx, "Authenticode hash matches DBX entry");
    ASSERT_STR_EQ(info.matched_threat, "Test Bootkit", "Matched threat name");
    ASSERT_INT_EQ(info.matched_severity, SEVERITY_HIGH, "Severity mapped");

    unlink(json_path);
    unlink(seal_path);
    rmdir(dir);
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    rules_reset_cache();
    TEST_PASS("test_dbx_revocation_matching");
}

static void test_pe_wrapping_offset_rejected(void) {
    TEST_START("test_pe_wrapping_offset_rejected");
    uint8_t buf[0x200];
    memset(buf, 0, sizeof(buf));
    buf[0] = 'M';
    buf[1] = 'Z';
    // e_lfanew = 0xFFFFFF80: 32-bit "pe_offset + 0x100" wraps to 0x80 and used to pass the bounds check.
    buf[0x3C] = 0x80; buf[0x3D] = 0xFF; buf[0x3E] = 0xFF; buf[0x3F] = 0xFF;
    pe_efi_info_t info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(buf, sizeof(buf), &info), BOOTO_ERR_CORRUPT_DATA, "Wrapping PE offset must be rejected");
    TEST_PASS("test_pe_wrapping_offset_rejected");
}

/* An 8 KiB executable section: random bytes are flagged as packed, ordinary-looking bytes are not. */
static bool packed_flagged(bool random_bytes) {
    static uint8_t b[0x2200];
    build_pe(b, sizeof(b), true, false);
    size_t sect = 0x84 + 20 + 0xF0;
    b[sect + 16] = 0x00; b[sect + 17] = 0x20;      // SizeOfRawData = 0x2000
    b[sect + 39] = 0x20;                           // IMAGE_SCN_MEM_EXECUTE
    uint32_t x = 2463534242u;
    for (size_t i = 0x200; i < sizeof(b); i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = random_bytes ? (uint8_t)x : (uint8_t)(i % 16);
    }
    const char *path = "/tmp/booto_packed_test.efi";
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    fwrite(b, 1, sizeof(b), fp);
    fclose(fp);
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_efi_file(path, &res);
    unlink(path);
    for (int i = 0; i < res.bootkits_detected; i++) {
        if (strcmp(res.findings[i].rule_id, "UEFI_PACKED_CODE_SECTION") == 0) return true;
    }
    return false;
}

static void test_packed_code_section(void) {
    TEST_START("test_packed_code_section");
    ASSERT_TRUE(packed_flagged(true), "High-entropy executable section is flagged as packed");
    ASSERT_TRUE(!packed_flagged(false), "Low-entropy executable section is not flagged");
    TEST_PASS("test_packed_code_section");
}

/* Sign build_pe's unsigned image the way signtool/sbsign does: SpcIndirectDataContent with the SHA-256
 * Authenticode digest, PKCS#7 SignedData by a throwaway self-signed key, appended as a WIN_CERTIFICATE. */
static size_t sign_pe(uint8_t *b, size_t cap) {
    size_t len = build_pe(b, cap, true, false);
    pe_efi_info_t info;
    if (uefi_parse_pe_buffer(b, len, &info) != BOOTO_OK) return 0;
    uint8_t idc[] = {
        0x30, 0x41,                                                       // SpcIndirectDataContent
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f, // SPC_PE_IMAGE_DATA
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0x04, 0x20,                                                       // sha256 digest follows
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(info.authenticode_sha256 + i * 2, "%2x", &v);
        idc[sizeof(idc) - 32 + (size_t)i] = (uint8_t)v;
    }

    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (const unsigned char *)"Booto Test", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(cert));
    X509_set_pubkey(cert, key);
    X509_sign(cert, key, EVP_sha256());

    PKCS7 *p7 = PKCS7_new(), *inner = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    PKCS7_SIGNER_INFO *si = PKCS7_add_signature(p7, cert, key, EVP_sha256());
    PKCS7_add_certificate(p7, cert);
    ASN1_OBJECT *spc = OBJ_txt2obj("1.3.6.1.4.1.311.2.1.4", 1);
    PKCS7_add_attrib_content_type(si, OBJ_dup(spc));
    inner->type = spc;
    inner->d.other = ASN1_TYPE_new();
    ASN1_STRING *seq = ASN1_STRING_new();
    ASN1_STRING_set(seq, idc, sizeof(idc));
    ASN1_TYPE_set(inner->d.other, V_ASN1_SEQUENCE, seq);
    PKCS7_set_content(p7, inner);
    BIO *bio = PKCS7_dataInit(p7, NULL);
    BIO_write(bio, idc + 2, sizeof(idc) - 2);  // signed bytes exclude the outer SEQUENCE header
    PKCS7_dataFinal(p7, bio);
    BIO_free_all(bio);

    unsigned char *der = NULL;
    int der_len = i2d_PKCS7(p7, &der);
    size_t wc_len = 8 + (size_t)der_len, table = (wc_len + 7) & ~(size_t)7;
    if (der_len <= 0 || 0x300 + table > cap) table = 0;
    if (table) {
        uint8_t *wc = b + 0x300;
        memset(wc, 0, table);
        wc[0] = (uint8_t)wc_len; wc[1] = (uint8_t)(wc_len >> 8);
        wc[5] = 0x02;                              // WIN_CERT_REVISION_2_0
        wc[6] = 0x02;                              // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        memcpy(wc + 8, der, (size_t)der_len);
        size_t dir = 0x84 + 20 + 112 + 32;
        b[dir + 1] = 0x03;                         // cert table at file offset 0x300
        b[dir + 4] = (uint8_t)table; b[dir + 5] = (uint8_t)(table >> 8);
    }
    OPENSSL_free(der);
    PKCS7_free(p7);
    X509_free(cert);
    EVP_PKEY_free(key);
    return table ? 0x300 + table : 0;
}

static authenticode_state_t verify_state(const uint8_t *b, size_t len) {
    pe_efi_info_t info;
    if (uefi_parse_pe_buffer(b, len, &info) != BOOTO_OK) return (authenticode_state_t)-1;
    authenticode_verify(b, len, &info);
    return info.authenticode_state;
}

static void test_authenticode_signature(void) {
    TEST_START("test_authenticode_signature");
    static uint8_t b[0x1000];
    size_t len = sign_pe(b, sizeof(b));
    ASSERT_TRUE(len > 0, "Test image signed");
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_VALID, "Intact signed image verifies");

    b[0x250] ^= 0x01;
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_HASH_MISMATCH, "Patched section breaks the signed digest");
    b[0x250] ^= 0x01;

    b[len - 0x40] ^= 0x01;                         // inside the RSA signature value
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_INVALID, "Corrupted signature is invalid");
    b[len - 0x40] ^= 0x01;

    b[0x306] = 0x01;                               // WIN_CERT_TYPE_X509, not PKCS#7
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_INVALID, "Wrong certificate type is invalid");

    len = build_pe(b, sizeof(b), true, true);
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_INVALID, "Garbage certificate table is invalid");
    len = build_pe(b, sizeof(b), true, false);
    ASSERT_INT_EQ(verify_state(b, len), AUTHENTICODE_NONE, "Unsigned image has no signature");
    TEST_PASS("test_authenticode_signature");
}

static void test_esp_scan_by_magic(void) {
    TEST_START("test_esp_scan_by_magic");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), true, false);
    char dir[] = "/tmp/booto_esp_XXXXXX", pe[64], txt[64];
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");
    snprintf(pe, sizeof(pe), "%s/grubx64.bak", dir);
    snprintf(txt, sizeof(txt), "%s/grub.cfg", dir);
    FILE *fp = fopen(pe, "wb");
    if (fp) { fwrite(b, 1, len, fp); fclose(fp); }
    fp = fopen(txt, "wb");
    if (fp) { fputs("MENU\n", fp); fclose(fp); }
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_esp_directory(dir, &res);
    unlink(pe);
    unlink(txt);
    rmdir(dir);
    ASSERT_INT_EQ(res.efi_files_scanned, 1, "Renamed PE scanned, text file skipped");
    ASSERT_STR_EQ(res.findings[0].rule_id, "UEFI_MISSING_AUTHENTICODE", "Renamed unsigned PE flagged");
    TEST_PASS("test_esp_scan_by_magic");
}

int main(void) {
    printf("\n--- Running UEFI & ESP Bootkit Analyzer Tests ---\n");
    test_synthetic_pe32_plus_parser();
    test_corrupted_pe_rejection();
    test_dbx_revocation_matching();
    test_authenticode_invariance();
    test_pe32_parser();
    test_pe_wrapping_offset_rejected();
    test_packed_code_section();
    test_authenticode_signature();
    test_esp_scan_by_magic();
    TEST_SUMMARY();
    return 0;
}
