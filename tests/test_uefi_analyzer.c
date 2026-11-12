/**
 * @file test_uefi_analyzer.c
 * @brief Unit tests for UEFI PE32+ parser, Authenticode verification, and DBX revocation matching.
 */
#include "test_framework.h"
#include "uefi_analyzer.h"
#include "crypto_utils.h"
#include "rules_fixture.h"
#include "pe_fixture.h"

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
    char json_path[256], sig_path[300], json[512];
    snprintf(json_path, sizeof(json_path), "%s/uefi_dbx_revocations.json", dir);
    snprintf(sig_path, sizeof(sig_path), "%s.sig", json_path);
    int n = snprintf(json, sizeof(json),
                     "{\"revocations\":[{\"threat\":\"Test Bootkit\",\"cve\":\"CVE-0000-0000\","
                     "\"sha256\":\"%s\",\"severity\":\"HIGH\",\"description\":\"test\"}]}\n", hash);
    FILE *fp = fopen(json_path, "wb");
    ASSERT_TRUE(fp != NULL, "open json");
    if (fp) { fwrite(json, 1, (size_t)n, fp); fclose(fp); }
    rules_fixture_sign(json_path, json, (size_t)n);

    setenv("BOOTO_RULES_DIR", dir, 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &info), BOOTO_OK, "Image parses with custom rules");
    ASSERT_TRUE(info.is_revoked_dbx, "Authenticode hash matches DBX entry");
    ASSERT_STR_EQ(info.matched_threat, "Test Bootkit", "Matched threat name");
    ASSERT_INT_EQ(info.matched_severity, SEVERITY_HIGH, "Severity mapped");

    unlink(json_path);
    unlink(sig_path);
    rmdir(dir);
    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    rules_fixture_done();
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

/* An unsigned EFI program is flagged; an unsigned Windows resource file (bootres.dll.mui) is not. */
static bool unsigned_flagged(uint16_t subsystem) {
    static uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), true, false);
    b[0x84 + 20 + 68] = (uint8_t)subsystem;
    const char *path = "/tmp/booto_unsigned_test.efi";
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    fwrite(b, 1, len, fp);
    fclose(fp);
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_efi_file(path, &res);
    unlink(path);
    for (int i = 0; i < res.bootkits_detected; i++) {
        if (strcmp(res.findings[i].rule_id, "UEFI_MISSING_AUTHENTICODE") == 0) return true;
    }
    return false;
}

static void test_unsigned_needs_efi_subsystem(void) {
    TEST_START("test_unsigned_needs_efi_subsystem");
    ASSERT_TRUE(unsigned_flagged(10), "Unsigned EFI application is flagged");
    ASSERT_TRUE(!unsigned_flagged(2), "Unsigned Windows GUI resource PE is not flagged");
    TEST_PASS("test_unsigned_needs_efi_subsystem");
}

/* A first-stage loader without NX_COMPAT is LOW; with the flag it is not reported. */
static bool nx_flagged(bool nx) {
    static uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), true, false);
    if (nx) b[0x84 + 20 + 71] = 0x01;   // DllCharacteristics |= 0x0100
    const char *path = "/tmp/bootx64_nx_test.efi";
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    fwrite(b, 1, len, fp);
    fclose(fp);
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_efi_file(path, &res);
    unlink(path);
    for (int i = 0; i < res.bootkits_detected; i++)
        if (strcmp(res.findings[i].rule_id, "UEFI_NO_NX_COMPAT") == 0) return res.findings[i].severity == SEVERITY_LOW;
    return false;
}

static void test_nx_compat(void) {
    TEST_START("test_nx_compat");
    ASSERT_TRUE(nx_flagged(false), "Loader without NX_COMPAT is LOW");
    ASSERT_TRUE(!nx_flagged(true), "NX-compatible loader is not reported");
    TEST_PASS("test_nx_compat");
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
    pe_efi_info_t signed_info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(b, len, &signed_info), BOOTO_OK, "Signed image parses");
    authenticode_verify(b, len, &signed_info);
    ASSERT_TRUE(!signed_info.authenticode_microsoft, "Self-signed image does not chain to a Microsoft root");

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
    ASSERT_INT_EQ(res.findings[0].severity, SEVERITY_MEDIUM, "Unsigned later-stage loader is MEDIUM");
    TEST_PASS("test_esp_scan_by_magic");
}

static void write_pe(const char *dir, const char *rel, const uint8_t *b, size_t len) {
    char path[160], cmd[200];
    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    snprintf(cmd, sizeof(cmd), "mkdir -p \"$(dirname '%s')\"", path);
    if (system(cmd) != 0) return;
    FILE *fp = fopen(path, "wb");
    if (fp) { fwrite(b, 1, len, fp); fclose(fp); }
}

static int count_rule(const uefi_scan_result_t *res, const char *rule) {
    int n = 0;
    for (int i = 0; i < res->bootkits_detected; i++) n += strcmp(res->findings[i].rule_id, rule) == 0;
    return n;
}

static void test_esp_layout_and_sbat(void) {
    TEST_START("test_esp_layout_and_sbat");
    uint8_t b[0x400], old[0x400];
    size_t len = build_pe(b, sizeof(b), true, false);
    memcpy(old, b, sizeof(b));
    memcpy(old + 0x188, ".sbat", 5);  // the one section, at 0x200
    static const char csv[] = "sbat,1,SBAT Version,sbat,1,https://x\ngrub,2,Free Software Foundation,grub,2.04,https://x\n";
    memcpy(old + 0x200, csv, sizeof(csv) - 1);
    memset(old + 0x200 + sizeof(csv) - 1, 0, 0x100 - (sizeof(csv) - 1));

    char dir[] = "/tmp/booto_esp_XXXXXX", cmd[64];
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");
    write_pe(dir, "system32/winload.efi", b, len);
    write_pe(dir, "EFI/Microsoft/Boot/grubx64.efi", b, len);
    write_pe(dir, "EFI/Microsoft/Boot/bootmgfw.efi", b, len);
    write_pe(dir, "EFI/fedora/grubx64-real.efi", b, len);
    write_pe(dir, "EFI/fedora/shimx64.efi", b, len);
    write_pe(dir, "EFI/ubuntu/grubx64.efi", old, len);
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_esp_directory(dir, &res);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) perror("rm");

    ASSERT_INT_EQ(res.efi_files_scanned, 6, "Every PE scanned");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_ESP_SYSTEM32"), 1, "ESP:/system32 flagged");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_ESP_FOREIGN_LOADER"), 1, "GRUB in EFI/Microsoft flagged; bootmgfw is not");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_ESP_SHADOW_LOADER"), 1, "Renamed-aside loader flagged; shimx64.efi is not");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_SBAT_REVOKED"), 1, "grub,2 below SbatLevel flagged; no .sbat is not");
    TEST_PASS("test_esp_layout_and_sbat");
}

static void test_first_stage_signer(void) {
    TEST_START("test_first_stage_signer");
    static uint8_t b[0x1000];
    size_t len = sign_pe(b, sizeof(b));
    char dir[] = "/tmp/booto_stage_XXXXXX", cmd[64];
    ASSERT_TRUE(len > 0 && mkdtemp(dir) != NULL, "signed image and mkdtemp");
    write_pe(dir, "EFI/BOOT/BOOTX64.EFI", b, len);
    write_pe(dir, "EFI/debian/shimx64.efi", b, len);
    write_pe(dir, "EFI/debian/grubx64.efi", b, len);
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_esp_directory(dir, &res);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) perror("rm");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_FIRST_STAGE_NOT_MICROSOFT"), 2,
                  "Self-signed BOOTX64 and shim flagged; distro-signed grub is not");
    TEST_PASS("test_first_stage_signer");
}

/* An unsigned shim: one 0x400-byte long-named .vendor_cert section (as "/4" in the COFF string table) holding ca. */
static size_t build_shim(uint8_t *b, size_t cap, X509 *ca) {
    if (cap < 0x611) return 0;
    build_pe(b, cap, true, false);
    unsigned char *der = NULL;
    int n = i2d_X509(ca, &der);
    if (n <= 0 || n > 0x3F0) { OPENSSL_free(der); return 0; }
    size_t sect = 0x84 + 20 + 0xF0;
    memset(b + 0x200, 0, 0x400);
    memcpy(b + sect, "/4\0\0\0\0\0\0", 8);
    b[sect + 17] = 0x04;                           // SizeOfRawData = 0x400
    b[0x200] = (uint8_t)n; b[0x201] = (uint8_t)(n >> 8); // authorized size
    b[0x208] = 0x10;                               // authorized offset
    memcpy(b + 0x210, der, (size_t)n);
    OPENSSL_free(der);
    b[0x84 + 9] = 0x06;                            // PointerToSymbolTable = 0x600, no symbols
    b[0x600] = 17;
    memcpy(b + 0x604, ".vendor_cert", 13);
    return 0x611;
}

static void test_shim_vendor_signer(void) {
    TEST_START("test_shim_vendor_signer");
    static uint8_t shim[0x1000], grub[0x1000], rogue[0x1000];
    EVP_PKEY *distro = EVP_RSA_gen(2048), *other = EVP_RSA_gen(2048);
    X509 *ca = fixture_cert(distro), *other_cert = fixture_cert(other);
    size_t shim_len = build_shim(shim, sizeof(shim), ca);
    size_t grub_len = sign_pe_with(grub, sizeof(grub), distro, ca);
    size_t rogue_len = sign_pe_with(rogue, sizeof(rogue), other, other_cert);
    X509_free(ca);
    X509_free(other_cert);
    EVP_PKEY_free(distro);
    EVP_PKEY_free(other);
    pe_efi_info_t info;
    ASSERT_INT_EQ(uefi_parse_pe_buffer(shim, shim_len, &info), BOOTO_OK, "fixture shim parses");
    ASSERT_TRUE(info.vendor_cert_ptr == 0x210 && info.vendor_cert_size > 0, ".vendor_cert found by its long name");

    char dir[] = "/tmp/booto_vendor_XXXXXX", cmd[64];
    ASSERT_TRUE(shim_len && grub_len && rogue_len && mkdtemp(dir) != NULL, "fixtures and mkdtemp");
    write_pe(dir, "EFI/debian/shimx64.efi", shim, shim_len);
    write_pe(dir, "EFI/debian/grubx64.efi", grub, grub_len);
    write_pe(dir, "EFI/debian/mmx64.efi", rogue, rogue_len);
    write_pe(dir, "EFI/other/grubx64.efi", rogue, rogue_len);  // no shim beside it: judged by db, not here
    uefi_scan_result_t res;
    memset(&res, 0, sizeof(res));
    uefi_inspect_esp_directory(dir, &res);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) perror("rm");
    ASSERT_INT_EQ(count_rule(&res, "UEFI_LOADER_NOT_SHIM_VENDOR"), 1, "Only the loader signed by a stranger key is flagged");
    for (int i = 0; i < res.bootkits_detected; i++)
        if (strcmp(res.findings[i].rule_id, "UEFI_LOADER_NOT_SHIM_VENDOR") == 0)
            ASSERT_TRUE(strstr(res.findings[i].file_path, "debian/mmx64.efi") != NULL, "the rogue one beside the shim");
    TEST_PASS("test_shim_vendor_signer");
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
    test_unsigned_needs_efi_subsystem();
    test_nx_compat();
    test_authenticode_signature();
    test_esp_scan_by_magic();
    test_esp_layout_and_sbat();
    test_shim_vendor_signer();
    test_first_stage_signer();
    TEST_SUMMARY();
    return 0;
}
