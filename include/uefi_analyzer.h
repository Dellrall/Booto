/**
 * @file uefi_analyzer.h
 * @brief Offline forensic analyzer for UEFI binaries (PE/COFF) and EFI System Partitions (ESP).
 */
#ifndef BOOTO_UEFI_ANALYZER_H
#define BOOTO_UEFI_ANALYZER_H

#include "booto.h"
#include "yara_scan.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_UEFI_THREATS 64

typedef enum {
    AUTHENTICODE_NONE = 0,     // no certificate table
    AUTHENTICODE_VALID,        // PKCS#7 signature verifies and the signed digest matches the image
    AUTHENTICODE_INVALID,      // certificate table present but malformed, or the signature does not verify
    AUTHENTICODE_HASH_MISMATCH,// signature verifies but the image changed after signing
    AUTHENTICODE_UNSUPPORTED   // signed with a digest other than SHA-256: not checked
} authenticode_state_t;

typedef struct {
    char file_path[256];
    char sha256[65];              // whole-file SHA-256 (reporting)
    char authenticode_sha256[65]; // Authenticode PE image hash (DBX matching)
    bool is_pe32_plus;
    uint16_t machine_type;
    uint16_t subsystem;       // 10 = IMAGE_SUBSYSTEM_EFI_APPLICATION
    uint64_t entry_point;
    uint32_t cert_table_rva;  // Security Directory RVA
    uint32_t cert_table_size; // Security Directory Size
    bool has_authenticode;
    authenticode_state_t authenticode_state; // set by uefi_parse_pe_file / authenticode_verify
    bool authenticode_microsoft; // VALID and the signer chains to a Microsoft root (expiry ignored)
    bool is_revoked_dbx;
    char matched_threat[96];
    booto_severity_t matched_severity;
    uint32_t exec_ptr;        // largest executable section: file offset (0 = none)
    uint32_t exec_size;       // and raw size
    double exec_entropy;      // its entropy in bits/byte (set by uefi_parse_pe_file only)
    uint32_t sbat_ptr;        // .sbat section (shim/GRUB revocation metadata): file offset (0 = none)
    uint32_t sbat_size;       // and raw size
    char sbat_revoked[64];    // "<component>,<generation>" below the current SbatLevel, or "" (uefi_parse_pe_file)
    int yara_count;           // signed YARA rules the whole file matched (uefi_parse_pe_file only)
    yara_match_t yara[YARA_MAX_MATCHES];
} pe_efi_info_t;

typedef struct {
    char threat_name[96];          /* fits a dbx rule's threat field */
    char file_path[256];
    char sha256[65];
    char rule_id[64];
    booto_severity_t severity;
    char description[256];
} uefi_threat_finding_t;

typedef struct {
    int efi_files_scanned;
    int bootkits_detected;
    uefi_threat_finding_t findings[MAX_UEFI_THREATS];
} uefi_scan_result_t;

/**
 * @brief Parse a UEFI PE32+ executable and extract security headers.
 * @param path Filepath to the .efi binary.
 * @param info Output structure to fill.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t uefi_parse_pe_file(const char *path, pe_efi_info_t *info);

/**
 * @brief Parse a UEFI PE32+ executable from memory buffer.
 * @param buf Pointer to file bytes.
 * @param len Buffer length.
 * @param info Output structure to fill.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t uefi_parse_pe_buffer(const uint8_t *buf, size_t len, pe_efi_info_t *info);

/**
 * @brief Verify the embedded Authenticode signature of an image uefi_parse_pe_buffer already parsed.
 *        Checks signature integrity and the signed digest, and whether the signer chains to a Microsoft root;
 *        it does not check the signer against db.
 * @param buf Same bytes passed to uefi_parse_pe_buffer.
 * @param len Buffer length.
 * @param info Parsed info; authenticode_state is written.
 */
void authenticode_verify(const uint8_t *buf, size_t len, pe_efi_info_t *info);

/**
 * @brief Inspect a single .efi binary for bootkits, DBX revocations, or missing signatures.
 * @param efi_path Filepath to the .efi file.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t uefi_inspect_efi_file(const char *efi_path, uefi_scan_result_t *result);

/**
 * @brief Recursively scan an EFI System Partition directory (e.g. /boot/efi/EFI).
 * @param esp_dir Path to ESP root or EFI directory.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t uefi_inspect_esp_directory(const char *esp_dir, uefi_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_UEFI_ANALYZER_H */
