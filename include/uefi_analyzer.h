/**
 * @file uefi_analyzer.h
 * @brief Offline forensic analyzer for UEFI binaries (PE/COFF) and EFI System Partitions (ESP).
 */
#ifndef BOOTO_UEFI_ANALYZER_H
#define BOOTO_UEFI_ANALYZER_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_UEFI_THREATS 64

typedef enum {
    UEFI_SEVERITY_INFO = 0,
    UEFI_SEVERITY_LOW,
    UEFI_SEVERITY_MEDIUM,
    UEFI_SEVERITY_HIGH,
    UEFI_SEVERITY_CRITICAL
} uefi_severity_t;

typedef struct {
    char file_path[256];
    char sha256[65];
    bool is_pe32_plus;
    uint16_t machine_type;
    uint16_t subsystem;       // 10 = IMAGE_SUBSYSTEM_EFI_APPLICATION
    uint64_t entry_point;
    uint32_t cert_table_rva;  // Security Directory RVA
    uint32_t cert_table_size; // Security Directory Size
    bool has_authenticode;
    bool is_revoked_dbx;
    char matched_threat[64];
} pe_efi_info_t;

typedef struct {
    char threat_name[64];
    char file_path[256];
    char sha256[65];
    char rule_id[64];
    uefi_severity_t severity;
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

/**
 * @brief Convert UEFI severity enum to string.
 */
const char *uefi_severity_to_string(uefi_severity_t severity);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_UEFI_ANALYZER_H */
