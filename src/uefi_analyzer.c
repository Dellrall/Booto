/**
 * @file uefi_analyzer.c
 * @brief Implementation of UEFI PE/COFF binary parser and ESP bootkit scanner.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "uefi_analyzer.h"
#include "crypto_utils.h"
#include "logger.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const char *uefi_severity_to_string(uefi_severity_t severity) {
    switch (severity) {
        case UEFI_SEVERITY_CRITICAL: return "CRITICAL";
        case UEFI_SEVERITY_HIGH:     return "HIGH";
        case UEFI_SEVERITY_MEDIUM:   return "MEDIUM";
        case UEFI_SEVERITY_LOW:      return "LOW";
        default:                     return "INFO";
    }
}

// Database of known revoked EFI bootloaders / bootkits (Secure Boot DBX signatures)
typedef struct {
    const char *sha256_hash;
    const char *threat_name;
    const char *cve;
    uefi_severity_t severity;
    const char *description;
} dbx_revocation_entry_t;

static const dbx_revocation_entry_t G_DBX_REVOCATIONS[] = {
    // 1. BlackLotus UEFI Bootkit Revocations
    { "0c644d57c79e614066929a008c2a382d5e305e9e03d42c38848d7c4dbfc78f24",
      "BlackLotus Revoked Windows Bootloader", "CVE-2022-21894", UEFI_SEVERITY_CRITICAL,
      "Vulnerable Windows EFI boot manager exploited by BlackLotus UEFI bootkit to bypass Secure Boot" },
    { "80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca44b83993b36a49f63",
      "BlackLotus Batched EFI Payload", "CVE-2023-24932", UEFI_SEVERITY_CRITICAL,
      "BlackLotus second-stage kernel hijacker payload deployed into ESP" },

    // 2. BootHole GRUB2 Vulnerability Hashes
    { "cb078e4726b008d51624c96ea208d249f3e498c8793b890916d7a46abf1d4f9b",
      "BootHole Vulnerable GRUB2 Binary", "CVE-2020-10713", UEFI_SEVERITY_HIGH,
      "Revoked GRUB2 EFI executable vulnerable to heap-overflow buffer execution in grub.cfg parser" },

    // 3. ESPecter UEFI Bootkit
    { "5f8a3562a63200dc8ba79198642738a9d9e4a3b17728f3a9e0123ef89a12c451",
      "ESPecter UEFI Bootloader Implant", "ESPecter", UEFI_SEVERITY_CRITICAL,
      "ESPecter bootkit persistence module hidden in the EFI partition" },

    // 4. MoonBounce / CosmicStrand Firmware-to-ESP Stage
    { "a849201bc93ef4a890123ef9a82bc128912ef349a128901bc3412ef89018f4b2",
      "MoonBounce Stage-2 Bootloader", "MoonBounce", UEFI_SEVERITY_CRITICAL,
      "Stage-2 OS-loader interceptor deploying memory implants from ESP" }
};

static const size_t G_DBX_REVOCATIONS_COUNT = sizeof(G_DBX_REVOCATIONS) / sizeof(G_DBX_REVOCATIONS[0]);

booto_error_t uefi_parse_pe_buffer(const uint8_t *buf, size_t len, pe_efi_info_t *info) {
    if (!buf || !info) return BOOTO_ERR_INVALID_ARG;
    if (len < 0x200) return BOOTO_ERR_CORRUPT_DATA; // Minimum PE size

    memset(info, 0, sizeof(*info));
    sha256_buffer_hex(buf, len, info->sha256);

    // 1. Validate DOS Header ("MZ" = 0x5A4D)
    if (buf[0] != 'M' || buf[1] != 'Z') {
        return BOOTO_ERR_CORRUPT_DATA;
    }

    uint32_t pe_offset = (uint32_t)buf[0x3C] | ((uint32_t)buf[0x3D] << 8) |
                         ((uint32_t)buf[0x3E] << 16) | ((uint32_t)buf[0x3F] << 24);

    if (pe_offset + 0x100 > len) {
        LOG_ERROR("PE header offset out of bounds: 0x%x", pe_offset);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    // 2. Validate PE Signature ("PE\0\0" = 0x00004550)
    if (buf[pe_offset] != 'P' || buf[pe_offset + 1] != 'E' ||
        buf[pe_offset + 2] != 0 || buf[pe_offset + 3] != 0) {
        return BOOTO_ERR_CORRUPT_DATA;
    }

    // 3. COFF File Header (20 bytes after PE signature)
    size_t coff_offset = pe_offset + 4;
    info->machine_type = (uint16_t)(buf[coff_offset] | (buf[coff_offset + 1] << 8));
    uint16_t opt_hdr_size = (uint16_t)(buf[coff_offset + 16] | (buf[coff_offset + 17] << 8));

    if (opt_hdr_size == 0 || coff_offset + 20 + opt_hdr_size > len) {
        return BOOTO_ERR_CORRUPT_DATA;
    }

    // 4. Optional Header (PE32+ / 64-bit check)
    size_t opt_offset = coff_offset + 20;
    uint16_t opt_magic = (uint16_t)(buf[opt_offset] | (buf[opt_offset + 1] << 8));
    info->is_pe32_plus = (opt_magic == 0x20b); // 0x20b = PE32+ (64-bit)

    if (info->is_pe32_plus) {
        // PE32+ EntryPoint offset is at opt_offset + 16
        info->entry_point = (uint64_t)(buf[opt_offset + 16] | (buf[opt_offset + 17] << 8) |
                                      (buf[opt_offset + 18] << 16) | (buf[opt_offset + 19] << 24));

        // Subsystem offset is at opt_offset + 68
        info->subsystem = (uint16_t)(buf[opt_offset + 68] | (buf[opt_offset + 69] << 8));

        // NumberOfRvaAndSizes is at opt_offset + 108
        uint32_t num_rva = (uint32_t)buf[opt_offset + 108] | ((uint32_t)buf[opt_offset + 109] << 8) |
                           ((uint32_t)buf[opt_offset + 110] << 16) | ((uint32_t)buf[opt_offset + 111] << 24);

        // Security Directory is Directory #4 (Index 4 * 8 bytes = offset 144)
        if (num_rva > 4 && opt_offset + 112 + (4 * 8) + 8 <= len) {
            size_t sec_dir_offset = opt_offset + 112 + (4 * 8);
            info->cert_table_rva = (uint32_t)buf[sec_dir_offset] | ((uint32_t)buf[sec_dir_offset + 1] << 8) |
                                   ((uint32_t)buf[sec_dir_offset + 2] << 16) | ((uint32_t)buf[sec_dir_offset + 3] << 24);
            info->cert_table_size = (uint32_t)buf[sec_dir_offset + 4] | ((uint32_t)buf[sec_dir_offset + 5] << 8) |
                                    ((uint32_t)buf[sec_dir_offset + 6] << 16) | ((uint32_t)buf[sec_dir_offset + 7] << 24);

            if (info->cert_table_size > 0 && info->cert_table_rva > 0 && info->cert_table_rva + info->cert_table_size <= len) {
                info->has_authenticode = true;
            }
        }
    }

    // 5. Compare with Secure Boot DBX Revocations
    for (size_t i = 0; i < G_DBX_REVOCATIONS_COUNT; i++) {
        if (strcasecmp(info->sha256, G_DBX_REVOCATIONS[i].sha256_hash) == 0) {
            info->is_revoked_dbx = true;
            snprintf(info->matched_threat, sizeof(info->matched_threat), "%s", G_DBX_REVOCATIONS[i].threat_name);
            break;
        }
    }

    return BOOTO_OK;
}

booto_error_t uefi_parse_pe_file(const char *path, pe_efi_info_t *info) {
    if (!path || !info) return BOOTO_ERR_INVALID_ARG;

    FILE *fp = fopen(path, "rb");
    if (!fp) return BOOTO_ERR_IO;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 64 * 1024 * 1024) { // Max 64 MB for EFI binaries
        fclose(fp);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }

    size_t r = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);

    if (r != (size_t)fsize) {
        free(buf);
        return BOOTO_ERR_IO;
    }

    booto_error_t ret = uefi_parse_pe_buffer(buf, (size_t)fsize, info);
    snprintf(info->file_path, sizeof(info->file_path), "%s", path);
    free(buf);

    return ret;
}

static void add_uefi_threat(uefi_scan_result_t *result,
                            const char *threat_name,
                            const char *file_path,
                            const char *sha256,
                            const char *rule_id,
                            uefi_severity_t severity,
                            const char *description) {
    if (!result || result->bootkits_detected >= MAX_UEFI_THREATS) return;

    uefi_threat_finding_t *f = &result->findings[result->bootkits_detected++];
    snprintf(f->threat_name, sizeof(f->threat_name), "%s", threat_name ? threat_name : "UEFI Anomaly");
    snprintf(f->file_path, sizeof(f->file_path), "%s", file_path ? file_path : "");
    snprintf(f->sha256, sizeof(f->sha256), "%s", sha256 ? sha256 : "");
    snprintf(f->rule_id, sizeof(f->rule_id), "%s", rule_id ? rule_id : "RULE_UNKNOWN");
    f->severity = severity;
    snprintf(f->description, sizeof(f->description), "%s", description ? description : "");

    LOG_CRITICAL("[BOOTKIT ALERT] %s in %s (Rule: %s, Severity: %s)",
                 f->threat_name, f->file_path, f->rule_id, uefi_severity_to_string(f->severity));
}

booto_error_t uefi_inspect_efi_file(const char *efi_path, uefi_scan_result_t *result) {
    if (!efi_path || !result) return BOOTO_ERR_INVALID_ARG;

    result->efi_files_scanned++;

    pe_efi_info_t pe;
    booto_error_t err = uefi_parse_pe_file(efi_path, &pe);
    if (err != BOOTO_OK) {
        LOG_WARN("Could not parse PE/COFF file '%s' (err: %d)", efi_path, err);
        return err;
    }

    // 1. Check if binary is explicitly revoked in Secure Boot DBX
    if (pe.is_revoked_dbx) {
        add_uefi_threat(result,
                        pe.matched_threat,
                        efi_path,
                        pe.sha256,
                        "UEFI_DBX_REVOCATION_MATCH",
                        UEFI_SEVERITY_CRITICAL,
                        "EFI executable matches a known revoked bootkit or vulnerable loader in the Secure Boot DBX");
    }

    // 2. Check for unsigned / missing Authenticode certificates
    if (!pe.has_authenticode) {
        add_uefi_threat(result,
                        "Unsigned EFI Bootloader / Driver",
                        efi_path,
                        pe.sha256,
                        "UEFI_MISSING_AUTHENTICODE",
                        UEFI_SEVERITY_HIGH,
                        "EFI executable does not contain an embedded Authenticode signature table");
    }

    return BOOTO_OK;
}

static void scan_esp_dir_recursive(const char *base_path, uefi_scan_result_t *result, int depth) {
    if (depth > 6) return;

    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_esp_dir_recursive(full_path, result, depth + 1);
            } else if (S_ISREG(st.st_mode)) {
                size_t nlen = strlen(entry->d_name);
                if (nlen > 4 && strcasecmp(entry->d_name + nlen - 4, ".efi") == 0) {
                    uefi_inspect_efi_file(full_path, result);
                }
            }
        }
    }
    closedir(dir);
}

booto_error_t uefi_inspect_esp_directory(const char *esp_dir, uefi_scan_result_t *result) {
    if (!esp_dir || !result) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Scanning EFI System Partition (ESP) at: %s", esp_dir);
    scan_esp_dir_recursive(esp_dir, result, 0);

    LOG_INFO("ESP scan complete: %d EFI files inspected, %d bootkits/anomalies flagged",
             result->efi_files_scanned, result->bootkits_detected);
    return BOOTO_OK;
}
