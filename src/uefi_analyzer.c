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
#include "rules_loader.h"
#include "logger.h"

#include <dirent.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool in_bounds(size_t len, uint64_t off, uint64_t size) {
    return off <= len && size <= len - off;
}

#define PE_SCN_MEM_EXECUTE 0x20000000u

typedef struct { uint32_t ptr; uint32_t size; } raw_section_t;

static int cmp_section(const void *a, const void *b) {
    uint32_t x = ((const raw_section_t *)a)->ptr, y = ((const raw_section_t *)b)->ptr;
    return (x > y) - (x < y);
}

booto_error_t uefi_parse_pe_buffer(const uint8_t *buf, size_t len, pe_efi_info_t *info) {
    if (!buf || !info) return BOOTO_ERR_INVALID_ARG;
    if (len < 0x200) return BOOTO_ERR_CORRUPT_DATA; // Minimum PE size

    memset(info, 0, sizeof(*info));
    sha256_buffer_hex(buf, len, info->sha256);

    // 1. Validate DOS Header ("MZ")
    if (buf[0] != 'M' || buf[1] != 'Z') return BOOTO_ERR_CORRUPT_DATA;

    uint32_t pe_offset = rd32(buf + 0x3C);
    if (!in_bounds(len, pe_offset, 24)) {
        LOG_ERROR("PE header offset out of bounds: 0x%x", pe_offset);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    // 2. Validate PE Signature ("PE\0\0")
    if (buf[pe_offset] != 'P' || buf[pe_offset + 1] != 'E' ||
        buf[pe_offset + 2] != 0 || buf[pe_offset + 3] != 0) {
        return BOOTO_ERR_CORRUPT_DATA;
    }

    // 3. COFF File Header
    size_t coff = (size_t)pe_offset + 4;
    info->machine_type = (uint16_t)(buf[coff] | (buf[coff + 1] << 8));
    uint16_t num_sections = (uint16_t)(buf[coff + 2] | (buf[coff + 3] << 8));
    uint16_t opt_hdr_size = (uint16_t)(buf[coff + 16] | (buf[coff + 17] << 8));
    size_t opt = coff + 20;
    if (!in_bounds(len, opt, opt_hdr_size)) return BOOTO_ERR_CORRUPT_DATA;

    // 4. Optional Header
    if (opt_hdr_size < 2) return BOOTO_ERR_CORRUPT_DATA;
    uint16_t opt_magic = (uint16_t)(buf[opt] | (buf[opt + 1] << 8));
    if (opt_magic != 0x10b && opt_magic != 0x20b) return BOOTO_ERR_CORRUPT_DATA;
    info->is_pe32_plus = (opt_magic == 0x20b);
    size_t num_rva_off = info->is_pe32_plus ? 108 : 92;
    size_t dirs_off = info->is_pe32_plus ? 112 : 96;
    if (opt_hdr_size < dirs_off) return BOOTO_ERR_CORRUPT_DATA;

    info->entry_point = rd32(buf + opt + 16);
    info->subsystem = (uint16_t)(buf[opt + 68] | (buf[opt + 69] << 8));
    uint32_t size_of_headers = rd32(buf + opt + 60);
    uint32_t num_rva = rd32(buf + opt + num_rva_off);
    size_t checksum_off = opt + 64;
    size_t cert_dir_off = opt + dirs_off + 4 * 8;
    bool has_cert_dir = num_rva > 4 && cert_dir_off + 8 <= opt + opt_hdr_size;

    if (has_cert_dir) {
        info->cert_table_rva = rd32(buf + cert_dir_off);  // file offset, not an RVA
        info->cert_table_size = rd32(buf + cert_dir_off + 4);
        info->has_authenticode = info->cert_table_size > 0 && info->cert_table_rva > 0 &&
                                 in_bounds(len, info->cert_table_rva, info->cert_table_size);
    }

    // 5. Authenticode image hash (Microsoft PE/Authenticode spec)
    if (size_of_headers > len || size_of_headers < (has_cert_dir ? cert_dir_off + 8 : checksum_off + 4)) {
        return BOOTO_ERR_CORRUPT_DATA;
    }
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, buf, checksum_off);
    if (has_cert_dir) {
        sha256_update(&ctx, buf + checksum_off + 4, cert_dir_off - (checksum_off + 4));
        sha256_update(&ctx, buf + cert_dir_off + 8, size_of_headers - (cert_dir_off + 8));
    } else {
        sha256_update(&ctx, buf + checksum_off + 4, size_of_headers - (checksum_off + 4));
    }

    size_t sect_tbl = opt + opt_hdr_size;
    if (!in_bounds(len, sect_tbl, (uint64_t)num_sections * 40)) return BOOTO_ERR_CORRUPT_DATA;
    raw_section_t *secs = NULL;
    size_t n = 0;
    if (num_sections > 0) {
        secs = calloc(num_sections, sizeof(*secs));
        if (!secs) return BOOTO_ERR_OUT_OF_MEMORY;
    }
    for (size_t i = 0; i < num_sections; i++) {
        const uint8_t *e = buf + sect_tbl + i * 40;
        uint32_t size = rd32(e + 16), ptr = rd32(e + 20);
        if (size == 0) continue;
        if (!in_bounds(len, ptr, size)) {
            free(secs);
            return BOOTO_ERR_CORRUPT_DATA;
        }
        if ((rd32(e + 36) & PE_SCN_MEM_EXECUTE) && size > info->exec_size) {
            info->exec_ptr = ptr;
            info->exec_size = size;
        }
        if (memcmp(e, ".sbat\0", 6) == 0) {
            info->sbat_ptr = ptr;
            info->sbat_size = size;
        }
        secs[n].ptr = ptr;
        secs[n].size = size;
        n++;
    }
    if (n > 1) qsort(secs, n, sizeof(*secs), cmp_section);
    uint64_t sum_of_bytes = size_of_headers;
    for (size_t i = 0; i < n; i++) {
        sha256_update(&ctx, buf + secs[i].ptr, secs[i].size);
        sum_of_bytes += secs[i].size;
    }
    free(secs);

    // Trailing data, excluding the certificate table
    if (sum_of_bytes < len) {
        uint64_t extra = len - sum_of_bytes;
        if (info->has_authenticode) {
            extra = info->cert_table_size > extra ? 0 : extra - info->cert_table_size;
        }
        sha256_update(&ctx, buf + sum_of_bytes, (size_t)extra);
    }
    uint8_t digest[32];
    sha256_final(&ctx, digest);
    for (size_t i = 0; i < 32; i++) {
        snprintf(info->authenticode_sha256 + i * 2, 3, "%02x", digest[i]);
    }

    // 6. Compare with Secure Boot DBX revocations
    const rules_dbx_set_t *dbx = NULL;
    booto_error_t err = rules_get_dbx(&dbx);
    if (err != BOOTO_OK) return err;
    for (int i = 0; i < dbx->count; i++) {
        if (strcasecmp(info->authenticode_sha256, dbx->entries[i].sha256) == 0) {
            info->is_revoked_dbx = true;
            snprintf(info->matched_threat, sizeof(info->matched_threat), "%s", dbx->entries[i].threat);
            info->matched_severity = (booto_severity_t)rules_severity_level(dbx->entries[i].severity);
            break;
        }
    }

    return BOOTO_OK;
}

// shim 15.8's SBAT_VAR_LATEST (2024010900): firmware with this SbatLevel refuses older generations, so a loader
// below it is a known-vulnerable build (the downgrade BlackLotus-style bootkits rely on) or a stale leftover.
// shortcut: table is fixed at 2024010900, update when shim ships a newer SbatLevel.
static const struct { const char *component; int generation; } SBAT_LEVEL[] = {
    { "shim", 4 }, { "grub", 3 }, { "grub.debian", 4 },
};

// Writes the first "<component>,<generation>" row of a .sbat CSV that is below SBAT_LEVEL into out.
static void sbat_check(const uint8_t *sbat, uint32_t size, char *out, size_t out_len) {
    char csv[4096];
    size_t n = size < sizeof(csv) - 1 ? size : sizeof(csv) - 1;
    memcpy(csv, sbat, n);
    csv[n] = '\0';
    out[0] = '\0';
    char *save = NULL;
    for (char *line = strtok_r(csv, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char *comma = strchr(line, ',');
        if (!comma) continue;
        *comma = '\0';
        int gen = atoi(comma + 1);
        for (size_t i = 0; i < sizeof(SBAT_LEVEL) / sizeof(SBAT_LEVEL[0]); i++) {
            if (strcmp(line, SBAT_LEVEL[i].component) == 0 && gen < SBAT_LEVEL[i].generation) {
                snprintf(out, out_len, "%.40s,%d", line, gen);
                return;
            }
        }
    }
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
    if (ret == BOOTO_OK && info->exec_size) { // range already bounds-checked by the parser
        size_t hist[256] = { 0 };
        for (uint32_t i = 0; i < info->exec_size; i++) hist[buf[info->exec_ptr + i]]++;
        info->exec_entropy = entropy_bits(hist, info->exec_size);
    }
    if (ret == BOOTO_OK && info->sbat_size) sbat_check(buf + info->sbat_ptr, info->sbat_size, info->sbat_revoked,
                                                       sizeof(info->sbat_revoked));
    if (ret == BOOTO_OK) authenticode_verify(buf, (size_t)fsize, info);
    snprintf(info->file_path, sizeof(info->file_path), "%s", path);
    free(buf);

    return ret;
}

#define UEFI_PACKED_ENTROPY_BITS 7.2
#define UEFI_PACKED_MIN_BYTES 4096u

static void add_uefi_threat(uefi_scan_result_t *result,
                            const char *threat_name,
                            const char *file_path,
                            const char *sha256,
                            const char *rule_id,
                            booto_severity_t severity,
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
                 f->threat_name, f->file_path, f->rule_id, booto_severity_str(f->severity));
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
                        pe.matched_severity,
                        "EFI executable matches a known revoked bootkit or vulnerable loader in the Secure Boot DBX");
    }

    // 2. Check for unsigned / missing Authenticode certificates
    if (!pe.has_authenticode) {
        add_uefi_threat(result,
                        "Unsigned EFI Bootloader / Driver",
                        efi_path,
                        pe.sha256,
                        "UEFI_MISSING_AUTHENTICODE",
                        SEVERITY_HIGH,
                        "EFI executable does not contain an embedded Authenticode signature table");
    }

    if (pe.authenticode_state == AUTHENTICODE_HASH_MISMATCH) {
        add_uefi_threat(result,
                        "Tampered Signed EFI Image",
                        efi_path,
                        pe.sha256,
                        "UEFI_AUTHENTICODE_HASH_MISMATCH",
                        SEVERITY_CRITICAL,
                        "Authenticode signature is intact but the image was modified after signing (patched loader)");
    } else if (pe.authenticode_state == AUTHENTICODE_INVALID) {
        add_uefi_threat(result,
                        "Invalid Authenticode Signature",
                        efi_path,
                        pe.sha256,
                        "UEFI_AUTHENTICODE_INVALID",
                        SEVERITY_HIGH,
                        "Certificate table is malformed or its PKCS#7 signature does not verify");
    }

    // 3. Heuristic: compressed or encrypted code (packer / loader stub). Normal x86-64 code is about 6 bits/byte.
    if (pe.exec_size >= UEFI_PACKED_MIN_BYTES && pe.exec_entropy >= UEFI_PACKED_ENTROPY_BITS) {
        add_uefi_threat(result,
                        "Packed EFI Executable",
                        efi_path,
                        pe.sha256,
                        "UEFI_PACKED_CODE_SECTION",
                        SEVERITY_MEDIUM,
                        "Executable section is high-entropy (compressed or encrypted code), typical of packed bootkit loaders");
    }

    if (pe.sbat_revoked[0]) {
        char desc[256];
        snprintf(desc, sizeof(desc), "SBAT entry %s is below the current SbatLevel: a revoked, known-vulnerable loader",
                 pe.sbat_revoked);
        add_uefi_threat(result, "SBAT-Revoked Boot Loader", efi_path, pe.sha256, "UEFI_SBAT_REVOKED", SEVERITY_MEDIUM,
                        desc);
    }

    return BOOTO_OK;
}

static bool path_has(const char *path, const char *needle) {
    for (size_t n = strlen(needle); *path; path++)
        if (strncasecmp(path, needle, n) == 0) return true;
    return false;
}

// Where a file sits on the ESP, not what it contains: layouts used by known bootkits. rel is relative to the ESP root.
static void check_esp_layout(const char *full_path, const char *rel, uefi_scan_result_t *result) {
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    // BlackLotus: a vulnerable Windows boot manager chain in ESP:/system32, and its payload as
    // EFI/Microsoft/Boot/grubx64.efi so the shim it installs as bootmgfw.efi runs it.
    if (strncasecmp(rel, "system32/", 9) == 0)
        add_uefi_threat(result, "Windows Boot Files Outside EFI/Microsoft", full_path, "", "UEFI_ESP_SYSTEM32",
                        SEVERITY_HIGH, "Executable in ESP:/system32, where BlackLotus stages its vulnerable boot chain");
    if (path_has(rel, "EFI/Microsoft/") && (strncasecmp(base, "grub", 4) == 0 || strncasecmp(base, "shim", 4) == 0))
        add_uefi_threat(result, "Linux Loader In Windows Boot Directory", full_path, "", "UEFI_ESP_FOREIGN_LOADER",
                        SEVERITY_HIGH, "GRUB or shim inside EFI/Microsoft, the BlackLotus payload layout");
    // A loader renamed aside so a replacement can chainload it (bootmgfw.efi.bak, grubx64-real.efi).
    static const char *const loaders[] = { "bootmgfw", "bootx64", "grubx64", "shimx64" };
    static const char *const aside[] = { "real", ".bak", ".old", "orig" };
    for (size_t i = 0; i < sizeof(loaders) / sizeof(loaders[0]); i++) {
        if (!path_has(base, loaders[i])) continue;
        for (size_t j = 0; j < sizeof(aside) / sizeof(aside[0]); j++) {
            if (!path_has(base, aside[j])) continue;
            add_uefi_threat(result, "Shadowed Boot Loader", full_path, "", "UEFI_ESP_SHADOW_LOADER", SEVERITY_MEDIUM,
                            "Copy of a boot loader renamed aside, how a replacement loader chainloads the original");
            return;
        }
    }
}

static void scan_esp_dir_recursive(const char *base_path, size_t root_len, uefi_scan_result_t *result, int depth) {
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
                scan_esp_dir_recursive(full_path, root_len, result, depth + 1);
            } else if (S_ISREG(st.st_mode)) {
                // By content, not name: a renamed payload (grubx64.bak) or a systemd-boot kernel is still a PE.
                char magic[2] = { 0 };
                FILE *fp = fopen(full_path, "rb");
                if (fp) {
                    size_t got = fread(magic, 1, sizeof(magic), fp);
                    fclose(fp);
                    if (got == 2 && magic[0] == 'M' && magic[1] == 'Z') {
                        uefi_inspect_efi_file(full_path, result);
                        check_esp_layout(full_path, full_path + root_len + 1, result);
                    }
                }
            }
        }
    }
    closedir(dir);
}

booto_error_t uefi_inspect_esp_directory(const char *esp_dir, uefi_scan_result_t *result) {
    if (!esp_dir || !result) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Scanning EFI System Partition (ESP) at: %s", esp_dir);
    scan_esp_dir_recursive(esp_dir, strlen(esp_dir), result, 0);

    LOG_INFO("ESP scan complete: %d EFI files inspected, %d bootkits/anomalies flagged",
             result->efi_files_scanned, result->bootkits_detected);
    return BOOTO_OK;
}
