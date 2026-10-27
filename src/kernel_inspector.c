/**
 * @file kernel_inspector.c
 * @brief Offline forensic inspection of Linux Kernel Modules (.ko) and vmlinuz.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "kernel_inspector.h"
#include "crypto_utils.h"
#include "disk_mount.h"
#include "logger.h"
#include "rules_loader.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

const char *kernel_severity_to_string(threat_severity_t severity) {
    switch (severity) {
        case SEVERITY_CRITICAL: return "CRITICAL";
        case SEVERITY_HIGH:     return "HIGH";
        case SEVERITY_MEDIUM:   return "MEDIUM";
        case SEVERITY_LOW:      return "LOW";
        default:                return "INFO";
    }
}

static void add_threat_finding(kernel_scan_result_t *result,
                               const char *threat_name,
                               const char *file_path,
                               const char *sha256,
                               const char *rule_id,
                               const char *matched_sym,
                               uint64_t offset,
                               threat_severity_t severity,
                               const char *description) {
    if (!result || result->threats_detected >= MAX_KERNEL_THREATS) return;

    kernel_threat_finding_t *f = &result->findings[result->threats_detected++];
    snprintf(f->threat_name, sizeof(f->threat_name), "%s", threat_name ? threat_name : "Kernel Anomaly");
    snprintf(f->file_path, sizeof(f->file_path), "%s", file_path ? file_path : "");
    snprintf(f->sha256, sizeof(f->sha256), "%s", sha256 ? sha256 : "");
    snprintf(f->detection_rule, sizeof(f->detection_rule), "%s", rule_id ? rule_id : "RULE_UNKNOWN");
    snprintf(f->matched_symbol, sizeof(f->matched_symbol), "%s", matched_sym ? matched_sym : "");
    f->symbol_offset = offset;
    f->severity = severity;
    snprintf(f->description, sizeof(f->description), "%s", description ? description : "");

    LOG_CRITICAL("[ALERT] %s in %s (Rule: %s, Symbol: %s, Severity: %s)",
                 f->threat_name, f->file_path, f->detection_rule, f->matched_symbol,
                 kernel_severity_to_string(f->severity));
}

#define LKM_DECOMP_CAP ((size_t)256 * 1024 * 1024)

typedef struct {
    const char *suffix;
    const char *tool;
} lkm_codec_t;

static const lkm_codec_t G_LKM_CODECS[] = {
    { ".ko.xz",  "xz" },
    { ".ko.zst", "zstd" },
    { ".ko.gz",  "gzip" }
};

#define LKM_CODEC_COUNT (sizeof(G_LKM_CODECS) / sizeof(G_LKM_CODECS[0]))

/* Rule + modinfo checks on a parsed module; frees elf's symbol table. */
static void analyze_lkm(const char *ko_path, const rules_lkm_set_t *rules, elf_binary_info_t *elf, kernel_scan_result_t *result) {
    // 1. Symbol Table Signature Matching
    for (int i = 0; i < elf->symbol_count; i++) {
        const elf_symbol_info_t *sym = &elf->symbols[i];

        for (int r = 0; r < rules->count; r++) {
            const rules_lkm_entry_t *rule = &rules->entries[r];
            for (int s = 0; s < rule->symbol_count; s++) {
                if (strstr(sym->name, rule->symbols[s]) == NULL) continue;
                add_threat_finding(result,
                                   rule->name,
                                   ko_path,
                                   elf->sha256,
                                   rule->rule_id,
                                   sym->name,
                                   sym->value,
                                   (threat_severity_t)rules_severity_level(rule->severity),
                                   rule->description);
                break; // one finding per (symbol, rule)
            }
        }
    }

    // 2. Modinfo Checks (Unusual or suspicious attributes)
    if (elf->modinfo.has_modinfo) {
        if (strlen(elf->modinfo.license) == 0) {
            add_threat_finding(result,
                               "Unlicensed Kernel Module",
                               ko_path,
                               elf->sha256,
                               "LKM_MISSING_LICENSE",
                               ".modinfo",
                               0,
                               SEVERITY_LOW,
                               "Kernel module lacks a declared license attribute");
        }
    }

    elf_free_info(elf);
}

booto_error_t kernel_inspect_lkm_file(const char *ko_path, kernel_scan_result_t *result) {
    if (!ko_path || !result) return BOOTO_ERR_INVALID_ARG;

    const rules_lkm_set_t *rules;
    booto_error_t err = rules_get_lkm(&rules);
    if (err != BOOTO_OK) return err;

    result->modules_scanned++;

    elf_binary_info_t elf;
    err = elf_parse_file(ko_path, &elf);
    if (err != BOOTO_OK) {
        LOG_WARN("Could not parse ELF binary '%s' (err: %d)", ko_path, err);
        return err;
    }
    analyze_lkm(ko_path, rules, &elf, result);
    return BOOTO_OK;
}

/* Decompress a .ko.{xz,zst,gz} via the external tool and run the same ELF checks on the buffer. */
static booto_error_t inspect_compressed_lkm(const char *ko_path, const lkm_codec_t *codec, kernel_scan_result_t *result) {
    const rules_lkm_set_t *rules;
    booto_error_t err = rules_get_lkm(&rules);
    if (err != BOOTO_OK) return err;

    result->modules_scanned++;

    const char *const argv[] = {codec->tool, "-dc", "--", ko_path, NULL};
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    err = disk_exec_capture(argv, NULL, 0, &raw, &raw_len, LKM_DECOMP_CAP);
    if (err != BOOTO_OK) {
        if (err == BOOTO_ERR_NOT_FOUND) {
            LOG_ERROR("Decompressor '%s' not available; cannot inspect compressed module '%s'", codec->tool, ko_path);
        } else {
            LOG_WARN("Could not decompress kernel module '%s' (err: %d)", ko_path, err);
        }
        return err;
    }

    elf_binary_info_t elf;
    err = raw ? elf_parse_buffer(raw, raw_len, &elf) : BOOTO_ERR_CORRUPT_DATA;
    free(raw);
    if (err != BOOTO_OK) {
        LOG_WARN("Could not parse decompressed ELF binary '%s' (err: %d)", ko_path, err);
        return err;
    }
    snprintf(elf.file_path, sizeof(elf.file_path), "%s", ko_path);
    analyze_lkm(ko_path, rules, &elf, result);
    return BOOTO_OK;
}

/* missing_tools: bitmask over G_LKM_CODECS of decompressors found absent (logged once, skipped afterwards). */
static void scan_dir_recursive(const char *base_path, kernel_scan_result_t *result, int depth, unsigned *missing_tools) {
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
                scan_dir_recursive(full_path, result, depth + 1, missing_tools);
            } else if (S_ISREG(st.st_mode)) {
                size_t nlen = strlen(entry->d_name);
                if (nlen > 3 && strcmp(entry->d_name + nlen - 3, ".ko") == 0) {
                    kernel_inspect_lkm_file(full_path, result);
                    continue;
                }
                for (size_t c = 0; c < LKM_CODEC_COUNT; c++) {
                    size_t slen = strlen(G_LKM_CODECS[c].suffix);
                    if (nlen <= slen || strcmp(entry->d_name + nlen - slen, G_LKM_CODECS[c].suffix) != 0) continue;
                    if (!(*missing_tools & (1U << c)) &&
                        inspect_compressed_lkm(full_path, &G_LKM_CODECS[c], result) == BOOTO_ERR_NOT_FOUND) {
                        *missing_tools |= 1U << c;
                    }
                    break;
                }
            }
        }
    }
    closedir(dir);
}

booto_error_t kernel_inspect_directory(const char *lib_modules_dir, kernel_scan_result_t *result) {
    if (!lib_modules_dir || !result) return BOOTO_ERR_INVALID_ARG;

    // Per-file errors are tolerated during the walk; unusable rules or a missing decompressor fail the whole engine.
    const rules_lkm_set_t *rules;
    booto_error_t err = rules_get_lkm(&rules);
    if (err != BOOTO_OK) return err;

    LOG_INFO("Scanning kernel modules in directory: %s", lib_modules_dir);
    unsigned missing_tools = 0;
    scan_dir_recursive(lib_modules_dir, result, 0, &missing_tools);

    LOG_INFO("Kernel module scan complete: %d modules inspected, %d threats flagged",
             result->modules_scanned, result->threats_detected);
    if (missing_tools != 0) {
        LOG_ERROR("Compressed kernel modules were left uninspected because a decompressor is missing");
        return BOOTO_ERR_NOT_FOUND;
    }
    return BOOTO_OK;
}

booto_error_t kernel_inspect_vmlinuz(const char *vmlinuz_path, kernel_scan_result_t *result) {
    if (!vmlinuz_path || !result) return BOOTO_ERR_INVALID_ARG;

    (void)result;
    LOG_INFO("Inspecting kernel image: %s", vmlinuz_path);

    char sha256[65];
    if (sha256_file_hex(vmlinuz_path, sha256)) {
        LOG_INFO("Kernel image %s SHA-256: %s", vmlinuz_path, sha256);
    } else {
        LOG_WARN("Could not read kernel image '%s'", vmlinuz_path);
    }

    return BOOTO_OK;
}
