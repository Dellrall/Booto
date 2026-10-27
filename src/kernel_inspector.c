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

    // 1. Symbol Table Signature Matching
    for (int i = 0; i < elf.symbol_count; i++) {
        const elf_symbol_info_t *sym = &elf.symbols[i];

        for (int r = 0; r < rules->count; r++) {
            const rules_lkm_entry_t *rule = &rules->entries[r];
            for (int s = 0; s < rule->symbol_count; s++) {
                if (strstr(sym->name, rule->symbols[s]) == NULL) continue;
                add_threat_finding(result,
                                   rule->name,
                                   ko_path,
                                   elf.sha256,
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
    if (elf.modinfo.has_modinfo) {
        if (strlen(elf.modinfo.license) == 0) {
            add_threat_finding(result,
                               "Unlicensed Kernel Module",
                               ko_path,
                               elf.sha256,
                               "LKM_MISSING_LICENSE",
                               ".modinfo",
                               0,
                               SEVERITY_LOW,
                               "Kernel module lacks a declared license attribute");
        }
    }

    elf_free_info(&elf);
    return BOOTO_OK;
}

static void scan_dir_recursive(const char *base_path, kernel_scan_result_t *result, int depth) {
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
                scan_dir_recursive(full_path, result, depth + 1);
            } else if (S_ISREG(st.st_mode)) {
                size_t nlen = strlen(entry->d_name);
                if (nlen > 3 && strcmp(entry->d_name + nlen - 3, ".ko") == 0) {
                    kernel_inspect_lkm_file(full_path, result);
                }
            }
        }
    }
    closedir(dir);
}

booto_error_t kernel_inspect_directory(const char *lib_modules_dir, kernel_scan_result_t *result) {
    if (!lib_modules_dir || !result) return BOOTO_ERR_INVALID_ARG;

    // Per-file errors are tolerated during the walk; unusable rules must fail the whole engine.
    const rules_lkm_set_t *rules;
    booto_error_t err = rules_get_lkm(&rules);
    if (err != BOOTO_OK) return err;

    LOG_INFO("Scanning kernel modules in directory: %s", lib_modules_dir);
    scan_dir_recursive(lib_modules_dir, result, 0);

    LOG_INFO("Kernel module scan complete: %d modules inspected, %d threats flagged",
             result->modules_scanned, result->threats_detected);
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
