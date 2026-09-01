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

typedef struct {
    const char *symbol_pattern;
    const char *rule_id;
    const char *threat_name;
    threat_severity_t severity;
    const char *description;
} lkm_threat_rule_t;

static const lkm_threat_rule_t G_LKM_RULES[] = {
    // 1. Syscall Table Manipulation
    { "sys_call_table",      "LKM_HOOK_SYS_CALL_TABLE", "Syscall Table Hooking",
      SEVERITY_CRITICAL, "Direct reference or modification to the kernel sys_call_table" },
    { "kallsyms_lookup_name","LKM_KALLSYMS_LOOKUP",     "Dynamic Kernel Symbol Resolution",
      SEVERITY_MEDIUM,   "Resolves unexported kernel symbols at runtime (used for syscall hooking)" },

    // 2. Diamorphine & Derivatives
    { "diamorphine",         "LKM_DIAMORPHINE_CORE",    "Diamorphine Rootkit",
      SEVERITY_CRITICAL, "Matches Diamorphine rootkit core symbol signatures" },
    { "hacked_kill",         "LKM_HOOK_KILL",           "Kill Syscall Interceptor",
      SEVERITY_CRITICAL, "Hooks sys_kill to execute root backdoor signals (e.g. signal 64 root escalation)" },
    { "hacked_getdents",     "LKM_HOOK_GETDENTS",       "Directory Entry Hider",
      SEVERITY_CRITICAL, "Hooks sys_getdents to hide rootkit files and directories from userland" },
    { "hacked_getdents64",   "LKM_HOOK_GETDENTS64",     "Directory Entry Hider (64-bit)",
      SEVERITY_CRITICAL, "Hooks sys_getdents64 to hide rootkit files and directories from userland" },
    { "is_invisible",        "LKM_DKOM_HIDE_MODULE",    "LKM Kernel Object Hiding (DKOM)",
      SEVERITY_CRITICAL, "Unlinks module from the sysfs/lsmod list using Direct Kernel Object Manipulation" },
    { "hide_proc",           "LKM_DKOM_HIDE_PROC",      "Process Hiding Mechanism",
      SEVERITY_CRITICAL, "Hides malicious PID structures from /proc directory walks" },

    // 3. Ftrace / Kprobe Hooking (Reptile / Suterusu / Ftrace Hooks)
    { "fh_install_hook",     "LKM_FTRACE_HOOK_INSTALL", "Ftrace Syscall Hijack",
      SEVERITY_CRITICAL, "Uses Linux ftrace subsystem to redirect kernel execution flow" },
    { "fh_remove_hook",      "LKM_FTRACE_HOOK_REMOVE",  "Ftrace Hook Uninstaller",
      SEVERITY_HIGH,     "Ftrace hook removal routine" },
    { "khook_init",          "LKM_KHOOK_ENGINE",        "Khook In-Kernel Hooking Engine",
      SEVERITY_CRITICAL, "Generic kernel-mode inline function hooking framework" },
    { "rep_hook",            "LKM_REPTILE_HOOK",        "Reptile Rootkit Hook",
      SEVERITY_CRITICAL, "Matches Reptile Linux rootkit network and file hook signatures" },
    { "suterusu",            "LKM_SUTERUSU_SIGNATURE",  "Suterusu Rootkit",
      SEVERITY_CRITICAL, "Matches Suterusu LKM rootkit framework signatures" },

    // 4. Network Packet Interceptors
    { "tcp4_seq_show",       "LKM_NET_PORT_HIDER",      "TCP Network Port Hider",
      SEVERITY_CRITICAL, "Hooks tcp4_seq_show to hide listening reverse shell ports from netstat/ss" },
    { "udp4_seq_show",       "LKM_NET_PORT_HIDER",      "UDP Network Port Hider",
      SEVERITY_CRITICAL, "Hooks udp4_seq_show to hide UDP listening ports" }
};

static const size_t G_LKM_RULES_COUNT = sizeof(G_LKM_RULES) / sizeof(G_LKM_RULES[0]);

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

    result->modules_scanned++;

    elf_binary_info_t elf;
    booto_error_t err = elf_parse_file(ko_path, &elf);
    if (err != BOOTO_OK) {
        LOG_WARN("Could not parse ELF binary '%s' (err: %d)", ko_path, err);
        return err;
    }

    // 1. Symbol Table Signature Matching
    for (int i = 0; i < elf.symbol_count; i++) {
        const elf_symbol_info_t *sym = &elf.symbols[i];

        for (size_t r = 0; r < G_LKM_RULES_COUNT; r++) {
            const lkm_threat_rule_t *rule = &G_LKM_RULES[r];
            if (strstr(sym->name, rule->symbol_pattern) != NULL) {
                add_threat_finding(result,
                                   rule->threat_name,
                                   ko_path,
                                   elf.sha256,
                                   rule->rule_id,
                                   sym->name,
                                   sym->value,
                                   rule->severity,
                                   rule->description);
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
