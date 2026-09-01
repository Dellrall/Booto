/**
 * @file preload_scanner.c
 * @brief Implementation of userland LD_PRELOAD and PAM interceptor scanner.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "preload_scanner.h"
#include "crypto_utils.h"
#include "logger.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void add_preload_threat(preload_scan_result_t *result,
                               const char *file_path,
                               const char *threat_name,
                               const char *target_lib,
                               const char *sha256,
                               const char *rule_id,
                               const char *description) {
    if (!result || result->threats_detected >= MAX_PRELOAD_THREATS) return;

    preload_finding_t *f = &result->findings[result->threats_detected++];
    snprintf(f->file_path, sizeof(f->file_path), "%.255s", file_path ? file_path : "");
    snprintf(f->threat_name, sizeof(f->threat_name), "%.63s", threat_name ? threat_name : "Preload Anomaly");
    snprintf(f->target_library, sizeof(f->target_library), "%.255s", target_lib ? target_lib : "");
    snprintf(f->sha256, sizeof(f->sha256), "%.64s", sha256 ? sha256 : "");
    snprintf(f->rule_id, sizeof(f->rule_id), "%.63s", rule_id ? rule_id : "RULE_UNKNOWN");
    snprintf(f->description, sizeof(f->description), "%.255s", description ? description : "");

    LOG_CRITICAL("[PRELOAD ALERT] %s in %s (Target: '%s', Rule: %s)",
                 f->threat_name, f->file_path, f->target_library, f->rule_id);
}

static void scan_ld_so_preload(const char *rootfs, preload_scan_result_t *result) {
    char preload_path[512];
    snprintf(preload_path, sizeof(preload_path), "%.400s/etc/ld.so.preload", rootfs);

    FILE *fp = fopen(preload_path, "r");
    if (!fp) return;

    result->files_scanned++;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        char *ptr = line;
        while (*ptr && isspace((unsigned char)*ptr)) ptr++;
        if (*ptr == '\0' || *ptr == '#') continue;

        size_t len = strlen(ptr);
        while (len > 0 && isspace((unsigned char)ptr[len - 1])) {
            ptr[--len] = '\0';
        }

        if (len > 0) {
            char target_full[1024];
            snprintf(target_full, sizeof(target_full), "%.500s%.500s", rootfs, ptr);

            char sha256[65] = "0000000000000000000000000000000000000000000000000000000000000000";
            sha256_file_hex(target_full, sha256);

            add_preload_threat(result,
                               preload_path,
                               "Active Userland LD_PRELOAD Rootkit",
                               ptr,
                               sha256,
                               "PRELOAD_ACTIVE_HOOK",
                               "Active dynamic linker shared object hook configured in /etc/ld.so.preload");
        }
    }

    fclose(fp);
}

static void scan_ld_conf_dir(const char *rootfs, preload_scan_result_t *result) {
    char conf_dir[512];
    snprintf(conf_dir, sizeof(conf_dir), "%.400s/etc/ld.so.conf.d", rootfs);

    DIR *dir = opendir(conf_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_file[1024];
        snprintf(full_file, sizeof(full_file), "%.500s/%.255s", conf_dir, entry->d_name);

        FILE *fp = fopen(full_file, "r");
        if (!fp) continue;

        result->files_scanned++;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            char *ptr = line;
            while (*ptr && isspace((unsigned char)*ptr)) ptr++;
            if (*ptr == '#' || *ptr == '\0') continue;

            if (strstr(ptr, "/tmp") || strstr(ptr, "/dev/shm") || strstr(ptr, "/var/tmp") || strstr(ptr, "/.")) {
                add_preload_threat(result,
                                   full_file,
                                   "Suspicious Dynamic Linker Path",
                                   ptr,
                                   "",
                                   "PRELOAD_SUSPICIOUS_CONF_PATH",
                                   "ld.so.conf references temporary or hidden directory for library resolution");
            }
        }
        fclose(fp);
    }
    closedir(dir);
}

booto_error_t preload_scan_rootfs(const char *target_rootfs, preload_scan_result_t *result) {
    if (!target_rootfs || !result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    LOG_INFO("Scanning userland preload configurations in rootfs: %s", target_rootfs);

    scan_ld_so_preload(target_rootfs, result);
    scan_ld_conf_dir(target_rootfs, result);

    LOG_INFO("Preload scanner complete: %d config files audited, %d userland threats flagged",
             result->files_scanned, result->threats_detected);
    return BOOTO_OK;
}
