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
#include <errno.h>
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

#define PRELOAD_MAX_FILE_BYTES (1024u * 1024u)

// Reads path fully into a NUL-terminated heap buffer; absent -> NOT_FOUND, oversized -> CORRUPT_DATA.
static booto_error_t read_config_file(const char *path, char **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    char *buf = malloc(PRELOAD_MAX_FILE_BYTES + 1);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }
    size_t n = fread(buf, 1, PRELOAD_MAX_FILE_BYTES + 1, fp);
    bool failed = ferror(fp) != 0;
    fclose(fp);
    if (failed || n > PRELOAD_MAX_FILE_BYTES) {
        free(buf);
        return failed ? BOOTO_ERR_IO : BOOTO_ERR_CORRUPT_DATA;
    }
    buf[n] = '\0';
    *out = buf;
    *out_len = n;
    return BOOTO_OK;
}

static bool is_preload_separator(char c) {
    return c == ':' || c == '\0' || c == '"' || c == '\'' || isspace((unsigned char)c);
}

// Hashes and reports every library in s[0..len): ld.so separates entries by whitespace or ':' and
// treats '#' as a comment to end of line.
static void report_preload_tokens(const char *rootfs, const char *cfg_path, const char *s, size_t len,
                                  const char *threat_name, const char *rule_id, const char *description,
                                  preload_scan_result_t *result) {
    size_t i = 0;
    while (i < len) {
        if (s[i] == '#') {
            while (i < len && s[i] != '\n') i++;
            continue;
        }
        if (is_preload_separator(s[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < len && s[i] != '#' && !is_preload_separator(s[i])) i++;

        char lib[256];
        size_t tok_len = i - start < sizeof(lib) - 1 ? i - start : sizeof(lib) - 1;
        memcpy(lib, s + start, tok_len);
        lib[tok_len] = '\0';

        char target_full[1024];
        snprintf(target_full, sizeof(target_full), "%.700s%s%s", rootfs, lib[0] == '/' ? "" : "/", lib);
        char sha256[65] = "0000000000000000000000000000000000000000000000000000000000000000";
        sha256_file_hex(target_full, sha256);

        add_preload_threat(result, cfg_path, threat_name, lib, sha256, rule_id, description);
    }
}

static booto_error_t scan_ld_so_preload(const char *rootfs, preload_scan_result_t *result) {
    char preload_path[512];
    snprintf(preload_path, sizeof(preload_path), "%.400s/etc/ld.so.preload", rootfs);

    char *buf = NULL;
    size_t len = 0;
    booto_error_t err = read_config_file(preload_path, &buf, &len);
    if (err == BOOTO_ERR_NOT_FOUND) return BOOTO_OK;
    if (err != BOOTO_OK) {
        LOG_ERROR("Cannot read '%s' (err: %d); preload hooks not audited", preload_path, err);
        return err;
    }

    result->files_scanned++;
    report_preload_tokens(rootfs, preload_path, buf, len,
                          "Active Userland LD_PRELOAD Rootkit", "PRELOAD_ACTIVE_HOOK",
                          "Active dynamic linker shared object hook configured in /etc/ld.so.preload", result);
    free(buf);
    return BOOTO_OK;
}

// pam_env reads KEY=VALUE lines (optionally prefixed by "export") from /etc/environment.
static booto_error_t scan_environment(const char *rootfs, preload_scan_result_t *result) {
    char env_path[512];
    snprintf(env_path, sizeof(env_path), "%.400s/etc/environment", rootfs);

    char *buf = NULL;
    size_t len = 0;
    booto_error_t err = read_config_file(env_path, &buf, &len);
    if (err == BOOTO_ERR_NOT_FOUND) return BOOTO_OK;
    if (err != BOOTO_OK) {
        LOG_ERROR("Cannot read '%s' (err: %d); LD_PRELOAD environment not audited", env_path, err);
        return err;
    }

    result->files_scanned++;
    static const char key[] = "LD_PRELOAD=";
    const size_t key_len = sizeof(key) - 1;
    size_t pos = 0;
    while (pos < len) {
        const char *nl = memchr(buf + pos, '\n', len - pos);
        size_t eol = nl ? (size_t)(nl - buf) : len;
        size_t p = pos;
        while (p < eol && isspace((unsigned char)buf[p])) p++;
        if (eol - p > 7 && strncmp(buf + p, "export", 6) == 0 && isspace((unsigned char)buf[p + 6])) {
            p += 7;
            while (p < eol && isspace((unsigned char)buf[p])) p++;
        }
        if (eol - p >= key_len && strncmp(buf + p, key, key_len) == 0) {
            report_preload_tokens(rootfs, env_path, buf + p + key_len, eol - p - key_len,
                                  "Persistent LD_PRELOAD Environment Hook", "PRELOAD_ENV_HOOK",
                                  "LD_PRELOAD shared object injected into every login session via /etc/environment",
                                  result);
        }
        pos = eol + 1;
    }
    free(buf);
    return BOOTO_OK;
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

    booto_error_t err = scan_ld_so_preload(target_rootfs, result);
    booto_error_t env_err = scan_environment(target_rootfs, result);
    scan_ld_conf_dir(target_rootfs, result);
    if (err == BOOTO_OK) err = env_err;

    LOG_INFO("Preload scanner complete: %d config files audited, %d userland threats flagged",
             result->files_scanned, result->threats_detected);
    return err;
}
