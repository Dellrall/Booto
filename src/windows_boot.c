/**
 * @file windows_boot.c
 * @brief Windows boot chain check: what bootkits such as FinSpy and ESPecter patch on the system partition.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "windows_boot.h"
#include "uefi_analyzer.h"
#include "logger.h"
#include "firmware_auditor.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

/* NTFS names are case-insensitive but ntfs3 lookups are not: find <dir>/<name> by any case. */
static bool ci_child(const char *dir, const char *name, char *out, size_t n) {
    DIR *d = opendir(dir);
    if (!d) return false;
    struct dirent *de;
    bool found = false;
    while (!found && (de = readdir(d)) != NULL) {
        if (strcasecmp(de->d_name, name) == 0) {
            snprintf(out, n, "%.300s/%.200s", dir, de->d_name);
            found = true;
        }
    }
    closedir(d);
    return found;
}

static bool system32(const char *root, char *out, size_t n) {
    char win[512];
    return ci_child(root, "Windows", win, sizeof(win)) && ci_child(win, "System32", out, n);
}

bool winboot_is_windows_root(const char *root) {
    char s32[512], krnl[512];
    return root && system32(root, s32, sizeof(s32)) && ci_child(s32, "ntoskrnl.exe", krnl, sizeof(krnl));
}

static void add(winboot_scan_result_t *res, const char *path, const pe_efi_info_t *pe, booto_severity_t sev,
                const char *reason) {
    LOG_WARN("Windows boot: %s %s", path, reason);
    if (res->threats_detected >= MAX_WINBOOT_THREATS) return;
    winboot_finding_t *f = &res->findings[res->threats_detected++];
    snprintf(f->file_path, sizeof(f->file_path), "%s", path);
    snprintf(f->sha256, sizeof(f->sha256), "%s", pe ? pe->sha256 : "");
    snprintf(f->reason, sizeof(f->reason), "%s", reason);
    f->severity = sev;
}

static void check_file(winboot_scan_result_t *res, const char *path, bool core) {
    pe_efi_info_t pe;
    memset(&pe, 0, sizeof(pe));
    booto_error_t e = uefi_parse_pe_file(path, &pe);
    res->files_checked++;
    if (e == BOOTO_ERR_CORRUPT_DATA) { add(res, path, NULL, SEVERITY_HIGH, "is not a valid PE image"); return; }
    if (e != BOOTO_OK) { res->not_checked++; return; }
    switch (pe.authenticode_state) {
        case AUTHENTICODE_HASH_MISMATCH:
            add(res, path, &pe, SEVERITY_CRITICAL, "was changed after it was signed"); break;
        case AUTHENTICODE_INVALID:
            add(res, path, &pe, SEVERITY_HIGH, "has a signature that does not verify"); break;
        case AUTHENTICODE_UNSUPPORTED:
            res->not_checked++; break;
        case AUTHENTICODE_NONE:
            if (core) add(res, path, &pe, SEVERITY_HIGH, "has no embedded signature");
            else res->drivers_unsigned++;
            break;
        case AUTHENTICODE_VALID:
            if (pe.authenticode_microsoft) break;
            if (core) add(res, path, &pe, SEVERITY_CRITICAL, "is signed, but not by Microsoft");
            else res->drivers_third_party++;  // shortcut: legacy cross-signed drivers chain elsewhere; check against db later
            break;
    }
}

static const char *const CORE[] = { "winload.efi", "winload.exe", "winresume.efi", "winresume.exe",
                                   "ntoskrnl.exe", "hal.dll", "ci.dll" };

void winboot_each_core_file(const char *root, void (*fn)(const char *path, void *user), void *user) {
    char s32[512], path[512];
    if (!root || !fn || !system32(root, s32, sizeof(s32))) return;
    for (size_t i = 0; i < sizeof(CORE) / sizeof(CORE[0]); i++)
        if (ci_child(s32, CORE[i], path, sizeof(path))) fn(path, user);
}

booto_error_t winboot_scan_rootfs(const char *root, winboot_scan_result_t *res) {
    if (!root || !res) return BOOTO_ERR_INVALID_ARG;
    memset(res, 0, sizeof(*res));
    char s32[512], path[512];
    if (!system32(root, s32, sizeof(s32))) return BOOTO_ERR_NOT_FOUND;

    for (size_t i = 0; i < sizeof(CORE) / sizeof(CORE[0]); i++)
        if (ci_child(s32, CORE[i], path, sizeof(path))) check_file(res, path, true);

    char drv[512];
    if (!ci_child(s32, "drivers", drv, sizeof(drv))) return BOOTO_OK;
    DIR *d = opendir(drv);
    if (!d) return BOOTO_ERR_IO;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len < 5 || strcasecmp(de->d_name + len - 4, ".sys") != 0) continue;
        snprintf(path, sizeof(path), "%.300s/%.200s", drv, de->d_name);
        struct stat st;
        if (lstat(path, &st) == 0 && S_ISREG(st.st_mode)) check_file(res, path, false);
    }
    closedir(d);
    LOG_INFO("Windows boot: %d files, %d finding(s), %d driver(s) without embedded signature", res->files_checked,
             res->threats_detected, res->drivers_unsigned);
    return BOOTO_OK;
}

#define MEASURED_LOG_CAP (4u << 20)
#define MEASURED_MAX_APPS 64

booto_error_t winboot_measured_has(const char *root, const char *authenticode_hex, bool *found, char *log_name,
                                   size_t n) {
    if (!root || !authenticode_hex || !found) return BOOTO_ERR_INVALID_ARG;
    *found = false;
    char win[512], logs[512], mb[512];
    if (!ci_child(root, "Windows", win, sizeof(win)) || !ci_child(win, "Logs", logs, sizeof(logs)) ||
        !ci_child(logs, "MeasuredBoot", mb, sizeof(mb)))
        return BOOTO_ERR_NOT_FOUND;
    // Names are <boot count>-<resume count>.log, zero-padded, so the largest name is the newest boot.
    DIR *d = opendir(mb);
    if (!d) return BOOTO_ERR_NOT_FOUND;
    char newest[256] = "";
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t len = strlen(de->d_name);
        if (len > 4 && len < sizeof(newest) && strcasecmp(de->d_name + len - 4, ".log") == 0 &&
            strcmp(de->d_name, newest) > 0)
            snprintf(newest, sizeof(newest), "%s", de->d_name);
    }
    closedir(d);
    if (!newest[0]) return BOOTO_ERR_NOT_FOUND;
    if (log_name) snprintf(log_name, n, "%s", newest);

    char path[800];
    snprintf(path, sizeof(path), "%s/%s", mb, newest);
    FILE *fp = fopen(path, "rb");
    if (!fp) return BOOTO_ERR_IO;
    uint8_t *buf = malloc(MEASURED_LOG_CAP);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }
    size_t len = fread(buf, 1, MEASURED_LOG_CAP, fp);
    fclose(fp);
    uint8_t apps[MEASURED_MAX_APPS][32];
    int napps = firmware_tpm_log_apps(buf, len, apps, MEASURED_MAX_APPS);
    free(buf);
    if (napps < 0) return BOOTO_ERR_CORRUPT_DATA;
    for (int i = 0; i < napps && !*found; i++) {
        char hex[65];
        for (int j = 0; j < 32; j++) snprintf(hex + 2 * j, 3, "%02x", apps[i][j]);
        *found = strcasecmp(hex, authenticode_hex) == 0;
    }
    return BOOTO_OK;
}
