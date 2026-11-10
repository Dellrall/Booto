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
#include "reg_hive.h"

#include <ctype.h>
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

/* <dir>/<rel> by any case, rel split on '\\' or '/'. Refuses "..", symlinks and a final non-regular file:
 * rel comes from a hive the attacker controls. */
static bool ci_path(const char *dir, const char *rel, char *out, size_t n) {
    char cur[512], next[512], part[256];
    snprintf(cur, sizeof(cur), "%s", dir);
    struct stat st = {0};
    while (*rel) {
        size_t len = strcspn(rel, "\\/");
        if (len >= sizeof(part)) return false;
        memcpy(part, rel, len);
        part[len] = '\0';
        rel += len + (rel[len] != '\0');
        if (len == 0 || strcmp(part, ".") == 0) continue;
        if (strcmp(part, "..") == 0 || !ci_child(cur, part, next, sizeof(next))) return false;
        if (lstat(next, &st) != 0 || S_ISLNK(st.st_mode)) return false;
        memcpy(cur, next, sizeof(cur));
    }
    if (!S_ISREG(st.st_mode)) return false;
    snprintf(out, n, "%s", cur);
    return true;
}

#define HIVE_CAP (256u << 20)

/* Whole file in a malloc'd buffer, or NULL. */
static uint8_t *read_hive(const char *path, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    uint8_t *buf = NULL;
    struct stat st;
    if (fstat(fileno(fp), &st) == 0 && st.st_size > 0 && (uint64_t)st.st_size <= HIVE_CAP &&
        (buf = malloc((size_t)st.st_size)) != NULL) {
        *len = fread(buf, 1, (size_t)st.st_size, fp);
    }
    fclose(fp);
    return buf;
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

/* ImagePath (or the default System32\\drivers\\<name>.sys) to a file under the install. */
static bool image_file(const char *root, const char *win, const char *img, char *out, size_t n) {
    const char *p = img, *base = win;
    if (strncmp(p, "\\??\\", 4) == 0) p += 4;
    if (strncasecmp(p, "\\SystemRoot\\", 12) == 0) p += 12;
    else if (strncasecmp(p, "%SystemRoot%\\", 13) == 0) p += 13;
    else if (isalpha((unsigned char)p[0]) && p[1] == ':') { p += 2; base = root; }  // shortcut: assumes the system drive
    else if (p[0] == '\\') base = root;
    return ci_path(base, p, out, n);
}

/* Boot-start services (Start = 0) in the SYSTEM hive whose file lies outside System32\\drivers, which the caller
 * already checked. shortcut: changes still in the hive's .LOG1/.LOG2 transaction logs are not applied. */
static void check_boot_start(winboot_scan_result_t *res, const char *root, const char *win, const char *drv) {
    char path[512], cs[16], name[256], img[512];
    if (!ci_path(win, "System32/config/SYSTEM", path, sizeof(path))) return;
    size_t len = 0;
    uint8_t *buf = read_hive(path, &len);
    reg_hive_t h;
    uint32_t cur = 0, svcs = 0, top;
    if (buf && reg_hive_open(buf, len, &h) == BOOTO_OK && (top = reg_hive_root(&h)) != 0 &&
        reg_hive_dword(&h, reg_hive_subkey(&h, top, "Select"), "Current", &cur) && cur > 0 && cur < 1000) {
        snprintf(cs, sizeof(cs), "ControlSet%03u", cur);
        svcs = reg_hive_subkey(&h, reg_hive_subkey(&h, top, cs), "Services");
    }
    if (!svcs) {
        LOG_WARN("Windows boot: cannot read the service list in %s", path);
        res->not_checked++;
        free(buf);
        return;
    }
    size_t dlen = strlen(drv);
    uint32_t svc, start;
    for (uint32_t i = 0; (svc = reg_hive_subkey_at(&h, svcs, i, name, sizeof(name))) != 0; i++) {
        if (!reg_hive_dword(&h, svc, "Start", &start) || start != 0) continue;
        res->boot_start++;
        if (!reg_hive_string(&h, svc, "ImagePath", img, sizeof(img)))
            snprintf(img, sizeof(img), "System32\\drivers\\%.200s.sys", name);
        if (!image_file(root, win, img, path, sizeof(path))) {
            res->not_checked++;
            continue;
        }
        const char *slash = strrchr(path, '/');
        if (slash && (size_t)(slash - path) == dlen && strncmp(path, drv, dlen) == 0) continue;
        check_file(res, path, false);
    }
    free(buf);
}

/* BCD elements (bcdedit names) that switch off a boot protection when set on any object. */
static const struct {
    const char *type;
    booto_severity_t sev;
    const char *reason;
} BCD_FLAGS[] = {
    { "16000049", SEVERITY_HIGH, "BCD: testsigning is on: drivers need no trusted signature" },
    { "16000048", SEVERITY_HIGH, "BCD: nointegritychecks is on: code integrity is off" },
    { "16000010", SEVERITY_MEDIUM, "BCD: the boot debugger is on" },
    { "260000a0", SEVERITY_MEDIUM, "BCD: the kernel debugger is on" },
};
#define BCD_APP_PATH "12000002"
#define BCD_OS_LOADER 0x10200003u

booto_error_t winboot_check_bcd(const char *esp, winboot_scan_result_t *res) {
    if (!esp || !res) return BOOTO_ERR_INVALID_ARG;
    char path[512];
    if (!ci_path(esp, "EFI/Microsoft/Boot/BCD", path, sizeof(path))) return BOOTO_ERR_NOT_FOUND;
    size_t len = 0;
    uint8_t *buf = read_hive(path, &len);
    if (!buf) return BOOTO_ERR_IO;
    reg_hive_t h;
    uint32_t objs = 0;
    if (reg_hive_open(buf, len, &h) == BOOTO_OK) objs = reg_hive_subkey(&h, reg_hive_root(&h), "Objects");
    if (!objs) {
        free(buf);
        add(res, path, NULL, SEVERITY_HIGH, "BCD store is not a valid registry hive");
        return BOOTO_OK;
    }
    char guid[64], app[512], why[96];
    uint32_t obj, type, blen;
    const uint8_t *d;
    for (uint32_t i = 0; (obj = reg_hive_subkey_at(&h, objs, i, guid, sizeof(guid))) != 0; i++) {
        uint32_t els = reg_hive_subkey(&h, obj, "Elements");
        for (size_t f = 0; f < sizeof(BCD_FLAGS) / sizeof(BCD_FLAGS[0]); f++)
            if (reg_hive_value(&h, reg_hive_subkey(&h, els, BCD_FLAGS[f].type), "Element", &type, &d, &blen) &&
                blen > 0 && d[0] != 0)
                add(res, path, NULL, BCD_FLAGS[f].sev, BCD_FLAGS[f].reason);
        uint32_t otype = 0;
        if (!reg_hive_dword(&h, reg_hive_subkey(&h, obj, "Description"), "Type", &otype) || otype != BCD_OS_LOADER ||
            !reg_hive_string(&h, reg_hive_subkey(&h, els, BCD_APP_PATH), "Element", app, sizeof(app)))
            continue;
        if (strcasecmp(app, "\\Windows\\system32\\winload.efi") != 0 &&
            strcasecmp(app, "\\Windows\\system32\\winload.exe") != 0) {
            snprintf(why, sizeof(why), "BCD: Windows loads %.60s, not winload", app);
            add(res, path, NULL, SEVERITY_CRITICAL, why);
        }
    }
    free(buf);
    LOG_INFO("Windows boot: BCD store %s read", path);
    return BOOTO_OK;
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
    char win[512];
    if (ci_child(root, "Windows", win, sizeof(win))) check_boot_start(res, root, win, drv);
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
