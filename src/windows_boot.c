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
#include "crypto_utils.h"

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
static bool ci_walk(const char *dir, const char *rel, char *out, size_t n, bool want_dir) {
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
    if (want_dir ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) return false;
    snprintf(out, n, "%s", cur);
    return true;
}

static bool ci_path(const char *dir, const char *rel, char *out, size_t n) { return ci_walk(dir, rel, out, n, false); }
static bool ci_dir(const char *dir, const char *rel, char *out, size_t n) { return ci_walk(dir, rel, out, n, true); }

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

static void add_rule(winboot_scan_result_t *res, const char *path, booto_severity_t sev, const char *rule,
                     const char *reason) {
    int before = res->threats_detected;
    add(res, path, NULL, sev, reason);
    if (res->threats_detected > before) snprintf(res->findings[before].rule_id, sizeof(res->findings[before].rule_id), "%s", rule);
}

/* A command line that runs a script host, or a program from a folder any user (or a dropper) can write. */
static const char *suspect_command(const char *cmd) {
    char lc[512];
    size_t i = 0;
    for (; cmd[i] && i + 1 < sizeof(lc); i++) lc[i] = (char)tolower((unsigned char)cmd[i]);
    lc[i] = '\0';
    static const char *const hosts[] = { "powershell", "pwsh", "mshta", "wscript", "cscript", "%comspec%", "cmd.exe /c",
                                         "cmd /c", "cmd.exe /k" };
    static const char *const dirs[] = { "\\windows\\temp\\", "\\appdata\\local\\temp\\", "\\users\\public\\",
                                        "\\$recycle.bin\\", "\\perflogs\\" };
    for (size_t k = 0; k < sizeof(hosts) / sizeof(hosts[0]); k++)
        if (strstr(lc, hosts[k])) return "runs a script host";
    for (size_t k = 0; k < sizeof(dirs) / sizeof(dirs[0]); k++)
        if (strstr(lc, dirs[k])) return "runs from a user-writable folder";
    return NULL;
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
    char reason[96];
    for (int i = 0; i < pe.yara_count && !pe.authenticode_microsoft; i++) {
        snprintf(reason, sizeof(reason), "matches YARA rule %.63s", pe.yara[i].rule);
        add(res, path, &pe, pe.yara[i].severity, reason);
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
    char path[512], hive[512], cs[16], name[256], img[512];
    if (!ci_path(win, "System32/config/SYSTEM", path, sizeof(path))) return;
    memcpy(hive, path, sizeof(hive));  // path is reused for each driver below
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
        if (!reg_hive_dword(&h, svc, "Start", &start) || start > 2) continue;
        const char *why = reg_hive_string(&h, svc, "ImagePath", img, sizeof(img)) ? suspect_command(img) : NULL;
        if (why) {
            char reason[96];
            snprintf(reason, sizeof(reason), "auto-start service %.30s %s: %.30s", name, why, img);
            add_rule(res, hive, SEVERITY_HIGH, "WIN_SERVICE_COMMAND", reason);
        }
        if (start != 0) continue;
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
        if (reg_hive_value(&h, reg_hive_subkey(&h, els, "16000009"), "Element", &type, &d, &blen) && blen > 0 && d[0] == 0) {
            int before = res->threats_detected;
            add(res, path, NULL, SEVERITY_MEDIUM, "BCD: automatic recovery is off (bcdedit recoveryenabled No)");
            if (res->threats_detected > before)
                snprintf(res->findings[before].rule_id, sizeof(res->findings[before].rule_id), "WIN_RANSOM_RECOVERY_OFF");
        }
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

/* Registry key by a backslash path below key, or 0. */
static uint32_t key_path(const reg_hive_t *h, uint32_t key, const char *rel) {
    char part[128];
    while (key && *rel) {
        size_t len = strcspn(rel, "\\");
        if (len >= sizeof(part)) return 0;
        memcpy(part, rel, len);
        part[len] = '\0';
        rel += len + (rel[len] != '\0');
        key = reg_hive_subkey(h, key, part);
    }
    return key;
}

/* Every comma-separated entry of v is exe, by name or as the last part of a path. */
static bool only_entries(const char *v, const char *exe) {
    size_t elen = strlen(exe);
    while (*v) {
        while (*v == ' ' || *v == ',') v++;
        size_t len = strcspn(v, ",");
        while (len > 0 && v[len - 1] == ' ') len--;
        if (len > 0 && !(len >= elen && strncasecmp(v + len - elen, exe, elen) == 0 &&
                         (len == elen || v[len - elen - 1] == '\\')))
            return false;
        v += len;
        while (*v && *v != ',') v++;
    }
    return true;
}

static const char *const ACCESSIBILITY[] = { "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe",
                                             "displayswitch.exe", "atbroker.exe" };

static bool is_accessibility(const char *exe) {
    for (size_t i = 0; i < sizeof(ACCESSIBILITY) / sizeof(ACCESSIBILITY[0]); i++)
        if (strcasecmp(exe, ACCESSIBILITY[i]) == 0) return true;
    return false;
}

/* Run and RunOnce values below base (the SOFTWARE root, or Software in NTUSER.DAT). */
static void check_run_keys(winboot_scan_result_t *res, const char *hive, const reg_hive_t *h, uint32_t base) {
    static const char *const keys[] = { "Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                                        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                                        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
    char name[128], v[512], reason[96];
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        uint32_t key = key_path(h, base, keys[k]);
        for (uint32_t i = 0; key && reg_hive_value_name_at(h, key, i, name, sizeof(name)); i++) {
            const char *why = reg_hive_string(h, key, name, v, sizeof(v)) ? suspect_command(v) : NULL;
            if (!why) continue;
            snprintf(reason, sizeof(reason), "Run value %.20s %s: %.30s", name, why, v);
            add_rule(res, hive, SEVERITY_MEDIUM, "WIN_RUN_KEY", reason);
        }
    }
}

/* SOFTWARE hive: Winlogon Shell and Userinit, IFEO debuggers, AppInit_DLLs and the machine Run keys. */
static void check_software(winboot_scan_result_t *res, const char *win) {
    char hive[512], v[512], name[256], reason[96];
    if (!ci_path(win, "System32/config/SOFTWARE", hive, sizeof(hive))) return;
    size_t len = 0;
    uint8_t *buf = read_hive(hive, &len);
    reg_hive_t h;
    uint32_t top = 0;
    if (buf && reg_hive_open(buf, len, &h) == BOOTO_OK) top = reg_hive_root(&h);
    if (!top) {
        res->not_checked++;
        free(buf);
        return;
    }
    uint32_t nt = key_path(&h, top, "Microsoft\\Windows NT\\CurrentVersion");
    uint32_t wl = reg_hive_subkey(&h, nt, "Winlogon");
    if (reg_hive_string(&h, wl, "Shell", v, sizeof(v)) && !only_entries(v, "explorer.exe")) {
        snprintf(reason, sizeof(reason), "Winlogon Shell is %.55s, not explorer.exe", v);
        add_rule(res, hive, SEVERITY_HIGH, "WIN_WINLOGON_SHELL", reason);
    }
    if (reg_hive_string(&h, wl, "Userinit", v, sizeof(v)) && !only_entries(v, "userinit.exe")) {
        snprintf(reason, sizeof(reason), "Winlogon Userinit also runs: %.60s", v);
        add_rule(res, hive, SEVERITY_HIGH, "WIN_WINLOGON_USERINIT", reason);
    }
    uint32_t ifeo = reg_hive_subkey(&h, nt, "Image File Execution Options"), sub;
    for (uint32_t i = 0; ifeo && (sub = reg_hive_subkey_at(&h, ifeo, i, name, sizeof(name))) != 0; i++) {
        if (!reg_hive_string(&h, sub, "Debugger", v, sizeof(v)) || !v[0]) continue;
        bool acc = is_accessibility(name);
        snprintf(reason, sizeof(reason), "IFEO starts %.45s instead of %.24s", v, name);
        add_rule(res, hive, acc ? SEVERITY_CRITICAL : SEVERITY_MEDIUM, acc ? "WIN_IFEO_ACCESSIBILITY" : "WIN_IFEO_DEBUGGER",
                 reason);
    }
    static const char *const appinit[] = { "Microsoft\\Windows NT\\CurrentVersion\\Windows",
                                           "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" };
    for (size_t k = 0; k < 2; k++) {
        uint32_t wk = key_path(&h, top, appinit[k]), load = 0;
        if (reg_hive_dword(&h, wk, "LoadAppInit_DLLs", &load) && load &&
            reg_hive_string(&h, wk, "AppInit_DLLs", v, sizeof(v)) && v[0]) {
            snprintf(reason, sizeof(reason), "AppInit_DLLs loads %.50s into every GUI process", v);
            add_rule(res, hive, SEVERITY_HIGH, "WIN_APPINIT_DLLS", reason);
        }
    }
    check_run_keys(res, hive, &h, top);
    free(buf);
}

/* Sticky keys backdoor: an accessibility program replaced by a copy of a shell, run from the logon screen. */
static void check_accessibility(winboot_scan_result_t *res, const char *s32) {
    static const char *const shells[] = { "cmd.exe", "WindowsPowerShell/v1.0/powershell.exe", "taskmgr.exe" };
    char hashes[3][65] = { "", "", "" }, path[512], hex[65], reason[96];
    for (size_t i = 0; i < 3; i++)
        if (!ci_path(s32, shells[i], path, sizeof(path)) || !sha256_file_hex(path, hashes[i])) hashes[i][0] = '\0';
    for (size_t a = 0; a < sizeof(ACCESSIBILITY) / sizeof(ACCESSIBILITY[0]); a++) {
        if (!ci_path(s32, ACCESSIBILITY[a], path, sizeof(path)) || !sha256_file_hex(path, hex)) continue;
        for (size_t i = 0; i < 3; i++) {
            if (!hashes[i][0] || strcmp(hex, hashes[i]) != 0) continue;
            snprintf(reason, sizeof(reason), "%.20s is a copy of %.40s: logon-screen shell", ACCESSIBILITY[a],
                     shells[i]);
            add_rule(res, path, SEVERITY_CRITICAL, "WIN_ACCESSIBILITY_SWAP", reason);
            break;
        }
    }
}

static bool ext_in(const char *ext, const char *const *list, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcasecmp(ext, list[i]) == 0) return true;
    return false;
}

/* Programs and scripts in a Startup folder run at every logon; shortcuts (.lnk) are normal there. */
static void check_startup(winboot_scan_result_t *res, const char *dir) {
    static const char *const run[] = { "exe", "bat", "cmd", "vbs", "vbe", "js", "jse", "ps1", "hta", "scr", "wsf", "pif" };
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    char path[800], reason[96];
    struct stat st;
    while ((de = readdir(d)) != NULL) {
        const char *dot = strrchr(de->d_name, '.');
        snprintf(path, sizeof(path), "%.500s/%.250s", dir, de->d_name);
        if (!dot || !ext_in(dot + 1, run, sizeof(run) / sizeof(run[0])) || lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        snprintf(reason, sizeof(reason), "Startup folder runs %.60s at logon", de->d_name);
        add_rule(res, path, SEVERITY_MEDIUM, "WIN_STARTUP_FILE", reason);
    }
    closedir(d);
}

#define RANSOM_NOTE_MAX (256u << 10)
#define RANSOM_MIN_FILES 10
#define RANSOM_MAX_EXTS 16

/* The note names a Tor .onion site, in ASCII or UTF-16LE. */
static bool note_has_onion(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    uint8_t *buf = malloc(RANSOM_NOTE_MAX);
    size_t len = buf ? fread(buf, 1, RANSOM_NOTE_MAX, fp) : 0;
    fclose(fp);
    bool hit = false;
    static const char onion[] = ".onion";
    for (size_t i = 0; buf && !hit && i + 12 <= len; i++) {
        bool a = true, w = true;
        for (size_t j = 0; j < 6 && (a || w); j++) {
            a = a && tolower(buf[i + j]) == onion[j];
            w = w && tolower(buf[i + 2 * j]) == onion[j] && buf[i + 2 * j + 1] == 0;
        }
        hit = a || w;
    }
    free(buf);
    return hit;
}

/* One folder, not recursive: a ransom note, and many files renamed to <name>.<document type>.<new extension>.
 * shortcut: top level of the usual user folders only; a walk of the whole profile when that proves too narrow. */
static void check_ransom_dir(winboot_scan_result_t *res, const char *dir) {
    static const char *const docs[] = { "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "jpg", "jpeg", "png", "txt",
                                        "csv", "rtf", "odt", "zip", "mp4", "mp3", "sql", "db" };
    static const char *const benign[] = { "lnk", "tmp", "bak", "old", "orig", "part", "crdownload", "download", "url",
                                          "sig", "asc", "gpg", "sha256", "md5", "7z", "gz", "rar", "xz", "ini" };
    static const char *const note_words[] = { "decrypt", "restore", "recover", "ransom", "readme", "read_me", "how_to",
                                              "how-to", "unlock" };
    static const char *const note_ext[] = { "txt", "html", "htm", "hta" };
    DIR *d = opendir(dir);
    if (!d) return;
    char exts[RANSOM_MAX_EXTS][25];
    int counts[RANSOM_MAX_EXTS] = {0}, nexts = 0;
    char path[800], lc[256], reason[96];
    struct stat st;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        snprintf(path, sizeof(path), "%.500s/%.250s", dir, de->d_name);
        if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        size_t i = 0;
        for (; de->d_name[i] && i + 1 < sizeof(lc); i++) lc[i] = (char)tolower((unsigned char)de->d_name[i]);
        lc[i] = '\0';
        char *ext2 = strrchr(lc, '.');
        if (!ext2) continue;
        bool word = false;
        for (size_t w = 0; w < sizeof(note_words) / sizeof(note_words[0]) && !word; w++) word = strstr(lc, note_words[w]);
        if (word && (uint64_t)st.st_size <= RANSOM_NOTE_MAX && ext_in(ext2 + 1, note_ext, 4) && note_has_onion(path)) {
            snprintf(reason, sizeof(reason), "ransom note %.50s names a Tor .onion site", de->d_name);
            add_rule(res, path, SEVERITY_HIGH, "WIN_RANSOM_NOTE", reason);
            continue;
        }
        *ext2 = '\0';
        char *inner = strrchr(lc, '.');
        size_t elen = strlen(ext2 + 1);
        if (!inner || elen < 2 || elen > 24 || !ext_in(inner + 1, docs, sizeof(docs) / sizeof(docs[0])) ||
            ext_in(ext2 + 1, docs, sizeof(docs) / sizeof(docs[0])) || ext_in(ext2 + 1, benign, sizeof(benign) / sizeof(benign[0])))
            continue;
        int e = 0;
        while (e < nexts && strcmp(exts[e], ext2 + 1) != 0) e++;
        if (e == nexts && nexts < RANSOM_MAX_EXTS) snprintf(exts[nexts++], sizeof(exts[0]), "%s", ext2 + 1);
        if (e < nexts) counts[e]++;
    }
    closedir(d);
    for (int e = 0; e < nexts; e++) {
        if (counts[e] < RANSOM_MIN_FILES) continue;
        snprintf(reason, sizeof(reason), "%d documents renamed to <name>.<type>.%.20s, as ransomware does", counts[e], exts[e]);
        add_rule(res, dir, SEVERITY_HIGH, "WIN_RANSOM_ENCRYPTED", reason);
    }
}

/* Per profile: NTUSER.DAT Run keys, the Startup folder, and ransomware signs in the usual folders. */
static void check_users(winboot_scan_result_t *res, const char *root) {
    char users[512], prof[800], path[800];
    if (!ci_child(root, "Users", users, sizeof(users))) return;
    DIR *d = opendir(users);
    if (!d) return;
    struct dirent *de;
    struct stat st;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(prof, sizeof(prof), "%.500s/%.250s", users, de->d_name);
        if (lstat(prof, &st) != 0 || !S_ISDIR(st.st_mode)) continue;  // "All Users" and "Default User" are links
        if (ci_path(prof, "NTUSER.DAT", path, sizeof(path))) {
            size_t len = 0;
            uint8_t *buf = read_hive(path, &len);
            reg_hive_t h;
            uint32_t top = 0;
            if (buf && reg_hive_open(buf, len, &h) == BOOTO_OK && (top = reg_hive_root(&h)) != 0)
                check_run_keys(res, path, &h, reg_hive_subkey(&h, top, "Software"));
            free(buf);
        }
        if (ci_dir(prof, "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", path, sizeof(path)))
            check_startup(res, path);
        static const char *const folders[] = { "Desktop", "Documents", "Pictures", "Downloads" };
        for (size_t f = 0; f < 4; f++)
            if (ci_dir(prof, folders[f], path, sizeof(path))) check_ransom_dir(res, path);
    }
    closedir(d);
}

booto_error_t winboot_scan_rootfs(const char *root, winboot_scan_result_t *res) {
    if (!root || !res) return BOOTO_ERR_INVALID_ARG;
    memset(res, 0, sizeof(*res));
    char s32[512], path[512];
    if (!system32(root, s32, sizeof(s32))) return BOOTO_ERR_NOT_FOUND;
    booto_error_t rules_err = yara_rules_status();
    if (rules_err != BOOTO_OK) return rules_err;

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
    if (ci_child(root, "Windows", win, sizeof(win))) {
        check_boot_start(res, root, win, drv);
        check_software(res, win);
    }
    check_accessibility(res, s32);
    char dir[512];
    if (ci_dir(root, "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp", dir, sizeof(dir))) check_startup(res, dir);
    check_users(res, root);
    check_ransom_dir(res, root);
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
