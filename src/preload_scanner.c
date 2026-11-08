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
#include "rules_loader.h"

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

static bool is_temp_path(const char *s) {
    return strstr(s, "/tmp") || strstr(s, "/dev/shm") || strstr(s, "/var/tmp");
}

static bool is_suspicious_path(const char *s) {
    return is_temp_path(s) || strstr(s, "/.");
}

// A program run from a temp dir or a hidden (dot) path; prefixes, so /usr/sbin/tmpwatch is not a temp path.
static bool is_suspicious_program(const char *p) {
    return strncmp(p, "/tmp/", 5) == 0 || strncmp(p, "/var/tmp/", 9) == 0 || strncmp(p, "/dev/shm/", 9) == 0 ||
           strstr(p, "/.");
}

// curl/wget/base64 output piped into a shell: the code that runs is fetched or unpacked at run time, never on disk.
static bool runs_hidden_code(const char *s) {
    if (!strstr(s, "curl") && !strstr(s, "wget") && !strstr(s, "base64")) return false;
    for (const char *p = strchr(s, '|'); p; p = strchr(p + 1, '|')) {
        const char *q = p + 1;
        while (*q == ' ') q++;
        if (strncmp(q, "/usr", 4) == 0) q += 4;
        if (strncmp(q, "/bin/", 5) == 0) q += 5;
        size_t n = strncmp(q, "bash", 4) == 0 ? 4 : strncmp(q, "dash", 4) == 0 ? 4 : strncmp(q, "sh", 2) == 0 ? 2 : 0;
        if (n && !isalnum((unsigned char)q[n])) return true;
    }
    return false;
}

typedef void (*conf_line_fn)(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result);

// Feeds every non-comment line (leading space trimmed, newline cut) of each <rootfs><rel_dir>/*<suffix> file to fn.
static void scan_conf_dir(const char *rootfs, const char *rel_dir, const char *suffix, conf_line_fn fn,
                          preload_scan_result_t *result) {
    char conf_dir[512];
    snprintf(conf_dir, sizeof(conf_dir), "%.400s%s", rootfs, rel_dir);

    // Merged-/usr roots symlink /lib to usr/lib; walking both would report every hook twice.
    char lib[512];
    struct stat st;
    snprintf(lib, sizeof(lib), "%.400s/lib", rootfs);
    if (strncmp(rel_dir, "/lib/", 5) == 0 && lstat(lib, &st) == 0 && S_ISLNK(st.st_mode)) return;

    DIR *dir = opendir(conf_dir);
    if (!dir) return;

    size_t suffix_len = strlen(suffix);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (entry->d_name[0] == '.' && (name_len == 1 || strcmp(entry->d_name, "..") == 0)) continue;
        if (name_len < suffix_len || strcmp(entry->d_name + name_len - suffix_len, suffix) != 0) continue;

        char full_file[1024];
        snprintf(full_file, sizeof(full_file), "%.500s/%.255s", conf_dir, entry->d_name);

        FILE *fp = fopen(full_file, "r");
        if (!fp) continue;

        result->files_scanned++;
        char line[1024];
        // shortcut: a line over 1023 bytes is read as two lines and backslash continuations are not joined; fine for hand-written hooks.
        while (fgets(line, sizeof(line), fp)) {
            char *ptr = line;
            while (*ptr && isspace((unsigned char)*ptr)) ptr++;
            ptr[strcspn(ptr, "\r\n")] = '\0';
            if (*ptr == '#' || *ptr == '\0') continue;
            fn(rootfs, full_file, ptr, result);
        }
        fclose(fp);
    }
    closedir(dir);
}

static void ld_conf_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    (void)rootfs;
    if (is_suspicious_path(line)) {
        add_preload_threat(result, file, "Suspicious Dynamic Linker Path", line, "", "PRELOAD_SUSPICIOUS_CONF_PATH",
                           "ld.so.conf references temporary or hidden directory for library resolution");
    }
}

// Copies the first whitespace-delimited token of s into out and returns its basename.
static const char *first_program(const char *s, char *out, size_t out_len) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strcspn(s, " \t;&|");
    if (n >= out_len) n = out_len - 1;
    memcpy(out, s, n);
    out[n] = '\0';
    const char *slash = strrchr(out, '/');
    return slash ? slash + 1 : out;
}

static void report_program(const char *rootfs, const char *file, const char *program, const char *threat_name,
                           const char *rule_id, const char *description, preload_scan_result_t *result) {
    char full[1024];
    snprintf(full, sizeof(full), "%.700s%s%.300s", rootfs, program[0] == '/' ? "" : "/", program);
    char sha256[65] = "0000000000000000000000000000000000000000000000000000000000000000";
    if (program[0]) sha256_file_hex(full, sha256);
    add_preload_threat(result, file, threat_name, program, sha256, rule_id, description);
}

// Copies the first absolute path in s (the program a hook runs) into out; empty when there is none.
static void first_abs_path(const char *s, char *out, size_t out_len) {
    const char *p = s;
    while ((p = strchr(p, '/')) && ((p != s && !strchr(" \t\"'=-@+!:", p[-1])) || p[1] == '/'))
        p += p[1] == '/' ? 2 : 1;  // "//" is a URL (curl http://x/a), not a program path
    out[0] = '\0';
    if (p) first_program(p, out, out_len);
}

// Reports cmd when the program it runs lives in a temp/hidden path or it pipes fetched code into a shell.
// Only the program is path-checked: vendor units and cron jobs pass /tmp as an argument all the time.
static void check_command(const char *rootfs, const char *file, const char *cmd, const char *threat_name,
                          const char *rule_id, const char *description, preload_scan_result_t *result) {
    char program[256];
    first_abs_path(cmd, program, sizeof(program));
    if (is_suspicious_program(program) || runs_hidden_code(cmd))
        report_program(rootfs, file, program, threat_name, rule_id, description, result);
}

// ExecStart=/ExecStartPre=/... run as the unit's user (root by default) at boot or on activation.
static void systemd_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    const char *eq = strchr(line, '=');
    if (strncmp(line, "Exec", 4) == 0 && eq)
        check_command(rootfs, file, eq + 1, "systemd Unit Execution Hook", "PERSIST_SYSTEMD_EXEC",
                      "systemd unit runs a temp/hidden-path program or fetched code", result);
}

static void cron_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    check_command(rootfs, file, line, "Scheduled Task Hook", "PERSIST_CRON",
                  "cron job or boot script runs a temp/hidden-path program or fetched code", result);
}

// Profiles source dotfiles and set TMPDIR=/tmp all the time: only a line that starts by running a temp-path
// program, fetched code, or LD_PRELOAD counts.
static void profile_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    const char *p = line;
    static const char *const lead[] = { ". ", "source ", "nohup ", "exec " };
    for (size_t i = 0; i < sizeof(lead) / sizeof(lead[0]); i++)
        if (strncmp(p, lead[i], strlen(lead[i])) == 0) p += strlen(lead[i]);
    char program[256];
    first_program(p, program, sizeof(program));
    /* Temp dirs only: profiles source dotfiles (~/.cargo/env) all the time. */
    bool temp = strncmp(program, "/tmp/", 5) == 0 || strncmp(program, "/var/tmp/", 9) == 0 ||
                strncmp(program, "/dev/shm/", 9) == 0;
    if (!temp && !runs_hidden_code(line) && !strstr(line, "LD_PRELOAD")) return;
    first_abs_path(p, program, sizeof(program));
    report_program(rootfs, file, program, "Shell Login Hook", "PERSIST_SHELL_PROFILE",
                   "shell profile runs a temp-path program, fetched code or sets LD_PRELOAD on every login", result);
}

// command="..." forces a program on every login with that key: a backdoor when it runs from temp or fetches code.
static void ssh_key_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    const char *cmd = strstr(line, "command=\"");
    if (!cmd) return;
    char value[512];
    snprintf(value, sizeof(value), "%.*s", (int)strcspn(cmd + 9, "\""), cmd + 9);  /* not the key's base64 */
    check_command(rootfs, file, value, "SSH Forced Command", "PERSIST_SSH_FORCED_COMMAND",
                      "authorized_keys entry forces a temp/hidden-path program or fetched code on login", result);
}

// Per-user dotfiles; entries must be real directories so a planted /home/x -> / symlink cannot reach the live system.
static void scan_homes(const char *rootfs, preload_scan_result_t *result) {
    char home[512];
    snprintf(home, sizeof(home), "%.400s/home", rootfs);
    DIR *dir = opendir(home);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' || entry->d_type != DT_DIR) continue;
        char rel[300];
        snprintf(rel, sizeof(rel), "/home/%.255s", entry->d_name);
        scan_conf_dir(rootfs, rel, "bashrc", profile_line, result);
        scan_conf_dir(rootfs, rel, "profile", profile_line, result);
        snprintf(rel, sizeof(rel), "/home/%.255s/.ssh", entry->d_name);
        scan_conf_dir(rootfs, rel, "authorized_keys", ssh_key_line, result);
    }
    closedir(dir);
}

// "install <module> <command>" runs <command> as root whenever the module is requested. Distros only use it to
// blacklist (true/false) or chain modprobe calls; anything else, or a temp/hidden path anywhere, is a hook.
static void modprobe_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    if (strncmp(line, "install", 7) != 0 || !isspace((unsigned char)line[7])) return;
    const char *p = line + 7;
    while (*p && isspace((unsigned char)*p)) p++;
    while (*p && !isspace((unsigned char)*p)) p++; // module name
    char program[256];
    const char *base = first_program(p, program, sizeof(program));
    if (!program[0]) return;
    bool benign = strcmp(base, "true") == 0 || strcmp(base, "false") == 0 || strcmp(base, "modprobe") == 0;
    if (benign && !is_suspicious_path(p)) return;
    report_program(rootfs, file, program, "Kernel Module Load Hook", "PERSIST_MODPROBE_INSTALL",
                   "modprobe.d install directive runs a non-modprobe command as root on every module load", result);
}

// RUN+="..." / RUN{program}+="..." executes as root on every matching device event.
static void udev_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result,
                      bool admin_dir) {
    for (const char *p = strstr(line, "RUN"); p; p = strstr(p + 3, "RUN")) {
        const char *q = p + 3;
        if (*q == '{') q = strchr(q, '}') ? strchr(q, '}') + 1 : q;
        while (*q == ' ') q++;
        if (*q == '+') q++;
        if (*q != '=' || q[1] == '=') continue;
        q++;
        while (*q == ' ') q++;
        if (*q != '"') continue;
        q++;
        const char *end = strchr(q, '"');
        size_t len = end ? (size_t)(end - q) : strlen(q);
        char value[512];
        snprintf(value, sizeof(value), "%.*s", (int)(len < sizeof(value) - 1 ? len : sizeof(value) - 1), q);

        char program[256];
        const char *base = first_program(value, program, sizeof(program));
        bool shell = strcmp(base, "sh") == 0 || strcmp(base, "bash") == 0 || strcmp(base, "dash") == 0;
        // Shipped rules (/usr/lib) do use "sh -c"; an admin-dir rule doing so is how sedexp-style droppers persist.
        if (is_suspicious_path(value) || (admin_dir && shell && strstr(value, " -c"))) {
            report_program(rootfs, file, program, "udev Event Execution Hook", "PERSIST_UDEV_RUN",
                           "udev rule runs a shell or a temp/hidden-path program as root on device events", result);
        }
    }
}

static void udev_admin_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    udev_line(rootfs, file, line, result, true);
}

static void udev_vendor_line(const char *rootfs, const char *file, const char *line, preload_scan_result_t *result) {
    udev_line(rootfs, file, line, result, false);
}

/* Known rootkit install paths; lstat so a planted symlink is reported, never followed out of the target root. */
static booto_error_t scan_file_iocs(const char *rootfs, preload_scan_result_t *result) {
    const rules_ioc_set_t *iocs = NULL;
    booto_error_t err = rules_get_ioc(&iocs);
    if (err != BOOTO_OK) {
        LOG_ERROR("Rootkit file indicators unavailable (err: %d); known install paths not checked", err);
        return err;
    }
    for (int i = 0; i < iocs->count; i++) {
        const rules_ioc_entry_t *e = &iocs->entries[i];
        for (int j = 0; j < e->path_count; j++) {
            char full[1024];
            snprintf(full, sizeof(full), "%.700s%.200s", rootfs, e->paths[j]);
            struct stat st;
            if (lstat(full, &st) != 0) continue;
            char sha256[65] = "0000000000000000000000000000000000000000000000000000000000000000";
            if (S_ISREG(st.st_mode)) sha256_file_hex(full, sha256);
            add_preload_threat(result, full, e->name, S_ISREG(st.st_mode) ? e->paths[j] : "", sha256, e->rule_id,
                               e->description);
        }
    }
    return BOOTO_OK;
}

booto_error_t preload_scan_rootfs(const char *target_rootfs, preload_scan_result_t *result) {
    if (!target_rootfs || !result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    LOG_INFO("Scanning userland preload configurations in rootfs: %s", target_rootfs);

    booto_error_t err = scan_ld_so_preload(target_rootfs, result);
    booto_error_t env_err = scan_environment(target_rootfs, result);
    scan_conf_dir(target_rootfs, "/etc/ld.so.conf.d", "", ld_conf_line, result);
    static const char *const modprobe_dirs[] = { "/etc/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d",
                                                 "/run/modprobe.d" };
    for (size_t i = 0; i < sizeof(modprobe_dirs) / sizeof(modprobe_dirs[0]); i++)
        scan_conf_dir(target_rootfs, modprobe_dirs[i], ".conf", modprobe_line, result);
    scan_conf_dir(target_rootfs, "/etc/udev/rules.d", ".rules", udev_admin_line, result);
    scan_conf_dir(target_rootfs, "/usr/lib/udev/rules.d", ".rules", udev_vendor_line, result);
    scan_conf_dir(target_rootfs, "/lib/udev/rules.d", ".rules", udev_vendor_line, result);
    static const char *const unit_dirs[] = { "/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system" };
    for (size_t i = 0; i < sizeof(unit_dirs) / sizeof(unit_dirs[0]); i++)
        scan_conf_dir(target_rootfs, unit_dirs[i], ".service", systemd_line, result);
    static const char *const cron_dirs[] = { "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                                             "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs" };
    for (size_t i = 0; i < sizeof(cron_dirs) / sizeof(cron_dirs[0]); i++)
        scan_conf_dir(target_rootfs, cron_dirs[i], "", cron_line, result);
    scan_conf_dir(target_rootfs, "/etc", "crontab", cron_line, result);   /* crontab and anacrontab */
    scan_conf_dir(target_rootfs, "/etc", "rc.local", cron_line, result);
    scan_conf_dir(target_rootfs, "/etc/profile.d", ".sh", profile_line, result);
    scan_conf_dir(target_rootfs, "/etc", "bashrc", profile_line, result);  /* bash.bashrc, bashrc */
    scan_conf_dir(target_rootfs, "/etc", "profile", profile_line, result);
    scan_conf_dir(target_rootfs, "/root", "bashrc", profile_line, result);
    scan_conf_dir(target_rootfs, "/root", "profile", profile_line, result);
    scan_conf_dir(target_rootfs, "/root/.ssh", "authorized_keys", ssh_key_line, result);
    scan_homes(target_rootfs, result);
    booto_error_t ioc_err = scan_file_iocs(target_rootfs, result);
    if (err == BOOTO_OK) err = env_err;
    if (err == BOOTO_OK) err = ioc_err;

    LOG_INFO("Preload scanner complete: %d config files audited, %d userland threats flagged",
             result->files_scanned, result->threats_detected);
    return err;
}
