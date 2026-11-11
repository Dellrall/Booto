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
#include "yara_scan.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void add_threat_finding(kernel_scan_result_t *result,
                               const char *threat_name,
                               const char *file_path,
                               const char *sha256,
                               const char *rule_id,
                               const char *matched_sym,
                               uint64_t offset,
                               booto_severity_t severity,
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
                 booto_severity_str(f->severity));
}

#define LKM_DECOMP_CAP ((size_t)256 * 1024 * 1024)
#define LKM_PACKED_CAP ((size_t)64 * 1024 * 1024)

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

/* scripts/sign-file appends the PKCS#7 blob, a module_signature struct, then this marker. */
#define LKM_SIG_MAGIC "~Module signature appended~\n"
#define LKM_SIG_MAGIC_LEN (sizeof(LKM_SIG_MAGIC) - 1)
#define LKM_UNSIGNED_CAP 32

/* The marker alone proves nothing: anyone can append it. Before it must sit a module_signature struct
 * (algo, hash, id_type, signer_len, key_id_len, pad[3], be32 sig_len) and a DER blob of exactly sig_len bytes.
 * shortcut: the signature is not verified against the kernel's keys (they live inside vmlinuz); add when
 * Booto extracts the builtin keyring. */
#define LKM_SIG_INFO_LEN 12
static bool lkm_tail_signed(const uint8_t *buf, size_t len) {
    static const uint8_t pkcs7_info[8] = { 0, 0, 2 /* PKEY_ID_PKCS7 */, 0, 0, 0, 0, 0 };
    if (len < LKM_SIG_MAGIC_LEN + LKM_SIG_INFO_LEN ||
        memcmp(buf + len - LKM_SIG_MAGIC_LEN, LKM_SIG_MAGIC, LKM_SIG_MAGIC_LEN) != 0) {
        return false;
    }
    const uint8_t *info = buf + len - LKM_SIG_MAGIC_LEN - LKM_SIG_INFO_LEN;
    size_t sig_len = ((size_t)info[8] << 24) | ((size_t)info[9] << 16) | ((size_t)info[10] << 8) | info[11];
    if (memcmp(info, pkcs7_info, sizeof(pkcs7_info)) != 0 || sig_len < 6 || sig_len > (size_t)(info - buf)) return false;
    const uint8_t *sig = info - sig_len;
    // DER SEQUENCE whose stated length fills the blob (long form, as every real signature is over 127 bytes).
    size_t n = sig[1] & 0x7f, body = 0;
    if (sig[0] != 0x30 || !(sig[1] & 0x80) || n < 1 || n > 4) return false;
    for (size_t i = 0; i < n; i++) body = (body << 8) | sig[2 + i];
    return 2 + n + body == sig_len;
}

/* shortcut: reads the last 16 KiB; a signature larger than that reads as unsigned. Raise if one is seen. */
static bool lkm_file_signed(const char *path) {
    uint8_t tail[16384];
    FILE *fp = fopen_regular(path);
    if (!fp) return false;
    size_t got = 0;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long size = ftell(fp);
        long start = size > (long)sizeof(tail) ? size - (long)sizeof(tail) : 0;
        if (size > 0 && fseek(fp, start, SEEK_SET) == 0) got = fread(tail, 1, sizeof(tail), fp);
    }
    fclose(fp);
    return lkm_tail_signed(tail, got);
}

/* Directory walk state: unsigned modules are held back until we know whether this kernel signs modules at all. */
typedef struct {
    unsigned missing_tools; /* bitmask over G_LKM_CODECS of decompressors found absent */
    int signed_count;
    int unsigned_count;
    char unsigned_paths[LKM_UNSIGNED_CAP][256];
    char unsigned_sha[LKM_UNSIGNED_CAP][65];
} lkm_walk_t;

static void note_signature(lkm_walk_t *w, const char *path, const char *sha, bool is_signed) {
    if (!w) return;
    if (is_signed) {
        w->signed_count++;
        return;
    }
    if (w->unsigned_count < LKM_UNSIGNED_CAP) {
        snprintf(w->unsigned_paths[w->unsigned_count], sizeof(w->unsigned_paths[0]), "%s", path);
        snprintf(w->unsigned_sha[w->unsigned_count], sizeof(w->unsigned_sha[0]), "%s", sha);
    }
    w->unsigned_count++;
}

/* Signed YARA rules over the module's bytes: buf when it was decompressed, else the file itself. */
static void yara_lkm(const char *ko_path, const char *sha256, const uint8_t *buf, size_t len, kernel_scan_result_t *result) {
    yara_match_t m[YARA_MAX_MATCHES];
    int n = 0;
    if (buf) yara_scan_buffer(buf, len, m, YARA_MAX_MATCHES, &n);
    else yara_scan_file(ko_path, m, YARA_MAX_MATCHES, &n);
    for (int i = 0; i < n; i++)
        add_threat_finding(result, "YARA Rule Match", ko_path, sha256, m[i].rule, "", 0, m[i].severity, m[i].description);
}

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
                                   (booto_severity_t)rules_severity_level(rule->severity),
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

static booto_error_t inspect_lkm_file(const char *ko_path, kernel_scan_result_t *result, lkm_walk_t *w) {

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
    note_signature(w, ko_path, elf.sha256, lkm_file_signed(ko_path));
    yara_lkm(ko_path, elf.sha256, NULL, 0, result);
    analyze_lkm(ko_path, rules, &elf, result);
    return BOOTO_OK;
}

booto_error_t kernel_inspect_lkm_file(const char *ko_path, kernel_scan_result_t *result) {
    if (!ko_path || !result) return BOOTO_ERR_INVALID_ARG;
    return inspect_lkm_file(ko_path, result, NULL);
}

/* Decompress a .ko.{xz,zst,gz} via the external tool and run the same ELF checks on the buffer. */
static booto_error_t inspect_compressed_lkm(const char *ko_path, const lkm_codec_t *codec, kernel_scan_result_t *result,
                                           lkm_walk_t *w) {
    const rules_lkm_set_t *rules;
    booto_error_t err = rules_get_lkm(&rules);
    if (err != BOOTO_OK) return err;

    result->modules_scanned++;

    /* Read here and pipe it in: the sandboxed decompressor runs as nobody and could not open a 0600 module. */
    FILE *fp = fopen_regular(ko_path);
    if (!fp) {
        LOG_WARN("Could not open kernel module '%s'", ko_path);
        return BOOTO_ERR_IO;
    }
    uint8_t *packed = malloc(LKM_PACKED_CAP + 1);
    size_t packed_len = packed ? fread(packed, 1, LKM_PACKED_CAP + 1, fp) : 0;
    bool read_failed = !packed || ferror(fp) || packed_len > LKM_PACKED_CAP;
    fclose(fp);
    if (read_failed) {
        free(packed);
        LOG_WARN("Could not read kernel module '%s' (missing, unreadable or over %zu bytes)", ko_path, LKM_PACKED_CAP);
        return packed ? BOOTO_ERR_IO : BOOTO_ERR_OUT_OF_MEMORY;
    }

    const char *const argv[] = {codec->tool, "-dc", NULL};
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    err = disk_exec_capture(argv, packed, packed_len, &raw, &raw_len, LKM_DECOMP_CAP);
    free(packed);
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
    bool is_signed = raw && lkm_tail_signed(raw, raw_len);
    if (err == BOOTO_OK) yara_lkm(ko_path, elf.sha256, raw, raw_len, result);
    free(raw);
    if (err != BOOTO_OK) {
        LOG_WARN("Could not parse decompressed ELF binary '%s' (err: %d)", ko_path, err);
        return err;
    }
    snprintf(elf.file_path, sizeof(elf.file_path), "%s", ko_path);
    note_signature(w, ko_path, elf.sha256, is_signed);
    analyze_lkm(ko_path, rules, &elf, result);
    return BOOTO_OK;
}

static void scan_dir_recursive(const char *base_path, kernel_scan_result_t *result, int depth, lkm_walk_t *w) {
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
        // lstat first: never descend a symlinked directory, which can point outside the target.
        if (lstat(full_path, &st) == 0 && (!S_ISLNK(st.st_mode) || (stat(full_path, &st) == 0 && !S_ISDIR(st.st_mode)))) {
            if (S_ISDIR(st.st_mode)) {
                scan_dir_recursive(full_path, result, depth + 1, w);
            } else if (S_ISREG(st.st_mode)) {
                size_t nlen = strlen(entry->d_name);
                if (nlen > 3 && strcmp(entry->d_name + nlen - 3, ".ko") == 0) {
                    inspect_lkm_file(full_path, result, w);
                    continue;
                }
                for (size_t c = 0; c < LKM_CODEC_COUNT; c++) {
                    size_t slen = strlen(G_LKM_CODECS[c].suffix);
                    if (nlen <= slen || strcmp(entry->d_name + nlen - slen, G_LKM_CODECS[c].suffix) != 0) continue;
                    if (!(w->missing_tools & (1U << c)) &&
                        inspect_compressed_lkm(full_path, &G_LKM_CODECS[c], result, w) == BOOTO_ERR_NOT_FOUND) {
                        w->missing_tools |= 1U << c;
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
    if (err == BOOTO_OK) err = yara_rules_status();
    if (err != BOOTO_OK) return err;

    LOG_INFO("Scanning kernel modules in directory: %s", lib_modules_dir);
    lkm_walk_t *w = calloc(1, sizeof(*w));
    if (!w) return BOOTO_ERR_OUT_OF_MEMORY;
    scan_dir_recursive(lib_modules_dir, result, 0, w);

    /* A kernel that signs its modules (every distro kernel) never ships an unsigned one; a self-built kernel signs none. */
    if (w->signed_count > 0) {
        int shown = w->unsigned_count < LKM_UNSIGNED_CAP ? w->unsigned_count : LKM_UNSIGNED_CAP;
        for (int i = 0; i < shown; i++) {
            add_threat_finding(result, "Unsigned Kernel Module", w->unsigned_paths[i], w->unsigned_sha[i], "LKM_UNSIGNED",
                               "", 0, SEVERITY_HIGH,
                               "Module has no signature while the kernel's own modules are signed: added after install "
                               "(rootkit, or a DKMS driver built without the MOK key)");
        }
        if (w->unsigned_count > shown) {
            LOG_WARN("%d more unsigned kernel modules not listed", w->unsigned_count - shown);
        }
    }
    unsigned missing_tools = w->missing_tools;
    free(w);

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
