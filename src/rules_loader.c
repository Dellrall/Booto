/**
 * @file rules_loader.c
 * @brief Sealed JSON rules loader (strict bounded JSON reader) with built-in fallback tables.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "rules_loader.h"
#include "crypto_utils.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define DBX_FILE "uefi_dbx_revocations.json"
#define LKM_FILE "lkm_rootkit_signatures.json"
#define MBR_FILE "mbr_bootkit_signatures.json"

#define JSON_MAX_DEPTH 16
#define RULES_MAX_FILE_BYTES (1024U * 1024U)
#define SEAL_MAX_FILE_BYTES 4096U

/* ========================================================================== */
/* Built-in tables (canonical content; the rules JSON files mirror them)      */
/* ========================================================================== */

typedef struct {
    const char *sha256;
    const char *threat;
    const char *cve;
    const char *severity;
    const char *description;
} builtin_dbx_t;

static const builtin_dbx_t G_BUILTIN_DBX[] = {
    // 1. BlackLotus UEFI Bootkit Revocations
    { "0c644d57c79e614066929a008c2a382d5e305e9e03d42c38848d7c4dbfc78f24",
      "BlackLotus Revoked Windows Bootloader", "CVE-2022-21894", "CRITICAL",
      "Vulnerable Windows EFI boot manager exploited by BlackLotus UEFI bootkit to bypass Secure Boot" },
    { "80b4d96931bf0d02fd91a61e19d14f1da452e66db2408ca44b83993b36a49f63",
      "BlackLotus Batched EFI Payload", "CVE-2023-24932", "CRITICAL",
      "BlackLotus second-stage kernel hijacker payload deployed into ESP" },

    // 2. BootHole GRUB2 Vulnerability Hashes
    { "cb078e4726b008d51624c96ea208d249f3e498c8793b890916d7a46abf1d4f9b",
      "BootHole Vulnerable GRUB2 Binary", "CVE-2020-10713", "HIGH",
      "Revoked GRUB2 EFI executable vulnerable to heap-overflow buffer execution in grub.cfg parser" },

    // 3. ESPecter UEFI Bootkit
    { "5f8a3562a63200dc8ba79198642738a9d9e4a3b17728f3a9e0123ef89a12c451",
      "ESPecter UEFI Bootloader Implant", "ESPecter", "CRITICAL",
      "ESPecter bootkit persistence module hidden in the EFI partition" },

    // 4. MoonBounce / CosmicStrand Firmware-to-ESP Stage
    { "a849201bc93ef4a890123ef9a82bc128912ef349a128901bc3412ef89018f4b2",
      "MoonBounce Stage-2 Bootloader", "MoonBounce", "CRITICAL",
      "Stage-2 OS-loader interceptor deploying memory implants from ESP" }
};

typedef struct {
    const char *symbol;
    const char *rule_id;
    const char *name;
    const char *severity;
    const char *description;
} builtin_lkm_t;

static const builtin_lkm_t G_BUILTIN_LKM[] = {
    // 1. Syscall Table Manipulation
    { "sys_call_table",      "LKM_HOOK_SYS_CALL_TABLE", "Syscall Table Hooking",
      "CRITICAL", "Direct reference or modification to the kernel sys_call_table" },
    { "kallsyms_lookup_name","LKM_KALLSYMS_LOOKUP",     "Dynamic Kernel Symbol Resolution",
      "MEDIUM",   "Resolves unexported kernel symbols at runtime (used for syscall hooking)" },

    // 2. Diamorphine & Derivatives
    { "diamorphine",         "LKM_DIAMORPHINE_CORE",    "Diamorphine Rootkit",
      "CRITICAL", "Matches Diamorphine rootkit core symbol signatures" },
    { "hacked_kill",         "LKM_HOOK_KILL",           "Kill Syscall Interceptor",
      "CRITICAL", "Hooks sys_kill to execute root backdoor signals (e.g. signal 64 root escalation)" },
    { "hacked_getdents",     "LKM_HOOK_GETDENTS",       "Directory Entry Hider",
      "CRITICAL", "Hooks sys_getdents to hide rootkit files and directories from userland" },
    { "hacked_getdents64",   "LKM_HOOK_GETDENTS64",     "Directory Entry Hider (64-bit)",
      "CRITICAL", "Hooks sys_getdents64 to hide rootkit files and directories from userland" },
    { "is_invisible",        "LKM_DKOM_HIDE_MODULE",    "LKM Kernel Object Hiding (DKOM)",
      "CRITICAL", "Unlinks module from the sysfs/lsmod list using Direct Kernel Object Manipulation" },
    { "hide_proc",           "LKM_DKOM_HIDE_PROC",      "Process Hiding Mechanism",
      "CRITICAL", "Hides malicious PID structures from /proc directory walks" },

    // 3. Ftrace / Kprobe Hooking (Reptile / Suterusu / Ftrace Hooks)
    { "fh_install_hook",     "LKM_FTRACE_HOOK_INSTALL", "Ftrace Syscall Hijack",
      "CRITICAL", "Uses Linux ftrace subsystem to redirect kernel execution flow" },
    { "fh_remove_hook",      "LKM_FTRACE_HOOK_REMOVE",  "Ftrace Hook Uninstaller",
      "HIGH",     "Ftrace hook removal routine" },
    { "khook_init",          "LKM_KHOOK_ENGINE",        "Khook In-Kernel Hooking Engine",
      "CRITICAL", "Generic kernel-mode inline function hooking framework" },
    { "rep_hook",            "LKM_REPTILE_HOOK",        "Reptile Rootkit Hook",
      "CRITICAL", "Matches Reptile Linux rootkit network and file hook signatures" },
    { "suterusu",            "LKM_SUTERUSU_SIGNATURE",  "Suterusu Rootkit",
      "CRITICAL", "Matches Suterusu LKM rootkit framework signatures" },

    // 4. Network Packet Interceptors
    { "tcp4_seq_show",       "LKM_NET_PORT_HIDER",      "TCP Network Port Hider",
      "CRITICAL", "Hooks tcp4_seq_show to hide listening reverse shell ports from netstat/ss" },
    { "udp4_seq_show",       "LKM_NET_PORT_HIDER",      "UDP Network Port Hider",
      "CRITICAL", "Hooks udp4_seq_show to hide UDP listening ports" }
};

typedef struct {
    const char *name;
    const char *rule_id;
    const char *target;
    const char *severity;
    bool unknown_bootloader_only;
    const char *description;
    const char *patterns_hex[RULES_MAX_PATTERNS]; /* NULL-terminated */
} builtin_mbr_t;

static const builtin_mbr_t G_BUILTIN_MBR[] = {
    // Rovnix / Carberp: INT 13h hook setup redirecting to hidden sectors
    { "Rovnix / Carberp MBR Bootkit", "MBR_BOOTKIT_ROVNIX", "mbr_bootstrap", "CRITICAL", false,
      "Matches Rovnix/Carberp MBR bootstrap hook redirecting execution to hidden sectors before partition table",
      { "fa33c08ed08ed88ec0bc007c", "fa31c08ed88ed0bc007cfbcd13", NULL } },
    // TDL4 / Mebroot: overwrites INT 13h IVT vector at 0x0000:0x004c
    { "TDL4 / Sinowal (Mebroot) Bootkit", "MBR_BOOTKIT_TDL4_MEBROOT", "mbr_bootstrap", "CRITICAL", false,
      "Intercepts and rewires INT 13h BIOS disk handler to execute rootkit payload from reserved sectors",
      { "31c08ed889164c00", "8cc88ed8a14c00", NULL } },
    // Stoned / Michelangelo: "Your PC is now Stoned!" or relocation to 0x9FC0
    { "Stoned / Legacy MBR Bootkit", "MBR_BOOTKIT_STONED", "mbr_bootstrap", "CRITICAL", false,
      "Classic MBR bootkit hooking INT 13h and relocating original boot sector to high memory (0x9FC0)",
      { "596f7572205043206973206e6f772053746f6e656421", "cd137205ea0000c09f", NULL } },
    // HermeticWiper / ransomware: fake repair screens or destructive zeroing loop
    { "HermeticWiper / Ransomware MBR Payload", "MBR_WIPER_RANSOMWARE", "mbr_bootstrap", "CRITICAL", false,
      "Destructive MBR wiper or ransomware screen replacing standard OS bootloader with fake repair screen / wiper loop",
      { "526570616972696e672066696c6573797374656d",
        "596f757220616374696f6e61626c652066696c65732061726520656e63727970746564",
        "43484b44534b20697320726570616972696e67", "31c08ed8b9000231c0aa", NULL } },
    // Clean MBRs only read (INT 13h ah=02h/42h), never write (mov ah,03h/43h; int 13h)
    { "Anomalous Direct Disk Write in MBR Code", "MBR_HEURISTIC_DISK_WRITE", "mbr_bootstrap", "HIGH", true,
      "Unrecognized MBR bootstrap code invokes BIOS INT 13h disk write routines (suspicious self-propagating bootkit)",
      { "b403cd13", "b443cd13", NULL } },
    // GAPZ / Cidox: VBR jump into reserved clusters hooking INT 13h
    { "GAPZ / Cidox VBR Bootkit", "VBR_BOOTKIT_GAPZ", "vbr_sector", "CRITICAL", false,
      "Partition VBR contains GAPZ/Cidox bootloader hook hijacking control flow before Windows kernel initialization",
      { "eb58905657538cc8", NULL } }
};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* ========================================================================== */
/* Field helpers shared by built-in and file loading                          */
/* ========================================================================== */

int rules_severity_level(const char *severity) {
    static const char *const LEVELS[] = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };
    if (!severity) return -1;
    for (size_t i = 0; i < ARRAY_LEN(LEVELS); i++) {
        if (strcmp(severity, LEVELS[i]) == 0) return (int)i;
    }
    return -1;
}

static bool copy_field(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) return false;
    memcpy(dst, src, n + 1);
    return true;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool is_lower_hex64(const char *s) {
    for (int i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    }
    return s[64] == '\0';
}

/* Decode a non-empty even-length hex string into at most RULES_MAX_PATTERN_BYTES bytes. */
static bool decode_pattern(const char *hex, uint8_t out[RULES_MAX_PATTERN_BYTES], size_t *out_len) {
    size_t n = strlen(hex);
    if (n == 0 || n % 2 != 0 || n / 2 > RULES_MAX_PATTERN_BYTES) return false;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return true;
}

static bool mbr_target_from_string(const char *s, rules_mbr_target_t *out) {
    if (strcmp(s, "mbr_bootstrap") == 0) { *out = RULES_MBR_TARGET_BOOTSTRAP; return true; }
    if (strcmp(s, "vbr_sector") == 0)    { *out = RULES_MBR_TARGET_VBR; return true; }
    return false;
}

static bool dbx_entry_valid(const rules_dbx_entry_t *e) {
    return is_lower_hex64(e->sha256) && e->threat[0] && rules_severity_level(e->severity) >= 0;
}

static bool lkm_entry_valid(const rules_lkm_entry_t *e) {
    if (!e->name[0] || !e->rule_id[0] || e->symbol_count < 1 || rules_severity_level(e->severity) < 0) return false;
    for (int i = 0; i < e->symbol_count; i++) {
        if (!e->symbols[i][0]) return false; /* "" would match every symbol */
    }
    return true;
}

static bool mbr_entry_valid(const rules_mbr_entry_t *e) {
    return e->name[0] && e->rule_id[0] && e->pattern_count >= 1 && rules_severity_level(e->severity) >= 0;
}

static bool builtin_dbx(rules_dbx_set_t *set) {
    for (size_t i = 0; i < ARRAY_LEN(G_BUILTIN_DBX); i++) {
        const builtin_dbx_t *b = &G_BUILTIN_DBX[i];
        rules_dbx_entry_t *e = &set->entries[set->count++];
        if (!copy_field(e->sha256, sizeof(e->sha256), b->sha256) ||
            !copy_field(e->threat, sizeof(e->threat), b->threat) ||
            !copy_field(e->cve, sizeof(e->cve), b->cve) ||
            !copy_field(e->severity, sizeof(e->severity), b->severity) ||
            !copy_field(e->description, sizeof(e->description), b->description) ||
            !dbx_entry_valid(e)) return false;
    }
    return true;
}

static bool builtin_lkm(rules_lkm_set_t *set) {
    for (size_t i = 0; i < ARRAY_LEN(G_BUILTIN_LKM); i++) {
        const builtin_lkm_t *b = &G_BUILTIN_LKM[i];
        rules_lkm_entry_t *e = &set->entries[set->count++];
        e->symbol_count = 1;
        if (!copy_field(e->name, sizeof(e->name), b->name) ||
            !copy_field(e->rule_id, sizeof(e->rule_id), b->rule_id) ||
            !copy_field(e->severity, sizeof(e->severity), b->severity) ||
            !copy_field(e->description, sizeof(e->description), b->description) ||
            !copy_field(e->symbols[0], sizeof(e->symbols[0]), b->symbol) ||
            !lkm_entry_valid(e)) return false;
    }
    return true;
}

static bool builtin_mbr(rules_mbr_set_t *set) {
    for (size_t i = 0; i < ARRAY_LEN(G_BUILTIN_MBR); i++) {
        const builtin_mbr_t *b = &G_BUILTIN_MBR[i];
        rules_mbr_entry_t *e = &set->entries[set->count++];
        e->unknown_bootloader_only = b->unknown_bootloader_only;
        if (!copy_field(e->name, sizeof(e->name), b->name) ||
            !copy_field(e->rule_id, sizeof(e->rule_id), b->rule_id) ||
            !copy_field(e->severity, sizeof(e->severity), b->severity) ||
            !copy_field(e->description, sizeof(e->description), b->description) ||
            !mbr_target_from_string(b->target, &e->target)) return false;
        for (int p = 0; p < RULES_MAX_PATTERNS && b->patterns_hex[p]; p++) {
            if (!decode_pattern(b->patterns_hex[p], e->patterns[p], &e->pattern_len[p])) return false;
            e->pattern_count++;
        }
        if (!mbr_entry_valid(e)) return false;
    }
    return true;
}

/* ========================================================================== */
/* Strict, bounded JSON reader                                                */
/* ========================================================================== */

typedef struct {
    const char *s;
    size_t len;
    size_t pos;
    int depth;
} jp_t;

static void jp_ws(jp_t *p) {
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
        p->pos++;
    }
}

/* Skip whitespace, then consume c if it is next. */
static bool jp_eat(jp_t *p, char c) {
    jp_ws(p);
    if (p->pos < p->len && p->s[p->pos] == c) {
        p->pos++;
        return true;
    }
    return false;
}

static bool jp_enter(jp_t *p, char open) {
    if (!jp_eat(p, open)) return false;
    return ++p->depth <= JSON_MAX_DEPTH;
}

static void jp_put(char *dst, size_t cap, size_t *n, bool *overflow, unsigned char c) {
    if (dst && *n + 1 < cap) dst[*n] = (char)c;
    else *overflow = true;
    (*n)++;
}

static bool jp_hex4(jp_t *p, unsigned *out) {
    if (p->len - p->pos < 4) return false;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hex_nibble(p->s[p->pos++]);
        if (h < 0) return false;
        v = (v << 4) | (unsigned)h;
    }
    *out = v;
    return true;
}

/* Parse a string into dst (NUL-terminated, cap bytes) or just consume it when dst is NULL.
 * Returns 0 ok, 1 too long for dst (fully consumed), -1 syntax error. */
static int jp_str(jp_t *p, char *dst, size_t cap) {
    if (!jp_eat(p, '"')) return -1;
    size_t n = 0;
    bool overflow = false;
    while (p->pos < p->len) {
        unsigned char c = (unsigned char)p->s[p->pos++];
        if (c == '"') {
            if (dst && cap > 0) dst[n < cap ? n : cap - 1] = '\0';
            return (dst && overflow) ? 1 : 0;
        }
        if (c < 0x20) return -1;
        if (c != '\\') {
            jp_put(dst, cap, &n, &overflow, c);
            continue;
        }
        if (p->pos >= p->len) return -1;
        char e = p->s[p->pos++];
        switch (e) {
            case '"':  jp_put(dst, cap, &n, &overflow, '"'); break;
            case '\\': jp_put(dst, cap, &n, &overflow, '\\'); break;
            case '/':  jp_put(dst, cap, &n, &overflow, '/'); break;
            case 'b':  jp_put(dst, cap, &n, &overflow, '\b'); break;
            case 'f':  jp_put(dst, cap, &n, &overflow, '\f'); break;
            case 'n':  jp_put(dst, cap, &n, &overflow, '\n'); break;
            case 'r':  jp_put(dst, cap, &n, &overflow, '\r'); break;
            case 't':  jp_put(dst, cap, &n, &overflow, '\t'); break;
            case 'u': {
                unsigned cp;
                if (!jp_hex4(p, &cp) || cp == 0 || (cp >= 0xDC00 && cp <= 0xDFFF)) return -1;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (p->len - p->pos < 2 || p->s[p->pos] != '\\' || p->s[p->pos + 1] != 'u') return -1;
                    p->pos += 2;
                    if (!jp_hex4(p, &lo) || lo < 0xDC00 || lo > 0xDFFF) return -1;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (cp < 0x80) {
                    jp_put(dst, cap, &n, &overflow, (unsigned char)cp);
                } else if (cp < 0x800) {
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0xC0 | (cp >> 6)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0xE0 | (cp >> 12)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | (cp & 0x3F)));
                } else {
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0xF0 | (cp >> 18)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | ((cp >> 12) & 0x3F)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
                    jp_put(dst, cap, &n, &overflow, (unsigned char)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default: return -1;
        }
    }
    return -1; /* unterminated */
}

/* A string value that must fit dst exactly. */
static bool jp_str_field(jp_t *p, char *dst, size_t cap) {
    return jp_str(p, dst, cap) == 0;
}

static bool jp_digits(jp_t *p) {
    size_t start = p->pos;
    while (p->pos < p->len && p->s[p->pos] >= '0' && p->s[p->pos] <= '9') p->pos++;
    return p->pos > start;
}

static bool jp_number(jp_t *p) {
    if (p->pos < p->len && p->s[p->pos] == '-') p->pos++;
    if (p->pos < p->len && p->s[p->pos] == '0') p->pos++;
    else if (!jp_digits(p)) return false;
    if (p->pos < p->len && p->s[p->pos] == '.') {
        p->pos++;
        if (!jp_digits(p)) return false;
    }
    if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-')) p->pos++;
        if (!jp_digits(p)) return false;
    }
    return true;
}

static bool jp_literal(jp_t *p, const char *lit) {
    size_t n = strlen(lit);
    if (p->len - p->pos < n || memcmp(p->s + p->pos, lit, n) != 0) return false;
    p->pos += n;
    return true;
}

static bool jp_bool(jp_t *p, bool *out) {
    jp_ws(p);
    if (jp_literal(p, "true")) { *out = true; return true; }
    if (jp_literal(p, "false")) { *out = false; return true; }
    return false;
}

/* Object member iteration after jp_enter(p,'{'): 1 = key read (and ':' consumed), 0 = '}' consumed, -1 = error.
 * Keys longer than key_cap come back as "" (treated as unknown). */
static int jp_member(jp_t *p, bool *first, char *key, size_t key_cap) {
    if (jp_eat(p, '}')) {
        p->depth--;
        return 0;
    }
    if (!*first && !jp_eat(p, ',')) return -1;
    *first = false;
    int r = jp_str(p, key, key_cap);
    if (r < 0) return -1;
    if (r == 1) key[0] = '\0';
    return jp_eat(p, ':') ? 1 : -1;
}

/* Array element iteration after jp_enter(p,'['): 1 = element follows, 0 = ']' consumed, -1 = error. */
static int jp_element(jp_t *p, bool *first) {
    if (jp_eat(p, ']')) {
        p->depth--;
        return 0;
    }
    if (!*first && !jp_eat(p, ',')) return -1;
    *first = false;
    return 1;
}

/* Skip any value; recursion is bounded by JSON_MAX_DEPTH via jp_enter. */
static bool jp_skip(jp_t *p) {
    jp_ws(p);
    if (p->pos >= p->len) return false;
    char c = p->s[p->pos];
    int r;
    bool first = true;
    switch (c) {
        case '{': {
            char key[8];
            if (!jp_enter(p, '{')) return false;
            while ((r = jp_member(p, &first, key, sizeof(key))) == 1) {
                if (!jp_skip(p)) return false;
            }
            return r == 0;
        }
        case '[':
            if (!jp_enter(p, '[')) return false;
            while ((r = jp_element(p, &first)) == 1) {
                if (!jp_skip(p)) return false;
            }
            return r == 0;
        case '"': return jp_str(p, NULL, 0) == 0;
        case 't': return jp_literal(p, "true");
        case 'f': return jp_literal(p, "false");
        case 'n': return jp_literal(p, "null");
        default:  return jp_number(p);
    }
}

/* Array of strings into a fixed table; fails on overflow, over-long or duplicate key use. */
static bool jp_str_array(jp_t *p, char *base, size_t stride, int max, int *count) {
    if (!jp_enter(p, '[')) return false;
    bool first = true;
    int r;
    while ((r = jp_element(p, &first)) == 1) {
        if (*count >= max || !jp_str_field(p, base + (size_t)*count * stride, stride)) return false;
        (*count)++;
    }
    return r == 0;
}

/* Marks a required/known key as seen; a repeated key is a schema error. */
static bool take_key(unsigned *seen, unsigned bit) {
    if (*seen & bit) return false;
    *seen |= bit;
    return true;
}

static bool parse_dbx_entry(jp_t *p, void *vset) {
    rules_dbx_set_t *set = vset;
    if (set->count >= RULES_MAX_ENTRIES) return false;
    rules_dbx_entry_t *e = &set->entries[set->count];
    char key[32];
    bool first = true;
    unsigned seen = 0;
    int r;
    if (!jp_enter(p, '{')) return false;
    while ((r = jp_member(p, &first, key, sizeof(key))) == 1) {
        bool ok;
        if (strcmp(key, "sha256") == 0)           ok = take_key(&seen, 1u) && jp_str_field(p, e->sha256, sizeof(e->sha256));
        else if (strcmp(key, "threat") == 0)      ok = take_key(&seen, 2u) && jp_str_field(p, e->threat, sizeof(e->threat));
        else if (strcmp(key, "cve") == 0)         ok = take_key(&seen, 4u) && jp_str_field(p, e->cve, sizeof(e->cve));
        else if (strcmp(key, "severity") == 0)    ok = take_key(&seen, 8u) && jp_str_field(p, e->severity, sizeof(e->severity));
        else if (strcmp(key, "description") == 0) ok = take_key(&seen, 16u) && jp_str_field(p, e->description, sizeof(e->description));
        else                                      ok = jp_skip(p);
        if (!ok) return false;
    }
    if (r != 0 || seen != 31u || !dbx_entry_valid(e)) return false;
    set->count++;
    return true;
}

static bool parse_lkm_entry(jp_t *p, void *vset) {
    rules_lkm_set_t *set = vset;
    if (set->count >= RULES_MAX_ENTRIES) return false;
    rules_lkm_entry_t *e = &set->entries[set->count];
    char key[32];
    bool first = true;
    unsigned seen = 0;
    int r;
    if (!jp_enter(p, '{')) return false;
    while ((r = jp_member(p, &first, key, sizeof(key))) == 1) {
        bool ok;
        if (strcmp(key, "name") == 0)             ok = take_key(&seen, 1u) && jp_str_field(p, e->name, sizeof(e->name));
        else if (strcmp(key, "rule_id") == 0)     ok = take_key(&seen, 2u) && jp_str_field(p, e->rule_id, sizeof(e->rule_id));
        else if (strcmp(key, "severity") == 0)    ok = take_key(&seen, 4u) && jp_str_field(p, e->severity, sizeof(e->severity));
        else if (strcmp(key, "description") == 0) ok = take_key(&seen, 8u) && jp_str_field(p, e->description, sizeof(e->description));
        else if (strcmp(key, "symbols") == 0)     ok = take_key(&seen, 16u) &&
                                                       jp_str_array(p, &e->symbols[0][0], sizeof(e->symbols[0]),
                                                                    RULES_MAX_SYMBOLS, &e->symbol_count);
        else                                      ok = jp_skip(p);
        if (!ok) return false;
    }
    if (r != 0 || seen != 31u || !lkm_entry_valid(e)) return false;
    set->count++;
    return true;
}

static bool parse_mbr_entry(jp_t *p, void *vset) {
    rules_mbr_set_t *set = vset;
    if (set->count >= RULES_MAX_ENTRIES) return false;
    rules_mbr_entry_t *e = &set->entries[set->count];
    char key[32];
    char target[32];
    char hex[RULES_MAX_PATTERNS][2 * RULES_MAX_PATTERN_BYTES + 1];
    int hex_count = 0;
    bool first = true;
    unsigned seen = 0;
    int r;
    if (!jp_enter(p, '{')) return false;
    while ((r = jp_member(p, &first, key, sizeof(key))) == 1) {
        bool ok;
        if (strcmp(key, "name") == 0)             ok = take_key(&seen, 1u) && jp_str_field(p, e->name, sizeof(e->name));
        else if (strcmp(key, "rule_id") == 0)     ok = take_key(&seen, 2u) && jp_str_field(p, e->rule_id, sizeof(e->rule_id));
        else if (strcmp(key, "severity") == 0)    ok = take_key(&seen, 4u) && jp_str_field(p, e->severity, sizeof(e->severity));
        else if (strcmp(key, "description") == 0) ok = take_key(&seen, 8u) && jp_str_field(p, e->description, sizeof(e->description));
        else if (strcmp(key, "target") == 0)      ok = take_key(&seen, 16u) && jp_str_field(p, target, sizeof(target)) &&
                                                       mbr_target_from_string(target, &e->target);
        else if (strcmp(key, "patterns_hex") == 0) ok = take_key(&seen, 32u) &&
                                                        jp_str_array(p, &hex[0][0], sizeof(hex[0]), RULES_MAX_PATTERNS, &hex_count);
        else if (strcmp(key, "unknown_bootloader_only") == 0)
                                                  ok = take_key(&seen, 64u) && jp_bool(p, &e->unknown_bootloader_only);
        else                                      ok = jp_skip(p);
        if (!ok) return false;
    }
    if (r != 0 || seen != 127u) return false;
    for (int i = 0; i < hex_count; i++) {
        if (!decode_pattern(hex[i], e->patterns[i], &e->pattern_len[i])) return false;
        e->pattern_count++;
    }
    if (!mbr_entry_valid(e)) return false;
    set->count++;
    return true;
}

typedef bool (*entry_parser_t)(jp_t *p, void *set);

/* Document: one top-level object holding exactly one `array_key` array of entry objects. */
static bool parse_document(const char *buf, size_t len, const char *array_key, entry_parser_t parse_entry, void *set) {
    jp_t p = { buf, len, 0, 0 };
    char key[32];
    bool first = true;
    bool found = false;
    int r;
    if (!jp_enter(&p, '{')) return false;
    while ((r = jp_member(&p, &first, key, sizeof(key))) == 1) {
        if (strcmp(key, array_key) != 0) {
            if (!jp_skip(&p)) return false;
            continue;
        }
        if (found || !jp_enter(&p, '[')) return false;
        found = true;
        bool efirst = true;
        int er;
        while ((er = jp_element(&p, &efirst)) == 1) {
            if (!parse_entry(&p, set)) return false;
        }
        if (er != 0) return false;
    }
    if (r != 0 || !found) return false;
    jp_ws(&p);
    return p.pos == p.len; /* reject trailing garbage */
}

/* ========================================================================== */
/* File location, seal verification and caching                              */
/* ========================================================================== */

static booto_error_t read_whole_file(const char *path, size_t max, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    char *buf = malloc(max + 1);
    if (!buf) {
        fclose(f);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }
    size_t n = fread(buf, 1, max + 1, f);
    bool failed = ferror(f) != 0;
    fclose(f);
    if (failed || n > max) {
        free(buf);
        return failed ? BOOTO_ERR_IO : BOOTO_ERR_CORRUPT_DATA;
    }
    *out = buf;
    *out_len = n;
    return BOOTO_OK;
}

/* Seal is sha256sum output "<hex>  <path>"; only the digest is compared. */
static booto_error_t verify_seal(const char *path, const char *data, size_t len) {
    char seal_path[600];
    if ((size_t)snprintf(seal_path, sizeof(seal_path), "%s.sha256", path) >= sizeof(seal_path)) {
        return BOOTO_ERR_CORRUPT_DATA;
    }
    char *seal = NULL;
    size_t seal_len = 0;
    if (read_whole_file(seal_path, SEAL_MAX_FILE_BYTES, &seal, &seal_len) != BOOTO_OK) {
        LOG_ERROR("Rules seal '%s' missing or unreadable; refusing '%s'", seal_path, path);
        return BOOTO_ERR_CORRUPT_DATA;
    }
    char actual[65];
    sha256_buffer_hex((const uint8_t *)data, len, actual);
    bool ok = seal_len >= 64 && strncasecmp(seal, actual, 64) == 0 &&
              (seal_len == 64 || seal[64] == ' ' || seal[64] == '\t' || seal[64] == '\n' || seal[64] == '\r');
    free(seal);
    if (!ok) {
        LOG_ERROR("Rules seal mismatch for '%s' (actual SHA-256 %s); refusing tampered rules", path, actual);
        return BOOTO_ERR_CORRUPT_DATA;
    }
    return BOOTO_OK;
}

/* First search directory containing `file` -> path; false when absent everywhere. */
static bool locate_rules_file(const char *file, char *path, size_t cap) {
    const char *env = getenv("BOOTO_RULES_DIR");
    const char *only = getenv("BOOTO_RULES_DIR_ONLY");
    bool env_only = only && strcmp(only, "1") == 0;
    const char *dirs[] = { (env && *env) ? env : NULL, "/persistence/rules", "/usr/share/booto/rules", "./rules" };
    size_t ndirs = env_only ? 1 : ARRAY_LEN(dirs);
    for (size_t i = 0; i < ndirs; i++) {
        if (!dirs[i]) continue;
        if ((size_t)snprintf(path, cap, "%s/%s", dirs[i], file) >= cap) continue;
        struct stat st;
        // Anything other than "does not exist" counts as present, so unreadable rules fail closed.
        if (stat(path, &st) == 0 || (errno != ENOENT && errno != ENOTDIR)) return true;
    }
    return false;
}

static booto_error_t load_rules(const char *file, const char *array_key, entry_parser_t parse_entry, void *set,
                                rules_source_t *source, char *path, size_t path_cap, int *count) {
    if (!locate_rules_file(file, path, path_cap)) {
        path[0] = '\0';
        *source = RULES_SOURCE_BUILTIN;
        return BOOTO_OK;
    }
    *source = RULES_SOURCE_FILE;
    char *buf = NULL;
    size_t len = 0;
    booto_error_t err = read_whole_file(path, RULES_MAX_FILE_BYTES, &buf, &len);
    if (err != BOOTO_OK) {
        LOG_ERROR("Cannot read rules file '%s' (err: %d)", path, err);
        return err == BOOTO_ERR_NOT_FOUND ? BOOTO_ERR_IO : err;
    }
    err = verify_seal(path, buf, len);
    if (err == BOOTO_OK && !parse_document(buf, len, array_key, parse_entry, set)) {
        LOG_ERROR("Rules file '%s' is malformed or violates the schema", path);
        err = BOOTO_ERR_CORRUPT_DATA;
    }
    free(buf);
    if (err == BOOTO_OK) LOG_INFO("Loaded %d sealed rules from %s", *count, path);
    return err;
}

typedef struct {
    bool loaded;
    booto_error_t err;
} rules_cache_t;

static rules_dbx_set_t g_dbx;
static rules_lkm_set_t g_lkm;
static rules_mbr_set_t g_mbr;
static rules_cache_t g_dbx_cache, g_lkm_cache, g_mbr_cache;

/* Expands the shared lazy-load body for one rule family. */
#define RULES_GET(cache, set, file, key, parser, builtin, out)                                          \
    do {                                                                                                 \
        if (!(out)) return BOOTO_ERR_INVALID_ARG;                                                        \
        if (!(cache).loaded) {                                                                           \
            memset(&(set), 0, sizeof(set));                                                              \
            (cache).err = load_rules(file, key, parser, &(set), &(set).source, (set).path,               \
                                     sizeof((set).path), &(set).count);                                  \
            if ((cache).err == BOOTO_OK && (set).source == RULES_SOURCE_BUILTIN && !builtin(&(set))) {   \
                (cache).err = BOOTO_ERR_CORRUPT_DATA;                                                    \
            }                                                                                            \
            (cache).loaded = true;                                                                       \
        }                                                                                                \
        *(out) = (cache).err == BOOTO_OK ? &(set) : NULL;                                                \
        return (cache).err;                                                                              \
    } while (0)

booto_error_t rules_get_dbx(const rules_dbx_set_t **out) {
    RULES_GET(g_dbx_cache, g_dbx, DBX_FILE, "revocations", parse_dbx_entry, builtin_dbx, out);
}

booto_error_t rules_get_lkm(const rules_lkm_set_t **out) {
    RULES_GET(g_lkm_cache, g_lkm, LKM_FILE, "signatures", parse_lkm_entry, builtin_lkm, out);
}

booto_error_t rules_get_mbr(const rules_mbr_set_t **out) {
    RULES_GET(g_mbr_cache, g_mbr, MBR_FILE, "signatures", parse_mbr_entry, builtin_mbr, out);
}

void rules_reset_cache(void) {
    g_dbx_cache.loaded = false;
    g_lkm_cache.loaded = false;
    g_mbr_cache.loaded = false;
}
