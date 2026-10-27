/**
 * @file rules_loader.h
 * @brief Sealed JSON detection rules (DBX, LKM, MBR) with built-in fallback tables.
 *
 * Each rules file is searched in: $BOOTO_RULES_DIR, /persistence/rules,
 * /usr/share/booto/rules, ./rules (first directory containing the file wins;
 * BOOTO_RULES_DIR_ONLY=1 restricts the search to $BOOTO_RULES_DIR).
 * A found file MUST have a matching "<file>.sha256" seal (sha256sum format; only
 * the hex digest is compared, the path column is ignored), otherwise loading fails
 * with BOOTO_ERR_CORRUPT_DATA. A file absent everywhere selects the built-in table.
 */
#ifndef BOOTO_RULES_LOADER_H
#define BOOTO_RULES_LOADER_H

#include "booto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RULES_MAX_ENTRIES 128
#define RULES_MAX_SYMBOLS 8
#define RULES_MAX_PATTERNS 8
#define RULES_MAX_PATTERN_BYTES 64

typedef enum { RULES_SOURCE_BUILTIN, RULES_SOURCE_FILE } rules_source_t;

/* uefi_dbx_revocations.json: {"revocations":[{sha256,threat,cve,severity,description}]} */
typedef struct {
    char sha256[65]; /* Authenticode PE image hash, lowercase hex */
    char threat[96];
    char cve[32];
    char severity[16];
    char description[160];
} rules_dbx_entry_t;

typedef struct {
    rules_source_t source;
    char path[512];
    int count;
    rules_dbx_entry_t entries[RULES_MAX_ENTRIES];
} rules_dbx_set_t;

/* lkm_rootkit_signatures.json: {"signatures":[{name,rule_id,severity,description,symbols[]}]}
 * A rule fires for every ELF symbol whose name contains any of its symbol substrings. */
typedef struct {
    char name[64];
    char rule_id[64];
    char severity[16];
    char description[256];
    int symbol_count;
    char symbols[RULES_MAX_SYMBOLS][64];
} rules_lkm_entry_t;

typedef struct {
    rules_source_t source;
    char path[512];
    int count;
    rules_lkm_entry_t entries[RULES_MAX_ENTRIES];
} rules_lkm_set_t;

/* Region a byte-pattern rule is matched against. */
typedef enum {
    RULES_MBR_TARGET_BOOTSTRAP, /* "mbr_bootstrap": first 446 bytes of sector 0 */
    RULES_MBR_TARGET_VBR        /* "vbr_sector": whole 512-byte partition boot sector */
} rules_mbr_target_t;

/* mbr_bootkit_signatures.json: {"signatures":[{name,rule_id,target,severity,description,
 * unknown_bootloader_only,patterns_hex[]}]}. A rule fires once if any pattern occurs in its region;
 * unknown_bootloader_only rules fire only when no known bootloader was identified. */
typedef struct {
    char name[64];
    char rule_id[64];
    char severity[16];
    char description[256];
    rules_mbr_target_t target;
    bool unknown_bootloader_only;
    int pattern_count;
    size_t pattern_len[RULES_MAX_PATTERNS];
    uint8_t patterns[RULES_MAX_PATTERNS][RULES_MAX_PATTERN_BYTES];
} rules_mbr_entry_t;

typedef struct {
    rules_source_t source;
    char path[512];
    int count;
    rules_mbr_entry_t entries[RULES_MAX_ENTRIES];
} rules_mbr_set_t;

/* Lazily load once and cache (including a failed result). *out is never NULL on BOOTO_OK. */
booto_error_t rules_get_dbx(const rules_dbx_set_t **out); /* uefi_dbx_revocations.json */
booto_error_t rules_get_lkm(const rules_lkm_set_t **out); /* lkm_rootkit_signatures.json */
booto_error_t rules_get_mbr(const rules_mbr_set_t **out); /* mbr_bootkit_signatures.json */

/* Tests: forget cached sets so the next rules_get_* reloads. */
void rules_reset_cache(void);

/* Severity string ("INFO".."CRITICAL") -> 0..4, matching every engine's severity enum order; -1 if invalid.
 * Loaded entries are validated, so their severity always maps to 0..4. */
int rules_severity_level(const char *severity);

#endif /* BOOTO_RULES_LOADER_H */
