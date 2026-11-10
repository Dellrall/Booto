/**
 * @file yara_scan.h
 * @brief Signed YARA rules (rules/bootkits.yar) matched against file buffers with libyara.
 *
 * The rules file is found on the rules search path (see rules_loader.h) and must carry a valid "<file>.sig".
 * Each rule needs string metas "severity" ("INFO".."CRITICAL") and "description"; a rule without them makes the
 * whole file invalid. No rules file anywhere means no YARA rules (every scan matches nothing).
 */
#ifndef BOOTO_YARA_SCAN_H
#define BOOTO_YARA_SCAN_H

#include "booto.h"

#include <stddef.h>
#include <stdint.h>

#define YARA_RULES_FILE "bootkits.yar"
#define YARA_MAX_MATCHES 4

typedef struct {
    char rule[64];         /* rule identifier, used as the finding's rule ID */
    char description[160]; /* the rule's "description" meta */
    booto_severity_t severity;
} yara_match_t;

/* Match buf against the rules (loaded once and cached, including a failed load). Writes at most `max` matches.
 * BOOTO_ERR_CORRUPT_DATA when the rules file is unsigned, altered or does not compile. */
booto_error_t yara_scan_buffer(const uint8_t *buf, size_t len, yara_match_t *out, int max, int *count);
/* The same for a file on disk, read by libyara. */
booto_error_t yara_scan_file(const char *path, yara_match_t *out, int max, int *count);

/* Load the rules if needed: BOOTO_OK when they loaded or no rules file exists. Engines call it first so refused
 * rules fail the engine instead of silently matching nothing. */
booto_error_t yara_rules_status(void);

/* Drop the cached rules so the next scan reloads them; rules_reset_cache calls it. */
void yara_scan_reset(void);

#endif /* BOOTO_YARA_SCAN_H */
