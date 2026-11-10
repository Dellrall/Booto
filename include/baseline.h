/**
 * @file baseline.h
 * @brief Boot chain hash list: written once on a known-good machine, compared on later scans.
 */
#ifndef BOOTO_BASELINE_H
#define BOOTO_BASELINE_H

#include "booto.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BASELINE_MAX 2048
#define BASELINE_LABEL_MAX 256

typedef struct {
    char label[BASELINE_LABEL_MAX];   /* "disk/first-1MiB", "esp/EFI/BOOT/BOOTX64.EFI", "root/boot/vmlinuz" */
    char sha256[65];
} baseline_entry_t;

typedef struct {
    int count;
    bool truncated;                   /* more than BASELINE_MAX files; the rest were not recorded */
    baseline_entry_t e[BASELINE_MAX];
} baseline_t;

/* Records label with a hash already computed (hex, 64 chars). */
void baseline_add_hash(baseline_t *b, const char *label, const char *sha256);
/* Hashes one regular file; unreadable files are recorded with hash "unreadable". */
void baseline_add_file(baseline_t *b, const char *label, const char *path);
/* Hashes every regular file under dir (symlinks not followed), labelled prefix/<path relative to dir>. */
void baseline_add_tree(baseline_t *b, const char *prefix, const char *dir);
/* Hashes the first `bytes` bytes of a raw device or image. */
void baseline_add_device(baseline_t *b, const char *label, const char *dev, size_t bytes);

/* File format: one "<sha256>  <label>" line per entry, like sha256sum. */
booto_error_t baseline_write(const baseline_t *b, const char *path);
/* Parses a baseline file's text (untrusted). BOOTO_ERR_CORRUPT_DATA on any malformed line. */
booto_error_t baseline_parse(const char *text, size_t len, baseline_t *out);
booto_error_t baseline_load(const char *path, baseline_t *out);
/* Prints changed, missing and new entries to fp; returns how many differ. */
int baseline_compare(const baseline_t *old, const baseline_t *cur, FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_BASELINE_H */
