/**
 * @file inspect.h
 * @brief Read-only byte view of one flagged file: its first bytes, hashes, and a map of what lies where.
 */
#ifndef BOOTO_INSPECT_H
#define BOOTO_INSPECT_H

#include "booto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INSPECT_MAX_BYTES   (256u * 1024)  /* bytes kept for the hex view and the map */
#define INSPECT_BLOCK       4096u          /* entropy strip granularity */
#define INSPECT_MAX_REGIONS 32

typedef struct {
    char name[40];
    uint64_t offset;
    uint64_t size;          /* bytes in the file */
    bool exec;
    double entropy;         /* bits per byte over the region, up to the hashed length */
} inspect_region_t;

typedef struct {
    char path[256];         /* "" = nothing captured */
    char format[40];        /* "PE32+ x86-64", "ELF64 x86-64", "MBR boot sector" or "data" */
    int region_count;
    int regions_total;      /* regions found; more than region_count when the list was cut */
    inspect_region_t regions[INSPECT_MAX_REGIONS];
    uint64_t file_size;     /* whole file, or device size */
    uint64_t hashed_len;    /* bytes the hashes cover: the whole file up to the capture limit */
    char sha256[65];
    char md5[33];
    size_t len;             /* bytes in data */
    uint8_t data[INSPECT_MAX_BYTES];
} inspect_sample_t;

/**
 * @brief Read path into out: keeps its first INSPECT_MAX_BYTES, hashes its first max_bytes, maps its sections
 * (PE and ELF section tables, or the parts of an MBR boot track).
 * root non-NULL: path must resolve inside root (symlinks followed). Only regular files and block devices are read.
 */
booto_error_t inspect_capture(const char *root, const char *path, uint64_t max_bytes, inspect_sample_t *out);

/** @brief Entropy in bits per byte of sample block i (INSPECT_BLOCK bytes each; the last may be shorter). */
double inspect_block_entropy(const inspect_sample_t *s, size_t block);

/** @brief One hex view row for the 16 bytes at off: "00000010  4d 5a ..  |MZ..|"; "" past the sample. */
void inspect_hex_row(const inspect_sample_t *s, size_t off, char *out, size_t out_len);

/** @brief One character for an entropy value: ' ' (0 bits) through '@' (8 bits, packed or encrypted). */
char inspect_entropy_char(double bits);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_INSPECT_H */
