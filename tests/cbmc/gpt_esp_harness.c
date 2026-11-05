/**
 * @file gpt_esp_harness.c
 * @brief CBMC proof harness for disk_parse_esp_partitions() (GPT header + entry array, or MBR).
 *
 * Proves, for a GPT_LEN-byte disk prefix with fully arbitrary contents (every header field,
 * including the entry-array LBA, entry count and entry size), any sector size (any uint32_t:
 * invalid ones must be rejected, 512..768 reach the GPT path within the prefix, larger ones take
 * the MBR path) and any max: no out-of-bounds access, invalid pointer, leak, or signed or
 * pointer overflow; at most max partition numbers are written, each in range 1..1024.
 *
 * crc32_update() is a stub: it asserts the range it is given is readable and returns an
 * arbitrary value, so both CRC checks may pass or fail for any data and every path after them
 * is explored. The real bit loop, unrolled for a symbolic length, does not fit in memory.
 * Run with `make cbmc`.
 */
#include "crypto_utils.h"
#include "disk_mount.h"
#include "logger.h"

#include <stdlib.h>

#ifndef GPT_LEN
#define GPT_LEN 1536 /* LBA 0-2 at 512-byte sectors: protective MBR, header, 4 entries */
#endif

int nondet_int(void);
uint32_t nondet_uint32_t(void);

uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    (void)crc;
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(data, len), "crc32_update: range inside the buffer");
    return nondet_uint32_t();
}

void log_message(log_level_t level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

void harness(void) {
    uint8_t *buf = malloc(GPT_LEN); /* contents are unconstrained */
    __CPROVER_assume(buf != NULL);
    uint32_t sector_size = nondet_uint32_t();
    int max = nondet_int();
    __CPROVER_assume(max <= DISK_MAX_ESP); /* contract: part_numbers holds max entries */
    uint32_t parts[DISK_MAX_ESP];
    int n = -1;

    booto_error_t err = disk_parse_esp_partitions(buf, GPT_LEN, sector_size, parts, max, &n);
    if (err == BOOTO_OK) {
        __CPROVER_assert(n >= 0 && n <= max, "result count within max");
        for (int i = 0; i < n; i++)
            __CPROVER_assert(parts[i] >= 1 && parts[i] <= 1024, "partition number in range");
    }
    free(buf);
}
