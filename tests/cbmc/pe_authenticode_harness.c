/**
 * @file pe_authenticode_harness.c
 * @brief CBMC proof harness for uefi_parse_pe_buffer() (PE header walk + Authenticode ranges).
 *
 * Proves, for a buffer of PE_LEN bytes with fully arbitrary contents: no out-of-bounds read or
 * write, no invalid pointer use, no leak, no signed or pointer overflow, and every byte range
 * handed to SHA-256 lies inside the buffer. Every header field (32-bit offsets and sizes,
 * section count) is unconstrained, so offset arithmetic overflow is covered whatever PE_LEN is.
 * The length is fixed per run because a symbolic length makes the formula blow up; `make cbmc`
 * runs several lengths. The section loop is unrolled completely (--unwinding-assertions), so a
 * PE_LEN also bounds how many sections fit: (PE_LEN - 120) / 40.
 * SHA-256, logging, the dbx rules loader, snprintf and strcasecmp are replaced by stubs. CBMC's
 * own snprintf/strcasecmp models unroll into thousands of steps; the stubs keep the checks that
 * matter here: snprintf writes stay inside the destination, and the strings strcasecmp compares
 * (two 64-hex-digit digests) are NUL-terminated within their 65-byte buffers. Hashing is checked
 * only for the ranges it is given; the dbx set holds one arbitrary entry to exercise the match.
 * Run with `make cbmc`.
 */
#include "crypto_utils.h"
#include "logger.h"
#include "rules_loader.h"
#include "uefi_analyzer.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef PE_LEN
#define PE_LEN 512
#endif

size_t nondet_size_t(void);
uint8_t nondet_uint8_t(void);

/* ---- stubs ---------------------------------------------------------------------------------- */

void sha256_init(sha256_ctx_t *ctx) {
    __CPROVER_assert(__CPROVER_w_ok(ctx, sizeof(*ctx)), "sha256_init: context writable");
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    __CPROVER_assert(__CPROVER_w_ok(ctx, sizeof(*ctx)), "sha256_update: context writable");
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(data, len), "sha256_update: hashed range inside the buffer");
}

void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    __CPROVER_assert(__CPROVER_w_ok(ctx, sizeof(*ctx)), "sha256_final: context writable");
    __CPROVER_assert(__CPROVER_w_ok(hash, 32), "sha256_final: digest writable");
    __CPROVER_havoc_slice(hash, 32);
}

void sha256_buffer_hex(const uint8_t *data, size_t len, char hex_out[65]) {
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(data, len), "sha256_buffer_hex: whole buffer readable");
    __CPROVER_assert(__CPROVER_w_ok(hex_out, 65), "sha256_buffer_hex: output writable");
    hex_out[64] = '\0';
}

void log_message(log_level_t level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

/* Models output that fills the destination (true for every call here: "%02x" into 3 bytes, a
 * rule name into a buffer of the same capacity): contents arbitrary, NUL at size - 1. */
int snprintf(char *str, size_t size, const char *fmt, ...) {
    (void)fmt;
    __CPROVER_assert(size == 0 || __CPROVER_w_ok(str, size), "snprintf: destination writable for size bytes");
    if (size > 0) {
        __CPROVER_havoc_slice(str, size - 1);
        str[size - 1] = '\0';
    }
    return size > 0 ? (int)(size - 1) : 0;
}

/* Sorting only reorders entries that were each bounds-checked before the call, so the order
 * cannot affect memory safety; check the whole array is accessible and leave it unsorted. */
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    (void)compar;
    __CPROVER_assert(nmemb == 0 || __CPROVER_w_ok(base, nmemb * size), "qsort: array accessible");
}

int strcasecmp(const char *a, const char *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, 65) && a[64] == '\0', "strcasecmp: first digest terminated in 65 bytes");
    __CPROVER_assert(__CPROVER_r_ok(b, 65) && b[64] == '\0', "strcasecmp: second digest terminated in 65 bytes");
    int r;
    return r;
}

/* One arbitrary entry; the parser only reads entries[0..count). */
static rules_dbx_set_t g_dbx;

booto_error_t rules_get_dbx(const rules_dbx_set_t **out) {
    g_dbx.count = 1;
    g_dbx.entries[0].threat[sizeof(g_dbx.entries[0].threat) - 1] = '\0';
    g_dbx.entries[0].severity[sizeof(g_dbx.entries[0].severity) - 1] = '\0';
    g_dbx.entries[0].sha256[64] = '\0';
    *out = &g_dbx;
    return BOOTO_OK;
}

int rules_severity_level(const char *severity) {
    (void)severity;
    return 1;
}

/* ---- harness -------------------------------------------------------------------------------- */

void harness(void) {
    uint8_t *buf = malloc(PE_LEN); /* contents are unconstrained */
    __CPROVER_assume(buf != NULL);
    size_t len = PE_LEN;
    pe_efi_info_t info;
    booto_error_t err = uefi_parse_pe_buffer(buf, len, &info);
    __CPROVER_assert(err != BOOTO_OK || info.authenticode_sha256[64] == '\0',
                     "success leaves a terminated Authenticode hex digest");
    free(buf);
}
