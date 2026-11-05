/**
 * @file modinfo_harness.c
 * @brief CBMC proof harness for elf_modinfo_entry(), the body of the .modinfo walk.
 *
 * Proves, for a string region of MODINFO_REM bytes with arbitrary contents: no out-of-bounds
 * access, invalid pointer, or overflow; every "%.Ns" copy starts at a string whose NUL lies
 * inside the region; and the bytes consumed are 0 or at most MODINFO_REM. That last fact is
 * the loop invariant of elf_parse_modinfo(): off only grows by at most size - off, so the walk
 * never leaves the section. Proving the body once avoids unrolling the walk, whose string
 * offsets depend on every earlier string and do not fit in memory.
 *
 * strncmp is CBMC's real model. strnlen (no CBMC model exists) asserts its whole bound is
 * readable and returns any r <= maxlen with r == maxlen or s[r] == 0; that set contains the
 * real result. snprintf checks the destination and searches its source for a NUL before the
 * region end. Run with `make cbmc`.
 */
#include "elf_analyzer.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifndef MODINFO_REM
#define MODINFO_REM 128 /* longer than every key; 50 s here, while 300 bytes takes over 20 min */
#endif

size_t nondet_size_t(void);

static const char *g_end; /* one past the region */

size_t strnlen(const char *s, size_t maxlen) {
    __CPROVER_assert(maxlen == 0 || __CPROVER_r_ok(s, maxlen), "strnlen: whole bound readable");
    size_t r = nondet_size_t();
    __CPROVER_assume(r <= maxlen);
    __CPROVER_assume(r == maxlen || s[r] == '\0');
    return r;
}

static bool nul_before_end(const char *p) {
    for (const char *q = p; q < g_end; q++)
        if (*q == '\0') return true;
    return false;
}

int snprintf(char *str, size_t size, const char *fmt, ...) {
    __CPROVER_assert(size == 0 || __CPROVER_w_ok(str, size), "snprintf: destination writable for size bytes");
    va_list ap;
    va_start(ap, fmt);
    const char *src = va_arg(ap, const char *); /* every call here is "%.Ns" */
    va_end(ap);
    /* "%.Ns" stops at the first NUL: there must be one between src and the region end. */
    __CPROVER_assert(nul_before_end(src), "snprintf %.Ns: source NUL-terminated inside the region");
    if (size > 0) {
        __CPROVER_havoc_slice(str, size - 1);
        str[size - 1] = '\0';
    }
    return size > 0 ? (int)(size - 1) : 0;
}

void harness(void) {
    char *p = malloc(MODINFO_REM); /* contents are unconstrained */
    __CPROVER_assume(p != NULL);
    g_end = p + MODINFO_REM;
    elf_modinfo_t out;
    size_t used = elf_modinfo_entry(p, MODINFO_REM, &out);
    __CPROVER_assert(used <= MODINFO_REM, "consumed bytes stay inside the region (loop invariant)");
    free(p);
}
