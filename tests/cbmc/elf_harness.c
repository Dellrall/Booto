/**
 * @file elf_harness.c
 * @brief CBMC proof harness for elf_parse_buffer() (ELF64 headers, section names, symbols).
 *
 * Proves, for every ELF_LEN-byte input with arbitrary contents (all header fields, section and
 * symbol table offsets, sizes and name indices unconstrained): no out-of-bounds access, invalid
 * pointer, leak, or signed or pointer overflow, and every byte any string helper reads lies in
 * the buffer. Tables may overlap each other and the headers.
 *
 * Stubs (the CBMC library models unroll too far for a symbolic input):
 *  - elf_parse_modinfo is replaced (goto-instrument --replace-calls) by elf_parse_modinfo_stub,
 *    which asserts the section range it gets is readable; it is proved in modinfo_harness.c.
 *  - strnlen asserts all maxlen bytes are readable (stronger than the real call, which may stop
 *    at an earlier NUL) and returns any r <= maxlen with r == maxlen or s[r] == 0. That set
 *    contains the real result, so every behaviour of the parser is still explored.
 *  - snprintf asserts the destination is writable; for "%.*s" it also asserts the n source bytes
 *    are readable (the string-table copy that once over-read).
 *  - sha256_buffer_hex and logging only check their arguments.
 * Run with `make cbmc`.
 */
#include "crypto_utils.h"
#include "elf_analyzer.h"
#include "logger.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef ELF_LEN
#define ELF_LEN 256
#endif

size_t nondet_size_t(void);

void sha256_buffer_hex(const uint8_t *data, size_t len, char hex_out[65]) {
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(data, len), "sha256_buffer_hex: whole buffer readable");
    __CPROVER_assert(__CPROVER_w_ok(hex_out, 65), "sha256_buffer_hex: output writable");
    hex_out[64] = '\0';
}

void log_message(log_level_t level, const char *fmt, ...) {
    (void)level;
    (void)fmt;
}

void elf_parse_modinfo_stub(const char *data, size_t size, elf_modinfo_t *out) {
    __CPROVER_assert(size == 0 || __CPROVER_r_ok(data, size), "elf_parse_modinfo: section inside the buffer");
    __CPROVER_assert(__CPROVER_w_ok(out, sizeof(*out)), "elf_parse_modinfo: output writable");
    out->has_modinfo = true;
}

size_t strnlen(const char *s, size_t maxlen) {
    __CPROVER_assert(maxlen == 0 || __CPROVER_r_ok(s, maxlen), "strnlen: whole bound readable");
    size_t r = nondet_size_t();
    __CPROVER_assume(r <= maxlen);
    __CPROVER_assume(r == maxlen || s[r] == '\0');
    return r;
}

int snprintf(char *str, size_t size, const char *fmt, ...) {
    __CPROVER_assert(size == 0 || __CPROVER_w_ok(str, size), "snprintf: destination writable for size bytes");
    if (fmt[0] == '%' && fmt[1] == '.' && fmt[2] == '*' && fmt[3] == 's' && fmt[4] == '\0') {
        va_list ap;
        va_start(ap, fmt);
        int n = va_arg(ap, int);
        const char *src = va_arg(ap, const char *);
        va_end(ap);
        __CPROVER_assert(n >= 0 && (n == 0 || __CPROVER_r_ok(src, (size_t)n)), "snprintf %.*s: source bytes readable");
    }
    if (size > 0) {
        __CPROVER_havoc_slice(str, size - 1);
        str[size - 1] = '\0';
    }
    return size > 0 ? (int)(size - 1) : 0;
}

void harness(void) {
    uint8_t *buf = malloc(ELF_LEN); /* contents are unconstrained */
    __CPROVER_assume(buf != NULL);
    elf_binary_info_t info;
    booto_error_t err = elf_parse_buffer(buf, ELF_LEN, &info);
    if (err == BOOTO_OK) {
        __CPROVER_assert(info.section_count >= 0 && info.section_count <= MAX_ELF_SECTIONS, "section count in range");
        __CPROVER_assert(info.symbol_count == 0 || info.symbols != NULL, "symbol count published only with its array");
        free(info.symbols);
    }
    free(buf);
}
