/**
 * @file hive_fixture.h
 * @brief Builds small Windows registry hives (regf) for tests: keys with "lf" subkey lists and "vk" values.
 *
 * Build bottom-up: values and child keys first, then their parent, then hv_root on the top key.
 */
#ifndef BOOTO_HIVE_FIXTURE_H
#define BOOTO_HIVE_FIXTURE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *b;
    size_t cap;
    uint32_t next; /* next free cell, relative to the first hbin at 0x1000 */
} hv_t;

static void hv_put32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static void hv_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void hv_init(hv_t *h, uint8_t *b, size_t cap) {
    memset(b, 0, cap);
    memcpy(b, "regf", 4);
    memcpy(b + 0x1000, "hbin", 4);
    h->b = b;
    h->cap = cap;
    h->next = 0x20;
}

/* A used cell holding `size` bytes; returns its data, *off gets the cell offset. */
static uint8_t *hv_cell(hv_t *h, uint32_t size, uint32_t *off) {
    uint32_t total = (size + 4 + 7) & ~7u;
    if (0x1000u + h->next + total > h->cap) {
        fprintf(stderr, "hive fixture: buffer too small\n");
        abort();
    }
    *off = h->next;
    uint8_t *p = h->b + 0x1000 + h->next;
    hv_put32(p, (uint32_t)-(int32_t)total);
    h->next += total;
    return p + 4;
}

/* REG_SZ data: ASCII s as UTF-16LE with its terminator, into out (2 * strlen + 2 bytes). */
static uint32_t hv_utf16(const char *s, uint8_t *out) {
    uint32_t n = 0;
    for (; s[n]; n++) hv_put16(out + 2 * n, (uint8_t)s[n]);
    hv_put16(out + 2 * n, 0);
    return 2 * n + 2;
}

static uint32_t hv_value(hv_t *h, const char *name, uint32_t type, const void *data, uint32_t len) {
    uint32_t nlen = (uint32_t)strlen(name), off, doff = 0;
    if (len > 4) {
        uint8_t *d = hv_cell(h, len, &doff);
        memcpy(d, data, len);
    }
    uint8_t *v = hv_cell(h, 0x14 + nlen, &off);
    v[0] = 'v'; v[1] = 'k';
    hv_put16(v + 2, (uint16_t)nlen);
    if (len > 4) {
        hv_put32(v + 4, len);
        hv_put32(v + 8, doff);
    } else {
        hv_put32(v + 4, len | 0x80000000u); // data kept in the offset field
        memcpy(v + 8, data, len);
    }
    hv_put32(v + 0x0C, type);
    hv_put16(v + 0x10, 1); // ASCII name
    memcpy(v + 0x14, name, nlen);
    return off;
}

static uint32_t hv_dword(hv_t *h, const char *name, uint32_t x) {
    uint8_t d[4];
    hv_put32(d, x);
    return hv_value(h, name, 4, d, 4);
}

static uint32_t hv_string(hv_t *h, const char *name, const char *s) {
    uint8_t d[512];
    return hv_value(h, name, 1, d, hv_utf16(s, d));
}

static uint32_t hv_key(hv_t *h, const char *name, const uint32_t *subs, uint32_t nsub, const uint32_t *vals,
                       uint32_t nval) {
    uint32_t nlen = (uint32_t)strlen(name), off, list = 0xFFFFFFFFu, vlist = 0xFFFFFFFFu;
    if (nsub) {
        uint8_t *l = hv_cell(h, 4 + 8 * nsub, &list);
        l[0] = 'l'; l[1] = 'f';
        hv_put16(l + 2, (uint16_t)nsub);
        for (uint32_t i = 0; i < nsub; i++) hv_put32(l + 4 + 8 * i, subs[i]);
    }
    if (nval) {
        uint8_t *l = hv_cell(h, 4 * nval, &vlist);
        for (uint32_t i = 0; i < nval; i++) hv_put32(l + 4 * i, vals[i]);
    }
    uint8_t *k = hv_cell(h, 0x4C + nlen, &off);
    k[0] = 'n'; k[1] = 'k';
    hv_put16(k + 2, 0x20); // ASCII name
    hv_put32(k + 0x14, nsub);
    hv_put32(k + 0x1C, list);
    hv_put32(k + 0x24, nval);
    hv_put32(k + 0x28, vlist);
    hv_put16(k + 0x48, (uint16_t)nlen);
    memcpy(k + 0x4C, name, nlen);
    return off;
}

/* Sets the root key; returns the hive length. */
static size_t hv_root(hv_t *h, uint32_t key) {
    hv_put32(h->b + 0x24, key);
    return 0x1000u + h->next;
}

#endif /* BOOTO_HIVE_FIXTURE_H */
