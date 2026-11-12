/**
 * @file reg_hive.c
 * @brief Read-only Windows registry hive (regf) reader: keys, subkeys and values, every offset bounds-checked.
 *
 * Cells sit at 0x1000 + offset; a cell starts with an int32 size (negative when in use). Key nodes ("nk")
 * point to a subkey list ("lf", "lh", "li", or "ri" of lists) and a value list of "vk" cells.
 */
#include "reg_hive.h"

#include <string.h>
#include <strings.h>

#define HBIN_START 0x1000u
#define NK_NAME 0x4C
#define VK_NAME 0x14
#define KEY_COMP_NAME 0x20
#define VALUE_COMP_NAME 0x01
#define MAX_NAME 256

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | p[1] << 8);
}

/* Cell data at off, or NULL; *n gets its length. */
static const uint8_t *cell(const reg_hive_t *h, uint32_t off, uint32_t *n) {
    if (!h || off == 0 || off == 0xFFFFFFFFu) return NULL;
    size_t abs = (size_t)HBIN_START + off;
    if (abs > h->len || h->len - abs < 4) return NULL;
    int32_t size = (int32_t)rd32(h->d + abs);
    if (size >= 0) return NULL;                        // free cell
    uint32_t total = (uint32_t)(-(int64_t)size);
    if (total < 4 || total > h->len - abs) return NULL;
    *n = total - 4;
    return h->d + abs + 4;
}

static const uint8_t *typed(const reg_hive_t *h, uint32_t off, const char sig[2], uint32_t min, uint32_t *n) {
    const uint8_t *c = cell(h, off, n);
    return (c && *n >= min && c[0] == sig[0] && c[1] == sig[1]) ? c : NULL;
}

booto_error_t reg_hive_open(const uint8_t *buf, size_t len, reg_hive_t *h) {
    if (!buf || !h) return BOOTO_ERR_INVALID_ARG;
    if (len < HBIN_START + 32 || memcmp(buf, "regf", 4) != 0) return BOOTO_ERR_CORRUPT_DATA;
    h->d = buf;
    h->len = len;
    return reg_hive_root(h) ? BOOTO_OK : BOOTO_ERR_CORRUPT_DATA;
}

uint32_t reg_hive_root(const reg_hive_t *h) {
    if (!h || !h->d) return 0;
    uint32_t root = rd32(h->d + 0x24), n;
    return typed(h, root, "nk", NK_NAME, &n) ? root : 0;
}

/* Name stored at p (ASCII when comp, else UTF-16LE) into out. */
static void copy_name(const uint8_t *p, uint16_t len, bool comp, char *out, size_t n) {
    size_t chars = comp ? len : len / 2u, j = 0;
    for (size_t i = 0; i < chars && j + 1 < n; i++) {
        unsigned ch = comp ? p[i] : rd16(p + 2 * i);
        out[j++] = (ch >= 0x20 && ch < 0x7F) ? (char)ch : '?';
    }
    if (n) out[j] = '\0';
}

static bool key_name(const reg_hive_t *h, uint32_t key, char *out, size_t n) {
    uint32_t cn;
    const uint8_t *k = typed(h, key, "nk", NK_NAME, &cn);
    if (!k) return false;
    uint16_t len = rd16(k + 0x48);
    if (len > cn - NK_NAME) return false;
    copy_name(k + NK_NAME, len, rd16(k + 2) & KEY_COMP_NAME, out, n);
    return true;
}

/* i-th entry of a subkey list (following one level of "ri"), or 0. */
static uint32_t list_at(const reg_hive_t *h, uint32_t list, uint32_t i, int depth) {
    uint32_t n;
    const uint8_t *l = cell(h, list, &n);
    if (!l || n < 4) return 0;
    uint16_t count = rd16(l + 2);
    bool hashed = (l[0] == 'l' && (l[1] == 'f' || l[1] == 'h'));
    bool plain = (l[0] == 'l' && l[1] == 'i');
    bool indirect = (l[0] == 'r' && l[1] == 'i');
    if (!hashed && !plain && !indirect) return 0;
    uint32_t stride = hashed ? 8u : 4u;
    if ((uint32_t)count > (n - 4) / stride) return 0;
    if (!indirect) return i < count ? rd32(l + 4 + i * stride) : 0;
    if (depth > 0) return 0;
    for (uint32_t s = 0; s < count; s++) {
        uint32_t sub = rd32(l + 4 + s * 4), sn;
        const uint8_t *sl = cell(h, sub, &sn);
        if (!sl || sn < 4) return 0;
        uint16_t c = rd16(sl + 2);
        if (i < c) return list_at(h, sub, i, depth + 1);
        i -= c;
    }
    return 0;
}

uint32_t reg_hive_subkey_at(const reg_hive_t *h, uint32_t key, uint32_t i, char *name, size_t n) {
    uint32_t cn;
    const uint8_t *k = typed(h, key, "nk", NK_NAME, &cn);
    if (!k || i >= rd32(k + 0x14)) return 0;
    uint32_t child = list_at(h, rd32(k + 0x1C), i, 0);
    if (!child || !key_name(h, child, name ? name : (char[1]){0}, name ? n : 1)) return 0;
    return child;
}

uint32_t reg_hive_subkey(const reg_hive_t *h, uint32_t key, const char *name) {
    if (!name) return 0;
    char cur[MAX_NAME];
    for (uint32_t i = 0;; i++) {
        uint32_t child = reg_hive_subkey_at(h, key, i, cur, sizeof(cur));
        if (!child) return 0;
        if (strcasecmp(cur, name) == 0) return child;
    }
}

bool reg_hive_value(const reg_hive_t *h, uint32_t key, const char *name, uint32_t *type, const uint8_t **data,
                    uint32_t *len) {
    uint32_t cn;
    const uint8_t *k = typed(h, key, "nk", NK_NAME, &cn);
    if (!k || !name) return false;
    uint32_t count = rd32(k + 0x24), ln;
    if (count == 0) return false;
    const uint8_t *list = cell(h, rd32(k + 0x28), &ln);
    if (!list || count > ln / 4) return false;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t vn;
        const uint8_t *v = typed(h, rd32(list + 4 * i), "vk", VK_NAME, &vn);
        if (!v) continue;
        uint16_t nlen = rd16(v + 2);
        if (nlen > vn - VK_NAME) continue;
        char cur[MAX_NAME];
        copy_name(v + VK_NAME, nlen, rd16(v + 0x10) & VALUE_COMP_NAME, cur, sizeof(cur));
        if (strcasecmp(cur, name) != 0) continue;
        uint32_t size = rd32(v + 4), off = rd32(v + 8);
        if (type) *type = rd32(v + 0x0C);
        if (size & 0x80000000u) {               // data of up to 4 bytes kept in the offset field
            size &= 0x7FFFFFFFu;
            if (size > 4) return false;
            *data = v + 8;
            *len = size;
            return true;
        }
        uint32_t dn;
        const uint8_t *d = cell(h, off, &dn);
        if (!d || size > dn) return false;      // shortcut: "db" big-data cells (> 16 KiB) are not followed
        *data = d;
        *len = size;
        return true;
    }
    return false;
}

bool reg_hive_value_name_at(const reg_hive_t *h, uint32_t key, uint32_t i, char *name, size_t n) {
    uint32_t cn, ln, vn;
    const uint8_t *k = typed(h, key, "nk", NK_NAME, &cn);
    if (!k || !name || n == 0) return false;
    uint32_t count = rd32(k + 0x24);
    if (i >= count) return false;
    const uint8_t *list = cell(h, rd32(k + 0x28), &ln);
    if (!list || count > ln / 4) return false;
    name[0] = '\0';
    const uint8_t *v = typed(h, rd32(list + 4 * i), "vk", VK_NAME, &vn);
    uint16_t nlen = v ? rd16(v + 2) : 0;
    if (v && nlen <= vn - VK_NAME) copy_name(v + VK_NAME, nlen, rd16(v + 0x10) & VALUE_COMP_NAME, name, n);
    return true;  // a broken entry gives "", so the caller keeps iterating
}

bool reg_hive_dword(const reg_hive_t *h, uint32_t key, const char *name, uint32_t *out) {
    uint32_t type, len;
    const uint8_t *d;
    if (!reg_hive_value(h, key, name, &type, &d, &len) || type != REG_DWORD || len < 4) return false;
    *out = rd32(d);
    return true;
}

bool reg_hive_string(const reg_hive_t *h, uint32_t key, const char *name, char *out, size_t n) {
    uint32_t type, len;
    const uint8_t *d;
    if (!out || n == 0 || !reg_hive_value(h, key, name, &type, &d, &len)) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    size_t j = 0;
    for (uint32_t i = 0; i + 1 < len && j + 1 < n; i += 2) {
        unsigned ch = rd16(d + i);
        if (ch == 0) break;
        out[j++] = (ch >= 0x20 && ch < 0x7F) ? (char)ch : '?';
    }
    out[j] = '\0';
    return true;
}
