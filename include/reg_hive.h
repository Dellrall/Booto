/**
 * @file reg_hive.h
 * @brief Read-only Windows registry hive (regf) reader: keys, subkeys and values, every offset bounds-checked.
 */
#ifndef BOOTO_REG_HIVE_H
#define BOOTO_REG_HIVE_H

#include "booto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REG_SZ        1u
#define REG_EXPAND_SZ 2u
#define REG_BINARY    3u
#define REG_DWORD     4u

typedef struct {
    const uint8_t *d;
    size_t len;
} reg_hive_t;

/* Checks the "regf" base block. The buffer is borrowed; it must outlive h. */
booto_error_t reg_hive_open(const uint8_t *buf, size_t len, reg_hive_t *h);
/* Key handles are cell offsets; 0 means none. */
uint32_t reg_hive_root(const reg_hive_t *h);
/* Child key by name, case-insensitive (ASCII). */
uint32_t reg_hive_subkey(const reg_hive_t *h, uint32_t key, const char *name);
/* i-th child: its handle, name in `name` (non-ASCII characters become '?'). 0 when i is past the end. */
uint32_t reg_hive_subkey_at(const reg_hive_t *h, uint32_t key, uint32_t i, char *name, size_t n);
/* Value by name (case-insensitive; "" is the default value). Data points into the hive. */
bool reg_hive_value(const reg_hive_t *h, uint32_t key, const char *name, uint32_t *type, const uint8_t **data,
                    uint32_t *len);
/* REG_DWORD value, or false. */
bool reg_hive_dword(const reg_hive_t *h, uint32_t key, const char *name, uint32_t *out);
/* REG_SZ / REG_EXPAND_SZ value as ASCII ('?' for other characters), or false. */
bool reg_hive_string(const reg_hive_t *h, uint32_t key, const char *name, char *out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_REG_HIVE_H */
