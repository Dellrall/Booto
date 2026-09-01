/**
 * @file crypto_utils.h
 * @brief Self-contained, zero-dependency SHA-256 cryptographic hash implementation.
 */
#ifndef BOOTO_CRYPTO_UTILS_H
#define BOOTO_CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx_t;

/**
 * @brief Initialize SHA-256 context.
 */
void sha256_init(sha256_ctx_t *ctx);

/**
 * @brief Update SHA-256 context with input bytes.
 */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize SHA-256 calculation and output 32-byte digest.
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]);

/**
 * @brief Compute SHA-256 of a memory buffer and return hex string (64 chars + null).
 */
void sha256_buffer_hex(const uint8_t *data, size_t len, char hex_out[65]);

/**
 * @brief Compute SHA-256 of a file path and return hex string (64 chars + null).
 */
bool sha256_file_hex(const char *file_path, char hex_out[65]);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_CRYPTO_UTILS_H */
