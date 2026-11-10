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

/**
 * @brief SHA-256 of the first `bytes` bytes of a file or block device (fewer if it is shorter).
 * @return false if it cannot be opened or nothing could be read.
 */
bool sha256_head_hex(const char *path, size_t bytes, char hex_out[65]);

/**
 * @brief CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320) over data, continuing from crc.
 *        No pre/post inversion: start with 0xFFFFFFFF and invert the final value.
 */
uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len);

/**
 * @brief Shannon entropy in bits per byte of n bytes whose byte-value counts are hist (0 when n == 0).
 */
double entropy_bits(const size_t hist[256], size_t n);

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[64];
} md5_ctx_t;

/**
 * @brief MD5 (RFC 1321). Only for matching dpkg's md5sums lists; never trust it alone as a security hash.
 */
void md5_init(md5_ctx_t *ctx);
void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len);
void md5_final(md5_ctx_t *ctx, uint8_t hash[16]);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_CRYPTO_UTILS_H */
