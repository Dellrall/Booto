/**
 * @file crypto_utils.c
 * @brief Implementation of standalone SHA-256 hashing.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "crypto_utils.h"

#include <stdio.h>
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx) {
    if (!ctx) return;
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data) return;
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if (ctx->count % 64 == 0)
            sha256_transform(ctx, ctx->buffer);
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    if (!ctx || !hash) return;
    uint32_t i = (uint32_t)(ctx->count % 64);

    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0x00;
    }

    uint64_t bit_count = ctx->count * 8;
    for (size_t j = 0; j < 8; j++) {
        ctx->buffer[63 - j] = (uint8_t)(bit_count >> (j * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    for (size_t k = 0; k < 4; ++k) {
        for (size_t j = 0; j < 8; j++) {
            hash[j * 4 + k] = (uint8_t)((ctx->state[j] >> (24 - k * 8)) & 0x000000ff);
        }
    }
}

uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return crc;
}

void sha256_buffer_hex(const uint8_t *data, size_t len, char hex_out[65]) {
    if (!hex_out) return;
    uint8_t hash[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; i++) {
        snprintf(&hex_out[i * 2], 3, "%02x", hash[i]);
    }
    hex_out[64] = '\0';
}

bool sha256_file_hex(const char *file_path, char hex_out[65]) {
    if (!file_path || !hex_out) return false;

    FILE *fp = fopen(file_path, "rb");
    if (!fp) return false;

    sha256_ctx_t ctx;
    sha256_init(&ctx);

    uint8_t buf[8192];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) {
        sha256_update(&ctx, buf, bytes_read);
    }
    fclose(fp);

    uint8_t hash[32];
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; i++) {
        snprintf(&hex_out[i * 2], 3, "%02x", hash[i]);
    }
    hex_out[64] = '\0';
    return true;
}

/* MD5 (RFC 1321): only to compare against dpkg's md5sums lists, never as a security hash on its own. */
static const uint32_t MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
static const uint8_t MD5_S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                  5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static void md5_block(uint32_t st[4], const uint8_t blk[64]) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)blk[i * 4] | (uint32_t)blk[i * 4 + 1] << 8 | (uint32_t)blk[i * 4 + 2] << 16 |
               (uint32_t)blk[i * 4 + 3] << 24;
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) % 16; }
        else             { f = c ^ (b | ~d);       g = (7 * i) % 16; }
        f += a + MD5_K[i] + m[g];
        a = d;
        d = c;
        c = b;
        b += (f << MD5_S[i]) | (f >> (32 - MD5_S[i]));
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

void md5_init(md5_ctx_t *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->count = 0;
}

void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t used = (size_t)(ctx->count % 64);
    ctx->count += len;
    while (len > 0) {
        size_t n = 64 - used < len ? 64 - used : len;
        memcpy(ctx->buffer + used, data, n);
        used += n;
        data += n;
        len -= n;
        if (used == 64) {
            md5_block(ctx->state, ctx->buffer);
            used = 0;
        }
    }
}

void md5_final(md5_ctx_t *ctx, uint8_t hash[16]) {
    uint64_t bits = ctx->count * 8;
    static const uint8_t pad[64] = {0x80};
    size_t used = (size_t)(ctx->count % 64);
    md5_update(ctx, pad, used < 56 ? 56 - used : 120 - used);
    uint8_t len_le[8];
    for (int i = 0; i < 8; i++) len_le[i] = (uint8_t)(bits >> (8 * i));
    md5_update(ctx, len_le, 8);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) hash[i * 4 + j] = (uint8_t)(ctx->state[i] >> (8 * j));
}
