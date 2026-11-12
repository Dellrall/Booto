/**
 * @file disk_image.c
 * @brief Read-only raw disk imaging with an inline SHA-256 and a bad-block log.
 */
#include "disk_image.h"
#include "crypto_utils.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IMG_CHUNK (1u << 20)
#define IMG_BLOCK 4096u

static bool write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n, len -= (size_t)n;
    }
    return true;
}

// Fills buf[0..len) from offset; a failed read retries per 4 KiB block and zero-fills what stays unreadable.
static void read_chunk(int fd, uint8_t *buf, size_t len, off_t off, FILE **log, const char *dst, uint64_t *bad) {
    ssize_t n = pread(fd, buf, len, off);
    if (n == (ssize_t)len) return;
    for (size_t pos = 0; pos < len; pos += IMG_BLOCK) {
        size_t blk = len - pos < IMG_BLOCK ? len - pos : IMG_BLOCK;
        if (pread(fd, buf + pos, blk, off + (off_t)pos) == (ssize_t)blk) continue;
        memset(buf + pos, 0, blk);
        *bad += blk;
        if (!*log) {
            char path[600];
            snprintf(path, sizeof(path), "%.500s.log", dst);
            *log = fopen(path, "w");
            if (*log) fprintf(*log, "# unreadable ranges, zero-filled in the image: offset length (bytes)\n");
        }
        if (*log) fprintf(*log, "%lld %zu\n", (long long)(off + (off_t)pos), blk);
    }
}

booto_error_t disk_image_acquire(const char *src, const char *dst, disk_image_result_t *res) {
    if (!src || !dst || !res) return BOOTO_ERR_INVALID_ARG;
    memset(res, 0, sizeof(*res));
    int in = open(src, O_RDONLY | O_CLOEXEC);  // never O_RDWR: the evidence stays untouched
    if (in < 0) return errno == EACCES ? BOOTO_ERR_PERMISSION_DENIED : BOOTO_ERR_NOT_FOUND;
    off_t size = lseek(in, 0, SEEK_END);
    int out = size >= 0 ? open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600) : -1;  // never overwrite
    uint8_t *buf = out >= 0 ? malloc(IMG_CHUNK) : NULL;
    if (!buf) {
        if (out >= 0) close(out), unlink(dst);
        close(in);
        return out < 0 ? BOOTO_ERR_IO : BOOTO_ERR_OUT_OF_MEMORY;
    }
    sha256_ctx_t sha;
    sha256_init(&sha);
    FILE *log = NULL;
    bool ok = true;
    for (off_t off = 0; ok && off < size; off += IMG_CHUNK) {
        size_t len = (uint64_t)(size - off) < IMG_CHUNK ? (size_t)(size - off) : IMG_CHUNK;
        read_chunk(in, buf, len, off, &log, dst, &res->bad_bytes);
        sha256_update(&sha, buf, len);
        ok = write_all(out, buf, len);
        res->bytes += len;
        if (res->bytes % (1ull << 30) == 0) LOG_INFO("Imaged %llu GiB of %s", (unsigned long long)(res->bytes >> 30), src);
    }
    free(buf);
    close(in);
    if (log) fclose(log);
    ok = fsync(out) == 0 && ok;
    ok = close(out) == 0 && ok;
    if (!ok) return BOOTO_ERR_IO;  // partial image kept for the examiner, but no .sha256 vouches for it

    uint8_t digest[32];
    sha256_final(&sha, digest);
    for (int i = 0; i < 32; i++) snprintf(res->sha256 + i * 2, 3, "%02x", digest[i]);
    char path[600];
    snprintf(path, sizeof(path), "%.500s.sha256", dst);
    FILE *fp = fopen(path, "w");
    const char *base = strrchr(dst, '/');
    ok = fp && fprintf(fp, "%s  %s\n", res->sha256, base ? base + 1 : dst) > 0;
    if (fp) ok = fclose(fp) == 0 && ok;
    return ok ? BOOTO_OK : BOOTO_ERR_IO;
}
