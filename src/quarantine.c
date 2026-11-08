/**
 * @file quarantine.c
 * @brief Stored ZIP with ZipCrypto (APPNOTE 6.1): two passes per file, CRC first, so no data descriptor is needed.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "quarantine.h"
#include "crypto_utils.h"
#include "logger.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHUNK 65536
#define ZIP32_LIMIT 0xFFFFFFFFull

typedef struct {
    char name[224];
    uint32_t crc, size, offset;
} q_entry_t;

struct quarantine {
    char dir[256];
    char path[512];
    int fd;
    uint64_t off;
    uint16_t dos_time, dos_date;
    int count;
    q_entry_t e[QUARANTINE_MAX_FILES];
};

typedef struct { uint32_t k0, k1, k2; } zc_keys_t;

static uint32_t crc_byte(uint32_t crc, uint8_t b) { return crc32_update(crc, &b, 1); }

static void zc_update(zc_keys_t *k, uint8_t p) {
    k->k0 = crc_byte(k->k0, p);
    k->k1 = (k->k1 + (k->k0 & 0xFFu)) * 134775813u + 1u;
    k->k2 = crc_byte(k->k2, (uint8_t)(k->k1 >> 24));
}

static void zc_init(zc_keys_t *k) {
    k->k0 = 0x12345678u; k->k1 = 0x23456789u; k->k2 = 0x34567890u;
    for (const char *p = QUARANTINE_PASSWORD; *p; p++) zc_update(k, (uint8_t)*p);
}

static void zc_encrypt(zc_keys_t *k, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint32_t t = (k->k2 | 2u) & 0xFFFFu;
        uint8_t plain = buf[i];
        buf[i] = (uint8_t)(plain ^ (uint8_t)((t * (t ^ 1u)) >> 8));
        zc_update(k, plain);
    }
}

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, v & 0xFFFFu); put16(p + 2, v >> 16); }

static bool write_all(int fd, const uint8_t *b, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, b, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        b += w;
        n -= (size_t)w;
    }
    return true;
}

static ssize_t read_full(int fd, uint8_t *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

quarantine_t *quarantine_open(const char *dir) {
    if (!dir) return NULL;
    quarantine_t *q = calloc(1, sizeof(*q));
    if (!q) return NULL;
    snprintf(q->dir, sizeof(q->dir), "%.255s", dir);
    q->fd = -1;
    return q;
}

/* "<prefix>/<rel>.malware" with only [A-Za-z0-9._-/] and no ".." component, so unzipping cannot escape. */
static void entry_name(char *out, size_t len, const char *prefix, const char *rel) {
    while (*rel == '/') rel++;
    snprintf(out, len, "%.40s/%.170s.malware", prefix, rel);
    for (char *c = out; *c; c++)
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '_' && *c != '-' && *c != '/') *c = '_';
    for (char *c = strstr(out, ".."); c; c = strstr(c, "..")) c[0] = c[1] = '_';
}

static booto_error_t create_zip(quarantine_t *q) {
    time_t now = time(NULL);
    struct tm tm;
    if (!gmtime_r(&now, &tm)) return BOOTO_ERR_IO;
    q->dos_time = (uint16_t)((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    q->dos_date = (uint16_t)(((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
    snprintf(q->path, sizeof(q->path), "%.255s/booto-quarantine-%s.zip", q->dir, stamp);
    q->fd = open(q->path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (q->fd < 0) {
        LOG_ERROR("Cannot create quarantine archive %s: %s", q->path, strerror(errno));
        return BOOTO_ERR_IO;
    }
    LOG_INFO("Quarantine archive: %s (password \"%s\")", q->path, QUARANTINE_PASSWORD);
    return BOOTO_OK;
}

/* Resolves path and checks it stays inside root; rel points into resolved. */
static booto_error_t resolve_inside(const char *root, const char *path, char resolved[PATH_MAX], const char **rel) {
    char rroot[PATH_MAX];
    if (!realpath(path, resolved)) return errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    if (!root) {
        const char *slash = strrchr(resolved, '/');
        *rel = slash ? slash + 1 : resolved;
        return BOOTO_OK;
    }
    if (!realpath(root, rroot)) return BOOTO_ERR_IO;
    size_t n = strcmp(rroot, "/") == 0 ? 0 : strlen(rroot);
    if (strncmp(resolved, rroot, n) != 0 || resolved[n] != '/') return BOOTO_ERR_PERMISSION_DENIED;
    *rel = resolved + n;
    return BOOTO_OK;
}

static booto_error_t copy_encrypted(quarantine_t *q, int in, uint32_t size, uint32_t crc, uint8_t *buf) {
    zc_keys_t k;
    zc_init(&k);
    uint8_t hdr[12];
    if (getrandom(hdr, 11, 0) != 11) {
        for (int i = 0; i < 11; i++) hdr[i] = (uint8_t)rand();  /* header bytes need only vary, not be secret */
    }
    hdr[11] = (uint8_t)(crc >> 24);
    zc_encrypt(&k, hdr, sizeof(hdr));
    if (!write_all(q->fd, hdr, sizeof(hdr))) return BOOTO_ERR_IO;

    uint32_t left = size;
    while (left > 0) {
        size_t want = left < CHUNK ? left : CHUNK;
        ssize_t r = read_full(in, buf, want);
        if (r != (ssize_t)want) return BOOTO_ERR_IO;  /* file changed between passes */
        zc_encrypt(&k, buf, want);
        if (!write_all(q->fd, buf, want)) return BOOTO_ERR_IO;
        left -= (uint32_t)want;
    }
    return BOOTO_OK;
}

booto_error_t quarantine_add(quarantine_t *q, const char *prefix, const char *root, const char *path, uint64_t max_bytes) {
    if (!q || !prefix || !path) return BOOTO_ERR_INVALID_ARG;
    if (q->fd == -2) return BOOTO_ERR_IO;
    if (max_bytes > QUARANTINE_MAX_ITEM) max_bytes = QUARANTINE_MAX_ITEM;

    char resolved[PATH_MAX];
    const char *rel = NULL;
    booto_error_t e = resolve_inside(root, path, resolved, &rel);
    if (e == BOOTO_ERR_PERMISSION_DENIED) LOG_WARN("Quarantine: %s resolves outside the target, not exported", path);
    if (e != BOOTO_OK) return e;

    char name[224];
    entry_name(name, sizeof(name), prefix, rel);
    for (int i = 0; i < q->count; i++)
        if (strcmp(q->e[i].name, name) == 0) return BOOTO_OK;
    if (q->count >= QUARANTINE_MAX_FILES) return BOOTO_ERR_IO;

    int in = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) return BOOTO_ERR_IO;
    struct stat st;
    uint8_t *buf = malloc(CHUNK);
    if (!buf || fstat(in, &st) != 0 || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
        free(buf);
        close(in);
        return buf ? BOOTO_ERR_IO : BOOTO_ERR_OUT_OF_MEMORY;
    }

    uint32_t crc = 0xFFFFFFFFu;
    uint64_t size = 0;
    while (size < max_bytes) {
        uint64_t want = max_bytes - size < CHUNK ? max_bytes - size : CHUNK;
        ssize_t r = read_full(in, buf, (size_t)want);
        if (r < 0) { e = BOOTO_ERR_IO; break; }
        crc = crc32_update(crc, buf, (size_t)r);
        size += (uint64_t)r;
        if ((uint64_t)r < want) break;
    }
    crc = ~crc;
    size_t nlen = strlen(name);
    /* keep room for this entry's central record and the end record so the archive stays ZIP32 */
    if (e == BOOTO_OK && q->off + 30 + nlen + 12 + size + (uint64_t)(q->count + 1) * (46 + 224) + 22 > ZIP32_LIMIT) {
        LOG_WARN("Quarantine archive full (4 GiB): %s not exported", path);
        e = BOOTO_ERR_IO;
    }
    if (e == BOOTO_OK && q->fd < 0) e = create_zip(q);
    if (e == BOOTO_OK && lseek(in, 0, SEEK_SET) != 0) e = BOOTO_ERR_IO;

    if (e == BOOTO_OK) {
        uint8_t lh[30] = {0};
        put32(lh, 0x04034b50u);
        put16(lh + 4, 20);
        put16(lh + 6, 0x0001);                        /* encrypted */
        put16(lh + 10, q->dos_time);
        put16(lh + 12, q->dos_date);
        put32(lh + 14, crc);
        put32(lh + 18, (uint32_t)size + 12);
        put32(lh + 22, (uint32_t)size);
        put16(lh + 26, (uint32_t)nlen);
        if (!write_all(q->fd, lh, sizeof(lh)) || !write_all(q->fd, (const uint8_t *)name, nlen)) e = BOOTO_ERR_IO;
        if (e == BOOTO_OK) e = copy_encrypted(q, in, (uint32_t)size, crc, buf);
        if (e == BOOTO_OK) {
            q_entry_t *en = &q->e[q->count++];
            snprintf(en->name, sizeof(en->name), "%s", name);
            en->crc = crc;
            en->size = (uint32_t)size;
            en->offset = (uint32_t)q->off;
            q->off += 30 + nlen + 12 + size;
        } else if (ftruncate(q->fd, (off_t)q->off) != 0 || lseek(q->fd, (off_t)q->off, SEEK_SET) < 0) {
            LOG_ERROR("Quarantine archive %s could not drop a partial entry", q->path);
            close(q->fd);
            q->fd = -2;  /* unusable: later adds fail, close reports -1 */
        }
    }
    free(buf);
    close(in);
    if (e == BOOTO_OK) LOG_INFO("Quarantined %s as %s (%" PRIu64 " bytes)", path, name, size);
    return e;
}

int quarantine_close(quarantine_t *q, char *zip_path, size_t zip_path_len) {
    if (zip_path && zip_path_len) zip_path[0] = '\0';
    if (!q) return -1;
    int rc = q->count;
    if (q->fd == -2) rc = -1;
    if (q->fd >= 0) {
        uint64_t cd_start = q->off;
        bool ok = true;
        for (int i = 0; i < q->count && ok; i++) {
            const q_entry_t *en = &q->e[i];
            size_t nlen = strlen(en->name);
            uint8_t ch[46] = {0};
            put32(ch, 0x02014b50u);
            put16(ch + 4, 0x031E);                    /* made by Unix, spec 3.0: external attrs hold the mode */
            put16(ch + 6, 20);
            put16(ch + 8, 0x0001);
            put16(ch + 12, q->dos_time);
            put16(ch + 14, q->dos_date);
            put32(ch + 16, en->crc);
            put32(ch + 20, en->size + 12);
            put32(ch + 24, en->size);
            put16(ch + 28, (uint32_t)nlen);
            put32(ch + 38, (uint32_t)(S_IFREG | 0400) << 16);
            put32(ch + 42, en->offset);
            ok = write_all(q->fd, ch, sizeof(ch)) && write_all(q->fd, (const uint8_t *)en->name, nlen);
            q->off += 46 + nlen;
        }
        uint8_t eocd[22] = {0};
        put32(eocd, 0x06054b50u);
        put16(eocd + 8, (uint32_t)q->count);
        put16(eocd + 10, (uint32_t)q->count);
        put32(eocd + 12, (uint32_t)(q->off - cd_start));
        put32(eocd + 16, (uint32_t)cd_start);
        ok = ok && write_all(q->fd, eocd, sizeof(eocd)) && fsync(q->fd) == 0 && fchmod(q->fd, 0400) == 0;
        if (close(q->fd) != 0) ok = false;
        if (!ok) {
            LOG_ERROR("Failed to finish quarantine archive %s", q->path);
            rc = -1;
        } else if (zip_path && zip_path_len) {
            snprintf(zip_path, zip_path_len, "%s", q->path);
        }
    }
    free(q);
    return rc;
}
