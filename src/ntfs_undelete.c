/**
 * @file ntfs_undelete.c
 * @brief Bounded NTFS MFT parser and deleted-file recovery, read straight from the raw device (O_RDONLY).
 */
#include "ntfs_undelete.h"
#include "logger.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ATTR_LIST 0x20u
#define ATTR_FILE_NAME 0x30u
#define ATTR_DATA 0x80u
#define ATTR_END 0xFFFFFFFFu
#define COPY_CHUNK (1u << 20)

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

/* Runlist: header byte = offset size << 4 | length size; offsets are signed and relative to the previous run. */
static bool decode_runs(const uint8_t *p, const uint8_t *end, ntfs_record_t *out) {
    int64_t lcn = 0;
    while (p < end && *p) {
        unsigned ls = *p & 0xFu, os = *p >> 4;
        p++;
        if (ls == 0 || ls > 8 || os > 8 || (size_t)(end - p) < ls + os || out->nruns == NTFS_MAX_RUNS) return false;
        uint64_t len = 0, u = 0;
        for (unsigned i = 0; i < ls; i++) len |= (uint64_t)p[i] << (8 * i);
        p += ls;
        ntfs_run_t *r = &out->runs[out->nruns++];
        r->len = len;
        if (os == 0) {
            r->lcn = -1;
            continue;
        }
        for (unsigned i = 0; i < os; i++) u |= (uint64_t)p[i] << (8 * i);
        if (os < 8 && (p[os - 1] & 0x80)) u |= ~0ULL << (8 * os);
        p += os;
        int64_t d = (int64_t)u;
        if ((d > 0 && lcn > INT64_MAX - d) || (d < 0 && lcn + d < 0)) return false;
        lcn += d;
        r->lcn = lcn;
    }
    return true;
}

static void set_name(ntfs_record_t *out, const uint8_t *utf16, size_t n) {
    size_t j = 0;
    for (size_t i = 0; i < n && j < 80; i++) {
        uint16_t c = rd16(utf16 + 2 * i);
        out->name[j++] = c < 128 && (isalnum(c) || c == '.' || c == '-' || c == '_') ? (char)c : '_';
    }
    out->name[j] = '\0';
}

booto_error_t ntfs_parse_record(uint8_t *rec, size_t len, ntfs_record_t *out) {
    if (!rec || !out || len < 512 || len > 4096 || len % 512) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (memcmp(rec, "FILE", 4) != 0) return BOOTO_ERR_CORRUPT_DATA;
    size_t usa = rd16(rec + 4), cnt = rd16(rec + 6);
    if (cnt != len / 512 + 1 || usa + 2 * cnt > 510) return BOOTO_ERR_CORRUPT_DATA;
    for (size_t i = 1; i < cnt; i++) {  // each sector ends in the sequence number; the real bytes live in the array
        uint8_t *tail = rec + i * 512 - 2;
        if (memcmp(tail, rec + usa, 2) != 0) return BOOTO_ERR_CORRUPT_DATA;
        memcpy(tail, rec + usa + 2 * i, 2);
    }
    uint16_t flags = rd16(rec + 0x16);
    out->in_use = flags & 1;
    out->is_dir = flags & 2;
    size_t used = rd32(rec + 0x18), off = rd16(rec + 0x14);
    if (used > len) used = len;
    bool dos_name = false;
    while (off + 16 <= used) {
        const uint8_t *a = rec + off;
        uint32_t type = rd32(a), alen = rd32(a + 4);
        if (type == ATTR_END) break;
        if (alen < 24 || alen > used - off) return BOOTO_ERR_CORRUPT_DATA;
        bool unnamed_data = type == ATTR_DATA && a[9] == 0 && !out->has_data;
        if (type == ATTR_LIST) out->has_attr_list = true;
        if (!a[8]) {  // resident
            uint32_t vlen = rd32(a + 0x10), voff = rd16(a + 0x14);
            if (voff > alen || vlen > alen - voff) return BOOTO_ERR_CORRUPT_DATA;
            const uint8_t *v = a + voff;
            if (type == ATTR_FILE_NAME && vlen >= 0x42 && 0x42u + 2u * v[0x40] <= vlen && (!out->name[0] || dos_name)) {
                set_name(out, v + 0x42, v[0x40]);
                dos_name = v[0x41] == 2;
            }
            if (unnamed_data) out->has_data = out->resident = true, out->data = v, out->data_len = vlen;
        } else if (unnamed_data && alen >= 0x40 && rd64(a + 0x10) == 0) {  // first extent only
            size_t ro = rd16(a + 0x20);
            if (ro >= alen || !decode_runs(a + ro, a + alen, out)) return BOOTO_ERR_CORRUPT_DATA;
            out->has_data = true;
            out->size = rd64(a + 0x30);
        }
        off += alen;
    }
    return BOOTO_OK;
}

static bool write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n, len -= (size_t)n;
    }
    return true;
}

typedef struct {
    int fd;
    uint64_t cs, clusters;
} vol_t;

/* Read @p n bytes at byte @p pos of the stream described by @p r (an MFT or file runlist). */
static bool read_stream(const vol_t *v, const ntfs_record_t *r, uint64_t pos, uint8_t *buf, size_t n) {
    uint64_t base = 0;
    for (size_t i = 0; i < r->nruns && n > 0; i++) {
        uint64_t rlen = r->runs[i].len * v->cs;
        if (pos < base + rlen) {
            size_t take = (size_t)(base + rlen - pos < n ? base + rlen - pos : n);
            if (r->runs[i].lcn < 0) memset(buf, 0, take);
            else if (pread(v->fd, buf, take, (off_t)((uint64_t)r->runs[i].lcn * v->cs + pos - base)) != (ssize_t)take)
                memset(buf, 0, take);  // unreadable sectors come out as zeros, like --acquire
            buf += take, n -= take, pos += take;
        }
        base += rlen;
    }
    return n == 0;
}

static bool runs_fit(const vol_t *v, const ntfs_record_t *r) {
    for (size_t i = 0; i < r->nruns; i++)
        if (r->runs[i].lcn >= 0 && (r->runs[i].len > v->clusters || (uint64_t)r->runs[i].lcn > v->clusters - r->runs[i].len))
            return false;
    return true;
}

/* 1 written, 0 skipped, -1 output write failed (disk full). */
static int recover(const vol_t *v, int dfd, uint64_t idx, const ntfs_record_t *r, uint8_t *chunk) {
    uint64_t size = r->resident ? r->data_len : r->size;
    if (size > NTFS_UNDELETE_MAX_FILE || (!r->resident && !runs_fit(v, r))) return 0;
    char name[128];
    snprintf(name, sizeof(name), "%llu_%s.recovered", (unsigned long long)idx, r->name[0] ? r->name : "noname");
    int fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0400);
    if (fd < 0) return 0;
    bool ok = true;
    if (r->resident) ok = write_all(fd, r->data, r->data_len);
    for (uint64_t pos = 0; ok && !r->resident && pos < size; pos += COPY_CHUNK) {
        size_t n = (size_t)(size - pos < COPY_CHUNK ? size - pos : COPY_CHUNK);
        if (!read_stream(v, r, pos, chunk, n)) break;  // runs end before the size: keep what they hold
        ok = write_all(fd, chunk, n);
    }
    close(fd);
    if (!ok) unlinkat(dfd, name, 0);
    return ok ? 1 : -1;
}

booto_error_t ntfs_undelete(const char *dev, const char *out_dir, ntfs_undelete_result_t *res) {
    if (!dev || !out_dir || !res) return BOOTO_ERR_INVALID_ARG;
    memset(res, 0, sizeof(*res));
    uint8_t bs[512], rec[4096];
    vol_t v = {open(dev, O_RDONLY | O_CLOEXEC), 0, 0};
    if (v.fd < 0) return BOOTO_ERR_IO;
    if (pread(v.fd, bs, sizeof(bs), 0) != (ssize_t)sizeof(bs) || memcmp(bs + 3, "NTFS    ", 8) != 0) {
        close(v.fd);
        return BOOTO_ERR_NOT_FOUND;
    }
    unsigned bps = rd16(bs + 0x0B), spc = bs[0x0D];
    int cpr = (int8_t)bs[0x40];
    v.cs = (uint64_t)bps * spc;
    v.clusters = spc ? rd64(bs + 0x28) / spc : 0;
    uint64_t rs = cpr > 0 ? (uint64_t)cpr * v.cs : (cpr <= -9 && cpr >= -12 ? 1ull << -cpr : 0);
    uint64_t mft_lcn = rd64(bs + 0x30);
    ntfs_record_t mft, r;
    booto_error_t err = BOOTO_ERR_CORRUPT_DATA;
    int dfd = -1;
    uint8_t *chunk = NULL;
    if (bps < 512 || bps > 4096 || (bps & (bps - 1)) || !spc || spc > 128 || (spc & (spc - 1)) || rs < 512 ||
        rs > 4096 || mft_lcn >= v.clusters)
        goto out;
    if (pread(v.fd, rec, rs, (off_t)(mft_lcn * v.cs)) != (ssize_t)rs || ntfs_parse_record(rec, rs, &mft) != BOOTO_OK ||
        !mft.has_data || mft.resident || !runs_fit(&v, &mft))
        goto out;
    err = BOOTO_ERR_IO;
    dfd = open(out_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    chunk = malloc(COPY_CHUNK);
    if (dfd < 0 || !chunk) goto out;
    err = BOOTO_OK;
    for (uint64_t i = 0; (i + 1) * rs <= mft.size && read_stream(&v, &mft, i * rs, rec, rs); i++) {
        res->records++;
        if (ntfs_parse_record(rec, rs, &r) != BOOTO_OK || r.in_use || r.is_dir || !r.has_data) continue;
        res->deleted++;
        int w = r.has_attr_list ? 0 : recover(&v, dfd, i, &r, chunk);
        if (w < 0) {
            LOG_ERROR("Writing recovered file %llu to %s failed; stopping", (unsigned long long)i, out_dir);
            err = BOOTO_ERR_IO;
            break;
        }
        if (w) res->recovered++;
        else res->skipped++;
    }
out:
    free(chunk);
    if (dfd >= 0) close(dfd);
    close(v.fd);
    return err;
}
