/**
 * @file inspect.c
 * @brief Captures one flagged file's bytes, hashes and section map while the target is still mounted.
 */
#include "inspect.h"
#include "crypto_utils.h"
#include "elf_analyzer.h"
#include "quarantine.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK (64u * 1024)
#define SCN_MEM_EXECUTE 0x20000000u
#define SHF_EXEC        0x4u
#define SHT_NOBITS_     8u

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static const char *machine_name(uint16_t m) {
    switch (m) {
        case 0x8664: case 62: return "x86-64";
        case 0x14c: case 3: return "i386";
        case 0xaa64: case 183: return "ARM64";
        case 0x1c0: case 0x1c4: case 40: return "ARM";
        case 0x5064: case 243: return "RISC-V";
        default: return "unknown machine";
    }
}

static void add_region(inspect_sample_t *s, const char *name, uint64_t off, uint64_t size, bool exec) {
    s->regions_total++;
    if (s->region_count >= INSPECT_MAX_REGIONS) return;
    inspect_region_t *r = &s->regions[s->region_count++];
    snprintf(r->name, sizeof(r->name), "%s", name);
    r->offset = off;
    r->size = size;
    r->exec = exec;
}

/* PE headers sit at the front of the file, so the sample holds them; every read is checked against s->len. */
static bool map_pe(inspect_sample_t *s) {
    const uint8_t *d = s->data;
    if (s->len < 0x40 || d[0] != 'M' || d[1] != 'Z') return false;
    uint32_t pe = rd32(d + 0x3c);
    if (pe > s->len - 24 || memcmp(d + pe, "PE\0\0", 4) != 0) return false;
    uint16_t machine = rd16(d + pe + 4), nsec = rd16(d + pe + 6), opt = rd16(d + pe + 20);
    uint16_t magic = s->len - (pe + 24) >= 2 ? rd16(d + pe + 24) : 0;
    snprintf(s->format, sizeof(s->format), "%s %s", magic == 0x20b ? "PE32+" : "PE32", machine_name(machine));
    size_t tab = (size_t)pe + 24 + opt;
    for (uint16_t i = 0; i < nsec && tab <= s->len && (s->len - tab) / 40 > i; i++) {
        const uint8_t *h = d + tab + (size_t)i * 40;
        char name[9] = {0};
        for (int k = 0; k < 8 && h[k]; k++) name[k] = (h[k] >= 0x20 && h[k] < 0x7f) ? (char)h[k] : '?';
        add_region(s, name[0] ? name : "(unnamed)", rd32(h + 20), rd32(h + 16), (rd32(h + 36) & SCN_MEM_EXECUTE) != 0);
    }
    return true;
}

/* ELF section headers usually sit at the end of the file, past the sample: parse the whole file. */
static bool map_elf(inspect_sample_t *s, const char *path) {
    if (s->len < 4 || memcmp(s->data, "\x7f" "ELF", 4) != 0) return false;
    elf_binary_info_t *e = calloc(1, sizeof(*e));
    if (!e) return true;
    if (elf_parse_file(path, e) == BOOTO_OK) {
        snprintf(s->format, sizeof(s->format), "ELF%s %s", e->is_64bit ? "64" : "32", machine_name(e->machine_type));
        for (int i = 0; i < e->section_count && i < MAX_ELF_SECTIONS; i++) {
            const elf_section_info_t *c = &e->sections[i];
            if (c->type == 0 || c->type == SHT_NOBITS_ || c->size == 0) continue;
            add_region(s, c->name[0] ? c->name : "(unnamed)", c->offset, c->size, (c->flags & SHF_EXEC) != 0);
        }
    } else {
        snprintf(s->format, sizeof(s->format), "ELF (section table unreadable)");
    }
    elf_free_info(e);
    free(e);
    return true;
}

static bool map_mbr(inspect_sample_t *s) {
    if (s->len < 512 || s->data[510] != 0x55 || s->data[511] != 0xAA) return false;
    snprintf(s->format, sizeof(s->format), "MBR boot sector");
    add_region(s, "boot code", 0, 446, true);
    add_region(s, "partition table", 446, 64, false);
    add_region(s, "signature 55AA", 510, 2, false);
    if (s->hashed_len > 512) add_region(s, "post-MBR gap", 512, s->hashed_len - 512, false);
    return true;
}

/* Entropy of each region over the bytes the capture read (offsets past hashed_len count nothing). */
static void region_entropy(inspect_sample_t *s, int fd, uint8_t *buf) {
    for (int i = 0; i < s->region_count; i++) {
        inspect_region_t *r = &s->regions[i];
        size_t hist[256] = {0}, n = 0;
        uint64_t end = r->offset + r->size < r->offset ? s->hashed_len : r->offset + r->size;
        if (end > s->hashed_len) end = s->hashed_len;
        for (uint64_t off = r->offset; off < end;) {
            size_t want = end - off < CHUNK ? (size_t)(end - off) : CHUNK;
            ssize_t got = pread(fd, buf, want, (off_t)off);
            if (got <= 0) break;
            for (ssize_t k = 0; k < got; k++) hist[buf[k]]++;
            n += (size_t)got;
            off += (uint64_t)got;
        }
        r->entropy = entropy_bits(hist, n);
    }
}

booto_error_t inspect_capture(const char *root, const char *path, uint64_t max_bytes, inspect_sample_t *out) {
    if (!path || !out) return BOOTO_ERR_INVALID_ARG;
    char resolved[PATH_MAX];
    const char *rel;
    booto_error_t e = quarantine_resolve_inside(root, path, resolved, &rel);
    if (e != BOOTO_OK) return e;
    int fd = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return BOOTO_ERR_IO;
    struct stat st;
    uint8_t *buf = malloc(CHUNK);
    if (!buf || fstat(fd, &st) != 0 || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
        free(buf);
        close(fd);
        return buf ? BOOTO_ERR_IO : BOOTO_ERR_OUT_OF_MEMORY;
    }

    memset(out, 0, offsetof(inspect_sample_t, data));
    snprintf(out->path, sizeof(out->path), "%.255s", path);
    off_t end = S_ISBLK(st.st_mode) ? lseek(fd, 0, SEEK_END) : st.st_size;
    out->file_size = end > 0 ? (uint64_t)end : 0;
    sha256_ctx_t sh;
    md5_ctx_t m5;
    sha256_init(&sh);
    md5_init(&m5);
    while (out->hashed_len < max_bytes) {
        uint64_t left = max_bytes - out->hashed_len;
        ssize_t got = pread(fd, buf, left < CHUNK ? (size_t)left : CHUNK, (off_t)out->hashed_len);
        if (got < 0) {
            free(buf);
            close(fd);
            return BOOTO_ERR_IO;
        }
        if (got == 0) break;
        if (out->len < INSPECT_MAX_BYTES) {
            size_t keep = INSPECT_MAX_BYTES - out->len < (size_t)got ? INSPECT_MAX_BYTES - out->len : (size_t)got;
            memcpy(out->data + out->len, buf, keep);
            out->len += keep;
        }
        sha256_update(&sh, buf, (size_t)got);
        md5_update(&m5, buf, (size_t)got);
        out->hashed_len += (uint64_t)got;
    }
    uint8_t h[32];
    sha256_final(&sh, h);
    for (int i = 0; i < 32; i++) snprintf(out->sha256 + i * 2, 3, "%02x", h[i]);
    md5_final(&m5, h);
    for (int i = 0; i < 16; i++) snprintf(out->md5 + i * 2, 3, "%02x", h[i]);

    snprintf(out->format, sizeof(out->format), "data");
    if (!map_pe(out) && !map_elf(out, resolved)) map_mbr(out);
    region_entropy(out, fd, buf);
    free(buf);
    close(fd);
    return BOOTO_OK;
}

double inspect_block_entropy(const inspect_sample_t *s, size_t block) {
    size_t off = block * INSPECT_BLOCK;
    if (!s || off >= s->len) return 0;
    size_t n = s->len - off < INSPECT_BLOCK ? s->len - off : INSPECT_BLOCK;
    size_t hist[256] = {0};
    for (size_t i = 0; i < n; i++) hist[s->data[off + i]]++;
    return entropy_bits(hist, n);
}

void inspect_hex_row(const inspect_sample_t *s, size_t off, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!s || off >= s->len) return;
    size_t n = s->len - off < 16 ? s->len - off : 16, p = 0;
    char hex[3 * 16 + 2] = {0}, txt[17] = {0};
    for (size_t i = 0; i < 16; i++) {
        if (i < n) snprintf(hex + p, sizeof(hex) - p, "%02x ", s->data[off + i]);
        else snprintf(hex + p, sizeof(hex) - p, "   ");
        p += 3;
        if (i == 7) hex[p++] = ' ';
        if (i < n) txt[i] = (s->data[off + i] >= 0x20 && s->data[off + i] < 0x7f) ? (char)s->data[off + i] : '.';
    }
    snprintf(out, out_len, "%08zx  %s |%s|", off, hex, txt);
}

char inspect_entropy_char(double bits) {
    static const char scale[] = " .:-=+*#%@";
    int i = (int)(bits * 10.0 / 8.0);
    if (i < 0) i = 0;
    if (i > 9) i = 9;
    return scale[i];
}
