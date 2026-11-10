/**
 * @file baseline.c
 * @brief Boot chain hash list: written once on a known-good machine, compared on later scans.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "baseline.h"
#include "crypto_utils.h"
#include "logger.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define UNREADABLE "unreadable"
#define TREE_MAX_DEPTH 16

void baseline_add_hash(baseline_t *b, const char *label, const char *sha256) {
    if (!b || !label || !sha256) return;
    if (b->count >= BASELINE_MAX) {
        b->truncated = true;
        return;
    }
    baseline_entry_t *e = &b->e[b->count++];
    snprintf(e->label, sizeof(e->label), "%s", label);
    // A newline in a file name would split the line; a planted name must not hide its file.
    for (char *p = e->label; *p; p++)
        if (*p == '\n' || *p == '\r') *p = '?';
    snprintf(e->sha256, sizeof(e->sha256), "%s", sha256);
}

void baseline_add_file(baseline_t *b, const char *label, const char *path) {
    char hex[65];
    baseline_add_hash(b, label, sha256_file_hex(path, hex) ? hex : UNREADABLE);
}

static void walk(baseline_t *b, const char *label, const char *dir, int depth) {
    DIR *d = opendir(dir);
    if (!d) {
        baseline_add_hash(b, label, UNREADABLE);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char path[4096], sub[BASELINE_LABEL_MAX + 256];
        int w = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (w < 0 || (size_t)w >= sizeof(path)) continue;
        snprintf(sub, sizeof(sub), "%s/%s", label, de->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) baseline_add_file(b, sub, path);
        else if (S_ISDIR(st.st_mode) && depth < TREE_MAX_DEPTH) walk(b, sub, path, depth + 1);
    }
    closedir(d);
}

void baseline_add_tree(baseline_t *b, const char *prefix, const char *dir) {
    if (b && prefix && dir) walk(b, prefix, dir, 0);
}

void baseline_add_device(baseline_t *b, const char *label, const char *dev, size_t bytes) {
    int fd = open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        baseline_add_hash(b, label, UNREADABLE);
        return;
    }
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    uint8_t buf[65536];
    size_t done = 0;
    while (done < bytes) {
        size_t want = bytes - done < sizeof(buf) ? bytes - done : sizeof(buf);
        ssize_t n = read(fd, buf, want);
        if (n <= 0) break;
        sha256_update(&ctx, buf, (size_t)n);
        done += (size_t)n;
    }
    close(fd);
    uint8_t h[32];
    sha256_final(&ctx, h);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    baseline_add_hash(b, label, done ? hex : UNREADABLE);
}

booto_error_t baseline_write(const baseline_t *b, const char *path) {
    if (!b || !path) return BOOTO_ERR_INVALID_ARG;
    FILE *fp = fopen(path, "w");
    if (!fp) return BOOTO_ERR_IO;
    for (int i = 0; i < b->count; i++) fprintf(fp, "%s  %s\n", b->e[i].sha256, b->e[i].label);
    bool ok = !ferror(fp);
    return (fclose(fp) == 0 && ok) ? BOOTO_OK : BOOTO_ERR_IO;
}

static bool valid_hash(const char *s, size_t n) {
    if (n == strlen(UNREADABLE) && memcmp(s, UNREADABLE, n) == 0) return true;
    if (n != 64) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

booto_error_t baseline_parse(const char *text, size_t len, baseline_t *out) {
    if (!text || !out) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    while (off < len) {
        const char *line = text + off;
        const char *nl = memchr(line, '\n', len - off);
        size_t n = nl ? (size_t)(nl - line) : len - off;
        off += n + (nl ? 1 : 0);
        if (n == 0) continue;
        const char *sep = memchr(line, ' ', n);
        if (!sep || (size_t)(sep - line) + 2 >= n || sep[1] != ' ') return BOOTO_ERR_CORRUPT_DATA;
        size_t hlen = (size_t)(sep - line), llen = n - hlen - 2;
        if (!valid_hash(line, hlen) || llen >= BASELINE_LABEL_MAX || memchr(sep + 2, '\0', llen))
            return BOOTO_ERR_CORRUPT_DATA;
        if (out->count >= BASELINE_MAX) {
            out->truncated = true;
            break;
        }
        baseline_entry_t *e = &out->e[out->count++];
        memcpy(e->sha256, line, hlen);
        e->sha256[hlen] = '\0';
        memcpy(e->label, sep + 2, llen);
        e->label[llen] = '\0';
    }
    return BOOTO_OK;
}

booto_error_t baseline_load(const char *path, baseline_t *out) {
    if (!path || !out) return BOOTO_ERR_INVALID_ARG;
    FILE *fp = fopen(path, "r");
    if (!fp) return BOOTO_ERR_NOT_FOUND;
    size_t cap = (size_t)BASELINE_MAX * (BASELINE_LABEL_MAX + 68);
    char *buf = malloc(cap);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }
    size_t len = fread(buf, 1, cap, fp);
    bool err = ferror(fp);
    fclose(fp);
    booto_error_t e = err ? BOOTO_ERR_IO : baseline_parse(buf, len, out);
    free(buf);
    return e;
}

static const baseline_entry_t *find(const baseline_t *b, const char *label) {
    for (int i = 0; i < b->count; i++)
        if (strcmp(b->e[i].label, label) == 0) return &b->e[i];
    return NULL;
}

int baseline_compare(const baseline_t *old, const baseline_t *cur, FILE *fp) {
    if (!old || !cur) return 0;
    int diff = 0;
    for (int i = 0; i < old->count; i++) {
        const baseline_entry_t *c = find(cur, old->e[i].label);
        if (!c) {
            if (fp) fprintf(fp, "  missing  %s\n", old->e[i].label);
            diff++;
        } else if (strcmp(c->sha256, old->e[i].sha256) != 0) {
            if (fp) fprintf(fp, "  changed  %s\n", old->e[i].label);
            diff++;
        }
    }
    for (int i = 0; i < cur->count; i++) {
        if (!find(old, cur->e[i].label)) {
            if (fp) fprintf(fp, "  new      %s\n", cur->e[i].label);
            diff++;
        }
    }
    return diff;
}
