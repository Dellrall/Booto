/**
 * @file pkg_integrity.c
 * @brief debsums/pacman -Qkk-style offline check of packaged system files against the package database.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pkg_integrity.h"
#include "crypto_utils.h"
#include "disk_mount.h"
#include "logger.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DIVERSIONS_MAX_BYTES (1024u * 1024u)
#define MTREE_PACKED_CAP (16u * 1024u * 1024u)
#define MTREE_RAW_CAP (128u * 1024u * 1024u)

/* RPM header tags and types (rpmtag.h) used to rebuild each file's path and digest. */
#define RPMTAG_NAME 1000u
#define RPMTAG_FILEDIGESTS 1035u
#define RPMTAG_DIRINDEXES 1116u
#define RPMTAG_BASENAMES 1117u
#define RPMTAG_DIRNAMES 1118u
#define RPMTAG_FILEDIGESTALGO 5011u
#define RPM_INT32_TYPE 4u
#define RPM_STRING_TYPE 6u
#define RPM_STRING_ARRAY_TYPE 8u
#define RPM_ALGO_MD5 1u
#define RPM_ALGO_SHA256 8u

/* Directories whose files a rootkit replaces; docs, headers and data under usr/share are not hashed. */
static bool is_system_path(const char *rel) {
    static const char *prefixes[] = {"bin/", "sbin/", "lib", "usr/bin/", "usr/sbin/", "usr/lib", "boot/"};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (strncmp(rel, prefixes[i], strlen(prefixes[i])) == 0) return true;
    return false;
}

/* Every third line of the diversions file, starting with the first, is a diverted path ("/usr/bin/foo"). */
static bool is_diverted(const char *diversions, const char *rel) {
    if (!diversions) return false;
    int line = 0;
    for (const char *p = diversions; *p;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (line % 3 == 0 && len > 1 && p[0] == '/' && strlen(rel) == len - 1 && strncmp(p + 1, rel, len - 1) == 0)
            return true;
        line++;
        if (!nl) break;
        p = nl + 1;
    }
    return false;
}

static char *read_diversions(int rootfd) {
    int fd = openat(rootfd, "var/lib/dpkg/diversions", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    char *buf = malloc(DIVERSIONS_MAX_BYTES + 1);
    size_t n = 0;
    ssize_t r = 0;
    while (buf && n < DIVERSIONS_MAX_BYTES && (r = read(fd, buf + n, DIVERSIONS_MAX_BYTES - n)) > 0) n += (size_t)r;
    close(fd);
    if (buf) buf[n] = '\0';
    return buf;
}

static void add_finding(pkg_scan_result_t *res, const char *rel, const char *pkg, const char *expected,
                        const char *actual, const char *reason) {
    if (res->threats_detected >= MAX_PKG_THREATS) return;
    pkg_finding_t *f = &res->findings[res->threats_detected++];
    snprintf(f->file_path, sizeof(f->file_path), "/%.254s", rel);
    snprintf(f->package, sizeof(f->package), "%.95s", pkg);
    snprintf(f->expected_hash, sizeof(f->expected_hash), "%.64s", expected);
    snprintf(f->actual_hash, sizeof(f->actual_hash), "%.64s", actual);
    snprintf(f->reason, sizeof(f->reason), "%.47s", reason);
    LOG_CRITICAL("[PKG ALERT] %s: %s (package %s)", f->file_path, f->reason, f->package);
}

/* Opens rel with ".." and absolute symlinks confined to the target root; never follows a final symlink. */
static int open_in_root(int rootfd, const char *rel) {
    struct open_how how = {.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                           .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS};
    return (int)syscall(SYS_openat2, rootfd, rel, &how, sizeof(how));
}

static void check_file(int rootfd, const char *rel, const char *expected, const char *pkg, pkg_scan_result_t *res) {
    int fd = open_in_root(rootfd, rel);
    if (fd < 0) {
        if (errno == ENOENT || errno == ENOTDIR) res->files_missing++;
        else if (errno == ELOOP) add_finding(res, rel, pkg, expected, "", "replaced by a symlink");
        else {
            res->files_unreadable++;
            LOG_WARN("Cannot open /%s: %s", rel, strerror(errno));
        }
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        add_finding(res, rel, pkg, expected, "", "no longer a regular file");
        return;
    }
    bool sha = strlen(expected) == 64;
    md5_ctx_t md5;
    sha256_ctx_t sha256;
    if (sha) sha256_init(&sha256);
    else md5_init(&md5);
    uint8_t buf[16384];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (sha) sha256_update(&sha256, buf, (size_t)n);
        else md5_update(&md5, buf, (size_t)n);
    }
    close(fd);
    if (n < 0) {
        res->files_unreadable++;
        LOG_WARN("Read error on /%s", rel);
        return;
    }
    uint8_t digest[32];
    size_t dlen = sha ? 32 : 16;
    if (sha) sha256_final(&sha256, digest);
    else md5_final(&md5, digest);
    char hex[65];
    for (size_t i = 0; i < dlen; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
    res->files_checked++;
    if (strcmp(hex, expected) != 0) add_finding(res, rel, pkg, expected, hex, "content differs from package");
}

/* One md5sums list: lines of "<32 lowercase hex>  <path relative to />". Malformed lines are skipped. */
static void check_list(int rootfd, int infofd, const char *name, const char *diversions, pkg_scan_result_t *res) {
    int fd = openat(infofd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    FILE *fp = fd >= 0 ? fdopen(fd, "r") : NULL;
    if (!fp) {
        if (fd >= 0) close(fd);
        res->files_unreadable++;
        return;
    }
    char pkg[96];
    snprintf(pkg, sizeof(pkg), "%.*s", (int)(strlen(name) - strlen(".md5sums")), name);
    res->packages_checked++;

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, fp)) > 0) {
        if (line[len - 1] == '\n') line[--len] = '\0';
        if (len < 35 || line[32] != ' ' || (line[33] != ' ' && line[33] != '*')) continue;
        bool hex_ok = true;
        for (int i = 0; i < 32 && hex_ok; i++) {
            line[i] = (char)tolower((unsigned char)line[i]);
            hex_ok = isxdigit((unsigned char)line[i]);
        }
        if (!hex_ok) continue;
        line[32] = '\0';
        const char *rel = line + 34;
        while (*rel == '/' || (rel[0] == '.' && rel[1] == '/')) rel += *rel == '/' ? 1 : 2;
        if (!is_system_path(rel) || is_diverted(diversions, rel)) continue;
        check_file(rootfd, rel, line, pkg, res);
    }
    free(line);
    fclose(fp);
}

/* Scans every md5sums list in <root>/var/lib/dpkg/info; false when the root has no dpkg database. */
static bool scan_dpkg(int rootfd, pkg_scan_result_t *result) {
    int infofd = openat(rootfd, "var/lib/dpkg/info", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (infofd < 0) {
        if (errno != ENOENT) result->files_unreadable++;
        return errno != ENOENT;
    }
    DIR *dir = fdopendir(infofd);
    if (!dir) {
        close(infofd);
        result->files_unreadable++;
        return true;
    }
    char *diversions = read_diversions(rootfd);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n > 8 && strcmp(de->d_name + n - 8, ".md5sums") == 0)
            check_list(rootfd, dirfd(dir), de->d_name, diversions, result);
    }
    free(diversions);
    closedir(dir);
    return true;
}

/* mtree escapes bytes outside the safe set as \ooo octal (a space is \040). Decodes in place. */
static void mtree_unescape(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' && r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
            *w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 3;
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

/* Value of " key=" within the space-separated keyword list kw, copied into out; false when absent. */
static bool mtree_keyword(const char *kw, const char *key, char *out, size_t out_len) {
    size_t klen = strlen(key);
    for (const char *p = kw; (p = strstr(p, key)) != NULL; p += klen) {
        if ((p != kw && p[-1] != ' ') || p[klen] != '=') continue;
        const char *v = p + klen + 1;
        size_t n = strcspn(v, " ");
        snprintf(out, out_len, "%.*s", (int)(n < out_len ? n : out_len - 1), v);
        return true;
    }
    return false;
}

/* Lines are "./path key=value ..."; "/set key=value ..." sets defaults (type) for later lines. */
static void check_mtree(int rootfd, char *text, const char *pkg, pkg_scan_result_t *res) {
    char set_type[16] = "file";
    for (char *line = text, *next; line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = '\0';
        if (strncmp(line, "/set ", 5) == 0) {
            mtree_keyword(line + 5, "type", set_type, sizeof(set_type));
            continue;
        }
        if (strncmp(line, "./", 2) != 0) continue;
        char *kw = strchr(line, ' ');
        if (!kw) continue;
        *kw++ = '\0';
        char type[16], digest[65];
        if (!mtree_keyword(kw, "type", type, sizeof(type))) snprintf(type, sizeof(type), "%s", set_type);
        if (strcmp(type, "file") != 0 || !mtree_keyword(kw, "sha256digest", digest, sizeof(digest))) continue;
        if (strlen(digest) != 64) continue;
        for (char *d = digest; *d; d++) *d = (char)tolower((unsigned char)*d);
        char *rel = line + 2;
        mtree_unescape(rel);
        if (!is_system_path(rel)) continue;
        check_file(rootfd, rel, digest, pkg, res);
    }
}

/* Reads at most cap bytes of an untrusted file inside the root without following a final symlink. */
static uint8_t *read_in_root(int dirfd, const char *rel, size_t cap, size_t *len) {
    int fd = openat(dirfd, rel, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    uint8_t *buf = malloc(cap + 1);
    size_t n = 0;
    ssize_t r = 0;
    while (buf && n <= cap && (r = read(fd, buf + n, cap + 1 - n)) > 0) n += (size_t)r;
    close(fd);
    if (!buf || r < 0 || n > cap) {
        free(buf);
        if (n > cap) errno = EFBIG;
        return NULL;
    }
    *len = n;
    return buf;
}

/* Scans every <root>/var/lib/pacman/local/<pkg>/mtree; false when the root has no pacman database. */
static bool scan_pacman(int rootfd, pkg_scan_result_t *result) {
    int localfd = openat(rootfd, "var/lib/pacman/local", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (localfd < 0) {
        if (errno != ENOENT) result->files_unreadable++;
        return errno != ENOENT;
    }
    DIR *dir = fdopendir(localfd);
    if (!dir) {
        close(localfd);
        result->files_unreadable++;
        return true;
    }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.' || strcmp(de->d_name, "ALPM_DB_VERSION") == 0) continue;
        char rel[300];
        snprintf(rel, sizeof(rel), "%.255s/mtree", de->d_name);
        size_t packed_len = 0;
        uint8_t *packed = read_in_root(dirfd(dir), rel, MTREE_PACKED_CAP, &packed_len);
        if (!packed) {
            if (errno != ENOENT) {
                result->files_unreadable++;
                LOG_WARN("Cannot read pacman mtree for %s", de->d_name);
            }
            continue;
        }
        const char *const argv[] = {"gzip", "-dc", NULL};
        uint8_t *raw = NULL;
        size_t raw_len = 0;
        booto_error_t e = disk_exec_capture(argv, packed, packed_len, &raw, &raw_len, MTREE_RAW_CAP);
        free(packed);
        char *text = raw ? realloc(raw, raw_len + 1) : NULL;
        if (e != BOOTO_OK || !text) {
            free(text ? text : (char *)raw);
            result->files_unreadable++;
            LOG_WARN("Cannot inflate pacman mtree for %s (err: %d)", de->d_name, e);
            continue;
        }
        text[raw_len] = '\0';
        result->packages_checked++;
        check_mtree(rootfd, text, de->d_name, result);
        free(text);
    }
    closedir(dir);
    return true;
}

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

typedef struct {
    const uint8_t *data; /* start of the tag's data within the store */
    size_t avail;        /* bytes from data to the end of the store */
    uint32_t count;
} rpm_tag_t;

/* Finds tag of the given type in an exported header blob (il, dl, il 16-byte entries, dl data bytes). */
static bool rpm_find_tag(const uint8_t *blob, size_t len, uint32_t tag, uint32_t type, rpm_tag_t *out) {
    if (len < 8) return false;
    uint32_t il = be32(blob), dl = be32(blob + 4);
    if (il > 0xFFFFu || dl > len - 8u || (size_t)il * 16u > len - 8u - dl) return false;
    const uint8_t *store = blob + 8 + (size_t)il * 16u;
    for (uint32_t i = 0; i < il; i++) {
        const uint8_t *e = blob + 8 + (size_t)i * 16u;
        if (be32(e) != tag || be32(e + 4) != type) continue;
        uint32_t off = be32(e + 8);
        if (off >= dl) return false;
        out->data = store + off;
        out->avail = dl - off;
        out->count = be32(e + 12);
        return out->count > 0;
    }
    return false;
}

/* Splits a string-array tag into count NUL-terminated pointers; false if any runs past the store. */
static const char **rpm_strings(const rpm_tag_t *t) {
    if (t->count > t->avail) return NULL;
    const char **v = calloc(t->count, sizeof(*v));
    size_t off = 0;
    for (uint32_t i = 0; v && i < t->count; i++) {
        const char *s = (const char *)t->data + off;
        const char *nul = off < t->avail ? memchr(s, '\0', t->avail - off) : NULL;
        if (!nul) {
            free(v);
            return NULL;
        }
        v[i] = s;
        off += (size_t)(nul - s) + 1;
    }
    return v;
}

/* Checks every file of one package header. A malformed header is counted unreadable, never trusted. */
static void check_rpm_header(int rootfd, const uint8_t *blob, size_t len, pkg_scan_result_t *res) {
    rpm_tag_t name, base, dirs, idx, dig, algo;
    if (!rpm_find_tag(blob, len, RPMTAG_NAME, RPM_STRING_TYPE, &name)) {
        res->files_unreadable++;
        return;
    }
    char pkg[96];
    const char *nul = memchr(name.data, '\0', name.avail);
    snprintf(pkg, sizeof(pkg), "%.*s", nul ? (int)(nul - (const char *)name.data) : 0, (const char *)name.data);
    res->packages_checked++;
    if (!rpm_find_tag(blob, len, RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE, &base)) return; /* no files */

    uint32_t algo_id = RPM_ALGO_MD5; /* rpm's default when the tag is absent */
    if (rpm_find_tag(blob, len, RPMTAG_FILEDIGESTALGO, RPM_INT32_TYPE, &algo) && algo.avail >= 4)
        algo_id = be32(algo.data);
    if (algo_id != RPM_ALGO_MD5 && algo_id != RPM_ALGO_SHA256) {
        LOG_WARN("rpm package %s uses digest algorithm %u; not verified", pkg, algo_id);
        return;
    }
    size_t hex_len = algo_id == RPM_ALGO_SHA256 ? 64 : 32;

    const char **bases = NULL, **dirnames = NULL, **digests = NULL;
    bool ok = rpm_find_tag(blob, len, RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, &dirs) &&
              rpm_find_tag(blob, len, RPMTAG_DIRINDEXES, RPM_INT32_TYPE, &idx) &&
              rpm_find_tag(blob, len, RPMTAG_FILEDIGESTS, RPM_STRING_ARRAY_TYPE, &dig) &&
              idx.count == base.count && dig.count == base.count && idx.avail / 4 >= idx.count &&
              (bases = rpm_strings(&base)) && (dirnames = rpm_strings(&dirs)) && (digests = rpm_strings(&dig));
    for (uint32_t i = 0; ok && i < base.count; i++) {
        uint32_t d = be32(idx.data + (size_t)i * 4u);
        if (d >= dirs.count) {
            ok = false;
            break;
        }
        if (strlen(digests[i]) != hex_len) continue; /* directories, symlinks and %ghost files carry no digest */
        char path[PATH_MAX], hex[65];
        if (snprintf(path, sizeof(path), "%s%s", dirnames[d], bases[i]) >= (int)sizeof(path)) continue;
        snprintf(hex, sizeof(hex), "%s", digests[i]);
        for (char *c = hex; *c; c++) *c = (char)tolower((unsigned char)*c);
        const char *rel = path;
        while (*rel == '/') rel++;
        if (is_system_path(rel)) check_file(rootfd, rel, hex, pkg, res);
    }
    if (!ok) {
        res->files_unreadable++;
        LOG_WARN("Malformed rpm header for package %s", pkg);
    }
    free(bases);
    free(dirnames);
    free(digests);
}

/* sqlite URIs give '?', '#' and '%' meaning; escape them so a mount path is taken literally. */
static void uri_path(const char *path, char *out, size_t out_len) {
    size_t o = 0;
    for (const char *p = path; *p && o + 4 < out_len; p++) {
        if (*p == '?' || *p == '#' || *p == '%') o += (size_t)snprintf(out + o, out_len - o, "%%%02X", (unsigned char)*p);
        else out[o++] = *p;
    }
    out[o] = '\0';
}

/* Reads every header in rpmdb.sqlite (rpm >= 4.16); false when the root has no rpm database. */
static bool scan_rpm(int rootfd, const char *target_rootfs, pkg_scan_result_t *result) {
    static const char *const dbs[] = {"usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite"};
    char root_real[PATH_MAX], db_real[PATH_MAX], cand[PATH_MAX];
    if (!realpath(target_rootfs, root_real)) return false;
    size_t root_len = strlen(root_real);
    const char *db = NULL;
    for (size_t i = 0; i < sizeof(dbs) / sizeof(dbs[0]) && !db; i++) {
        int w = snprintf(cand, sizeof(cand), "%s/%s", root_real, dbs[i]);
        if (w < 0 || (size_t)w >= sizeof(cand)) continue;
        /* A planted absolute symlink must not point the scan at the live system's database. */
        if (realpath(cand, db_real) && strncmp(db_real, root_real, root_len) == 0 && db_real[root_len] == '/')
            db = db_real;
    }
    if (!db) {
        if (faccessat(rootfd, "var/lib/rpm/Packages", F_OK, AT_SYMLINK_NOFOLLOW) != 0) return false;
        LOG_ERROR("Berkeley DB rpm database (rpm < 4.16) is not supported; package integrity not verified");
        result->files_unreadable++;
        return true;
    }

    /* immutable: the target is mounted read-only, so take no locks and create no -wal/-shm files. */
    char uri[PATH_MAX * 3 + 32], esc[PATH_MAX * 3];
    uri_path(db, esc, sizeof(esc));
    snprintf(uri, sizeof(uri), "file:%s?immutable=1", esc);
    sqlite3 *h = NULL;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_open_v2(uri, &h, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOFOLLOW, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_db_config(h, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL);
        sqlite3_db_config(h, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
        rc = sqlite3_prepare_v2(h, "SELECT blob FROM Packages", -1, &st, NULL);
    }
    if (rc != SQLITE_OK) {
        LOG_ERROR("Cannot read rpm database %s: %s", db, h ? sqlite3_errmsg(h) : "out of memory");
        result->files_unreadable++;
        sqlite3_close(h);
        return true;
    }
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const uint8_t *blob = sqlite3_column_blob(st, 0);
        int n = sqlite3_column_bytes(st, 0);
        if (blob && n > 0) check_rpm_header(rootfd, blob, (size_t)n, result);
        else result->files_unreadable++;
    }
    if (rc != SQLITE_DONE) {
        LOG_ERROR("rpm database %s is corrupt: %s", db, sqlite3_errmsg(h));
        result->files_unreadable++;
    }
    sqlite3_finalize(st);
    sqlite3_close(h);
    return true;
}

booto_error_t pkg_integrity_scan_rootfs(const char *target_rootfs, pkg_scan_result_t *result) {
    if (!target_rootfs || !result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    int rootfd = open(target_rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;

    LOG_INFO("Verifying packaged system files in %s against the package database", target_rootfs);
    bool dpkg = scan_dpkg(rootfd, result);
    bool pacman = scan_pacman(rootfd, result);
    bool rpm = scan_rpm(rootfd, target_rootfs, result);
    close(rootfd);
    if (!dpkg && !pacman && !rpm) return BOOTO_ERR_NOT_FOUND;

    LOG_INFO("Package integrity: %d packages, %d files hashed, %d missing, %d unreadable, %d threats",
             result->packages_checked, result->files_checked, result->files_missing, result->files_unreadable,
             result->threats_detected);
    return result->files_unreadable > 0 ? BOOTO_ERR_IO : BOOTO_OK;
}
