/**
 * @file pkg_integrity.c
 * @brief debsums-style offline check of packaged system files against dpkg's md5sums lists.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pkg_integrity.h"
#include "crypto_utils.h"
#include "logger.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DIVERSIONS_MAX_BYTES (1024u * 1024u)

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
    snprintf(f->expected_md5, sizeof(f->expected_md5), "%.32s", expected);
    snprintf(f->actual_md5, sizeof(f->actual_md5), "%.32s", actual);
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
    md5_ctx_t ctx;
    md5_init(&ctx);
    uint8_t buf[16384];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) md5_update(&ctx, buf, (size_t)n);
    close(fd);
    if (n < 0) {
        res->files_unreadable++;
        LOG_WARN("Read error on /%s", rel);
        return;
    }
    uint8_t digest[16];
    md5_final(&ctx, digest);
    char hex[33];
    for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
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

booto_error_t pkg_integrity_scan_rootfs(const char *target_rootfs, pkg_scan_result_t *result) {
    if (!target_rootfs || !result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    int rootfd = open(target_rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    int infofd = openat(rootfd, "var/lib/dpkg/info", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (infofd < 0) {
        booto_error_t e = errno == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
        close(rootfd);
        return e;
    }
    DIR *dir = fdopendir(infofd);
    if (!dir) {
        close(infofd);
        close(rootfd);
        return BOOTO_ERR_IO;
    }

    LOG_INFO("Verifying packaged system files in %s against dpkg md5sums", target_rootfs);
    char *diversions = read_diversions(rootfd);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n > 8 && strcmp(de->d_name + n - 8, ".md5sums") == 0)
            check_list(rootfd, dirfd(dir), de->d_name, diversions, result);
    }
    free(diversions);
    closedir(dir);
    close(rootfd);

    LOG_INFO("Package integrity: %d packages, %d files hashed, %d missing, %d unreadable, %d threats",
             result->packages_checked, result->files_checked, result->files_missing, result->files_unreadable,
             result->threats_detected);
    return result->files_unreadable > 0 ? BOOTO_ERR_IO : BOOTO_OK;
}
