/**
 * @file test_pkg_integrity.c
 * @brief MD5 vectors and the offline dpkg md5sums / pacman mtree integrity check.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "pkg_integrity.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[64];

static void md5_hex(const char *s, char out[33]) {
    md5_ctx_t ctx;
    uint8_t d[16];
    md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)s, strlen(s));
    md5_final(&ctx, d);
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", d[i]);
}

static void put(const char *rel, const char *content) {
    char p[256];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    for (char *s = strchr(p + strlen(g_root) + 1, '/'); s; s = strchr(s + 1, '/')) {
        *s = '\0';
        mkdir(p, 0755);
        *s = '/';
    }
    FILE *fp = fopen(p, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

static void make_root(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/booto_pkg_XXXXXX");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        exit(1);
    }
}

static void test_md5_vectors(void) {
    TEST_START("test_md5_vectors");
    char h[33];
    md5_hex("", h);
    ASSERT_STR_EQ(h, "d41d8cd98f00b204e9800998ecf8427e", "MD5 of empty string");
    md5_hex("The quick brown fox jumps over the lazy dog", h);
    ASSERT_STR_EQ(h, "9e107d9d372bb6826bd81d3542a419d6", "MD5 of pangram");
    md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", h);
    ASSERT_STR_EQ(h, "57edf4a22be3c955ac49da2e2107b67a", "MD5 of 80 bytes (two blocks)");
    TEST_PASS("test_md5_vectors");
}

static void test_detects_modified_files(void) {
    TEST_START("test_detects_modified_files");
    make_root();
    char good[33], list[1024];
    md5_hex("ls binary\n", good);
    put("usr/bin/ls", "ls binary\n");
    put("usr/bin/ps", "trojaned ps\n");          /* listed with the hash of the original */
    put("usr/sbin/sshd", "diverted sshd\n");     /* diverted: content legitimately differs */
    put("usr/share/doc/x/README", "edited doc\n"); /* not a system directory: ignored */
    snprintf(list, sizeof(list), "%s/usr/bin/login", g_root);
    ASSERT_TRUE(symlink("/etc/hostname", list) == 0, "symlink failed"); /* absolute target would escape the root if followed */
    char orig_ps[33];
    md5_hex("original ps\n", orig_ps);
    snprintf(list, sizeof(list),
             "%s  usr/bin/ls\n%s  usr/bin/ps\n%s  usr/sbin/sshd\n%s  usr/share/doc/x/README\n%s  usr/bin/login\n"
             "%s  usr/bin/removed\nnot a valid line\n",
             good, orig_ps, orig_ps, orig_ps, orig_ps, orig_ps);
    put("var/lib/dpkg/info/coreutils:amd64.md5sums", list);
    put("var/lib/dpkg/diversions", "/usr/sbin/sshd\n/usr/sbin/sshd.distrib\nlocal\n");

    pkg_scan_result_t *res = calloc(1, sizeof(*res));
    booto_error_t err = pkg_integrity_scan_rootfs(g_root, res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Scan succeeds");
    ASSERT_INT_EQ(res->packages_checked, 1, "One md5sums list");
    ASSERT_INT_EQ(res->files_checked, 2, "ls and ps hashed; diverted, doc, symlink and missing are not");
    ASSERT_INT_EQ(res->files_missing, 1, "Removed file counted as missing, not a threat");
    ASSERT_INT_EQ(res->threats_detected, 2, "Trojaned ps and symlinked login flagged");
    bool saw_ps = false, saw_login = false;
    for (int i = 0; i < res->threats_detected; i++) {
        if (strcmp(res->findings[i].file_path, "/usr/bin/ps") == 0) {
            saw_ps = true;
            ASSERT_STR_EQ(res->findings[i].package, "coreutils:amd64", "Package from list name");
            ASSERT_STR_EQ(res->findings[i].expected_hash, orig_ps, "Expected hash recorded");
        }
        if (strcmp(res->findings[i].file_path, "/usr/bin/login") == 0) saw_login = true;
    }
    ASSERT_TRUE(saw_ps && saw_login, "Both findings present");
    free(res);
    TEST_PASS("test_detects_modified_files");
}

static void test_no_dpkg_database(void) {
    TEST_START("test_no_dpkg_database");
    make_root();
    pkg_scan_result_t *res = calloc(1, sizeof(*res));
    ASSERT_INT_EQ(pkg_integrity_scan_rootfs(g_root, res), BOOTO_ERR_NOT_FOUND, "No dpkg or pacman database -> NOT_FOUND");
    free(res);
    TEST_PASS("test_no_dpkg_database");
}

static void test_pacman_mtree(void) {
    TEST_START("test_pacman_mtree");
    make_root();
    char good[65], orig[65], mtree[2048], cmd[256];
    sha256_buffer_hex((const uint8_t *)"bash binary\n", 12, good);
    sha256_buffer_hex((const uint8_t *)"original sudo\n", 14, orig);
    put("usr/bin/bash", "bash binary\n");
    put("usr/bin/sudo", "trojaned sudo\n");
    put("usr/lib/my lib.so", "trojaned lib\n");
    put("usr/share/doc/x", "edited doc\n");
    snprintf(mtree, sizeof(mtree),
             "#mtree\n/set type=file uid=0 gid=0 mode=644\n"
             "./.BUILDINFO time=1.0 size=1 sha256digest=%s\n"
             "./usr time=1.0 mode=755 type=dir\n"
             "./usr/bin/bash time=1.0 mode=755 size=12 md5digest=0 sha256digest=%s\n"
             "./usr/bin/sudo time=1.0 mode=4755 sha256digest=%s\n"
             "./usr/lib/my\\040lib.so time=1.0 sha256digest=%s\n"
             "./usr/lib/libx.so time=1.0 type=link link=libx.so.1\n"
             "./usr/share/doc/x time=1.0 sha256digest=%s\n"
             "./usr/bin/gone time=1.0 sha256digest=%s\n",
             orig, good, orig, orig, orig, orig);
    put("var/lib/pacman/local/sudo-1.9-1/mtree.txt", mtree);
    put("var/lib/pacman/local/ALPM_DB_VERSION", "9\n");
    snprintf(cmd, sizeof(cmd), "gzip -nc '%s/var/lib/pacman/local/sudo-1.9-1/mtree.txt' > '%s/var/lib/pacman/local/sudo-1.9-1/mtree'",
             g_root, g_root);
    ASSERT_INT_EQ(system(cmd), 0, "gzip mtree");

    pkg_scan_result_t *res = calloc(1, sizeof(*res));
    booto_error_t err = pkg_integrity_scan_rootfs(g_root, res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Scan succeeds");
    ASSERT_INT_EQ(res->packages_checked, 1, "One pacman package");
    ASSERT_INT_EQ(res->files_checked, 3, "bash, sudo and the escaped-name lib hashed");
    ASSERT_INT_EQ(res->files_missing, 1, "Removed file counted as missing");
    ASSERT_INT_EQ(res->threats_detected, 2, "Trojaned sudo and lib flagged");
    ASSERT_STR_EQ(res->findings[0].file_path, "/usr/bin/sudo", "sudo first in mtree order");
    ASSERT_STR_EQ(res->findings[0].package, "sudo-1.9-1", "Package from directory name");
    ASSERT_STR_EQ(res->findings[0].expected_hash, orig, "Expected SHA-256 recorded");
    ASSERT_STR_EQ(res->findings[1].file_path, "/usr/lib/my lib.so", "Octal escape decoded");
    free(res);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    ASSERT_INT_EQ(system(cmd), 0, "cleanup");
    TEST_PASS("test_pacman_mtree");
}

typedef struct {
    uint8_t index[16 * 8], data[1024];
    uint32_t il, dl;
} hdr_t;

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Appends one tag; strings arrive as one buffer of NUL-terminated strings (count of them). */
static void hdr_add(hdr_t *h, uint32_t tag, uint32_t type, uint32_t count, const void *data, size_t len) {
    uint8_t *e = h->index + h->il++ * 16;
    put32(e, tag);
    put32(e + 4, type);
    put32(e + 8, h->dl);
    put32(e + 12, count);
    memcpy(h->data + h->dl, data, len);
    h->dl += (uint32_t)len;
}

static size_t hdr_blob(const hdr_t *h, uint8_t *out) {
    put32(out, h->il);
    put32(out + 4, h->dl);
    memcpy(out + 8, h->index, h->il * 16u);
    memcpy(out + 8 + h->il * 16u, h->data, h->dl);
    return 8 + h->il * 16u + h->dl;
}

static void write_rpmdb(const char *rel, const uint8_t *blob, size_t len) {
    char p[256];
    put(rel, "");
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    unlink(p);
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    sqlite3_open(p, &db);
    sqlite3_exec(db, "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)", NULL, NULL,
                 NULL);
    sqlite3_prepare_v2(db, "INSERT INTO Packages (blob) VALUES (?)", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, blob, (int)len, SQLITE_STATIC);
    sqlite3_step(st);
    sqlite3_finalize(st);
    sqlite3_close(db);
}

static size_t sudo_header(uint8_t *blob, const char *sudo_sha, const char *ls_sha) {
    hdr_t h = {0};
    hdr_add(&h, 1000, 6, 1, "sudo", 5);
    char digests[200];
    int n = snprintf(digests, sizeof(digests), "%s%c%s%c%c", sudo_sha, 0, ls_sha, 0, 0);
    hdr_add(&h, 1035, 8, 3, digests, (size_t)n);
    uint8_t idx[12];
    put32(idx, 0);
    put32(idx + 4, 0);
    put32(idx + 8, 1);
    hdr_add(&h, 1116, 4, 3, idx, sizeof(idx));
    hdr_add(&h, 1117, 8, 3, "sudo\0ls\0doc", 12);
    hdr_add(&h, 1118, 8, 2, "/usr/bin/\0/usr/share/\0", 22);
    uint8_t algo[4];
    put32(algo, 8);
    hdr_add(&h, 5011, 4, 1, algo, sizeof(algo));
    return hdr_blob(&h, blob);
}

static void test_rpm_sqlite(void) {
    TEST_START("test_rpm_sqlite");
    make_root();
    char good[65], orig[65], cmd[320];
    sha256_buffer_hex((const uint8_t *)"ls binary\n", 10, good);
    sha256_buffer_hex((const uint8_t *)"original sudo\n", 14, orig);
    put("usr/bin/ls", "ls binary\n");
    put("usr/bin/sudo", "trojaned sudo\n");
    uint8_t blob[2048];
    size_t len = sudo_header(blob, orig, good);
    write_rpmdb("usr/lib/sysimage/rpm/rpmdb.sqlite", blob, len);

    pkg_scan_result_t *res = calloc(1, sizeof(*res));
    ASSERT_INT_EQ(pkg_integrity_scan_rootfs(g_root, res), BOOTO_OK, "Scan succeeds");
    ASSERT_INT_EQ(res->packages_checked, 1, "One rpm package");
    ASSERT_INT_EQ(res->files_checked, 2, "sudo and ls hashed; digest-less doc skipped");
    ASSERT_INT_EQ(res->threats_detected, 1, "Trojaned sudo flagged");
    ASSERT_STR_EQ(res->findings[0].file_path, "/usr/bin/sudo", "Path from dirname + basename");
    ASSERT_STR_EQ(res->findings[0].package, "sudo", "Package from NAME tag");
    ASSERT_STR_EQ(res->findings[0].expected_hash, orig, "Expected SHA-256 recorded");

    /* Every truncation and single-byte corruption must be rejected or parsed in bounds (ASan job checks). */
    for (size_t cut = 0; cut < len; cut += 3) {
        write_rpmdb("usr/lib/sysimage/rpm/rpmdb.sqlite", blob, cut ? cut : 1);
        pkg_integrity_scan_rootfs(g_root, res);
    }
    for (size_t i = 0; i < len; i++) {
        uint8_t bad[2048];
        memcpy(bad, blob, len);
        bad[i] ^= 0xA5;
        write_rpmdb("usr/lib/sysimage/rpm/rpmdb.sqlite", bad, len);
        pkg_integrity_scan_rootfs(g_root, res);
    }

    snprintf(cmd, sizeof(cmd), "rm -rf '%s/usr/lib/sysimage' && ln -s /usr/lib/sysimage '%s/usr/lib/sysimage'", g_root,
             g_root);
    ASSERT_INT_EQ(system(cmd), 0, "plant escaping symlink");
    ASSERT_INT_EQ(pkg_integrity_scan_rootfs(g_root, res), BOOTO_ERR_NOT_FOUND,
                  "Absolute symlink out of the root is not followed to the live rpmdb");
    free(res);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    ASSERT_INT_EQ(system(cmd), 0, "cleanup");
    TEST_PASS("test_rpm_sqlite");
}

int main(void) {
    printf("\n--- Running Package Integrity Tests ---\n");
    test_md5_vectors();
    test_detects_modified_files();
    test_no_dpkg_database();
    test_pacman_mtree();
    test_rpm_sqlite();
    TEST_SUMMARY();
    return 0;
}
