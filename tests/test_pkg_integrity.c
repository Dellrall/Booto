/**
 * @file test_pkg_integrity.c
 * @brief MD5 vectors and the offline dpkg md5sums / pacman mtree integrity check.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "pkg_integrity.h"

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

int main(void) {
    printf("\n--- Running Package Integrity Tests ---\n");
    test_md5_vectors();
    test_detects_modified_files();
    test_no_dpkg_database();
    test_pacman_mtree();
    TEST_SUMMARY();
    return 0;
}
