/**
 * @file test_quarantine.c
 * @brief Quarantine ZIP: decrypts with the standard password, keeps samples non-executable, never leaves the target.
 */
#include "test_framework.h"
#include "quarantine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[] = "/tmp/test_booto_quar_XXXXXX";

static void write_file(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fputs(data, f);
    fclose(f);
}

static bool have_python(void) { return system("python3 -c '' >/dev/null 2>&1") == 0; }

static void test_roundtrip(void) {
    TEST_START("test_roundtrip");
    char root[300], out[300], p[400], zip[512];
    snprintf(root, sizeof(root), "%s/root", g_dir);
    snprintf(out, sizeof(out), "%s/out", g_dir);
    mkdir(root, 0700);
    mkdir(out, 0700);
    snprintf(p, sizeof(p), "%s/lib", root);
    mkdir(p, 0700);
    snprintf(p, sizeof(p), "%s/lib/evil.so", root);
    write_file(p, "#!/bin/sh\necho pwned\n");
    chmod(p, 0755);

    quarantine_t *q = quarantine_open(out);
    ASSERT_TRUE(q != NULL, "open");
    ASSERT_INT_EQ(quarantine_add(q, "preload", root, p, QUARANTINE_MAX_ITEM), BOOTO_OK, "add sample");
    ASSERT_INT_EQ(quarantine_add(q, "preload", root, p, QUARANTINE_MAX_ITEM), BOOTO_OK, "repeat is a no-op");
    char big[400];
    snprintf(big, sizeof(big), "%s/lib/big.bin", root);
    write_file(big, "0123456789");
    ASSERT_INT_EQ(quarantine_add(q, "pkg", root, big, 4), BOOTO_OK, "add truncated");
    ASSERT_INT_EQ(quarantine_close(q, zip, sizeof(zip)), 2, "two files exported");

    struct stat st;
    ASSERT_TRUE(stat(zip, &st) == 0 && (st.st_mode & 0777) == 0400, "archive is read-only");
    if (!have_python()) {
        printf("    python3 missing: skipping decrypt check\n");
        TEST_PASS("test_roundtrip");
        return;
    }
    char cmd[1200];
    snprintf(cmd, sizeof(cmd),
             "python3 -I -c 'import sys,zipfile\n"
             "z=zipfile.ZipFile(sys.argv[1])\n"
             "assert z.namelist()==[\"preload/lib/evil.so.malware\",\"pkg/lib/big.bin.malware\"],z.namelist()\n"
             "i=z.getinfo(\"preload/lib/evil.so.malware\")\n"
             "assert i.flag_bits&1 and (i.external_attr>>16)&0o111==0\n"
             "assert z.read(i,pwd=b\"infected\")==b\"#!/bin/sh\\necho pwned\\n\"\n"
             "assert z.read(\"pkg/lib/big.bin.malware\",pwd=b\"infected\")==b\"0123\"\n"
             "try:\n z.read(i,pwd=b\"wrong\"); sys.exit(1)\n"
             "except RuntimeError: pass' '%s'",
             zip);
    ASSERT_INT_EQ(system(cmd), 0, "python zipfile decrypts with password infected");
    TEST_PASS("test_roundtrip");
}

static void test_escape_rejected(void) {
    TEST_START("test_escape_rejected");
    char root[300], out[300], link[400], zip[512];
    snprintf(root, sizeof(root), "%s/root2", g_dir);
    snprintf(out, sizeof(out), "%s/out2", g_dir);
    mkdir(root, 0700);
    mkdir(out, 0700);
    snprintf(link, sizeof(link), "%s/shadow", root);
    ASSERT_TRUE(symlink("/etc/hostname", link) == 0, "plant absolute symlink");

    quarantine_t *q = quarantine_open(out);
    ASSERT_INT_EQ(quarantine_add(q, "pkg", root, link, QUARANTINE_MAX_ITEM), BOOTO_ERR_PERMISSION_DENIED,
                  "symlink out of the target is refused");
    char dots[400];
    snprintf(dots, sizeof(dots), "%s/../root/lib/evil.so", root);
    ASSERT_INT_EQ(quarantine_add(q, "pkg", root, dots, QUARANTINE_MAX_ITEM), BOOTO_ERR_PERMISSION_DENIED,
                  "dot-dot out of the target is refused");
    ASSERT_INT_EQ(quarantine_close(q, zip, sizeof(zip)), 0, "nothing exported");
    ASSERT_STR_EQ(zip, "", "no archive created when nothing was added");
    TEST_PASS("test_escape_rejected");
}

int main(void) {
    printf("Running quarantine tests...\n");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        return 1;
    }
    test_roundtrip();
    test_escape_rejected();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "chmod -R u+w '%s'; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_dir);
    TEST_SUMMARY();
    return 0;
}
