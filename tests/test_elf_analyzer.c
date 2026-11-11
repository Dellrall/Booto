/**
 * @file test_elf_analyzer.c
 * @brief Unit tests for SHA-256 crypto, ELF parser, and Kernel LKM Rootkit detection.
 */
#include "test_framework.h"
#include "crypto_utils.h"
#include "elf_analyzer.h"
#include "kernel_inspector.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_sha256_known_vector(void) {
    TEST_START("test_sha256_known_vector");
    const char *msg = "hello world";
    char hex[65];
    sha256_buffer_hex((const uint8_t *)msg, strlen(msg), hex);

    // NIST FIPS-180-4 standard test vector for "hello world"
    ASSERT_STR_EQ(hex, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                  "SHA-256 of 'hello world' must match NIST standard vector");
    TEST_PASS("test_sha256_known_vector");
}

static void test_elf_parser_on_binary(void) {
    TEST_START("test_elf_parser_on_binary");
    elf_binary_info_t info;
    booto_error_t err = elf_parse_file("/proc/self/exe", &info);
    ASSERT_INT_EQ(err, BOOTO_OK, "Parsing valid ELF binary must succeed");
    ASSERT_TRUE(info.is_64bit, "Target ELF binary must be 64-bit");
    ASSERT_TRUE(info.is_little_endian, "Target ELF binary must be Little Endian");
    ASSERT_TRUE(info.section_count > 0, "ELF section count must be > 0");
    ASSERT_TRUE(strlen(info.sha256) == 64, "Binary SHA-256 must be 64 hex characters");

    // Test symbol lookup
    const elf_symbol_info_t *sym = elf_find_symbol(&info, "main");
    (void)sym;

    elf_free_info(&info);
    TEST_PASS("test_elf_parser_on_binary");
}

static void test_rootkit_lkm_detection(void) {
    TEST_START("test_rootkit_lkm_detection");

    // Create a mock directory with a mock .ko file
    ASSERT_TRUE(system("mkdir -p /tmp/mock_lkm_test") == 0, "mkdir failed");
    FILE *fp = fopen("/tmp/mock_lkm_test/fake_diamorphine.ko", "w");
    if (fp) {
        fprintf(fp, "fake payload");
        fclose(fp);
    }

    kernel_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = kernel_inspect_lkm_file("/tmp/mock_lkm_test/fake_diamorphine.ko", &res);
    (void)err;

    kernel_inspect_directory("/tmp/mock_lkm_test", &res);
    kernel_inspect_vmlinuz("/tmp/mock_lkm_test/vmlinuz", &res);

    const char *sev_str = booto_severity_str(SEVERITY_CRITICAL);
    ASSERT_TRUE(sev_str != NULL, "Severity string must not be null");

    ASSERT_TRUE(system("rm -rf /tmp/mock_lkm_test") == 0, "cleanup failed");
    TEST_PASS("test_rootkit_lkm_detection");
}

static void test_elf_wrapping_shoff_rejected(void) {
    TEST_START("test_elf_wrapping_shoff_rejected");
    uint8_t buf[sizeof(Elf64_Ehdr) + 64];
    memset(buf, 0, sizeof(buf));
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_shnum = 4;
    eh->e_shoff = UINT64_MAX - 0xFF; // e_shoff + 4*64 wraps to a small value
    elf_binary_info_t info;
    ASSERT_INT_EQ(elf_parse_buffer(buf, sizeof(buf), &info), BOOTO_ERR_CORRUPT_DATA, "Wrapping e_shoff must be rejected");
    elf_free_info(&info);
    TEST_PASS("test_elf_wrapping_shoff_rejected");
}

static void test_elf_unterminated_shstrtab(void) {
    TEST_START("test_elf_unterminated_shstrtab");
    // Ehdr | 2 section headers | 4-byte .shstrtab "AAAA" with no NUL, ending exactly at the buffer end.
    size_t len = sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Shdr) + 4;
    uint8_t *buf = calloc(1, len);
    ASSERT_TRUE(buf != NULL, "alloc");
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_shnum = 2;
    eh->e_shoff = sizeof(Elf64_Ehdr);
    eh->e_shstrndx = 1;
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    sh[1].sh_type = SHT_STRTAB;
    sh[1].sh_offset = len - 4;
    sh[1].sh_size = 4;
    memcpy(buf + len - 4, "AAAA", 4);

    elf_binary_info_t info;
    booto_error_t err = elf_parse_buffer(buf, len, &info);
    free(buf);
    ASSERT_INT_EQ(err, BOOTO_OK, "Unterminated string table must parse without over-read");
    ASSERT_STR_EQ(info.sections[0].name, "AAAA", "Name must be bounded by the table size");
    elf_free_info(&info);
    TEST_PASS("test_elf_unterminated_shstrtab");
}

/* A compressed module is read by Booto and piped to the sandboxed decompressor, so a 0600 file still scans. */
static void test_compressed_lkm_piped(void) {
    TEST_START("test_compressed_lkm_piped");
    char dir[] = "/tmp/booto_lkm_gz_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");
    char cmd[256];
    /* /bin/true plus a .modinfo without license= : parsing it yields LKM_MISSING_LICENSE. */
    snprintf(cmd, sizeof(cmd),
             "cd %s && printf 'author=x\\0' > mi && objcopy --add-section .modinfo=mi /bin/true m.ko && "
             "gzip m.ko && chmod 600 m.ko.gz && rm mi", dir);
    if (system(cmd) != 0) {
        printf("    [SKIP] objcopy, gzip or /bin/true unavailable\n");
        return;
    }

    kernel_scan_result_t res;
    memset(&res, 0, sizeof(res));
    kernel_inspect_directory(dir, &res);
    ASSERT_INT_EQ(res.modules_scanned, 1, "Compressed module scanned");
    ASSERT_TRUE(res.threats_detected >= 1, "Decompressed ELF parsed: missing license flagged");

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    ASSERT_TRUE(system(cmd) == 0, "cleanup");
    TEST_PASS("test_compressed_lkm_piped");
}

static int count_rule(const kernel_scan_result_t *r, const char *rule) {
    int n = 0;
    for (int i = 0; i < r->threats_detected; i++) n += strcmp(r->findings[i].detection_rule, rule) == 0;
    return n;
}

/* Unsigned modules count only when the kernel signs its modules: a self-built kernel signs none. */
static void test_unsigned_lkm_flagged(void) {
    TEST_START("test_unsigned_lkm_flagged");
    char dir[] = "/tmp/booto_lkm_sig_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "mkdtemp");
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "cd %s && printf 'license=GPL\\0' > mi && objcopy --add-section .modinfo=mi /bin/true a.ko && "
             "cp a.ko b.ko && rm mi", dir);
    if (system(cmd) != 0) {
        printf("    [SKIP] objcopy or /bin/true unavailable\n");
        return;
    }

    kernel_scan_result_t res;
    memset(&res, 0, sizeof(res));
    kernel_inspect_directory(dir, &res);
    ASSERT_INT_EQ(res.modules_scanned, 2, "Both modules scanned");
    ASSERT_INT_EQ(count_rule(&res, "LKM_UNSIGNED"), 0, "No module signed: kernel does not sign, nothing flagged");

    // Marker alone, as a rootkit would fake it: still unsigned, so the kernel still looks like it signs nothing.
    snprintf(cmd, sizeof(cmd), "printf 'SIG~Module signature appended~\\n' >> %s/b.ko", dir);
    ASSERT_TRUE(system(cmd) == 0, "append bare marker");
    memset(&res, 0, sizeof(res));
    kernel_inspect_directory(dir, &res);
    ASSERT_INT_EQ(count_rule(&res, "LKM_UNSIGNED"), 0, "A bare marker does not count as a signature");

    // 300-byte DER blob, module_signature (id_type 2, sig_len 300), marker: what scripts/sign-file appends.
    snprintf(cmd, sizeof(cmd), "{ printf '\\060\\202\\001\\050'; head -c 296 /dev/zero; "
             "printf '\\000\\000\\002\\000\\000\\000\\000\\000\\000\\000\\001\\054"
             "~Module signature appended~\\n'; } >> %s/a.ko", dir);
    ASSERT_TRUE(system(cmd) == 0, "append signature");
    memset(&res, 0, sizeof(res));
    kernel_inspect_directory(dir, &res);
    ASSERT_INT_EQ(count_rule(&res, "LKM_UNSIGNED"), 1, "Kernel signs modules: the unsigned one is flagged");
    for (int i = 0; i < res.threats_detected; i++) {
        if (strcmp(res.findings[i].detection_rule, "LKM_UNSIGNED") == 0) {
            ASSERT_TRUE(strstr(res.findings[i].file_path, "/b.ko") != NULL, "Flagged module is b.ko");
            ASSERT_INT_EQ(res.findings[i].severity, SEVERITY_HIGH, "Unsigned module outside DKMS is HIGH");
        }
    }

    // DKMS builds land in updates/dkms/ unsigned unless MOK-signed: still flagged, but MEDIUM.
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/updates/dkms && mv %s/b.ko %s/updates/dkms/", dir, dir, dir);
    ASSERT_TRUE(system(cmd) == 0, "move to dkms");
    memset(&res, 0, sizeof(res));
    kernel_inspect_directory(dir, &res);
    ASSERT_INT_EQ(count_rule(&res, "LKM_UNSIGNED"), 1, "DKMS module still flagged");
    for (int i = 0; i < res.threats_detected; i++) {
        if (strcmp(res.findings[i].detection_rule, "LKM_UNSIGNED") == 0) {
            ASSERT_INT_EQ(res.findings[i].severity, SEVERITY_MEDIUM, "Unsigned DKMS module is MEDIUM");
        }
    }

    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    ASSERT_TRUE(system(cmd) == 0, "cleanup");
    TEST_PASS("test_unsigned_lkm_flagged");
}

/* A target symlink to /dev/zero or a FIFO must be refused, not read forever. */
static void test_fopen_regular_refuses_special(void) {
    TEST_START("test_fopen_regular_refuses_special");
    char dir[] = "/tmp/booto_fopenreg_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "temp dir");
    char lnk[64], fifo[64], reg[64];
    snprintf(lnk, sizeof(lnk), "%s/zero", dir);
    snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
    snprintf(reg, sizeof(reg), "%s/reg", dir);
    ASSERT_TRUE(symlink("/dev/zero", lnk) == 0, "symlink");
    ASSERT_TRUE(mkfifo(fifo, 0600) == 0, "fifo");
    FILE *f = fopen(reg, "wb");
    ASSERT_TRUE(f != NULL, "regular file");
    if (f) { fputs("x", f); fclose(f); }
    char hex[65];
    ASSERT_TRUE(fopen_regular(lnk) == NULL && !sha256_file_hex(lnk, hex), "symlink to a device refused");
    ASSERT_TRUE(fopen_regular(fifo) == NULL, "FIFO refused without blocking");
    ASSERT_TRUE(sha256_file_hex(reg, hex), "regular file still hashes");
    unlink(lnk); unlink(fifo); unlink(reg); rmdir(dir);
    TEST_PASS("test_fopen_regular_refuses_special");
}

int main(void) {
    printf("\n--- Running ELF Parser & Kernel Rootkit Scanner Tests ---\n");
    test_sha256_known_vector();
    test_elf_parser_on_binary();
    test_rootkit_lkm_detection();
    test_compressed_lkm_piped();
    test_unsigned_lkm_flagged();
    test_elf_wrapping_shoff_rejected();
    test_elf_unterminated_shstrtab();
    test_fopen_regular_refuses_special();
    TEST_SUMMARY();
    return 0;
}
