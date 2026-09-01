/**
 * @file test_preload_scanner.c
 * @brief Unit tests for userland LD_PRELOAD and PAM interceptor scanner.
 */
#include "test_framework.h"
#include "preload_scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void test_ld_preload_detection(void) {
    TEST_START("test_ld_preload_detection");

    // Create temporary mock rootfs layout
    system("mkdir -p /tmp/mock_rootfs/etc/ld.so.conf.d");

    FILE *fp = fopen("/tmp/mock_rootfs/etc/ld.so.preload", "w");
    if (fp) {
        fprintf(fp, "/lib/x86_64-linux-gnu/libazazel.so\n");
        fclose(fp);
    }

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs("/tmp/mock_rootfs", &res);

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_TRUE(res.threats_detected >= 1, "Must detect active LD_PRELOAD hook");
    ASSERT_STR_EQ(res.findings[0].target_library, "/lib/x86_64-linux-gnu/libazazel.so", "Target library must match");

    system("rm -rf /tmp/mock_rootfs");
    TEST_PASS("test_ld_preload_detection");
}

int main(void) {
    printf("\n--- Running LD_PRELOAD & PAM Interceptor Tests ---\n");
    test_ld_preload_detection();
    TEST_SUMMARY();
    return 0;
}
