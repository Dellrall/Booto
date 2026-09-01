/**
 * @file test_version.c
 * @brief Unit tests for version generation and constants.
 */
#include "test_framework.h"
#include "version.h"

#include <string.h>

static void test_version_constants(void) {
    TEST_START("test_version_constants");
    ASSERT_TRUE(BOOTO_VERSION_MAJOR >= 0, "Major version must be non-negative");
    ASSERT_TRUE(BOOTO_VERSION_MINOR >= 0, "Minor version must be non-negative");
    ASSERT_TRUE(strlen(BOOTO_VERSION_STRING) > 0, "Version string must not be empty");
    ASSERT_TRUE(strlen(BOOTO_GIT_HASH) > 0, "Git hash must not be empty");
    TEST_PASS("test_version_constants");
}

int main(void) {
    printf("\n--- Running Version Tests ---\n");
    test_version_constants();
    TEST_SUMMARY();
    return 0;
}
