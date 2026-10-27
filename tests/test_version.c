/**
 * @file test_version.c
 * @brief Unit tests for version generation and constants.
 */
#include "test_framework.h"
#include "version.h"

#include <stdio.h>
#include <string.h>

static void test_version_constants(void) {
    TEST_START("test_version_constants");
    ASSERT_TRUE(BOOTO_VERSION_MAJOR >= 0, "Major version must be non-negative");
    ASSERT_TRUE(BOOTO_VERSION_MINOR >= 0, "Minor version must be non-negative");
    ASSERT_TRUE(strlen(BOOTO_VERSION_STRING) > 0, "Version string must not be empty");
    ASSERT_TRUE(strlen(BOOTO_GIT_HASH) > 0, "Git hash must not be empty");
    TEST_PASS("test_version_constants");
}

static void test_version_string_format(void) {
    TEST_START("test_version_string_format");
    unsigned major = 0, minor = 0, patch = 0;
    int n = sscanf(BOOTO_VERSION_STRING, "%u.%u.%u", &major, &minor, &patch);
    ASSERT_TRUE(n == 3 || strcmp(BOOTO_VERSION_STRING, "0.0.0-unknown") == 0,
                "Version string must start with MAJOR.MINOR.PATCH");
    TEST_PASS("test_version_string_format");
}

int main(void) {
    printf("\n--- Running Version Tests ---\n");
    test_version_constants();
    test_version_string_format();
    TEST_SUMMARY();
    return 0;
}
