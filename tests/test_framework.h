/**
 * @file test_framework.h
 * @brief Minimal, zero-dependency C11 unit test framework for Booto.
 */
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define TEST_START(name) \
    printf("  [RUN ] %s\n", name); \
    g_tests_run++;

#define ASSERT_TRUE(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("    \033[31m[FAIL]\033[0m %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #condition); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_STR_EQ(actual, expected, msg) \
    do { \
        const char *a_val = (const char *)(actual); \
        const char *e_val = (const char *)(expected); \
        if (a_val == NULL || e_val == NULL || strcmp(a_val, e_val) != 0) { \
            printf("    \033[31m[FAIL]\033[0m %s:%d: %s (expected '%s', got '%s')\n", \
                   __FILE__, __LINE__, msg, e_val ? e_val : "NULL", a_val ? a_val : "NULL"); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_INT_EQ(actual, expected, msg) \
    do { \
        if ((actual) != (expected)) { \
            printf("    \033[31m[FAIL]\033[0m %s:%d: %s (expected %d, got %d)\n", \
                   __FILE__, __LINE__, msg, (int)(expected), (int)(actual)); \
            g_tests_failed++; \
            return; \
        } \
    } while (0)

#define TEST_PASS(name) \
    printf("    \033[32m[PASS]\033[0m %s\n", name)

#define TEST_SUMMARY() \
    do { \
        printf("\n========================================\n"); \
        printf("Test Summary: %d run, %d passed, %d failed\n", \
               g_tests_run, g_tests_run - g_tests_failed, g_tests_failed); \
        printf("========================================\n"); \
        if (g_tests_failed > 0) return 1; \
    } while (0)

#endif /* TEST_FRAMEWORK_H */
