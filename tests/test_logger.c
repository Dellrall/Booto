/**
 * @file test_logger.c
 * @brief Unit tests for forensic logger subsystem.
 */
#include "test_framework.h"
#include "logger.h"

#include <string.h>

static char g_last_callback_msg[2048] = {0};
static log_level_t g_last_callback_level = LOG_LEVEL_DEBUG;

static void mock_log_callback(log_level_t level, const char *timestamp, const char *msg, void *user_data) {
    (void)timestamp;
    (void)user_data;
    g_last_callback_level = level;
    snprintf(g_last_callback_msg, sizeof(g_last_callback_msg), "%s", msg);
}

static void test_logger_callback(void) {
    TEST_START("test_logger_callback");
    logger_init(LOG_LEVEL_DEBUG, NULL);
    logger_set_callback(mock_log_callback, NULL);

    LOG_INFO("Test payload %d", 42);
    ASSERT_STR_EQ(g_last_callback_msg, "Test payload 42", "Logger message must match formatted payload");
    ASSERT_INT_EQ(g_last_callback_level, LOG_LEVEL_INFO, "Logger callback level must match");

    logger_shutdown();
    TEST_PASS("test_logger_callback");
}

int main(void) {
    printf("\n--- Running Logger Tests ---\n");
    test_logger_callback();
    TEST_SUMMARY();
    return 0;
}
