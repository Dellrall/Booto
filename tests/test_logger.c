/**
 * @file test_logger.c
 * @brief Unit tests for forensic logger subsystem.
 */
#include "test_framework.h"
#include "logger.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void test_logger_callback_silences_stderr(void) {
    TEST_START("test_logger_callback_silences_stderr");
    char path[] = "/tmp/booto_logger_stderr_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0, "mkstemp must succeed");
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    dup2(fd, STDERR_FILENO);

    logger_init(LOG_LEVEL_DEBUG, NULL);
    logger_set_callback(mock_log_callback, NULL);
    g_last_callback_msg[0] = '\0';
    LOG_ERROR("quiet %d", 7);
    fflush(stderr);
    dup2(saved, STDERR_FILENO);
    close(saved);

    off_t size = lseek(fd, 0, SEEK_END);
    close(fd);
    unlink(path);
    ASSERT_STR_EQ(g_last_callback_msg, "quiet 7", "Callback must receive message");
    ASSERT_TRUE(size == 0, "Nothing written to stderr while callback set");
    logger_shutdown();
    TEST_PASS("test_logger_callback_silences_stderr");
}

static int g_count = 0; /* only touched inside the callback, i.e. under the logger mutex */

static void counting_callback(log_level_t level, const char *timestamp, const char *msg, void *user_data) {
    (void)level;
    (void)timestamp;
    (void)msg;
    (void)user_data;
    g_count++;
}

static void *log_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) LOG_INFO("msg %d", i);
    return NULL;
}

static void test_logger_two_threads(void) {
    TEST_START("test_logger_two_threads");
    logger_init(LOG_LEVEL_DEBUG, NULL);
    logger_set_callback(counting_callback, NULL);
    g_count = 0;
    pthread_t a, b;
    pthread_create(&a, NULL, log_worker, NULL);
    pthread_create(&b, NULL, log_worker, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    ASSERT_INT_EQ(g_count, 2000, "Every message from both threads reaches the callback");
    logger_shutdown();
    TEST_PASS("test_logger_two_threads");
}

int main(void) {
    printf("\n--- Running Logger Tests ---\n");
    test_logger_callback();
    test_logger_callback_silences_stderr();
    test_logger_two_threads();
    TEST_SUMMARY();
    return 0;
}
