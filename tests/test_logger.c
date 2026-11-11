/**
 * @file test_logger.c
 * @brief Unit tests for forensic logger subsystem.
 */
#define _XOPEN_SOURCE 700 // posix_openpt, grantpt, unlockpt, ptsname
#include "test_framework.h"
#include "logger.h"

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
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

static void test_logger_use_color(void) {
    TEST_START("test_logger_use_color");
    FILE *file = tmpfile();
    ASSERT_TRUE(file != NULL, "tmpfile opens");
    unsetenv("NO_COLOR");
    ASSERT_INT_EQ(logger_use_color(file), 0, "A file gets no color");
    fclose(file);

    int master = posix_openpt(O_RDWR | O_NOCTTY);
    ASSERT_TRUE(master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0, "pty opens");
    FILE *tty = fopen(ptsname(master), "w");
    ASSERT_TRUE(tty != NULL, "pty slave opens");
    ASSERT_INT_EQ(logger_use_color(tty), 1, "A terminal gets color");
    setenv("NO_COLOR", "1", 1);
    ASSERT_INT_EQ(logger_use_color(tty), 0, "NO_COLOR turns color off");
    setenv("NO_COLOR", "", 1);
    ASSERT_INT_EQ(logger_use_color(tty), 1, "Empty NO_COLOR is ignored");
    unsetenv("NO_COLOR");
    fclose(tty);
    close(master);
    TEST_PASS("test_logger_use_color");
}

/* A crash writes its report to the fallback path when the primary cannot be opened, then dies with the signal. */
static void test_crash_handler_report(void) {
    TEST_START("test_crash_handler_report");
    char dir[] = "/tmp/booto_crash_XXXXXX";
    ASSERT_TRUE(mkdtemp(dir) != NULL, "temp dir");
    char fallback[64];
    snprintf(fallback, sizeof(fallback), "%s/crash.txt", dir);
    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDERR_FILENO);
        logger_install_crash_handler("9.9.9-test", "/nonexistent/booto/crash.txt", fallback);
        raise(SIGSEGV);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV, "child still dies with SIGSEGV");
    char buf[4096] = {0};
    FILE *f = fopen(fallback, "r");
    ASSERT_TRUE(f != NULL, "report written to the fallback");
    if (f) { size_t got = fread(buf, 1, sizeof(buf) - 1, f); (void)got; fclose(f); }
    ASSERT_TRUE(strstr(buf, "version: 9.9.9-test") && strstr(buf, "signal: 11") && strstr(buf, "backtrace:"),
                "report has version, signal and backtrace");
    unlink(fallback);
    rmdir(dir);
    TEST_PASS("test_crash_handler_report");
}

int main(void) {
    printf("\n--- Running Logger Tests ---\n");
    test_logger_callback();
    test_logger_callback_silences_stderr();
    test_logger_two_threads();
    test_logger_use_color();
    test_crash_handler_report();
    TEST_SUMMARY();
    return 0;
}
