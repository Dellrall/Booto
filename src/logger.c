/**
 * @file logger.c
 * @brief Implementation of forensic logger for Booto.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* Guards every g_* below; held while dispatching so the callback is serialised. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static log_level_t g_min_level = LOG_LEVEL_INFO;
static FILE *g_log_file = NULL;
static log_callback_fn g_callback = NULL;
static void *g_callback_user_data = NULL;

static const char *level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:    return "DEBUG";
        case LOG_LEVEL_INFO:     return "INFO ";
        case LOG_LEVEL_WARN:     return "WARN ";
        case LOG_LEVEL_ERROR:    return "ERROR";
        case LOG_LEVEL_CRITICAL: return "CRIT ";
        default:                 return "UNK  ";
    }
}

static const char *level_to_color(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:    return "\033[36m"; // Cyan
        case LOG_LEVEL_INFO:     return "\033[32m"; // Green
        case LOG_LEVEL_WARN:     return "\033[33m"; // Yellow
        case LOG_LEVEL_ERROR:    return "\033[31m"; // Red
        case LOG_LEVEL_CRITICAL: return "\033[35;1m"; // Bold Magenta
        default:                 return "\033[0m";
    }
}

int logger_init(log_level_t min_level, const char *log_file) {
    int rc = 0;
    pthread_mutex_lock(&g_lock);
    g_min_level = min_level;
    if (log_file != NULL && strlen(log_file) > 0) {
        if (g_log_file) {
            fclose(g_log_file);
        }
        g_log_file = fopen(log_file, "a");
        if (!g_log_file) {
            fprintf(stderr, "Warning: Failed to open log file '%s'\n", log_file);
            rc = -1;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

void logger_set_callback(log_callback_fn callback, void *user_data) {
    pthread_mutex_lock(&g_lock);
    g_callback = callback;
    g_callback_user_data = user_data;
    pthread_mutex_unlock(&g_lock);
}

void logger_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    if (g_log_file) {
        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    g_callback = NULL;
    g_callback_user_data = NULL;
    pthread_mutex_unlock(&g_lock);
}

void log_message(log_level_t level, const char *fmt, ...) {
    pthread_mutex_lock(&g_lock);
    if (level < g_min_level) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    char time_buf[32];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    char msg_buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    // 1. Console only when no UI callback owns the screen (raw stderr would paint over the TUI)
    if (!g_callback) {
        fprintf(stderr, "%s[%s] [%s]\033[0m %s\n", level_to_color(level), time_buf,
                level_to_string(level), msg_buf);
    }

    // 2. Output to log file if configured
    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] %s\n", time_buf, level_to_string(level), msg_buf);
        fflush(g_log_file);
    }

    // 3. Dispatch to UI/TUI callback if registered
    if (g_callback) {
        g_callback(level, time_buf, msg_buf, g_callback_user_data);
    }
    pthread_mutex_unlock(&g_lock);
}
