/**
 * @file logger.h
 * @brief Thread-safe, formatted forensic logger for Booto.
 */
#ifndef BOOTO_LOGGER_H
#define BOOTO_LOGGER_H

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

/**
 * @brief Callback function type for UI / TUI log capture.
 */
typedef void (*log_callback_fn)(log_level_t level, const char *timestamp, const char *msg, void *user_data);

/**
 * @brief Initialize logger subsystem.
 * @param min_level Minimum log level to output.
 * @param log_file Optional file path to append logs to (can be NULL).
 */
int logger_init(log_level_t min_level, const char *log_file);

/**
 * @brief Set a custom UI callback to receive streaming log lines.
 */
void logger_set_callback(log_callback_fn callback, void *user_data);

/**
 * @brief Close log files and cleanup logger.
 */
void logger_shutdown(void);

/**
 * @brief Log a message with formatted arguments.
 */
void log_message(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Clean C99/C11 variadic macros */
#define LOG_DEBUG(...)    log_message(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)     log_message(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARN(...)     log_message(LOG_LEVEL_WARN, __VA_ARGS__)
#define LOG_ERROR(...)    log_message(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_CRITICAL(...) log_message(LOG_LEVEL_CRITICAL, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_LOGGER_H */
