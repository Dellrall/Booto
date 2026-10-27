/**
 * @file booto.h
 * @brief Core global types, error codes, and runtime context for Booto.
 */
#ifndef BOOTO_H
#define BOOTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "version.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes returned across Booto subsystems.
 */
typedef enum {
    BOOTO_OK                    =  0,
    BOOTO_ERR_GENERIC           = -1,
    BOOTO_ERR_INVALID_ARG       = -2,
    BOOTO_ERR_OUT_OF_MEMORY     = -3,
    BOOTO_ERR_IO                = -4,
    BOOTO_ERR_MOUNT_FAILED      = -5,
    BOOTO_ERR_PERMISSION_DENIED = -6,
    BOOTO_ERR_NOT_FOUND         = -7,
    BOOTO_ERR_CORRUPT_DATA      = -8,
    BOOTO_ERR_LUKS_LOCKED       = -9,
    BOOTO_ERR_CANCELLED         = -10
} booto_error_t;

/**
 * @brief Runtime mode of operation.
 */
typedef enum {
    BOOTO_MODE_TUI,      /**< Interactive raw termios/ANSI dynamic window manager (Default) */
    BOOTO_MODE_CLI,      /**< Headless/scripted CLI scanner */
    BOOTO_MODE_DRY_RUN   /**< Print the planned scan and exit without touching any disk */
} booto_mode_t;

/**
 * @brief Global execution context & configuration.
 */
typedef struct {
    booto_mode_t mode;
    bool verbose;
    bool mock_drives;
    char target_dev[128];      /**< Raw block device to scan (-t) */
    char target_rootfs[512];   /**< Already-available rootfs directory to inspect (-s) */
    char persistence_dir[512]; /**< Case report output directory (-p) */
} booto_context_t;

/**
 * @brief Initialize the global context with safe defaults.
 * @param ctx Pointer to booto_context_t instance.
 */
void booto_context_init(booto_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_H */
