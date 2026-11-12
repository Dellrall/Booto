/**
 * @file disk_image.h
 * @brief Read-only raw disk imaging (--acquire): a dd-style copy hashed with SHA-256 as it is read.
 */
#ifndef BOOTO_DISK_IMAGE_H
#define BOOTO_DISK_IMAGE_H

#include "booto.h"

#include <stdint.h>

typedef struct {
    uint64_t bytes;      /**< Bytes written to the image (the source size) */
    uint64_t bad_bytes;  /**< Unreadable bytes, written as zeros and listed in <image>.log */
    char sha256[65];     /**< SHA-256 of the image, also written to <image>.sha256 */
} disk_image_result_t;

/**
 * @brief Copy @p src (opened O_RDONLY) to a new file @p dst (never overwritten), hashing while copying.
 *        Unreadable 4 KiB blocks are zero-filled and their offsets logged to <dst>.log.
 */
booto_error_t disk_image_acquire(const char *src, const char *dst, disk_image_result_t *res);

#endif
