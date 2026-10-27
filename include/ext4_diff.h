/**
 * @file ext4_diff.h
 * @brief Raw Ext4 superblock statistics (hidden-inode cross-view is not implemented).
 */
#ifndef BOOTO_EXT4_DIFF_H
#define BOOTO_EXT4_DIFF_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t total_disk_inodes;
    uint32_t allocated_raw_inodes;
    bool cross_view_performed; /**< Always false: raw-inode vs VFS cross-view is not implemented. */
} ext4_diff_result_t;

/**
 * @brief Read Ext4 superblock inode statistics from a raw block device.
 * @param block_dev Path to raw block device (e.g. /dev/nvme0n1p2).
 * @param vfs_mount_point Reserved for the future cross-view walk; currently unused.
 * @param result Output statistics.
 * @return BOOTO_OK on success; BOOTO_ERR_CORRUPT_DATA if not Ext4 or the superblock is inconsistent;
 *         BOOTO_ERR_PERMISSION_DENIED / BOOTO_ERR_NOT_FOUND / BOOTO_ERR_IO if the device cannot be read.
 */
booto_error_t ext4_diff_scan(const char *block_dev, const char *vfs_mount_point, ext4_diff_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_EXT4_DIFF_H */
