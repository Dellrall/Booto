/**
 * @file ext4_diff.h
 * @brief Raw Ext4 disk inode vs VFS directory table cross-view differential scanner.
 */
#ifndef BOOTO_EXT4_DIFF_H
#define BOOTO_EXT4_DIFF_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HIDDEN_INODES 32

typedef struct {
    uint32_t inode_num;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size_bytes;
    uint32_t links_count;
    char description[256];
} ext4_unlinked_inode_t;

typedef struct {
    uint32_t total_disk_inodes;
    uint32_t allocated_raw_inodes;
    uint32_t vfs_visible_inodes;
    int hidden_inodes_count;
    ext4_unlinked_inode_t hidden_inodes[MAX_HIDDEN_INODES];
} ext4_diff_result_t;

/**
 * @brief Perform cross-view differential analysis between raw block device and mounted VFS rootfs.
 * @param block_dev Path to raw block device (e.g. /dev/nvme0n1p2).
 * @param vfs_mount_point Path to mounted read-only directory (e.g. /tmp/booto_target_mnt).
 * @param result Output structure to record hidden inode anomalies.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t ext4_diff_scan(const char *block_dev, const char *vfs_mount_point, ext4_diff_result_t *result);

/**
 * @brief Mock differential scan for non-root verification environments.
 */
booto_error_t ext4_diff_mock(ext4_diff_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_EXT4_DIFF_H */
