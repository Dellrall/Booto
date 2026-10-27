/**
 * @file ext4_diff.c
 * @brief Raw Ext4 superblock statistics. Hidden-inode cross-view detection is not implemented.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "ext4_diff.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXT4_SUPERBLOCK_OFFSET 1024
#define EXT4_MAGIC             0xEF53

#pragma pack(push, 1)
typedef struct {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_r_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
} ext4_superblock_raw_t;
#pragma pack(pop)

booto_error_t ext4_diff_scan(const char *block_dev, const char *vfs_mount_point, ext4_diff_result_t *result) {
    if (!block_dev || !result) return BOOTO_ERR_INVALID_ARG;
    (void)vfs_mount_point;

    memset(result, 0, sizeof(*result));
    LOG_INFO("Reading raw Ext4 superblock statistics on: %s", block_dev);

    int fd = open(block_dev, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        LOG_ERROR("Cannot open block device '%s': %s", block_dev, strerror(e));
        if (e == EACCES || e == EPERM) return BOOTO_ERR_PERMISSION_DENIED;
        return e == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    }

    ext4_superblock_raw_t sb;
    ssize_t n = pread(fd, &sb, sizeof(sb), EXT4_SUPERBLOCK_OFFSET);
    close(fd);
    if (n != (ssize_t)sizeof(sb)) {
        LOG_ERROR("Failed to read Ext4 superblock from '%s'", block_dev);
        return BOOTO_ERR_IO;
    }

    if (sb.s_magic != EXT4_MAGIC) {
        LOG_INFO("Device '%s' is not an Ext4 filesystem (magic: 0x%04x)", block_dev, sb.s_magic);
        return BOOTO_ERR_CORRUPT_DATA;
    }
    if (sb.s_free_inodes_count > sb.s_inodes_count) {
        LOG_ERROR("Corrupt Ext4 superblock on '%s': free inodes exceed total", block_dev);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    result->total_disk_inodes = sb.s_inodes_count;
    result->allocated_raw_inodes = sb.s_inodes_count - sb.s_free_inodes_count;
    result->cross_view_performed = false;

    LOG_INFO("Ext4 superblock: %u total inodes, %u allocated (hidden-inode cross-view not performed)",
             result->total_disk_inodes, result->allocated_raw_inodes);
    return BOOTO_OK;
}
