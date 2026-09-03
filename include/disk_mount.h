/**
 * @file disk_mount.h
 * @brief Block device discovery and forensic read-only mounting subsystem for Booto.
 */
#ifndef BOOTO_DISK_MOUNT_H
#define BOOTO_DISK_MOUNT_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DISCOVERED_PARTITIONS 64
#define DEFAULT_RO_MOUNT_POINT    "/tmp/booto_target_mnt"

/**
 * @brief Represents an enumerated block device partition.
 */
typedef struct {
    char dev_path[128];     /**< Full device path (e.g., /dev/nvme0n1p2) */
    char name[64];          /**< Device node name (e.g., nvme0n1p2) */
    char size_str[32];      /**< Human-readable size (e.g., 512 GB) */
    uint64_t size_bytes;    /**< Exact size in bytes */
    char fs_type[32];       /**< Filesystem type (ext4, vfat, xfs, etc.) */
    char label[64];         /**< Filesystem volume label */
    char uuid[64];          /**< UUID */
    char mount_point[256];  /**< Current mountpoint if mounted */
    bool is_mounted_ro;     /**< True if safely mounted read-only */
    bool is_target;         /**< Selected as the forensic target */
    bool is_removable;      /**< True if USB / removable media */
} disk_partition_t;

/**
 * @brief Collection of discovered partitions.
 */
typedef struct {
    disk_partition_t partitions[MAX_DISCOVERED_PARTITIONS];
    int count;
} disk_discovery_result_t;

/**
 * @brief Discover all block storage devices and partitions on the host.
 * @param result Pointer to output discovery result struct.
 * @param include_mock If true or non-root, injects mock test partitions for verification.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t disk_discover_partitions(disk_discovery_result_t *result, bool include_mock);

/**
 * @brief Safely mount a partition strictly READ-ONLY (MS_RDONLY, noload).
 * @param dev_path Path to device (e.g., /dev/nvme0n1p2).
 * @param mount_point Target directory (e.g., /tmp/booto_target_mnt).
 * @param fs_type Optional filesystem type string (or NULL for auto-detect).
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t disk_mount_ro(const char *dev_path, const char *mount_point, const char *fs_type);

/**
 * @brief Safely unmount a previously mounted target partition.
 * @param mount_point Target directory to unmount.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t disk_unmount(const char *mount_point);

/**
 * @brief Directly probe superblock magic bytes of a block device to identify filesystem.
 * @param dev_path Device node path (e.g., /dev/sda1).
 * @param fs_buf Output buffer to receive filesystem name ("ext4", "vfat", "ntfs", "btrfs", "xfs", "iso9660", "unknown").
 * @param fs_buf_size Size of output buffer.
 * @param label_buf Optional output buffer for volume label (may be NULL).
 * @param label_buf_size Size of label buffer.
 * @return BOOTO_OK on successful detection, BOOTO_ERR_* on failure.
 */
booto_error_t disk_probe_fs_magic(const char *dev_path, char *fs_buf, size_t fs_buf_size, char *label_buf, size_t label_buf_size);

/**
 * @brief Forensically unlock a LUKS1/LUKS2 encrypted target partition strictly READ-ONLY.
 * @param dev_path Path to encrypted block device (e.g. /dev/nvme0n1p3).
 * @param mapper_name Mapper target name (e.g. booto_target_decrypted).
 * @param passphrase Decryption passphrase.
 * @return BOOTO_OK on success, BOOTO_ERR_PERMISSION_DENIED on bad passphrase, BOOTO_ERR_IO on failure.
 */
booto_error_t disk_luks_open_ro(const char *dev_path, const char *mapper_name, const char *passphrase);

/**
 * @brief Safely close a decrypted LUKS mapper device.
 * @param mapper_name Mapper target name to close.
 * @return BOOTO_OK on success.
 */
booto_error_t disk_luks_close(const char *mapper_name);

/**
 * @brief Helper to format bytes into human-readable string (KB, MB, GB, TB).
 */
const char *disk_format_size(uint64_t bytes, char *buf, size_t buf_size);

/**
 * @brief Check if the current process has effective root / CAP_SYS_ADMIN privileges.
 */
bool disk_is_running_as_root(void);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_DISK_MOUNT_H */
