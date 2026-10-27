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
 * @param include_mock If true, appends the built-in mock partition set (for tests/demo); otherwise only real devices are returned (possibly none).
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t disk_discover_partitions(disk_discovery_result_t *result, bool include_mock);

/**
 * @brief Safely mount a partition strictly READ-ONLY. Sets BLKROSET on the device first and uses
 *        per-fs no-replay options (ext3/ext4 noload, xfs norecovery, btrfs nologreplay).
 * @param dev_path Path to device (e.g., /dev/nvme0n1p2).
 * @param mount_point Target directory (created 0700 if missing; must be a private dir owned by euid).
 * @param fs_type Optional filesystem type string (or NULL for auto-detect).
 * @return BOOTO_OK on success, BOOTO_ERR_PERMISSION_DENIED if not root or unsafe mount dir,
 *         BOOTO_ERR_IO if the device cannot be set read-only, BOOTO_ERR_MOUNT_FAILED if no mount succeeded.
 */
booto_error_t disk_mount_ro(const char *dev_path, const char *mount_point, const char *fs_type);

/**
 * @brief Safely unmount a previously mounted target partition.
 * @param mount_point Target directory to unmount.
 * @return BOOTO_OK on success, BOOTO_ERR_PERMISSION_DENIED if not root, BOOTO_ERR_IO on failure.
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
 *        Runs `cryptsetup open --readonly --key-file=-` without a shell; passphrase is passed on stdin.
 * @param dev_path Path to encrypted block device (e.g. /dev/nvme0n1p3).
 * @param mapper_name Mapper target name, must match [A-Za-z0-9_-]{1,63}.
 * @param passphrase Decryption passphrase (exact bytes, no trailing newline added).
 * @return BOOTO_OK on success, BOOTO_ERR_INVALID_ARG on bad mapper name,
 *         BOOTO_ERR_PERMISSION_DENIED on bad passphrase or non-root, BOOTO_ERR_IO on other failure.
 */
booto_error_t disk_luks_open_ro(const char *dev_path, const char *mapper_name, const char *passphrase);

/**
 * @brief Safely close a decrypted LUKS mapper device (`cryptsetup close`, no shell).
 * @param mapper_name Mapper target name to close, must match [A-Za-z0-9_-]{1,63}.
 * @return BOOTO_OK on success, BOOTO_ERR_INVALID_ARG, BOOTO_ERR_PERMISSION_DENIED if not root, BOOTO_ERR_IO on failure.
 */
booto_error_t disk_luks_close(const char *mapper_name);

/**
 * @brief Run argv[0] via fork+execvp (no shell). If stdin_data != NULL, its exact stdin_len bytes are
 *        written to the child's stdin, then closed. Child stdout/stderr go to /dev/null.
 * @param exit_status Optional; receives the child exit code, or -1 if killed by signal / fork failed.
 * @return BOOTO_OK on exit 0, BOOTO_ERR_NOT_FOUND if exec failed (exit 127), otherwise BOOTO_ERR_GENERIC.
 */
booto_error_t disk_exec_argv(const char *const argv[], const char *stdin_data, size_t stdin_len, int *exit_status);

/**
 * @brief Run argv[0] via fork+execvp (no shell), feeding stdin_data (may be NULL) to its stdin while
 *        concurrently capturing its stdout (poll-driven, no pipe deadlock). Child stderr goes to /dev/null.
 * @param out Receives a malloc'd buffer with the child's stdout (caller frees); NULL on error.
 * @param max_out Output cap; exceeding it kills the child (decompression-bomb guard).
 * @return BOOTO_OK on exit 0, BOOTO_ERR_NOT_FOUND if exec failed (exit 127), BOOTO_ERR_CORRUPT_DATA on
 *         non-zero exit, signal death or output above max_out, BOOTO_ERR_IO/OUT_OF_MEMORY/GENERIC otherwise.
 */
booto_error_t disk_exec_capture(const char *const argv[], const uint8_t *stdin_data, size_t stdin_len,
                                uint8_t **out, size_t *out_len, size_t max_out);

/**
 * @brief Create directory with mode 0700 if missing; if it exists it must be a real directory
 *        (not a symlink) owned by geteuid() without group/other write bits.
 * @return BOOTO_OK, BOOTO_ERR_PERMISSION_DENIED if unsafe, BOOTO_ERR_IO on other failure.
 */
booto_error_t disk_ensure_private_dir(const char *path);

/**
 * @brief Helper to format bytes into human-readable string (KB, MB, GB, TB).
 */
const char *disk_format_size(uint64_t bytes, char *buf, size_t buf_size);

#define DISK_MAX_ESP 8

/**
 * @brief Pure parser: find EFI System Partitions in a GPT (validated incl. CRC32s) or classic MBR.
 * @param buf Disk bytes from LBA 0. @param sector_size Logical sector size.
 * @return BOOTO_OK (*n may be 0 if no table), BOOTO_ERR_CORRUPT_DATA on bad GPT / protective MBR without GPT.
 */
booto_error_t disk_parse_esp_partitions(const uint8_t *buf, size_t len, uint32_t sector_size,
                                        uint32_t *part_numbers, int max, int *n);

/** @brief Read disk_path read-only (block device or image) and return ESP partition numbers. */
booto_error_t disk_find_esp_partitions(const char *disk_path, uint32_t *part_numbers, int max, int *n);

/** @brief "/dev/nvme0n1p2" -> "/dev/nvme0n1" via sysfs. BOOTO_ERR_NOT_FOUND if not a partition. */
booto_error_t disk_partition_parent(const char *part_dev, char *parent, size_t parent_size);

/** @brief "/dev/nvme0n1" + 1 -> "/dev/nvme0n1p1" via sysfs. BOOTO_ERR_NOT_FOUND if absent. */
booto_error_t disk_partition_by_number(const char *disk_dev, uint32_t number, char *out, size_t out_size);

/**
 * @brief Check if the current process has effective root / CAP_SYS_ADMIN privileges.
 */
bool disk_is_running_as_root(void);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_DISK_MOUNT_H */
