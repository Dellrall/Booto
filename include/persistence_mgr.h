/**
 * @file persistence_mgr.h
 * @brief Report storage on the boot USB: the BOOTO_DATA partition, LUKS2-encrypted or plain ext4.
 */
#ifndef BOOTO_PERSISTENCE_MGR_H
#define BOOTO_PERSISTENCE_MGR_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_PERSISTENCE_MOUNT "/persistence"
#define PERSISTENCE_MAPPER_NAME   "booto_persistence"
#define PERSISTENCE_PART_LABEL    "BOOTO_DATA"

typedef enum {
    PERSISTENCE_STATE_ABSENT = 0,    /**< No persistence partition detected */
    PERSISTENCE_STATE_LOCKED,        /**< Partition detected, not mounted */
    PERSISTENCE_STATE_UNLOCKED       /**< Partition mounted at DEFAULT_PERSISTENCE_MOUNT */
} persistence_state_t;

typedef struct {
    persistence_state_t state;
    bool encrypted;                  /**< LUKS header found (or device unreadable): needs a passphrase */
    char dev_path[128];
    char mount_path[256];
    char cases_dir[256];
    char rules_dir[256];
    char logs_dir[256];
    uint64_t total_bytes;
    uint64_t free_bytes;
} persistence_mgr_t;

/**
 * @brief Find the BOOTO_DATA partition on the disk live-boot booted from.
 *
 * Only the disk holding the live medium (mounted at /run/live/medium) is searched, so a
 * suspect disk carrying a partition with the same name is never picked.
 * @param mountinfo_path Normally "/proc/self/mountinfo".
 * @param sysfs_root Normally "/sys".
 * @param out_dev Receives e.g. "/dev/sdb2".
 * @return BOOTO_OK; BOOTO_ERR_NOT_FOUND when not booted from a live medium or no such partition;
 *         BOOTO_ERR_IO if mountinfo is unreadable.
 */
booto_error_t persistence_find_data_partition(const char *mountinfo_path, const char *sysfs_root,
                                              char *out_dev, size_t out_len);

/**
 * @brief Initialize the manager: use preferred_dev or find the partition, then detect LUKS.
 * @param mgr Output manager structure; state ABSENT when no partition was found.
 * @param preferred_dev Optional device path under /dev/ (or NULL for auto-detection).
 * @return BOOTO_OK on success, BOOTO_ERR_INVALID_ARG if preferred_dev is not under /dev/.
 */
booto_error_t persistence_init(persistence_mgr_t *mgr, const char *preferred_dev);

/**
 * @brief Mount the report partition, opening its LUKS container first when encrypted.
 * @param mgr Manager structure.
 * @param passphrase Decryption passphrase (ignored when not encrypted). NOT wiped by this module;
 *                   the caller owns the buffer and must clear it (e.g. explicit_bzero) after the call.
 * @return BOOTO_OK on success; BOOTO_ERR_NOT_FOUND when ABSENT; BOOTO_ERR_PERMISSION_DENIED when
 *         not root or the passphrase is wrong; BOOTO_ERR_IO / BOOTO_ERR_MOUNT_FAILED otherwise.
 */
booto_error_t persistence_unlock(persistence_mgr_t *mgr, const char *passphrase);

/**
 * @brief Unmount the report partition and close its LUKS container.
 * @param mgr Manager structure.
 * @return BOOTO_OK on success or when not unlocked; BOOTO_ERR_PERMISSION_DENIED when not root;
 *         BOOTO_ERR_IO if unmount/close fails (state stays UNLOCKED).
 */
booto_error_t persistence_lock(persistence_mgr_t *mgr);

/**
 * @brief Check if persistence is currently unlocked and ready for writes.
 */
bool persistence_is_unlocked(const persistence_mgr_t *mgr);

/**
 * @brief Convert persistence state enum to human-readable string.
 */
const char *persistence_state_to_string(persistence_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PERSISTENCE_MGR_H */
