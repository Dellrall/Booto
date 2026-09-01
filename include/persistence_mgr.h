/**
 * @file persistence_mgr.h
 * @brief Tails-style optional LUKS2 encrypted persistence subsystem.
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
    PERSISTENCE_STATE_LOCKED,        /**< Partition detected, LUKS container locked */
    PERSISTENCE_STATE_UNLOCKED       /**< LUKS container unlocked and mounted */
} persistence_state_t;

typedef struct {
    persistence_state_t state;
    char dev_path[128];
    char mount_path[256];
    char cases_dir[256];
    char rules_dir[256];
    char logs_dir[256];
    uint64_t total_bytes;
    uint64_t free_bytes;
} persistence_mgr_t;

/**
 * @brief Initialize persistence manager and detect secondary encrypted partition.
 * @param mgr Output manager structure.
 * @param preferred_dev Optional device path (or NULL for auto-detection).
 * @return BOOTO_OK on success.
 */
booto_error_t persistence_init(persistence_mgr_t *mgr, const char *preferred_dev);

/**
 * @brief Unlock and mount LUKS persistence container.
 * @param mgr Manager structure.
 * @param passphrase Decryption passphrase (wiped after use).
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t persistence_unlock(persistence_mgr_t *mgr, const char *passphrase);

/**
 * @brief Safely unmount and close LUKS persistence container.
 * @param mgr Manager structure.
 * @return BOOTO_OK on success.
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
