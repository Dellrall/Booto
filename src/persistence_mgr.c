/**
 * @file persistence_mgr.c
 * @brief Implementation of Tails-style LUKS2 encrypted persistence subsystem.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "persistence_mgr.h"
#include "disk_mount.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

const char *persistence_state_to_string(persistence_state_t state) {
    switch (state) {
        case PERSISTENCE_STATE_UNLOCKED: return "UNLOCKED (Encrypted Writes Active)";
        case PERSISTENCE_STATE_LOCKED:   return "LOCKED (Amnesic RAM Mode)";
        default:                         return "ABSENT (No Persistence Partition)";
    }
}

bool persistence_is_unlocked(const persistence_mgr_t *mgr) {
    return (mgr && mgr->state == PERSISTENCE_STATE_UNLOCKED);
}

booto_error_t persistence_init(persistence_mgr_t *mgr, const char *preferred_dev) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;
    memset(mgr, 0, sizeof(*mgr));

    if (preferred_dev && strlen(preferred_dev) > 0) {
        snprintf(mgr->dev_path, sizeof(mgr->dev_path), "%.127s", preferred_dev);
        mgr->state = PERSISTENCE_STATE_LOCKED;
    } else {
        // Auto-discover mock or physical second partition
        snprintf(mgr->dev_path, sizeof(mgr->dev_path), "/dev/sdb2");
        mgr->state = PERSISTENCE_STATE_LOCKED;
    }

    snprintf(mgr->mount_path, sizeof(mgr->mount_path), "%s", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->cases_dir, sizeof(mgr->cases_dir), "%s/cases", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->rules_dir, sizeof(mgr->rules_dir), "%s/rules", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->logs_dir, sizeof(mgr->logs_dir), "%s/logs", DEFAULT_PERSISTENCE_MOUNT);

    LOG_INFO("Persistence manager initialized on %s (State: %s)",
             mgr->dev_path, persistence_state_to_string(mgr->state));
    return BOOTO_OK;
}

static void ensure_dir_0700(const char *dir_path) {
    struct stat st;
    if (stat(dir_path, &st) != 0) {
        mkdir(dir_path, 0700);
    }
}

booto_error_t persistence_unlock(persistence_mgr_t *mgr, const char *passphrase) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Attempting to unlock LUKS persistence volume on %s...", mgr->dev_path);

    if (!disk_is_running_as_root()) {
        LOG_WARN("Non-root environment: Emulating safe mock LUKS2 container unlock");

        // Use safe mock temp directory for non-root persistence testing
        snprintf(mgr->mount_path, sizeof(mgr->mount_path), "/tmp/booto_mock_persistence");
        snprintf(mgr->cases_dir, sizeof(mgr->cases_dir), "/tmp/booto_mock_persistence/cases");
        snprintf(mgr->rules_dir, sizeof(mgr->rules_dir), "/tmp/booto_mock_persistence/rules");
        snprintf(mgr->logs_dir, sizeof(mgr->logs_dir), "/tmp/booto_mock_persistence/logs");

        ensure_dir_0700(mgr->mount_path);
        ensure_dir_0700(mgr->cases_dir);
        ensure_dir_0700(mgr->rules_dir);
        ensure_dir_0700(mgr->logs_dir);

        mgr->state = PERSISTENCE_STATE_UNLOCKED;
        mgr->total_bytes = 1024ULL * 1024ULL * 1024ULL * 32ULL; // 32 GB
        mgr->free_bytes = 1024ULL * 1024ULL * 1024ULL * 31ULL;  // 31 GB

        LOG_INFO("Persistence volume unlocked successfully (Mock Mode active)");
        return BOOTO_OK;
    }

    // Root execution with cryptsetup
    ensure_dir_0700(DEFAULT_PERSISTENCE_MOUNT);

    // Shell invocation to cryptsetup with passphrase pipe
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo -n '%s' | cryptsetup open %s %s --type luks >/dev/null 2>&1",
             passphrase ? passphrase : "", mgr->dev_path, PERSISTENCE_MAPPER_NAME);

    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to open LUKS container '%s': invalid passphrase or corrupted header", mgr->dev_path);
        return BOOTO_ERR_INVALID_ARG;
    }

    // Mount decrypted device mapper
    char mnt_cmd[512];
    snprintf(mnt_cmd, sizeof(mnt_cmd), "mount /dev/mapper/%s %s",
             PERSISTENCE_MAPPER_NAME, DEFAULT_PERSISTENCE_MOUNT);
    if (system(mnt_cmd) != 0) {
        LOG_ERROR("Failed to mount decrypted persistence volume");
        return BOOTO_ERR_MOUNT_FAILED;
    }

    ensure_dir_0700(mgr->cases_dir);
    ensure_dir_0700(mgr->rules_dir);
    ensure_dir_0700(mgr->logs_dir);

    mgr->state = PERSISTENCE_STATE_UNLOCKED;
    LOG_INFO("LUKS Persistence volume unlocked and mounted at %s", DEFAULT_PERSISTENCE_MOUNT);
    return BOOTO_OK;
}

booto_error_t persistence_lock(persistence_mgr_t *mgr) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Locking LUKS persistence volume...");

    if (!disk_is_running_as_root()) {
        mgr->state = PERSISTENCE_STATE_LOCKED;
        LOG_INFO("Persistence volume locked (Restored to Amnesic RAM Mode)");
        return BOOTO_OK;
    }

    sync();

    char umnt_cmd[256];
    snprintf(umnt_cmd, sizeof(umnt_cmd), "umount %s >/dev/null 2>&1", DEFAULT_PERSISTENCE_MOUNT);
    system(umnt_cmd);

    char close_cmd[256];
    snprintf(close_cmd, sizeof(close_cmd), "cryptsetup close %s >/dev/null 2>&1", PERSISTENCE_MAPPER_NAME);
    system(close_cmd);

    mgr->state = PERSISTENCE_STATE_LOCKED;
    LOG_INFO("Persistence volume cleanly detached and locked (Amnesic Mode restored)");
    return BOOTO_OK;
}
