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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
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
        if (strncmp(preferred_dev, "/dev/", 5) != 0) {
            LOG_ERROR("Rejecting persistence device path outside /dev/: %.127s", preferred_dev);
            return BOOTO_ERR_INVALID_ARG;
        }
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

static void close_mapper(void) {
    const char *const argv[] = {"cryptsetup", "close", PERSISTENCE_MAPPER_NAME, NULL};
    if (disk_exec_argv(argv, NULL, 0, NULL) != BOOTO_OK) {
        LOG_ERROR("Failed to close LUKS mapper '%s'", PERSISTENCE_MAPPER_NAME);
    }
}

booto_error_t persistence_unlock(persistence_mgr_t *mgr, const char *passphrase) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Attempting to unlock LUKS persistence volume on %s...", mgr->dev_path);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Root privileges required to unlock LUKS persistence volume");
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    booto_error_t err = disk_ensure_private_dir(DEFAULT_PERSISTENCE_MOUNT);
    if (err != BOOTO_OK) {
        LOG_ERROR("Unsafe or unusable persistence mount point %s", DEFAULT_PERSISTENCE_MOUNT);
        return err;
    }

    const char *pass = passphrase ? passphrase : "";
    const char *const open_argv[] = {"cryptsetup", "open", "--type", "luks", "--key-file=-",
                                     mgr->dev_path, PERSISTENCE_MAPPER_NAME, NULL};
    int status = 0;
    err = disk_exec_argv(open_argv, pass, strlen(pass), &status);
    if (err != BOOTO_OK) {
        if (status == 2) {
            LOG_ERROR("Failed to open LUKS container '%s': invalid passphrase", mgr->dev_path);
            return BOOTO_ERR_PERMISSION_DENIED;
        }
        LOG_ERROR("Failed to open LUKS container '%s' (exit %d)", mgr->dev_path, status);
        return BOOTO_ERR_IO;
    }

    if (mount("/dev/mapper/" PERSISTENCE_MAPPER_NAME, DEFAULT_PERSISTENCE_MOUNT, "ext4",
              MS_NODEV | MS_NOSUID, NULL) != 0) {
        LOG_ERROR("Failed to mount decrypted persistence volume: %s", strerror(errno));
        close_mapper();
        return BOOTO_ERR_MOUNT_FAILED;
    }

    if (disk_ensure_private_dir(mgr->cases_dir) != BOOTO_OK ||
        disk_ensure_private_dir(mgr->rules_dir) != BOOTO_OK ||
        disk_ensure_private_dir(mgr->logs_dir) != BOOTO_OK) {
        LOG_WARN("Persistence subdirectories missing or unsafe under %s", DEFAULT_PERSISTENCE_MOUNT);
    }

    struct statvfs vfs;
    if (statvfs(DEFAULT_PERSISTENCE_MOUNT, &vfs) == 0) {
        mgr->total_bytes = (uint64_t)vfs.f_blocks * (uint64_t)vfs.f_frsize;
        mgr->free_bytes = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
    }

    mgr->state = PERSISTENCE_STATE_UNLOCKED;
    LOG_INFO("LUKS Persistence volume unlocked and mounted at %s", DEFAULT_PERSISTENCE_MOUNT);
    return BOOTO_OK;
}

booto_error_t persistence_lock(persistence_mgr_t *mgr) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Locking LUKS persistence volume...");

    if (!disk_is_running_as_root()) {
        if (mgr->state != PERSISTENCE_STATE_UNLOCKED) return BOOTO_OK;
        LOG_ERROR("Root privileges required to lock LUKS persistence volume");
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    sync();

    if (umount2(DEFAULT_PERSISTENCE_MOUNT, 0) != 0 && errno != EINVAL) {
        LOG_ERROR("Failed to unmount %s: %s", DEFAULT_PERSISTENCE_MOUNT, strerror(errno));
        return BOOTO_ERR_IO;
    }

    const char *const argv[] = {"cryptsetup", "close", PERSISTENCE_MAPPER_NAME, NULL};
    if (disk_exec_argv(argv, NULL, 0, NULL) != BOOTO_OK) {
        LOG_ERROR("Failed to close LUKS mapper '%s'", PERSISTENCE_MAPPER_NAME);
        return BOOTO_ERR_IO;
    }

    mgr->state = PERSISTENCE_STATE_LOCKED;
    LOG_INFO("Persistence volume cleanly detached and locked (Amnesic Mode restored)");
    return BOOTO_OK;
}
