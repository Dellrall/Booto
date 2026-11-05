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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* live-boot mounts the medium it booted from here (live-media=removable keeps it off internal disks). */
#define LIVE_MEDIUM_MOUNT "/run/live/medium"

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

/* Copies the value of "KEY=value" from a sysfs uevent file. */
static bool uevent_value(const char *path, const char *key, char *out, size_t out_len) {
    FILE *f = fopen(path, "re");
    if (!f) return false;
    char line[256];
    size_t klen = strlen(key);
    bool found = false;
    while (!found && fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            line[strcspn(line, "\n")] = '\0';
            snprintf(out, out_len, "%s", line + klen + 1);
            found = true;
        }
    }
    fclose(f);
    return found;
}

booto_error_t persistence_find_data_partition(const char *mountinfo_path, const char *sysfs_root,
                                              char *out_dev, size_t out_len) {
    if (!mountinfo_path || !sysfs_root || !out_dev || out_len == 0) return BOOTO_ERR_INVALID_ARG;

    FILE *f = fopen(mountinfo_path, "re");
    if (!f) return BOOTO_ERR_IO;
    char line[1024], mnt[512], devnum[32] = "";
    unsigned maj, min;
    while (fgets(line, sizeof(line), f)) {
        /* mountinfo: id parent major:minor root mountpoint ... */
        if (sscanf(line, "%*u %*u %u:%u %*s %511s", &maj, &min, mnt) == 3 && strcmp(mnt, LIVE_MEDIUM_MOUNT) == 0) {
            snprintf(devnum, sizeof(devnum), "%u:%u", maj, min);
            break;
        }
    }
    fclose(f);
    if (!devnum[0]) return BOOTO_ERR_NOT_FOUND;

    char path[PATH_MAX], disk[PATH_MAX];
    snprintf(path, sizeof(path), "%s/dev/block/%s", sysfs_root, devnum);
    if (!realpath(path, disk)) return BOOTO_ERR_NOT_FOUND;
    /* The medium is normally partition 1: its disk is the parent sysfs directory. */
    snprintf(path, sizeof(path), "%.4000s/partition", disk);
    if (access(path, F_OK) == 0) *strrchr(disk, '/') = '\0';

    DIR *d = opendir(disk);
    if (!d) return BOOTO_ERR_NOT_FOUND;
    booto_error_t ret = BOOTO_ERR_NOT_FOUND;
    struct dirent *e;
    while (ret != BOOTO_OK && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char name[64], devname[64];
        snprintf(path, sizeof(path), "%.3800s/%.255s/uevent", disk, e->d_name);
        if (!uevent_value(path, "PARTNAME", name, sizeof(name)) || strcmp(name, PERSISTENCE_PART_LABEL) != 0) continue;
        if (!uevent_value(path, "DEVNAME", devname, sizeof(devname)) || !devname[0] || strchr(devname, '/')) continue;
        snprintf(out_dev, out_len, "/dev/%s", devname);
        ret = BOOTO_OK;
    }
    closedir(d);
    return ret;
}

/* Unreadable counts as encrypted: an unidentified device is never mounted as plain ext4 by default. */
static bool has_luks_header(const char *dev) {
    unsigned char magic[6] = {0};
    int fd = open(dev, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return true;
    ssize_t n = read(fd, magic, sizeof(magic));
    close(fd);
    return n != (ssize_t)sizeof(magic) || memcmp(magic, "LUKS\xba\xbe", sizeof(magic)) == 0;
}

booto_error_t persistence_init(persistence_mgr_t *mgr, const char *preferred_dev) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;
    memset(mgr, 0, sizeof(*mgr));

    snprintf(mgr->mount_path, sizeof(mgr->mount_path), "%s", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->cases_dir, sizeof(mgr->cases_dir), "%s/cases", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->rules_dir, sizeof(mgr->rules_dir), "%s/rules", DEFAULT_PERSISTENCE_MOUNT);
    snprintf(mgr->logs_dir, sizeof(mgr->logs_dir), "%s/logs", DEFAULT_PERSISTENCE_MOUNT);

    if (preferred_dev && strlen(preferred_dev) > 0) {
        if (strncmp(preferred_dev, "/dev/", 5) != 0) {
            LOG_ERROR("Rejecting persistence device path outside /dev/: %.127s", preferred_dev);
            return BOOTO_ERR_INVALID_ARG;
        }
        snprintf(mgr->dev_path, sizeof(mgr->dev_path), "%.127s", preferred_dev);
    } else if (persistence_find_data_partition("/proc/self/mountinfo", "/sys", mgr->dev_path,
                                               sizeof(mgr->dev_path)) != BOOTO_OK) {
        LOG_INFO("No %s partition on the boot medium; reports stay in RAM", PERSISTENCE_PART_LABEL);
        return BOOTO_OK;
    }

    mgr->state = PERSISTENCE_STATE_LOCKED;
    mgr->encrypted = has_luks_header(mgr->dev_path);
    LOG_INFO("Report storage found on %s (%s)", mgr->dev_path, mgr->encrypted ? "encrypted" : "no passphrase");
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
    if (mgr->state == PERSISTENCE_STATE_ABSENT) return BOOTO_ERR_NOT_FOUND;

    LOG_INFO("Attempting to unlock persistence volume on %s...", mgr->dev_path);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Root privileges required to unlock persistence volume");
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    booto_error_t err = disk_ensure_private_dir(DEFAULT_PERSISTENCE_MOUNT);
    if (err != BOOTO_OK) {
        LOG_ERROR("Unsafe or unusable persistence mount point %s", DEFAULT_PERSISTENCE_MOUNT);
        return err;
    }

    const char *source = mgr->dev_path;
    if (mgr->encrypted) {
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
        source = "/dev/mapper/" PERSISTENCE_MAPPER_NAME;
    }

    if (mount(source, DEFAULT_PERSISTENCE_MOUNT, "ext4", MS_NODEV | MS_NOSUID, NULL) != 0) {
        LOG_ERROR("Failed to mount persistence volume %s: %s", source, strerror(errno));
        if (mgr->encrypted) close_mapper();
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
    LOG_INFO("Persistence volume mounted at %s", DEFAULT_PERSISTENCE_MOUNT);
    return BOOTO_OK;
}

booto_error_t persistence_lock(persistence_mgr_t *mgr) {
    if (!mgr) return BOOTO_ERR_INVALID_ARG;
    if (mgr->state != PERSISTENCE_STATE_UNLOCKED) return BOOTO_OK;

    LOG_INFO("Locking persistence volume...");

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Root privileges required to lock persistence volume");
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    sync();

    if (umount2(DEFAULT_PERSISTENCE_MOUNT, 0) != 0 && errno != EINVAL) {
        LOG_ERROR("Failed to unmount %s: %s", DEFAULT_PERSISTENCE_MOUNT, strerror(errno));
        return BOOTO_ERR_IO;
    }

    if (mgr->encrypted) {
        const char *const argv[] = {"cryptsetup", "close", PERSISTENCE_MAPPER_NAME, NULL};
        if (disk_exec_argv(argv, NULL, 0, NULL) != BOOTO_OK) {
            LOG_ERROR("Failed to close LUKS mapper '%s'", PERSISTENCE_MAPPER_NAME);
            return BOOTO_ERR_IO;
        }
    }

    mgr->state = PERSISTENCE_STATE_LOCKED;
    LOG_INFO("Persistence volume cleanly detached and locked (Amnesic Mode restored)");
    return BOOTO_OK;
}
