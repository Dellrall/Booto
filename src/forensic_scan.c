/**
 * @file forensic_scan.c
 * @brief Runs every detection engine against one target; CLEAN only when every engine really ran OK.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "forensic_scan.h"
#include "disk_mount.h"
#include "logger.h"

#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define SCAN_MOUNT_POINT "/tmp/booto_scan_target"
#define ESP_MOUNT_POINT "/tmp/booto_esp_target"

static const char *err_name(booto_error_t e) {
    switch (e) {
        case BOOTO_OK:                    return "ok";
        case BOOTO_ERR_INVALID_ARG:       return "invalid argument";
        case BOOTO_ERR_OUT_OF_MEMORY:     return "out of memory";
        case BOOTO_ERR_IO:                return "I/O error";
        case BOOTO_ERR_MOUNT_FAILED:      return "mount failed";
        case BOOTO_ERR_PERMISSION_DENIED: return "permission denied";
        case BOOTO_ERR_NOT_FOUND:         return "not found";
        case BOOTO_ERR_CORRUPT_DATA:      return "corrupt data";
        case BOOTO_ERR_LUKS_LOCKED:       return "LUKS locked";
        case BOOTO_ERR_CANCELLED:         return "cancelled";
        default:                          return "generic error";
    }
}

const char *forensic_scan_module_name(scan_module_id_t id) {
    static const char *names[SCAN_MOD_COUNT] = {"MBR/VBR", "UEFI ESP", "Kernel LKM", "Initramfs", "LD_PRELOAD", "Ext4 stats"};
    return ((unsigned)id < SCAN_MOD_COUNT) ? names[id] : "unknown";
}

const char *forensic_scan_status_str(scan_status_t s) {
    switch (s) {
        case SCAN_STATUS_OK:      return "OK";
        case SCAN_STATUS_ERROR:   return "ERROR";
        case SCAN_STATUS_SKIPPED: return "SKIPPED";
        default:                  return "NOT_RUN";
    }
}

const char *forensic_scan_verdict_str(scan_verdict_t v) {
    switch (v) {
        case SCAN_VERDICT_CLEAN:   return "CLEAN";
        case SCAN_VERDICT_THREATS: return "THREATS";
        default:                   return "INCOMPLETE";
    }
}

int forensic_scan_module_threats(const forensic_scan_report_t *r, scan_module_id_t id) {
    switch (id) {
        case SCAN_MOD_MBR:       return r->mbr.threats_detected;
        case SCAN_MOD_UEFI:      return r->uefi.bootkits_detected;
        case SCAN_MOD_KERNEL:    return r->kernel.threats_detected;
        case SCAN_MOD_INITRAMFS: return r->initramfs.threats_detected;
        case SCAN_MOD_PRELOAD:   return r->preload.threats_detected;
        default:                 return 0;
    }
}

static void set_status(forensic_scan_report_t *r, scan_module_id_t id, scan_status_t s, booto_error_t e, const char *note) {
    r->status[id] = s;
    r->err[id] = e;
    snprintf(r->note[id], sizeof(r->note[id]), "%.95s", note);
}

static void set_result(forensic_scan_report_t *r, scan_module_id_t id, booto_error_t e) {
    if (e == BOOTO_OK) {
        set_status(r, id, SCAN_STATUS_OK, e, "");
    } else {
        set_status(r, id, SCAN_STATUS_ERROR, e, err_name(e));
        LOG_WARN("%s engine failed: %s", forensic_scan_module_name(id), err_name(e));
    }
}

/* Reports progress; returns false (and marks SKIPPED) when the module is disabled. */
static bool begin(forensic_scan_report_t *r, scan_module_id_t id, const bool *enabled,
                  forensic_scan_progress_cb cb, void *user) {
    if (cb) cb((int)id + 1, SCAN_MOD_COUNT, forensic_scan_module_name(id), user);
    if (enabled && !enabled[id]) {
        set_status(r, id, SCAN_STATUS_SKIPPED, BOOTO_OK, "disabled");
        return false;
    }
    return true;
}

static bool is_regular_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* <root>/boot/initrd.img, <root>/initrd.img, else lexicographically greatest <root>/boot/initrd.img-*. */
static bool find_initramfs(const char *root, char *out, size_t out_size) {
    snprintf(out, out_size, "%.256s/boot/initrd.img", root);
    if (is_regular_file(out)) return true;
    snprintf(out, out_size, "%.256s/initrd.img", root);
    if (is_regular_file(out)) return true;

    char boot[300];
    snprintf(boot, sizeof(boot), "%.256s/boot", root);
    DIR *d = opendir(boot);
    if (!d) return false;
    char best[256] = "";
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "initrd.img-", 11) != 0 || strcmp(de->d_name, best) <= 0) continue;
        snprintf(out, out_size, "%.256s/%.200s", boot, de->d_name);
        if (is_regular_file(out)) snprintf(best, sizeof(best), "%.255s", de->d_name);
    }
    closedir(d);
    if (!best[0]) return false;
    snprintf(out, out_size, "%.256s/%.200s", boot, best);
    return true;
}

/* UEFI engine: <root>/boot/efi if it holds EFI files, else the ESP(s) on target_dev's disk, mounted read-only. */
static void run_uefi(forensic_scan_report_t *out, const char *target_dev, bool have_root) {
    char note[96];
    if (have_root) {
        char path[512];
        snprintf(path, sizeof(path), "%.256s/boot/efi", out->scan_root);
        booto_error_t e = uefi_inspect_esp_directory(path, &out->uefi);
        if (e == BOOTO_OK && out->uefi.efi_files_scanned > 0) {
            snprintf(out->esp_dev, sizeof(out->esp_dev), "%.118s/boot/efi", out->scan_root);
            snprintf(note, sizeof(note), "ESP: %.90s", out->esp_dev);
            set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_OK, e, note);
            return;
        }
    }
    if (!target_dev) {
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_SKIPPED, BOOTO_OK, "no EFI system partition found");
        return;
    }

    char disk[128];
    booto_error_t e = disk_partition_parent(target_dev, disk, sizeof(disk));
    if (e == BOOTO_ERR_NOT_FOUND) snprintf(disk, sizeof(disk), "%.127s", target_dev);  /* already a whole disk */
    else if (e != BOOTO_OK) {
        snprintf(note, sizeof(note), "cannot resolve parent disk: %s", err_name(e));
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_ERROR, e, note);
        return;
    }

    uint32_t nums[DISK_MAX_ESP];
    int n = 0;
    e = disk_find_esp_partitions(disk, nums, DISK_MAX_ESP, &n);
    if (e == BOOTO_ERR_CORRUPT_DATA) {
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_ERROR, e, "partition table corrupt (GPT checksum mismatch)");
        return;
    }
    if (e != BOOTO_OK) {
        snprintf(note, sizeof(note), "cannot read partition table: %s", err_name(e));
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_ERROR, e, note);
        return;
    }

    booto_error_t last_err = BOOTO_OK;
    char last_dev[64] = "";
    for (int i = 0; i < n && i < DISK_MAX_ESP; i++) {
        char esp[128];
        e = disk_partition_by_number(disk, nums[i], esp, sizeof(esp));
        if (e != BOOTO_OK) {
            last_err = e;
            snprintf(last_dev, sizeof(last_dev), "partition %" PRIu32, nums[i]);
            continue;
        }
        if (strcmp(esp, target_dev) == 0) continue;
        e = disk_mount_ro(esp, ESP_MOUNT_POINT, "vfat");
        if (e != BOOTO_OK) {
            LOG_WARN("Cannot mount ESP %s read-only: %s", esp, err_name(e));
            last_err = e;
            snprintf(last_dev, sizeof(last_dev), "%.63s", esp);
            continue;
        }
        memset(&out->uefi, 0, sizeof(out->uefi));
        e = uefi_inspect_esp_directory(ESP_MOUNT_POINT, &out->uefi);
        booto_error_t ue = disk_unmount(ESP_MOUNT_POINT);
        if (ue != BOOTO_OK) LOG_WARN("Failed to unmount %s: %s", ESP_MOUNT_POINT, err_name(ue));
        snprintf(out->esp_dev, sizeof(out->esp_dev), "%.127s", esp);
        if (e != BOOTO_OK) {
            set_result(out, SCAN_MOD_UEFI, e);
            return;
        }
        snprintf(note, sizeof(note), "ESP: %.60s (auto-discovered)", esp);
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_OK, e, note);
        return;
    }
    if (last_dev[0]) {
        snprintf(note, sizeof(note), "ESP %.40s not mounted: %s", last_dev, err_name(last_err));
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_ERROR, last_err, note);
        return;
    }
    set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_SKIPPED, BOOTO_OK, "no EFI system partition found");
}

booto_error_t forensic_scan_run(const char *target_dev, const char *rootfs_dir, const bool *enabled,
                                forensic_scan_progress_cb cb, void *user, forensic_scan_report_t *out) {
    if (!out || (!target_dev && !rootfs_dir)) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (target_dev) snprintf(out->target_dev, sizeof(out->target_dev), "%.127s", target_dev);

    if (rootfs_dir) {
        snprintf(out->scan_root, sizeof(out->scan_root), "%.255s", rootfs_dir);
    } else {
        snprintf(out->scan_root, sizeof(out->scan_root), "%s", SCAN_MOUNT_POINT);
        out->mount_err = disk_mount_ro(target_dev, SCAN_MOUNT_POINT, NULL);
        out->mounted = (out->mount_err == BOOTO_OK);
        if (!out->mounted) LOG_ERROR("Cannot mount %s read-only: %s", target_dev, err_name(out->mount_err));
    }

    char rootfs_note[96];
    snprintf(rootfs_note, sizeof(rootfs_note), "rootfs not mounted: %s", err_name(out->mount_err));
    bool have_root = (out->mount_err == BOOTO_OK);
    const char *root = out->scan_root;
    char path[512];

    if (begin(out, SCAN_MOD_MBR, enabled, cb, user)) {
        if (!target_dev) set_status(out, SCAN_MOD_MBR, SCAN_STATUS_SKIPPED, BOOTO_OK, "no raw device");
        else set_result(out, SCAN_MOD_MBR, mbr_audit_device(target_dev, &out->mbr));
    }

    if (begin(out, SCAN_MOD_UEFI, enabled, cb, user)) run_uefi(out, target_dev, have_root);

    if (begin(out, SCAN_MOD_KERNEL, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_KERNEL, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else {
            snprintf(path, sizeof(path), "%.256s/lib/modules", root);
            set_result(out, SCAN_MOD_KERNEL, kernel_inspect_directory(path, &out->kernel));
        }
    }

    if (begin(out, SCAN_MOD_INITRAMFS, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_INITRAMFS, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else if (!find_initramfs(root, path, sizeof(path))) {
            set_status(out, SCAN_MOD_INITRAMFS, SCAN_STATUS_SKIPPED, BOOTO_OK, "no initramfs found");
        } else {
            set_result(out, SCAN_MOD_INITRAMFS, initramfs_audit_file(path, &out->initramfs));
        }
    }

    if (begin(out, SCAN_MOD_PRELOAD, enabled, cb, user)) {
        if (!have_root) set_status(out, SCAN_MOD_PRELOAD, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        else set_result(out, SCAN_MOD_PRELOAD, preload_scan_rootfs(root, &out->preload));
    }

    if (begin(out, SCAN_MOD_EXT4, enabled, cb, user)) {
        if (!target_dev) {
            set_status(out, SCAN_MOD_EXT4, SCAN_STATUS_SKIPPED, BOOTO_OK, "no raw device");
        } else {
            booto_error_t e = ext4_diff_scan(target_dev, have_root ? root : NULL, &out->ext4);
            if (e == BOOTO_ERR_CORRUPT_DATA) set_status(out, SCAN_MOD_EXT4, SCAN_STATUS_SKIPPED, e, "not ext4");
            else if (e == BOOTO_OK) set_status(out, SCAN_MOD_EXT4, SCAN_STATUS_OK, e, "stats only: hidden-inode cross-view not implemented");
            else set_result(out, SCAN_MOD_EXT4, e);
        }
    }

    if (out->mounted) {
        booto_error_t ue = disk_unmount(SCAN_MOUNT_POINT);
        if (ue != BOOTO_OK) LOG_WARN("Failed to unmount %s: %s", SCAN_MOUNT_POINT, err_name(ue));
    }

    if (target_dev) {
        firmware_audit(NULL, &out->firmware);
        out->firmware_ran = true;
        LOG_INFO("Firmware: %d issue(s), %d unknown", out->firmware.fail_count, out->firmware.unknown_count);
    }

    out->total_threats = 0;
    for (int i = 0; i < SCAN_MOD_COUNT; i++) out->total_threats += forensic_scan_module_threats(out, (scan_module_id_t)i);

    bool any_ok = false, any_err = false;
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        if (out->status[i] == SCAN_STATUS_OK) any_ok = true;
        if (out->status[i] == SCAN_STATUS_ERROR) any_err = true;
    }
    if (out->total_threats > 0) out->verdict = SCAN_VERDICT_THREATS;
    else if (any_err || !any_ok) out->verdict = SCAN_VERDICT_INCOMPLETE;
    else out->verdict = SCAN_VERDICT_CLEAN;
    return BOOTO_OK;
}

void forensic_scan_fill_case_summary(const forensic_scan_report_t *r, const char *case_id, const char *examiner,
                                     forensic_case_summary_t *sum) {
    if (!r || !sum) return;
    memset(sum, 0, sizeof(*sum));
    snprintf(sum->case_id, sizeof(sum->case_id), "%.63s", case_id ? case_id : "");
    snprintf(sum->examiner, sizeof(sum->examiner), "%.63s", examiner ? examiner : "unknown");
    snprintf(sum->target_disk, sizeof(sum->target_disk), "%.127s", r->target_dev[0] ? r->target_dev : r->scan_root);
    snprintf(sum->target_fs, sizeof(sum->target_fs), "unknown");

    time_t now = time(NULL);
    struct tm tm_utc;
    if (gmtime_r(&now, &tm_utc)) strftime(sum->timestamp, sizeof(sum->timestamp), "%Y-%m-%d %H:%M:%S UTC", &tm_utc);

    sum->mbr_threats_count = r->mbr.threats_detected;
    sum->kernel_threats_count = r->kernel.threats_detected;
    sum->uefi_threats_count = r->uefi.bootkits_detected;
    sum->initramfs_threats_count = r->initramfs.threats_detected;
    sum->preload_threats_count = r->preload.threats_detected;
    sum->total_threats = r->total_threats;
    snprintf(sum->highest_severity, sizeof(sum->highest_severity), "%s", r->total_threats > 0 ? "CRITICAL" : "NONE");
    snprintf(sum->verdict, sizeof(sum->verdict), "%s", forensic_scan_verdict_str(r->verdict));
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        snprintf(sum->module_status[i], sizeof(sum->module_status[i]), "%s", forensic_scan_status_str(r->status[i]));
    }
    sum->firmware_ran = r->firmware_ran;
    sum->firmware = r->firmware;
}
