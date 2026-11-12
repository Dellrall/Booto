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
#include "quarantine.h"
#include "inspect.h"
#include "baseline.h"
#include "crypto_utils.h"

#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define SCAN_MOUNT_POINT "/tmp/booto_scan_target"
#define ESP_MOUNT_POINT "/tmp/booto_esp_target"
#define MBR_EXPORT_BYTES (1024 * 1024)  /* MBR plus the post-MBR gap where bootkits hide their stage 2 */

static baseline_t *g_baseline;   /* NULL: no boot chain hash list wanted */

void forensic_scan_set_baseline(baseline_t *b) {
    g_baseline = b;
}

static const char *g_bodyfile;   /* NULL: no timeline wanted */

void forensic_scan_set_bodyfile(const char *path) {
    g_bodyfile = path;
}

static const char *g_hashlist;   /* NULL: no executable hash list wanted */

void forensic_scan_set_hashlist(const char *path) {
    g_hashlist = path;
}

typedef struct { baseline_t *b; size_t root_len; } core_ctx_t;

static void add_core(const char *path, void *user) {
    const core_ctx_t *c = user;
    char label[BASELINE_LABEL_MAX];
    snprintf(label, sizeof(label), "root%s", path + c->root_len);
    baseline_add_file(c->b, label, path);
}

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
    static const char *names[SCAN_MOD_COUNT] = {"MBR/VBR", "UEFI ESP", "Kernel LKM", "Initramfs", "Preload/users", "Packages",
                                                     "Windows boot"};
    return ((unsigned)id < SCAN_MOD_COUNT) ? names[id] : "unknown";
}

const char *forensic_scan_status_str(scan_status_t s) {
    switch (s) {
        case SCAN_STATUS_OK:      return "OK";
        case SCAN_STATUS_ERROR:   return "ERROR";
        case SCAN_STATUS_SKIPPED: return "SKIPPED";
        case SCAN_STATUS_NA:      return "N/A";
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
        case SCAN_MOD_PKG:       return r->pkg.threats_detected;
        case SCAN_MOD_WINBOOT:   return r->winboot.threats_detected;
        default:                 return 0;
    }
}

/* Findings an engine kept: it counts past its array when it runs out of room. */
static int kept(int detected, int max) {
    return detected < 0 ? 0 : detected < max ? detected : max;
}

int forensic_scan_finding_count(const forensic_scan_report_t *r) {
    if (!r) return 0;
    return kept(r->mbr.threats_detected, MAX_MBR_THREATS) + kept(r->uefi.bootkits_detected, MAX_UEFI_THREATS) +
           kept(r->kernel.threats_detected, MAX_KERNEL_THREATS) + kept(r->initramfs.threats_detected, MAX_INITRAMFS_THREATS) +
           kept(r->preload.threats_detected, MAX_PRELOAD_THREATS) + kept(r->pkg.threats_detected, MAX_PKG_THREATS) +
           kept(r->winboot.threats_detected, MAX_WINBOOT_THREATS);
}

bool forensic_scan_finding(const forensic_scan_report_t *r, int i, scan_finding_t *f) {
    if (!r || !f || i < 0) return false;
    memset(f, 0, sizeof(*f));
    f->severity = SEVERITY_CRITICAL;
    int n = kept(r->mbr.threats_detected, MAX_MBR_THREATS);
    if (i < n) {
        const mbr_threat_finding_t *s = &r->mbr.findings[i];
        f->engine = SCAN_MOD_MBR;
        f->severity = s->severity;
        snprintf(f->name, sizeof(f->name), "%s", s->threat_name);
        snprintf(f->where, sizeof(f->where), "%.255s (LBA %llu)", s->target_device, (unsigned long long)s->sector_lba);
        snprintf(f->rule, sizeof(f->rule), "%s", s->rule_id);
        snprintf(f->hash, sizeof(f->hash), "%s", s->sha256);
        snprintf(f->detail, sizeof(f->detail), "%s", s->description);
        return true;
    }
    i -= n;
    n = kept(r->uefi.bootkits_detected, MAX_UEFI_THREATS);
    if (i < n) {
        const uefi_threat_finding_t *s = &r->uefi.findings[i];
        f->engine = SCAN_MOD_UEFI;
        f->severity = s->severity;
        snprintf(f->name, sizeof(f->name), "%s", s->threat_name);
        snprintf(f->where, sizeof(f->where), "%s", s->file_path);
        snprintf(f->rule, sizeof(f->rule), "%s", s->rule_id);
        snprintf(f->hash, sizeof(f->hash), "%s", s->sha256);
        snprintf(f->detail, sizeof(f->detail), "%s", s->description);
        return true;
    }
    i -= n;
    n = kept(r->kernel.threats_detected, MAX_KERNEL_THREATS);
    if (i < n) {
        const kernel_threat_finding_t *s = &r->kernel.findings[i];
        f->engine = SCAN_MOD_KERNEL;
        f->severity = s->severity;
        snprintf(f->name, sizeof(f->name), "%s", s->threat_name);
        snprintf(f->where, sizeof(f->where), "%s", s->file_path);
        snprintf(f->rule, sizeof(f->rule), "%s%s%s", s->detection_rule, s->matched_symbol[0] ? ": " : "", s->matched_symbol);
        snprintf(f->hash, sizeof(f->hash), "%s", s->sha256);
        snprintf(f->detail, sizeof(f->detail), "%s", s->description);
        return true;
    }
    i -= n;
    n = kept(r->initramfs.threats_detected, MAX_INITRAMFS_THREATS);
    if (i < n) {
        const initramfs_finding_t *s = &r->initramfs.findings[i];
        f->engine = SCAN_MOD_INITRAMFS;
        snprintf(f->name, sizeof(f->name), "%s", s->threat_name);
        snprintf(f->where, sizeof(f->where), "%.255s line %u", s->file_path, (unsigned)s->line_number);
        snprintf(f->rule, sizeof(f->rule), "Pattern: %s", s->matched_pattern);
        snprintf(f->detail, sizeof(f->detail), "%s", s->description);
        return true;
    }
    i -= n;
    n = kept(r->preload.threats_detected, MAX_PRELOAD_THREATS);
    if (i < n) {
        const preload_finding_t *s = &r->preload.findings[i];
        f->engine = SCAN_MOD_PRELOAD;
        f->severity = s->severity;
        snprintf(f->name, sizeof(f->name), "%s", s->threat_name);
        snprintf(f->where, sizeof(f->where), "%s", s->file_path);
        snprintf(f->rule, sizeof(f->rule), "%.60s -> %.95s", s->rule_id, s->target_library);
        snprintf(f->hash, sizeof(f->hash), "%s", s->sha256);
        snprintf(f->detail, sizeof(f->detail), "%s", s->description);
        return true;
    }
    i -= n;
    n = kept(r->pkg.threats_detected, MAX_PKG_THREATS);
    if (i < n) {
        const pkg_finding_t *s = &r->pkg.findings[i];
        f->engine = SCAN_MOD_PKG;
        snprintf(f->name, sizeof(f->name), "Modified package file");
        snprintf(f->where, sizeof(f->where), "%s", s->file_path);
        snprintf(f->rule, sizeof(f->rule), "%.47s (%.95s)", s->reason, s->package);
        if (s->actual_hash[0])
            snprintf(f->hash, sizeof(f->hash), "%s %s", strlen(s->actual_hash) == 32 ? "MD5" : "SHA-256", s->actual_hash);
        snprintf(f->detail, sizeof(f->detail), "Package manager recorded %s", s->expected_hash);
        return true;
    }
    i -= n;
    n = kept(r->winboot.threats_detected, MAX_WINBOOT_THREATS);
    if (i < n) {
        const winboot_finding_t *s = &r->winboot.findings[i];
        f->engine = SCAN_MOD_WINBOOT;
        f->severity = s->severity;
        snprintf(f->name, sizeof(f->name), "%s", !s->rule_id[0] ? "Windows boot file"
                                                 : strstr(s->rule_id, "_RANSOM_") ? "Ransomware sign"
                                                 : strstr(s->rule_id, "_EVTX_")   ? "Event log tampering"
                                                                                               : "Windows persistence");
        snprintf(f->where, sizeof(f->where), "%.299s", s->file_path);
        if (s->rule_id[0]) {
            snprintf(f->rule, sizeof(f->rule), "%s", s->rule_id);
            snprintf(f->detail, sizeof(f->detail), "%s", s->reason);
        } else {
            snprintf(f->rule, sizeof(f->rule), "%s", s->reason);
        }
        snprintf(f->hash, sizeof(f->hash), "%s", s->sha256);
        return true;
    }
    return false;
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

/* The first flagged file is captured for the Inspect view; the export is a no-op when quarantine is off.
 * Failures are logged and the scan goes on. */
static void export_file(forensic_scan_report_t *out, quarantine_t *q, const char *prefix, const char *root,
                        const char *path, uint64_t max) {
    if (!path[0]) return;
    if (!out->inspect.path[0]) {
        booto_error_t ie = inspect_capture(root, path, max, &out->inspect);
        if (ie != BOOTO_OK) LOG_WARN("Inspect: could not read %s: %s", path, err_name(ie));
    }
    if (!q) return;
    booto_error_t e = quarantine_add(q, prefix, root, path, max);
    if (e != BOOTO_OK) LOG_WARN("Quarantine: could not export %s: %s", path, err_name(e));
}

static void export_uefi(forensic_scan_report_t *out, quarantine_t *q, const uefi_scan_result_t *u, const char *esp_root) {
    for (int i = 0; i < u->bootkits_detected && i < MAX_UEFI_THREATS; i++)
        export_file(out, q, "uefi", esp_root, u->findings[i].file_path, QUARANTINE_MAX_ITEM);
}

/* The boot manager on the ESP against the newest boot log Windows saved: report only, never the verdict. */
static void check_measured(forensic_scan_report_t *out, const char *esp) {
    char path[512], log[64] = "";
    snprintf(path, sizeof(path), "%s/EFI/Microsoft/Boot/bootmgfw.efi", esp);
    pe_efi_info_t pe;
    memset(&pe, 0, sizeof(pe));
    if (uefi_parse_pe_file(path, &pe) != BOOTO_OK || !pe.authenticode_sha256[0]) return;
    bool found = false;
    booto_error_t e = winboot_measured_has(out->scan_root, pe.authenticode_sha256, &found, log, sizeof(log));
    char *m = out->measured_note;
    size_t n = sizeof(out->measured_note);
    if (e == BOOTO_ERR_NOT_FOUND) snprintf(m, n, "no saved Windows boot log to compare bootmgfw.efi with");
    else if (e == BOOTO_ERR_CORRUPT_DATA) snprintf(m, n, "Windows boot log %s is malformed", log);
    else if (e != BOOTO_OK) snprintf(m, n, "Windows boot log %s unreadable: %s", log, err_name(e));
    else if (found) snprintf(m, n, "bootmgfw.efi is what the last Windows boot (%s) ran", log);
    else snprintf(m, n, "bootmgfw.efi is NOT what the last Windows boot (%s) ran: changed since, by an update or tampering", log);
    LOG_INFO("Measured boot: %s", m);
}

/* UEFI engine: <root>/boot/efi if it holds EFI files, else the ESP(s) on target_dev's disk, mounted read-only. */
static void run_uefi(forensic_scan_report_t *out, const char *target_dev, bool have_root, quarantine_t *q) {
    char note[96];
    if (have_root) {
        char path[512];
        snprintf(path, sizeof(path), "%.256s/boot/efi", out->scan_root);
        booto_error_t e = uefi_inspect_esp_directory(path, &out->uefi);
        if (e == BOOTO_OK && out->uefi.efi_files_scanned > 0) {
            export_uefi(out, q, &out->uefi, path);
            snprintf(out->esp_dev, sizeof(out->esp_dev), "%.118s/boot/efi", out->scan_root);
            snprintf(note, sizeof(note), "ESP: %.90s", out->esp_dev);
            set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_OK, e, note);
            return;
        }
        if (e == BOOTO_ERR_CORRUPT_DATA) {
            set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_ERROR, e, "YARA rules refused (unsigned or altered)");
            return;
        }
    }
    if (!target_dev) {
        set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_NA, BOOTO_OK, "no EFI system partition found");
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
        if (e == BOOTO_OK) export_uefi(out, q, &out->uefi, ESP_MOUNT_POINT);
        if (g_baseline) baseline_add_tree(g_baseline, "esp", ESP_MOUNT_POINT);
        if (have_root && winboot_is_windows_root(out->scan_root)) check_measured(out, ESP_MOUNT_POINT);
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
    set_status(out, SCAN_MOD_UEFI, SCAN_STATUS_NA, BOOTO_OK, "no EFI system partition found");
}

/* The BCD store on the ESP the UEFI engine found, mounted again read-only when it is a device. */
static void check_bcd(forensic_scan_report_t *out, quarantine_t *q) {
    if (!out->esp_dev[0]) return;
    bool dev = strncmp(out->esp_dev, out->scan_root, strlen(out->scan_root)) != 0;
    const char *esp = dev ? ESP_MOUNT_POINT : out->esp_dev;
    if (dev && disk_mount_ro(out->esp_dev, ESP_MOUNT_POINT, "vfat") != BOOTO_OK) {
        LOG_WARN("Windows boot: cannot mount %s again for its BCD store", out->esp_dev);
        out->winboot.not_checked++;
        return;
    }
    int before = out->winboot.threats_detected;
    booto_error_t e = winboot_check_bcd(esp, &out->winboot);
    if (e != BOOTO_OK && e != BOOTO_ERR_NOT_FOUND) out->winboot.not_checked++;
    for (int i = before; i < out->winboot.threats_detected && i < MAX_WINBOOT_THREATS; i++)
        export_file(out, q, "windows", esp, out->winboot.findings[i].file_path, QUARANTINE_MAX_ITEM);
    if (dev) {
        booto_error_t ue = disk_unmount(ESP_MOUNT_POINT);
        if (ue != BOOTO_OK) LOG_WARN("Failed to unmount %s: %s", ESP_MOUNT_POINT, err_name(ue));
    }
}

booto_error_t forensic_scan_run(const char *target_dev, const char *rootfs_dir, const bool *enabled,
                                const char *quarantine_dir, forensic_scan_progress_cb cb, void *user,
                                forensic_scan_report_t *out) {
    if (!out || (!target_dev && !rootfs_dir)) return BOOTO_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (target_dev) snprintf(out->target_dev, sizeof(out->target_dev), "%.127s", target_dev);

    if (rootfs_dir) {
        snprintf(out->scan_root, sizeof(out->scan_root), "%.255s", rootfs_dir);
    } else {
        snprintf(out->scan_root, sizeof(out->scan_root), "%s", SCAN_MOUNT_POINT);
        if (!sha256_head_hex(target_dev, SCAN_HEAD_BYTES, out->head_before)) out->head_before[0] = '\0';
        out->mount_err = disk_mount_ro(target_dev, SCAN_MOUNT_POINT, NULL);
        out->mounted = (out->mount_err == BOOTO_OK);
        if (!out->mounted) LOG_ERROR("Cannot mount %s read-only: %s", target_dev, err_name(out->mount_err));
    }

    char rootfs_note[96];
    snprintf(rootfs_note, sizeof(rootfs_note), "rootfs not mounted: %s", err_name(out->mount_err));
    char fs[32] = "";
    if (target_dev && !out->mounted && disk_probe_fs_magic(target_dev, fs, sizeof(fs), NULL, 0) == BOOTO_OK &&
        strcmp(fs, "BitLocker") == 0)
        snprintf(rootfs_note, sizeof(rootfs_note), "BitLocker volume: locked, not scanned (F3 unlocks)");
    bool have_root = (out->mount_err == BOOTO_OK);
    bool windows = have_root && winboot_is_windows_root(out->scan_root);
    static const char WIN_NOTE[] = "Windows install: Linux engine does not apply";
    const char *root = out->scan_root;
    char path[512];
    quarantine_t *q = quarantine_dir ? quarantine_open(quarantine_dir) : NULL;
    if (quarantine_dir && !q) LOG_ERROR("Out of memory: quarantine export disabled");

    if (begin(out, SCAN_MOD_MBR, enabled, cb, user)) {
        if (!target_dev) set_status(out, SCAN_MOD_MBR, SCAN_STATUS_SKIPPED, BOOTO_OK, "no raw device");
        else set_result(out, SCAN_MOD_MBR, mbr_audit_device(target_dev, &out->mbr));
        if (out->mbr.threats_detected > 0) export_file(out, q, "mbr", NULL, target_dev, MBR_EXPORT_BYTES);
    }

    if (begin(out, SCAN_MOD_UEFI, enabled, cb, user)) run_uefi(out, target_dev, have_root, q);

    if (begin(out, SCAN_MOD_KERNEL, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_KERNEL, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else if (windows) {
            set_status(out, SCAN_MOD_KERNEL, SCAN_STATUS_NA, BOOTO_OK, WIN_NOTE);
        } else {
            snprintf(path, sizeof(path), "%.256s/lib/modules", root);
            set_result(out, SCAN_MOD_KERNEL, kernel_inspect_directory(path, &out->kernel));
            for (int i = 0; i < out->kernel.threats_detected && i < MAX_KERNEL_THREATS; i++)
                export_file(out, q, "kernel", root, out->kernel.findings[i].file_path, QUARANTINE_MAX_ITEM);
        }
    }

    if (begin(out, SCAN_MOD_INITRAMFS, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_INITRAMFS, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else if (windows) {
            set_status(out, SCAN_MOD_INITRAMFS, SCAN_STATUS_NA, BOOTO_OK, WIN_NOTE);
        } else if (!find_initramfs(root, path, sizeof(path))) {
            set_status(out, SCAN_MOD_INITRAMFS, SCAN_STATUS_NA, BOOTO_OK, "no initramfs found");
        } else {
            set_result(out, SCAN_MOD_INITRAMFS, initramfs_audit_file(path, &out->initramfs));
            if (out->initramfs.threats_detected > 0) export_file(out, q, "initramfs", root, path, QUARANTINE_MAX_ITEM);
        }
    }

    if (begin(out, SCAN_MOD_PRELOAD, enabled, cb, user)) {
        if (!have_root) set_status(out, SCAN_MOD_PRELOAD, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        else if (windows) set_status(out, SCAN_MOD_PRELOAD, SCAN_STATUS_NA, BOOTO_OK, WIN_NOTE);
        else set_result(out, SCAN_MOD_PRELOAD, preload_scan_rootfs(root, &out->preload));
        for (int i = 0; i < out->preload.threats_detected && i < MAX_PRELOAD_THREATS; i++) {
            const char *lib = out->preload.findings[i].target_library;
            snprintf(path, sizeof(path), "%.256s%s%.250s", root, lib[0] == '/' ? "" : "/", lib);
            export_file(out, q, "preload", root, lib[0] ? path : "", QUARANTINE_MAX_ITEM);
        }
    }

    if (begin(out, SCAN_MOD_PKG, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_PKG, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else if (windows) {
            set_status(out, SCAN_MOD_PKG, SCAN_STATUS_NA, BOOTO_OK, WIN_NOTE);
        } else {
            booto_error_t e = pkg_integrity_scan_rootfs(root, &out->pkg);
            if (e == BOOTO_ERR_NOT_FOUND) {
                set_status(out, SCAN_MOD_PKG, SCAN_STATUS_SKIPPED, BOOTO_OK, "no dpkg or pacman database");
            } else if (e == BOOTO_OK) {
                for (int i = 0; i < out->pkg.threats_detected && i < MAX_PKG_THREATS; i++) {
                    snprintf(path, sizeof(path), "%.256s%.255s", root, out->pkg.findings[i].file_path);
                    export_file(out, q, "pkg", root, path, QUARANTINE_MAX_ITEM);
                }
                char note[96];
                snprintf(note, sizeof(note), "%d files verified, %d listed files missing", out->pkg.files_checked,
                         out->pkg.files_missing);
                set_status(out, SCAN_MOD_PKG, SCAN_STATUS_OK, e, note);
            } else {
                set_result(out, SCAN_MOD_PKG, e);
            }
        }
    }

    if (begin(out, SCAN_MOD_WINBOOT, enabled, cb, user)) {
        if (!have_root) {
            set_status(out, SCAN_MOD_WINBOOT, SCAN_STATUS_ERROR, out->mount_err, rootfs_note);
        } else if (!windows) {
            set_status(out, SCAN_MOD_WINBOOT, SCAN_STATUS_NA, BOOTO_OK, "not a Windows install");
        } else {
            booto_error_t e = winboot_scan_rootfs(root, &out->winboot);
            for (int i = 0; i < out->winboot.threats_detected && i < MAX_WINBOOT_THREATS; i++)
                export_file(out, q, "windows", root, out->winboot.findings[i].file_path, QUARANTINE_MAX_ITEM);
            if (e == BOOTO_OK) check_bcd(out, q);
            if (e == BOOTO_OK) {
                char note[96];
                snprintf(note, sizeof(note), "%d files, %d boot-start; %d drivers unsigned, %d third-party",
                         out->winboot.files_checked, out->winboot.boot_start, out->winboot.drivers_unsigned,
                         out->winboot.drivers_third_party);
                set_status(out, SCAN_MOD_WINBOOT, SCAN_STATUS_OK, e, note);
            } else {
                set_result(out, SCAN_MOD_WINBOOT, e);
            }
        }
    }

    if (g_baseline) {
        if (target_dev) baseline_add_device(g_baseline, "disk/first-1MiB", target_dev, MBR_EXPORT_BYTES);
        if (have_root) {
            snprintf(path, sizeof(path), "%.256s/boot", root);
            baseline_add_tree(g_baseline, "root/boot", path);
            core_ctx_t c = { g_baseline, strlen(root) };
            if (windows) winboot_each_core_file(root, add_core, &c);
        }
    }

    if (g_bodyfile && have_root) out->bodyfile_written = bodyfile_write(root, g_bodyfile) == BOOTO_OK;
    if (g_hashlist && have_root) out->hashlist_written = hashlist_write(root, g_hashlist) == BOOTO_OK;

    if (q) out->quarantined = quarantine_close(q, out->quarantine_zip, sizeof(out->quarantine_zip));

    if (out->mounted) {
        booto_error_t ue = disk_unmount(SCAN_MOUNT_POINT);
        if (ue != BOOTO_OK) LOG_WARN("Failed to unmount %s: %s", SCAN_MOUNT_POINT, err_name(ue));
    }
    if (out->head_before[0] && !sha256_head_hex(target_dev, SCAN_HEAD_BYTES, out->head_after)) out->head_after[0] = '\0';

    if (target_dev) {
        firmware_audit(NULL, &out->firmware);
        out->firmware_ran = true;
        LOG_INFO("Firmware: %d issue(s), %d unknown", out->firmware.fail_count, out->firmware.unknown_count);
        if (out->firmware.chipset_unconfirmed)
            LOG_INFO("Firmware: this chipset is not confirmed yet; run 'booto -c -t %s' for how to help", target_dev);
    }

    out->total_threats = 0;
    for (int i = 0; i < SCAN_MOD_COUNT; i++) out->total_threats += forensic_scan_module_threats(out, (scan_module_id_t)i);

    bool any_ok = false, any_gap = false;
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        if (out->status[i] == SCAN_STATUS_OK) any_ok = true;
        // A skipped engine left part of the boot chain unchecked, so CLEAN would overclaim.
        if (out->status[i] == SCAN_STATUS_ERROR || out->status[i] == SCAN_STATUS_SKIPPED) any_gap = true;
    }
    if (out->total_threats > 0) out->verdict = SCAN_VERDICT_THREATS;
    else if (any_gap || !any_ok) out->verdict = SCAN_VERDICT_INCOMPLETE;
    else out->verdict = SCAN_VERDICT_CLEAN;
    return BOOTO_OK;
}

/* Initramfs and package findings carry no severity: each is confirmed tampering, so CRITICAL. */
static booto_severity_t highest_severity(const forensic_scan_report_t *r) {
    if (r->initramfs.threats_detected || r->pkg.threats_detected) return SEVERITY_CRITICAL;
    booto_severity_t max = SEVERITY_INFO;
    for (int i = 0; i < r->preload.threats_detected && i < MAX_PRELOAD_THREATS; i++)
        if (r->preload.findings[i].severity > max) max = r->preload.findings[i].severity;
    for (int i = 0; i < r->mbr.threats_detected; i++)
        if (r->mbr.findings[i].severity > max) max = r->mbr.findings[i].severity;
    for (int i = 0; i < r->uefi.bootkits_detected; i++)
        if (r->uefi.findings[i].severity > max) max = r->uefi.findings[i].severity;
    for (int i = 0; i < r->kernel.threats_detected; i++)
        if (r->kernel.findings[i].severity > max) max = r->kernel.findings[i].severity;
    for (int i = 0; i < r->winboot.threats_detected && i < MAX_WINBOOT_THREATS; i++)
        if (r->winboot.findings[i].severity > max) max = r->winboot.findings[i].severity;
    return max;
}

/* Read a sysfs attribute of the disk behind /dev/<name>: a partition's own dir has no device/, its parent's has.
 * skip drops the 4-byte header of a SCSI VPD page 0x80. Keeps printable ASCII only, trimmed. */
static void disk_attr(const char *dev, const char *attr, size_t skip, char *out, size_t size) {
    out[0] = '\0';
    const char *name = strrchr(dev, '/');
    name = name ? name + 1 : dev;
    if (!name[0] || strchr(name, '.')) return;
    char path[256], buf[128];
    FILE *fp = NULL;
    for (int up = 0; up < 2 && !fp; up++) {
        snprintf(path, sizeof(path), "/sys/class/block/%.64s/%sdevice/%s", name, up ? "../" : "", attr);
        fp = fopen(path, "rb");
    }
    if (!fp) return;
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    size_t o = 0;
    for (size_t i = skip; i < n && o + 1 < size; i++)
        if (buf[i] > 0x20 && buf[i] < 0x7f) out[o++] = buf[i];
        else if (buf[i] == ' ' && o > 0) out[o++] = ' ';
    while (o > 0 && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

void forensic_scan_fill_case_summary(const forensic_scan_report_t *r, const char *case_id, const char *examiner,
                                     forensic_case_summary_t *sum) {
    if (!r || !sum) return;
    memset(sum, 0, sizeof(*sum));
    time_t now = time(NULL);
    struct tm tm_utc;
    bool have_time = gmtime_r(&now, &tm_utc) != NULL;
    if (case_id) snprintf(sum->case_id, sizeof(sum->case_id), "%.63s", case_id);
    else if (!have_time || strftime(sum->case_id, sizeof(sum->case_id), "CASE-%Y%m%d-%H%M%S", &tm_utc) == 0)
        snprintf(sum->case_id, sizeof(sum->case_id), "CASE-unknown");
    if (!examiner) examiner = getenv("USER");
    snprintf(sum->examiner, sizeof(sum->examiner), "%.63s", (examiner && examiner[0]) ? examiner : "unknown");
    snprintf(sum->target_disk, sizeof(sum->target_disk), "%.127s", r->target_dev[0] ? r->target_dev : r->scan_root);
    snprintf(sum->target_fs, sizeof(sum->target_fs), "unknown");
    if (r->target_dev[0]) {
        disk_attr(r->target_dev, "model", 0, sum->target_model, sizeof(sum->target_model));
        disk_attr(r->target_dev, "serial", 0, sum->target_serial, sizeof(sum->target_serial));  // NVMe
        if (!sum->target_serial[0]) disk_attr(r->target_dev, "vpd_pg80", 4, sum->target_serial, sizeof(sum->target_serial));
    }

    if (have_time) strftime(sum->timestamp, sizeof(sum->timestamp), "%Y-%m-%d %H:%M:%S UTC", &tm_utc);

    sum->mbr_threats_count = r->mbr.threats_detected;
    sum->kernel_threats_count = r->kernel.threats_detected;
    sum->uefi_threats_count = r->uefi.bootkits_detected;
    sum->initramfs_threats_count = r->initramfs.threats_detected;
    sum->preload_threats_count = r->preload.threats_detected;
    sum->pkg_threats_count = r->pkg.threats_detected;
    sum->winboot_threats_count = r->winboot.threats_detected;
    sum->total_threats = r->total_threats;
    snprintf(sum->highest_severity, sizeof(sum->highest_severity), "%s", r->total_threats > 0 ? booto_severity_str(highest_severity(r)) : "NONE");
    snprintf(sum->verdict, sizeof(sum->verdict), "%s", forensic_scan_verdict_str(r->verdict));
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        snprintf(sum->module_status[i], sizeof(sum->module_status[i]), "%s", forensic_scan_status_str(r->status[i]));
    }
    sum->firmware_ran = r->firmware_ran;
    sum->firmware = r->firmware;
    snprintf(sum->head_before, sizeof(sum->head_before), "%s", r->head_before);
    snprintf(sum->head_after, sizeof(sum->head_after), "%s", r->head_after);
}
