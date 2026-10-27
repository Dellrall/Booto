/**
 * @file forensic_scan.h
 * @brief Orchestrates every detection engine against one target and computes an honest verdict.
 */
#ifndef BOOTO_FORENSIC_SCAN_H
#define BOOTO_FORENSIC_SCAN_H

#include "booto.h"
#include "case_reporter.h"
#include "mbr_auditor.h"
#include "uefi_analyzer.h"
#include "kernel_inspector.h"
#include "initramfs_auditor.h"
#include "preload_scanner.h"
#include "ext4_diff.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { SCAN_MOD_MBR, SCAN_MOD_UEFI, SCAN_MOD_KERNEL, SCAN_MOD_INITRAMFS, SCAN_MOD_PRELOAD, SCAN_MOD_EXT4, SCAN_MOD_COUNT } scan_module_id_t;
typedef enum { SCAN_STATUS_NOT_RUN, SCAN_STATUS_OK, SCAN_STATUS_ERROR, SCAN_STATUS_SKIPPED } scan_status_t;
typedef enum { SCAN_VERDICT_CLEAN, SCAN_VERDICT_THREATS, SCAN_VERDICT_INCOMPLETE } scan_verdict_t;

typedef struct {
    char target_dev[128];
    char scan_root[256];
    bool mounted;                       /* we mounted target_dev at scan_root */
    booto_error_t mount_err;            /* BOOTO_OK if rootfs available */
    scan_status_t status[SCAN_MOD_COUNT];
    booto_error_t err[SCAN_MOD_COUNT];
    char note[SCAN_MOD_COUNT][96];      /* human reason for SKIPPED/ERROR, "" if OK */
    mbr_scan_result_t mbr;
    uefi_scan_result_t uefi;
    kernel_scan_result_t kernel;
    initramfs_scan_result_t initramfs;
    preload_scan_result_t preload;
    ext4_diff_result_t ext4;
    int total_threats;
    scan_verdict_t verdict;
} forensic_scan_report_t;

/* step is 1..SCAN_MOD_COUNT, called before each module runs. */
typedef void (*forensic_scan_progress_cb)(int step, int total, const char *msg, void *user);

/* target_dev: raw device (may be NULL when rootfs_dir is given).
 * rootfs_dir: already-available root directory to inspect (e.g. -s path); when NULL, target_dev is mounted RO at
 *   /tmp/booto_scan_target via disk_mount_ro(target_dev, ..., NULL) and unmounted at the end.
 * enabled: NULL = all enabled. Disabled modules -> SKIPPED, note "disabled".
 * out: caller-allocated (it is large; heap-allocate it). Returns BOOTO_OK when the scan ran (whatever the verdict),
 * BOOTO_ERR_INVALID_ARG if both target_dev and rootfs_dir are NULL or out is NULL. */
booto_error_t forensic_scan_run(const char *target_dev, const char *rootfs_dir, const bool *enabled,
                                forensic_scan_progress_cb cb, void *user, forensic_scan_report_t *out);
const char *forensic_scan_module_name(scan_module_id_t id);
const char *forensic_scan_status_str(scan_status_t s);
const char *forensic_scan_verdict_str(scan_verdict_t v);
/* Fill a case summary from a finished report (timestamp = now UTC). */
void forensic_scan_fill_case_summary(const forensic_scan_report_t *r, const char *case_id, const char *examiner,
                                     forensic_case_summary_t *sum);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_FORENSIC_SCAN_H */
