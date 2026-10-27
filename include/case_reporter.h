/**
 * @file case_reporter.h
 * @brief Structured cryptographic forensic case report generator (JSON & Markdown).
 */
#ifndef BOOTO_CASE_REPORTER_H
#define BOOTO_CASE_REPORTER_H

#include "booto.h"
#include "firmware_auditor.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char case_id[64];
    char timestamp[32];
    char target_disk[128];
    char target_fs[32];
    char examiner[64];
    int mbr_threats_count;
    int kernel_threats_count;
    int uefi_threats_count;
    int initramfs_threats_count;
    int preload_threats_count;
    char verdict[16];                 /**< "CLEAN" / "THREATS" / "INCOMPLETE" */
    char module_status[6][16];        /**< Per-module status, indexed by scan_module_id_t */
    int total_threats;
    char highest_severity[16];
    bool firmware_ran;                /**< Host firmware audit ran (device mode only) */
    firmware_report_t firmware;       /**< Machine running Booto; not part of the verdict */
} forensic_case_summary_t;

/**
 * @brief Generate a machine-readable JSON forensic case report.
 * @param summary Aggregated scan results.
 * @param output_dir Destination directory (e.g. /persistence/cases).
 * @param saved_path Output buffer to receive full filepath of generated report.
 * @param max_path Max buffer length.
 * @return BOOTO_OK on success.
 */
booto_error_t case_report_generate_json(const forensic_case_summary_t *summary,
                                        const char *output_dir,
                                        char *saved_path,
                                        size_t max_path);

/**
 * @brief Generate a human-readable Markdown forensic case report.
 * @param summary Aggregated scan results.
 * @param output_dir Destination directory (e.g. /persistence/cases).
 * @param saved_path Output buffer to receive full filepath of generated report.
 * @param max_path Max buffer length.
 * @return BOOTO_OK on success.
 */
booto_error_t case_report_generate_markdown(const forensic_case_summary_t *summary,
                                            const char *output_dir,
                                            char *saved_path,
                                            size_t max_path);

/**
 * @brief Compute SHA-256 integrity seal for an exported case report.
 * @param report_path Full path to exported report.
 * @param sha256_seal 65-byte buffer to receive hex digest.
 * @return BOOTO_OK on success.
 */
booto_error_t case_report_sign_and_seal(const char *report_path, char sha256_seal[65]);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_CASE_REPORTER_H */
