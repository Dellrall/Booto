/**
 * @file case_reporter.c
 * @brief Implementation of cryptographic forensic case report generator.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "case_reporter.h"
#include "crypto_utils.h"
#include "logger.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

booto_error_t case_report_sign_and_seal(const char *report_path, char sha256_seal[65]) {
    if (!report_path || !sha256_seal) return BOOTO_ERR_INVALID_ARG;

    if (!sha256_file_hex(report_path, sha256_seal)) {
        LOG_ERROR("Failed to compute SHA-256 seal on report '%s'", report_path);
        return BOOTO_ERR_IO;
    }

    // Write companion .sha256 file
    char seal_file[512];
    snprintf(seal_file, sizeof(seal_file), "%.500s.sha256", report_path);

    FILE *fp = fopen(seal_file, "w");
    if (fp) {
        fprintf(fp, "%s  %s\n", sha256_seal, report_path);
        fclose(fp);
    }

    LOG_INFO("Case report integrity seal generated: %s (Seal: %.16s...)", report_path, sha256_seal);
    return BOOTO_OK;
}

booto_error_t case_report_generate_json(const forensic_case_summary_t *summary,
                                        const char *output_dir,
                                        char *saved_path,
                                        size_t max_path) {
    if (!summary || !output_dir || !saved_path || max_path == 0) return BOOTO_ERR_INVALID_ARG;

    char filename[512];
    snprintf(filename, sizeof(filename), "%.400s/case_%.50s.json", output_dir, summary->case_id);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        LOG_ERROR("Failed to create JSON case report '%s'", filename);
        return BOOTO_ERR_IO;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"generator\": \"Booto Forensic Rootkit & Bootkit Detection Suite\",\n");
    fprintf(fp, "  \"version\": \"%s\",\n", BOOTO_VERSION_STRING);
    fprintf(fp, "  \"git_hash\": \"%s\",\n", BOOTO_GIT_HASH);\
    fprintf(fp, "  \"case_metadata\": {\n");
    fprintf(fp, "    \"case_id\": \"%s\",\n", summary->case_id);
    fprintf(fp, "    \"timestamp\": \"%s\",\n", summary->timestamp);
    fprintf(fp, "    \"examiner\": \"%s\",\n", summary->examiner);
    fprintf(fp, "    \"target_disk\": \"%s\",\n", summary->target_disk);
    fprintf(fp, "    \"target_fs\": \"%s\"\n", summary->target_fs);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"findings_summary\": {\n");
    fprintf(fp, "    \"total_threats\": %d,\n", summary->total_threats);
    fprintf(fp, "    \"highest_severity\": \"%s\",\n", summary->highest_severity);
    fprintf(fp, "    \"mbr_bootkit_threats\": %d,\n", summary->mbr_threats_count);
    fprintf(fp, "    \"kernel_lkm_threats\": %d,\n", summary->kernel_threats_count);
    fprintf(fp, "    \"uefi_bootkit_threats\": %d,\n", summary->uefi_threats_count);
    fprintf(fp, "    \"initramfs_script_threats\": %d,\n", summary->initramfs_threats_count);
    fprintf(fp, "    \"userland_preload_threats\": %d,\n", summary->preload_threats_count);
    fprintf(fp, "    \"ext4_hidden_inodes\": %d\n", summary->ext4_hidden_inodes_count);
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    fclose(fp);

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    case_report_sign_and_seal(filename, seal);
    return BOOTO_OK;
}

booto_error_t case_report_generate_markdown(const forensic_case_summary_t *summary,
                                            const char *output_dir,
                                            char *saved_path,
                                            size_t max_path) {
    if (!summary || !output_dir || !saved_path || max_path == 0) return BOOTO_ERR_INVALID_ARG;

    char filename[512];
    snprintf(filename, sizeof(filename), "%.400s/case_%.50s.md", output_dir, summary->case_id);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        LOG_ERROR("Failed to create Markdown case report '%s'", filename);
        return BOOTO_ERR_IO;
    }

    fprintf(fp, "# Booto Forensic Rootkit & Bootkit Detection Report\n\n");
    fprintf(fp, "**Case ID:** `%s`  \n", summary->case_id);
    fprintf(fp, "**Generated:** `%s`  \n", summary->timestamp);
    fprintf(fp, "**Examiner:** `%s`  \n", summary->examiner);
    fprintf(fp, "**Engine Version:** `%s` (Commit `%s`)  \n\n", BOOTO_VERSION_STRING, BOOTO_GIT_HASH);

    fprintf(fp, "## 1. Executive Summary\n\n");
    fprintf(fp, "| Parameter | Details |\n");
    fprintf(fp, "| :--- | :--- |\n");
    fprintf(fp, "| **Target Block Device** | `%s` |\n", summary->target_disk);
    fprintf(fp, "| **Target Filesystem** | `%s` |\n", summary->target_fs);
    fprintf(fp, "| **Total Anomalies Detected** | **%d** |\n", summary->total_threats);
    fprintf(fp, "| **Highest Severity Level** | **%s** |\n\n", summary->highest_severity);

    fprintf(fp, "## 2. Detection Breakdown by Module\n\n");
    fprintf(fp, "| Forensic Inspection Engine | Detections Count | Status |\n");
    fprintf(fp, "| :--- | :---: | :--- |\n");
    fprintf(fp, "| **MBR & VBR Boot Sector Auditor** | %d | %s |\n",
            summary->mbr_threats_count, summary->mbr_threats_count > 0 ? "CRITICAL ALERT" : "CLEAN");
    fprintf(fp, "| **Kernel LKM & Syscall Hook Inspector** | %d | %s |\n",
            summary->kernel_threats_count, summary->kernel_threats_count > 0 ? "CRITICAL ALERT" : "CLEAN");
    fprintf(fp, "| **UEFI & ESP Bootkit Analyzer** | %d | %s |\n",
            summary->uefi_threats_count, summary->uefi_threats_count > 0 ? "CRITICAL ALERT" : "CLEAN");
    fprintf(fp, "| **In-Memory Initramfs Script Auditor** | %d | %s |\n",
            summary->initramfs_threats_count, summary->initramfs_threats_count > 0 ? "WARNING" : "CLEAN");
    fprintf(fp, "| **Userland `ld.so.preload` & PAM Scanner** | %d | %s |\n",
            summary->preload_threats_count, summary->preload_threats_count > 0 ? "ALERT" : "CLEAN");
    fprintf(fp, "| **Raw Ext4 Inode vs VFS Differential Engine** | %d | %s |\n\n",
            summary->ext4_hidden_inodes_count, summary->ext4_hidden_inodes_count > 0 ? "HIDDEN INODES FOUND" : "CLEAN");

    fprintf(fp, "## 3. Cryptographic Chain of Custody\n\n");
    fprintf(fp, "This report was generated in an amnesic Live RAM environment and saved to the LUKS2 encrypted persistence container. Integrity hashes are verified with SHA-256.\n");

    fclose(fp);

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    case_report_sign_and_seal(filename, seal);
    return BOOTO_OK;
}
