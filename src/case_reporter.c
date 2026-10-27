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
#include "forensic_scan.h"
#include "crypto_utils.h"
#include "logger.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* case_id becomes part of the report filename: allow only [A-Za-z0-9_-]{1,50}. */
static bool case_id_is_safe(const char *id) {
    size_t n = strlen(id);
    if (n == 0 || n > 50) return false;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

/* Emit s as a quoted JSON string (RFC 8259 escaping). */
static void json_put_string(FILE *fp, const char *s) {
    fputc('"', fp);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (*p < 0x20) fprintf(fp, "\\u%04x", *p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

/* Emit s inside a Markdown table code span: backticks, pipes and control chars would break the cell. */
static void md_put_cell(FILE *fp, const char *s) {
    fputc('`', fp);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '`') fputc('\'', fp);
        else if (*p == '|') fputs("\\|", fp);
        else if (*p < 0x20) fputc(' ', fp);
        else fputc(*p, fp);
    }
    fputc('`', fp);
}

/* Close fp and report any buffered write error so truncated reports are never reported as OK. */
static booto_error_t finish_report(FILE *fp, const char *filename) {
    bool write_err = ferror(fp) != 0;
    if (fclose(fp) != 0 || write_err) {
        LOG_ERROR("Failed to write case report '%s'", filename);
        return BOOTO_ERR_IO;
    }
    return BOOTO_OK;
}

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
    if (!fp) {
        LOG_ERROR("Failed to create seal file '%s'", seal_file);
        return BOOTO_ERR_IO;
    }
    fprintf(fp, "%s  %s\n", sha256_seal, report_path);
    booto_error_t err = finish_report(fp, seal_file);
    if (err != BOOTO_OK) return err;

    LOG_INFO("Case report integrity seal generated: %s (Seal: %.16s...)", report_path, sha256_seal);
    return BOOTO_OK;
}

booto_error_t case_report_generate_json(const forensic_case_summary_t *summary,
                                        const char *output_dir,
                                        char *saved_path,
                                        size_t max_path) {
    if (!summary || !output_dir || !saved_path || max_path == 0) return BOOTO_ERR_INVALID_ARG;
    if (!case_id_is_safe(summary->case_id)) {
        LOG_ERROR("Rejected unsafe case ID '%.64s' (allowed: A-Z a-z 0-9 _ -)", summary->case_id);
        return BOOTO_ERR_INVALID_ARG;
    }

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
    fprintf(fp, "  \"git_hash\": \"%s\",\n", BOOTO_GIT_HASH);
    fprintf(fp, "  \"case_metadata\": {\n");
    fputs("    \"case_id\": ", fp); json_put_string(fp, summary->case_id); fputs(",\n", fp);
    fputs("    \"timestamp\": ", fp); json_put_string(fp, summary->timestamp); fputs(",\n", fp);
    fputs("    \"examiner\": ", fp); json_put_string(fp, summary->examiner); fputs(",\n", fp);
    fputs("    \"target_disk\": ", fp); json_put_string(fp, summary->target_disk); fputs(",\n", fp);
    fputs("    \"target_fs\": ", fp); json_put_string(fp, summary->target_fs); fputs("\n", fp);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"findings_summary\": {\n");
    fprintf(fp, "    \"total_threats\": %d,\n", summary->total_threats);
    fputs("    \"highest_severity\": ", fp); json_put_string(fp, summary->highest_severity); fputs(",\n", fp);
    fprintf(fp, "    \"mbr_bootkit_threats\": %d,\n", summary->mbr_threats_count);
    fprintf(fp, "    \"kernel_lkm_threats\": %d,\n", summary->kernel_threats_count);
    fprintf(fp, "    \"uefi_bootkit_threats\": %d,\n", summary->uefi_threats_count);
    fprintf(fp, "    \"initramfs_script_threats\": %d,\n", summary->initramfs_threats_count);
    fprintf(fp, "    \"userland_preload_threats\": %d\n", summary->preload_threats_count);
    fprintf(fp, "  },\n");
    fputs("  \"verdict\": ", fp); json_put_string(fp, summary->verdict); fputs(",\n", fp);
    fprintf(fp, "  \"module_status\": {\n");
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        fputs("    ", fp); json_put_string(fp, forensic_scan_module_name((scan_module_id_t)i));
        fputs(": ", fp); json_put_string(fp, summary->module_status[i]);
        fputs(i + 1 < SCAN_MOD_COUNT ? ",\n" : "\n", fp);
    }
    fprintf(fp, "  },\n");
    fputs("  \"host_firmware\": ", fp);
    if (!summary->firmware_ran) {
        fputs("null\n", fp);
    } else {
        fprintf(fp, "{\n    \"scope\": \"machine running Booto\",\n    \"uefi_boot\": %s,\n    \"checks\": [\n",
                summary->firmware.uefi_boot ? "true" : "false");
        for (int i = 0; i < FW_CHECK_COUNT; i++) {
            const fw_check_t *c = &summary->firmware.checks[i];
            fputs("      {\"name\": ", fp); json_put_string(fp, firmware_check_name((fw_check_id_t)i));
            fputs(", \"result\": ", fp); json_put_string(fp, firmware_result_str(c->result));
            fputs(", \"detail\": ", fp); json_put_string(fp, c->detail);
            fputs(i + 1 < FW_CHECK_COUNT ? "},\n" : "}\n", fp);
        }
        fputs("    ]\n  }\n", fp);
    }
    fprintf(fp, "}\n");

    booto_error_t err = finish_report(fp, filename);
    if (err != BOOTO_OK) return err;

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    return case_report_sign_and_seal(filename, seal);
}

static void md_module_row(FILE *fp, const char *engine, int detections, const char *status) {
    fprintf(fp, "| **%s** | %d | ", engine, detections);
    md_put_cell(fp, status);
    fputs(" |\n", fp);
}

booto_error_t case_report_generate_markdown(const forensic_case_summary_t *summary,
                                            const char *output_dir,
                                            char *saved_path,
                                            size_t max_path) {
    if (!summary || !output_dir || !saved_path || max_path == 0) return BOOTO_ERR_INVALID_ARG;
    if (!case_id_is_safe(summary->case_id)) {
        LOG_ERROR("Rejected unsafe case ID '%.64s' (allowed: A-Z a-z 0-9 _ -)", summary->case_id);
        return BOOTO_ERR_INVALID_ARG;
    }

    char filename[512];
    snprintf(filename, sizeof(filename), "%.400s/case_%.50s.md", output_dir, summary->case_id);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        LOG_ERROR("Failed to create Markdown case report '%s'", filename);
        return BOOTO_ERR_IO;
    }

    fprintf(fp, "# Booto Forensic Rootkit & Bootkit Detection Report\n\n");
    fputs("**Case ID:** ", fp); md_put_cell(fp, summary->case_id); fputs("  \n", fp);
    fputs("**Generated:** ", fp); md_put_cell(fp, summary->timestamp); fputs("  \n", fp);
    fputs("**Examiner:** ", fp); md_put_cell(fp, summary->examiner); fputs("  \n", fp);
    fprintf(fp, "**Engine Version:** `%s` (Commit `%s`)  \n\n", BOOTO_VERSION_STRING, BOOTO_GIT_HASH);

    fprintf(fp, "## 1. Executive Summary\n\n");
    fprintf(fp, "| Parameter | Details |\n");
    fprintf(fp, "| :--- | :--- |\n");
    fputs("| **Target Block Device** | ", fp); md_put_cell(fp, summary->target_disk); fputs(" |\n", fp);
    fputs("| **Target Filesystem** | ", fp); md_put_cell(fp, summary->target_fs); fputs(" |\n", fp);
    fputs("| **Scan Verdict** | ", fp); md_put_cell(fp, summary->verdict); fputs(" |\n", fp);
    fprintf(fp, "| **Total Anomalies Detected** | **%d** |\n", summary->total_threats);
    fputs("| **Highest Severity Level** | ", fp); md_put_cell(fp, summary->highest_severity); fputs(" |\n\n", fp);

    fprintf(fp, "## 2. Detection Breakdown by Module\n\n");
    fprintf(fp, "| Forensic Inspection Engine | Detections Count | Status |\n");
    fprintf(fp, "| :--- | :---: | :--- |\n");
    md_module_row(fp, "MBR & VBR Boot Sector Auditor", summary->mbr_threats_count, summary->module_status[SCAN_MOD_MBR]);
    md_module_row(fp, "Kernel LKM & Syscall Hook Inspector", summary->kernel_threats_count, summary->module_status[SCAN_MOD_KERNEL]);
    md_module_row(fp, "UEFI & ESP Bootkit Analyzer", summary->uefi_threats_count, summary->module_status[SCAN_MOD_UEFI]);
    md_module_row(fp, "In-Memory Initramfs Script Auditor", summary->initramfs_threats_count, summary->module_status[SCAN_MOD_INITRAMFS]);
    md_module_row(fp, "Userland `ld.so.preload` Scanner", summary->preload_threats_count, summary->module_status[SCAN_MOD_PRELOAD]);
    md_module_row(fp, "Ext4 Superblock Stats", 0, summary->module_status[SCAN_MOD_EXT4]);
    fputs("\n", fp);

    fprintf(fp, "## Host firmware\n\n");
    if (!summary->firmware_ran) {
        fprintf(fp, "Not run (no raw target device).\n\n");
    } else {
        fprintf(fp, "These checks describe the machine Booto booted on and do not affect the disk verdict.\n\n");
        fprintf(fp, "| Check | Result | Detail |\n| :--- | :--- | :--- |\n");
        for (int i = 0; i < FW_CHECK_COUNT; i++) {
            const fw_check_t *c = &summary->firmware.checks[i];
            fputs("| ", fp); md_put_cell(fp, firmware_check_name((fw_check_id_t)i));
            fputs(" | ", fp); md_put_cell(fp, firmware_result_str(c->result));
            fputs(" | ", fp); md_put_cell(fp, c->detail);
            fputs(" |\n", fp);
        }
        fputs("\n", fp);
    }

    fprintf(fp, "## 3. Cryptographic Chain of Custody\n\n");
    fprintf(fp, "This report was generated in an amnesic Live RAM environment and saved to the LUKS2 encrypted persistence container. Integrity hashes are verified with SHA-256.\n");

    booto_error_t err = finish_report(fp, filename);
    if (err != BOOTO_OK) return err;

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    return case_report_sign_and_seal(filename, seal);
}
