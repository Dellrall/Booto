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
    // Bare file name, so `sha256sum -c` works from the cases directory wherever it is mounted.
    const char *base = strrchr(report_path, '/');
    fprintf(fp, "%s  %s\n", sha256_seal, base ? base + 1 : report_path);
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

    // One line, no indentation: the Markdown file is the human-readable copy.
    fprintf(fp, "{\"generator\":\"Booto\",\"version\":\"%s\",\"git_hash\":\"%s\",\"case_metadata\":{",
            BOOTO_VERSION_STRING, BOOTO_GIT_HASH);
    fputs("\"case_id\":", fp); json_put_string(fp, summary->case_id);
    fputs(",\"timestamp\":", fp); json_put_string(fp, summary->timestamp);
    fputs(",\"examiner\":", fp); json_put_string(fp, summary->examiner);
    fputs(",\"target_disk\":", fp); json_put_string(fp, summary->target_disk);
    fputs(",\"target_fs\":", fp); json_put_string(fp, summary->target_fs);
    fprintf(fp, "},\"findings_summary\":{\"total_threats\":%d,\"highest_severity\":", summary->total_threats);
    json_put_string(fp, summary->highest_severity);
    fprintf(fp, ",\"mbr_bootkit_threats\":%d,\"kernel_lkm_threats\":%d,\"uefi_bootkit_threats\":%d,"
                "\"initramfs_script_threats\":%d,\"userland_preload_threats\":%d,\"package_integrity_threats\":%d},",
            summary->mbr_threats_count, summary->kernel_threats_count, summary->uefi_threats_count,
            summary->initramfs_threats_count, summary->preload_threats_count, summary->pkg_threats_count);
    fputs("\"verdict\":", fp); json_put_string(fp, summary->verdict);
    fputs(",\"module_status\":{", fp);
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        if (i) fputc(',', fp);
        json_put_string(fp, forensic_scan_module_name((scan_module_id_t)i));
        fputc(':', fp);
        json_put_string(fp, summary->module_status[i]);
    }
    fputs("},\"host_firmware\":", fp);
    if (!summary->firmware_ran) {
        fputs("null", fp);
    } else {
        fprintf(fp, "{\"scope\":\"machine running Booto\",\"uefi_boot\":%s,\"checks\":[",
                summary->firmware.uefi_boot ? "true" : "false");
        for (int i = 0; i < FW_CHECK_COUNT; i++) {
            const fw_check_t *c = &summary->firmware.checks[i];
            fputs(i ? ",{\"name\":" : "{\"name\":", fp); json_put_string(fp, firmware_check_name((fw_check_id_t)i));
            fputs(",\"result\":", fp); json_put_string(fp, firmware_result_str(c->result));
            fputs(",\"detail\":", fp); json_put_string(fp, c->detail);
            fputc('}', fp);
        }
        fputs("]}", fp);
    }
    fputs("}\n", fp);

    booto_error_t err = finish_report(fp, filename);
    if (err != BOOTO_OK) return err;

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    return case_report_sign_and_seal(filename, seal);
}

static int summary_module_threats(const forensic_case_summary_t *s, scan_module_id_t id) {
    switch (id) {
        case SCAN_MOD_MBR:       return s->mbr_threats_count;
        case SCAN_MOD_UEFI:      return s->uefi_threats_count;
        case SCAN_MOD_KERNEL:    return s->kernel_threats_count;
        case SCAN_MOD_INITRAMFS: return s->initramfs_threats_count;
        case SCAN_MOD_PRELOAD:   return s->preload_threats_count;
        case SCAN_MOD_PKG:       return s->pkg_threats_count;
        default:                 return 0;
    }
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

    fputs("# Booto case ", fp); md_put_cell(fp, summary->case_id);
    fputs("\n\n", fp); md_put_cell(fp, summary->timestamp);
    fputs(", examiner ", fp); md_put_cell(fp, summary->examiner);
    fprintf(fp, ", Booto `%s` (`%s`)\n\n", BOOTO_VERSION_STRING, BOOTO_GIT_HASH);
    fputs("**Verdict:** ", fp); md_put_cell(fp, summary->verdict);
    fprintf(fp, ", **threats:** %d (", summary->total_threats); md_put_cell(fp, summary->highest_severity);
    fputs("), **target:** ", fp); md_put_cell(fp, summary->target_disk);
    fputs("\n\n| Engine | Threats | Status |\n| :--- | ---: | :--- |\n", fp);
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        fprintf(fp, "| %s | %d | ", forensic_scan_module_name((scan_module_id_t)i),
                summary_module_threats(summary, (scan_module_id_t)i));
        md_put_cell(fp, summary->module_status[i]);
        fputs(" |\n", fp);
    }

    fputs("\n## Host firmware\n\n", fp);
    if (!summary->firmware_ran) {
        fputs("Not run (no raw target device).\n", fp);
    } else {
        fputs("Describes the machine Booto booted on; these checks do not affect the disk verdict.\n\n", fp);
        fputs("| Check | Result | Detail |\n| :--- | :--- | :--- |\n", fp);
        for (int i = 0; i < FW_CHECK_COUNT; i++) {
            const fw_check_t *c = &summary->firmware.checks[i];
            fputs("| ", fp); md_put_cell(fp, firmware_check_name((fw_check_id_t)i));
            fputs(" | ", fp); md_put_cell(fp, firmware_result_str(c->result));
            fputs(" | ", fp); md_put_cell(fp, c->detail);
            fputs(" |\n", fp);
        }
    }

    booto_error_t err = finish_report(fp, filename);
    if (err != BOOTO_OK) return err;

    snprintf(saved_path, max_path, "%s", filename);

    char seal[65];
    return case_report_sign_and_seal(filename, seal);
}
