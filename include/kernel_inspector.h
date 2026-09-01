/**
 * @file kernel_inspector.h
 * @brief Offline forensic analyzer for Linux kernel images (vmlinuz) and LKMs (.ko).
 */
#ifndef BOOTO_KERNEL_INSPECTOR_H
#define BOOTO_KERNEL_INSPECTOR_H

#include "booto.h"
#include "elf_analyzer.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_KERNEL_THREATS 64

typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} threat_severity_t;

typedef struct {
    char threat_name[64];
    char file_path[256];
    char sha256[65];
    char detection_rule[64];
    char matched_symbol[64];
    uint64_t symbol_offset;
    threat_severity_t severity;
    char description[256];
} kernel_threat_finding_t;

typedef struct {
    int modules_scanned;
    int threats_detected;
    kernel_threat_finding_t findings[MAX_KERNEL_THREATS];
} kernel_scan_result_t;

/**
 * @brief Inspect a single Linux Kernel Module (.ko) ELF file for rootkit hooks.
 * @param ko_path Filepath to the .ko module.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t kernel_inspect_lkm_file(const char *ko_path, kernel_scan_result_t *result);

/**
 * @brief Recursively scan a target /lib/modules/ directory.
 * @param lib_modules_dir Target rootfs /lib/modules directory path.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t kernel_inspect_directory(const char *lib_modules_dir, kernel_scan_result_t *result);

/**
 * @brief Inspect kernel image (vmlinuz) and symbol map for integrity anomalies.
 * @param vmlinuz_path Path to vmlinuz or extracted vmlinux binary.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t kernel_inspect_vmlinuz(const char *vmlinuz_path, kernel_scan_result_t *result);

/**
 * @brief Get string representation of threat severity.
 */
const char *kernel_severity_to_string(threat_severity_t severity);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_KERNEL_INSPECTOR_H */
