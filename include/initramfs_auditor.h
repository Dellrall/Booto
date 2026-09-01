/**
 * @file initramfs_auditor.h
 * @brief In-memory CPIO decompressor and early-boot script security auditor.
 */
#ifndef BOOTO_INITRAMFS_AUDITOR_H
#define BOOTO_INITRAMFS_AUDITOR_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INITRAMFS_THREATS 32
#define MAX_CPIO_FILES        256

typedef struct {
    char file_path[256];
    char threat_name[64];
    char matched_pattern[64];
    uint32_t line_number;
    char description[256];
} initramfs_finding_t;

typedef struct {
    int files_extracted;
    int scripts_audited;
    int threats_detected;
    initramfs_finding_t findings[MAX_INITRAMFS_THREATS];
} initramfs_scan_result_t;

/**
 * @brief Parse and audit an in-memory CPIO initramfs archive.
 * @param buf Pointer to archive buffer.
 * @param len Buffer length in bytes.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t initramfs_audit_buffer(const uint8_t *buf, size_t len, initramfs_scan_result_t *result);

/**
 * @brief Audit an initramfs/initrd image file on disk.
 * @param initrd_path Path to the initrd image (e.g., /boot/initrd.img).
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t initramfs_audit_file(const char *initrd_path, initramfs_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_INITRAMFS_AUDITOR_H */
