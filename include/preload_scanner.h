/**
 * @file preload_scanner.h
 * @brief Offline forensic scanner for LD_PRELOAD rootkits and PAM interceptors.
 */
#ifndef BOOTO_PRELOAD_SCANNER_H
#define BOOTO_PRELOAD_SCANNER_H

#include "booto.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PRELOAD_THREATS 32

typedef struct {
    char file_path[256];
    char threat_name[64];
    char target_library[256];
    char sha256[65];
    char rule_id[64];
    char description[256];
} preload_finding_t;

typedef struct {
    int files_scanned;
    int threats_detected;
    preload_finding_t findings[MAX_PRELOAD_THREATS];
} preload_scan_result_t;

/**
 * @brief Run full userland preload and PAM interceptor scan on target rootfs.
 * @param target_rootfs Path to mounted target rootfs (e.g. /tmp/booto_target_mnt).
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t preload_scan_rootfs(const char *target_rootfs, preload_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PRELOAD_SCANNER_H */
