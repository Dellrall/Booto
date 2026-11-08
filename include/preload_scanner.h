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
 * @brief Audit every library listed in <root>/etc/ld.so.preload (whitespace/':' separated, '#' comments),
 *        LD_PRELOAD in <root>/etc/environment, suspicious ld.so.conf.d search paths, modprobe.d
 *        install hooks (PERSIST_MODPROBE_INSTALL), udev RUN hooks (PERSIST_UDEV_RUN), systemd Exec lines
 *        (PERSIST_SYSTEMD_EXEC), cron jobs and rc.local (PERSIST_CRON), shell profiles (PERSIST_SHELL_PROFILE)
 *        and authorized_keys forced commands (PERSIST_SSH_FORCED_COMMAND) that run temp/hidden-path programs
 *        or code fetched at run time (curl/wget/base64 piped into a shell), and known rootkit install
 *        paths from rootkit_file_iocs.json (IOC_*).
 * @param target_rootfs Path to mounted target rootfs (e.g. /tmp/booto_target_mnt).
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success; BOOTO_ERR_IO if a present preload/environment file cannot be read,
 *         BOOTO_ERR_CORRUPT_DATA if it exceeds 1 MiB or the IOC rules fail their seal, other negative codes on failure.
 */
booto_error_t preload_scan_rootfs(const char *target_rootfs, preload_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PRELOAD_SCANNER_H */
