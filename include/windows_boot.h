/**
 * @file windows_boot.h
 * @brief Windows boot chain on a mounted NTFS root: Authenticode of the loader, kernel and boot drivers.
 */
#ifndef BOOTO_WINDOWS_BOOT_H
#define BOOTO_WINDOWS_BOOT_H

#include "booto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_WINBOOT_THREATS 32

typedef struct {
    char file_path[512];
    char sha256[65];              /* whole file; "" when it could not be read */
    char reason[96];
    char rule_id[32];             /* WIN_* for persistence and ransomware findings; "" for boot chain findings */
    booto_severity_t severity;
} winboot_finding_t;

typedef struct {
    int files_checked;
    int drivers_unsigned;         /* no embedded signature: usually catalog-signed, not verified yet */
    int drivers_third_party;      /* intact signature, signer not under a Microsoft root */
    int not_checked;              /* SHA-1/SHA-384 signed, too large to read, or a boot-start file not found */
    int boot_start;               /* services with Start = 0 in the SYSTEM hive */
    int threats_detected;
    winboot_finding_t findings[MAX_WINBOOT_THREATS];
} winboot_scan_result_t;

/* <root>/Windows/System32/ntoskrnl.exe exists (names matched case-insensitively). */
bool winboot_is_windows_root(const char *root);

/* Core files (winload, winresume, ntoskrnl, hal, ci) must carry an intact signature chaining to Microsoft;
 * a driver in System32/drivers, or a boot-start driver (SYSTEM hive) elsewhere, is flagged when its embedded
 * signature is broken. */
booto_error_t winboot_scan_rootfs(const char *root, winboot_scan_result_t *res);
/* <esp>/EFI/Microsoft/Boot/BCD: flags testsigning, nointegritychecks, the boot and kernel debuggers, and a Windows
 * loader entry whose path is not winload. Findings are appended to res. BOOTO_ERR_NOT_FOUND: no BCD store. */
booto_error_t winboot_check_bcd(const char *esp, winboot_scan_result_t *res);
/* Calls fn with the path of each core file present (winload, winresume, ntoskrnl, hal, ci). */
/* Newest TCG log Windows saved at boot under <root>/Windows/Logs/MeasuredBoot: *found = the Authenticode hash
 * (hex) is among the EFI applications that boot loaded. log_name gets the log's name. BOOTO_ERR_NOT_FOUND: no
 * log; BOOTO_ERR_CORRUPT_DATA: malformed log. */
booto_error_t winboot_measured_has(const char *root, const char *authenticode_hex, bool *found, char *log_name,
                                   size_t n);
/* EVTX buffer: number of chunks holding a log-clear event (1102/104), -1 when it is not an EVTX file.
 * *records gets the event count summed over valid chunks. */
int winboot_evtx_scan(const uint8_t *buf, size_t len, uint64_t *records);
void winboot_each_core_file(const char *root, void (*fn)(const char *path, void *user), void *user);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_WINDOWS_BOOT_H */
