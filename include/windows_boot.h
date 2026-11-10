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
    booto_severity_t severity;
} winboot_finding_t;

typedef struct {
    int files_checked;
    int drivers_unsigned;         /* no embedded signature: usually catalog-signed, not verified yet */
    int drivers_third_party;      /* intact signature, signer not under a Microsoft root */
    int not_checked;              /* SHA-1/SHA-384 signed, or too large to read */
    int threats_detected;
    winboot_finding_t findings[MAX_WINBOOT_THREATS];
} winboot_scan_result_t;

/* <root>/Windows/System32/ntoskrnl.exe exists (names matched case-insensitively). */
bool winboot_is_windows_root(const char *root);

/* Core files (winload, winresume, ntoskrnl, hal, ci) must carry an intact signature chaining to Microsoft;
 * a driver in System32/drivers is flagged when its embedded signature is broken. */
booto_error_t winboot_scan_rootfs(const char *root, winboot_scan_result_t *res);
/* Calls fn with the path of each core file present (winload, winresume, ntoskrnl, hal, ci). */
void winboot_each_core_file(const char *root, void (*fn)(const char *path, void *user), void *user);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_WINDOWS_BOOT_H */
