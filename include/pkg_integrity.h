/**
 * @file pkg_integrity.h
 * @brief Offline dpkg integrity check: re-hashes packaged system files against the md5sums lists in
 *        <root>/var/lib/dpkg/info.
 */
#ifndef BOOTO_PKG_INTEGRITY_H
#define BOOTO_PKG_INTEGRITY_H

#include "booto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PKG_THREATS 32

typedef struct {
    char file_path[256];    /**< Path inside the target root, e.g. "/usr/bin/ls" */
    char package[96];       /**< Owning package, from the md5sums file name */
    char expected_md5[33];  /**< MD5 recorded by dpkg */
    char actual_md5[33];    /**< MD5 on disk; "" when the file is no longer a regular file */
    char reason[48];
} pkg_finding_t;

typedef struct {
    int packages_checked;
    int files_checked;      /**< Files in system directories that were hashed */
    int files_missing;      /**< Listed but absent (deleted by the admin or a tool); not a threat */
    int files_unreadable;
    int threats_detected;
    pkg_finding_t findings[MAX_PKG_THREATS];
} pkg_scan_result_t;

/**
 * @brief Hash every file dpkg lists under bin, sbin, lib*, usr/bin, usr/sbin, usr/lib*, boot and flag mismatches.
 *        Paths resolve inside target_rootfs only (openat2 RESOLVE_IN_ROOT), so planted absolute symlinks cannot
 *        point the check at the live system. Diverted files (<root>/var/lib/dpkg/diversions) are skipped.
 *        Limit: trusts the md5sums lists on the target; an attacker with root can rewrite them.
 * @return BOOTO_OK; BOOTO_ERR_NOT_FOUND if the root has no dpkg database; BOOTO_ERR_IO if any listed system file
 *         could not be read (findings are still filled in).
 */
booto_error_t pkg_integrity_scan_rootfs(const char *target_rootfs, pkg_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PKG_INTEGRITY_H */
