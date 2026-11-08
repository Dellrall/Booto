/**
 * @file pkg_integrity.h
 * @brief Offline package integrity check: re-hashes packaged system files against dpkg's md5sums lists
 *        (<root>/var/lib/dpkg/info) and pacman's mtree sha256 digests (<root>/var/lib/pacman/local).
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
    char package[96];       /**< Owning package, from the md5sums file or pacman directory name */
    char expected_hash[65]; /**< MD5 (dpkg, 32 hex) or SHA-256 (pacman, 64 hex) recorded by the package manager */
    char actual_hash[65];   /**< Same algorithm, on disk; "" when the file is no longer a regular file */
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
 * @brief Hash every file dpkg or pacman lists under bin, sbin, lib*, usr/bin, usr/sbin, usr/lib*, boot and flag
 *        mismatches. pacman's gzip mtree files are inflated by the sandboxed external gzip.
 *        Paths resolve inside target_rootfs only (openat2 RESOLVE_IN_ROOT), so planted absolute symlinks cannot
 *        point the check at the live system. Diverted files (<root>/var/lib/dpkg/diversions) are skipped.
 *        Limit: trusts the package database on the target; an attacker with root can rewrite it.
 * @return BOOTO_OK; BOOTO_ERR_NOT_FOUND if the root has neither a dpkg nor a pacman database; BOOTO_ERR_IO if any
 *         listed system file or pacman mtree could not be read (findings are still filled in).
 */
booto_error_t pkg_integrity_scan_rootfs(const char *target_rootfs, pkg_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PKG_INTEGRITY_H */
