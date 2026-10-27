/**
 * @file firmware_auditor.h
 * @brief Read-only audit of the host machine's firmware: Secure Boot key state
 *        (efivars), PKfail test keys, dbx presence and DMA protection (ACPI DMAR/IVRS,
 *        Thunderbolt). Describes the machine Booto booted on, not the scanned disk.
 */
#ifndef BOOTO_FIRMWARE_AUDITOR_H
#define BOOTO_FIRMWARE_AUDITOR_H

#include "booto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FW_RESULT_PASS, FW_RESULT_FAIL, FW_RESULT_UNKNOWN, FW_RESULT_NA } fw_result_t;

typedef enum {
    FW_CHECK_SECURE_BOOT,      /* "Secure Boot on" */
    FW_CHECK_SETUP_MODE,       /* "Setup mode off" */
    FW_CHECK_PLATFORM_KEY,     /* "Platform key" */
    FW_CHECK_TEST_KEYS,        /* "No test keys (PKfail)" */
    FW_CHECK_DBX,              /* "Revocation list (dbx)" */
    FW_CHECK_IOMMU,            /* "IOMMU described (DMAR/IVRS)" */
    FW_CHECK_THUNDERBOLT_DMA,  /* "Thunderbolt DMA protection" */
    FW_CHECK_COUNT
} fw_check_id_t;

typedef struct {
    fw_result_t result;
    char detail[160];          /* one plain sentence */
} fw_check_t;

typedef struct {
    bool uefi_boot;                     /* efivars directory exists */
    fw_check_t checks[FW_CHECK_COUNT];
    int fail_count;
    int unknown_count;
} firmware_report_t;

typedef struct {
    const char *efivars_dir;
    const char *acpi_tables_dir;
    const char *thunderbolt_dir;
} firmware_paths_t;

/**
 * @brief Audit host firmware state. Never writes to any firmware interface.
 * @param paths NULL (or NULL fields) = /sys/firmware/efi/efivars, /sys/firmware/acpi/tables,
 *              /sys/bus/thunderbolt/devices.
 * @return BOOTO_OK whenever out != NULL (unreadable checks carry UNKNOWN);
 *         BOOTO_ERR_INVALID_ARG if out is NULL.
 */
booto_error_t firmware_audit(const firmware_paths_t *paths, firmware_report_t *out);

const char *firmware_check_name(fw_check_id_t id);
const char *firmware_result_str(fw_result_t r);   /* "pass" "fail" "unknown" "n/a" */

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_FIRMWARE_AUDITOR_H */
