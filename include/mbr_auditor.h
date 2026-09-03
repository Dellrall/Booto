/**
 * @file mbr_auditor.h
 * @brief Offline forensic analyzer for Master Boot Record (MBR), MBR Slack Gap, and Volume Boot Records (VBR).
 */
#ifndef BOOTO_MBR_AUDITOR_H
#define BOOTO_MBR_AUDITOR_H

#include "booto.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MBR_THREATS 64
#define MBR_SECTOR_SIZE 512
#define MBR_BOOTSTRAP_SIZE 446
#define MBR_PARTITION_TABLE_OFFSET 446
#define MBR_PARTITION_COUNT 4
#define MBR_SIGNATURE_OFFSET 510
#define MBR_BOOT_SIGNATURE 0xAA55 // Little-endian 0x55, 0xAA

typedef enum {
    MBR_SEVERITY_INFO = 0,
    MBR_SEVERITY_LOW,
    MBR_SEVERITY_MEDIUM,
    MBR_SEVERITY_HIGH,
    MBR_SEVERITY_CRITICAL
} mbr_severity_t;

typedef enum {
    BOOTLOADER_UNKNOWN = 0,
    BOOTLOADER_GRUB2,
    BOOTLOADER_GRUB_LEGACY,
    BOOTLOADER_SYSLINUX,
    BOOTLOADER_WINDOWS_NT,
    BOOTLOADER_WINDOWS_LEGACY,
    BOOTLOADER_LILO,
    BOOTLOADER_CUSTOM_CLEAN
} bootloader_type_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t status;          // 0x80 = active/bootable, 0x00 = inactive
    uint8_t first_chs[3];    // CHS address of first sector
    uint8_t partition_type;  // Partition type (e.g. 0x83 = Linux, 0x07 = NTFS, 0xEF = EFI)
    uint8_t last_chs[3];     // CHS address of last sector
    uint32_t lba_start;      // LBA of first sector
    uint32_t sector_count;   // Number of sectors
} mbr_partition_record_t;

typedef struct {
    uint8_t bootstrap[MBR_BOOTSTRAP_SIZE];
    mbr_partition_record_t partitions[MBR_PARTITION_COUNT];
    uint16_t signature;
} mbr_raw_sector_t;
#pragma pack(pop)

typedef struct {
    char device_path[256];
    char mbr_sha256[65];
    char bootstrap_sha256[65];
    bool has_valid_signature;
    uint32_t disk_signature;
    bootloader_type_t detected_bootloader;
    const char *bootloader_name;
    int valid_partition_count;
    int active_partition_count;
    uint32_t first_partition_lba;
    uint32_t mbr_gap_sectors;
    bool has_mbr_gap_payload;
} mbr_analysis_info_t;

typedef struct {
    char threat_name[64];
    char target_device[256];
    char sha256[65];
    char rule_id[64];
    uint64_t sector_lba;
    mbr_severity_t severity;
    char description[256];
} mbr_threat_finding_t;

typedef struct {
    int sectors_scanned;
    bool mbr_inspected;
    int vbr_scanned;
    int threats_detected;
    mbr_analysis_info_t mbr_info;
    mbr_threat_finding_t findings[MAX_MBR_THREATS];
} mbr_scan_result_t;

/**
 * @brief Parse and audit a 512-byte MBR sector buffer.
 * @param buffer Pointer to 512-byte sector data.
 * @param len Length of buffer (must be at least 512 bytes).
 * @param device_path Path or identifier of the source device.
 * @param result Output structure to record findings and analysis metadata.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t mbr_audit_buffer(const uint8_t *buffer, size_t len, const char *device_path, mbr_scan_result_t *result);

/**
 * @brief Audit the Master Boot Record, MBR slack/gap, and VBR sectors of a block device.
 * @param block_dev Path to raw disk device (e.g. /dev/sda).
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t mbr_audit_device(const char *block_dev, mbr_scan_result_t *result);

/**
 * @brief Parse and audit a 512-byte Volume Boot Record (VBR) / Partition Boot Sector.
 * @param buffer Pointer to 512-byte VBR sector.
 * @param len Buffer length.
 * @param vbr_lba LBA sector location of the VBR.
 * @param device_path Path of source device or partition.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t mbr_audit_vbr_buffer(const uint8_t *buffer, size_t len, uint64_t vbr_lba, const char *device_path, mbr_scan_result_t *result);

/**
 * @brief Audit the unpartitioned MBR gap (Track 0 slack space) between sector 1 and first partition.
 * @param gap_data Pointer to buffer containing raw gap sectors.
 * @param gap_len Length of buffer in bytes.
 * @param start_lba First LBA of the gap (normally 1).
 * @param device_path Source device path.
 * @param result Output structure to record findings.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t mbr_audit_gap_buffer(const uint8_t *gap_data, size_t gap_len, uint64_t start_lba, const char *device_path, mbr_scan_result_t *result);

/**
 * @brief Convert MBR severity enum to string.
 * @param severity Severity level.
 * @return Human-readable severity string.
 */
const char *mbr_severity_to_string(mbr_severity_t severity);

/**
 * @brief Convert bootloader type enum to string.
 * @param type Bootloader identifier.
 * @return Human-readable bootloader name.
 */
const char *mbr_bootloader_to_string(bootloader_type_t type);

/**
 * @brief Emulate MBR bootkit scan with mock findings for non-root / test environments.
 * @param mock_type Identifier of mock scenario (e.g. "clean", "rovnix", "tdl4", "wiper").
 * @param result Output structure to fill.
 * @return BOOTO_OK on success.
 */
booto_error_t mbr_audit_mock(const char *mock_type, mbr_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_MBR_AUDITOR_H */
