/**
 * @file test_mbr_auditor.c
 * @brief Unit tests for MBR, Track 0 Slack Gap, and VBR bootkit forensic analyzer.
 */
#include "test_framework.h"
#include "mbr_auditor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_clean_grub2_mbr(void) {
    TEST_START("test_clean_grub2_mbr");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    // GRUB2 jump & string
    mbr[0] = 0xEB;
    mbr[1] = 0x63;
    mbr[2] = 0x90;
    memcpy(&mbr[0x180], "Welcome to GRUB!", 16);

    // Boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // Partition 1: Linux Rootfs at LBA 2048 (size 1000000 sectors), Active
    mbr_partition_record_t *p1 = (mbr_partition_record_t *)&mbr[MBR_PARTITION_TABLE_OFFSET];
    p1->status = 0x80;
    p1->partition_type = 0x83; // Linux
    p1->lba_start = 2048;
    p1->sector_count = 1000000;

    // Partition 2: Linux Swap at LBA 1002048
    mbr_partition_record_t *p2 = (mbr_partition_record_t *)&mbr[MBR_PARTITION_TABLE_OFFSET + 16];
    p2->status = 0x00;
    p2->partition_type = 0x82; // Linux Swap
    p2->lba_start = 1002048;
    p2->sector_count = 8000;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_buffer(mbr, sizeof(mbr), "/dev/sda", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "MBR audit buffer must return OK");
    ASSERT_TRUE(res.mbr_info.has_valid_signature, "Boot signature 0x55AA must be valid");
    ASSERT_INT_EQ(res.mbr_info.detected_bootloader, BOOTLOADER_GRUB2, "Bootloader must be identified as GRUB2");
    ASSERT_INT_EQ(res.mbr_info.valid_partition_count, 2, "Must detect 2 valid partitions");
    ASSERT_INT_EQ(res.mbr_info.active_partition_count, 1, "Must detect 1 active partition");
    ASSERT_INT_EQ(res.mbr_info.first_partition_lba, 2048, "First partition LBA must be 2048");
    ASSERT_INT_EQ(res.mbr_info.mbr_gap_sectors, 2047, "MBR gap must be 2047 sectors");
    ASSERT_INT_EQ(res.threats_detected, 0, "Clean GRUB2 MBR must have 0 threats");

    TEST_PASS("test_clean_grub2_mbr");
}

static void test_clean_windows_mbr(void) {
    TEST_START("test_clean_windows_mbr");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    mbr[0] = 0x33;
    mbr[1] = 0xC0;
    mbr[2] = 0x8E;
    memcpy(&mbr[0x100], "Invalid partition table\x00Missing operating system", 48);

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr_partition_record_t *p1 = (mbr_partition_record_t *)&mbr[MBR_PARTITION_TABLE_OFFSET];
    p1->status = 0x80;
    p1->partition_type = 0x07; // NTFS
    p1->lba_start = 2048;
    p1->sector_count = 5000000;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_buffer(mbr, sizeof(mbr), "/dev/nvme0n1", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "MBR audit buffer must return OK");
    ASSERT_INT_EQ(res.mbr_info.detected_bootloader, BOOTLOADER_WINDOWS_NT, "Must identify Windows NT bootloader");
    ASSERT_INT_EQ(res.threats_detected, 0, "Clean Windows MBR must have 0 threats");

    TEST_PASS("test_clean_windows_mbr");
}

static void test_rovnix_bootkit_detection(void) {
    TEST_START("test_rovnix_bootkit_detection");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    // Inject Rovnix bootkit signature
    uint8_t rovnix_code[] = { 0xFA, 0x33, 0xC0, 0x8E, 0xD0, 0x8E, 0xD8, 0x8E, 0xC0, 0xBC, 0x00, 0x7C, 0xCD, 0x13 };
    memcpy(&mbr[0], rovnix_code, sizeof(rovnix_code));

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr_partition_record_t *p1 = (mbr_partition_record_t *)&mbr[MBR_PARTITION_TABLE_OFFSET];
    p1->status = 0x80;
    p1->partition_type = 0x83;
    p1->lba_start = 2048;
    p1->sector_count = 1000;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_buffer(mbr, sizeof(mbr), "/dev/sda", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Audit buffer must succeed");
    ASSERT_TRUE(res.threats_detected > 0, "Rovnix bootkit must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_BOOTKIT_ROVNIX", "Must match MBR_BOOTKIT_ROVNIX rule");
    ASSERT_INT_EQ(res.findings[0].severity, MBR_SEVERITY_CRITICAL, "Rovnix severity must be CRITICAL");

    TEST_PASS("test_rovnix_bootkit_detection");
}

static void test_tdl4_bootkit_detection(void) {
    TEST_START("test_tdl4_bootkit_detection");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    // Inject TDL4 IVT overwrite hook
    uint8_t tdl4_code[] = { 0x31, 0xC0, 0x8E, 0xD8, 0x89, 0x16, 0x4C, 0x00, 0xEB, 0x10 };
    memcpy(&mbr[0], tdl4_code, sizeof(tdl4_code));

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    mbr_audit_buffer(mbr, sizeof(mbr), "/dev/sdb", &res);
    ASSERT_TRUE(res.threats_detected > 0, "TDL4 bootkit must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_BOOTKIT_TDL4_MEBROOT", "Must match MBR_BOOTKIT_TDL4_MEBROOT");

    TEST_PASS("test_tdl4_bootkit_detection");
}

static void test_wiper_ransomware_detection(void) {
    TEST_START("test_wiper_ransomware_detection");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    memcpy(&mbr[0x20], "Repairing filesystem... CHKDSK is repairing bad sectors", 55);
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    mbr_audit_buffer(mbr, sizeof(mbr), "/dev/sdc", &res);
    ASSERT_TRUE(res.threats_detected > 0, "Wiper payload must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_WIPER_RANSOMWARE", "Must match MBR_WIPER_RANSOMWARE");

    TEST_PASS("test_wiper_ransomware_detection");
}

static void test_mbr_gap_hidden_payload(void) {
    TEST_START("test_mbr_gap_hidden_payload");

    uint8_t gap[2048]; // 4 sectors
    memset(gap, 0, sizeof(gap));

    // Inject hidden payload in sector 1 (LBA 2)
    gap[512] = 0xEB; // jmp short
    gap[513] = 0x20;
    gap[514] = 0xCD; // int 13h
    gap[515] = 0x13;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Gap buffer audit must succeed");
    ASSERT_TRUE(res.threats_detected > 0, "Hidden gap payload must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_GAP_ANOMALOUS_PAYLOAD", "Must match MBR_GAP_ANOMALOUS_PAYLOAD");
    ASSERT_TRUE(res.mbr_info.has_mbr_gap_payload, "MBR gap payload flag must be set");

    TEST_PASS("test_mbr_gap_hidden_payload");
}

static void test_vbr_gapz_detection(void) {
    TEST_START("test_vbr_gapz_detection");

    uint8_t vbr[512];
    memset(vbr, 0, sizeof(vbr));

    memcpy(&vbr[3], "NTFS    ", 8);
    // GAPZ hook signature
    uint8_t gapz_hook[] = { 0xEB, 0x58, 0x90, 0x56, 0x57, 0x53, 0x8C, 0xC8 };
    memcpy(&vbr[0], gapz_hook, sizeof(gapz_hook));
    vbr[510] = 0x55;
    vbr[511] = 0xAA;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_vbr_buffer(vbr, sizeof(vbr), 2048, "/dev/sda1", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "VBR audit must succeed");
    ASSERT_TRUE(res.threats_detected > 0, "GAPZ VBR bootkit must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "VBR_BOOTKIT_GAPZ", "Must match VBR_BOOTKIT_GAPZ");

    TEST_PASS("test_vbr_gapz_detection");
}

static void test_corrupt_signature_and_partitions(void) {
    TEST_START("test_corrupt_signature_and_partitions");

    uint8_t mbr[512];
    memset(mbr, 0, sizeof(mbr));

    // Missing 0x55AA (leaves zeroes at 510-511)
    mbr_partition_record_t *p1 = (mbr_partition_record_t *)&mbr[MBR_PARTITION_TABLE_OFFSET];
    p1->status = 0x33; // Invalid status byte
    p1->partition_type = 0x83;
    p1->lba_start = 2048;
    p1->sector_count = 5000;

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    mbr_audit_buffer(mbr, sizeof(mbr), "/dev/sda", &res);
    ASSERT_TRUE(res.threats_detected >= 2, "Must detect invalid signature and corrupt partition table");

    TEST_PASS("test_corrupt_signature_and_partitions");
}

static void test_device_open_failure_is_error(void) {
    TEST_START("test_device_open_failure_is_error");
    mbr_scan_result_t res;
    ASSERT_INT_EQ(mbr_audit_device("/nonexistent/booto_disk", &res), BOOTO_ERR_NOT_FOUND,
                  "Unreadable device must fail instead of reporting a clean mock");
    ASSERT_INT_EQ(res.threats_detected, 0, "No findings may be fabricated");
    ASSERT_INT_EQ(res.sectors_scanned, 0, "No sectors were scanned");
    TEST_PASS("test_device_open_failure_is_error");
}

int main(void) {
    printf("\n--- Running MBR/VBR Bootkit Auditor Tests ---\n");
    test_clean_grub2_mbr();
    test_clean_windows_mbr();
    test_rovnix_bootkit_detection();
    test_tdl4_bootkit_detection();
    test_wiper_ransomware_detection();
    test_mbr_gap_hidden_payload();
    test_vbr_gapz_detection();
    test_corrupt_signature_and_partitions();
    test_device_open_failure_is_error();
    TEST_SUMMARY();
    return 0;
}
