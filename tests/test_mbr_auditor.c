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

// Deterministic xorshift32 fill: stands in for packed/encrypted (or LZMA-compressed) bytes.
static void fill_random(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        buf[i] = (uint8_t)(x >> 24);
    }
}

static void test_mbr_gap_hidden_payload(void) {
    TEST_START("test_mbr_gap_hidden_payload");

    uint8_t gap[2048]; // 4 sectors
    memset(gap, 0, sizeof(gap));

    // Real-mode INT 13h hooking stub in sector 1 (LBA 2): stack/segment setup, IVT hook, chain to 0000:7C00
    static const uint8_t stub[] = {
        0xFA,                               // cli
        0x31, 0xC0,                         // xor ax,ax
        0x8E, 0xD0,                         // mov ss,ax
        0xBC, 0x00, 0x7C,                   // mov sp,7C00h
        0xFB,                               // sti
        0x8E, 0xD8,                         // mov ds,ax
        0xA1, 0x4C, 0x00,                   // mov ax,[004Ch] (save INT 13h vector)
        0xC7, 0x06, 0x4C, 0x00, 0x40, 0x7E, // mov word [004Ch],7E40h (install hook)
        0xB8, 0x01, 0x02,                   // mov ax,0201h
        0xCD, 0x13,                         // int 13h
        0xEA, 0x00, 0x7C, 0x00, 0x00,       // jmp 0000:7C00
    };
    memcpy(&gap[512], stub, sizeof(stub));

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));

    booto_error_t err = mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res);
    ASSERT_INT_EQ(err, BOOTO_OK, "Gap buffer audit must succeed");
    ASSERT_TRUE(res.threats_detected > 0, "Hidden gap payload must be detected");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_GAP_ANOMALOUS_PAYLOAD", "Must match MBR_GAP_ANOMALOUS_PAYLOAD");
    ASSERT_TRUE(res.mbr_info.has_mbr_gap_payload, "MBR gap payload flag must be set");

    TEST_PASS("test_mbr_gap_hidden_payload");
}

static void test_mbr_gap_grub_string_evasion(void) {
    TEST_START("test_mbr_gap_grub_string_evasion");

    uint8_t gap[4096];
    fill_random(gap, sizeof(gap), 0xC0FFEEu);
    // Strings that used to allow-list the whole gap, embedded inside the packed payload
    memcpy(&gap[64], "GRUB ", 5);
    memcpy(&gap[600], "grub_core", 9);
    memcpy(&gap[1200], "SYSLINUX ldlinux", 16);

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res), BOOTO_OK, "Gap audit must succeed");
    ASSERT_INT_EQ(res.threats_detected, 1, "Embedded loader strings must not suppress the packed-payload finding");
    ASSERT_STR_EQ(res.findings[0].rule_id, "MBR_GAP_ANOMALOUS_PAYLOAD", "Rule ID");

    TEST_PASS("test_mbr_gap_grub_string_evasion");
}

static void test_mbr_gap_grub_core_clean(void) {
    TEST_START("test_mbr_gap_grub_core_clean");

    uint8_t gap[8192];
    fill_random(gap, sizeof(gap), 0x1234567u); // LZMA-compressed GRUB kernel after diskboot.img
    memset(gap, 0, MBR_SECTOR_SIZE);
    // diskboot.img: push dx; push si; mov si,811Bh; call message; pop si; mov di,81F4h; mov ebp,[di]
    static const uint8_t diskboot[] = { 0x52, 0x56, 0xBE, 0x1B, 0x81, 0xE8, 0x39, 0x01,
                                        0x5E, 0xBF, 0xF4, 0x81, 0x66, 0x8B, 0x2D };
    memcpy(gap, diskboot, sizeof(diskboot));
    memcpy(&gap[0x11B], "loading", 8);
    // firstlist blocklist: start LBA 2, 15 sectors, load segment 0x0820
    static const uint8_t blocklist[] = { 0x02, 0, 0, 0, 0, 0, 0, 0, 0x0F, 0x00, 0x20, 0x08 };
    memcpy(&gap[0x1F4], blocklist, sizeof(blocklist));
    // lzma_decompress.img real-mode startup does INT 13h / segment setup legitimately
    static const uint8_t startup[] = { 0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xD0, 0xCD, 0x13 };
    memcpy(&gap[512], startup, sizeof(startup));

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res), BOOTO_OK, "Gap audit must succeed");
    ASSERT_INT_EQ(res.threats_detected, 0, "Structurally recognised GRUB core.img must not be flagged");
    ASSERT_TRUE(!res.mbr_info.has_mbr_gap_payload, "Payload flag must stay clear");

    TEST_PASS("test_mbr_gap_grub_core_clean");
}

static void test_mbr_gap_jump_byte_text_clean(void) {
    TEST_START("test_mbr_gap_jump_byte_text_clean");

    static const char text[] = "Partition tool scratch log: resized volume, moved extents, verified table. ";
    uint8_t gap[2048];
    for (size_t i = 0; i < sizeof(gap); i++) gap[i] = (uint8_t)text[i % (sizeof(text) - 1)];
    for (size_t s = 0; s < sizeof(gap); s += MBR_SECTOR_SIZE) gap[s] = 0xEB; // every sector starts with "jmp short"

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res), BOOTO_OK, "Gap audit must succeed");
    ASSERT_INT_EQ(res.threats_detected, 0, "Low-entropy data whose sectors start with 0xEB must not be flagged");

    TEST_PASS("test_mbr_gap_jump_byte_text_clean");
}

static void test_mbr_gap_all_zero_clean(void) {
    TEST_START("test_mbr_gap_all_zero_clean");

    uint8_t gap[4096];
    memset(gap, 0, sizeof(gap));

    mbr_scan_result_t res;
    memset(&res, 0, sizeof(res));
    ASSERT_INT_EQ(mbr_audit_gap_buffer(gap, sizeof(gap), 1, "/dev/sda", &res), BOOTO_OK, "Gap audit must succeed");
    ASSERT_INT_EQ(res.threats_detected, 0, "All-zero gap is clean");
    ASSERT_TRUE(!res.mbr_info.has_mbr_gap_payload, "Payload flag must stay clear");

    TEST_PASS("test_mbr_gap_all_zero_clean");
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
    test_mbr_gap_grub_string_evasion();
    test_mbr_gap_grub_core_clean();
    test_mbr_gap_jump_byte_text_clean();
    test_mbr_gap_all_zero_clean();
    test_vbr_gapz_detection();
    test_corrupt_signature_and_partitions();
    test_device_open_failure_is_error();
    TEST_SUMMARY();
    return 0;
}
