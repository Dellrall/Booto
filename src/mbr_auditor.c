/**
 * @file mbr_auditor.c
 * @brief Implementation of MBR, Track 0 Slack Gap, and VBR bootkit forensic analyzer.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "mbr_auditor.h"
#include "crypto_utils.h"
#include "logger.h"
#include "rules_loader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *mbr_severity_to_string(mbr_severity_t severity) {
    switch (severity) {
        case MBR_SEVERITY_CRITICAL: return "CRITICAL";
        case MBR_SEVERITY_HIGH:     return "HIGH";
        case MBR_SEVERITY_MEDIUM:   return "MEDIUM";
        case MBR_SEVERITY_LOW:      return "LOW";
        default:                    return "INFO";
    }
}

const char *mbr_bootloader_to_string(bootloader_type_t type) {
    switch (type) {
        case BOOTLOADER_GRUB2:          return "GRUB 2 (GNU GRUB)";
        case BOOTLOADER_GRUB_LEGACY:   return "GRUB Legacy (0.9x)";
        case BOOTLOADER_SYSLINUX:       return "Syslinux / ISOLINUX";
        case BOOTLOADER_WINDOWS_NT:     return "Windows Boot Manager (NT 6+)";
        case BOOTLOADER_WINDOWS_LEGACY: return "Windows Legacy MBR (NT 5 / XP)";
        case BOOTLOADER_LILO:           return "LILO Bootloader";
        case BOOTLOADER_CUSTOM_CLEAN:   return "Custom Standard Bootstrap";
        default:                        return "Unknown / Custom Bootstrap";
    }
}

static void add_mbr_threat(mbr_scan_result_t *result,
                           const char *threat_name,
                           const char *dev_path,
                           const char *sha256,
                           const char *rule_id,
                           uint64_t sector_lba,
                           mbr_severity_t severity,
                           const char *description) {
    if (!result || result->threats_detected >= MAX_MBR_THREATS) return;

    mbr_threat_finding_t *f = &result->findings[result->threats_detected++];
    snprintf(f->threat_name, sizeof(f->threat_name), "%.63s", threat_name ? threat_name : "MBR Anomaly");
    snprintf(f->target_device, sizeof(f->target_device), "%.255s", dev_path ? dev_path : "Disk");
    snprintf(f->sha256, sizeof(f->sha256), "%.64s", sha256 ? sha256 : "");
    snprintf(f->rule_id, sizeof(f->rule_id), "%.63s", rule_id ? rule_id : "MBR_UNKNOWN");
    f->sector_lba = sector_lba;
    f->severity = severity;
    snprintf(f->description, sizeof(f->description), "%.255s", description ? description : "");

    LOG_CRITICAL("[MBR ALERT] %s on %s (LBA %llu, Rule: %s)",
                 f->threat_name, f->target_device, (unsigned long long)f->sector_lba, f->rule_id);
}

// Helper: search byte pattern in buffer
static const uint8_t *mem_search(const uint8_t *haystack, size_t haystack_len,
                                  const uint8_t *needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(&haystack[i], needle, needle_len) == 0) {
            return &haystack[i];
        }
    }
    return NULL;
}

// Report every rule for `target` whose patterns (any of them) occur in buf[0..len).
static void apply_pattern_rules(const rules_mbr_set_t *rules, rules_mbr_target_t target,
                                const uint8_t *buf, size_t len, bool bootloader_known,
                                const char *dev_path, const char *sha256, uint64_t sector_lba,
                                mbr_scan_result_t *result) {
    for (int r = 0; r < rules->count; r++) {
        const rules_mbr_entry_t *rule = &rules->entries[r];
        if (rule->target != target || (rule->unknown_bootloader_only && bootloader_known)) continue;
        for (int p = 0; p < rule->pattern_count; p++) {
            if (!mem_search(buf, len, rule->patterns[p], rule->pattern_len[p])) continue;
            add_mbr_threat(result, rule->name, dev_path, sha256, rule->rule_id, sector_lba,
                           (mbr_severity_t)rules_severity_level(rule->severity), rule->description);
            break;
        }
    }
}

static bootloader_type_t detect_known_bootloader(const uint8_t *code, size_t len) {
    if (len < MBR_BOOTSTRAP_SIZE) return BOOTLOADER_UNKNOWN;

    // 1. Check GRUB 2
    if (mem_search(code, len, (const uint8_t *)"GRUB ", 5) ||
        mem_search(code, len, (const uint8_t *)"Welcome to GRUB!", 16) ||
        (code[0] == 0xEB && (code[1] == 0x63 || code[1] == 0x5E || code[1] == 0x48) && code[2] == 0x90)) {
        return BOOTLOADER_GRUB2;
    }

    // 2. Check Syslinux
    if (mem_search(code, len, (const uint8_t *)"SYSLINUX", 8) ||
        mem_search(code, len, (const uint8_t *)"ISOLINUX", 8) ||
        mem_search(code, len, (const uint8_t *)"EXTLINUX", 8)) {
        return BOOTLOADER_SYSLINUX;
    }

    // 3. Check Windows NT 6.x (Vista / 7 / 8 / 10 / 11)
    if (mem_search(code, len, (const uint8_t *)"Invalid partition table", 23) ||
        mem_search(code, len, (const uint8_t *)"Missing operating system", 24)) {
        return BOOTLOADER_WINDOWS_NT;
    }

    // 4. Check Windows Legacy (NT 5.x / XP)
    if (mem_search(code, len, (const uint8_t *)"A disk read error occurred", 26)) {
        return BOOTLOADER_WINDOWS_LEGACY;
    }

    // 5. Check GRUB Legacy
    if (mem_search(code, len, (const uint8_t *)"GRUB \x00", 6) ||
        mem_search(code, len, (const uint8_t *)"Geom\x00Hard Disk", 14)) {
        return BOOTLOADER_GRUB_LEGACY;
    }

    // 6. Check LILO
    if (mem_search(code, len, (const uint8_t *)"LILO", 4)) {
        return BOOTLOADER_LILO;
    }

    // Check if standard clean startup jump
    if ((code[0] == 0xFA && code[1] == 0x33 && code[2] == 0xC0) || // cli; xor ax, ax
        (code[0] == 0x33 && code[1] == 0xC0 && code[2] == 0x8E) || // xor ax, ax; mov ds, ax
        (code[0] == 0xEB && code[2] == 0x90)) {                     // jmp short xx; nop
        return BOOTLOADER_CUSTOM_CLEAN;
    }

    return BOOTLOADER_UNKNOWN;
}

booto_error_t mbr_audit_buffer(const uint8_t *buffer, size_t len, const char *device_path, mbr_scan_result_t *result) {
    if (!buffer || len < MBR_SECTOR_SIZE || !result) return BOOTO_ERR_INVALID_ARG;

    const rules_mbr_set_t *rules;
    booto_error_t err = rules_get_mbr(&rules);
    if (err != BOOTO_OK) return err;

    result->sectors_scanned++;
    result->mbr_inspected = true;

    mbr_analysis_info_t *info = &result->mbr_info;
    memset(info, 0, sizeof(*info));
    snprintf(info->device_path, sizeof(info->device_path), "%.255s", device_path ? device_path : "/dev/unknown");

    // Compute checksums
    sha256_buffer_hex(buffer, MBR_SECTOR_SIZE, info->mbr_sha256);
    sha256_buffer_hex(buffer, MBR_BOOTSTRAP_SIZE, info->bootstrap_sha256);

    // 1. Verify MBR Boot Signature 0x55AA (at offset 510-511)
    uint16_t sig = (uint16_t)((uint16_t)buffer[MBR_SIGNATURE_OFFSET] |
                              ((uint16_t)buffer[MBR_SIGNATURE_OFFSET + 1] << 8));
    info->has_valid_signature = (sig == MBR_BOOT_SIGNATURE);

    // 2. Parse MBR Disk Signature (at offset 440 / 0x1B8, 4 bytes)
    info->disk_signature = (uint32_t)buffer[0x1B8] |
                           ((uint32_t)buffer[0x1B9] << 8) |
                           ((uint32_t)buffer[0x1BA] << 16) |
                           ((uint32_t)buffer[0x1BB] << 24);

    // 3. Parse and Validate Partition Table (at offset 446 / 0x1BE)
    const mbr_partition_record_t *ptable = (const mbr_partition_record_t *)(const void *)&buffer[MBR_PARTITION_TABLE_OFFSET];
    uint32_t lowest_partition_lba = 0xFFFFFFFFU;
    bool has_partition_corruption = false;

    for (int i = 0; i < MBR_PARTITION_COUNT; i++) {
        const mbr_partition_record_t *entry = &ptable[i];

        // Check active / bootable flag: standard values are 0x00 (inactive) or 0x80 (active)
        if (entry->status == 0x80) {
            info->active_partition_count++;
        } else if (entry->status != 0x00) {
            has_partition_corruption = true;
        }

        if (entry->partition_type != 0x00 && entry->sector_count > 0) {
            info->valid_partition_count++;
            if (entry->lba_start > 0 && entry->lba_start < lowest_partition_lba) {
                lowest_partition_lba = entry->lba_start;
            }
        }
    }

    if (lowest_partition_lba != 0xFFFFFFFFU) {
        info->first_partition_lba = lowest_partition_lba;
        if (lowest_partition_lba > 1) {
            info->mbr_gap_sectors = lowest_partition_lba - 1;
        }
    }

    // 4. Identify Standard Bootloader
    info->detected_bootloader = detect_known_bootloader(buffer, MBR_BOOTSTRAP_SIZE);
    info->bootloader_name = mbr_bootloader_to_string(info->detected_bootloader);

    LOG_INFO("MBR on %s audited (Sig: 0x%04X, Bootloader: %s, Partitions: %d, Gap: %u sectors)",
             info->device_path, sig, info->bootloader_name, info->valid_partition_count, info->mbr_gap_sectors);

    // --- Threat Detections & Heuristic Analysis ---

    // A. Check for Missing / Invalid Boot Signature
    if (!info->has_valid_signature && info->valid_partition_count > 0) {
        add_mbr_threat(result, "Invalid MBR Boot Signature", info->device_path, info->mbr_sha256,
                       "MBR_INVALID_BOOT_SIGNATURE", 0, MBR_SEVERITY_HIGH,
                       "Partitioned storage sector 0 lacks standard 0x55AA boot signature (possible corrupt or wiped MBR)");
    }

    // B. Check Partition Table Corruptions
    if (has_partition_corruption) {
        add_mbr_threat(result, "Corrupted Partition Table Status Bytes", info->device_path, info->mbr_sha256,
                       "MBR_CORRUPT_PARTITION_TABLE", 0, MBR_SEVERITY_HIGH,
                       "MBR partition table status byte contains invalid active/boot flags (not 0x00 or 0x80)");
    }

    if (info->active_partition_count > 1) {
        add_mbr_threat(result, "Multiple Active MBR Partitions", info->device_path, info->mbr_sha256,
                       "MBR_MULTIPLE_ACTIVE_PARTITIONS", 0, MBR_SEVERITY_MEDIUM,
                       "More than one partition flagged as active/bootable (0x80) in MBR table");
    }

    // C. Known Bootkit Signatures and bootstrap heuristics (rules_loader: mbr_bootkit_signatures.json)
    apply_pattern_rules(rules, RULES_MBR_TARGET_BOOTSTRAP, buffer, MBR_BOOTSTRAP_SIZE,
                        info->detected_bootloader != BOOTLOADER_UNKNOWN,
                        info->device_path, info->bootstrap_sha256, 0, result);

    return BOOTO_OK;
}

// GRUB 2 diskboot.img (core.img sector 0): push dx; push si; mov si,imm16; call rel16; pop si;
// mov di,0x81F4 (firstlist); first blocklist segment 0x0820 in the last word of the sector.
static bool gap_starts_with_grub_core(const uint8_t *g, size_t len) {
    return len >= MBR_SECTOR_SIZE &&
           g[0] == 0x52 && g[1] == 0x56 && g[2] == 0xBE && g[5] == 0xE8 && g[8] == 0x5E &&
           g[9] == 0xBF && g[10] == 0xF4 && g[11] == 0x81 &&
           g[0x1FE] == 0x20 && g[0x1FF] == 0x08;
}

// Syslinux ldlinux.sys: "\r\n<NAME>LINUX " banner, then LDLINUX_MAGIC (0x3EB202FE) 8-byte aligned.
static bool gap_starts_with_ldlinux(const uint8_t *g, size_t len) {
    if (len < 64 || g[0] != '\r' || g[1] != '\n' || memcmp(&g[5], "LINUX ", 6) != 0) return false;
    static const uint8_t magic[4] = { 0xFE, 0x02, 0xB2, 0x3E };
    for (size_t off = 8; off + sizeof(magic) <= 64; off += 8) {
        if (memcmp(&g[off], magic, sizeof(magic)) == 0) return true;
    }
    return false;
}

typedef struct {
    const char *bytes;
    size_t len;
} gap_pattern_t;
#define GAP_PATTERN(s) { s, sizeof(s) - 1 }

// INT 13h call, INT 13h IVT vector overwrite (0000:004C), far jump to the relocated MBR at 0000:7C00.
static const gap_pattern_t k_gap_hook_patterns[] = {
    GAP_PATTERN("\xCD\x13"), GAP_PATTERN("\xA3\x4C\x00"), GAP_PATTERN("\xC7\x06\x4C\x00"),
    GAP_PATTERN("\xEA\x00\x7C\x00\x00"),
};
// Real-mode segment/stack setup: mov ss,ax / mov ds,ax / mov es,ax / mov sp,7C00h.
static const gap_pattern_t k_gap_setup_patterns[] = {
    GAP_PATTERN("\x8E\xD0"), GAP_PATTERN("\x8E\xD8"), GAP_PATTERN("\x8E\xC0"), GAP_PATTERN("\xBC\x00\x7C"),
};

static bool gap_has_any(const uint8_t *buf, size_t len, const gap_pattern_t *pats, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (mem_search(buf, len, (const uint8_t *)pats[i].bytes, pats[i].len)) return true;
    }
    return false;
}

// log2 without libm (the project links nothing): scale into [1,2), then ln via the atanh series.
static double log2_nolibm(double x) {
    double exponent = 0.0;
    while (x >= 2.0) { x /= 2.0; exponent += 1.0; }
    while (x < 1.0) { x *= 2.0; exponent -= 1.0; }
    double z = (x - 1.0) / (x + 1.0), z2 = z * z, term = z, sum = 0.0;
    for (int k = 1; k < 40; k += 2) {
        sum += term / (double)k;
        term *= z2;
    }
    return exponent + 2.0 * sum / 0.69314718055994530942;
}

// Shannon entropy (bits/byte) over the sectors holding any non-zero byte; *region_len gets their size.
static double gap_nonzero_entropy(const uint8_t *g, size_t len, size_t *region_len) {
    size_t hist[256] = { 0 };
    size_t n = 0;
    for (size_t off = 0; off < len; off += MBR_SECTOR_SIZE) {
        size_t chunk = (len - off < MBR_SECTOR_SIZE) ? len - off : MBR_SECTOR_SIZE;
        bool nonzero = false;
        for (size_t i = 0; i < chunk && !nonzero; i++) nonzero = g[off + i] != 0;
        if (!nonzero) continue;
        for (size_t i = 0; i < chunk; i++) hist[g[off + i]]++;
        n += chunk;
    }
    *region_len = n;
    if (n == 0) return 0.0;
    double weighted = 0.0;
    for (size_t b = 0; b < 256; b++) {
        if (hist[b]) weighted += (double)hist[b] * log2_nolibm((double)hist[b]);
    }
    return log2_nolibm((double)n) - weighted / (double)n;
}

#define GAP_PACKED_ENTROPY_BITS 7.2

booto_error_t mbr_audit_gap_buffer(const uint8_t *gap_data, size_t gap_len, uint64_t start_lba, const char *device_path, mbr_scan_result_t *result) {
    if (!gap_data || gap_len == 0 || !result) return BOOTO_ERR_INVALID_ARG;

    char dev_str[256];
    snprintf(dev_str, sizeof(dev_str), "%.255s", device_path ? device_path : "/dev/unknown");

    size_t region_len = 0;
    double entropy = gap_nonzero_entropy(gap_data, gap_len, &region_len);
    if (region_len == 0) {
        LOG_INFO("MBR gap (LBA %llu..%llu) is clean (all zero bytes)",
                 (unsigned long long)start_lba, (unsigned long long)(start_lba + (gap_len / MBR_SECTOR_SIZE) - 1));
        return BOOTO_OK;
    }

    // Allow-list only structurally recognised loaders at the gap start; strings elsewhere are attacker-controlled.
    if (gap_starts_with_grub_core(gap_data, gap_len)) {
        LOG_INFO("MBR gap starts with legitimate GRUB core.img (diskboot.img) payload");
        return BOOTO_OK;
    }
    if (gap_starts_with_ldlinux(gap_data, gap_len)) {
        LOG_INFO("MBR gap starts with legitimate Syslinux ldlinux stage payload");
        return BOOTO_OK;
    }

    bool code_like = gap_has_any(gap_data, gap_len, k_gap_hook_patterns,
                                 sizeof(k_gap_hook_patterns) / sizeof(k_gap_hook_patterns[0])) &&
                     gap_has_any(gap_data, gap_len, k_gap_setup_patterns,
                                 sizeof(k_gap_setup_patterns) / sizeof(k_gap_setup_patterns[0]));
    bool packed = region_len >= MBR_SECTOR_SIZE && entropy >= GAP_PACKED_ENTROPY_BITS;

    if (code_like || packed) {
        char gap_sha256[65];
        sha256_buffer_hex(gap_data, gap_len, gap_sha256);
        result->mbr_info.has_mbr_gap_payload = true;

        add_mbr_threat(result, "Hidden Executable Payload in MBR Gap", dev_str, gap_sha256,
                       "MBR_GAP_ANOMALOUS_PAYLOAD", start_lba, MBR_SEVERITY_HIGH,
                       code_like
                           ? "Unpartitioned Track 0 slack space contains unrecognized real-mode code with INT 13h / IVT hook patterns"
                           : "Unpartitioned Track 0 slack space contains unrecognized high-entropy (packed/encrypted) payload");
    }

    return BOOTO_OK;
}

booto_error_t mbr_audit_vbr_buffer(const uint8_t *buffer, size_t len, uint64_t vbr_lba, const char *device_path, mbr_scan_result_t *result) {
    if (!buffer || len < MBR_SECTOR_SIZE || !result) return BOOTO_ERR_INVALID_ARG;

    const rules_mbr_set_t *rules;
    booto_error_t err = rules_get_mbr(&rules);
    if (err != BOOTO_OK) return err;

    result->sectors_scanned++;
    result->vbr_scanned++;

    char dev_str[256];
    snprintf(dev_str, sizeof(dev_str), "%.255s", device_path ? device_path : "Partition");

    char vbr_sha256[65];
    sha256_buffer_hex(buffer, MBR_SECTOR_SIZE, vbr_sha256);

    // 1. Verify VBR signature (0x55AA at offset 510)
    uint16_t sig = (uint16_t)((uint16_t)buffer[MBR_SIGNATURE_OFFSET] |
                              ((uint16_t)buffer[MBR_SIGNATURE_OFFSET + 1] << 8));
    if (sig != MBR_BOOT_SIGNATURE) {
        // Some filesystems (like ext4) don't have 0x55AA at sector 0; only flag if NTFS/FAT OEM ID present
        if (memcmp(&buffer[3], "NTFS    ", 8) == 0 ||
            memcmp(&buffer[3], "MSDOS5.0", 8) == 0 ||
            memcmp(&buffer[3], "FAT32   ", 8) == 0) {
            add_mbr_threat(result, "Invalid VBR Boot Signature", dev_str, vbr_sha256,
                           "VBR_INVALID_SIGNATURE", vbr_lba, MBR_SEVERITY_HIGH,
                           "Partition Volume Boot Record contains Microsoft OEM ID but lacks 0x55AA signature");
        }
        return BOOTO_OK;
    }

    // 2. Validate BPB (BIOS Parameter Block)
    uint16_t bytes_per_sector = (uint16_t)(buffer[11] | (buffer[12] << 8));
    if (bytes_per_sector != 0 && bytes_per_sector != 512 && bytes_per_sector != 1024 &&
        bytes_per_sector != 2048 && bytes_per_sector != 4096) {
        add_mbr_threat(result, "Corrupted BPB Sector Geometry", dev_str, vbr_sha256,
                       "VBR_CORRUPTED_BPB", vbr_lba, MBR_SEVERITY_HIGH,
                       "Volume Boot Record BPB contains invalid sector geometry (possible bootkit hook or tamper)");
    }

    // 3. VBR bootkit signatures (e.g. GAPZ / Cidox jump into reserved clusters hooking INT 13h)
    apply_pattern_rules(rules, RULES_MBR_TARGET_VBR, buffer, MBR_SECTOR_SIZE, false,
                        dev_str, vbr_sha256, vbr_lba, result);

    return BOOTO_OK;
}

booto_error_t mbr_audit_device(const char *block_dev, mbr_scan_result_t *result) {
    if (!block_dev || !result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    LOG_INFO("Initiating offline MBR/VBR boot sector inspection on: %s", block_dev);

    int fd = open(block_dev, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        LOG_ERROR("Cannot open block device '%s': %s", block_dev, strerror(e));
        if (e == EACCES || e == EPERM) return BOOTO_ERR_PERMISSION_DENIED;
        return e == ENOENT ? BOOTO_ERR_NOT_FOUND : BOOTO_ERR_IO;
    }

    // 1. Read Master Boot Record (Sector 0)
    uint8_t mbr_buf[MBR_SECTOR_SIZE];
    ssize_t bytes_read = read(fd, mbr_buf, sizeof(mbr_buf));
    if (bytes_read != (ssize_t)sizeof(mbr_buf)) {
        LOG_ERROR("Failed to read Sector 0 from '%s'", block_dev);
        close(fd);
        return BOOTO_ERR_IO;
    }

    booto_error_t err = mbr_audit_buffer(mbr_buf, sizeof(mbr_buf), block_dev, result);
    if (err != BOOTO_OK) {
        close(fd);
        return err;
    }

    // 2. Audit Track 0 Slack Gap (if first partition starts after sector 1)
    if (result->mbr_info.first_partition_lba > 1 && result->mbr_info.mbr_gap_sectors > 0) {
        uint32_t gap_sectors_to_read = result->mbr_info.mbr_gap_sectors;
        if (gap_sectors_to_read > 63) {
            gap_sectors_to_read = 63; // Limit check to standard Track 0 slack size (31.5 KB)
        }

        size_t gap_bytes = (size_t)gap_sectors_to_read * MBR_SECTOR_SIZE;
        uint8_t *gap_buf = malloc(gap_bytes);
        if (gap_buf) {
            if (read(fd, gap_buf, gap_bytes) == (ssize_t)gap_bytes) {
                mbr_audit_gap_buffer(gap_buf, gap_bytes, 1, block_dev, result);
            }
            free(gap_buf);
        }
    }

    // 3. Audit VBRs of discovered partitions
    const mbr_partition_record_t *ptable = (const mbr_partition_record_t *)(const void *)&mbr_buf[MBR_PARTITION_TABLE_OFFSET];
    for (int i = 0; i < MBR_PARTITION_COUNT; i++) {
        if (ptable[i].partition_type != 0x00 && ptable[i].lba_start > 0) {
            off_t offset = (off_t)ptable[i].lba_start * MBR_SECTOR_SIZE;
            if (lseek(fd, offset, SEEK_SET) == offset) {
                uint8_t vbr_buf[MBR_SECTOR_SIZE];
                if (read(fd, vbr_buf, sizeof(vbr_buf)) == (ssize_t)sizeof(vbr_buf)) {
                    char part_name[300];
                    snprintf(part_name, sizeof(part_name), "%s#part%d", block_dev, i + 1);
                    mbr_audit_vbr_buffer(vbr_buf, sizeof(vbr_buf), ptable[i].lba_start, part_name, result);
                }
            }
        }
    }

    close(fd);
    LOG_INFO("MBR/VBR audit complete for %s: %d sectors scanned, %d threats detected",
             block_dev, result->sectors_scanned, result->threats_detected);
    return BOOTO_OK;
}
