/**
 * @file initramfs_auditor.c
 * @brief In-memory CPIO archive unpacker and initramfs script security auditor.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "initramfs_auditor.h"
#include "logger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *pattern;
    const char *threat_name;
    const char *description;
} script_audit_rule_t;

static const script_audit_rule_t G_SCRIPT_RULES[] = {
    { "/dev/tcp/",               "Reverse Shell Payload",           "Network socket redirection (/dev/tcp/) in boot script" },
    { "/dev/udp/",               "Reverse Shell Payload",           "Network socket redirection (/dev/udp/) in boot script" },
    { "bash -i",                 "Interactive Reverse Shell",       "Spawning interactive bash shell in initramfs" },
    { "nc -e",                   "Netcat Backdoor",                 "Netcat executable execution flag in boot script" },
    { "mkfifo /tmp/",            "FIFO Pipe Shell Backdoor",        "Named pipe allocation in temp space for reverse shell" },
    { "curl -s",                 "Silent Remote Payload Fetcher",   "Silent curl invocation during early boot" },
    { "wget -q",                 "Silent Remote Payload Fetcher",   "Silent wget invocation during early boot" },
    { "insmod /dev/shm",         "Ramdisk LKM Injection",           "Direct kernel module loading from shared memory" },
    { "insmod /tmp",             "Temp LKM Injection",              "Direct kernel module loading from temporary directory" },
    { "kexec -l",                "Untrusted Kernel Re-execution",   "kexec dynamic kernel swap during boot sequence" }
};

static const size_t G_SCRIPT_RULES_COUNT = sizeof(G_SCRIPT_RULES) / sizeof(G_SCRIPT_RULES[0]);

static uint32_t parse_hex8(const char *hex) {
    char buf[9];
    memcpy(buf, hex, 8);
    buf[8] = '\0';
    return (uint32_t)strtoul(buf, NULL, 16);
}

static void add_initramfs_threat(initramfs_scan_result_t *result,
                                const char *file_path,
                                const char *threat_name,
                                const char *pattern,
                                uint32_t line_num,
                                const char *description) {
    if (!result || result->threats_detected >= MAX_INITRAMFS_THREATS) return;

    initramfs_finding_t *f = &result->findings[result->threats_detected++];
    snprintf(f->file_path, sizeof(f->file_path), "%s", file_path ? file_path : "");
    snprintf(f->threat_name, sizeof(f->threat_name), "%s", threat_name ? threat_name : "Initramfs Anomaly");
    snprintf(f->matched_pattern, sizeof(f->matched_pattern), "%s", pattern ? pattern : "");
    f->line_number = line_num;
    snprintf(f->description, sizeof(f->description), "%s", description ? description : "");

    LOG_CRITICAL("[INITRAMFS ALERT] %s in %s (Pattern: '%s', Line: %u)",
                 f->threat_name, f->file_path, f->matched_pattern, f->line_number);
}

static void audit_script_content(const char *file_name, const char *content, size_t len, initramfs_scan_result_t *result) {
    result->scripts_audited++;

    const char *ptr = content;
    const char *end = content + len;
    uint32_t line_no = 1;

    while (ptr < end) {
        const char *next = (const char *)memchr(ptr, '\n', (size_t)(end - ptr));
        size_t line_len = next ? (size_t)(next - ptr) : (size_t)(end - ptr);

        if (line_len > 0) {
            char line[1024];
            size_t copy_len = (line_len < sizeof(line) - 1) ? line_len : sizeof(line) - 1;
            memcpy(line, ptr, copy_len);
            line[copy_len] = '\0';

            const char *trimmed = line;
            while (*trimmed && isspace((unsigned char)*trimmed)) trimmed++;
            if (*trimmed != '#') {
                for (size_t r = 0; r < G_SCRIPT_RULES_COUNT; r++) {
                    const script_audit_rule_t *rule = &G_SCRIPT_RULES[r];
                    if (strstr(line, rule->pattern) != NULL) {
                        add_initramfs_threat(result, file_name, rule->threat_name, rule->pattern, line_no, rule->description);
                    }
                }
            }
        }

        if (!next) break;
        ptr = next + 1;
        line_no++;
    }
}

booto_error_t initramfs_audit_buffer(const uint8_t *buf, size_t len, initramfs_scan_result_t *result) {
    if (!buf || !result) return BOOTO_ERR_INVALID_ARG;
    if (len < 110) return BOOTO_ERR_CORRUPT_DATA;

    memset(result, 0, sizeof(*result));

    size_t offset = 0;
    while (offset + 110 <= len) {
        const char *hdr = (const char *)(buf + offset);

        if (memcmp(hdr, "070701", 6) != 0 && memcmp(hdr, "070702", 6) != 0) {
            offset++;
            continue;
        }

        uint32_t namesize = parse_hex8(hdr + 94);
        uint32_t filesize = parse_hex8(hdr + 54);

        if (namesize == 0 || namesize > 1024) {
            offset += 6;
            continue;
        }

        size_t name_offset = offset + 110;
        size_t name_padded = (size_t)(110U + namesize + 3U) & (size_t)(~3U);
        size_t data_offset = offset + name_padded;
        size_t data_padded = (size_t)(filesize + 3U) & (size_t)(~3U);

        if (data_offset + filesize > len) {
            LOG_WARN("Truncated CPIO file entry at offset %zu", offset);
            break;
        }

        char file_name[256];
        size_t copy_name = (namesize < sizeof(file_name)) ? (size_t)namesize : sizeof(file_name) - 1;
        memcpy(file_name, buf + name_offset, copy_name);
        file_name[copy_name] = '\0';

        if (strcmp(file_name, "TRAILER!!!") == 0) {
            offset = data_offset + data_padded;
            continue;
        }

        result->files_extracted++;

        if (strstr(file_name, "init") || strstr(file_name, ".sh") ||
            strstr(file_name, "scripts/") || strstr(file_name, "conf/")) {
            const char *content = (const char *)(buf + data_offset);
            audit_script_content(file_name, content, filesize, result);
        }

        offset = data_offset + data_padded;
    }

    LOG_INFO("Initramfs audit complete: %d files unpacked in RAM, %d scripts analyzed, %d threats found",
             result->files_extracted, result->scripts_audited, result->threats_detected);
    return BOOTO_OK;
}

booto_error_t initramfs_audit_file(const char *initrd_path, initramfs_scan_result_t *result) {
    if (!initrd_path || !result) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Auditing in-memory initramfs image: %s", initrd_path);

    FILE *fp = fopen(initrd_path, "rb");
    if (!fp) return BOOTO_ERR_IO;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 150 * 1024 * 1024) {
        fclose(fp);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }

    size_t r = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);

    if (r != (size_t)fsize) {
        free(buf);
        return BOOTO_ERR_IO;
    }

    booto_error_t ret = initramfs_audit_buffer(buf, (size_t)fsize, result);
    free(buf);
    return ret;
}
