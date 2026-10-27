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
#include "disk_mount.h"
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

#define CPIO_HDR_LEN        110U
#define CPIO_MAX_SEGMENTS   64
#define CPIO_MAX_DECOMP_DEPTH 2
#define INITRD_DECOMP_CAP   ((size_t)1024 * 1024 * 1024)

typedef struct {
    uint8_t magic[6];
    size_t magic_len;
    const char *name;
    const char *argv[5];
} initrd_codec_t;

static const initrd_codec_t G_CODECS[] = {
    { {0x1f, 0x8b},                         2, "gzip",  {"gzip", "-dc", "-", NULL, NULL} },
    { {0x28, 0xb5, 0x2f, 0xfd},             4, "zstd",  {"zstd", "-dc", "-", NULL, NULL} },
    { {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, 6, "xz",    {"xz", "-dc", "-", NULL, NULL} },
    { {0x5d, 0x00, 0x00},                   3, "lzma",  {"xz", "--format=lzma", "-dc", "-", NULL} },
    { {0x02, 0x21, 0x4c, 0x18},             4, "lz4",   {"lz4", "-dc", "-", NULL, NULL} },
    { {0x42, 0x5a, 0x68},                   3, "bzip2", {"bzip2", "-dc", "-", NULL, NULL} }
};

/* Strict newc field: exactly 8 hex digits, nothing else. */
static bool parse_hex8(const char *hex, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 8; i++) {
        char c = hex[i];
        uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return false;
        v = (v << 4) | d;
    }
    *out = v;
    return true;
}

static bool mem_contains(const char *hay, size_t hay_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hay_len) return false;
    const char *last = hay + (hay_len - nlen);
    for (const char *p = hay; p <= last; p++) {
        p = (const char *)memchr(p, needle[0], (size_t)(last - p) + 1);
        if (!p) return false;
        if (memcmp(p, needle, nlen) == 0) return true;
    }
    return false;
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

    // Lines are matched in full (no fixed-size copy), so padding cannot push a pattern out of view.
    while (ptr < end) {
        const char *next = (const char *)memchr(ptr, '\n', (size_t)(end - ptr));
        size_t line_len = next ? (size_t)(next - ptr) : (size_t)(end - ptr);

        size_t lead = 0;
        while (lead < line_len && isspace((unsigned char)ptr[lead])) lead++;
        if (lead < line_len && ptr[lead] != '#') {
            for (size_t r = 0; r < G_SCRIPT_RULES_COUNT; r++) {
                const script_audit_rule_t *rule = &G_SCRIPT_RULES[r];
                if (mem_contains(ptr, line_len, rule->pattern)) {
                    add_initramfs_threat(result, file_name, rule->threat_name, rule->pattern, line_no, rule->description);
                }
            }
        }

        if (!next) break;
        ptr = next + 1;
        line_no++;
    }
}

static size_t align4(size_t v) {
    return (v + 3U) & ~(size_t)3U;
}

/* Parse one newc archive starting at buf up to and including TRAILER!!!; *consumed gets its padded length. */
static booto_error_t parse_cpio_archive(const uint8_t *buf, size_t len, size_t base, initramfs_scan_result_t *result, size_t *consumed) {
    size_t off = 0;
    for (;;) {
        if (len - off < CPIO_HDR_LEN) {
            LOG_ERROR("Truncated CPIO archive (no TRAILER!!!) at offset %zu", base + off);
            return BOOTO_ERR_CORRUPT_DATA;
        }
        const char *hdr = (const char *)(buf + off);
        if (memcmp(hdr, "070701", 6) != 0 && memcmp(hdr, "070702", 6) != 0) {
            LOG_ERROR("Invalid CPIO header magic at offset %zu", base + off);
            return BOOTO_ERR_CORRUPT_DATA;
        }

        uint32_t fields[13];
        for (int i = 0; i < 13; i++) {
            if (!parse_hex8(hdr + 6 + 8 * i, &fields[i])) {
                LOG_ERROR("Malformed CPIO header field at offset %zu", base + off);
                return BOOTO_ERR_CORRUPT_DATA;
            }
        }
        uint32_t filesize = fields[6];
        uint32_t namesize = fields[11];

        size_t avail = len - off - CPIO_HDR_LEN;
        if (namesize == 0 || namesize > avail || hdr[(size_t)CPIO_HDR_LEN + namesize - 1] != '\0') {
            LOG_ERROR("Invalid CPIO name field at offset %zu", base + off);
            return BOOTO_ERR_CORRUPT_DATA;
        }
        const char *file_name = hdr + CPIO_HDR_LEN;

        size_t data_offset = align4(off + CPIO_HDR_LEN + namesize);
        if (data_offset > len || filesize > len - data_offset) {
            LOG_ERROR("Truncated CPIO file entry '%s' at offset %zu", file_name, base + off);
            return BOOTO_ERR_CORRUPT_DATA;
        }
        size_t next = align4(data_offset + filesize);
        if (next > len) next = len;

        if (strcmp(file_name, "TRAILER!!!") == 0) {
            *consumed = next;
            return BOOTO_OK;
        }

        result->files_extracted++;

        if (strstr(file_name, "init") || strstr(file_name, ".sh") ||
            strstr(file_name, "scripts/") || strstr(file_name, "conf/")) {
            audit_script_content(file_name, (const char *)(buf + data_offset), filesize, result);
        }

        off = next;
    }
}

/* Walk concatenated segments: newc archives, zero padding, and a trailing compressed archive (as the kernel does). */
static booto_error_t audit_segments(const uint8_t *buf, size_t len, int depth, initramfs_scan_result_t *result) {
    size_t off = 0;
    while (off < len) {
        if (buf[off] == 0) {
            off++;
            continue;
        }

        if (len - off >= 6 && (memcmp(buf + off, "070701", 6) == 0 || memcmp(buf + off, "070702", 6) == 0)) {
            if ((off & 3U) != 0) {
                LOG_ERROR("Misaligned CPIO archive at offset %zu", off);
                return BOOTO_ERR_CORRUPT_DATA;
            }
            if (result->segments_parsed >= CPIO_MAX_SEGMENTS) {
                LOG_ERROR("Initramfs exceeds %d CPIO segments", CPIO_MAX_SEGMENTS);
                return BOOTO_ERR_CORRUPT_DATA;
            }
            size_t consumed = 0;
            booto_error_t err = parse_cpio_archive(buf + off, len - off, off, result, &consumed);
            if (err != BOOTO_OK) return err;
            result->segments_parsed++;
            off += consumed;
            continue;
        }

        const initrd_codec_t *codec = NULL;
        for (size_t c = 0; c < sizeof(G_CODECS) / sizeof(G_CODECS[0]); c++) {
            if (len - off >= G_CODECS[c].magic_len && memcmp(buf + off, G_CODECS[c].magic, G_CODECS[c].magic_len) == 0) {
                codec = &G_CODECS[c];
                break;
            }
        }
        if (!codec) {
            LOG_ERROR("Unrecognised initramfs data at offset %zu (neither CPIO nor known compression)", off);
            return BOOTO_ERR_CORRUPT_DATA;
        }
        if (depth >= CPIO_MAX_DECOMP_DEPTH) {
            LOG_ERROR("Initramfs compression nesting exceeds %d levels", CPIO_MAX_DECOMP_DEPTH);
            return BOOTO_ERR_CORRUPT_DATA;
        }

        // shortcut: the decompressor consumes the whole remainder, so segments after a compressed one are not split out; upgrade if such images appear.
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        booto_error_t err = disk_exec_capture(codec->argv, buf + off, len - off, &plain, &plain_len, INITRD_DECOMP_CAP);
        if (err == BOOTO_ERR_NOT_FOUND) {
            LOG_ERROR("Decompressor '%s' not available; cannot audit %s-compressed initramfs segment", codec->argv[0], codec->name);
            return err;
        }
        if (err != BOOTO_OK) {
            LOG_ERROR("Failed to decompress %s initramfs segment at offset %zu (err: %d)", codec->name, off, err);
            return err;
        }
        snprintf(result->compression, sizeof(result->compression), "%s", codec->name);
        err = audit_segments(plain, plain_len, depth + 1, result);
        free(plain);
        return err;
    }
    return BOOTO_OK;
}

booto_error_t initramfs_audit_buffer(const uint8_t *buf, size_t len, initramfs_scan_result_t *result) {
    if (!buf || !result) return BOOTO_ERR_INVALID_ARG;

    memset(result, 0, sizeof(*result));
    snprintf(result->compression, sizeof(result->compression), "none");

    booto_error_t err = audit_segments(buf, len, 0, result);
    if (err != BOOTO_OK) return err;
    if (result->segments_parsed == 0) {
        LOG_ERROR("Initramfs image contains no CPIO archive");
        return BOOTO_ERR_CORRUPT_DATA;
    }

    LOG_INFO("Initramfs audit complete: %d CPIO segments (compression: %s), %d files unpacked in RAM, %d scripts analyzed, %d threats found",
             result->segments_parsed, result->compression, result->files_extracted, result->scripts_audited, result->threats_detected);
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
