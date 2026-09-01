/**
 * @file elf_analyzer.h
 * @brief Defensive 64-bit ELF binary and Linux kernel module (.ko) parser.
 */
#ifndef BOOTO_ELF_ANALYZER_H
#define BOOTO_ELF_ANALYZER_H

#include "booto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ELF_SECTIONS 128
#define MAX_ELF_SYMBOLS  2048

typedef struct {
    char name[128];
    uint64_t value;
    uint64_t size;
    uint8_t type;
    uint8_t bind;
    uint16_t shndx;
} elf_symbol_info_t;

typedef struct {
    char name[64];
    uint32_t type;
    uint64_t flags;
    uint64_t offset;
    uint64_t size;
    uint64_t addr;
} elf_section_info_t;

typedef struct {
    char license[64];
    char author[128];
    char description[256];
    char vermagic[128];
    char srcversion[64];
    char depends[256];
    bool has_modinfo;
} elf_modinfo_t;

typedef struct {
    char file_path[256];
    char sha256[65];
    bool is_64bit;
    bool is_little_endian;
    uint16_t machine_type;
    uint16_t elf_type; // 1 = ET_REL (.ko module), 2 = ET_EXEC, 3 = ET_DYN (.so shared object)
    uint64_t entry_point;

    int section_count;
    elf_section_info_t sections[MAX_ELF_SECTIONS];

    int symbol_count;
    elf_symbol_info_t *symbols;

    elf_modinfo_t modinfo;
} elf_binary_info_t;

/**
 * @brief Parse an ELF binary or .ko kernel module from disk.
 * @param path Filepath to the ELF binary.
 * @param info Output structure to fill.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t elf_parse_file(const char *path, elf_binary_info_t *info);

/**
 * @brief Parse an ELF binary from an in-memory buffer.
 * @param buf Pointer to raw ELF file buffer.
 * @param len Total length of buffer.
 * @param info Output structure to fill.
 * @return BOOTO_OK on success, negative error code on failure.
 */
booto_error_t elf_parse_buffer(const uint8_t *buf, size_t len, elf_binary_info_t *info);

/**
 * @brief Search for a specific symbol name in the parsed symbol table.
 * @return Pointer to symbol info, or NULL if not found.
 */
const elf_symbol_info_t *elf_find_symbol(const elf_binary_info_t *info, const char *name);

/**
 * @brief Free allocated symbol tables and internal data.
 */
void elf_free_info(elf_binary_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_ELF_ANALYZER_H */
