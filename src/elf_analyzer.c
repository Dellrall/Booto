/**
 * @file elf_analyzer.c
 * @brief Defensive 64-bit ELF binary and kernel module parser.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "elf_analyzer.h"
#include "crypto_utils.h"
#include "logger.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

booto_error_t elf_parse_buffer(const uint8_t *buf, size_t len, elf_binary_info_t *info) {
    if (!buf || !info) return BOOTO_ERR_INVALID_ARG;
    if (len < sizeof(Elf64_Ehdr)) return BOOTO_ERR_CORRUPT_DATA;

    memset(info, 0, sizeof(*info));
    sha256_buffer_hex(buf, len, info->sha256);

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buf;

    // 1. Verify Magic
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return BOOTO_ERR_CORRUPT_DATA;
    }

    info->is_64bit = (ehdr->e_ident[EI_CLASS] == ELFCLASS64);
    if (!info->is_64bit) {
        LOG_WARN("32-bit ELF binary detected (only ELF64 deep parsing supported)");
        return BOOTO_OK;
    }

    info->is_little_endian = (ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
    info->machine_type = ehdr->e_machine;
    info->elf_type = ehdr->e_type;
    info->entry_point = ehdr->e_entry;

    // 2. Validate Section Headers Bounds
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        return BOOTO_OK; // No section headers (stripped)
    }

    uint64_t sh_total_size = (uint64_t)ehdr->e_shnum * (uint64_t)sizeof(Elf64_Shdr);
    if (ehdr->e_shoff + sh_total_size > len) {
        LOG_ERROR("ELF Section headers exceed file bounds");
        return BOOTO_ERR_CORRUPT_DATA;
    }

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + ehdr->e_shoff);

    // 3. Extract Section Header String Table (.shstrtab)
    const char *shstrtab = NULL;
    size_t shstrtab_size = 0;
    if (ehdr->e_shstrndx < ehdr->e_shnum) {
        const Elf64_Shdr *shstr_hdr = &shdrs[ehdr->e_shstrndx];
        if (shstr_hdr->sh_offset + shstr_hdr->sh_size <= len) {
            shstrtab = (const char *)(buf + shstr_hdr->sh_offset);
            shstrtab_size = shstr_hdr->sh_size;
        }
    }

    // 4. Record Section Headers
    info->section_count = (ehdr->e_shnum > MAX_ELF_SECTIONS) ? MAX_ELF_SECTIONS : (int)ehdr->e_shnum;

    const Elf64_Shdr *symtab_hdr = NULL;
    const Elf64_Shdr *strtab_hdr = NULL;
    const Elf64_Shdr *modinfo_hdr = NULL;

    for (int i = 0; i < info->section_count; i++) {
        const Elf64_Shdr *sh = &shdrs[i];
        elf_section_info_t *sec = &info->sections[i];

        sec->type = sh->sh_type;
        sec->flags = sh->sh_flags;
        sec->offset = sh->sh_offset;
        sec->size = sh->sh_size;
        sec->addr = sh->sh_addr;

        if (shstrtab && sh->sh_name < shstrtab_size) {
            snprintf(sec->name, sizeof(sec->name), "%s", shstrtab + sh->sh_name);
        } else {
            snprintf(sec->name, sizeof(sec->name), "section_%d", i);
        }

        if (sh->sh_type == SHT_SYMTAB) {
            symtab_hdr = sh;
        } else if (sh->sh_type == SHT_STRTAB && strcmp(sec->name, ".strtab") == 0) {
            strtab_hdr = sh;
        } else if (strcmp(sec->name, ".modinfo") == 0) {
            modinfo_hdr = sh;
        }
    }

    // 5. Parse .modinfo (for Linux .ko kernel modules)
    if (modinfo_hdr && modinfo_hdr->sh_offset + modinfo_hdr->sh_size <= len) {
        info->modinfo.has_modinfo = true;
        const char *mptr = (const char *)(buf + modinfo_hdr->sh_offset);
        const char *mend = mptr + modinfo_hdr->sh_size;

        while (mptr < mend) {
            size_t slen = strlen(mptr);
            if (strncmp(mptr, "license=", 8) == 0) {
                snprintf(info->modinfo.license, sizeof(info->modinfo.license), "%s", mptr + 8);
            } else if (strncmp(mptr, "author=", 7) == 0) {
                snprintf(info->modinfo.author, sizeof(info->modinfo.author), "%s", mptr + 7);
            } else if (strncmp(mptr, "description=", 12) == 0) {
                snprintf(info->modinfo.description, sizeof(info->modinfo.description), "%s", mptr + 12);
            } else if (strncmp(mptr, "vermagic=", 9) == 0) {
                snprintf(info->modinfo.vermagic, sizeof(info->modinfo.vermagic), "%s", mptr + 9);
            } else if (strncmp(mptr, "srcversion=", 11) == 0) {
                snprintf(info->modinfo.srcversion, sizeof(info->modinfo.srcversion), "%s", mptr + 11);
            } else if (strncmp(mptr, "depends=", 8) == 0) {
                snprintf(info->modinfo.depends, sizeof(info->modinfo.depends), "%s", mptr + 8);
            }
            mptr += slen + 1;
        }
    }

    // 6. Parse Symbol Table (.symtab + .strtab)
    if (symtab_hdr && strtab_hdr &&
        symtab_hdr->sh_offset + symtab_hdr->sh_size <= len &&
        strtab_hdr->sh_offset + strtab_hdr->sh_size <= len) {

        const Elf64_Sym *syms = (const Elf64_Sym *)(buf + symtab_hdr->sh_offset);
        const char *strtab = (const char *)(buf + strtab_hdr->sh_offset);
        size_t strtab_sz = strtab_hdr->sh_size;
        int total_syms = (int)(symtab_hdr->sh_size / sizeof(Elf64_Sym));

        info->symbol_count = (total_syms > MAX_ELF_SYMBOLS) ? MAX_ELF_SYMBOLS : total_syms;
        info->symbols = (elf_symbol_info_t *)calloc((size_t)info->symbol_count, sizeof(elf_symbol_info_t));

        if (info->symbols) {
            for (int i = 0; i < info->symbol_count; i++) {
                const Elf64_Sym *s = &syms[i];
                elf_symbol_info_t *si = &info->symbols[i];

                si->value = s->st_value;
                si->size = s->st_size;
                si->type = ELF64_ST_TYPE(s->st_info);
                si->bind = ELF64_ST_BIND(s->st_info);
                si->shndx = s->st_shndx;

                if (s->st_name < strtab_sz) {
                    snprintf(si->name, sizeof(si->name), "%s", strtab + s->st_name);
                } else {
                    snprintf(si->name, sizeof(si->name), "sym_%d", i);
                }
            }
        }
    }

    return BOOTO_OK;
}

booto_error_t elf_parse_file(const char *path, elf_binary_info_t *info) {
    if (!path || !info) return BOOTO_ERR_INVALID_ARG;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERROR("Failed to open binary file '%s'", path);
        return BOOTO_ERR_IO;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 100 * 1024 * 1024) { // Max 100 MB per binary
        fclose(fp);
        return BOOTO_ERR_CORRUPT_DATA;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf) {
        fclose(fp);
        return BOOTO_ERR_OUT_OF_MEMORY;
    }

    size_t read_bytes = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);

    if (read_bytes != (size_t)fsize) {
        free(buf);
        return BOOTO_ERR_IO;
    }

    booto_error_t ret = elf_parse_buffer(buf, (size_t)fsize, info);
    snprintf(info->file_path, sizeof(info->file_path), "%s", path);
    free(buf);

    return ret;
}

const elf_symbol_info_t *elf_find_symbol(const elf_binary_info_t *info, const char *name) {
    if (!info || !info->symbols || !name) return NULL;

    for (int i = 0; i < info->symbol_count; i++) {
        if (strcmp(info->symbols[i].name, name) == 0) {
            return &info->symbols[i];
        }
    }
    return NULL;
}

void elf_free_info(elf_binary_info_t *info) {
    if (!info) return;
    if (info->symbols) {
        free(info->symbols);
        info->symbols = NULL;
    }
    info->symbol_count = 0;
}
