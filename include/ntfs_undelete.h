/**
 * @file ntfs_undelete.h
 * @brief Deleted-file recovery from an NTFS volume (--undelete): reads the MFT from the raw device, read-only.
 */
#ifndef BOOTO_NTFS_UNDELETE_H
#define BOOTO_NTFS_UNDELETE_H

#include "booto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NTFS_MAX_RUNS 64
#define NTFS_UNDELETE_MAX_FILE (64u << 20) /**< Larger deleted files are skipped */

typedef struct {
    int64_t lcn;  /**< First cluster; -1 for a sparse run */
    uint64_t len; /**< Clusters */
} ntfs_run_t;

typedef struct {
    bool in_use, is_dir, has_attr_list, has_data, resident;
    char name[96];        /**< Long name from $FILE_NAME, ASCII-sanitized */
    const uint8_t *data;  /**< Resident $DATA value, inside the record buffer */
    uint32_t data_len;
    uint64_t size;        /**< Non-resident real size */
    ntfs_run_t runs[NTFS_MAX_RUNS];
    size_t nruns;
} ntfs_record_t;

typedef struct {
    uint64_t records;   /**< MFT records read */
    uint64_t deleted;   /**< Deleted file records with an unnamed $DATA */
    uint64_t recovered; /**< Written to the output folder */
    uint64_t skipped;   /**< Too large, attribute list, or runs off the volume */
} ntfs_undelete_result_t;

/** Apply update-sequence fixups to @p rec in place and parse it. BOOTO_ERR_CORRUPT_DATA when it is not a valid
 *  FILE record. */
booto_error_t ntfs_parse_record(uint8_t *rec, size_t len, ntfs_record_t *out);

/** Write every deleted file on NTFS device @p dev to new files in @p out_dir as <record>_<name>.recovered (0400).
 *  BOOTO_ERR_NOT_FOUND: @p dev is not NTFS. */
booto_error_t ntfs_undelete(const char *dev, const char *out_dir, ntfs_undelete_result_t *res);

#endif
