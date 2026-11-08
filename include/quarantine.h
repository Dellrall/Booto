/**
 * @file quarantine.h
 * @brief Exports flagged files into a password-protected ZIP so they can be analysed elsewhere without running.
 *
 * Industry convention: stored (uncompressed) entries, ZipCrypto, password "infected". The password only stops
 * antivirus from deleting the samples and stops a file manager from opening them by accident; it is not secrecy.
 * Each entry ends in ".malware" and is stored with mode 0400; the finished ZIP itself is 0400.
 */
#ifndef BOOTO_QUARANTINE_H
#define BOOTO_QUARANTINE_H

#include "booto.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUARANTINE_PASSWORD  "infected"
#define QUARANTINE_MAX_ITEM  (512ull * 1024 * 1024)  /* larger files are truncated to this many bytes */
#define QUARANTINE_MAX_FILES 320

typedef struct quarantine quarantine_t;

/* dir must already exist; the ZIP is created there on the first successful add. NULL on out of memory. */
quarantine_t *quarantine_open(const char *dir);

/* Adds up to max_bytes of path as "<prefix>/<name>.malware".
 * root non-NULL: path must resolve (symlinks followed) inside root, and name is the path relative to root;
 * root NULL: name is the basename (used for raw devices). The same name is added once; repeats return BOOTO_OK.
 * Returns BOOTO_ERR_PERMISSION_DENIED when path escapes root, BOOTO_ERR_IO on read/write failure. */
booto_error_t quarantine_add(quarantine_t *q, const char *prefix, const char *root, const char *path, uint64_t max_bytes);

/* Writes the ZIP directory, makes the file 0400 and frees q. zip_path receives the ZIP's path, or "" when nothing
 * was added. Returns the number of files exported, or -1 when the ZIP could not be finished. */
int quarantine_close(quarantine_t *q, char *zip_path, size_t zip_path_len);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_QUARANTINE_H */
