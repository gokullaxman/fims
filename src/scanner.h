#ifndef FIMS_SCANNER_H
#define FIMS_SCANNER_H

#include "../include/fims.h"

/**
 * Initialize an empty fims_file_list_t structure.
 */
fims_status_t fims_file_list_init(fims_file_list_t *list);

/**
 * Free all dynamically allocated memory inside a fims_file_list_t.
 */
void fims_file_list_free(fims_file_list_t *list);

/**
 * Append a file record to a fims_file_list_t, growing capacity as needed.
 */
fims_status_t fims_file_list_append(fims_file_list_t *list, const fims_file_record_t *rec);

/**
 * Sort file records in ascending lexicographical order by path.
 */
void fims_file_list_sort(fims_file_list_t *list);

/**
 * Inspect and hash a single regular file at `file_path`, populating `out_rec`.
 */
fims_status_t fims_scan_single_file(const char *file_path, fims_file_record_t *out_rec);

/**
 * Recursively scan a directory tree and append all regular files (with SHA-256 hashes
 * and POSIX metadata) into `out_list`.
 *
 * Security & Robustness features:
 * - Uses lstat() to detect symbolic links without dereferencing them, avoiding symlink
 *   infinite loops and directory traversal traps.
 * - Tracks visited directory (dev, inode) pairs up to depth 128 as an extra guard
 *   against bind-mount or filesystem cycles.
 * - Gracefully logs and skips inaccessible files/subdirectories (EACCES/EPERM)
 *   without aborting the scan.
 */
fims_status_t fims_scan_directory(const char *dir_path, const fims_config_t *cfg, fims_file_list_t *out_list);

/**
 * Scan multiple root directories listed in `dirs` (count `dir_count`) and sort the result.
 */
fims_status_t fims_scan_directories(const char dirs[][FIMS_MAX_PATH], size_t dir_count,
                                    const fims_config_t *cfg, fims_file_list_t *out_list);

#endif /* FIMS_SCANNER_H */
