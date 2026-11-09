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
 *
 * Hardening & TOCTOU protection (Item 12):
 * - Opens file with O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK.
 * - Performs fstat on the open descriptor, eliminating TOCTOU race conditions.
 * - Rejects FIFOs, sockets, character devices cleanly without blocking.
 *
 * Unreadable file support (Item 10):
 * - If open fails with EACCES / EPERM, gathers metadata via lstat, sets unreadable=true,
 *   empty sha256 (""), and returns FIMS_OK to preserve the record in the list.
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
 * - Enforces FIMS_MAX_SCAN_DEPTH (128) and logs a SEV_HIGH warning when reached (Item 13).
 * - Treats missing (ENOENT), unreadable (EACCES), or non-directory roots gracefully as
 *   empty roots rather than aborting (Item 7).
 */
fims_status_t fims_scan_directory(const char *dir_path, const fims_config_t *cfg, fims_file_list_t *out_list);

/**
 * Scan multiple root directories listed in `dirs` (count `dir_count`) and sort the result.
 */
fims_status_t fims_scan_directories(const char dirs[][FIMS_MAX_PATH], size_t dir_count,
                                    const fims_config_t *cfg, fims_file_list_t *out_list);

/**
 * Query the count of missing, unreadable, or non-directory roots encountered during scans (Item 7).
 */
size_t fims_scanner_get_missing_root_count(void);

/**
 * Reset the missing/unreadable root counter to 0.
 */
void fims_scanner_reset_missing_root_count(void);

/**
 * Query the count of times directory scan recursion reached FIMS_MAX_SCAN_DEPTH (Item 13).
 */
size_t fims_scanner_get_depth_limit_reached_count(void);

/**
 * Reset the depth limit hit counter to 0.
 */
void fims_scanner_reset_depth_limit_reached_count(void);

#endif /* FIMS_SCANNER_H */
