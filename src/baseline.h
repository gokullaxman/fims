#ifndef FIMS_BASELINE_H
#define FIMS_BASELINE_H

#include "../include/fims.h"

/**
 * Save a scanned `fims_file_list_t` as a cryptographically self-verified baseline file.
 *
 * Security features:
 * - Refuses to overwrite an existing baseline unless `allow_overwrite` is true, using
 *   atomic link semantics (O_EXCL / link) to prevent TOCTOU races.
 * - Computes a cryptographic checksum (HMAC-SHA256 if FIMS_HMAC_KEY_FILE is set,
 *   otherwise SHA-256) over all header lines (MAGIC, CREATED_AT, RECORD_COUNT, ROOT_DIRs)
 *   and all serialized record lines so any tampering or corruption is deterministically
 *   detected on load.
 * - Writes to a temporary file with restrictive 0600 permissions, fsyncs data, atomically
 *   replaces into place, and fsyncs the parent directory descriptor to guarantee disk durability.
 * - On any error, temporary files are cleanly unlinked and the original baseline is untouched.
 */
fims_status_t fims_baseline_save(const char *baseline_path,
                                 const fims_file_list_t *list,
                                 bool allow_overwrite);

/**
 * Load and cryptographically validate a baseline file into `out_list`.
 * Returns FIMS_ERR_CORRUPT if the magic header, field formatting, record count,
 * ROOT_DIR lines, CREATED_AT, or checksum/HMAC digest does not match.
 * If FIMS_HMAC_KEY_FILE is configured, the baseline MUST contain a valid HMAC matching
 * the key file, or FIMS_ERR_CORRUPT is returned.
 */
fims_status_t fims_baseline_load(const char *baseline_path, fims_file_list_t *out_list);

/**
 * Validate a baseline file without keeping the records in memory.
 */
fims_status_t fims_baseline_validate(const char *baseline_path);

/**
 * Create a new baseline by scanning `dir_path` and saving to `cfg->baseline_file`.
 */
fims_status_t fims_baseline_init_from_dir(const char *dir_path,
                                          fims_config_t *cfg,
                                          bool allow_overwrite,
                                          size_t *out_file_count);

/**
 * Display human-readable baseline metadata and records to stdout.
 */
fims_status_t fims_baseline_show(const char *baseline_path);

/**
 * Add a root directory string to a file list if not already present.
 */
fims_status_t fims_baseline_add_root_dir(fims_file_list_t *list, const char *root_dir);

/**
 * Append an additional root directory to an existing baseline file without wiping
 * existing roots or records.
 *
 * Scans `new_dir_path`, merges any newly discovered files into the baseline records,
 * preserves existing roots and records, and atomically saves the updated baseline.
 */
fims_status_t fims_baseline_add_root(const char *baseline_path,
                                     const char *new_dir_path,
                                     fims_config_t *cfg);

#endif /* FIMS_BASELINE_H */
