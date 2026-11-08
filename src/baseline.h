#ifndef FIMS_BASELINE_H
#define FIMS_BASELINE_H

#include "../include/fims.h"

/**
 * Save a scanned `fims_file_list_t` as a cryptographically self-verified baseline file.
 *
 * Security features:
 * - Refuses to overwrite an existing baseline unless `allow_overwrite` is true.
 * - Computes a SHA-256 checksum (`BODY_SHA256`) over all serialized record lines
 *   and embeds it in the header so any tampering or corruption of the baseline
 *   file is deterministically detected on load.
 * - Writes to a temporary file with 0600 permissions and atomically renames into place.
 */
fims_status_t fims_baseline_save(const char *baseline_path,
                                 const fims_file_list_t *list,
                                 bool allow_overwrite);

/**
 * Load and cryptographically validate a baseline file into `out_list`.
 * Returns FIMS_ERR_CORRUPT if the magic header, field formatting, record count,
 * or BODY_SHA256 digest does not match.
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

#endif /* FIMS_BASELINE_H */
