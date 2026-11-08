#ifndef FIMS_CONFIG_H
#define FIMS_CONFIG_H

#include "../include/fims.h"

/**
 * Initialize configuration structure with secure defaults.
 * Checks environment variables FIMS_BASELINE_PATH, FIMS_LOG_PATH, FIMS_CONFIG_PATH
 * to support isolated testing and custom deployments.
 */
void fims_config_init_defaults(fims_config_t *cfg);

/**
 * Load configuration from a key=value file if present.
 * Returns FIMS_OK on success or FIMS_ERR_NOT_FOUND if file does not exist.
 */
fims_status_t fims_config_load(fims_config_t *cfg, const char *config_path);

/**
 * Save current configuration to disk with restrictive permissions (0600).
 */
fims_status_t fims_config_save(const fims_config_t *cfg, const char *config_path);

/**
 * Add a monitored directory to configuration (normalizes path and prevents duplicates).
 */
fims_status_t fims_config_add_dir(fims_config_t *cfg, const char *dir_path);

/**
 * Add an excluded path pattern/prefix to configuration.
 */
fims_status_t fims_config_add_exclude(fims_config_t *cfg, const char *exclude_path);

/**
 * Check if a given path matches any configured exclusion rule.
 */
bool fims_config_is_excluded(const fims_config_t *cfg, const char *path);

/**
 * Display human-readable configuration to stdout.
 */
void fims_config_print(const fims_config_t *cfg);

/**
 * Validate and normalize a filesystem path, rejecting path traversal ("..") sequences
 * or malformed inputs.
 */
fims_status_t fims_sanitize_path(const char *input_path, char *out_path, size_t out_size);

#endif /* FIMS_CONFIG_H */
