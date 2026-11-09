#ifndef FIMS_CONFIG_H
#define FIMS_CONFIG_H

#include "../include/fims.h"

/**
 * Initialize configuration structure with secure defaults.
 * Uses absolute paths (/var/lib/fims, /var/log/fims, /etc/fims) with automatic
 * non-root fallback to ~/.local/state/fims and ~/.config/fims.
 * Supports environment variable overrides (FIMS_BASELINE_FILE / FIMS_BASELINE_PATH, etc.).
 */
void fims_config_init_defaults(fims_config_t *cfg);

/**
 * Load configuration from a key=value file if present.
 * Verifies security permissions: rejects files not owned by current user or root,
 * or files that are group/world-writable (mode & 0022).
 * Returns FIMS_OK on success, FIMS_ERR_NOT_FOUND if file does not exist,
 * or FIMS_ERR_PERMISSION on security validation failure.
 */
fims_status_t fims_config_load(fims_config_t *cfg, const char *config_path);

/**
 * Save current configuration to disk with restrictive permissions (0600).
 * Persists all configuration options including state_file, follow_symlinks,
 * min_alert_severity, alert_threshold, and exclude_glob.
 */
fims_status_t fims_config_save(const fims_config_t *cfg, const char *config_path);

/**
 * Add a monitored directory to configuration (normalizes path and prevents duplicates).
 */
fims_status_t fims_config_add_dir(fims_config_t *cfg, const char *dir_path);

/**
 * Add an excluded path exact path or directory prefix to configuration.
 */
fims_status_t fims_config_add_exclude(fims_config_t *cfg, const char *exclude_path);

/**
 * Add an explicit glob pattern exclusion rule to configuration.
 */
fims_status_t fims_config_add_exclude_glob(fims_config_t *cfg, const char *pattern);

/**
 * Check if a given path matches any configured exclusion rule.
 * Excludes only exact absolute paths or directory prefixes matching on a '/' boundary,
 * or explicit exclude_glob patterns. Basename matching is not used for default exclusions.
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

/**
 * Validate file ownership and permissions.
 * Refuses files not owned by current user or root, or with group/world-writable bits set.
 */
fims_status_t fims_check_file_security(const char *path);

#endif /* FIMS_CONFIG_H */
