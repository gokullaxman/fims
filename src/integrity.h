#ifndef FIMS_INTEGRITY_H
#define FIMS_INTEGRITY_H

#include "../include/fims.h"

/**
 * Initialize an empty `fims_report_t` structure.
 */
fims_status_t fims_report_init(fims_report_t *rep);

/**
 * Free all dynamically allocated memory in a `fims_report_t`.
 */
void fims_report_free(fims_report_t *rep);

/**
 * Append a single `fims_alert_t` to a `fims_report_t`.
 */
fims_status_t fims_report_add_alert(fims_report_t *rep, const fims_alert_t *alert);

/**
 * Compare a single baseline file record against a current file record and return
 * the bitmask of detected changes (FIMS_FLAG_FILE_MODIFIED, FIMS_FLAG_PERMISSION_CHANGED,
 * FIMS_FLAG_SIZE_CHANGED, FIMS_FLAG_METADATA_CHANGED).
 * Returns FIMS_FLAG_NONE (0) if the file is completely unchanged.
 */
uint32_t fims_compare_records(const fims_file_record_t *base, const fims_file_record_t *curr);

/**
 * Compare the full current scanned file list against the trusted baseline list.
 * Populates `out_report` with all detected alerts, logs them via the logger engine,
 * and optionally prints `[ALERT] <EVENT>: <PATH>` lines to stdout.
 */
fims_status_t fims_check_integrity(const fims_file_list_t *baseline,
                                   const fims_file_list_t *current,
                                   const fims_config_t *cfg,
                                   bool print_alerts,
                                   fims_report_t *out_report);

/**
 * Save a completed integrity scan report to disk (`report_path`) so `fims report`
 * and `fims status` can display the results of the most recent scan.
 */
fims_status_t fims_report_save(const char *report_path, const fims_report_t *rep);

/**
 * Display the saved integrity scan report (`report_path`) to stdout.
 */
fims_status_t fims_report_display(const char *report_path);

#endif /* FIMS_INTEGRITY_H */
