#ifndef FIMS_LOGGER_H
#define FIMS_LOGGER_H

#include "../include/fims.h"

/**
 * Convert an event type enum to its canonical string identifier
 * (e.g., "FILE_MODIFIED", "FILE_DELETED", "FILE_ADDED", "PERMISSION_CHANGED").
 */
const char *fims_event_type_str(fims_event_type_t type);

/**
 * Convert a severity enum to its canonical string identifier.
 */
const char *fims_severity_str(fims_severity_t sev);

/**
 * Initialize the logging subsystem, ensuring parent directory exists
 * and log file is created with restrictive 0600 permissions.
 */
fims_status_t fims_logger_init(const char *log_path);

/**
 * Emit a structured security alert to the log file and optionally to stdout.
 * Thread-safe via internal pthread mutex.
 */
fims_status_t fims_log_alert(const char *log_path, const fims_alert_t *alert, bool print_stdout);

/**
 * Log an operational message (e.g., baseline initialized, scan started, overflow warning).
 * Thread-safe via internal pthread mutex.
 */
fims_status_t fims_log_message(const char *log_path, fims_severity_t severity, const char *fmt, ...);

#endif /* FIMS_LOGGER_H */
