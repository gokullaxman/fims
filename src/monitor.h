#ifndef FIMS_MONITOR_H
#define FIMS_MONITOR_H

#include "../include/fims.h"

/**
 * Runtime statistics for the real-time monitor and status reporting.
 */
typedef struct {
    time_t   started_at;
    time_t   last_full_scan_at;
    size_t   active_watches;
    size_t   realtime_events_processed;
    size_t   realtime_alerts_emitted;
    size_t   overflow_recoveries;
    size_t   periodic_scans_completed;
    size_t   watch_failures;              /* Item 13: inotify watch failure counter */
    bool     monitor_active;
} fims_monitor_stats_t;

/**
 * Request the running real-time monitor loop to stop gracefully.
 * Safe to call from a signal handler or another thread.
 */
void fims_monitor_request_stop(void);

/**
 * Reset the stop flag before starting a new monitoring session.
 */
void fims_monitor_reset_stop(void);

/**
 * Start real-time filesystem integrity monitoring using Linux `inotify`
 * combined with a background `pthread` periodic consistency scan thread.
 *
 * @param cfg          Active FIMS configuration (paths, scan interval, exclusions).
 * @param max_seconds  If > 0, automatically stop monitoring after `max_seconds`
 *                     (useful for bounded demonstrations and automated tests).
 *                     If 0, run continuously until SIGINT/SIGTERM or fims_monitor_request_stop().
 * @return FIMS_OK on clean shutdown, or an error status code.
 */
fims_status_t fims_monitor_run(const fims_config_t *cfg, uint32_t max_seconds);

/**
 * Save current monitoring/scan status statistics to `state_path`.
 */
fims_status_t fims_status_save(const char *state_path,
                               const fims_config_t *cfg,
                               const fims_monitor_stats_t *stats,
                               size_t baseline_files,
                               size_t last_alert_count);

/**
 * Display comprehensive monitoring status and statistics (`fims status`).
 */
fims_status_t fims_status_display(const fims_config_t *cfg);

#endif /* FIMS_MONITOR_H */
