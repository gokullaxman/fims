#ifndef FIMS_LOGGER_H
#define FIMS_LOGGER_H

#include "../include/fims.h"

const char *fims_event_type_str(fims_event_type_t type);
const char *fims_severity_str(fims_severity_t sev);
fims_status_t fims_logger_init(const char *log_path);
fims_status_t fims_logger_init_lazy(const char *log_path);
fims_status_t fims_log_alert(const char *log_path, const fims_alert_t *alert, bool print_stdout);
fims_status_t fims_log_message(const char *log_path, fims_severity_t severity, const char *fmt, ...);

#endif /* FIMS_LOGGER_H */
