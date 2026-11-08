#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void ensure_parent_dir(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    strncpy(tmp, file_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        /* Create parent directory with 0700 restrictive permissions */
        mkdir(tmp, 0700);
    }
}

const char *fims_event_type_str(fims_event_type_t type) {
    switch (type) {
        case EVENT_FILE_ADDED:         return "FILE_ADDED";
        case EVENT_FILE_MODIFIED:      return "FILE_MODIFIED";
        case EVENT_FILE_DELETED:      return "FILE_DELETED";
        case EVENT_FILE_RENAMED:      return "FILE_RENAMED";
        case EVENT_PERMISSION_CHANGED: return "PERMISSION_CHANGED";
        case EVENT_SIZE_CHANGED:       return "SIZE_CHANGED";
        case EVENT_METADATA_CHANGED:   return "METADATA_CHANGED";
        default:                       return "NONE";
    }
}

const char *fims_severity_str(fims_severity_t sev) {
    switch (sev) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
        default:           return "UNKNOWN";
    }
}

fims_status_t fims_logger_init(const char *log_path) {
    if (!log_path || log_path[0] == '\0') return FIMS_ERR_INVALID_ARG;

    pthread_mutex_lock(&g_log_mutex);
    ensure_parent_dir(log_path);

    /* Security-critical: Open with O_NOFOLLOW to prevent symlink attacks and 0600 permissions */
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        pthread_mutex_unlock(&g_log_mutex);
        return FIMS_ERR_IO;
    }
    (void)fchmod(fd, 0600);
    close(fd);
    pthread_mutex_unlock(&g_log_mutex);
    return FIMS_OK;
}

static void format_iso8601(time_t t, char *buf, size_t sz) {
    struct tm tm_info;
    if (localtime_r(&t, &tm_info) != NULL) {
        strftime(buf, sz, "%Y-%m-%d %H:%M:%S %z", &tm_info);
    } else {
        snprintf(buf, sz, "%lld", (long long)t);
    }
}

fims_status_t fims_log_alert(const char *log_path, const fims_alert_t *alert, bool print_stdout) {
    if (!alert) return FIMS_ERR_INVALID_ARG;

    pthread_mutex_lock(&g_log_mutex);

    if (print_stdout) {
        if (alert->event_type == EVENT_FILE_RENAMED && alert->old_path[0] != '\0') {
            printf("[ALERT] %s: %s -> %s\n",
                   fims_event_type_str(alert->event_type),
                   alert->old_path,
                   alert->path);
        } else {
            printf("[ALERT] %s: %s\n",
                   fims_event_type_str(alert->event_type),
                   alert->path);
        }
        fflush(stdout);
    }

    if (log_path && log_path[0] != '\0') {
        ensure_parent_dir(log_path);
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) {
            (void)fchmod(fd, 0600);
            FILE *fp = fdopen(fd, "a");
            if (fp) {
                char ts_buf[64];
                format_iso8601(alert->timestamp ? alert->timestamp : time(NULL), ts_buf, sizeof(ts_buf));
                fprintf(fp,
                        "[%s] [ALERT] event=%s severity=%s path=\"%s\" prev_hash=%s curr_hash=%s "
                        "prev_size=%llu curr_size=%llu prev_mode=%04o curr_mode=%04o desc=\"%s\"\n",
                        ts_buf,
                        fims_event_type_str(alert->event_type),
                        fims_severity_str(alert->severity),
                        alert->path,
                        alert->prev_hash[0] ? alert->prev_hash : "N/A",
                        alert->curr_hash[0] ? alert->curr_hash : "N/A",
                        (unsigned long long)alert->prev_size,
                        (unsigned long long)alert->curr_size,
                        alert->prev_mode,
                        alert->curr_mode,
                        alert->description);
                fclose(fp);
            } else {
                close(fd);
            }
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
    return FIMS_OK;
}

fims_status_t fims_log_message(const char *log_path, fims_severity_t severity, const char *fmt, ...) {
    if (!log_path || !fmt) return FIMS_ERR_INVALID_ARG;

    pthread_mutex_lock(&g_log_mutex);
    ensure_parent_dir(log_path);

    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        pthread_mutex_unlock(&g_log_mutex);
        return FIMS_ERR_IO;
    }
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "a");
    if (!fp) {
        close(fd);
        pthread_mutex_unlock(&g_log_mutex);
        return FIMS_ERR_IO;
    }

    char ts_buf[64];
    format_iso8601(time(NULL), ts_buf, sizeof(ts_buf));
    fprintf(fp, "[%s] [%s] ", ts_buf, fims_severity_str(severity));

    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);

    fprintf(fp, "\n");
    fclose(fp);
    pthread_mutex_unlock(&g_log_mutex);
    return FIMS_OK;
}
