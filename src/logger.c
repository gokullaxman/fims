#include "logger.h"
#include "escape.h"

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

fims_status_t fims_logger_init_lazy(const char *log_path) {
    if (!log_path || log_path[0] == '\0') return FIMS_ERR_INVALID_ARG;
    return FIMS_OK;
}

fims_status_t fims_logger_init(const char *log_path) {
    return fims_logger_init_lazy(log_path);
}

static void format_iso8601(time_t t, char *buf, size_t sz) {
    struct tm tm_info;
    if (localtime_r(&t, &tm_info) != NULL) {
        strftime(buf, sz, "%Y-%m-%d %H:%M:%S %z", &tm_info);
    } else {
        snprintf(buf, sz, "%lld", (long long)t);
    }
}

static char *escape_alloc(const char *str) {
    if (!str) {
        char *empty = (char *)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    size_t needed = fims_escape_for_log(str, NULL, 0) + 1;
    char *buf = (char *)malloc(needed);
    if (buf) {
        fims_escape_for_log(str, buf, needed);
    }
    return buf;
}

fims_status_t fims_log_alert(const char *log_path, const fims_alert_t *alert, bool print_stdout) {
    if (!alert) return FIMS_ERR_INVALID_ARG;

    pthread_mutex_lock(&g_log_mutex);

    char *esc_path = escape_alloc(alert->path);
    char *esc_old_path = escape_alloc(alert->old_path);
    char *esc_desc = escape_alloc(alert->description);

    const char *safe_path = esc_path ? esc_path : alert->path;
    const char *safe_old_path = esc_old_path ? esc_old_path : alert->old_path;
    const char *safe_desc = esc_desc ? esc_desc : alert->description;

    if (print_stdout) {
        if (alert->event_type == EVENT_FILE_RENAMED && safe_old_path[0] != '\0') {
            printf("[ALERT] %s: %s -> %s\n",
                   fims_event_type_str(alert->event_type),
                   safe_old_path,
                   safe_path);
        } else {
            printf("[ALERT] %s: %s\n",
                   fims_event_type_str(alert->event_type),
                   safe_path);
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
                        safe_path,
                        alert->prev_hash[0] ? alert->prev_hash : "N/A",
                        alert->curr_hash[0] ? alert->curr_hash : "N/A",
                        (unsigned long long)alert->prev_size,
                        (unsigned long long)alert->curr_size,
                        alert->prev_mode,
                        alert->curr_mode,
                        safe_desc);
                fclose(fp);
            } else {
                close(fd);
            }
        }
    }

    free(esc_path);
    free(esc_old_path);
    free(esc_desc);

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

    va_list args, args_copy;
    va_start(args, fmt);
    va_copy(args_copy, args);
    int needed = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    char *raw_buf = NULL;
    if (needed >= 0) {
        raw_buf = (char *)malloc((size_t)needed + 1);
        if (raw_buf) {
            vsnprintf(raw_buf, (size_t)needed + 1, fmt, args);
        }
    }
    va_end(args);

    char *esc_msg = raw_buf ? escape_alloc(raw_buf) : NULL;
    const char *safe_msg = esc_msg ? esc_msg : (raw_buf ? raw_buf : "");

    char ts_buf[64];
    format_iso8601(time(NULL), ts_buf, sizeof(ts_buf));
    fprintf(fp, "[%s] [%s] %s\n", ts_buf, fims_severity_str(severity), safe_msg);

    free(esc_msg);
    free(raw_buf);
    fclose(fp);
    pthread_mutex_unlock(&g_log_mutex);
    return FIMS_OK;
}
