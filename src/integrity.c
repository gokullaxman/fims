#include "integrity.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void ensure_parent_dir_report(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    fims_str_copy(tmp, sizeof(tmp), file_path);
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

fims_status_t fims_report_init(fims_report_t *rep) {
    if (!rep) return FIMS_ERR_INVALID_ARG;
    memset(rep, 0, sizeof(*rep));
    rep->capacity = 32;
    rep->alerts = (fims_alert_t *)calloc(rep->capacity, sizeof(fims_alert_t));
    if (!rep->alerts) {
        rep->capacity = 0;
        return FIMS_ERR_NOMEM;
    }
    rep->scan_timestamp = time(NULL);
    return FIMS_OK;
}

void fims_report_free(fims_report_t *rep) {
    if (!rep) return;
    free(rep->alerts);
    rep->alerts = NULL;
    rep->count = 0;
    rep->capacity = 0;
}

fims_status_t fims_report_add_alert(fims_report_t *rep, const fims_alert_t *alert) {
    if (!rep || !alert) return FIMS_ERR_INVALID_ARG;

    if (rep->count >= rep->capacity) {
        size_t new_cap = (rep->capacity == 0) ? 32 : rep->capacity * 2;
        fims_alert_t *new_arr = (fims_alert_t *)realloc(rep->alerts, new_cap * sizeof(fims_alert_t));
        if (!new_arr) return FIMS_ERR_NOMEM;
        rep->alerts = new_arr;
        rep->capacity = new_cap;
    }

    rep->alerts[rep->count++] = *alert;
    return FIMS_OK;
}

uint32_t fims_compare_records(const fims_file_record_t *base, const fims_file_record_t *curr) {
    if (!base || !curr) return FIMS_FLAG_NONE;

    uint32_t flags = FIMS_FLAG_NONE;
    if (strcmp(base->sha256, curr->sha256) != 0) {
        flags |= FIMS_FLAG_FILE_MODIFIED;
    }
    if (base->size != curr->size) {
        flags |= FIMS_FLAG_SIZE_CHANGED;
    }
    if ((base->mode & 07777U) != (curr->mode & 07777U)) {
        flags |= FIMS_FLAG_PERMISSION_CHANGED;
    }
    if (base->uid != curr->uid || base->gid != curr->gid || base->mtime != curr->mtime) {
        flags |= FIMS_FLAG_METADATA_CHANGED;
    }
    return flags;
}

static fims_status_t emit_and_record(fims_report_t *rep,
                                     const fims_config_t *cfg,
                                     bool print_alerts,
                                     const fims_alert_t *alert) {
    fims_status_t st = fims_report_add_alert(rep, alert);
    if (st != FIMS_OK) return st;

    const char *log_path = (cfg && cfg->log_file[0]) ? cfg->log_file : NULL;
    return fims_log_alert(log_path, alert, print_alerts);
}

fims_status_t fims_check_integrity(const fims_file_list_t *baseline,
                                   const fims_file_list_t *current,
                                   const fims_config_t *cfg,
                                   bool print_alerts,
                                   fims_report_t *out_report) {
    if (!baseline || !current || !out_report) {
        return FIMS_ERR_INVALID_ARG;
    }

    out_report->scan_timestamp = time(NULL);
    out_report->total_files_checked = current->count;

    bool *base_matched = (bool *)calloc(baseline->count ? baseline->count : 1, sizeof(bool));
    bool *curr_matched = (bool *)calloc(current->count ? current->count : 1, sizeof(bool));
    if (!base_matched || !curr_matched) {
        free(base_matched);
        free(curr_matched);
        return FIMS_ERR_NOMEM;
    }

    /* Pass 1: Match records with identical paths */
    for (size_t b_idx = 0; b_idx < baseline->count; b_idx++) {
        const fims_file_record_t *b = &baseline->records[b_idx];
        for (size_t c_idx = 0; c_idx < current->count; c_idx++) {
            if (curr_matched[c_idx]) continue;
            const fims_file_record_t *c = &current->records[c_idx];

            if (strcmp(b->path, c->path) == 0) {
                base_matched[b_idx] = true;
                curr_matched[c_idx] = true;

                uint32_t flags = fims_compare_records(b, c);
                if (flags == FIMS_FLAG_NONE) {
                    /* Unchanged file: Do NOT report as a threat */
                    out_report->unchanged_files++;
                    break;
                }

                if (flags & FIMS_FLAG_SIZE_CHANGED) {
                    out_report->size_changed_count++;
                }
                if (flags & FIMS_FLAG_METADATA_CHANGED) {
                    out_report->meta_changed_count++;
                }

                /* Check for content modification (SHA-256 mismatch) */
                if (flags & FIMS_FLAG_FILE_MODIFIED) {
                    fims_alert_t alert;
                    memset(&alert, 0, sizeof(alert));
                    alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(alert.path, sizeof(alert.path), c->path);
                    alert.event_type = EVENT_FILE_MODIFIED;
                    alert.change_flags = flags;
                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                    alert.prev_size = b->size;
                    alert.curr_size = c->size;
                    alert.prev_mode = b->mode;
                    alert.curr_mode = c->mode;
                    alert.severity = SEV_HIGH;
                    snprintf(alert.description, sizeof(alert.description),
                             "SHA-256 content hash mismatch detected (size: %llu -> %llu bytes)",
                             (unsigned long long)b->size, (unsigned long long)c->size);
                    emit_and_record(out_report, cfg, print_alerts, &alert);
                    out_report->modified_count++;
                } else if (flags & FIMS_FLAG_SIZE_CHANGED) {
                    /* Size changed without SHA-256 mismatch (e.g., synthetic/metadata test) */
                    fims_alert_t alert;
                    memset(&alert, 0, sizeof(alert));
                    alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(alert.path, sizeof(alert.path), c->path);
                    alert.event_type = EVENT_SIZE_CHANGED;
                    alert.change_flags = flags;
                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                    alert.prev_size = b->size;
                    alert.curr_size = c->size;
                    alert.prev_mode = b->mode;
                    alert.curr_mode = c->mode;
                    alert.severity = SEV_MEDIUM;
                    snprintf(alert.description, sizeof(alert.description),
                             "File size changed from %llu to %llu bytes",
                             (unsigned long long)b->size, (unsigned long long)c->size);
                    emit_and_record(out_report, cfg, print_alerts, &alert);
                }

                /* Check for permission changes */
                if (flags & FIMS_FLAG_PERMISSION_CHANGED) {
                    fims_alert_t alert;
                    memset(&alert, 0, sizeof(alert));
                    alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(alert.path, sizeof(alert.path), c->path);
                    alert.event_type = EVENT_PERMISSION_CHANGED;
                    alert.change_flags = flags;
                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                    alert.prev_size = b->size;
                    alert.curr_size = c->size;
                    alert.prev_mode = b->mode;
                    alert.curr_mode = c->mode;
                    alert.severity = ((c->mode & 0002U) || (c->mode & 06000U)) ? SEV_HIGH : SEV_MEDIUM;
                    snprintf(alert.description, sizeof(alert.description),
                             "File permissions changed from %04o to %04o",
                             b->mode, c->mode);
                    emit_and_record(out_report, cfg, print_alerts, &alert);
                    out_report->perm_changed_count++;
                }

                /* Check for pure metadata changes (UID/GID/mtime changed while content & perms identical) */
                if ((flags & FIMS_FLAG_METADATA_CHANGED) &&
                    !(flags & (FIMS_FLAG_FILE_MODIFIED | FIMS_FLAG_SIZE_CHANGED | FIMS_FLAG_PERMISSION_CHANGED))) {
                    fims_alert_t alert;
                    memset(&alert, 0, sizeof(alert));
                    alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(alert.path, sizeof(alert.path), c->path);
                    alert.event_type = EVENT_METADATA_CHANGED;
                    alert.change_flags = flags;
                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                    alert.prev_size = b->size;
                    alert.curr_size = c->size;
                    alert.prev_mode = b->mode;
                    alert.curr_mode = c->mode;
                    alert.severity = SEV_LOW;
                    snprintf(alert.description, sizeof(alert.description),
                             "File metadata changed (uid:%u->%u, gid:%u->%u, mtime:%lld->%lld)",
                             b->uid, c->uid, b->gid, c->gid,
                             (long long)b->mtime, (long long)c->mtime);
                    emit_and_record(out_report, cfg, print_alerts, &alert);
                }

                break;
            }
        }
    }

    /* Pass 2: Check for reliably identifiable renamed files if enabled in config
     * A file rename preserves device ID, inode number, non-zero size, mtime, and SHA-256 hash. */
    if (cfg && cfg->detect_renames) {
        for (size_t b_idx = 0; b_idx < baseline->count; b_idx++) {
            if (base_matched[b_idx]) continue;
            const fims_file_record_t *b = &baseline->records[b_idx];
            if (b->size == 0) continue;

            for (size_t c_idx = 0; c_idx < current->count; c_idx++) {
                if (curr_matched[c_idx]) continue;
                const fims_file_record_t *c = &current->records[c_idx];

                if (b->dev == c->dev &&
                    b->inode == c->inode &&
                    b->size == c->size &&
                    b->mtime == c->mtime &&
                    strcmp(b->sha256, c->sha256) == 0) {
                    base_matched[b_idx] = true;
                    curr_matched[c_idx] = true;

                    fims_alert_t alert;
                    memset(&alert, 0, sizeof(alert));
                    alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(alert.path, sizeof(alert.path), c->path);
                    fims_str_copy(alert.old_path, sizeof(alert.old_path), b->path);
                    alert.event_type = EVENT_FILE_RENAMED;
                    alert.change_flags = FIMS_FLAG_FILE_RENAMED;
                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                    alert.prev_size = b->size;
                    alert.curr_size = c->size;
                    alert.prev_mode = b->mode;
                    alert.curr_mode = c->mode;
                    alert.severity = SEV_MEDIUM;
                    snprintf(alert.description, sizeof(alert.description),
                             "File renamed (inode %llu preserved, SHA-256 unchanged)",
                             (unsigned long long)c->inode);
                    emit_and_record(out_report, cfg, print_alerts, &alert);
                    out_report->renamed_count++;
                    break;
                }
            }
        }
    }

    /* Pass 3: Report all remaining unmatched baseline records as FILE_DELETED */
    for (size_t b_idx = 0; b_idx < baseline->count; b_idx++) {
        if (base_matched[b_idx]) continue;
        const fims_file_record_t *b = &baseline->records[b_idx];

        fims_alert_t alert;
        memset(&alert, 0, sizeof(alert));
        alert.timestamp = out_report->scan_timestamp;
        fims_str_copy(alert.path, sizeof(alert.path), b->path);
        alert.event_type = EVENT_FILE_DELETED;
        alert.change_flags = FIMS_FLAG_FILE_DELETED;
        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "DELETED");
        alert.prev_size = b->size;
        alert.curr_size = 0;
        alert.prev_mode = b->mode;
        alert.curr_mode = 0;
        alert.severity = SEV_HIGH;
        snprintf(alert.description, sizeof(alert.description),
                 "Monitored file was deleted from filesystem (previous size: %llu bytes)",
                 (unsigned long long)b->size);
        emit_and_record(out_report, cfg, print_alerts, &alert);
        out_report->deleted_count++;
    }

    /* Pass 4: Report all remaining unmatched current records as FILE_ADDED */
    for (size_t c_idx = 0; c_idx < current->count; c_idx++) {
        if (curr_matched[c_idx]) continue;
        const fims_file_record_t *c = &current->records[c_idx];

        fims_alert_t alert;
        memset(&alert, 0, sizeof(alert));
        alert.timestamp = out_report->scan_timestamp;
        fims_str_copy(alert.path, sizeof(alert.path), c->path);
        alert.event_type = EVENT_FILE_ADDED;
        alert.change_flags = FIMS_FLAG_FILE_ADDED;
        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), "NONE");
        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
        alert.prev_size = 0;
        alert.curr_size = c->size;
        alert.prev_mode = 0;
        alert.curr_mode = c->mode;
        alert.severity = SEV_MEDIUM;
        snprintf(alert.description, sizeof(alert.description),
                 "New file detected in monitored directory (size: %llu bytes, mode: %04o)",
                 (unsigned long long)c->size, c->mode);
        emit_and_record(out_report, cfg, print_alerts, &alert);
        out_report->added_count++;
    }

    free(base_matched);
    free(curr_matched);
    return FIMS_OK;
}

fims_status_t fims_report_save(const char *report_path, const fims_report_t *rep) {
    if (!report_path || !rep || report_path[0] == '\0') return FIMS_ERR_INVALID_ARG;

    ensure_parent_dir_report(report_path);
    int fd = open(report_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return FIMS_ERR_IO;
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return FIMS_ERR_IO;
    }

    char ts_buf[64];
    struct tm tm_info;
    if (localtime_r(&rep->scan_timestamp, &tm_info) != NULL) {
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S %z", &tm_info);
    } else {
        snprintf(ts_buf, sizeof(ts_buf), "%lld", (long long)rep->scan_timestamp);
    }

    fprintf(fp, "================================================================================\n");
    fprintf(fp, " FIMS Integrity Scan Report\n");
    fprintf(fp, "================================================================================\n");
    fprintf(fp, " Scan Timestamp      : %s\n", ts_buf);
    fprintf(fp, " Files Checked       : %zu\n", rep->total_files_checked);
    fprintf(fp, " Unchanged Files     : %zu\n", rep->unchanged_files);
    fprintf(fp, " Total Alerts        : %zu\n", rep->count);
    fprintf(fp, "   - Modified        : %zu\n", rep->modified_count);
    fprintf(fp, "   - Deleted         : %zu\n", rep->deleted_count);
    fprintf(fp, "   - Added           : %zu\n", rep->added_count);
    fprintf(fp, "   - Renamed         : %zu\n", rep->renamed_count);
    fprintf(fp, "   - Perm Changed    : %zu\n", rep->perm_changed_count);
    fprintf(fp, "   - Size Changed    : %zu\n", rep->size_changed_count);
    fprintf(fp, "   - Metadata Changed: %zu\n", rep->meta_changed_count);
    fprintf(fp, "--------------------------------------------------------------------------------\n");

    if (rep->count == 0) {
        fprintf(fp, " [OK] No unauthorized integrity changes detected. Filesystem matches baseline.\n");
    } else {
        for (size_t i = 0; i < rep->count; i++) {
            const fims_alert_t *a = &rep->alerts[i];
            if (a->event_type == EVENT_FILE_RENAMED && a->old_path[0] != '\0') {
                fprintf(fp, "[ALERT] %s: %s -> %s\n", fims_event_type_str(a->event_type), a->old_path, a->path);
            } else {
                fprintf(fp, "[ALERT] %s: %s\n", fims_event_type_str(a->event_type), a->path);
            }
            fprintf(fp, "        Severity   : %s\n", fims_severity_str(a->severity));
            fprintf(fp, "        Prev Hash  : %s\n", a->prev_hash[0] ? a->prev_hash : "N/A");
            fprintf(fp, "        Curr Hash  : %s\n", a->curr_hash[0] ? a->curr_hash : "N/A");
            fprintf(fp, "        Description: %s\n", a->description);
        }
    }
    fprintf(fp, "================================================================================\n");
    fclose(fp);
    return FIMS_OK;
}

fims_status_t fims_report_display(const char *report_path) {
    if (!report_path || report_path[0] == '\0') return FIMS_ERR_INVALID_ARG;

    FILE *fp = fopen(report_path, "r");
    if (!fp) {
        return FIMS_ERR_NOT_FOUND;
    }

    char line[FIMS_MAX_LINE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }
    fclose(fp);
    return FIMS_OK;
}
