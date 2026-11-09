#include "integrity.h"
#include "logger.h"
#include "escape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <inttypes.h>

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

    if (curr->unreadable) {
        flags |= FIMS_FLAG_UNREADABLE;
    } else if (strcmp(base->sha256, curr->sha256) != 0) {
        flags |= FIMS_FLAG_FILE_MODIFIED;
    }

    if (base->size != curr->size) {
        flags |= FIMS_FLAG_SIZE_CHANGED;
    }
    if ((base->mode & 07777U) != (curr->mode & 07777U)) {
        flags |= FIMS_FLAG_PERMISSION_CHANGED;
    }
    if (base->uid != curr->uid || base->gid != curr->gid ||
        base->mtime != curr->mtime || base->ctime != curr->ctime ||
        base->inode != curr->inode) {
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

/* Inode hash map node for O(1) average rename matching */
typedef struct fims_inode_node {
    const fims_file_record_t *rec;
    size_t                    c_idx;
    bool                      matched;
    struct fims_inode_node   *next;
} fims_inode_node_t;

static inline uint64_t hash_dev_inode(uint64_t dev, uint64_t inode) {
    uint64_t h = (dev ^ (inode + 0x517cc1b727220a95ULL));
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

static bool is_list_sorted(const fims_file_list_t *list) {
    if (!list || list->count <= 1) return true;
    for (size_t i = 1; i < list->count; i++) {
        if (strcmp(list->records[i - 1].path, list->records[i].path) > 0) {
            return false;
        }
    }
    return true;
}

static int compare_record_pointers(const void *a, const void *b) {
    const fims_file_record_t *ra = *(const fims_file_record_t * const *)a;
    const fims_file_record_t *rb = *(const fims_file_record_t * const *)b;
    return strcmp(ra->path, rb->path);
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

    const fims_file_record_t **b_recs = NULL;
    const fims_file_record_t **c_recs = NULL;
    size_t *unmatched_b = NULL;
    size_t *unmatched_c = NULL;
    fims_status_t status = FIMS_OK;

    if (baseline->count > 0) {
        b_recs = (const fims_file_record_t **)malloc(baseline->count * sizeof(*b_recs));
        unmatched_b = (size_t *)malloc(baseline->count * sizeof(*unmatched_b));
        if (!b_recs || !unmatched_b) {
            status = FIMS_ERR_NOMEM;
            goto cleanup;
        }
        for (size_t i = 0; i < baseline->count; i++) {
            b_recs[i] = &baseline->records[i];
        }
        if (!is_list_sorted(baseline)) {
            qsort(b_recs, baseline->count, sizeof(*b_recs), compare_record_pointers);
        }
    }

    if (current->count > 0) {
        c_recs = (const fims_file_record_t **)malloc(current->count * sizeof(*c_recs));
        unmatched_c = (size_t *)malloc(current->count * sizeof(*unmatched_c));
        if (!c_recs || !unmatched_c) {
            status = FIMS_ERR_NOMEM;
            goto cleanup;
        }
        for (size_t i = 0; i < current->count; i++) {
            c_recs[i] = &current->records[i];
        }
        if (!is_list_sorted(current)) {
            qsort(c_recs, current->count, sizeof(*c_recs), compare_record_pointers);
        }
    }

    size_t b_idx = 0;
    size_t c_idx = 0;
    size_t ub_count = 0;
    size_t uc_count = 0;

    /* Linear merge join over sorted records */
    while (b_idx < baseline->count && c_idx < current->count) {
        const fims_file_record_t *b = b_recs[b_idx];
        const fims_file_record_t *c = c_recs[c_idx];
        int cmp = strcmp(b->path, c->path);

        if (cmp == 0) {
            /* Path matches in both baseline and current */
            if (c->unreadable) {
                /* Item 10: unreadable records emitted as UNREADABLE (never DELETED) */
                fims_alert_t alert;
                memset(&alert, 0, sizeof(alert));
                alert.timestamp = out_report->scan_timestamp;
                fims_str_copy(alert.path, sizeof(alert.path), c->path);
                alert.event_type = EVENT_UNREADABLE;
                alert.change_flags = FIMS_FLAG_UNREADABLE;
                if ((b->mode & 07777U) != (c->mode & 07777U)) {
                    alert.change_flags |= FIMS_FLAG_PERMISSION_CHANGED;
                }
                fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "UNREADABLE");
                alert.prev_size = b->size;
                alert.curr_size = c->size;
                alert.prev_mode = b->mode;
                alert.curr_mode = c->mode;
                alert.severity = SEV_HIGH;
                snprintf(alert.description, sizeof(alert.description),
                         "File is unreadable or permission denied (lstat metadata preserved)");
                status = emit_and_record(out_report, cfg, print_alerts, &alert);
                if (status != FIMS_OK) goto cleanup;

                /* If permissions also changed on the unreadable file, emit permission alert */
                if ((b->mode & 07777U) != (c->mode & 07777U)) {
                    fims_alert_t perm_alert;
                    memset(&perm_alert, 0, sizeof(perm_alert));
                    perm_alert.timestamp = out_report->scan_timestamp;
                    fims_str_copy(perm_alert.path, sizeof(perm_alert.path), c->path);
                    perm_alert.event_type = EVENT_PERMISSION_CHANGED;
                    perm_alert.change_flags = FIMS_FLAG_PERMISSION_CHANGED | FIMS_FLAG_UNREADABLE;
                    fims_str_copy(perm_alert.prev_hash, sizeof(perm_alert.prev_hash), b->sha256);
                    fims_str_copy(perm_alert.curr_hash, sizeof(perm_alert.curr_hash), "UNREADABLE");
                    perm_alert.prev_size = b->size;
                    perm_alert.curr_size = c->size;
                    perm_alert.prev_mode = b->mode;
                    perm_alert.curr_mode = c->mode;
                    perm_alert.severity = SEV_HIGH;
                    snprintf(perm_alert.description, sizeof(perm_alert.description),
                             "File permissions changed from %04o to %04o (unreadable)",
                             b->mode, c->mode);
                    status = emit_and_record(out_report, cfg, print_alerts, &perm_alert);
                    if (status != FIMS_OK) goto cleanup;
                    out_report->perm_changed_count++;
                }
            } else {
                uint32_t flags = fims_compare_records(b, c);
                if (flags == FIMS_FLAG_NONE) {
                    out_report->unchanged_files++;
                } else {
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
                        status = emit_and_record(out_report, cfg, print_alerts, &alert);
                        if (status != FIMS_OK) goto cleanup;
                        out_report->modified_count++;
                        if (flags & FIMS_FLAG_SIZE_CHANGED) {
                            out_report->size_changed_count++;
                        }
                    } else if (flags & FIMS_FLAG_SIZE_CHANGED) {
                        /* Size changed without hash mismatch */
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
                        status = emit_and_record(out_report, cfg, print_alerts, &alert);
                        if (status != FIMS_OK) goto cleanup;
                        out_report->size_changed_count++;
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
                        status = emit_and_record(out_report, cfg, print_alerts, &alert);
                        if (status != FIMS_OK) goto cleanup;
                        out_report->perm_changed_count++;
                    }

                    /* Item 11 & Item 24: Metadata changes (uid/gid, ctime, inode, mtime) */
                    bool uid_gid_changed = (b->uid != c->uid || b->gid != c->gid);
                    bool ctime_inode_changed = (b->ctime != c->ctime || b->inode != c->inode);
                    bool mtime_changed = (b->mtime != c->mtime);

                    bool emit_meta = false;
                    if (uid_gid_changed) {
                        /* Item 11: emit whenever uid or gid changes even with other flags */
                        emit_meta = true;
                    } else if (ctime_inode_changed && !(flags & FIMS_FLAG_FILE_MODIFIED)) {
                        /* Item 24: ctime or inode changed on same-path records */
                        emit_meta = true;
                    } else if (mtime_changed && !(flags & (FIMS_FLAG_FILE_MODIFIED | FIMS_FLAG_SIZE_CHANGED | FIMS_FLAG_PERMISSION_CHANGED))) {
                        emit_meta = true;
                    }

                    if (emit_meta) {
                        fims_alert_t alert;
                        memset(&alert, 0, sizeof(alert));
                        alert.timestamp = out_report->scan_timestamp;
                        fims_str_copy(alert.path, sizeof(alert.path), c->path);
                        alert.event_type = EVENT_METADATA_CHANGED;
                        alert.change_flags = flags | FIMS_FLAG_METADATA_CHANGED;
                        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), b->sha256);
                        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), c->sha256);
                        alert.prev_size = b->size;
                        alert.curr_size = c->size;
                        alert.prev_mode = b->mode;
                        alert.curr_mode = c->mode;
                        alert.severity = SEV_LOW;
                        snprintf(alert.description, sizeof(alert.description),
                                 "File metadata changed (uid:%u->%u, gid:%u->%u, mtime:%lld->%lld, ctime:%lld->%lld, inode:%llu->%llu)",
                                 b->uid, c->uid, b->gid, c->gid,
                                 (long long)b->mtime, (long long)c->mtime,
                                 (long long)b->ctime, (long long)c->ctime,
                                 (unsigned long long)b->inode, (unsigned long long)c->inode);
                        status = emit_and_record(out_report, cfg, print_alerts, &alert);
                        if (status != FIMS_OK) goto cleanup;
                        out_report->meta_changed_count++;
                    }
                }
            }
            b_idx++;
            c_idx++;
        } else if (cmp < 0) {
            unmatched_b[ub_count++] = b_idx++;
        } else {
            unmatched_c[uc_count++] = c_idx++;
        }
    }

    while (b_idx < baseline->count) {
        unmatched_b[ub_count++] = b_idx++;
    }
    while (c_idx < current->count) {
        unmatched_c[uc_count++] = c_idx++;
    }

    /* Rename detection using (dev, inode) hash map */
    if (cfg && cfg->detect_renames && ub_count > 0 && uc_count > 0) {
        size_t num_buckets = 1024;
        while (num_buckets < uc_count * 2) {
            num_buckets <<= 1;
        }

        fims_inode_node_t **buckets = (fims_inode_node_t **)calloc(num_buckets, sizeof(*buckets));
        fims_inode_node_t *nodes = (fims_inode_node_t *)calloc(uc_count ? uc_count : 1, sizeof(*nodes));
        if (!buckets || !nodes) {
            free(buckets);
            free(nodes);
            status = FIMS_ERR_NOMEM;
            goto cleanup;
        }

        for (size_t i = 0; i < uc_count; i++) {
            const fims_file_record_t *c = c_recs[unmatched_c[i]];
            nodes[i].rec = c;
            nodes[i].c_idx = i;
            nodes[i].matched = false;

            if (c->size == 0 || c->unreadable) continue;

            uint64_t h = hash_dev_inode(c->dev, c->inode) & (num_buckets - 1);
            nodes[i].next = buckets[h];
            buckets[h] = &nodes[i];
        }

        for (size_t i = 0; i < ub_count; i++) {
            const fims_file_record_t *b = b_recs[unmatched_b[i]];
            bool renamed = false;

            if (b->size > 0 && !b->unreadable) {
                uint64_t h = hash_dev_inode(b->dev, b->inode) & (num_buckets - 1);
                for (fims_inode_node_t *node = buckets[h]; node; node = node->next) {
                    if (node->matched) continue;
                    const fims_file_record_t *c = node->rec;

                    if (b->dev == c->dev &&
                        b->inode == c->inode &&
                        b->size == c->size &&
                        b->mtime == c->mtime &&
                        strcmp(b->sha256, c->sha256) == 0) {

                        node->matched = true;
                        renamed = true;

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
                        status = emit_and_record(out_report, cfg, print_alerts, &alert);
                        if (status != FIMS_OK) {
                            free(buckets);
                            free(nodes);
                            goto cleanup;
                        }
                        out_report->renamed_count++;
                        break;
                    }
                }
            }

            if (!renamed) {
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
                status = emit_and_record(out_report, cfg, print_alerts, &alert);
                if (status != FIMS_OK) {
                    free(buckets);
                    free(nodes);
                    goto cleanup;
                }
                out_report->deleted_count++;
            }
        }

        for (size_t i = 0; i < uc_count; i++) {
            if (nodes[i].matched) continue;
            const fims_file_record_t *c = c_recs[unmatched_c[i]];

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
            status = emit_and_record(out_report, cfg, print_alerts, &alert);
            if (status != FIMS_OK) {
                free(buckets);
                free(nodes);
                goto cleanup;
            }
            out_report->added_count++;
        }

        free(buckets);
        free(nodes);
    } else {
        /* No rename detection: all unmatched baseline deleted, all unmatched current added */
        for (size_t i = 0; i < ub_count; i++) {
            const fims_file_record_t *b = b_recs[unmatched_b[i]];
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
            status = emit_and_record(out_report, cfg, print_alerts, &alert);
            if (status != FIMS_OK) goto cleanup;
            out_report->deleted_count++;
        }

        for (size_t i = 0; i < uc_count; i++) {
            const fims_file_record_t *c = c_recs[unmatched_c[i]];
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
            status = emit_and_record(out_report, cfg, print_alerts, &alert);
            if (status != FIMS_OK) goto cleanup;
            out_report->added_count++;
        }
    }

cleanup:
    free(b_recs);
    free(c_recs);
    free(unmatched_b);
    free(unmatched_c);
    return status;
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
            char esc_path[FIMS_MAX_PATH * 4];
            char esc_old_path[FIMS_MAX_PATH * 4];
            char esc_desc[sizeof(a->description) * 4];

            fims_escape_for_log(a->path, esc_path, sizeof(esc_path));
            fims_escape_for_log(a->old_path, esc_old_path, sizeof(esc_old_path));
            fims_escape_for_log(a->description, esc_desc, sizeof(esc_desc));

            const char *type_str = (a->event_type == EVENT_UNREADABLE) ? "UNREADABLE" : fims_event_type_str(a->event_type);
            if (a->event_type == EVENT_FILE_RENAMED && a->old_path[0] != '\0') {
                fprintf(fp, "[ALERT] %s: %s -> %s\n", type_str, esc_old_path, esc_path);
            } else {
                fprintf(fp, "[ALERT] %s: %s\n", type_str, esc_path);
            }
            fprintf(fp, "        Severity   : %s\n", fims_severity_str(a->severity));
            fprintf(fp, "        Prev Hash  : %s\n", a->prev_hash[0] ? a->prev_hash : "N/A");
            fprintf(fp, "        Curr Hash  : %s\n", a->curr_hash[0] ? a->curr_hash : "N/A");
            fprintf(fp, "        Description: %s\n", esc_desc);
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
        /* Safely escape paths and descriptions when displaying report */
        if (strncmp(line, "[ALERT] ", 8) == 0) {
            char *colon = strchr(line + 8, ':');
            if (colon && *(colon + 1) == ' ') {
                char prefix[256];
                size_t plen = (size_t)(colon + 2 - line);
                if (plen < sizeof(prefix)) {
                    memcpy(prefix, line, plen);
                    prefix[plen] = '\0';
                    char *target = colon + 2;
                    size_t tlen = strlen(target);
                    while (tlen > 0 && (target[tlen - 1] == '\n' || target[tlen - 1] == '\r')) {
                        target[--tlen] = '\0';
                    }
                    char *arrow = strstr(target, " -> ");
                    if (arrow) {
                        *arrow = '\0';
                        char *old_p = target;
                        char *new_p = arrow + 4;
                        char esc_old[FIMS_MAX_PATH * 4];
                        char esc_new[FIMS_MAX_PATH * 4];
                        fims_escape_for_log(old_p, esc_old, sizeof(esc_old));
                        fims_escape_for_log(new_p, esc_new, sizeof(esc_new));
                        printf("%s%s -> %s\n", prefix, esc_old, esc_new);
                        continue;
                    } else {
                        char esc_target[FIMS_MAX_PATH * 4];
                        fims_escape_for_log(target, esc_target, sizeof(esc_target));
                        printf("%s%s\n", prefix, esc_target);
                        continue;
                    }
                }
            }
        } else if (strncmp(line, "        Description: ", 21) == 0) {
            char *desc = line + 21;
            size_t dlen = strlen(desc);
            while (dlen > 0 && (desc[dlen - 1] == '\n' || desc[dlen - 1] == '\r')) {
                desc[--dlen] = '\0';
            }
            char esc_desc[sizeof(line) * 4];
            fims_escape_for_log(desc, esc_desc, sizeof(esc_desc));
            printf("        Description: %s\n", esc_desc);
            continue;
        }
        fputs(line, stdout);
    }
    fclose(fp);
    return FIMS_OK;
}
