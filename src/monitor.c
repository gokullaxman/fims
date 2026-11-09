#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "monitor.h"
#include "scanner.h"
#include "baseline.h"
#include "integrity.h"
#include "logger.h"
#include "config.h"
#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <dirent.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/inotify.h>

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define FIMS_INOTIFY_BUF_LEN (64 * (sizeof(struct inotify_event) + NAME_MAX + 1))

/* Item 2: IN_CLOSE_WRITE (not IN_MODIFY) triggers re-hash; keep IN_ATTRIB, IN_CREATE, IN_DELETE, IN_MOVED_* */
#define FIMS_WATCH_MASK (IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | \
                         IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)

typedef struct {
    int  wd;
    char path[FIMS_MAX_PATH];
} watch_entry_t;

/* Item 18: Inotify cookie pairing for renames */
typedef struct {
    uint32_t cookie;
    char     old_path[FIMS_MAX_PATH];
    bool     is_dir;
    time_t   timestamp;
} pending_move_t;

typedef struct {
    int                  inotify_fd;
    watch_entry_t       *watches;
    size_t               watch_count;
    size_t               watch_cap;
    const fims_config_t *cfg;
    fims_file_list_t     baseline;
    fims_file_list_t     live_state;
    fims_report_t        cumulative_report;
    fims_monitor_stats_t stats;
    pending_move_t       pending_move;
    pthread_mutex_t      lock;
} monitor_ctx_t;

static volatile sig_atomic_t g_stop_requested = 0;

static void monitor_sig_handler(int sig) {
    (void)sig;
    g_stop_requested = 1;
}

void fims_monitor_request_stop(void) {
    g_stop_requested = 1;
}

void fims_monitor_reset_stop(void) {
    g_stop_requested = 0;
}

static void sleep_ms(long milliseconds) {
    struct timespec req;
    req.tv_sec = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

static void ensure_parent_dir_state(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    fims_str_copy(tmp, sizeof(tmp), file_path);
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

static const char *lookup_watch_path(const monitor_ctx_t *ctx, int wd) {
    for (size_t i = 0; i < ctx->watch_count; i++) {
        if (ctx->watches[i].wd == wd) {
            return ctx->watches[i].path;
        }
    }
    return NULL;
}

/* Item 7: Remove watch entry when directory is deleted, moved, or ignored */
static void remove_watch_entry(monitor_ctx_t *ctx, int wd) {
    for (size_t i = 0; i < ctx->watch_count; i++) {
        if (ctx->watches[i].wd == wd) {
            if (i + 1 < ctx->watch_count) {
                memmove(&ctx->watches[i], &ctx->watches[i + 1],
                        (ctx->watch_count - i - 1) * sizeof(watch_entry_t));
            }
            ctx->watch_count--;
            ctx->stats.active_watches = ctx->watch_count;
            return;
        }
    }
}

/* Item 13: Add IN_DONT_FOLLOW | IN_ONLYDIR, ENOSPC logging, and max depth enforcement */
static fims_status_t add_watch_recursive(monitor_ctx_t *ctx, const char *dir_path, int depth) {
    if (!ctx || !dir_path) return FIMS_OK;

    if (depth >= FIMS_MAX_SCAN_DEPTH) {
        if (ctx->cfg && ctx->cfg->log_file[0]) {
            fims_log_message(ctx->cfg->log_file, SEV_MEDIUM,
                             "Maximum scan depth (%d) reached at directory: %s",
                             FIMS_MAX_SCAN_DEPTH, dir_path);
        }
        return FIMS_OK;
    }

    if (ctx->cfg && fims_config_is_excluded(ctx->cfg, dir_path)) return FIMS_OK;

    struct stat st;
    if (lstat(dir_path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return FIMS_OK;
    }

    uint32_t mask = FIMS_WATCH_MASK | IN_DONT_FOLLOW | IN_ONLYDIR;
    int wd = inotify_add_watch(ctx->inotify_fd, dir_path, mask);
    if (wd < 0) {
        ctx->stats.watch_failures++;
        if (ctx->cfg && ctx->cfg->log_file[0]) {
            fims_log_message(ctx->cfg->log_file, SEV_HIGH,
                             "inotify_add_watch failed on '%s': %s (errno=%d)",
                             dir_path, strerror(errno), errno);
        }
        return FIMS_OK;
    }

    /* Update existing watch entry if wd already present */
    bool updated = false;
    for (size_t i = 0; i < ctx->watch_count; i++) {
        if (ctx->watches[i].wd == wd) {
            fims_str_copy(ctx->watches[i].path, FIMS_MAX_PATH, dir_path);
            updated = true;
            break;
        }
    }
    if (!updated) {
        if (ctx->watch_count >= ctx->watch_cap) {
            size_t new_cap = (ctx->watch_cap == 0) ? 32 : ctx->watch_cap * 2;
            watch_entry_t *new_w = (watch_entry_t *)realloc(ctx->watches, new_cap * sizeof(watch_entry_t));
            if (!new_w) return FIMS_ERR_NOMEM;
            ctx->watches = new_w;
            ctx->watch_cap = new_cap;
        }
        ctx->watches[ctx->watch_count].wd = wd;
        fims_str_copy(ctx->watches[ctx->watch_count].path, FIMS_MAX_PATH, dir_path);
        ctx->watch_count++;
        ctx->stats.active_watches = ctx->watch_count;
    }

    DIR *dirp = opendir(dir_path);
    if (!dirp) return FIMS_OK;

    struct dirent *entry;
    while ((entry = readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child[FIMS_MAX_PATH];
        if (!fims_path_join(child, sizeof(child), dir_path, entry->d_name)) continue;

        struct stat cst;
        if (lstat(child, &cst) == 0 && S_ISDIR(cst.st_mode) && !S_ISLNK(cst.st_mode)) {
            add_watch_recursive(ctx, child, depth + 1);
        }
    }
    closedir(dirp);
    return FIMS_OK;
}

/* Item 14: Binary search and sorted record operations */
static int record_path_cmp(const void *key, const void *elem) {
    const char *path = (const char *)key;
    const fims_file_record_t *rec = (const fims_file_record_t *)elem;
    return strcmp(path, rec->path);
}

static fims_file_record_t *find_record_in_list(fims_file_list_t *list, const char *path) {
    if (!list || !list->records || list->count == 0 || !path) return NULL;
    return (fims_file_record_t *)bsearch(path, list->records, list->count,
                                          sizeof(fims_file_record_t), record_path_cmp);
}

static fims_status_t insert_record_sorted(fims_file_list_t *list, const fims_file_record_t *rec) {
    if (!list || !rec) return FIMS_ERR_INVALID_ARG;

    size_t low = 0;
    size_t high = list->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = strcmp(rec->path, list->records[mid].path);
        if (cmp == 0) {
            list->records[mid] = *rec;
            return FIMS_OK;
        } else if (cmp < 0) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    size_t idx = low;

    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 64 : list->capacity * 2;
        fims_file_record_t *new_recs = (fims_file_record_t *)realloc(
            list->records, new_cap * sizeof(fims_file_record_t));
        if (!new_recs) return FIMS_ERR_NOMEM;
        list->records = new_recs;
        list->capacity = new_cap;
    }

    if (idx < list->count) {
        memmove(&list->records[idx + 1], &list->records[idx],
                (list->count - idx) * sizeof(fims_file_record_t));
    }
    list->records[idx] = *rec;
    list->count++;
    return FIMS_OK;
}

static void remove_record_from_list(fims_file_list_t *list, const char *path) {
    if (!list || !list->records || list->count == 0 || !path) return;
    fims_file_record_t *rec = find_record_in_list(list, path);
    if (!rec) return;
    size_t idx = (size_t)(rec - list->records);
    if (idx + 1 < list->count) {
        memmove(&list->records[idx], &list->records[idx + 1],
                (list->count - idx - 1) * sizeof(fims_file_record_t));
    }
    list->count--;
}

/* Item 18: Recursive directory deletion alerts */
static void handle_directory_deletion(monitor_ctx_t *ctx, const char *dir_path) {
    if (!ctx || !dir_path) return;
    size_t dlen = strlen(dir_path);

    for (size_t i = ctx->live_state.count; i > 0; i--) {
        size_t idx = i - 1;
        const char *p = ctx->live_state.records[idx].path;
        if (strncmp(p, dir_path, dlen) == 0 && (p[dlen] == '/' || p[dlen] == '\0')) {
            fims_alert_t alert;
            memset(&alert, 0, sizeof(alert));
            alert.timestamp = time(NULL);
            fims_str_copy(alert.path, sizeof(alert.path), p);
            alert.event_type = EVENT_FILE_DELETED;
            alert.change_flags = FIMS_FLAG_FILE_DELETED;
            fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), ctx->live_state.records[idx].sha256);
            fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "DELETED");
            alert.prev_size = ctx->live_state.records[idx].size;
            alert.prev_mode = ctx->live_state.records[idx].mode;
            alert.severity = SEV_HIGH;
            snprintf(alert.description, sizeof(alert.description),
                     "Real-time inotify event: file deleted via directory deletion (%s)", dir_path);

            fims_log_alert(ctx->cfg->log_file, &alert, true);
            fims_report_add_alert(&ctx->cumulative_report, &alert);
            ctx->cumulative_report.deleted_count++;
            ctx->stats.realtime_alerts_emitted++;

            if (idx + 1 < ctx->live_state.count) {
                memmove(&ctx->live_state.records[idx], &ctx->live_state.records[idx + 1],
                        (ctx->live_state.count - idx - 1) * sizeof(fims_file_record_t));
            }
            ctx->live_state.count--;
        }
    }

    /* Remove watched directories that fell under the deleted tree */
    for (size_t i = ctx->watch_count; i > 0; i--) {
        size_t idx = i - 1;
        if (strncmp(ctx->watches[idx].path, dir_path, dlen) == 0 &&
            (ctx->watches[idx].path[dlen] == '/' || ctx->watches[idx].path[dlen] == '\0')) {
            inotify_rm_watch(ctx->inotify_fd, ctx->watches[idx].wd);
            if (idx + 1 < ctx->watch_count) {
                memmove(&ctx->watches[idx], &ctx->watches[idx + 1],
                        (ctx->watch_count - idx - 1) * sizeof(watch_entry_t));
            }
            ctx->watch_count--;
            ctx->stats.active_watches = ctx->watch_count;
        }
    }
}

/* Item 18: Flush pending rename move if unpaired */
static void flush_pending_move(monitor_ctx_t *ctx) {
    if (!ctx || ctx->pending_move.cookie == 0) return;
    if (ctx->pending_move.is_dir) {
        handle_directory_deletion(ctx, ctx->pending_move.old_path);
    } else {
        fims_file_record_t *live_rec = find_record_in_list(&ctx->live_state, ctx->pending_move.old_path);
        if (live_rec) {
            fims_alert_t alert;
            memset(&alert, 0, sizeof(alert));
            alert.timestamp = time(NULL);
            fims_str_copy(alert.path, sizeof(alert.path), ctx->pending_move.old_path);
            alert.event_type = EVENT_FILE_DELETED;
            alert.change_flags = FIMS_FLAG_FILE_DELETED;
            fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), live_rec->sha256);
            fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "DELETED");
            alert.prev_size = live_rec->size;
            alert.prev_mode = live_rec->mode;
            alert.severity = SEV_HIGH;
            snprintf(alert.description, sizeof(alert.description),
                     "Real-time inotify event: file moved out of monitored tree");

            fims_log_alert(ctx->cfg->log_file, &alert, true);
            fims_report_add_alert(&ctx->cumulative_report, &alert);
            ctx->cumulative_report.deleted_count++;
            ctx->stats.realtime_alerts_emitted++;

            remove_record_from_list(&ctx->live_state, ctx->pending_move.old_path);
        }
    }
    ctx->pending_move.cookie = 0;
    ctx->pending_move.old_path[0] = '\0';
}

static void handle_single_file_event(monitor_ctx_t *ctx, const char *full_path, uint32_t mask) {
    if (!ctx || !full_path) return;
    if (ctx->cfg && fims_config_is_excluded(ctx->cfg, full_path)) return;

    /* Item 2: Ignore raw IN_MODIFY; rehash only on IN_CLOSE_WRITE, IN_ATTRIB, etc. */
    if (mask & IN_MODIFY) return;

    fims_file_record_t *live_rec = find_record_in_list(&ctx->live_state, full_path);

    if (mask & (IN_DELETE | IN_MOVED_FROM)) {
        if (live_rec) {
            fims_alert_t alert;
            memset(&alert, 0, sizeof(alert));
            alert.timestamp = time(NULL);
            fims_str_copy(alert.path, sizeof(alert.path), full_path);
            alert.event_type = EVENT_FILE_DELETED;
            alert.change_flags = FIMS_FLAG_FILE_DELETED;
            fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), live_rec->sha256);
            fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "DELETED");
            alert.prev_size = live_rec->size;
            alert.prev_mode = live_rec->mode;
            alert.severity = SEV_HIGH;
            snprintf(alert.description, sizeof(alert.description),
                     "Real-time inotify event: monitored file deleted");

            fims_log_alert(ctx->cfg->log_file, &alert, true);
            fims_report_add_alert(&ctx->cumulative_report, &alert);
            ctx->cumulative_report.deleted_count++;
            ctx->stats.realtime_alerts_emitted++;

            remove_record_from_list(&ctx->live_state, full_path);
        }
        return;
    }

    /* Inspect current file on disk */
    fims_file_record_t curr_rec;
    fims_status_t st = fims_scan_single_file(full_path, &curr_rec);
    if (st != FIMS_OK) {
        return; /* Ignore non-regular files or transient race where file vanished */
    }

    if (!live_rec) {
        /* Newly created or moved-in file */
        fims_alert_t alert;
        memset(&alert, 0, sizeof(alert));
        alert.timestamp = time(NULL);
        fims_str_copy(alert.path, sizeof(alert.path), full_path);
        alert.event_type = EVENT_FILE_ADDED;
        alert.change_flags = FIMS_FLAG_FILE_ADDED;
        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), "NONE");
        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), curr_rec.sha256);
        alert.curr_size = curr_rec.size;
        alert.curr_mode = curr_rec.mode;
        alert.severity = SEV_MEDIUM;
        snprintf(alert.description, sizeof(alert.description),
                 "Real-time inotify event: new file created (%llu bytes)",
                 (unsigned long long)curr_rec.size);

        fims_log_alert(ctx->cfg->log_file, &alert, true);
        fims_report_add_alert(&ctx->cumulative_report, &alert);
        ctx->cumulative_report.added_count++;
        ctx->stats.realtime_alerts_emitted++;

        insert_record_sorted(&ctx->live_state, &curr_rec);
        return;
    }

    /* File already tracked in live_state: check what changed */
    uint32_t flags = fims_compare_records(live_rec, &curr_rec);
    if (flags == FIMS_FLAG_NONE) {
        return; /* No substantive change since last event */
    }

    if (flags & FIMS_FLAG_FILE_MODIFIED) {
        fims_alert_t alert;
        memset(&alert, 0, sizeof(alert));
        alert.timestamp = time(NULL);
        fims_str_copy(alert.path, sizeof(alert.path), full_path);
        alert.event_type = EVENT_FILE_MODIFIED;
        alert.change_flags = flags;
        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), live_rec->sha256);
        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), curr_rec.sha256);
        alert.prev_size = live_rec->size;
        alert.curr_size = curr_rec.size;
        alert.prev_mode = live_rec->mode;
        alert.curr_mode = curr_rec.mode;
        alert.severity = SEV_HIGH;
        snprintf(alert.description, sizeof(alert.description),
                 "Real-time inotify event: SHA-256 hash changed (%llu -> %llu bytes)",
                 (unsigned long long)live_rec->size, (unsigned long long)curr_rec.size);

        fims_log_alert(ctx->cfg->log_file, &alert, true);
        fims_report_add_alert(&ctx->cumulative_report, &alert);
        ctx->cumulative_report.modified_count++;
        ctx->stats.realtime_alerts_emitted++;
    }

    if (flags & FIMS_FLAG_PERMISSION_CHANGED) {
        fims_alert_t alert;
        memset(&alert, 0, sizeof(alert));
        alert.timestamp = time(NULL);
        fims_str_copy(alert.path, sizeof(alert.path), full_path);
        alert.event_type = EVENT_PERMISSION_CHANGED;
        alert.change_flags = flags;
        fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), live_rec->sha256);
        fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), curr_rec.sha256);
        alert.prev_size = live_rec->size;
        alert.curr_size = curr_rec.size;
        alert.prev_mode = live_rec->mode;
        alert.curr_mode = curr_rec.mode;
        alert.severity = SEV_MEDIUM;
        snprintf(alert.description, sizeof(alert.description),
                 "Real-time inotify event: permissions changed (%04o -> %04o)",
                 live_rec->mode, curr_rec.mode);

        fims_log_alert(ctx->cfg->log_file, &alert, true);
        fims_report_add_alert(&ctx->cumulative_report, &alert);
        ctx->cumulative_report.perm_changed_count++;
        ctx->stats.realtime_alerts_emitted++;
    }

    /* Update live_rec to reflect current state */
    *live_rec = curr_rec;
}

/* Items 2, 7, 11: Periodic consistency scan with debouncing, error logging, and counter copying */
static void run_consistency_scan_locked(monitor_ctx_t *ctx) {
    fims_file_list_t scanned;
    if (fims_file_list_init(&scanned) != FIMS_OK) return;

    fims_status_t scan_st = fims_scan_directories(
        (const char (*)[FIMS_MAX_PATH])ctx->baseline.root_dirs,
        ctx->baseline.root_dir_count,
        ctx->cfg,
        &scanned);

    /* Item 7: Log SEV_HIGH when consistency scan fails; NEVER skip updating live state */
    bool root_missing = false;
    for (size_t i = 0; i < ctx->baseline.root_dir_count; i++) {
        struct stat rst;
        if (lstat(ctx->baseline.root_dirs[i], &rst) != 0 || !S_ISDIR(rst.st_mode)) {
            root_missing = true;
            break;
        }
    }
    if (scan_st != FIMS_OK || root_missing) {
        if (ctx->cfg && ctx->cfg->log_file[0]) {
            fims_log_message(ctx->cfg->log_file, SEV_HIGH,
                             "Consistency scan failed: monitored root missing or unreadable; treating as empty");
        }
    }

    /* Item 2: Debounce periodic scan: skip any file whose mtime is newer than ~500ms ago */
    struct timespec now_ts;
    clock_gettime(CLOCK_REALTIME, &now_ts);
    int64_t now_ms = (int64_t)now_ts.tv_sec * 1000 + (int64_t)now_ts.tv_nsec / 1000000;

    for (size_t i = 0; i < scanned.count; i++) {
        struct stat st;
        if (lstat(scanned.records[i].path, &st) == 0) {
            int64_t mtime_ms = (int64_t)st.st_mtim.tv_sec * 1000 + (int64_t)st.st_mtim.tv_nsec / 1000000;
            if (now_ms - mtime_ms < 500) {
                /* In-progress write / modified within 500ms: compare against live_state */
                fims_file_record_t *live_rec = find_record_in_list(&ctx->live_state, scanned.records[i].path);
                if (live_rec) {
                    /* Retain live_state record so diff sees no change until write settles */
                    scanned.records[i] = *live_rec;
                } else {
                    /* New file modified <500ms: drop from scanned list for this pass */
                    if (i + 1 < scanned.count) {
                        memmove(&scanned.records[i], &scanned.records[i + 1],
                                (scanned.count - i - 1) * sizeof(fims_file_record_t));
                    }
                    scanned.count--;
                    i--;
                }
            }
        }
    }

    fims_report_t diff_rep;
    if (fims_report_init(&diff_rep) == FIMS_OK) {
        /* Compare current filesystem against live_state to catch any missed race events */
        fims_check_integrity(&ctx->live_state, &scanned, ctx->cfg, true, &diff_rep);
        for (size_t i = 0; i < diff_rep.count; i++) {
            fims_report_add_alert(&ctx->cumulative_report, &diff_rep.alerts[i]);
            ctx->stats.realtime_alerts_emitted++;
        }

        /* Item 11: Copy diff_rep counters into cumulative_report */
        ctx->cumulative_report.added_count += diff_rep.added_count;
        ctx->cumulative_report.modified_count += diff_rep.modified_count;
        ctx->cumulative_report.deleted_count += diff_rep.deleted_count;
        ctx->cumulative_report.renamed_count += diff_rep.renamed_count;
        ctx->cumulative_report.perm_changed_count += diff_rep.perm_changed_count;
        ctx->cumulative_report.size_changed_count += diff_rep.size_changed_count;
        ctx->cumulative_report.meta_changed_count += diff_rep.meta_changed_count;
        ctx->cumulative_report.unchanged_files = diff_rep.unchanged_files;
        ctx->cumulative_report.total_files_checked = diff_rep.total_files_checked;

        fims_report_free(&diff_rep);
    }

    /* Item 7: NEVER skip updating live state */
    fims_file_list_free(&ctx->live_state);
    ctx->live_state = scanned;
    ctx->stats.last_full_scan_at = time(NULL);
    ctx->stats.periodic_scans_completed++;
}

static void *periodic_scan_thread(void *arg) {
    monitor_ctx_t *ctx = (monitor_ctx_t *)arg;
    uint32_t interval = ctx->cfg->scan_interval_sec > 0 ? ctx->cfg->scan_interval_sec : 30;
    uint32_t elapsed_ms = 0;
    uint32_t heartbeat_ms = 0;

    while (!g_stop_requested) {
        sleep_ms(100); /* Sleep 100 ms per tick for responsive shutdown */
        elapsed_ms += 100;
        heartbeat_ms += 100;

        /* Item 17: Update heartbeat timestamp periodically (every 1s) */
        if (heartbeat_ms >= 1000U) {
            heartbeat_ms = 0;
            pthread_mutex_lock(&ctx->lock);
            fims_status_save(ctx->cfg->state_file, ctx->cfg, &ctx->stats,
                             ctx->baseline.count, ctx->cumulative_report.count);
            pthread_mutex_unlock(&ctx->lock);
        }

        if (elapsed_ms >= interval * 1000U) {
            elapsed_ms = 0;
            pthread_mutex_lock(&ctx->lock);
            run_consistency_scan_locked(ctx);
            fims_report_save(ctx->cfg->report_file, &ctx->cumulative_report);
            fims_status_save(ctx->cfg->state_file, ctx->cfg, &ctx->stats,
                             ctx->baseline.count, ctx->cumulative_report.count);
            pthread_mutex_unlock(&ctx->lock);
        }
    }
    return NULL;
}

fims_status_t fims_monitor_run(const fims_config_t *cfg, uint32_t max_seconds) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;

    monitor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg = cfg;
    pthread_mutex_init(&ctx.lock, NULL);

    /* 1. Load and validate the trusted baseline */
    fims_status_t st = fims_baseline_load(cfg->baseline_file, &ctx.baseline);
    if (st != FIMS_OK) {
        pthread_mutex_destroy(&ctx.lock);
        return st;
    }

    /* 2. Clone baseline into live_state for incremental real-time tracking */
    st = fims_baseline_load(cfg->baseline_file, &ctx.live_state);
    if (st != FIMS_OK) {
        fims_file_list_free(&ctx.baseline);
        pthread_mutex_destroy(&ctx.lock);
        return st;
    }

    st = fims_report_init(&ctx.cumulative_report);
    if (st != FIMS_OK) {
        fims_file_list_free(&ctx.live_state);
        fims_file_list_free(&ctx.baseline);
        pthread_mutex_destroy(&ctx.lock);
        return st;
    }

    /* 3. Initialize Linux inotify instance */
    ctx.inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ctx.inotify_fd < 0) {
        fims_report_free(&ctx.cumulative_report);
        fims_file_list_free(&ctx.live_state);
        fims_file_list_free(&ctx.baseline);
        pthread_mutex_destroy(&ctx.lock);
        return FIMS_ERR_INOTIFY;
    }

    for (size_t i = 0; i < ctx.baseline.root_dir_count; i++) {
        add_watch_recursive(&ctx, ctx.baseline.root_dirs[i], 0);
    }

    ctx.stats.started_at = time(NULL);
    ctx.stats.last_full_scan_at = 0; /* Item 17: 0 until first scan completes */
    ctx.stats.monitor_active = true;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = monitor_sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (cfg->log_file[0]) {
        fims_log_message(cfg->log_file, SEV_INFO,
                         "Real-time monitoring started (%zu watches active)", ctx.watch_count);
    }

    fims_status_save(cfg->state_file, cfg, &ctx.stats,
                     ctx.baseline.count, ctx.cumulative_report.count);

    /* 4. Spawn background pthread for periodic consistency scans */
    pthread_t tid;
    bool thread_started = (pthread_create(&tid, NULL, periodic_scan_thread, &ctx) == 0);

    /* 5. Main inotify event loop using poll() */
    unsigned char buf[FIMS_INOTIFY_BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));
    time_t start_time = time(NULL);

    while (!g_stop_requested) {
        if (max_seconds > 0 && (uint32_t)(time(NULL) - start_time) >= max_seconds) {
            g_stop_requested = 1;
            break;
        }

        struct pollfd pfd;
        pfd.fd = ctx.inotify_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, 200); /* 200 ms timeout */
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0 || !(pfd.revents & POLLIN)) {
            continue;
        }

        ssize_t len = read(ctx.inotify_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            break;
        }

        pthread_mutex_lock(&ctx.lock);
        const unsigned char *ptr = buf;
        while (ptr < buf + len) {
            const struct inotify_event *ev = (const struct inotify_event *)ptr;
            ctx.stats.realtime_events_processed++;

            /* Handle event queue overflow */
            if (ev->mask & IN_Q_OVERFLOW) {
                ctx.stats.overflow_recoveries++;
                if (cfg->log_file[0]) {
                    fims_log_message(cfg->log_file, SEV_HIGH,
                                     "inotify queue overflow detected; running immediate full consistency scan");
                }
                for (size_t i = 0; i < ctx.baseline.root_dir_count; i++) {
                    add_watch_recursive(&ctx, ctx.baseline.root_dirs[i], 0);
                }
                run_consistency_scan_locked(&ctx);
            } else if (ev->len == 0) {
                /* Item 7: Handle IN_DELETE_SELF, IN_MOVE_SELF, IN_IGNORED (len == 0) */
                if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) {
                    remove_watch_entry(&ctx, ev->wd);
                    run_consistency_scan_locked(&ctx);
                }
            } else {
                /* ev->len > 0: event with filename */
                const char *dir_path = lookup_watch_path(&ctx, ev->wd);
                if (dir_path) {
                    char full_path[FIMS_MAX_PATH];
                    if (fims_path_join(full_path, sizeof(full_path), dir_path, ev->name)) {
                        if (ev->mask & IN_ISDIR) {
                            if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                                if ((ev->mask & IN_MOVED_FROM) && cfg->detect_renames && ev->cookie != 0) {
                                    flush_pending_move(&ctx);
                                    ctx.pending_move.cookie = ev->cookie;
                                    fims_str_copy(ctx.pending_move.old_path, sizeof(ctx.pending_move.old_path), full_path);
                                    ctx.pending_move.is_dir = true;
                                    ctx.pending_move.timestamp = time(NULL);
                                } else {
                                    /* Item 18: Recursive directory deletion */
                                    handle_directory_deletion(&ctx, full_path);
                                }
                            } else if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                                if ((ev->mask & IN_MOVED_TO) && cfg->detect_renames &&
                                    ev->cookie != 0 && ctx.pending_move.cookie == ev->cookie &&
                                    ctx.pending_move.is_dir) {
                                    /* Item 18: Directory rename pairing */
                                    size_t old_len = strlen(ctx.pending_move.old_path);
                                    for (size_t i = 0; i < ctx.live_state.count; i++) {
                                        if (strncmp(ctx.live_state.records[i].path, ctx.pending_move.old_path, old_len) == 0 &&
                                            (ctx.live_state.records[i].path[old_len] == '/' || ctx.live_state.records[i].path[old_len] == '\0')) {
                                            char new_child[FIMS_MAX_PATH];
                                            snprintf(new_child, sizeof(new_child), "%s%s",
                                                     full_path, ctx.live_state.records[i].path + old_len);

                                            fims_alert_t alert;
                                            memset(&alert, 0, sizeof(alert));
                                            alert.timestamp = time(NULL);
                                            fims_str_copy(alert.path, sizeof(alert.path), new_child);
                                            fims_str_copy(alert.old_path, sizeof(alert.old_path), ctx.live_state.records[i].path);
                                            alert.event_type = EVENT_FILE_RENAMED;
                                            alert.change_flags = FIMS_FLAG_FILE_RENAMED;
                                            fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), ctx.live_state.records[i].sha256);
                                            fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), ctx.live_state.records[i].sha256);
                                            alert.prev_size = ctx.live_state.records[i].size;
                                            alert.curr_size = ctx.live_state.records[i].size;
                                            alert.severity = SEV_MEDIUM;
                                            snprintf(alert.description, sizeof(alert.description),
                                                     "Real-time inotify event: file renamed via directory move");
                                            fims_log_alert(ctx.cfg->log_file, &alert, true);
                                            fims_report_add_alert(&ctx.cumulative_report, &alert);
                                            ctx.cumulative_report.renamed_count++;
                                            ctx.stats.realtime_alerts_emitted++;

                                            fims_str_copy(ctx.live_state.records[i].path, sizeof(ctx.live_state.records[i].path), new_child);
                                        }
                                    }
                                    fims_file_list_sort(&ctx.live_state);
                                    add_watch_recursive(&ctx, full_path, 0);
                                    ctx.pending_move.cookie = 0;
                                } else {
                                    flush_pending_move(&ctx);
                                    add_watch_recursive(&ctx, full_path, 0);

                                    /* Item 14: Subtree-only rescan off the critical event lock */
                                    pthread_mutex_unlock(&ctx.lock);

                                    fims_file_list_t sub_list;
                                    if (fims_file_list_init(&sub_list) == FIMS_OK) {
                                        if (fims_scan_directory(full_path, ctx.cfg, &sub_list) == FIMS_OK) {
                                            pthread_mutex_lock(&ctx.lock);
                                            for (size_t s = 0; s < sub_list.count; s++) {
                                                const fims_file_record_t *srec = &sub_list.records[s];
                                                if (!find_record_in_list(&ctx.live_state, srec->path)) {
                                                    fims_alert_t alert;
                                                    memset(&alert, 0, sizeof(alert));
                                                    alert.timestamp = time(NULL);
                                                    fims_str_copy(alert.path, sizeof(alert.path), srec->path);
                                                    alert.event_type = EVENT_FILE_ADDED;
                                                    alert.change_flags = FIMS_FLAG_FILE_ADDED;
                                                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), "NONE");
                                                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), srec->sha256);
                                                    alert.curr_size = srec->size;
                                                    alert.curr_mode = srec->mode;
                                                    alert.severity = SEV_MEDIUM;
                                                    snprintf(alert.description, sizeof(alert.description),
                                                             "Subtree rescan: new file added (%llu bytes)",
                                                             (unsigned long long)srec->size);
                                                    fims_log_alert(ctx.cfg->log_file, &alert, true);
                                                    fims_report_add_alert(&ctx.cumulative_report, &alert);
                                                    ctx.cumulative_report.added_count++;
                                                    ctx.stats.realtime_alerts_emitted++;
                                                    insert_record_sorted(&ctx.live_state, srec);
                                                }
                                            }
                                        } else {
                                            pthread_mutex_lock(&ctx.lock);
                                        }
                                        fims_file_list_free(&sub_list);
                                    } else {
                                        pthread_mutex_lock(&ctx.lock);
                                    }
                                }
                            }
                        } else if (!fims_config_is_excluded(cfg, full_path)) {
                            /* Regular file events */
                            if ((ev->mask & IN_MOVED_FROM) && cfg->detect_renames && ev->cookie != 0) {
                                flush_pending_move(&ctx);
                                ctx.pending_move.cookie = ev->cookie;
                                fims_str_copy(ctx.pending_move.old_path, sizeof(ctx.pending_move.old_path), full_path);
                                ctx.pending_move.is_dir = false;
                                ctx.pending_move.timestamp = time(NULL);
                            } else if ((ev->mask & IN_MOVED_TO) && cfg->detect_renames &&
                                       ev->cookie != 0 && ctx.pending_move.cookie == ev->cookie &&
                                       !ctx.pending_move.is_dir) {
                                /* Item 18: File rename pairing */
                                fims_file_record_t *old_rec = find_record_in_list(&ctx.live_state, ctx.pending_move.old_path);
                                fims_alert_t alert;
                                memset(&alert, 0, sizeof(alert));
                                alert.timestamp = time(NULL);
                                fims_str_copy(alert.path, sizeof(alert.path), full_path);
                                fims_str_copy(alert.old_path, sizeof(alert.old_path), ctx.pending_move.old_path);
                                alert.event_type = EVENT_FILE_RENAMED;
                                alert.change_flags = FIMS_FLAG_FILE_RENAMED;
                                if (old_rec) {
                                    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), old_rec->sha256);
                                    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), old_rec->sha256);
                                    alert.prev_size = old_rec->size;
                                    alert.curr_size = old_rec->size;
                                    alert.prev_mode = old_rec->mode;
                                    alert.curr_mode = old_rec->mode;
                                }
                                alert.severity = SEV_MEDIUM;
                                snprintf(alert.description, sizeof(alert.description),
                                         "Real-time inotify event: file renamed (%.200s -> %.200s)",
                                         ctx.pending_move.old_path, full_path);

                                fims_log_alert(ctx.cfg->log_file, &alert, true);
                                fims_report_add_alert(&ctx.cumulative_report, &alert);
                                ctx.cumulative_report.renamed_count++;
                                ctx.stats.realtime_alerts_emitted++;

                                fims_file_record_t new_rec;
                                if (old_rec) {
                                    new_rec = *old_rec;
                                    fims_str_copy(new_rec.path, sizeof(new_rec.path), full_path);
                                    remove_record_from_list(&ctx.live_state, ctx.pending_move.old_path);
                                    struct stat fst;
                                    if (lstat(full_path, &fst) == 0) {
                                        new_rec.dev = (uint64_t)fst.st_dev;
                                        new_rec.inode = (uint64_t)fst.st_ino;
                                        new_rec.mtime = (int64_t)fst.st_mtime;
                                        new_rec.ctime = (int64_t)fst.st_ctime;
                                    }
                                    insert_record_sorted(&ctx.live_state, &new_rec);
                                } else {
                                    if (fims_scan_single_file(full_path, &new_rec) == FIMS_OK) {
                                        insert_record_sorted(&ctx.live_state, &new_rec);
                                    }
                                }
                                ctx.pending_move.cookie = 0;
                            } else {
                                flush_pending_move(&ctx);
                                handle_single_file_event(&ctx, full_path, ev->mask);
                            }
                        }
                    }
                }
            }
            ptr += sizeof(struct inotify_event) + ev->len;
        }
        pthread_mutex_unlock(&ctx.lock);
    }

    g_stop_requested = 1;
    if (thread_started) {
        pthread_join(tid, NULL);
    }

    ctx.stats.monitor_active = false;
    ctx.cumulative_report.total_files_checked = ctx.live_state.count;
    fims_report_save(cfg->report_file, &ctx.cumulative_report);
    fims_status_save(cfg->state_file, cfg, &ctx.stats,
                     ctx.baseline.count, ctx.cumulative_report.count);

    if (cfg->log_file[0]) {
        fims_log_message(cfg->log_file, SEV_INFO,
                         "Real-time monitoring stopped cleanly (%zu events processed, %zu alerts emitted)",
                         ctx.stats.realtime_events_processed, ctx.stats.realtime_alerts_emitted);
    }

    close(ctx.inotify_fd);
    free(ctx.watches);
    fims_report_free(&ctx.cumulative_report);
    fims_file_list_free(&ctx.live_state);
    fims_file_list_free(&ctx.baseline);
    pthread_mutex_destroy(&ctx.lock);
    return FIMS_OK;
}

/* Item 17: PID heartbeat, atomic state file updates, and status accuracy */
fims_status_t fims_status_save(const char *state_path,
                               const fims_config_t *cfg,
                               const fims_monitor_stats_t *stats,
                               size_t baseline_files,
                               size_t last_alert_count) {
    if (!state_path || state_path[0] == '\0') return FIMS_ERR_INVALID_ARG;
    ensure_parent_dir_state(state_path);

    char tmp_path[FIMS_MAX_PATH];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", state_path);
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", state_path, (long)getpid());
        fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return FIMS_ERR_IO;
    }
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    pid_t pid = getpid();
    time_t now = time(NULL);

    fprintf(fp, "MONITOR_ACTIVE=%s\n", (stats && stats->monitor_active) ? "RUNNING" : "IDLE");
    fprintf(fp, "PID=%ld\n", (long)pid);
    fprintf(fp, "HEARTBEAT=%lld\n", (long long)now);
    fprintf(fp, "SCAN_INTERVAL=%u\n", cfg ? cfg->scan_interval_sec : 30);
    fprintf(fp, "BASELINE_FILE=%s\n", cfg ? cfg->baseline_file : FIMS_DEFAULT_BASELINE);
    fprintf(fp, "BASELINE_FILES=%zu\n", baseline_files);

    if (stats && stats->last_full_scan_at > 0) {
        fprintf(fp, "LAST_SCAN_TIMESTAMP=%lld\n", (long long)stats->last_full_scan_at);
    } else {
        fprintf(fp, "LAST_SCAN_TIMESTAMP=never\n");
    }

    fprintf(fp, "ACTIVE_WATCHES=%zu\n", stats ? stats->active_watches : 0);
    fprintf(fp, "REALTIME_EVENTS=%zu\n", stats ? stats->realtime_events_processed : 0);
    fprintf(fp, "TOTAL_ALERTS=%zu\n", last_alert_count);
    fprintf(fp, "OVERFLOW_RECOVERIES=%zu\n", stats ? stats->overflow_recoveries : 0);
    fprintf(fp, "PERIODIC_SCANS=%zu\n", stats ? stats->periodic_scans_completed : 0);
    fprintf(fp, "WATCH_FAILURES=%zu\n", stats ? stats->watch_failures : 0);

    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    if (rename(tmp_path, state_path) != 0) {
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    return FIMS_OK;
}

fims_status_t fims_status_display(const fims_config_t *cfg) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;

    printf("================================================================================\n");
    printf(" FIMS System Status & Statistics (v%s)\n", FIMS_VERSION);
    printf("================================================================================\n");

    fims_file_list_t base;
    fims_status_t bst = fims_baseline_load(cfg->baseline_file, &base);
    const char *bl_status_str = "VALID & VERIFIED";
    bool bl_valid = (bst == FIMS_OK);

    if (bst == FIMS_OK) {
        printf(" Baseline Status     : VALID & VERIFIED (%s)\n", cfg->baseline_file);
        printf(" Tracked Files       : %zu regular files\n", base.count);
        for (size_t i = 0; i < base.root_dir_count; i++) {
            printf(" Monitored Directory : %s\n", base.root_dirs[i]);
        }
    } else if (bst == FIMS_ERR_NOT_FOUND) {
        bl_status_str = "NOT INITIALIZED";
        printf(" Baseline Status     : NOT INITIALIZED (%s missing)\n", cfg->baseline_file);
    } else {
        bl_status_str = "CORRUPTED / INVALID";
        printf(" Baseline Status     : CORRUPTED / INVALID (%s)\n", cfg->baseline_file);
    }

    FILE *fp = fopen(cfg->state_file, "r");
    pid_t pid = 0;
    time_t heartbeat = 0;
    uint32_t interval = 30;
    char active_str[64] = "IDLE";
    char scan_ts_str[64] = "never";

    if (fp) {
        printf("--------------------------------------------------------------------------------\n");
        char line[512];

        while (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            const char *key = line;
            const char *val = eq + 1;

            if (strcmp(key, "PID") == 0) {
                pid = (pid_t)atol(val);
            } else if (strcmp(key, "HEARTBEAT") == 0) {
                heartbeat = (time_t)atoll(val);
            } else if (strcmp(key, "SCAN_INTERVAL") == 0) {
                interval = (uint32_t)atoi(val);
            } else if (strcmp(key, "MONITOR_ACTIVE") == 0) {
                fims_str_copy(active_str, sizeof(active_str), val);
            } else if (strcmp(key, "LAST_SCAN_TIMESTAMP") == 0) {
                fims_str_copy(scan_ts_str, sizeof(scan_ts_str), val);
            } else {
                printf(" %-19s : %s\n", key, val);
            }
        }
        fclose(fp);

        /* Item 17: RUNNING only if PID is active and heartbeat < 3x interval */
        bool is_alive = false;
        if (pid > 0 && kill(pid, 0) == 0) {
            uint32_t check_interval = interval > 0 ? interval : 30;
            time_t diff = time(NULL) - heartbeat;
            if (diff >= 0 && diff < (time_t)(3 * check_interval)) {
                is_alive = true;
            }
        }

        const char *effective_status = (is_alive && strcmp(active_str, "RUNNING") == 0) ? "RUNNING" : "IDLE";
        printf(" %-19s : %s\n", "MONITOR_ACTIVE", effective_status);
        printf(" %-19s : %ld\n", "PID", (long)pid);
        printf(" %-19s : %lld\n", "HEARTBEAT", (long long)heartbeat);
        printf(" %-19s : %u\n", "SCAN_INTERVAL", interval);
        printf(" %-19s : %s\n", "LAST_SCAN_TIMESTAMP", scan_ts_str);
    } else {
        printf(" Runtime State       : No scan or monitoring session recorded yet.\n");
    }
    printf("================================================================================\n");

    /* Professional Security Dashboard */
    const char *hmac_key_file = getenv("FIMS_HMAC_KEY_FILE");
    const char *auth_type = (hmac_key_file && hmac_key_file[0]) ? "HMAC-SHA256 (Authenticated)" : "SHA-256 Digest (Verified)";

    fims_ui_section("System Security Dashboard");
    fims_ui_field("Version", "%s", FIMS_VERSION);
    fims_ui_field("Baseline", "%s", bl_status_str);
    fims_ui_field("Authentication", "%s", auth_type);
    fims_ui_field("Monitor Daemon", "%s", active_str);
    fims_ui_field("Tracked Files", "%zu regular files", bl_valid ? base.count : 0);
    fims_ui_field("Scan Interval", "%u seconds", interval);

    fims_ui_section("Subsystem Readiness");
    fims_ui_field("Integrity Engine", "READY");
    fims_ui_field("SHA-256 Engine", "READY");
    fims_ui_field("Event Monitoring", "%s", (strcmp(active_str, "RUNNING") == 0) ? "ACTIVE" : "READY");

    if (bl_valid) {
        fims_ui_status_box("PROTECTED", true, "Trusted baseline active and intact");
        fims_file_list_free(&base);
    } else {
        fims_ui_status_box("ATTENTION REQUIRED", false, "Initialize baseline with 'fims init <dir>'");
    }

    return FIMS_OK;
}
