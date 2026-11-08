#include "monitor.h"
#include "scanner.h"
#include "baseline.h"
#include "integrity.h"
#include "logger.h"
#include "config.h"

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
#define FIMS_WATCH_MASK (IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | \
                         IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF)

typedef struct {
    int  wd;
    char path[FIMS_MAX_PATH];
} watch_entry_t;

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

static fims_status_t add_watch_recursive(monitor_ctx_t *ctx, const char *dir_path, int depth) {
    if (!ctx || !dir_path || depth > 64) return FIMS_OK;
    if (ctx->cfg && fims_config_is_excluded(ctx->cfg, dir_path)) return FIMS_OK;

    struct stat st;
    if (lstat(dir_path, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return FIMS_OK;
    }

    int wd = inotify_add_watch(ctx->inotify_fd, dir_path, FIMS_WATCH_MASK);
    if (wd >= 0) {
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

static fims_file_record_t *find_record_in_list(fims_file_list_t *list, const char *path) {
    if (!list || !path) return NULL;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->records[i].path, path) == 0) {
            return &list->records[i];
        }
    }
    return NULL;
}

static void remove_record_from_list(fims_file_list_t *list, const char *path) {
    if (!list || !path) return;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->records[i].path, path) == 0) {
            if (i + 1 < list->count) {
                memmove(&list->records[i], &list->records[i + 1],
                        (list->count - i - 1) * sizeof(fims_file_record_t));
            }
            list->count--;
            return;
        }
    }
}

static void handle_single_file_event(monitor_ctx_t *ctx, const char *full_path, uint32_t mask) {
    if (!ctx || !full_path) return;
    if (ctx->cfg && fims_config_is_excluded(ctx->cfg, full_path)) return;

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

        fims_file_list_append(&ctx->live_state, &curr_rec);
        fims_file_list_sort(&ctx->live_state);
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

static void run_consistency_scan_locked(monitor_ctx_t *ctx) {
    fims_file_list_t scanned;
    if (fims_file_list_init(&scanned) != FIMS_OK) return;

    if (fims_scan_directories((const char (*)[FIMS_MAX_PATH])ctx->baseline.root_dirs,
                              ctx->baseline.root_dir_count,
                              ctx->cfg,
                              &scanned) == FIMS_OK) {
        fims_report_t diff_rep;
        if (fims_report_init(&diff_rep) == FIMS_OK) {
            /* Compare current filesystem against live_state to catch any missed race events */
            fims_check_integrity(&ctx->live_state, &scanned, ctx->cfg, true, &diff_rep);
            for (size_t i = 0; i < diff_rep.count; i++) {
                fims_report_add_alert(&ctx->cumulative_report, &diff_rep.alerts[i]);
                ctx->stats.realtime_alerts_emitted++;
            }
            fims_report_free(&diff_rep);
        }
        /* Synchronize live_state with fresh scan */
        fims_file_list_free(&ctx->live_state);
        ctx->live_state = scanned;
        ctx->stats.last_full_scan_at = time(NULL);
        ctx->stats.periodic_scans_completed++;
    } else {
        fims_file_list_free(&scanned);
    }
}

static void *periodic_scan_thread(void *arg) {
    monitor_ctx_t *ctx = (monitor_ctx_t *)arg;
    uint32_t interval = ctx->cfg->scan_interval_sec > 0 ? ctx->cfg->scan_interval_sec : 30;
    uint32_t elapsed_ms = 0;

    while (!g_stop_requested) {
        sleep_ms(100); /* Sleep 100 ms per tick for responsive shutdown */
        elapsed_ms += 100;
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
    ctx.stats.last_full_scan_at = ctx.stats.started_at;
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

            /* Handle event queue overflow (Requirement 3 Module 5) */
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
            } else if (ev->len > 0) {
                const char *dir_path = lookup_watch_path(&ctx, ev->wd);
                if (dir_path) {
                    char full_path[FIMS_MAX_PATH];
                    if (fims_path_join(full_path, sizeof(full_path), dir_path, ev->name)) {
                        if (ev->mask & IN_ISDIR) {
                            if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                                add_watch_recursive(&ctx, full_path, 0);
                                /* Scan any files immediately placed inside the new subdirectory */
                                run_consistency_scan_locked(&ctx);
                            }
                        } else {
                            handle_single_file_event(&ctx, full_path, ev->mask);
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

fims_status_t fims_status_save(const char *state_path,
                               const fims_config_t *cfg,
                               const fims_monitor_stats_t *stats,
                               size_t baseline_files,
                               size_t last_alert_count) {
    if (!state_path || state_path[0] == '\0') return FIMS_ERR_INVALID_ARG;
    ensure_parent_dir_state(state_path);

    int fd = open(state_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return FIMS_ERR_IO;
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return FIMS_ERR_IO;
    }

    fprintf(fp, "MONITOR_ACTIVE=%s\n", (stats && stats->monitor_active) ? "RUNNING" : "IDLE");
    fprintf(fp, "BASELINE_FILE=%s\n", cfg ? cfg->baseline_file : FIMS_DEFAULT_BASELINE);
    fprintf(fp, "BASELINE_FILES=%zu\n", baseline_files);
    fprintf(fp, "LAST_SCAN_TIMESTAMP=%lld\n",
            (long long)(stats && stats->last_full_scan_at ? stats->last_full_scan_at : time(NULL)));
    fprintf(fp, "ACTIVE_WATCHES=%zu\n", stats ? stats->active_watches : 0);
    fprintf(fp, "REALTIME_EVENTS=%zu\n", stats ? stats->realtime_events_processed : 0);
    fprintf(fp, "TOTAL_ALERTS=%zu\n", last_alert_count);
    fprintf(fp, "OVERFLOW_RECOVERIES=%zu\n", stats ? stats->overflow_recoveries : 0);
    fprintf(fp, "PERIODIC_SCANS=%zu\n", stats ? stats->periodic_scans_completed : 0);
    fclose(fp);
    return FIMS_OK;
}

fims_status_t fims_status_display(const fims_config_t *cfg) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;

    printf("================================================================================\n");
    printf(" FIMS System Status & Statistics (v%s)\n", FIMS_VERSION);
    printf("================================================================================\n");

    fims_file_list_t base;
    fims_status_t bst = fims_baseline_load(cfg->baseline_file, &base);
    if (bst == FIMS_OK) {
        printf(" Baseline Status     : VALID & VERIFIED (%s)\n", cfg->baseline_file);
        printf(" Tracked Files       : %zu regular files\n", base.count);
        for (size_t i = 0; i < base.root_dir_count; i++) {
            printf(" Monitored Directory : %s\n", base.root_dirs[i]);
        }
        fims_file_list_free(&base);
    } else if (bst == FIMS_ERR_NOT_FOUND) {
        printf(" Baseline Status     : NOT INITIALIZED (%s missing)\n", cfg->baseline_file);
    } else {
        printf(" Baseline Status     : CORRUPTED / INVALID (%s)\n", cfg->baseline_file);
    }

    FILE *fp = fopen(cfg->state_file, "r");
    if (fp) {
        printf("--------------------------------------------------------------------------------\n");
        char line[512];
        while (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = '\0';
                printf(" %-19s : %s\n", line, eq + 1);
            }
        }
        fclose(fp);
    } else {
        printf(" Runtime State       : No scan or monitoring session recorded yet.\n");
    }
    printf("================================================================================\n");
    return FIMS_OK;
}
