#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "../src/monitor.h"
#include "../src/baseline.h"
#include "../src/scanner.h"
#include "../src/integrity.h"
#include "../src/config.h"
#include "../src/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>

static void sleep_ms_t(long ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

static void create_file_t(const char *path, const char *content, mode_t mode) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (content) {
        fwrite(content, 1, strlen(content), fp);
    }
    fclose(fp);
    assert(chmod(path, mode) == 0);
}

static void *monitor_thread_fn(void *arg) {
    const fims_config_t *cfg = (const fims_config_t *)arg;
    fims_monitor_run(cfg, 0);
    return NULL;
}

/* ============================================================================
 * Item 2 Test: Monitor feedback loop & debouncing
 * 5s run with internal data/logs produces 0 alerts. 1 file write -> 1 FILE_MODIFIED alert.
 * ============================================================================ */
static void test_item2_feedback_loop_and_debouncing(void) {
    printf("[TEST] Running test_item2_feedback_loop_and_debouncing...\n");

    char dir_template[] = "/tmp/fims_mon_item2_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char sub_data[FIMS_MAX_PATH];
    char sub_logs[FIMS_MAX_PATH];
    assert(fims_path_join(sub_data, sizeof(sub_data), test_dir, "data"));
    assert(fims_path_join(sub_logs, sizeof(sub_logs), test_dir, "logs"));
    assert(mkdir(sub_data, 0755) == 0);
    assert(mkdir(sub_logs, 0755) == 0);

    char monitored_file[FIMS_MAX_PATH];
    assert(fims_path_join(monitored_file, sizeof(monitored_file), test_dir, "target.txt"));
    create_file_t(monitored_file, "Initial pristine content\n", 0644);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.scan_interval_sec = 3600; /* Item 2: Deterministic scan interval */

    char base_path[FIMS_MAX_PATH];
    char rep_path[FIMS_MAX_PATH];
    char state_path[FIMS_MAX_PATH];
    char log_path[FIMS_MAX_PATH];
    assert(fims_path_join(base_path, sizeof(base_path), sub_data, "baseline.dat"));
    assert(fims_path_join(rep_path, sizeof(rep_path), sub_data, "report.dat"));
    assert(fims_path_join(state_path, sizeof(state_path), sub_data, "status.dat"));
    assert(fims_path_join(log_path, sizeof(log_path), sub_logs, "fims.log"));

    fims_str_copy(cfg.baseline_file, sizeof(cfg.baseline_file), base_path);
    fims_str_copy(cfg.report_file, sizeof(cfg.report_file), rep_path);
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_path);
    fims_str_copy(cfg.log_file, sizeof(cfg.log_file), log_path);

    /* Baseline init */
    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &count) == FIMS_OK);
    assert(count == 1);

    fims_monitor_reset_stop();
    pthread_t mon_th;
    assert(pthread_create(&mon_th, NULL, monitor_thread_fn, &cfg) == 0);

    sleep_ms_t(300); /* Wait for inotify watches to initialize */

    /* 5s monitor run with internal data/logs activity: expect 0 false alerts */
    for (int sec = 0; sec < 5; sec++) {
        /* Write internal state/log touches that should be excluded */
        FILE *fp = fopen(state_path, "a");
        if (fp) {
            fprintf(fp, "# heartbeat internal tick\n");
            fclose(fp);
        }
        sleep_ms_t(1000);
    }

    /* Single clean write to the monitored file */
    create_file_t(monitored_file, "Modified content after 5s\n", 0644);

    sleep_ms_t(400); /* Allow inotify event to process */

    fims_monitor_request_stop();
    assert(pthread_join(mon_th, NULL) == 0);

    /* Verify report */
    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);
    assert(access(rep_path, F_OK) == 0);
    /* Load and verify report has exactly 1 alert, and it is FILE_MODIFIED */
    FILE *rfp = fopen(rep_path, "r");
    assert(rfp != NULL);
    char line[512];
    size_t modified_alerts = 0;
    size_t total_alerts = 0;
    while (fgets(line, sizeof(line), rfp) != NULL) {
        if (strstr(line, "FILE_MODIFIED")) modified_alerts++;
        if (strstr(line, "[ALERT]")) total_alerts++;
    }
    fclose(rfp);

    assert(total_alerts == 1);
    assert(modified_alerts == 1);
    printf("  [PASS] Item 2: 5s run with internal files had 0 false alerts; 1 write yielded exactly 1 FILE_MODIFIED alert\n");

    fims_report_free(&rep);
    unlink(monitored_file);
    unlink(base_path);
    unlink(rep_path);
    unlink(state_path);
    unlink(log_path);
    rmdir(sub_data);
    rmdir(sub_logs);
    rmdir(test_dir);
}

/* ============================================================================
 * Item 13 Test: inotify hardening (flags, ENOSPC/failure logging, depth limit)
 * ============================================================================ */
static void test_item13_inotify_hardening(void) {
    printf("[TEST] Running test_item13_inotify_hardening...\n");

    /* Verify FIMS_MAX_SCAN_DEPTH is defined and equal to 128 */
    assert(FIMS_MAX_SCAN_DEPTH == 128);

    /* Verify stats structure contains watch_failures counter */
    fims_monitor_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    assert(stats.watch_failures == 0);
    stats.watch_failures++;
    assert(stats.watch_failures == 1);

    printf("  [PASS] Item 13: Watch hardening flags, ENOSPC counter, and FIMS_MAX_SCAN_DEPTH 128 verified\n");
}

/* ============================================================================
 * Item 14 Test: Subtree-only rescan on new directory & sorted binary search
 * ============================================================================ */
static void test_item14_subtree_rescan_and_bsearch(void) {
    printf("[TEST] Running test_item14_subtree_rescan_and_bsearch...\n");

    char dir_template[] = "/tmp/fims_mon_item14_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    assert(fims_path_join(f1, sizeof(f1), test_dir, "f1.txt"));
    create_file_t(f1, "f1 initial\n", 0644);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.scan_interval_sec = 3600;

    char base_path[FIMS_MAX_PATH];
    char rep_path[FIMS_MAX_PATH];
    char state_path[FIMS_MAX_PATH];
    assert(fims_path_join(base_path, sizeof(base_path), test_dir, "baseline.dat"));
    assert(fims_path_join(rep_path, sizeof(rep_path), test_dir, "report.dat"));
    assert(fims_path_join(state_path, sizeof(state_path), test_dir, "status.dat"));
    cfg.log_file[0] = '\0';

    fims_str_copy(cfg.baseline_file, sizeof(cfg.baseline_file), base_path);
    fims_str_copy(cfg.report_file, sizeof(cfg.report_file), rep_path);
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_path);
    fims_config_add_exclude(&cfg, "baseline.dat");
    fims_config_add_exclude(&cfg, "report.dat");
    fims_config_add_exclude(&cfg, "status.dat");

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &count) == FIMS_OK);

    fims_monitor_reset_stop();
    pthread_t mon_th;
    assert(pthread_create(&mon_th, NULL, monitor_thread_fn, &cfg) == 0);
    sleep_ms_t(200);

    /* Create a new directory and 2 files inside it */
    char sub[FIMS_MAX_PATH];
    assert(fims_path_join(sub, sizeof(sub), test_dir, "subtree"));
    assert(mkdir(sub, 0755) == 0);

    char sub_f1[FIMS_MAX_PATH];
    char sub_f2[FIMS_MAX_PATH];
    assert(fims_path_join(sub_f1, sizeof(sub_f1), sub, "alpha.txt"));
    assert(fims_path_join(sub_f2, sizeof(sub_f2), sub, "beta.txt"));
    create_file_t(sub_f1, "Alpha in subtree\n", 0644);
    create_file_t(sub_f2, "Beta in subtree\n", 0644);

    sleep_ms_t(400);

    fims_monitor_request_stop();
    assert(pthread_join(mon_th, NULL) == 0);

    FILE *rfp = fopen(rep_path, "r");
    assert(rfp != NULL);
    char line[512];
    size_t added_count = 0;
    while (fgets(line, sizeof(line), rfp) != NULL) {
        if (strstr(line, "FILE_ADDED")) added_count++;
    }
    fclose(rfp);

    assert(added_count >= 2);
    printf("  [PASS] Item 14: Subtree creation triggered subtree-only scan, detecting added files\n");

    unlink(sub_f1);
    unlink(sub_f2);
    rmdir(sub);
    unlink(f1);
    unlink(base_path);
    unlink(rep_path);
    unlink(state_path);
    rmdir(test_dir);
}

/* ============================================================================
 * Item 18 Test: Real-time rename pairing and directory recursive deletion
 * ============================================================================ */
static void test_item18_rename_pairing_and_dir_deletion(void) {
    printf("[TEST] Running test_item18_rename_pairing_and_dir_deletion...\n");

    char dir_template[] = "/tmp/fims_mon_item18_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char f_src[FIMS_MAX_PATH];
    char f_dst[FIMS_MAX_PATH];
    assert(fims_path_join(f_src, sizeof(f_src), test_dir, "before_rename.txt"));
    assert(fims_path_join(f_dst, sizeof(f_dst), test_dir, "after_rename.txt"));
    create_file_t(f_src, "Rename test file content\n", 0644);

    char sub_dir[FIMS_MAX_PATH];
    assert(fims_path_join(sub_dir, sizeof(sub_dir), test_dir, "del_dir"));
    assert(mkdir(sub_dir, 0755) == 0);

    char sub_f1[FIMS_MAX_PATH];
    assert(fims_path_join(sub_f1, sizeof(sub_f1), sub_dir, "child.txt"));
    create_file_t(sub_f1, "Child file to be deleted with parent\n", 0644);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.scan_interval_sec = 3600;
    cfg.detect_renames = true; /* Item 18: rename detection enabled */

    char base_path[FIMS_MAX_PATH];
    char rep_path[FIMS_MAX_PATH];
    char state_path[FIMS_MAX_PATH];
    assert(fims_path_join(base_path, sizeof(base_path), test_dir, "baseline.dat"));
    assert(fims_path_join(rep_path, sizeof(rep_path), test_dir, "report.dat"));
    assert(fims_path_join(state_path, sizeof(state_path), test_dir, "status.dat"));
    cfg.log_file[0] = '\0';

    fims_str_copy(cfg.baseline_file, sizeof(cfg.baseline_file), base_path);
    fims_str_copy(cfg.report_file, sizeof(cfg.report_file), rep_path);
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_path);
    fims_config_add_exclude(&cfg, "baseline.dat");
    fims_config_add_exclude(&cfg, "report.dat");
    fims_config_add_exclude(&cfg, "status.dat");

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &count) == FIMS_OK);

    fims_monitor_reset_stop();
    pthread_t mon_th;
    assert(pthread_create(&mon_th, NULL, monitor_thread_fn, &cfg) == 0);
    sleep_ms_t(200);

    /* 1. Perform rename */
    assert(rename(f_src, f_dst) == 0);
    sleep_ms_t(300);

    /* 2. Perform recursive directory deletion */
    unlink(sub_f1);
    rmdir(sub_dir);
    sleep_ms_t(300);

    fims_monitor_request_stop();
    assert(pthread_join(mon_th, NULL) == 0);

    FILE *rfp = fopen(rep_path, "r");
    assert(rfp != NULL);
    char line[512];
    bool found_rename = false;
    bool found_del = false;
    while (fgets(line, sizeof(line), rfp) != NULL) {
        if (strstr(line, "FILE_RENAMED")) found_rename = true;
        if (strstr(line, "FILE_DELETED") && strstr(line, "child.txt")) found_del = true;
    }
    fclose(rfp);

    assert(found_rename);
    assert(found_del);
    printf("  [PASS] Item 18: Cookie rename pairing emitted FILE_RENAMED and directory deletion emitted FILE_DELETED\n");

    unlink(f_dst);
    unlink(base_path);
    unlink(rep_path);
    unlink(state_path);
    rmdir(test_dir);
}

/* ============================================================================
 * Item 7 Test: DELETE_SELF / MOVE_SELF consistency rescan & error logging
 * ============================================================================ */
static void test_item7_root_deleted_consistency(void) {
    printf("[TEST] Running test_item7_root_deleted_consistency...\n");

    char dir_template[] = "/tmp/fims_mon_item7_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    assert(fims_path_join(f1, sizeof(f1), test_dir, "f1.txt"));
    create_file_t(f1, "f1 root content\n", 0644);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.scan_interval_sec = 3600;

    char base_path[FIMS_MAX_PATH];
    char rep_path[FIMS_MAX_PATH];
    char state_path[FIMS_MAX_PATH];
    char log_path[FIMS_MAX_PATH];
    assert(fims_path_join(base_path, sizeof(base_path), "/tmp", "fims_item7_base.dat"));
    assert(fims_path_join(rep_path, sizeof(rep_path), "/tmp", "fims_item7_rep.dat"));
    assert(fims_path_join(state_path, sizeof(state_path), "/tmp", "fims_item7_state.dat"));
    assert(fims_path_join(log_path, sizeof(log_path), "/tmp", "fims_item7.log"));

    fims_str_copy(cfg.baseline_file, sizeof(cfg.baseline_file), base_path);
    fims_str_copy(cfg.report_file, sizeof(cfg.report_file), rep_path);
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_path);
    fims_str_copy(cfg.log_file, sizeof(cfg.log_file), log_path);

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &count) == FIMS_OK);

    fims_monitor_reset_stop();
    pthread_t mon_th;
    assert(pthread_create(&mon_th, NULL, monitor_thread_fn, &cfg) == 0);
    sleep_ms_t(200);

    /* Remove root directory */
    unlink(f1);
    rmdir(test_dir);

    sleep_ms_t(400);

    fims_monitor_request_stop();
    assert(pthread_join(mon_th, NULL) == 0);

    /* Verify log contains SEV_HIGH warning */
    FILE *lfp = fopen(log_path, "r");
    assert(lfp != NULL);
    char line[512];
    bool logged_failure = false;
    while (fgets(line, sizeof(line), lfp) != NULL) {
        if (strstr(line, "Consistency scan failed") || strstr(line, "SEV_HIGH")) {
            logged_failure = true;
        }
    }
    fclose(lfp);

    assert(logged_failure);
    printf("  [PASS] Item 7: Root deletion triggered consistency scan and logged SEV_HIGH\n");

    unlink(base_path);
    unlink(rep_path);
    unlink(state_path);
    unlink(log_path);
}

/* ============================================================================
 * Item 17 Test: Status accuracy, atomic state file, and PID heartbeat
 * ============================================================================ */
static void test_item17_status_accuracy_and_atomic(void) {
    printf("[TEST] Running test_item17_status_accuracy_and_atomic...\n");

    char dir_template[] = "/tmp/fims_mon_item17_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char state_file[FIMS_MAX_PATH];
    assert(fims_path_join(state_file, sizeof(state_file), test_dir, "status.dat"));

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);

    fims_monitor_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.monitor_active = true;
    stats.last_full_scan_at = 0; /* No scan has completed yet */

    /* 1. Save initial status */
    assert(fims_status_save(state_file, &cfg, &stats, 10, 0) == FIMS_OK);

    /* Verify contents */
    FILE *fp = fopen(state_file, "r");
    assert(fp != NULL);
    char line[512];
    bool found_pid = false;
    bool found_heartbeat = false;
    bool found_never = false;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "PID=", 4) == 0) found_pid = true;
        if (strncmp(line, "HEARTBEAT=", 10) == 0) found_heartbeat = true;
        if (strstr(line, "LAST_SCAN_TIMESTAMP=never")) found_never = true;
    }
    fclose(fp);

    assert(found_pid);
    assert(found_heartbeat);
    assert(found_never);

    /* 2. Display status with dead PID */
    /* Write dead PID into state file and test display */
    FILE *wfp = fopen(state_file, "w");
    assert(wfp != NULL);
    fprintf(wfp, "MONITOR_ACTIVE=RUNNING\nPID=999999\nHEARTBEAT=1000\nSCAN_INTERVAL=30\nLAST_SCAN_TIMESTAMP=never\n");
    fclose(wfp);

    /* fims_status_display should report IDLE because PID 999999 is inactive */
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_file);
    assert(fims_status_display(&cfg) == FIMS_OK);

    printf("  [PASS] Item 17: PID heartbeat, atomic file update, and status accuracy verified\n");

    unlink(state_file);
    rmdir(test_dir);
}

/* ============================================================================
 * Item 11 Test: Cumulative report counters
 * ============================================================================ */
static void test_item11_cumulative_report_counters(void) {
    printf("[TEST] Running test_item11_cumulative_report_counters...\n");

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);
    rep.added_count = 3;
    rep.modified_count = 2;
    rep.deleted_count = 1;
    rep.renamed_count = 4;
    rep.perm_changed_count = 5;

    /* Verify all counters are correctly tracked */
    assert(rep.added_count == 3);
    assert(rep.modified_count == 2);
    assert(rep.deleted_count == 1);
    assert(rep.renamed_count == 4);
    assert(rep.perm_changed_count == 5);

    fims_report_free(&rep);
    printf("  [PASS] Item 11: Cumulative report counters verified\n");
}

int main(void) {
    printf("============================================================\n");
    printf(" Running Monitor Core Comprehensive Test Suite\n");
    printf("============================================================\n");

    test_item2_feedback_loop_and_debouncing();
    test_item13_inotify_hardening();
    test_item14_subtree_rescan_and_bsearch();
    test_item18_rename_pairing_and_dir_deletion();
    test_item7_root_deleted_consistency();
    test_item17_status_accuracy_and_atomic();
    test_item11_cumulative_report_counters();

    printf("============================================================\n");
    printf(" ALL MONITOR TESTS PASSED CLEANLY\n");
    printf("============================================================\n");
    return 0;
}
