#include "../src/integrity.h"
#include "../src/baseline.h"
#include "../src/scanner.h"
#include "../src/monitor.h"
#include "../src/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <utime.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>

static void sleep_ms_test(long ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&req, NULL);
}

static void create_file(const char *path, const char *content, mode_t mode) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (content) {
        fwrite(content, 1, strlen(content), fp);
    }
    fclose(fp);
    assert(chmod(path, mode) == 0);
}

static bool has_event(const fims_report_t *rep, fims_event_type_t type, const char *path) {
    for (size_t i = 0; i < rep->count; i++) {
        if (rep->alerts[i].event_type == type && strcmp(rep->alerts[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

static void *monitor_worker_thread(void *arg) {
    const fims_config_t *cfg = (const fims_config_t *)arg;
    fims_monitor_run(cfg, 10);
    return NULL;
}

static void test_default_exclusions_init_scan(void) {
    char dir_template[] = "/tmp/fims_test_defex_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char sub_data[FIMS_MAX_PATH];
    char sub_logs[FIMS_MAX_PATH];
    assert(fims_path_join(sub_data, sizeof(sub_data), test_dir, "data"));
    assert(fims_path_join(sub_logs, sizeof(sub_logs), test_dir, "logs"));
    assert(mkdir(sub_data, 0755) == 0);
    assert(mkdir(sub_logs, 0755) == 0);

    char old_cwd[PATH_MAX];
    assert(getcwd(old_cwd, sizeof(old_cwd)) != NULL);
    assert(chdir(test_dir) == 0);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    fims_path_join(cfg.baseline_file, sizeof(cfg.baseline_file), sub_data, "baseline.dat");
    fims_path_join(cfg.log_file, sizeof(cfg.log_file), sub_logs, "fims.log");
    fims_path_join(cfg.report_file, sizeof(cfg.report_file), sub_data, "report.dat");
    fims_path_join(cfg.state_file, sizeof(cfg.state_file), sub_data, "status.dat");
    fims_path_join(cfg.config_file, sizeof(cfg.config_file), sub_data, "fims.conf");

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);
    assert(fims_config_save(&cfg, NULL) == FIMS_OK);
    assert(fims_status_save(cfg.state_file, &cfg, NULL, count, 0) == FIMS_OK);

    fims_file_list_t baseline;
    assert(fims_baseline_load(cfg.baseline_file, &baseline) == FIMS_OK);
    fims_file_list_t current;
    assert(fims_file_list_init(&current) == FIMS_OK);
    assert(fims_scan_directory(test_dir, &cfg, &current) == FIMS_OK);

    fims_report_t report;
    assert(fims_report_init(&report) == FIMS_OK);
    assert(fims_check_integrity(&baseline, &current, &cfg, false, &report) == FIMS_OK);

    assert(report.count == 0);
    printf("  [PASS] Default exclusions matched (init with data/ and logs/, 0 alerts on scan)\n");

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);

    assert(chdir(old_cwd) == 0);
}

int main(void) {
    printf("[TEST SUITE] Running test_integrity (including real-time monitor interruption test)...\n");

    test_default_exclusions_init_scan();

    char dir_template[] = "/tmp/fims_test_integrity_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char f_unchanged[FIMS_MAX_PATH];
    char f_modified[FIMS_MAX_PATH];
    char f_deleted[FIMS_MAX_PATH];
    char f_perm[FIMS_MAX_PATH];
    char f_meta[FIMS_MAX_PATH];
    char f_added[FIMS_MAX_PATH];

    assert(fims_path_join(f_unchanged, sizeof(f_unchanged), test_dir, "unchanged.txt"));
    assert(fims_path_join(f_modified, sizeof(f_modified), test_dir, "sample.txt"));
    assert(fims_path_join(f_deleted, sizeof(f_deleted), test_dir, "old.txt"));
    assert(fims_path_join(f_perm, sizeof(f_perm), test_dir, "config.txt"));
    assert(fims_path_join(f_meta, sizeof(f_meta), test_dir, "meta.txt"));
    assert(fims_path_join(f_added, sizeof(f_added), test_dir, "new.txt"));

    create_file(f_unchanged, "Stay the same\n", 0644);
    create_file(f_modified, "Original content\n", 0644);
    create_file(f_deleted, "Will be deleted\n", 0644);
    create_file(f_perm, "db_host=localhost\n", 0644);
    create_file(f_meta, "Metadata test file\n", 0644);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.log_file[0] = '\0';

    /* Scan initial baseline */
    fims_file_list_t baseline;
    assert(fims_file_list_init(&baseline) == FIMS_OK);
    assert(fims_scan_directory(test_dir, &cfg, &baseline) == FIMS_OK);
    assert(baseline.count == 5);

    /* Apply modifications:
     * 1. Modify sample.txt (Requirement 7.1) & change size
     * 2. Delete old.txt (Requirement 7.2)
     * 3. Create new.txt (Requirement 7.3)
     * 4. Change permissions of config.txt (Requirement 7.4)
     * 5. Leave unchanged.txt untouched (Requirement 7.5)
     * 6. Change mtime of meta.txt (Metadata change)
     */
    create_file(f_modified, "Modified content with larger size!\n", 0644);
    assert(unlink(f_deleted) == 0);
    create_file(f_added, "Brand new file added\n", 0644);
    assert(chmod(f_perm, 0777) == 0);

    struct utimbuf new_times;
    new_times.actime = 1000000;
    new_times.modtime = 1000000;
    assert(utime(f_meta, &new_times) == 0);

    /* Scan current state */
    fims_file_list_t current;
    assert(fims_file_list_init(&current) == FIMS_OK);
    assert(fims_scan_directory(test_dir, &cfg, &current) == FIMS_OK);

    fims_report_t report;
    assert(fims_report_init(&report) == FIMS_OK);
    assert(fims_check_integrity(&baseline, &current, &cfg, false, &report) == FIMS_OK);

    /* Verify all expected detections */
    assert(has_event(&report, EVENT_FILE_MODIFIED, f_modified));
    printf("  [PASS] Detected FILE_MODIFIED & SIZE_CHANGED on sample.txt\n");
    assert(report.size_changed_count == 1);

    assert(has_event(&report, EVENT_FILE_DELETED, f_deleted));
    printf("  [PASS] Detected FILE_DELETED on old.txt\n");

    assert(has_event(&report, EVENT_FILE_ADDED, f_added));
    printf("  [PASS] Detected FILE_ADDED on new.txt\n");

    assert(has_event(&report, EVENT_PERMISSION_CHANGED, f_perm));
    printf("  [PASS] Detected PERMISSION_CHANGED on config.txt\n");

    assert(has_event(&report, EVENT_METADATA_CHANGED, f_meta));
    printf("  [PASS] Detected METADATA_CHANGED on meta.txt\n");

    /* Verify unchanged file was NOT reported as an alert (Requirement 7.5) */
    for (size_t i = 0; i < report.count; i++) {
        assert(strcmp(report.alerts[i].path, f_unchanged) != 0);
    }
    assert(report.unchanged_files == 1);
    printf("  [PASS] Unchanged file (unchanged.txt) was NOT reported as a threat\n");

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);

    /* Requirement 7.12: Test real-time monitoring and clean interruption handling */
    char base_file[FIMS_MAX_PATH];
    char rep_file[FIMS_MAX_PATH];
    char state_file[FIMS_MAX_PATH];
    assert(fims_path_join(base_file, sizeof(base_file), test_dir, "rt_baseline.dat"));
    assert(fims_path_join(rep_file, sizeof(rep_file), test_dir, "rt_report.dat"));
    assert(fims_path_join(state_file, sizeof(state_file), test_dir, "rt_state.dat"));

    fims_str_copy(cfg.baseline_file, sizeof(cfg.baseline_file), base_file);
    fims_str_copy(cfg.report_file, sizeof(cfg.report_file), rep_file);
    fims_str_copy(cfg.state_file, sizeof(cfg.state_file), state_file);
    /* Basename-exclude workarounds removed per Item 25 */

    size_t init_cnt = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &init_cnt) == FIMS_OK);

    fims_monitor_reset_stop();
    pthread_t mon_thread;
    assert(pthread_create(&mon_thread, NULL, monitor_worker_thread, &cfg) == 0);

    sleep_ms_test(200); /* Allow inotify watches to initialize */
    create_file(f_modified, "Real-time modification during monitoring!\n", 0644);
    sleep_ms_test(200); /* Allow event to be processed */

    /* Interrupt monitoring cleanly */
    fims_monitor_request_stop();
    assert(pthread_join(mon_thread, NULL) == 0);
    assert(access(rep_file, F_OK) == 0);
    assert(fims_test_report_has_alert(rep_file, "FILE_MODIFIED", "sample.txt"));
    printf("  [PASS] Real-time inotify monitoring & graceful interruption verified (alert present)\n");

    /* Cleanup */
    unlink(base_file);
    unlink(rep_file);
    unlink(state_file);
    unlink(f_added);
    unlink(f_meta);
    unlink(f_perm);
    unlink(f_modified);
    unlink(f_unchanged);
    rmdir(test_dir);

    printf("[TEST SUITE] test_integrity PASSED.\n\n");
    return 0;
}
