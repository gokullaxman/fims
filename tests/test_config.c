#include "../include/fims.h"
#include "../src/config.h"
#include "../src/baseline.h"
#include "../src/scanner.h"
#include "../src/integrity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

static void create_test_file(const char *path, const char *content, mode_t mode) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (content) {
        fwrite(content, 1, strlen(content), fp);
    }
    fclose(fp);
    assert(chmod(path, mode) == 0);
}

/* Item 24: fims_path_join edge cases */
static void test_path_join_edge_cases(void) {
    printf("[TEST] Item 24: fims_path_join edge cases...\n");

    char dst[FIMS_MAX_PATH];

    /* Must return false on empty dir */
    assert(fims_path_join(dst, sizeof(dst), "", "file.txt") == false);

    /* Null checks */
    assert(fims_path_join(dst, sizeof(dst), NULL, "file.txt") == false);
    assert(fims_path_join(dst, sizeof(dst), "/dir", NULL) == false);
    assert(fims_path_join(NULL, sizeof(dst), "/dir", "file.txt") == false);
    assert(fims_path_join(dst, 0, "/dir", "file.txt") == false);

    /* Normal join */
    assert(fims_path_join(dst, sizeof(dst), "/var/log", "fims.log") == true);
    assert(strcmp(dst, "/var/log/fims.log") == 0);

    /* Trailing and leading slashes handled properly */
    assert(fims_path_join(dst, sizeof(dst), "/var/log/", "/fims.log") == true);
    assert(strcmp(dst, "/var/log/fims.log") == 0);

    /* Buffer overflow guard */
    assert(fims_path_join(dst, 10, "/var/log", "toolongfilename") == false);

    printf("  [PASS] Item 24 verified: fims_path_join rejects empty dir and boundary inputs cleanly.\n");
}

/* Item 9: Absolute default paths, non-root fallback, environment overrides, security permissions */
static void test_default_paths_and_permissions(void) {
    printf("[TEST] Item 9: Default paths, non-root fallback, and security checks...\n");

    /* Clear any environment overrides */
    unsetenv("FIMS_BASELINE_FILE");
    unsetenv("FIMS_BASELINE_PATH");
    unsetenv("FIMS_LOG_FILE");
    unsetenv("FIMS_LOG_PATH");
    unsetenv("FIMS_REPORT_FILE");
    unsetenv("FIMS_REPORT_PATH");
    unsetenv("FIMS_STATE_FILE");
    unsetenv("FIMS_STATE_PATH");
    unsetenv("FIMS_CONFIG_FILE");
    unsetenv("FIMS_CONFIG_PATH");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);

    /* 1. All default paths must be absolute */
    assert(cfg.baseline_file[0] == '/');
    assert(cfg.log_file[0] == '/');
    assert(cfg.report_file[0] == '/');
    assert(cfg.state_file[0] == '/');
    assert(cfg.config_file[0] == '/');

    if (geteuid() != 0) {
        /* Non-root fallback should point to ~/.local/state/fims and ~/.config/fims */
        assert(strstr(cfg.baseline_file, "/.local/state/fims/baseline.dat") != NULL);
        assert(strstr(cfg.log_file, "/.local/state/fims/fims.log") != NULL);
        assert(strstr(cfg.report_file, "/.local/state/fims/last_report.dat") != NULL);
        assert(strstr(cfg.state_file, "/.local/state/fims/status.dat") != NULL);
        assert(strstr(cfg.config_file, "/.config/fims/fims.conf") != NULL);
        printf("  [PASS] Non-root user fallback to ~/.local/state/fims and ~/.config/fims verified.\n");
    } else {
        printf("  [INFO] Running as root (EUID 0); default paths are /var/lib, /var/log, /etc.\n");
    }

    /* 2. Environment variable overrides must work */
    setenv("FIMS_BASELINE_FILE", "/tmp/test_custom_baseline.dat", 1);
    setenv("FIMS_LOG_FILE", "/tmp/test_custom_log.log", 1);
    setenv("FIMS_CONFIG_FILE", "/tmp/test_custom_cfg.conf", 1);
    setenv("FIMS_STATE_FILE", "/tmp/test_custom_state.dat", 1);
    setenv("FIMS_REPORT_FILE", "/tmp/test_custom_report.dat", 1);

    fims_config_init_defaults(&cfg);
    assert(strcmp(cfg.baseline_file, "/tmp/test_custom_baseline.dat") == 0);
    assert(strcmp(cfg.log_file, "/tmp/test_custom_log.log") == 0);
    assert(strcmp(cfg.config_file, "/tmp/test_custom_cfg.conf") == 0);
    assert(strcmp(cfg.state_file, "/tmp/test_custom_state.dat") == 0);
    assert(strcmp(cfg.report_file, "/tmp/test_custom_report.dat") == 0);
    printf("  [PASS] Environment variable overrides (FIMS_*_FILE) verified.\n");

    unsetenv("FIMS_BASELINE_FILE");
    unsetenv("FIMS_LOG_FILE");
    unsetenv("FIMS_CONFIG_FILE");
    unsetenv("FIMS_STATE_FILE");
    unsetenv("FIMS_REPORT_FILE");

    /* 3. Security checks: Refuse config or baseline files with insecure permissions */
    char dir_tmpl[] = "/tmp/fims_test_sec_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char good_conf[FIMS_MAX_PATH];
    char bad_conf[FIMS_MAX_PATH];
    fims_path_join(good_conf, sizeof(good_conf), test_dir, "good.conf");
    fims_path_join(bad_conf, sizeof(bad_conf), test_dir, "bad.conf");

    create_test_file(good_conf, "scan_interval_sec = 60\n", 0600);
    create_test_file(bad_conf, "scan_interval_sec = 60\n", 0666); /* Group & world writable */

    fims_config_t test_cfg;
    fims_config_init_defaults(&test_cfg);
    assert(fims_config_load(&test_cfg, good_conf) == FIMS_OK);
    assert(test_cfg.scan_interval_sec == 60);

    /* Insecure permissions must return FIMS_ERR_PERMISSION */
    assert(fims_config_load(&test_cfg, bad_conf) == FIMS_ERR_PERMISSION);
    assert(fims_check_file_security(bad_conf) == FIMS_ERR_PERMISSION);
    printf("  [PASS] Insecure config file (mode 0666) rejected with FIMS_ERR_PERMISSION.\n");

    /* Check group-writable only (mode 0664) */
    assert(chmod(bad_conf, 0664) == 0);
    assert(fims_config_load(&test_cfg, bad_conf) == FIMS_ERR_PERMISSION);
    printf("  [PASS] Group-writable config file (mode 0664) rejected with FIMS_ERR_PERMISSION.\n");

    unlink(bad_conf);
    unlink(good_conf);
    rmdir(test_dir);
}

/* Item 22: Dead config clean up, persistence of state_file, follow_symlinks, min_alert_severity, alert_threshold */
static void test_config_persistence_and_thresholds(void) {
    printf("[TEST] Item 22: Save & load state_file, follow_symlinks, alert thresholds...\n");

    char dir_tmpl[] = "/tmp/fims_test_cfg_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char conf_file[FIMS_MAX_PATH];
    fims_path_join(conf_file, sizeof(conf_file), test_dir, "test_persist.conf");

    fims_config_t cfg_save;
    fims_config_init_defaults(&cfg_save);

    fims_path_join(cfg_save.state_file, sizeof(cfg_save.state_file), test_dir, "custom_status.dat");
    cfg_save.follow_symlinks = true;
    cfg_save.min_alert_severity = SEV_HIGH;
    cfg_save.alert_threshold_count = 42;
    cfg_save.scan_interval_sec = 15;
    cfg_save.detect_renames = false;
    cfg_save.monitor_mode = MODE_REALTIME_INOTIFY;

    assert(fims_config_save(&cfg_save, conf_file) == FIMS_OK);

    fims_config_t cfg_load;
    fims_config_init_defaults(&cfg_load);
    assert(fims_config_load(&cfg_load, conf_file) == FIMS_OK);

    assert(strcmp(cfg_load.state_file, cfg_save.state_file) == 0);
    assert(cfg_load.follow_symlinks == true);
    assert(cfg_load.min_alert_severity == SEV_HIGH);
    assert(cfg_load.alert_threshold_count == 42);
    assert(cfg_load.scan_interval_sec == 15);
    assert(cfg_load.detect_renames == false);
    assert(cfg_load.monitor_mode == MODE_REALTIME_INOTIFY);

    unlink(conf_file);
    rmdir(test_dir);
    printf("  [PASS] Item 22 verified: state_file, follow_symlinks, alert_threshold, min_alert_severity round-trip preserved.\n");
}

/* Item 3: Remove basename matching for defaults, support exclude_glob, and monitor nested .git */
static void test_git_basename_exclusion_and_glob(void) {
    printf("[TEST] Item 3: Basename matching removal, nested .git monitoring, and exclude_glob...\n");

    char dir_tmpl[] = "/tmp/fims_test_git_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    /* 1. Verify default exclusions do NOT match .git paths elsewhere in the tree */
    fims_config_t cfg;
    fims_config_init_defaults(&cfg);

    char path_git_payload[FIMS_MAX_PATH];
    char path_x_git[FIMS_MAX_PATH];
    fims_path_join(path_git_payload, sizeof(path_git_payload), test_dir, ".git/payload");
    fims_path_join(path_x_git, sizeof(path_x_git), test_dir, "x/.git");

    assert(fims_config_is_excluded(&cfg, path_git_payload) == false);
    assert(fims_config_is_excluded(&cfg, path_x_git) == false);
    printf("  [PASS] Default exclusions do not exclude mon/.git/payload or mon/x/.git.\n");

    /* 2. Verify exact path and directory prefix exclusions on '/' boundary */
    char sub_exclude[FIMS_MAX_PATH];
    fims_path_join(sub_exclude, sizeof(sub_exclude), test_dir, "excluded_sub");
    assert(fims_config_add_exclude(&cfg, sub_exclude) == FIMS_OK);

    char inside_sub[FIMS_MAX_PATH];
    char boundary_trick[FIMS_MAX_PATH];
    fims_path_join(inside_sub, sizeof(inside_sub), test_dir, "excluded_sub/file.txt");
    fims_path_join(boundary_trick, sizeof(boundary_trick), test_dir, "excluded_sub_extra/file.txt");

    assert(fims_config_is_excluded(&cfg, sub_exclude) == true);
    assert(fims_config_is_excluded(&cfg, inside_sub) == true);
    /* Sibling directory with matching prefix but no '/' boundary must NOT be excluded */
    assert(fims_config_is_excluded(&cfg, boundary_trick) == false);
    printf("  [PASS] Directory prefix exclusion strictly adheres to '/' boundary.\n");

    /* 3. Verify exclude_glob functionality */
    assert(fims_config_add_exclude_glob(&cfg, "*.git*") == FIMS_OK);
    assert(fims_config_is_excluded(&cfg, path_git_payload) == true);
    assert(fims_config_is_excluded(&cfg, path_x_git) == true);

    char normal_file[FIMS_MAX_PATH];
    fims_path_join(normal_file, sizeof(normal_file), test_dir, "normal.txt");
    assert(fims_config_is_excluded(&cfg, normal_file) == false);
    printf("  [PASS] Explicit exclude_glob properly excludes matching glob patterns.\n");

    /* 4. Scanner/baseline integration test:
     * Add mon/.git/payload and mon/x/.git after init; scan must report both as FILE_ADDED. */
    fims_config_t scan_cfg;
    fims_config_init_defaults(&scan_cfg);

    char base_file[FIMS_MAX_PATH];
    fims_path_join(base_file, sizeof(base_file), test_dir, "baseline.dat");
    fims_str_copy(scan_cfg.baseline_file, sizeof(scan_cfg.baseline_file), base_file);
    scan_cfg.log_file[0] = '\0';

    /* Monitored directory mon/ */
    char mon_dir[FIMS_MAX_PATH];
    fims_path_join(mon_dir, sizeof(mon_dir), test_dir, "mon");
    assert(mkdir(mon_dir, 0755) == 0);

    char init_file[FIMS_MAX_PATH];
    fims_path_join(init_file, sizeof(init_file), mon_dir, "init.txt");
    create_test_file(init_file, "initial file\n", 0644);

    size_t init_count = 0;
    assert(fims_baseline_init_from_dir(mon_dir, &scan_cfg, false, &init_count) == FIMS_OK);
    assert(init_count == 1);

    /* Create mon/.git/payload and mon/x/.git (as a regular file or directory) */
    char mon_dotgit[FIMS_MAX_PATH];
    char mon_git_payload[FIMS_MAX_PATH];
    char mon_x[FIMS_MAX_PATH];
    char mon_x_dotgit[FIMS_MAX_PATH];

    fims_path_join(mon_dotgit, sizeof(mon_dotgit), mon_dir, ".git");
    fims_path_join(mon_git_payload, sizeof(mon_git_payload), mon_dir, ".git/payload");
    fims_path_join(mon_x, sizeof(mon_x), mon_dir, "x");
    fims_path_join(mon_x_dotgit, sizeof(mon_x_dotgit), mon_dir, "x/.git");

    assert(mkdir(mon_dotgit, 0755) == 0);
    create_test_file(mon_git_payload, "malicious git payload\n", 0644);

    assert(mkdir(mon_x, 0755) == 0);
    create_test_file(mon_x_dotgit, "fake git file\n", 0644);

    /* Perform scan */
    fims_file_list_t baseline;
    assert(fims_baseline_load(scan_cfg.baseline_file, &baseline) == FIMS_OK);

    fims_file_list_t current;
    assert(fims_file_list_init(&current) == FIMS_OK);
    assert(fims_scan_directory(mon_dir, &scan_cfg, &current) == FIMS_OK);

    fims_report_t report;
    assert(fims_report_init(&report) == FIMS_OK);
    assert(fims_check_integrity(&baseline, &current, &scan_cfg, false, &report) == FIMS_OK);

    /* Verify both files are reported as EVENT_FILE_ADDED */
    bool found_payload = false;
    bool found_x_git = false;
    for (size_t i = 0; i < report.count; i++) {
        if (report.alerts[i].event_type == EVENT_FILE_ADDED) {
            if (strcmp(report.alerts[i].path, mon_git_payload) == 0) {
                found_payload = true;
            }
            if (strcmp(report.alerts[i].path, mon_x_dotgit) == 0) {
                found_x_git = true;
            }
        }
    }

    assert(found_payload == true);
    assert(found_x_git == true);
    assert(report.added_count == 2);
    printf("  [PASS] mon/.git/payload and mon/x/.git detected as FILE_ADDED by scan!\n");

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);

    unlink(mon_git_payload);
    rmdir(mon_dotgit);
    unlink(mon_x_dotgit);
    rmdir(mon_x);
    unlink(init_file);
    unlink(base_file);
    rmdir(mon_dir);
    rmdir(test_dir);
}

int main(void) {
    printf("============================================================\n");
    printf(" Running FIMS Agent 2 Config & Path Subsystem Tests\n");
    printf("============================================================\n");

    test_path_join_edge_cases();
    test_default_paths_and_permissions();
    test_config_persistence_and_thresholds();
    test_git_basename_exclusion_and_glob();

    printf("============================================================\n");
    printf(" ALL AGENT 2 CONFIG TESTS PASSED CLEANLY\n");
    printf("============================================================\n");
    return 0;
}
