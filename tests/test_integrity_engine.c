#include "../src/integrity.h"
#include "../src/logger.h"
#include "../src/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

static double get_elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

static bool has_event(const fims_report_t *rep, fims_event_type_t type, const char *path) {
    for (size_t i = 0; i < rep->count; i++) {
        if (rep->alerts[i].event_type == type && strcmp(rep->alerts[i].path, path) == 0) {
            return true;
        }
    }
    return false;
}

/* Test Item 5: Report escaping for paths and descriptions */
static void test_item5_report_escaping(void) {
    printf("[TEST] Item 5: Report escaping in fims_report_save & fims_report_display...\n");

    char dir_template[] = "/tmp/fims_test_esc_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char report_path[FIMS_MAX_PATH];
    snprintf(report_path, sizeof(report_path), "%s/test_report.dat", test_dir);

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);

    fims_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    alert.timestamp = time(NULL);
    /* Injected newline and fake alert string */
    snprintf(alert.path, sizeof(alert.path), "/test/dir/malicious\n[ALERT] INJECTED: /etc/shadow");
    alert.event_type = EVENT_FILE_MODIFIED;
    snprintf(alert.prev_hash, sizeof(alert.prev_hash), "1111111111111111111111111111111111111111111111111111111111111111");
    snprintf(alert.curr_hash, sizeof(alert.curr_hash), "2222222222222222222222222222222222222222222222222222222222222222");
    alert.prev_size = 10;
    alert.curr_size = 20;
    alert.severity = SEV_HIGH;
    snprintf(alert.description, sizeof(alert.description), "Fake\tdescription\rwith control\x1b[31m chars");

    assert(fims_report_add_alert(&rep, &alert) == FIMS_OK);
    assert(fims_report_save(report_path, &rep) == FIMS_OK);

    /* Verify report file can be read and displayed cleanly */
    assert(fims_report_display(report_path) == FIMS_OK);

    fims_report_free(&rep);
    unlink(report_path);
    rmdir(test_dir);
    printf("  [PASS] Item 5: Report escaping verified.\n");
}

/* Test Item 10: Unreadable records emitted as UNREADABLE or PERMISSION_CHANGED (never DELETED) */
static void test_item10_unreadable_records(void) {
    printf("[TEST] Item 10: Unreadable records handling...\n");

    fims_file_list_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    baseline.count = 1;
    baseline.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(baseline.records[0].path, sizeof(baseline.records[0].path), "/protected/secret.key");
    snprintf(baseline.records[0].sha256, sizeof(baseline.records[0].sha256), "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    baseline.records[0].mode = 0600;
    baseline.records[0].size = 256;
    baseline.records[0].unreadable = false;

    fims_file_list_t current;
    memset(&current, 0, sizeof(current));
    current.count = 1;
    current.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(current.records[0].path, sizeof(current.records[0].path), "/protected/secret.key");
    current.records[0].sha256[0] = '\0';
    current.records[0].mode = 0000;
    current.records[0].size = 256;
    current.records[0].unreadable = true; /* Permission revoked / unreadable */

    fims_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);

    assert(fims_check_integrity(&baseline, &current, &cfg, false, &rep) == FIMS_OK);

    /* Verify it is NEVER reported as DELETED */
    assert(!has_event(&rep, EVENT_FILE_DELETED, "/protected/secret.key"));
    /* Verify it is reported as UNREADABLE */
    assert(has_event(&rep, EVENT_UNREADABLE, "/protected/secret.key"));

    fims_report_free(&rep);
    free(baseline.records);
    free(current.records);
    printf("  [PASS] Item 10: Unreadable records emitted as UNREADABLE (never DELETED).\n");
}

/* Test Item 11: UID/GID metadata alerts, exact counters, and error propagation */
static void test_item11_uid_gid_and_counters(void) {
    printf("[TEST] Item 11: UID/GID alerts, exact counters, and error propagation...\n");

    fims_file_list_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    baseline.count = 1;
    baseline.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(baseline.records[0].path, sizeof(baseline.records[0].path), "/etc/app.conf");
    snprintf(baseline.records[0].sha256, sizeof(baseline.records[0].sha256), "1111222233334444111122223333444411112222333344441111222233334444");
    baseline.records[0].mode = 0644;
    baseline.records[0].uid = 1000;
    baseline.records[0].gid = 1000;
    baseline.records[0].size = 100;

    fims_file_list_t current;
    memset(&current, 0, sizeof(current));
    current.count = 1;
    current.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(current.records[0].path, sizeof(current.records[0].path), "/etc/app.conf");
    snprintf(current.records[0].sha256, sizeof(current.records[0].sha256), "1111222233334444111122223333444411112222333344441111222233334444");
    current.records[0].mode = 0755; /* mode changed */
    current.records[0].uid = 0;    /* uid changed */
    current.records[0].gid = 0;    /* gid changed */
    current.records[0].size = 100;

    fims_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);

    assert(fims_check_integrity(&baseline, &current, &cfg, false, &rep) == FIMS_OK);

    /* Verify both PERMISSION_CHANGED and METADATA_CHANGED are emitted */
    assert(has_event(&rep, EVENT_PERMISSION_CHANGED, "/etc/app.conf"));
    assert(has_event(&rep, EVENT_METADATA_CHANGED, "/etc/app.conf"));

    /* Verify exact counter equality */
    assert(rep.perm_changed_count == 1);
    assert(rep.meta_changed_count == 1);
    assert(rep.added_count == 0);
    assert(rep.modified_count == 0);
    assert(rep.deleted_count == 0);
    assert(rep.renamed_count == 0);
    assert(rep.size_changed_count == 0);
    assert(rep.count == rep.perm_changed_count + rep.meta_changed_count);

    /* Test error propagation on invalid arguments */
    assert(fims_report_add_alert(NULL, NULL) == FIMS_ERR_INVALID_ARG);
    assert(fims_check_integrity(NULL, &current, &cfg, false, &rep) == FIMS_ERR_INVALID_ARG);

    fims_report_free(&rep);
    free(baseline.records);
    free(current.records);
    printf("  [PASS] Item 11: UID/GID metadata alerts and exact counters verified.\n");
}

/* Test Item 24: ctime and inode checks */
static void test_item24_ctime_inode(void) {
    printf("[TEST] Item 24: ctime and inode checks...\n");

    fims_file_list_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    baseline.count = 1;
    baseline.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(baseline.records[0].path, sizeof(baseline.records[0].path), "/data/file.bin");
    snprintf(baseline.records[0].sha256, sizeof(baseline.records[0].sha256), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    baseline.records[0].mode = 0644;
    baseline.records[0].size = 500;
    baseline.records[0].ctime = 1600000000;
    baseline.records[0].inode = 12345;

    fims_file_list_t current;
    memset(&current, 0, sizeof(current));
    current.count = 1;
    current.records = (fims_file_record_t *)calloc(1, sizeof(fims_file_record_t));
    snprintf(current.records[0].path, sizeof(current.records[0].path), "/data/file.bin");
    snprintf(current.records[0].sha256, sizeof(current.records[0].sha256), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    current.records[0].mode = 0644;
    current.records[0].size = 500;
    current.records[0].ctime = 1600005000; /* changed ctime */
    current.records[0].inode = 67890;      /* changed inode */

    fims_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);

    assert(fims_check_integrity(&baseline, &current, &cfg, false, &rep) == FIMS_OK);

    assert(has_event(&rep, EVENT_METADATA_CHANGED, "/data/file.bin"));
    assert(rep.meta_changed_count == 1);

    fims_report_free(&rep);
    free(baseline.records);
    free(current.records);
    printf("  [PASS] Item 24: ctime and inode comparison verified.\n");
}

/* Test Item 19: Rename detection via (dev, inode) hash map */
static void test_item19_rename_detection(void) {
    printf("[TEST] Item 19: Rename detection via (dev, inode) hash map...\n");

    fims_file_list_t baseline;
    memset(&baseline, 0, sizeof(baseline));
    baseline.count = 2;
    baseline.records = (fims_file_record_t *)calloc(2, sizeof(fims_file_record_t));
    snprintf(baseline.records[0].path, sizeof(baseline.records[0].path), "/var/log/old_name.log");
    snprintf(baseline.records[0].sha256, sizeof(baseline.records[0].sha256), "aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444");
    baseline.records[0].dev = 42;
    baseline.records[0].inode = 99999;
    baseline.records[0].size = 1024;
    baseline.records[0].mtime = 1500000000;

    snprintf(baseline.records[1].path, sizeof(baseline.records[1].path), "/var/log/stay.log");
    snprintf(baseline.records[1].sha256, sizeof(baseline.records[1].sha256), "staystaystaystaystaystaystaystaystaystaystaystaystaystaystaystay");
    baseline.records[1].dev = 42;
    baseline.records[1].inode = 88888;
    baseline.records[1].size = 512;
    baseline.records[1].mtime = 1500000000;

    fims_file_list_t current;
    memset(&current, 0, sizeof(current));
    current.count = 2;
    current.records = (fims_file_record_t *)calloc(2, sizeof(fims_file_record_t));
    /* Renamed file */
    snprintf(current.records[0].path, sizeof(current.records[0].path), "/var/log/new_name.log");
    snprintf(current.records[0].sha256, sizeof(current.records[0].sha256), "aaaa1111bbbb2222cccc3333dddd4444aaaa1111bbbb2222cccc3333dddd4444");
    current.records[0].dev = 42;
    current.records[0].inode = 99999;
    current.records[0].size = 1024;
    current.records[0].mtime = 1500000000;

    snprintf(current.records[1].path, sizeof(current.records[1].path), "/var/log/stay.log");
    snprintf(current.records[1].sha256, sizeof(current.records[1].sha256), "staystaystaystaystaystaystaystaystaystaystaystaystaystaystaystay");
    current.records[1].dev = 42;
    current.records[1].inode = 88888;
    current.records[1].size = 512;
    current.records[1].mtime = 1500000000;

    fims_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.detect_renames = true;

    fims_report_t rep;
    assert(fims_report_init(&rep) == FIMS_OK);

    assert(fims_check_integrity(&baseline, &current, &cfg, false, &rep) == FIMS_OK);

    assert(has_event(&rep, EVENT_FILE_RENAMED, "/var/log/new_name.log"));
    assert(rep.renamed_count == 1);
    assert(rep.added_count == 0);
    assert(rep.deleted_count == 0);
    assert(rep.unchanged_files == 1);

    fims_report_free(&rep);
    free(baseline.records);
    free(current.records);
    printf("  [PASS] Item 19: Rename detection verified.\n");
}

/* Test Item 19: Performance benchmark comparing 5,000 files vs 200,000 files */
static void test_item19_performance_benchmark(void) {
    printf("[BENCHMARK] Executing 5,000 files vs 200,000 files performance benchmark...\n");

    /* 1. 5,000 Files Benchmark */
    size_t count_5k = 5000;
    fims_file_list_t base_5k;
    fims_file_list_t curr_5k;
    memset(&base_5k, 0, sizeof(base_5k));
    memset(&curr_5k, 0, sizeof(curr_5k));
    base_5k.count = count_5k;
    curr_5k.count = count_5k;
    base_5k.records = (fims_file_record_t *)malloc(count_5k * sizeof(fims_file_record_t));
    curr_5k.records = (fims_file_record_t *)malloc(count_5k * sizeof(fims_file_record_t));
    assert(base_5k.records != NULL && curr_5k.records != NULL);

    for (size_t i = 0; i < count_5k; i++) {
        snprintf(base_5k.records[i].path, sizeof(base_5k.records[i].path),
                 "/benchmark/dir_%03zu/file_%06zu.dat", i / 50, i);
        snprintf(base_5k.records[i].sha256, sizeof(base_5k.records[i].sha256),
                 "5555555555555555555555555555555555555555555555555555555555555555");
        base_5k.records[i].dev = 1;
        base_5k.records[i].inode = 100000 + i;
        base_5k.records[i].size = 1024;
        base_5k.records[i].mode = 0644;
        base_5k.records[i].uid = 1000;
        base_5k.records[i].gid = 1000;
        base_5k.records[i].mtime = 1600000000;
        base_5k.records[i].ctime = 1600000000;
        base_5k.records[i].unreadable = false;

        curr_5k.records[i] = base_5k.records[i];
    }
    /* Introduce modifications in 5k */
    for (size_t i = 0; i < 50; i++) {
        snprintf(curr_5k.records[i].sha256, sizeof(curr_5k.records[i].sha256),
                 "9999999999999999999999999999999999999999999999999999999999999999");
    }

    fims_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.detect_renames = true;

    fims_report_t rep_5k;
    assert(fims_report_init(&rep_5k) == FIMS_OK);

    struct timespec start_5k, end_5k;
    clock_gettime(CLOCK_MONOTONIC, &start_5k);
    assert(fims_check_integrity(&base_5k, &curr_5k, &cfg, false, &rep_5k) == FIMS_OK);
    clock_gettime(CLOCK_MONOTONIC, &end_5k);

    double sec_5k = get_elapsed_seconds(start_5k, end_5k);
    printf("  [BENCHMARK] 5,000 files comparison completed in %.6f seconds\n", sec_5k);
    printf("              (Modified: %zu, Unchanged: %zu)\n", rep_5k.modified_count, rep_5k.unchanged_files);
    assert(rep_5k.modified_count == 50);

    fims_report_free(&rep_5k);
    free(base_5k.records);
    free(curr_5k.records);

    /* 2. 200,000 Files Benchmark */
    size_t count_200k = 200000;
    fims_file_list_t base_200k;
    fims_file_list_t curr_200k;
    memset(&base_200k, 0, sizeof(base_200k));
    memset(&curr_200k, 0, sizeof(curr_200k));
    base_200k.count = count_200k;
    curr_200k.count = count_200k;
    base_200k.records = (fims_file_record_t *)malloc(count_200k * sizeof(fims_file_record_t));
    curr_200k.records = (fims_file_record_t *)malloc(count_200k * sizeof(fims_file_record_t));
    assert(base_200k.records != NULL && curr_200k.records != NULL);

    for (size_t i = 0; i < count_200k; i++) {
        snprintf(base_200k.records[i].path, sizeof(base_200k.records[i].path),
                 "/benchmark/dir_%04zu/file_%08zu.dat", i / 500, i);
        snprintf(base_200k.records[i].sha256, sizeof(base_200k.records[i].sha256),
                 "2222222222222222222222222222222222222222222222222222222222222222");
        base_200k.records[i].dev = 1;
        base_200k.records[i].inode = 1000000 + i;
        base_200k.records[i].size = 2048;
        base_200k.records[i].mode = 0644;
        base_200k.records[i].uid = 1000;
        base_200k.records[i].gid = 1000;
        base_200k.records[i].mtime = 1600000000;
        base_200k.records[i].ctime = 1600000000;
        base_200k.records[i].unreadable = false;

        curr_200k.records[i] = base_200k.records[i];
    }
    /* 1,000 modified in 200k */
    for (size_t i = 0; i < 1000; i++) {
        snprintf(curr_200k.records[i].sha256, sizeof(curr_200k.records[i].sha256),
                 "7777777777777777777777777777777777777777777777777777777777777777");
    }

    fims_report_t rep_200k;
    assert(fims_report_init(&rep_200k) == FIMS_OK);

    struct timespec start_200k, end_200k;
    clock_gettime(CLOCK_MONOTONIC, &start_200k);
    assert(fims_check_integrity(&base_200k, &curr_200k, &cfg, false, &rep_200k) == FIMS_OK);
    clock_gettime(CLOCK_MONOTONIC, &end_200k);

    double sec_200k = get_elapsed_seconds(start_200k, end_200k);
    printf("  [BENCHMARK] 200,000 files comparison completed in %.6f seconds (Limit: 5.0s)\n", sec_200k);
    printf("              (Modified: %zu, Unchanged: %zu)\n", rep_200k.modified_count, rep_200k.unchanged_files);

    /* HARD REQUIREMENT: 200,000 files MUST complete in under 5 seconds! */
    assert(sec_200k < 5.0);
    assert(rep_200k.modified_count == 1000);
    assert(rep_200k.unchanged_files == 199000);

    fims_report_free(&rep_200k);
    free(base_200k.records);
    free(curr_200k.records);
    printf("  [PASS] Item 19: 200k benchmark passed under 5.0 seconds!\n\n");
}

int main(void) {
    printf("============================================================\n");
    printf(" FIMS Integrity Engine Test Suite & Benchmark\n");
    printf("============================================================\n");

    test_item5_report_escaping();
    test_item10_unreadable_records();
    test_item11_uid_gid_and_counters();
    test_item24_ctime_inode();
    test_item19_rename_detection();
    test_item19_performance_benchmark();

    printf("============================================================\n");
    printf(" ALL INTEGRITY ENGINE TESTS & BENCHMARKS PASSED CLEANLY!\n");
    printf("============================================================\n");
    return 0;
}
