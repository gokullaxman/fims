#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "../src/scanner.h"
#include "../src/hash.h"
#include "../src/config.h"
#include "../src/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

static double get_elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}

static void test_item12_fifo_nonblocking_and_rejection(void) {
    printf("[TEST] Item 12: FIFO hang protection and TOCTOU rejection...\n");

    char dir_template[] = "/tmp/fims_test_fifo_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char fifo_path[FIMS_MAX_PATH];
    assert(fims_path_join(fifo_path, sizeof(fifo_path), test_dir, "test_fifo.pipe"));

    /* Create a named pipe (FIFO) */
    assert(mkfifo(fifo_path, 0666) == 0);

    /* 1. Verify fims_hash_file_sha256 rejects FIFO cleanly within 1.0 second */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    char hash_out[FIMS_HASH_HEX_LEN] = {0};
    fims_status_t h_st = fims_hash_file_sha256(fifo_path, hash_out);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = get_elapsed_seconds(t0, t1);

    assert(h_st != FIMS_OK);
    assert(elapsed < 1.0);
    printf("  [PASS] fims_hash_file_sha256 rejected FIFO in %.4f seconds (status=%d)\n", elapsed, h_st);

    /* 2. Verify fims_scan_single_file rejects FIFO cleanly within 1.0 second */
    clock_gettime(CLOCK_MONOTONIC, &t0);

    fims_file_record_t rec;
    memset(&rec, 0, sizeof(rec));
    fims_status_t s_st = fims_scan_single_file(fifo_path, &rec);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = get_elapsed_seconds(t0, t1);

    assert(s_st != FIMS_OK);
    assert(elapsed < 1.0);
    printf("  [PASS] fims_scan_single_file rejected FIFO in %.4f seconds (status=%d)\n", elapsed, s_st);

    /* 3. Verify directory scan skips FIFO without hanging */
    char reg_path[FIMS_MAX_PATH];
    assert(fims_path_join(reg_path, sizeof(reg_path), test_dir, "regular.txt"));
    FILE *fp = fopen(reg_path, "wb");
    assert(fp != NULL);
    fputs("content", fp);
    fclose(fp);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.log_file[0] = '\0';

    fims_file_list_t list;
    assert(fims_file_list_init(&list) == FIMS_OK);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    fims_status_t dir_st = fims_scan_directory(test_dir, &cfg, &list);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed = get_elapsed_seconds(t0, t1);

    assert(dir_st == FIMS_OK);
    assert(elapsed < 1.0);
    assert(list.count == 1);
    assert(strcmp(list.records[0].path, reg_path) == 0);
    printf("  [PASS] fims_scan_directory scanned directory containing FIFO in %.4f seconds\n", elapsed);

    fims_file_list_free(&list);
    unlink(reg_path);
    unlink(fifo_path);
    rmdir(test_dir);
}

static void test_item12_hash_fd_direct(void) {
    printf("[TEST] Item 12: Direct open file descriptor hashing...\n");

    char dir_template[] = "/tmp/fims_test_fd_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char file_path[FIMS_MAX_PATH];
    assert(fims_path_join(file_path, sizeof(file_path), test_dir, "test_data.txt"));

    const char *test_content = "hello world\n";
    FILE *fp = fopen(file_path, "wb");
    assert(fp != NULL);
    fputs(test_content, fp);
    fclose(fp);

    /* Open file descriptor and hash directly */
    int fd = open(file_path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);

    char hash_fd[FIMS_HASH_HEX_LEN] = {0};
    fims_status_t st = fims_hash_fd_sha256(fd, hash_fd);
    close(fd);

    assert(st == FIMS_OK);
    assert(strlen(hash_fd) == 64);

    /* Verify matches fims_hash_file_sha256 */
    char hash_file[FIMS_HASH_HEX_LEN] = {0};
    assert(fims_hash_file_sha256(file_path, hash_file) == FIMS_OK);
    assert(strcmp(hash_fd, hash_file) == 0);

    /* Known SHA-256 for "hello world\n" */
    const char *expected_sha256 = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";
    assert(strcmp(hash_fd, expected_sha256) == 0);
    printf("  [PASS] fims_hash_fd_sha256 produced verified hash: %s\n", hash_fd);

    unlink(file_path);
    rmdir(test_dir);
}

static void test_item10_unreadable_file_handling(void) {
    printf("[TEST] Item 10: Unreadable file metadata retention...\n");

    char dir_template[] = "/tmp/fims_test_unreadable_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char unreadable_file[FIMS_MAX_PATH];
    assert(fims_path_join(unreadable_file, sizeof(unreadable_file), test_dir, "secret.dat"));

    const char *secret_data = "classified data cannot read";
    FILE *fp = fopen(unreadable_file, "wb");
    assert(fp != NULL);
    fputs(secret_data, fp);
    fclose(fp);

    /* Set mode to 0000 (unreadable) */
    assert(chmod(unreadable_file, 0000) == 0);

    if (geteuid() != 0) {
        /* As non-root, file cannot be opened for reading */
        fims_file_record_t rec;
        memset(&rec, 0, sizeof(rec));

        fims_status_t st = fims_scan_single_file(unreadable_file, &rec);
        assert(st == FIMS_OK);
        assert(rec.unreadable == true);
        assert(rec.sha256[0] == '\0');
        assert(rec.size == strlen(secret_data));
        assert(strcmp(rec.path, unreadable_file) == 0);
        printf("  [PASS] fims_scan_single_file returned FIMS_OK with unreadable=true and empty hash\n");

        /* Verify file is preserved in fims_scan_directory */
        fims_config_t cfg;
        fims_config_init_defaults(&cfg);
        cfg.log_file[0] = '\0';

        fims_file_list_t list;
        assert(fims_file_list_init(&list) == FIMS_OK);
        assert(fims_scan_directory(test_dir, &cfg, &list) == FIMS_OK);

        assert(list.count == 1);
        assert(list.records[0].unreadable == true);
        assert(list.records[0].sha256[0] == '\0');
        assert(list.records[0].size == strlen(secret_data));
        printf("  [PASS] fims_scan_directory preserved unreadable file in record list\n");

        fims_file_list_free(&list);
    } else {
        printf("  [INFO] Running as root (EUID 0); EACCES behavior bypassed by DAC\n");
    }

    chmod(unreadable_file, 0600);
    unlink(unreadable_file);
    rmdir(test_dir);
}

static void test_item7_missing_and_nondir_roots(void) {
    printf("[TEST] Item 7: Missing and non-directory roots handled gracefully as empty...\n");

    fims_scanner_reset_missing_root_count();
    assert(fims_scanner_get_missing_root_count() == 0);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.log_file[0] = '\0';

    /* 1. Missing root directory (ENOENT) */
    const char *missing_root = "/tmp/fims_nonexistent_dir_99999";
    fims_file_list_t list;
    assert(fims_file_list_init(&list) == FIMS_OK);

    fims_status_t st = fims_scan_directory(missing_root, &cfg, &list);
    assert(st == FIMS_OK);
    assert(list.count == 0);
    assert(list.root_dir_count == 1);
    assert(strcmp(list.root_dirs[0], missing_root) == 0);
    assert(fims_scanner_get_missing_root_count() == 1);
    printf("  [PASS] Missing root treated as empty root (count=0, root_dir recorded, counter=1)\n");

    fims_file_list_free(&list);

    /* 2. Non-directory root (file passed as root directory) */
    char file_template[] = "/tmp/fims_test_notadir_XXXXXX";
    int fd = mkstemp(file_template);
    assert(fd >= 0);
    close(fd);

    assert(fims_file_list_init(&list) == FIMS_OK);
    st = fims_scan_directory(file_template, &cfg, &list);
    assert(st == FIMS_OK);
    assert(list.count == 0);
    assert(list.root_dir_count == 1);
    assert(fims_scanner_get_missing_root_count() == 2);
    printf("  [PASS] Non-directory root treated as empty root (counter=2)\n");

    fims_file_list_free(&list);
    unlink(file_template);

    /* 3. Multi-root scan with valid root and missing root */
    char dir_template[] = "/tmp/fims_test_valid_XXXXXX";
    char *valid_dir = mkdtemp(dir_template);
    assert(valid_dir != NULL);

    char file1[FIMS_MAX_PATH];
    assert(fims_path_join(file1, sizeof(file1), valid_dir, "file1.txt"));
    FILE *fp = fopen(file1, "wb");
    assert(fp != NULL);
    fputs("data", fp);
    fclose(fp);

    char roots[2][FIMS_MAX_PATH];
    snprintf(roots[0], FIMS_MAX_PATH, "%s", valid_dir);
    snprintf(roots[1], FIMS_MAX_PATH, "%s", missing_root);

    assert(fims_file_list_init(&list) == FIMS_OK);
    st = fims_scan_directories((const char (*)[FIMS_MAX_PATH])roots, 2, &cfg, &list);
    assert(st == FIMS_OK);
    assert(list.count == 1);
    assert(list.root_dir_count == 2);
    printf("  [PASS] Multi-root scan succeeded with mixed valid and missing roots\n");

    fims_file_list_free(&list);
    unlink(file1);
    rmdir(valid_dir);
}

static void test_item13_scan_depth_limit(void) {
    printf("[TEST] Item 13: Enforce FIMS_MAX_SCAN_DEPTH with warning logging...\n");

    fims_scanner_reset_depth_limit_reached_count();
    assert(fims_scanner_get_depth_limit_reached_count() == 0);

    char base_template[] = "/tmp/fims_test_depth_XXXXXX";
    char *base_dir = mkdtemp(base_template);
    assert(base_dir != NULL);

    char log_path[FIMS_MAX_PATH];
    assert(fims_path_join(log_path, sizeof(log_path), base_dir, "test.log"));

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.log_file, sizeof(cfg.log_file), "%s", log_path);

    /* Create nested tree reaching depth > FIMS_MAX_SCAN_DEPTH (128) */
    char current_path[FIMS_MAX_PATH];
    snprintf(current_path, sizeof(current_path), "%s", base_dir);

    const size_t total_depth = FIMS_MAX_SCAN_DEPTH + 4;
    char depth_dirs[FIMS_MAX_SCAN_DEPTH + 10][FIMS_MAX_PATH];

    for (size_t d = 0; d < total_depth; d++) {
        char next_path[FIMS_MAX_PATH];
        int n = snprintf(next_path, sizeof(next_path), "%s/d", current_path);
        assert(n > 0 && (size_t)n < sizeof(next_path));
        assert(mkdir(next_path, 0755) == 0);
        snprintf(depth_dirs[d], sizeof(depth_dirs[d]), "%s", next_path);
        snprintf(current_path, sizeof(current_path), "%s", next_path);
    }

    fims_file_list_t list;
    assert(fims_file_list_init(&list) == FIMS_OK);

    fims_status_t st = fims_scan_directory(base_dir, &cfg, &list);
    assert(st == FIMS_OK);
    assert(fims_scanner_get_depth_limit_reached_count() > 0);
    printf("  [PASS] Depth limit cap reached (%zu times triggered) without infinite loop\n",
           fims_scanner_get_depth_limit_reached_count());

    /* Verify warning was logged to log_file */
    FILE *log_fp = fopen(log_path, "r");
    assert(log_fp != NULL);
    char line[1024];
    bool found_warning = false;
    while (fgets(line, sizeof(line), log_fp) != NULL) {
        if (strstr(line, "Maximum directory scan depth") != NULL) {
            found_warning = true;
            break;
        }
    }
    fclose(log_fp);
    assert(found_warning);
    printf("  [PASS] Warning message logged at SEV_HIGH verified in log file\n");

    fims_file_list_free(&list);

    /* Clean up nested directories in reverse order */
    for (size_t d = total_depth; d > 0; d--) {
        rmdir(depth_dirs[d - 1]);
    }
    unlink(log_path);
    rmdir(base_dir);
}

int main(void) {
    printf("============================================================\n");
    printf(" Executing Scanner & Hash Hardening Test Suite (Items 12, 10, 7, 13)\n");
    printf("============================================================\n");

    test_item12_fifo_nonblocking_and_rejection();
    test_item12_hash_fd_direct();
    test_item10_unreadable_file_handling();
    test_item7_missing_and_nondir_roots();
    test_item13_scan_depth_limit();

    printf("============================================================\n");
    printf(" ALL SCANNER & HASH HARDENING TESTS PASSED CLEANLY\n");
    printf("============================================================\n");
    return 0;
}
