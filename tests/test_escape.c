#include "../src/escape.h"
#include "../src/logger.h"
#include "../include/fims.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

static void test_escape_unit(void) {
    char buf[128];
    size_t len;

    len = fims_escape_for_log(NULL, buf, sizeof(buf));
    assert(len == 0);
    assert(strcmp(buf, "") == 0);

    len = fims_escape_for_log("", buf, sizeof(buf));
    assert(len == 0);
    assert(strcmp(buf, "") == 0);

    len = fims_escape_for_log("hello/world_123.txt", buf, sizeof(buf));
    assert(len == 19);
    assert(strcmp(buf, "hello/world_123.txt") == 0);

    len = fims_escape_for_log("\"\\", buf, sizeof(buf));
    assert(len == 8);
    assert(strcmp(buf, "\\x22\\x5c") == 0);

    len = fims_escape_for_log("\n\r\t\x1b\x7f", buf, sizeof(buf));
    assert(len == 20);
    assert(strcmp(buf, "\\x0a\\x0d\\x09\\x1b\\x7f") == 0);

    len = fims_escape_for_log("test\"val", NULL, 0);
    assert(len == 11);

    memset(buf, 'Z', sizeof(buf));
    len = fims_escape_for_log("test\"val", buf, 6);
    assert(len == 11);
    assert(buf[5] == '\0');
    assert(strncmp(buf, "test\\", 5) == 0);

    memset(buf, 'Z', sizeof(buf));
    len = fims_escape_for_log("abc", buf, 1);
    assert(len == 3);
    assert(buf[0] == '\0');

    printf("  [PASS] Unit tests for fims_escape_for_log passed.\n");
}

static void test_log_alert_injection(void) {
    char dir_template[] = "/tmp/fims_test_escape_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char log_path[FIMS_MAX_PATH];
    assert(fims_path_join(log_path, sizeof(log_path), test_dir, "fims.log"));

    const char *evil_filename = "bad\n[ALERT] FILE_MODIFIED: /etc/passwd\r\t\"\\hello\x1b[31m";
    const char *evil_desc = "Fake desc\n[CRITICAL] Injection attack\r\x7f";

    fims_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    alert.timestamp = 1700000000;
    fims_str_copy(alert.path, sizeof(alert.path), evil_filename);
    fims_str_copy(alert.old_path, sizeof(alert.old_path), evil_filename);
    alert.event_type = EVENT_FILE_MODIFIED;
    alert.severity = SEV_HIGH;
    fims_str_copy(alert.prev_hash, sizeof(alert.prev_hash), "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff");
    fims_str_copy(alert.curr_hash, sizeof(alert.curr_hash), "aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000");
    alert.prev_size = 100;
    alert.curr_size = 200;
    alert.prev_mode = 0644;
    alert.curr_mode = 0644;
    fims_str_copy(alert.description, sizeof(alert.description), evil_desc);

    assert(fims_log_alert(log_path, &alert, false) == FIMS_OK);

    FILE *fp = fopen(log_path, "r");
    assert(fp != NULL);

    int newline_count = 0;
    char content[4096];
    size_t bytes_read = fread(content, 1, sizeof(content) - 1, fp);
    content[bytes_read] = '\0';
    fclose(fp);

    for (size_t i = 0; i < bytes_read; i++) {
        if (content[i] == '\n') {
            newline_count++;
        }
    }
    assert(newline_count == 1);
    assert(strstr(content, "\\x0a") != NULL);
    assert(strstr(content, "\\x0d") != NULL);
    assert(strstr(content, "\\x09") != NULL);
    assert(strstr(content, "\\x22") != NULL);
    assert(strstr(content, "\\x5c") != NULL);
    assert(strstr(content, "\\x1b") != NULL);
    assert(strstr(content, "\\x7f") != NULL);
    assert(strstr(content, "\n[ALERT]") == NULL);
    assert(strstr(content, "\n[CRITICAL]") == NULL);

    unlink(log_path);
    assert(fims_log_message(log_path, SEV_INFO, "Event on path: %s", evil_filename) == FIMS_OK);

    fp = fopen(log_path, "r");
    assert(fp != NULL);
    bytes_read = fread(content, 1, sizeof(content) - 1, fp);
    content[bytes_read] = '\0';
    fclose(fp);

    newline_count = 0;
    for (size_t i = 0; i < bytes_read; i++) {
        if (content[i] == '\n') {
            newline_count++;
        }
    }
    assert(newline_count == 1);
    assert(strstr(content, "\\x0a") != NULL);

    unlink(log_path);
    rmdir(test_dir);

    printf("  [PASS] Log injection escaping verified.\n");
}

static void test_lazy_logger_init(void) {
    char dir_template[] = "/tmp/fims_test_lazy_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char lazy_subdir[FIMS_MAX_PATH];
    char lazy_log_path[FIMS_MAX_PATH];
    assert(fims_path_join(lazy_subdir, sizeof(lazy_subdir), test_dir, "lazy_logs"));
    assert(fims_path_join(lazy_log_path, sizeof(lazy_log_path), lazy_subdir, "test.log"));

    assert(access(lazy_subdir, F_OK) != 0);

    assert(fims_logger_init(lazy_log_path) == FIMS_OK);
    assert(access(lazy_subdir, F_OK) != 0);
    assert(access(lazy_log_path, F_OK) != 0);

    char lazy_subdir2[FIMS_MAX_PATH];
    char lazy_log_path2[FIMS_MAX_PATH];
    assert(fims_path_join(lazy_subdir2, sizeof(lazy_subdir2), test_dir, "lazy_logs2"));
    assert(fims_path_join(lazy_log_path2, sizeof(lazy_log_path2), lazy_subdir2, "test.log"));

    assert(fims_logger_init_lazy(lazy_log_path2) == FIMS_OK);
    assert(access(lazy_subdir2, F_OK) != 0);
    assert(access(lazy_log_path2, F_OK) != 0);

    fims_alert_t alert;
    memset(&alert, 0, sizeof(alert));
    alert.timestamp = time(NULL);
    fims_str_copy(alert.path, sizeof(alert.path), "/test/path");
    alert.event_type = EVENT_FILE_ADDED;
    alert.severity = SEV_INFO;
    fims_str_copy(alert.description, sizeof(alert.description), "Initial test alert");

    assert(fims_log_alert(lazy_log_path, &alert, false) == FIMS_OK);

    assert(access(lazy_subdir, F_OK) == 0);
    assert(access(lazy_log_path, F_OK) == 0);

    struct stat st;
    assert(stat(lazy_log_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    unlink(lazy_log_path);
    rmdir(lazy_subdir);
    rmdir(test_dir);

    printf("  [PASS] Lazy logger initialization verified.\n");
}

int main(void) {
    printf("[TEST SUITE] Running test_escape (Item 5 & Item 21)...\n");
    test_escape_unit();
    test_log_alert_injection();
    test_lazy_logger_init();
    printf("[TEST SUITE] test_escape PASSED cleanly.\n\n");
    return 0;
}
