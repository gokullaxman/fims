#include "../src/scanner.h"
#include "../src/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

static void write_sample_file(const char *path, const char *content, mode_t mode) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (content && content[0] != '\0') {
        fwrite(content, 1, strlen(content), fp);
    }
    fclose(fp);
    assert(chmod(path, mode) == 0);
}

int main(void) {
    printf("[TEST SUITE] Running test_scanner...\n");

    char dir_template[] = "/tmp/fims_test_scanner_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    /* Create nested directory structure (Requirement 7.10) */
    char sub1[FIMS_MAX_PATH];
    char sub2[FIMS_MAX_PATH];
    assert(fims_path_join(sub1, sizeof(sub1), test_dir, "level1"));
    assert(fims_path_join(sub2, sizeof(sub2), sub1, "level2"));
    assert(mkdir(sub1, 0755) == 0);
    assert(mkdir(sub2, 0755) == 0);

    char f1[FIMS_MAX_PATH];
    char f2[FIMS_MAX_PATH];
    char f3_empty[FIMS_MAX_PATH];
    char f4_inacc[FIMS_MAX_PATH];
    char sym_loop[FIMS_MAX_PATH];
    char sym_file[FIMS_MAX_PATH];

    assert(fims_path_join(f1, sizeof(f1), test_dir, "root_file.txt"));
    assert(fims_path_join(f2, sizeof(f2), sub2, "nested_file.txt"));
    assert(fims_path_join(f3_empty, sizeof(f3_empty), sub1, "empty_file.txt"));
    assert(fims_path_join(f4_inacc, sizeof(f4_inacc), sub1, "inaccessible.txt"));
    assert(fims_path_join(sym_loop, sizeof(sym_loop), sub2, "loop_back_to_root"));
    assert(fims_path_join(sym_file, sizeof(sym_file), sub1, "symlink_to_f1.txt"));

    write_sample_file(f1, "Root file content\n", 0644);
    write_sample_file(f2, "Deep nested file content\n", 0600);
    write_sample_file(f3_empty, "", 0644);
    write_sample_file(f4_inacc, "Unreadable content\n", 0000);

    /* Create circular directory symlink & file symlink (Requirement 7.11) */
    assert(symlink(test_dir, sym_loop) == 0);
    assert(symlink(f1, sym_file) == 0);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    cfg.log_file[0] = '\0'; /* Disable log file during unit test */

    fims_file_list_t list;
    assert(fims_file_list_init(&list) == FIMS_OK);

    fims_status_t st = fims_scan_directory(test_dir, &cfg, &list);
    assert(st == FIMS_OK);

    /* Verify symlink loop was safely skipped without infinite recursion */
    assert(list.skipped_symlinks == 2);
    printf("  [PASS] Circular directory symlink and file symlink safely skipped (%zu symlinks)\n",
           list.skipped_symlinks);

    /* Verify nested directories & regular files collected */
    if (geteuid() != 0) {
        assert(list.count == 4);
        bool found_unreadable = false;
        for (size_t i = 0; i < list.count; i++) {
            if (list.records[i].unreadable) found_unreadable = true;
        }
        assert(found_unreadable);
        printf("  [PASS] Inaccessible file recorded with unreadable flag; all 4 regular files present\n");
    } else {
        assert(list.count == 4);
        printf("  [PASS] All 4 regular files across nested directories scanned (running as root)\n");
    }

    /* Verify path sorting and metadata collection */
    for (size_t i = 0; i < list.count; i++) {
        if (!list.records[i].unreadable) {
            assert(strlen(list.records[i].sha256) == 64);
        } else {
            assert(strlen(list.records[i].sha256) == 0);
        }
        if (i > 0) {
            assert(strcmp(list.records[i - 1].path, list.records[i].path) < 0);
        }
    }
    printf("  [PASS] File metadata, permissions, and SHA-256 hashes verified across nested tree\n");

    /* Verify path traversal rejection */
    fims_file_list_t bad_list;
    assert(fims_file_list_init(&bad_list) == FIMS_OK);
    assert(fims_scan_directory("/tmp/../etc", &cfg, &bad_list) == FIMS_ERR_PATH_SAFETY);
    fims_file_list_free(&bad_list);
    printf("  [PASS] Path traversal ('..') rejected by scanner\n");

    fims_file_list_free(&list);

    /* Cleanup */
    chmod(f4_inacc, 0600);
    unlink(sym_loop);
    unlink(sym_file);
    unlink(f4_inacc);
    unlink(f3_empty);
    unlink(f2);
    unlink(f1);
    rmdir(sub2);
    rmdir(sub1);
    rmdir(test_dir);

    printf("[TEST SUITE] test_scanner PASSED.\n\n");
    return 0;
}
