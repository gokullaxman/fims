#include "../src/baseline.h"
#include "../src/scanner.h"
#include "../src/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    printf("[TEST SUITE] Running test_baseline...\n");

    char dir_template[] = "/tmp/fims_test_baseline_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    char f2[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];

    snprintf(f1, sizeof(f1), "%s/alpha.txt", test_dir);
    snprintf(f2, sizeof(f2), "%s/beta.txt", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);

    FILE *fp = fopen(f1, "wb");
    assert(fp != NULL);
    fwrite("Alpha baseline content\n", 1, 23, fp);
    fclose(fp);

    fp = fopen(f2, "wb");
    assert(fp != NULL);
    fwrite("Beta baseline content\n", 1, 22, fp);
    fclose(fp);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    /* 1. Initialize baseline */
    size_t count = 0;
    fims_status_t st = fims_baseline_init_from_dir(test_dir, &cfg, false, &count);
    assert(st == FIMS_OK);
    assert(count == 2);
    printf("  [PASS] Baseline initialized with %zu files\n", count);

    /* 2. Verify restrictive 0600 permissions on baseline file */
    struct stat st_buf;
    assert(stat(base_path, &st_buf) == 0);
    assert((st_buf.st_mode & 0777) == 0600);
    printf("  [PASS] Baseline file protected with restrictive 0600 permissions\n");

    /* 3. Verify overwrite protection when allow_overwrite == false */
    st = fims_baseline_init_from_dir(test_dir, &cfg, false, &count);
    assert(st == FIMS_ERR_EXISTS);
    printf("  [PASS] Accidental baseline overwrite prevented (FIMS_ERR_EXISTS)\n");

    /* 4. Load and validate baseline */
    fims_file_list_t loaded;
    assert(fims_baseline_load(base_path, &loaded) == FIMS_OK);
    assert(loaded.count == 2);
    fims_file_list_free(&loaded);
    printf("  [PASS] Baseline loaded and cryptographic checksum verified\n");

    /* 5. Test corrupted baseline detection (Requirement 7.6) */
    fp = fopen(base_path, "r+b");
    assert(fp != NULL);
    /* Corrupt a byte inside the record body */
    assert(fseek(fp, -25, SEEK_END) == 0);
    fputc('X', fp);
    fclose(fp);

    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);
    printf("  [PASS] Corrupted baseline record detected and rejected (FIMS_ERR_CORRUPT)\n");

    /* 6. Test malformed header detection */
    fp = fopen(base_path, "wb");
    assert(fp != NULL);
    fprintf(fp, "MALFORMED_HEADER_V0\nGARBAGE\n");
    fclose(fp);
    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);
    printf("  [PASS] Malformed baseline header rejected (FIMS_ERR_CORRUPT)\n");

    /* Cleanup */
    unlink(base_path);
    unlink(f2);
    unlink(f1);
    rmdir(test_dir);

    printf("[TEST SUITE] test_baseline PASSED.\n\n");
    return 0;
}
