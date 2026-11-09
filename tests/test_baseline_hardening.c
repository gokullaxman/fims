#include "../src/baseline.h"
#include "../src/scanner.h"
#include "../src/config.h"
#include "../src/integrity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

static void create_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    assert(fp != NULL);
    if (content) {
        fwrite(content, 1, strlen(content), fp);
    }
    fclose(fp);
}

/* ----------------------------------------------------------------------------
 * Test Item 4: Filenames with tab/newline/percent/control characters
 * ---------------------------------------------------------------------------- */
static void test_item4_percent_encoding(void) {
    printf("[TEST] Item 4: Path percent-encoding and control characters...\n");

    char dir_tmpl[] = "/tmp/fims_test_item4_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char p_tab[FIMS_MAX_PATH];
    char p_nl[FIMS_MAX_PATH];
    char p_pct[FIMS_MAX_PATH];
    char p_cr[FIMS_MAX_PATH];
    char p_norm[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];

    snprintf(p_tab, sizeof(p_tab), "%s/we\tird", test_dir);
    snprintf(p_nl, sizeof(p_nl), "%s/a\nb", test_dir);
    snprintf(p_pct, sizeof(p_pct), "%s/pct%%file", test_dir);
    snprintf(p_cr, sizeof(p_cr), "%s/cr\rfile", test_dir);
    snprintf(p_norm, sizeof(p_norm), "%s/plain.txt", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);

    create_file(p_tab, "content with tab");
    create_file(p_nl, "content with newline");
    create_file(p_pct, "content with percent");
    create_file(p_cr, "content with cr");
    create_file(p_norm, "plain content");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    size_t count = 0;
    fims_status_t st = fims_baseline_init_from_dir(test_dir, &cfg, false, &count);
    assert(st == FIMS_OK);
    assert(count == 5);

    /* Verify percent-encoded representation inside the raw baseline file */
    FILE *raw_fp = fopen(base_path, "r");
    assert(raw_fp != NULL);
    char buf[FIMS_MAX_LINE * 8];
    size_t n = fread(buf, 1, sizeof(buf) - 1, raw_fp);
    fclose(raw_fp);
    buf[n] = '\0';

    assert(strstr(buf, "we%09ird") != NULL);
    assert(strstr(buf, "a%0Ab") != NULL);
    assert(strstr(buf, "pct%25file") != NULL);
    assert(strstr(buf, "cr%0Dfile") != NULL);

    /* Load and verify exact original filenames decoded in memory */
    fims_file_list_t loaded;
    st = fims_baseline_load(base_path, &loaded);
    assert(st == FIMS_OK);
    assert(loaded.count == 5);

    bool seen_tab = false, seen_nl = false, seen_pct = false, seen_cr = false, seen_norm = false;
    for (size_t i = 0; i < loaded.count; i++) {
        if (strcmp(loaded.records[i].path, p_tab) == 0) seen_tab = true;
        if (strcmp(loaded.records[i].path, p_nl) == 0) seen_nl = true;
        if (strcmp(loaded.records[i].path, p_pct) == 0) seen_pct = true;
        if (strcmp(loaded.records[i].path, p_cr) == 0) seen_cr = true;
        if (strcmp(loaded.records[i].path, p_norm) == 0) seen_norm = true;
    }
    assert(seen_tab && seen_nl && seen_pct && seen_cr && seen_norm);

    /* Integrity check against current files must yield 0 alerts */
    fims_file_list_t current;
    st = fims_file_list_init(&current);
    assert(st == FIMS_OK);
    st = fims_scan_directory(test_dir, &cfg, &current);
    assert(st == FIMS_OK);

    fims_report_t report;
    assert(fims_report_init(&report) == FIMS_OK);
    st = fims_check_integrity(&loaded, &current, &cfg, false, &report);
    assert(st == FIMS_OK);
    assert(report.count == 0);

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&loaded);

    /* Cleanup */
    unlink(base_path);
    unlink(p_tab);
    unlink(p_nl);
    unlink(p_pct);
    unlink(p_cr);
    unlink(p_norm);
    rmdir(test_dir);
    printf("  [PASS] Item 4 verified cleanly.\n");
}

/* ----------------------------------------------------------------------------
 * Test Item 8: Header digest tampering and HMAC-SHA256 support
 * ---------------------------------------------------------------------------- */
static void test_item8_header_digest_and_hmac(void) {
    printf("[TEST] Item 8: Header digest and HMAC-SHA256 authenticity...\n");

    char dir_tmpl[] = "/tmp/fims_test_item8_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];
    char key_path[FIMS_MAX_PATH];

    snprintf(f1, sizeof(f1), "%s/file1.txt", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);
    snprintf(key_path, sizeof(key_path), "%s/hmac_secret.key", test_dir);

    create_file(f1, "Sample data for item 8");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");
    fims_config_add_exclude(&cfg, "hmac_secret.key");

    /* 1. Baseline save without HMAC */
    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);
    assert(count == 1);
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* 2. Tampering with CREATED_AT header line must fail validation */
    FILE *fp = fopen(base_path, "r");
    assert(fp != NULL);
    char content[FIMS_MAX_LINE * 4];
    size_t sz = fread(content, 1, sizeof(content) - 1, fp);
    fclose(fp);
    content[sz] = '\0';

    char *created_pos = strstr(content, "CREATED_AT=");
    assert(created_pos != NULL);
    created_pos[11] = (created_pos[11] == '1') ? '2' : '1';

    fp = fopen(base_path, "w");
    assert(fp != NULL);
    fputs(content, fp);
    fclose(fp);

    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* 3. Tampering with RECORD_COUNT header line must fail validation */
    unlink(base_path);
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);
    fp = fopen(base_path, "r");
    assert(fp != NULL);
    sz = fread(content, 1, sizeof(content) - 1, fp);
    fclose(fp);
    content[sz] = '\0';

    char *rec_count_pos = strstr(content, "RECORD_COUNT=");
    assert(rec_count_pos != NULL);
    rec_count_pos[13] = '9';

    fp = fopen(base_path, "w");
    assert(fp != NULL);
    fputs(content, fp);
    fclose(fp);

    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* 4. Test HMAC-SHA256 */
    /* Create key file with 0600 mode */
    fp = fopen(key_path, "wb");
    assert(fp != NULL);
    fputs("top_secret_hmac_key_12345\n", fp);
    fclose(fp);
    assert(chmod(key_path, 0600) == 0);

    setenv("FIMS_HMAC_KEY_FILE", key_path, 1);

    unlink(base_path);
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);

    /* Verify HMAC header present */
    fp = fopen(base_path, "r");
    assert(fp != NULL);
    sz = fread(content, 1, sizeof(content) - 1, fp);
    fclose(fp);
    content[sz] = '\0';
    assert(strstr(content, "HMAC: ") != NULL);

    /* Validation succeeds with valid key */
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* Loading succeeds with valid key */
    fims_file_list_t hmac_list;
    assert(fims_baseline_load(base_path, &hmac_list) == FIMS_OK);
    fims_file_list_free(&hmac_list);

    /* Corrupt key content -> validation must fail with FIMS_ERR_CORRUPT */
    fp = fopen(key_path, "wb");
    assert(fp != NULL);
    fputs("wrong_secret_hmac_key_99999\n", fp);
    fclose(fp);
    assert(chmod(key_path, 0600) == 0);
    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* Insecure key permissions (0666) -> validation must fail with FIMS_ERR_CORRUPT */
    fp = fopen(key_path, "wb");
    assert(fp != NULL);
    fputs("top_secret_hmac_key_12345\n", fp);
    fclose(fp);
    assert(chmod(key_path, 0666) == 0);
    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* Restore 0600 permissions */
    assert(chmod(key_path, 0600) == 0);
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* Unset HMAC key env: loading an HMAC-signed baseline without key must return FIMS_ERR_CORRUPT */
    unsetenv("FIMS_HMAC_KEY_FILE");
    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* Cleanup */
    unlink(base_path);
    unlink(key_path);
    unlink(f1);
    rmdir(test_dir);
    printf("  [PASS] Item 8 verified cleanly.\n");
}

/* ----------------------------------------------------------------------------
 * Test Item 16: Safe baseline writes and atomic replacement
 * ---------------------------------------------------------------------------- */
static void test_item16_safe_writes_and_atomic_replace(void) {
    printf("[TEST] Item 16: Atomic safe baseline writes and overwrite protection...\n");

    char dir_tmpl[] = "/tmp/fims_test_item16_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];
    snprintf(f1, sizeof(f1), "%s/alpha.txt", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);

    create_file(f1, "Item 16 content");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);

    /* Check baseline permissions: strictly 0600 */
    struct stat st;
    assert(stat(base_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    /* Attempt save with allow_overwrite = false: MUST fail with FIMS_ERR_EXISTS */
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_ERR_EXISTS);

    /* Verify original baseline is still valid */
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* Save with allow_overwrite = true: succeeds */
    assert(fims_baseline_init_from_dir(test_dir, &cfg, true, &count) == FIMS_OK);
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* Verify no lingering .tmp. files in directory */
    char tmp_check[FIMS_MAX_PATH + 32];
    snprintf(tmp_check, sizeof(tmp_check), "%s.tmp.%d", base_path, (int)getpid());
    assert(access(tmp_check, F_OK) != 0);

    unlink(base_path);
    unlink(f1);
    rmdir(test_dir);
    printf("  [PASS] Item 16 verified cleanly.\n");
}

/* ----------------------------------------------------------------------------
 * Test Item 24: Reject baseline paths ending in /. or /..
 * ---------------------------------------------------------------------------- */
static void test_item24_path_traversal_validation(void) {
    printf("[TEST] Item 24: Path traversal and /. /.. rejection...\n");

    char dir_tmpl[] = "/tmp/fims_test_item24_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char f1[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];
    snprintf(f1, sizeof(f1), "%s/good.txt", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);

    create_file(f1, "Item 24 data");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    size_t count = 0;
    assert(fims_baseline_init_from_dir(test_dir, &cfg, false, &count) == FIMS_OK);

    /* Read baseline and inject a path ending in /.. */
    FILE *fp = fopen(base_path, "r");
    assert(fp != NULL);
    char content[FIMS_MAX_LINE * 4];
    size_t sz = fread(content, 1, sizeof(content) - 1, fp);
    fclose(fp);
    content[sz] = '\0';

    char *good_pos = strstr(content, "good.txt");
    assert(good_pos != NULL);
    /* Replace "good.txt" with "good/.." */
    memcpy(good_pos, "good/..\n", 8);

    fp = fopen(base_path, "w");
    assert(fp != NULL);
    fputs(content, fp);
    fclose(fp);

    /* Validation MUST reject the baseline as corrupt */
    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    /* Test path ending in /. */
    fp = fopen(base_path, "r");
    assert(fp != NULL);
    sz = fread(content, 1, sizeof(content) - 1, fp);
    fclose(fp);
    content[sz] = '\0';

    good_pos = strstr(content, "good/..");
    assert(good_pos != NULL);
    memcpy(good_pos, "good/. \n", 8);
    good_pos[6] = '\0';

    fp = fopen(base_path, "w");
    assert(fp != NULL);
    fputs(content, fp);
    fclose(fp);

    assert(fims_baseline_validate(base_path) == FIMS_ERR_CORRUPT);

    unlink(base_path);
    unlink(f1);
    rmdir(test_dir);
    printf("  [PASS] Item 24 verified cleanly.\n");
}

/* ----------------------------------------------------------------------------
 * Test Item 23: Multi-root appending in baseline
 * ---------------------------------------------------------------------------- */
static void test_item23_multi_root_appending(void) {
    printf("[TEST] Item 23: Multi-root appending...\n");

    char dir_tmpl1[] = "/tmp/fims_test_root1_XXXXXX";
    char dir_tmpl2[] = "/tmp/fims_test_root2_XXXXXX";
    char *root1 = mkdtemp(dir_tmpl1);
    char *root2 = mkdtemp(dir_tmpl2);
    assert(root1 != NULL && root2 != NULL);

    char r1_f1[FIMS_MAX_PATH];
    char r1_f2[FIMS_MAX_PATH];
    char r2_f1[FIMS_MAX_PATH];
    char r2_f2[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];

    snprintf(r1_f1, sizeof(r1_f1), "%s/r1_alpha.txt", root1);
    snprintf(r1_f2, sizeof(r1_f2), "%s/r1_beta.txt", root1);
    snprintf(r2_f1, sizeof(r2_f1), "%s/r2_gamma.txt", root2);
    snprintf(r2_f2, sizeof(r2_f2), "%s/r2_delta.txt", root2);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", root1);

    create_file(r1_f1, "Root 1 File 1");
    create_file(r1_f2, "Root 1 File 2");
    create_file(r2_f1, "Root 2 File 1");
    create_file(r2_f2, "Root 2 File 2");

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    /* 1. Init with root1 */
    size_t count = 0;
    assert(fims_baseline_init_from_dir(root1, &cfg, false, &count) == FIMS_OK);
    assert(count == 2);

    fims_file_list_t loaded;
    assert(fims_baseline_load(base_path, &loaded) == FIMS_OK);
    assert(loaded.root_dir_count == 1);
    assert(loaded.count == 2);
    fims_file_list_free(&loaded);

    /* 2. Append root2 without wiping root1 */
    assert(fims_baseline_add_root(base_path, root2, &cfg) == FIMS_OK);

    /* 3. Verify loaded baseline contains BOTH roots and ALL 4 files */
    assert(fims_baseline_load(base_path, &loaded) == FIMS_OK);
    assert(loaded.root_dir_count == 2);
    assert(loaded.count == 4);

    bool has_r1_f1 = false, has_r1_f2 = false, has_r2_f1 = false, has_r2_f2 = false;
    for (size_t i = 0; i < loaded.count; i++) {
        if (strcmp(loaded.records[i].path, r1_f1) == 0) has_r1_f1 = true;
        if (strcmp(loaded.records[i].path, r1_f2) == 0) has_r1_f2 = true;
        if (strcmp(loaded.records[i].path, r2_f1) == 0) has_r2_f1 = true;
        if (strcmp(loaded.records[i].path, r2_f2) == 0) has_r2_f2 = true;
    }
    assert(has_r1_f1 && has_r1_f2 && has_r2_f1 && has_r2_f2);
    fims_file_list_free(&loaded);

    /* Baseline validation must pass */
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    unlink(base_path);
    unlink(r1_f1);
    unlink(r1_f2);
    unlink(r2_f1);
    unlink(r2_f2);
    rmdir(root1);
    rmdir(root2);
    printf("  [PASS] Item 23 verified cleanly.\n");
}

/* ----------------------------------------------------------------------------
 * Test Item 10: Baseline serialization and deserialization of unreadable files
 * ---------------------------------------------------------------------------- */
static void test_item10_unreadable_file_baseline(void) {
    printf("[TEST] Item 10: Baseline persistence with unreadable/0000 files...\n");

    char dir_tmpl[] = "/tmp/fims_test_unreadable_base_XXXXXX";
    char *test_dir = mkdtemp(dir_tmpl);
    assert(test_dir != NULL);

    char p_readable[FIMS_MAX_PATH];
    char p_unreadable[FIMS_MAX_PATH];
    char base_path[FIMS_MAX_PATH];

    snprintf(p_readable, sizeof(p_readable), "%s/readable.txt", test_dir);
    snprintf(p_unreadable, sizeof(p_unreadable), "%s/secret.dat", test_dir);
    snprintf(base_path, sizeof(base_path), "%s/baseline.dat", test_dir);

    create_file(p_readable, "Public readable data");
    create_file(p_unreadable, "Confidential data");

    /* Mark secret.dat as mode 0000 (unreadable) */
    assert(chmod(p_unreadable, 0000) == 0);

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    snprintf(cfg.baseline_file, sizeof(cfg.baseline_file), "%s", base_path);
    cfg.log_file[0] = '\0';
    fims_config_add_exclude(&cfg, "baseline.dat");

    size_t count = 0;
    fims_status_t st = fims_baseline_init_from_dir(test_dir, &cfg, false, &count);
    assert(st == FIMS_OK);
    assert(count == 2);

    /* Cryptographic baseline validation must pass */
    assert(fims_baseline_validate(base_path) == FIMS_OK);

    /* Load baseline and verify metadata and unreadable flag */
    fims_file_list_t loaded;
    assert(fims_baseline_load(base_path, &loaded) == FIMS_OK);
    assert(loaded.count == 2);

    bool found_readable = false;
    bool found_unreadable = false;
    for (size_t i = 0; i < loaded.count; i++) {
        if (strcmp(loaded.records[i].path, p_readable) == 0) {
            found_readable = true;
            assert(!loaded.records[i].unreadable);
            assert(strlen(loaded.records[i].sha256) == 64);
        } else if (strcmp(loaded.records[i].path, p_unreadable) == 0) {
            found_unreadable = true;
            assert(loaded.records[i].unreadable);
            assert(loaded.records[i].sha256[0] == '\0');
        }
    }
    assert(found_readable && found_unreadable);
    fims_file_list_free(&loaded);

    /* Restore permission for cleanup */
    chmod(p_unreadable, 0600);
    unlink(p_readable);
    unlink(p_unreadable);
    unlink(base_path);
    rmdir(test_dir);
    printf("  [PASS] Item 10 unreadable baseline serialization verified cleanly.\n");
}

int main(void) {
    printf("============================================================\n");
    printf(" Executing Baseline Hardening Test Suite (Items 4, 8, 16, 24, 23, 10)\n");
    printf("============================================================\n");

    test_item4_percent_encoding();
    test_item8_header_digest_and_hmac();
    test_item16_safe_writes_and_atomic_replace();
    test_item24_path_traversal_validation();
    test_item23_multi_root_appending();
    test_item10_unreadable_file_baseline();

    printf("============================================================\n");
    printf(" ALL BASELINE HARDENING TESTS PASSED CLEANLY (6/6)\n");
    printf("============================================================\n");
    return 0;
}
