#include "../src/hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Known NIST SHA-256 test vectors */
#define EMPTY_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define ABC_SHA256   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

int main(void) {
    printf("[TEST SUITE] Running test_hash...\n");

    char dir_template[] = "/tmp/fims_test_hash_XXXXXX";
    char *test_dir = mkdtemp(dir_template);
    assert(test_dir != NULL);

    char path_empty[FIMS_MAX_PATH];
    char path_abc[FIMS_MAX_PATH];
    char path_large[FIMS_MAX_PATH];
    char path_inaccessible[FIMS_MAX_PATH];
    char path_symlink[FIMS_MAX_PATH];

    snprintf(path_empty, sizeof(path_empty), "%s/empty.txt", test_dir);
    snprintf(path_abc, sizeof(path_abc), "%s/abc.txt", test_dir);
    snprintf(path_large, sizeof(path_large), "%s/large.bin", test_dir);
    snprintf(path_inaccessible, sizeof(path_inaccessible), "%s/secret.txt", test_dir);
    snprintf(path_symlink, sizeof(path_symlink), "%s/link.txt", test_dir);

    /* 1. Test empty file (Requirement 7.7) */
    FILE *fp = fopen(path_empty, "wb");
    assert(fp != NULL);
    fclose(fp);

    char hash_out[FIMS_HASH_HEX_LEN];
    fims_status_t st = fims_hash_file_sha256(path_empty, hash_out);
    assert(st == FIMS_OK);
    assert(strcmp(hash_out, EMPTY_SHA256) == 0);
    printf("  [PASS] Empty file SHA-256 vector verified (%s)\n", hash_out);

    /* 2. Test known content "abc" */
    fp = fopen(path_abc, "wb");
    assert(fp != NULL);
    fwrite("abc", 1, 3, fp);
    fclose(fp);

    st = fims_hash_file_sha256(path_abc, hash_out);
    assert(st == FIMS_OK);
    assert(strcmp(hash_out, ABC_SHA256) == 0);
    printf("  [PASS] Known NIST 'abc' SHA-256 vector verified\n");

    /* 3. Test large multi-chunk file > 2.5 MB (Requirement 7.8) */
    fp = fopen(path_large, "wb");
    assert(fp != NULL);
    size_t total_written = 0;
    unsigned char pattern[4096];
    for (size_t i = 0; i < sizeof(pattern); i++) {
        pattern[i] = (unsigned char)(i & 0xFF);
    }
    for (int i = 0; i < 650; i++) { /* 650 * 4096 = 2,662,400 bytes (~2.66 MB, > 40 chunks) */
        fwrite(pattern, 1, sizeof(pattern), fp);
        total_written += sizeof(pattern);
    }
    fclose(fp);

    char hash_large1[FIMS_HASH_HEX_LEN];
    char hash_large2[FIMS_HASH_HEX_LEN];
    assert(fims_hash_file_sha256(path_large, hash_large1) == FIMS_OK);
    assert(fims_hash_file_sha256(path_large, hash_large2) == FIMS_OK);
    assert(strcmp(hash_large1, hash_large2) == 0);
    assert(strlen(hash_large1) == 64);
    printf("  [PASS] Large file (%zu bytes) multi-chunk streaming SHA-256 verified (%s)\n",
           total_written, hash_large1);

    /* 4. Test symlink rejection via O_NOFOLLOW (Requirement 7.11) */
    assert(symlink(path_abc, path_symlink) == 0);
    st = fims_hash_file_sha256(path_symlink, hash_out);
    assert(st != FIMS_OK);
    printf("  [PASS] Symlink rejected safely by O_NOFOLLOW in hash generator\n");

    /* 5. Test inaccessible file handling (Requirement 7.9) */
    fp = fopen(path_inaccessible, "wb");
    assert(fp != NULL);
    fwrite("secret", 1, 6, fp);
    fclose(fp);
    assert(chmod(path_inaccessible, 0000) == 0);
    if (geteuid() != 0) {
        st = fims_hash_file_sha256(path_inaccessible, hash_out);
        assert(st == FIMS_ERR_PERMISSION);
        printf("  [PASS] Inaccessible file (mode 0000) returned FIMS_ERR_PERMISSION cleanly\n");
    } else {
        printf("  [INFO] Running as root (EUID 0); skipping mode 0000 EACCES assertion\n");
    }
    chmod(path_inaccessible, 0600);

    /* Cleanup temporary files */
    unlink(path_symlink);
    unlink(path_inaccessible);
    unlink(path_large);
    unlink(path_abc);
    unlink(path_empty);
    rmdir(test_dir);

    printf("[TEST SUITE] test_hash PASSED.\n\n");
    return 0;
}
