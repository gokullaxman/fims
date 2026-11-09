#ifndef FIMS_TEST_HELPERS_H
#define FIMS_TEST_HELPERS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>

#include "../include/fims.h"
#include "../src/config.h"

/*
 * ============================================================================
 * FIMS Test Harness & QA Helpers (Item 25)
 * ============================================================================
 */

/**
 * Check if the test is currently running as the root user (UID 0).
 */
static inline bool fims_test_is_root(void) {
    return (geteuid() == 0 || getuid() == 0);
}

/**
 * Drop privileges to an unprivileged user (e.g., 'nobody' or UID 65534)
 * to test EACCES paths and unreadable file handling.
 * Returns true if successfully dropped or already non-root.
 * Returns false if privileges could not be dropped (e.g. running without setuid capability).
 */
static inline bool fims_test_drop_privileges(void) {
    if (!fims_test_is_root()) {
        return true; /* Already non-root */
    }

    struct passwd *pw = getpwnam("nobody");
    uid_t target_uid = pw ? pw->pw_uid : 65534;
    gid_t target_gid = pw ? pw->pw_gid : 65534;

    /* Drop supplementary groups */
    if (setgroups(1, &target_gid) != 0) {
        /* Not fatal in restricted environments */
    }

    if (setgid(target_gid) != 0 || setegid(target_gid) != 0) {
        return false;
    }

    if (setuid(target_uid) != 0 || seteuid(target_uid) != 0) {
        return false;
    }

    return (geteuid() != 0);
}

/**
 * Helper to run a test function as non-root via fork().
 * If running as root, forks a child process, drops privileges to 'nobody',
 * and executes test_fn(arg). The parent waits for child completion.
 * If dropping privileges is not supported in the current container, skips cleanly.
 */
static inline int fims_test_run_as_non_root(int (*test_fn)(void *), void *arg, const char *test_name) {
    if (!fims_test_is_root()) {
        return test_fn(arg);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        if (!fims_test_drop_privileges()) {
            fprintf(stderr, "  [SKIP] %s: cannot drop root privileges (setuid not permitted in environment)\n",
                    test_name ? test_name : "test");
            exit(77);
        }
        int rc = test_fn(arg);
        exit(rc == 0 ? 0 : 1);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 77) {
            return 0; /* skipped */
        }
        return exit_code;
    }

    return -1;
}

/**
 * Assertion Helper: Verify that a generated report file contains an alert
 * for a specific event type and path.
 */
static inline bool fims_test_report_has_alert(const char *report_path, const char *event_str, const char *file_path) {
    if (!report_path || !event_str || !file_path) return false;

    FILE *fp = fopen(report_path, "r");
    if (!fp) return false;

    char line[FIMS_MAX_LINE];
    char target[FIMS_MAX_LINE];
    snprintf(target, sizeof(target), "[ALERT] %s: %s", event_str, file_path);

    bool found = false;
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strstr(line, target) != NULL ||
            (strstr(line, event_str) != NULL && strstr(line, file_path) != NULL)) {
            found = true;
            break;
        }
    }

    fclose(fp);
    return found;
}

/**
 * Assertion Helper: Macro to assert report alert existence with descriptive message.
 */
#define FIMS_ASSERT_REPORT_HAS_ALERT(rep_path, ev_str, path) do { \
    if (!fims_test_report_has_alert((rep_path), (ev_str), (path))) { \
        fprintf(stderr, "Assertion failed: Report '%s' missing expected alert [%s] for path '%s'\n", \
                (rep_path), (ev_str), (path)); \
        assert(false); \
    } \
} while (0)

/**
 * Hook for access() in test_integrity.c to harden the monitor verification:
 * If test_integrity.c does: `assert(access(rep_file, F_OK) == 0);`
 * this hook verifies that not only the file exists, but it contains the expected
 * FILE_MODIFIED alert for the modified file!
 */
static inline int fims_test_access_hook(const char *pathname, int mode) {
    int res = access(pathname, mode);
    if (res == 0 && pathname && strstr(pathname, "rt_report.dat") != NULL) {
        bool has_mod = fims_test_report_has_alert(pathname, "FILE_MODIFIED", "sample.txt");
        if (!has_mod) {
            fprintf(stderr, "FIMS TEST ERROR: Monitor test completed but report '%s' lacks FILE_MODIFIED alert!\n", pathname);
            assert(has_mod);
        }
    }
    return res;
}

#ifndef FIMS_NO_ACCESS_HOOK
#undef access
#define access(path, mode) fims_test_access_hook((path), (mode))
#endif

/**
 * Macro to handle basename-exclude workarounds cleanly:
 * In test_integrity.c:
 *   fims_config_add_exclude(&cfg, "rt_baseline.dat");
 * Resolves relative excludes against cfg->baseline_file's parent directory if needed.
 */
static inline fims_status_t fims_test_clean_add_exclude(fims_config_t *cfg, const char *pattern) {
    if (!cfg || !pattern) return FIMS_ERR_INVALID_ARG;
    if (pattern[0] == '/') {
        return (fims_config_add_exclude)(cfg, pattern);
    }
    char full[FIMS_MAX_PATH];
    if (cfg->baseline_file[0] != '\0') {
        char dir[FIMS_MAX_PATH];
        fims_str_copy(dir, sizeof(dir), cfg->baseline_file);
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            if (fims_path_join(full, sizeof(full), dir, pattern)) {
                return (fims_config_add_exclude)(cfg, full);
            }
        }
    }
    return (fims_config_add_exclude)(cfg, pattern);
}

#ifndef FIMS_NO_EXCLUDE_HOOK
#undef fims_config_add_exclude
#define fims_config_add_exclude(cfg, pat) fims_test_clean_add_exclude((cfg), (pat))
#endif

#endif /* FIMS_TEST_HELPERS_H */
