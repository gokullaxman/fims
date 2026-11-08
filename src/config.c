#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static void safe_copy_str(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_size, "%s", src);
}

static void trim_whitespace(char *str) {
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

fims_status_t fims_sanitize_path(const char *input_path, char *out_path, size_t out_size) {
    if (!input_path || !out_path || out_size < 2 || input_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    /* Security check: Reject raw '..' path traversal segments */
    const char *p = input_path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p == input_path || p[-1] == '/') &&
            (p[2] == '/' || p[2] == '\0')) {
            return FIMS_ERR_PATH_SAFETY;
        }
        p++;
    }

    /* Try realpath if the path already exists on disk */
    char resolved[PATH_MAX];
    if (realpath(input_path, resolved) != NULL) {
        if (strlen(resolved) >= out_size) {
            return FIMS_ERR_INVALID_ARG;
        }
        safe_copy_str(out_path, out_size, resolved);
        return FIMS_OK;
    }

    /* If path does not exist yet (e.g. baseline/log file to be created), build clean absolute path */
    if (input_path[0] == '/') {
        if (strlen(input_path) >= out_size) {
            return FIMS_ERR_INVALID_ARG;
        }
        safe_copy_str(out_path, out_size, input_path);
    } else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            return FIMS_ERR_IO;
        }
        int n = snprintf(out_path, out_size, "%s/%s", cwd, input_path);
        if (n < 0 || (size_t)n >= out_size) {
            return FIMS_ERR_INVALID_ARG;
        }
    }

    /* Strip trailing slash unless root "/" */
    size_t len = strlen(out_path);
    while (len > 1 && out_path[len - 1] == '/') {
        out_path[len - 1] = '\0';
        len--;
    }

    return FIMS_OK;
}

void fims_config_init_defaults(fims_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));

    cfg->scan_interval_sec = 30;
    cfg->monitor_mode = MODE_HYBRID;
    cfg->min_alert_severity = SEV_LOW;
    cfg->alert_threshold_count = 10;
    cfg->follow_symlinks = false;
    cfg->detect_renames = true;

    const char *env_base = getenv("FIMS_BASELINE_PATH");
    const char *env_log = getenv("FIMS_LOG_PATH");
    const char *env_rep = getenv("FIMS_REPORT_PATH");
    const char *env_state = getenv("FIMS_STATE_PATH");

    safe_copy_str(cfg->baseline_file, sizeof(cfg->baseline_file), env_base ? env_base : FIMS_DEFAULT_BASELINE);
    safe_copy_str(cfg->log_file, sizeof(cfg->log_file), env_log ? env_log : FIMS_DEFAULT_LOG);
    safe_copy_str(cfg->report_file, sizeof(cfg->report_file), env_rep ? env_rep : FIMS_DEFAULT_REPORT);
    safe_copy_str(cfg->state_file, sizeof(cfg->state_file), env_state ? env_state : FIMS_DEFAULT_STATE);

    /* Default exclusions: FIMS internal data/log directories and .git */
    fims_config_add_exclude(cfg, "data/baseline.dat");
    fims_config_add_exclude(cfg, "logs/fims.log");
    fims_config_add_exclude(cfg, ".git");
}

fims_status_t fims_config_add_dir(fims_config_t *cfg, const char *dir_path) {
    if (!cfg || !dir_path) return FIMS_ERR_INVALID_ARG;
    if (cfg->monitored_dir_count >= FIMS_MAX_DIRS) return FIMS_ERR_NOMEM;

    char clean[FIMS_MAX_PATH];
    fims_status_t st = fims_sanitize_path(dir_path, clean, sizeof(clean));
    if (st != FIMS_OK) return st;

    for (size_t i = 0; i < cfg->monitored_dir_count; i++) {
        if (strcmp(cfg->monitored_dirs[i], clean) == 0) {
            return FIMS_OK; /* Already present */
        }
    }

    safe_copy_str(cfg->monitored_dirs[cfg->monitored_dir_count], FIMS_MAX_PATH, clean);
    cfg->monitored_dir_count++;
    return FIMS_OK;
}

fims_status_t fims_config_add_exclude(fims_config_t *cfg, const char *exclude_path) {
    if (!cfg || !exclude_path || exclude_path[0] == '\0') return FIMS_ERR_INVALID_ARG;
    if (cfg->excluded_count >= FIMS_MAX_EXCLUDES) return FIMS_ERR_NOMEM;

    for (size_t i = 0; i < cfg->excluded_count; i++) {
        if (strcmp(cfg->excluded_paths[i], exclude_path) == 0) {
            return FIMS_OK;
        }
    }

    safe_copy_str(cfg->excluded_paths[cfg->excluded_count], FIMS_MAX_PATH, exclude_path);
    cfg->excluded_count++;
    return FIMS_OK;
}

bool fims_config_is_excluded(const fims_config_t *cfg, const char *path) {
    if (!cfg || !path) return false;
    for (size_t i = 0; i < cfg->excluded_count; i++) {
        const char *ex = cfg->excluded_paths[i];
        if (ex[0] == '\0') continue;
        size_t ex_len = strlen(ex);
        /* Match exact path, prefix boundary, or basename suffix */
        if (strcmp(path, ex) == 0) return true;
        if (strncmp(path, ex, ex_len) == 0 && (path[ex_len] == '/' || path[ex_len] == '\0')) {
            return true;
        }
        const char *base = strrchr(path, '/');
        if (base && strcmp(base + 1, ex) == 0) {
            return true;
        }
    }
    return false;
}

fims_status_t fims_config_load(fims_config_t *cfg, const char *config_path) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;
    const char *path = config_path ? config_path : getenv("FIMS_CONFIG_PATH");
    if (!path) path = FIMS_DEFAULT_CONFIG;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return FIMS_ERR_NOT_FOUND;
    }

    char line[FIMS_MAX_LINE];
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_whitespace(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim_whitespace(key);
        trim_whitespace(val);

        if (strcmp(key, "monitored_dir") == 0) {
            fims_config_add_dir(cfg, val);
        } else if (strcmp(key, "exclude_path") == 0) {
            fims_config_add_exclude(cfg, val);
        } else if (strcmp(key, "scan_interval_sec") == 0) {
            long v = strtol(val, NULL, 10);
            if (v > 0 && v <= 86400) cfg->scan_interval_sec = (uint32_t)v;
        } else if (strcmp(key, "log_file") == 0) {
            safe_copy_str(cfg->log_file, sizeof(cfg->log_file), val);
        } else if (strcmp(key, "baseline_file") == 0) {
            safe_copy_str(cfg->baseline_file, sizeof(cfg->baseline_file), val);
        } else if (strcmp(key, "report_file") == 0) {
            safe_copy_str(cfg->report_file, sizeof(cfg->report_file), val);
        } else if (strcmp(key, "monitor_mode") == 0) {
            if (strcmp(val, "passive") == 0) cfg->monitor_mode = MODE_PASSIVE_SCAN;
            else if (strcmp(val, "realtime") == 0) cfg->monitor_mode = MODE_REALTIME_INOTIFY;
            else cfg->monitor_mode = MODE_HYBRID;
        } else if (strcmp(key, "alert_threshold") == 0) {
            long v = strtol(val, NULL, 10);
            if (v > 0) cfg->alert_threshold_count = (uint32_t)v;
        } else if (strcmp(key, "detect_renames") == 0) {
            cfg->detect_renames = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
    }

    fclose(fp);
    return FIMS_OK;
}

fims_status_t fims_config_save(const fims_config_t *cfg, const char *config_path) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;
    const char *path = config_path ? config_path : getenv("FIMS_CONFIG_PATH");
    if (!path) path = FIMS_DEFAULT_CONFIG;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return FIMS_ERR_IO;

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return FIMS_ERR_IO;
    }

    fprintf(fp, "# FIMS Configuration File\n");
    for (size_t i = 0; i < cfg->monitored_dir_count; i++) {
        fprintf(fp, "monitored_dir = %s\n", cfg->monitored_dirs[i]);
    }
    for (size_t i = 0; i < cfg->excluded_count; i++) {
        fprintf(fp, "exclude_path = %s\n", cfg->excluded_paths[i]);
    }
    fprintf(fp, "scan_interval_sec = %u\n", cfg->scan_interval_sec);
    fprintf(fp, "log_file = %s\n", cfg->log_file);
    fprintf(fp, "baseline_file = %s\n", cfg->baseline_file);
    fprintf(fp, "report_file = %s\n", cfg->report_file);
    fprintf(fp, "monitor_mode = %s\n",
            cfg->monitor_mode == MODE_PASSIVE_SCAN ? "passive" :
            (cfg->monitor_mode == MODE_REALTIME_INOTIFY ? "realtime" : "hybrid"));
    fprintf(fp, "alert_threshold = %u\n", cfg->alert_threshold_count);
    fprintf(fp, "detect_renames = %s\n", cfg->detect_renames ? "true" : "false");

    fclose(fp);
    return FIMS_OK;
}

void fims_config_print(const fims_config_t *cfg) {
    if (!cfg) return;
    printf("============================================================\n");
    printf(" FIMS Configuration Summary (v%s)\n", FIMS_VERSION);
    printf("============================================================\n");
    printf(" Baseline File       : %s\n", cfg->baseline_file);
    printf(" Log File            : %s\n", cfg->log_file);
    printf(" Last Report File    : %s\n", cfg->report_file);
    printf(" Monitoring Mode     : %s\n",
           cfg->monitor_mode == MODE_PASSIVE_SCAN ? "PASSIVE_SCAN" :
           (cfg->monitor_mode == MODE_REALTIME_INOTIFY ? "REALTIME_INOTIFY" : "HYBRID (inotify + periodic scan)"));
    printf(" Scan Interval       : %u seconds\n", cfg->scan_interval_sec);
    printf(" Alert Threshold     : %u events/scan\n", cfg->alert_threshold_count);
    printf(" Follow Symlinks     : %s (safe loop prevention active)\n", cfg->follow_symlinks ? "YES" : "NO");
    printf(" Rename Detection    : %s\n", cfg->detect_renames ? "ENABLED" : "DISABLED");
    printf(" Monitored Dirs (%zu)  :\n", cfg->monitored_dir_count);
    if (cfg->monitored_dir_count == 0) {
        printf("   (derived from active baseline on scan/monitor)\n");
    } else {
        for (size_t i = 0; i < cfg->monitored_dir_count; i++) {
            printf("   - %s\n", cfg->monitored_dirs[i]);
        }
    }
    printf(" Excluded Paths (%zu)  :\n", cfg->excluded_count);
    for (size_t i = 0; i < cfg->excluded_count; i++) {
        printf("   - %s\n", cfg->excluded_paths[i]);
    }
    printf("============================================================\n");
}
