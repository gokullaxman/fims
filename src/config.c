#include "config.h"

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fnmatch.h>

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

static const char *get_env_override(const char *name1, const char *name2) {
    const char *v = getenv(name1);
    if (v && v[0] != '\0') return v;
    if (name2) {
        v = getenv(name2);
        if (v && v[0] != '\0') return v;
    }
    return NULL;
}

static void get_user_fallback_dir(char *state_dir, size_t state_sz, char *conf_dir, size_t conf_sz) {
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0') {
        struct passwd *pw = getpwuid(geteuid());
        if (pw && pw->pw_dir) {
            home = pw->pw_dir;
        }
    }
    if (!home || home[0] == '\0') {
        home = "/tmp";
    }
    snprintf(state_dir, state_sz, "%s/.local/state/fims", home);
    snprintf(conf_dir, conf_sz, "%s/.config/fims", home);
}

fims_status_t fims_check_file_security(const char *path) {
    if (!path || path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        if (errno == EACCES || errno == EPERM) return FIMS_ERR_PERMISSION;
        return FIMS_ERR_IO;
    }

    if (!S_ISREG(st.st_mode)) {
        return FIMS_ERR_PERMISSION;
    }

    uid_t euid = geteuid();
    if (st.st_uid != euid && st.st_uid != 0) {
        return FIMS_ERR_PERMISSION;
    }

    if (st.st_mode & 0022) {
        return FIMS_ERR_PERMISSION;
    }

    return FIMS_OK;
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

    bool use_user_fallback = false;
    if (geteuid() != 0) {
        use_user_fallback = true;
    } else {
        if (access("/var/lib", W_OK) != 0 || access("/var/log", W_OK) != 0) {
            use_user_fallback = true;
        }
    }

    char def_base[FIMS_MAX_PATH];
    char def_log[FIMS_MAX_PATH];
    char def_rep[FIMS_MAX_PATH];
    char def_state[FIMS_MAX_PATH];
    char def_cfg[FIMS_MAX_PATH];

    if (use_user_fallback) {
        char state_dir[FIMS_MAX_PATH];
        char conf_dir[FIMS_MAX_PATH];
        get_user_fallback_dir(state_dir, sizeof(state_dir), conf_dir, sizeof(conf_dir));

        fims_path_join(def_base, sizeof(def_base), state_dir, "baseline.dat");
        fims_path_join(def_log, sizeof(def_log), state_dir, "fims.log");
        fims_path_join(def_rep, sizeof(def_rep), state_dir, "last_report.dat");
        fims_path_join(def_state, sizeof(def_state), state_dir, "status.dat");
        fims_path_join(def_cfg, sizeof(def_cfg), conf_dir, "fims.conf");
    } else {
        safe_copy_str(def_base, sizeof(def_base), FIMS_DEFAULT_BASELINE);
        safe_copy_str(def_log, sizeof(def_log), FIMS_DEFAULT_LOG);
        safe_copy_str(def_rep, sizeof(def_rep), FIMS_DEFAULT_REPORT);
        safe_copy_str(def_state, sizeof(def_state), FIMS_DEFAULT_STATE);
        safe_copy_str(def_cfg, sizeof(def_cfg), FIMS_DEFAULT_CONFIG);
    }

    const char *env_base = get_env_override("FIMS_BASELINE_FILE", "FIMS_BASELINE_PATH");
    const char *env_log  = get_env_override("FIMS_LOG_FILE", "FIMS_LOG_PATH");
    const char *env_rep  = get_env_override("FIMS_REPORT_FILE", "FIMS_REPORT_PATH");
    const char *env_state= get_env_override("FIMS_STATE_FILE", "FIMS_STATE_PATH");
    const char *env_cfg  = get_env_override("FIMS_CONFIG_FILE", "FIMS_CONFIG_PATH");

    safe_copy_str(cfg->baseline_file, sizeof(cfg->baseline_file), env_base ? env_base : def_base);
    safe_copy_str(cfg->log_file, sizeof(cfg->log_file), env_log ? env_log : def_log);
    safe_copy_str(cfg->report_file, sizeof(cfg->report_file), env_rep ? env_rep : def_rep);
    safe_copy_str(cfg->state_file, sizeof(cfg->state_file), env_state ? env_state : def_state);
    safe_copy_str(cfg->config_file, sizeof(cfg->config_file), env_cfg ? env_cfg : def_cfg);

    /* Default exclusions: FIMS internal files only (NO .git by default!) */
    fims_config_add_exclude(cfg, cfg->baseline_file);
    fims_config_add_exclude(cfg, cfg->log_file);
    fims_config_add_exclude(cfg, cfg->report_file);
    fims_config_add_exclude(cfg, cfg->state_file);
    fims_config_add_exclude(cfg, cfg->config_file);
}

fims_status_t fims_config_add_dir(fims_config_t *cfg, const char *dir_path) {
    if (!cfg || !dir_path || dir_path[0] == '\0') return FIMS_ERR_INVALID_ARG;
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

    char clean[FIMS_MAX_PATH];
    if (exclude_path[0] == '/') {
        safe_copy_str(clean, sizeof(clean), exclude_path);
    } else {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            return FIMS_ERR_IO;
        }
        int n = snprintf(clean, sizeof(clean), "%s/%s", cwd, exclude_path);
        if (n < 0 || (size_t)n >= sizeof(clean)) {
            return FIMS_ERR_INVALID_ARG;
        }
    }

    /* Strip trailing slashes unless "/" */
    size_t len = strlen(clean);
    while (len > 1 && clean[len - 1] == '/') {
        clean[len - 1] = '\0';
        len--;
    }

    for (size_t i = 0; i < cfg->excluded_count; i++) {
        if (strcmp(cfg->excluded_paths[i], clean) == 0) {
            return FIMS_OK;
        }
    }

    safe_copy_str(cfg->excluded_paths[cfg->excluded_count], FIMS_MAX_PATH, clean);
    cfg->excluded_count++;
    return FIMS_OK;
}

fims_status_t fims_config_add_exclude_glob(fims_config_t *cfg, const char *pattern) {
    if (!cfg || !pattern || pattern[0] == '\0') return FIMS_ERR_INVALID_ARG;
    if (cfg->excluded_count >= FIMS_MAX_EXCLUDES) return FIMS_ERR_NOMEM;

    char buf[FIMS_MAX_PATH];
    int n = snprintf(buf, sizeof(buf), "glob:%s", pattern);
    if (n < 0 || (size_t)n >= sizeof(buf)) return FIMS_ERR_INVALID_ARG;

    for (size_t i = 0; i < cfg->excluded_count; i++) {
        if (strcmp(cfg->excluded_paths[i], buf) == 0) {
            return FIMS_OK;
        }
    }

    safe_copy_str(cfg->excluded_paths[cfg->excluded_count], FIMS_MAX_PATH, buf);
    cfg->excluded_count++;
    return FIMS_OK;
}

static bool matches_exact_or_dir_prefix(const char *path, const char *target) {
    if (!path || !target || target[0] == '\0') return false;

    char abs_target[FIMS_MAX_PATH];
    if (target[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) return false;
        int n = snprintf(abs_target, sizeof(abs_target), "%s/%s", cwd, target);
        if (n < 0 || (size_t)n >= sizeof(abs_target)) return false;
    } else {
        safe_copy_str(abs_target, sizeof(abs_target), target);
    }

    size_t tlen = strlen(abs_target);
    while (tlen > 1 && abs_target[tlen - 1] == '/') {
        abs_target[--tlen] = '\0';
    }

    if (strcmp(path, abs_target) == 0) return true;
    if (strncmp(path, abs_target, tlen) == 0 && path[tlen] == '/') return true;
    return false;
}

static bool matches_baseline_tmp(const char *path, const char *baseline_file) {
    if (!path || !baseline_file || baseline_file[0] == '\0') return false;

    char abs_base[FIMS_MAX_PATH];
    if (baseline_file[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL) return false;
        int n = snprintf(abs_base, sizeof(abs_base), "%s/%s", cwd, baseline_file);
        if (n < 0 || (size_t)n >= sizeof(abs_base)) return false;
    } else {
        safe_copy_str(abs_base, sizeof(abs_base), baseline_file);
    }

    size_t blen = strlen(abs_base);
    while (blen > 1 && abs_base[blen - 1] == '/') {
        abs_base[--blen] = '\0';
    }

    if (strncmp(path, abs_base, blen) == 0) {
        const char *suffix = path + blen;
        if (strncmp(suffix, ".tmp.", 5) == 0 || strcmp(suffix, ".tmp") == 0) {
            return true;
        }
    }
    return false;
}

bool fims_config_is_excluded(const fims_config_t *cfg, const char *path) {
    if (!cfg || !path || path[0] == '\0') return false;

    char resolved_path[FIMS_MAX_PATH];
    if (path[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            int n = snprintf(resolved_path, sizeof(resolved_path), "%s/%s", cwd, path);
            if (n >= 0 && (size_t)n < sizeof(resolved_path)) {
                path = resolved_path;
            }
        }
    }

    /* 1. Automatically exclude cfg->baseline_file, log_file, report_file, state_file, config_file, <baseline>.tmp.* */
    if (cfg->baseline_file[0] != '\0') {
        if (matches_exact_or_dir_prefix(path, cfg->baseline_file)) return true;
        if (matches_baseline_tmp(path, cfg->baseline_file)) return true;
    }
    if (cfg->log_file[0] != '\0' && matches_exact_or_dir_prefix(path, cfg->log_file)) {
        return true;
    }
    if (cfg->report_file[0] != '\0' && matches_exact_or_dir_prefix(path, cfg->report_file)) {
        return true;
    }
    if (cfg->state_file[0] != '\0') {
        if (matches_exact_or_dir_prefix(path, cfg->state_file)) return true;
        if (matches_baseline_tmp(path, cfg->state_file)) return true;
    }
    if (cfg->config_file[0] != '\0') {
        if (matches_exact_or_dir_prefix(path, cfg->config_file)) return true;
    } else {
        const char *env_cfg = get_env_override("FIMS_CONFIG_FILE", "FIMS_CONFIG_PATH");
        if (matches_exact_or_dir_prefix(path, env_cfg ? env_cfg : FIMS_DEFAULT_CONFIG)) return true;
    }

    /* 2. Check explicitly configured exclusions */
    for (size_t i = 0; i < cfg->excluded_count; i++) {
        const char *ex = cfg->excluded_paths[i];
        if (ex[0] == '\0') continue;

        if (strncmp(ex, "glob:", 5) == 0) {
            const char *pattern = ex + 5;
            if (fnmatch(pattern, path, 0) == 0) return true;
            const char *base = strrchr(path, '/');
            if (base && fnmatch(pattern, base + 1, 0) == 0) return true;
        } else {
            /* Only exclude exact absolute paths or directory prefixes matching on a '/' boundary */
            if (matches_exact_or_dir_prefix(path, ex)) {
                return true;
            }
        }
    }
    return false;
}

fims_status_t fims_config_load(fims_config_t *cfg, const char *config_path) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;
    const char *path = config_path ? config_path : get_env_override("FIMS_CONFIG_FILE", "FIMS_CONFIG_PATH");
    if (!path) path = (cfg->config_file[0] != '\0') ? cfg->config_file : FIMS_DEFAULT_CONFIG;
    safe_copy_str(cfg->config_file, sizeof(cfg->config_file), path);

    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        if (errno == EACCES || errno == EPERM || errno == ELOOP) return FIMS_ERR_PERMISSION;
        return FIMS_ERR_IO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return FIMS_ERR_IO;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return FIMS_ERR_PERMISSION;
    }
    uid_t euid = geteuid();
    if (st.st_uid != euid && st.st_uid != 0) {
        close(fd);
        return FIMS_ERR_PERMISSION;
    }
    if (st.st_mode & 0022) {
        close(fd);
        return FIMS_ERR_PERMISSION;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        return FIMS_ERR_IO;
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
        } else if (strcmp(key, "exclude_glob") == 0) {
            fims_config_add_exclude_glob(cfg, val);
        } else if (strcmp(key, "scan_interval_sec") == 0) {
            long v = strtol(val, NULL, 10);
            if (v > 0 && v <= 86400) cfg->scan_interval_sec = (uint32_t)v;
        } else if (strcmp(key, "log_file") == 0) {
            safe_copy_str(cfg->log_file, sizeof(cfg->log_file), val);
        } else if (strcmp(key, "baseline_file") == 0) {
            safe_copy_str(cfg->baseline_file, sizeof(cfg->baseline_file), val);
        } else if (strcmp(key, "report_file") == 0) {
            safe_copy_str(cfg->report_file, sizeof(cfg->report_file), val);
        } else if (strcmp(key, "state_file") == 0) {
            safe_copy_str(cfg->state_file, sizeof(cfg->state_file), val);
        } else if (strcmp(key, "monitor_mode") == 0) {
            if (strcmp(val, "passive") == 0) cfg->monitor_mode = MODE_PASSIVE_SCAN;
            else if (strcmp(val, "realtime") == 0) cfg->monitor_mode = MODE_REALTIME_INOTIFY;
            else cfg->monitor_mode = MODE_HYBRID;
        } else if (strcmp(key, "min_alert_severity") == 0) {
            if (strcmp(val, "info") == 0) cfg->min_alert_severity = SEV_INFO;
            else if (strcmp(val, "low") == 0) cfg->min_alert_severity = SEV_LOW;
            else if (strcmp(val, "medium") == 0) cfg->min_alert_severity = SEV_MEDIUM;
            else if (strcmp(val, "high") == 0) cfg->min_alert_severity = SEV_HIGH;
            else if (strcmp(val, "critical") == 0) cfg->min_alert_severity = SEV_CRITICAL;
        } else if (strcmp(key, "alert_threshold") == 0 || strcmp(key, "alert_threshold_count") == 0) {
            long v = strtol(val, NULL, 10);
            if (v >= 0) cfg->alert_threshold_count = (uint32_t)v;
        } else if (strcmp(key, "follow_symlinks") == 0) {
            cfg->follow_symlinks = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        } else if (strcmp(key, "detect_renames") == 0) {
            cfg->detect_renames = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
    }

    fclose(fp);

    /* Also verify baseline_file security if it exists */
    if (cfg->baseline_file[0] != '\0' && access(cfg->baseline_file, F_OK) == 0) {
        fims_status_t b_sec = fims_check_file_security(cfg->baseline_file);
        if (b_sec != FIMS_OK) {
            return b_sec;
        }
    }

    return FIMS_OK;
}

static void ensure_parent_dir_config(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    safe_copy_str(tmp, sizeof(tmp), file_path);
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

fims_status_t fims_config_save(const fims_config_t *cfg, const char *config_path) {
    if (!cfg) return FIMS_ERR_INVALID_ARG;
    const char *path = config_path ? config_path : get_env_override("FIMS_CONFIG_FILE", "FIMS_CONFIG_PATH");
    if (!path) path = (cfg->config_file[0] != '\0') ? cfg->config_file : FIMS_DEFAULT_CONFIG;

    ensure_parent_dir_config(path);
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
        if (strncmp(cfg->excluded_paths[i], "glob:", 5) == 0) {
            fprintf(fp, "exclude_glob = %s\n", cfg->excluded_paths[i] + 5);
        } else {
            fprintf(fp, "exclude_path = %s\n", cfg->excluded_paths[i]);
        }
    }
    fprintf(fp, "scan_interval_sec = %u\n", cfg->scan_interval_sec);
    fprintf(fp, "log_file = %s\n", cfg->log_file);
    fprintf(fp, "baseline_file = %s\n", cfg->baseline_file);
    fprintf(fp, "report_file = %s\n", cfg->report_file);
    fprintf(fp, "state_file = %s\n", cfg->state_file);
    fprintf(fp, "monitor_mode = %s\n",
            cfg->monitor_mode == MODE_PASSIVE_SCAN ? "passive" :
            (cfg->monitor_mode == MODE_REALTIME_INOTIFY ? "realtime" : "hybrid"));
    const char *sev_str = "low";
    switch (cfg->min_alert_severity) {
        case SEV_INFO:     sev_str = "info"; break;
        case SEV_LOW:      sev_str = "low"; break;
        case SEV_MEDIUM:   sev_str = "medium"; break;
        case SEV_HIGH:     sev_str = "high"; break;
        case SEV_CRITICAL: sev_str = "critical"; break;
    }
    fprintf(fp, "min_alert_severity = %s\n", sev_str);
    fprintf(fp, "alert_threshold = %u\n", cfg->alert_threshold_count);
    fprintf(fp, "follow_symlinks = %s\n", cfg->follow_symlinks ? "true" : "false");
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
    printf(" State File          : %s\n", cfg->state_file);
    printf(" Last Report File    : %s\n", cfg->report_file);
    printf(" Config File         : %s\n", cfg->config_file);
    printf(" Monitoring Mode     : %s\n",
           cfg->monitor_mode == MODE_PASSIVE_SCAN ? "PASSIVE_SCAN" :
           (cfg->monitor_mode == MODE_REALTIME_INOTIFY ? "REALTIME_INOTIFY" : "HYBRID (inotify + periodic scan)"));
    printf(" Scan Interval       : %u seconds\n", cfg->scan_interval_sec);
    printf(" Min Alert Severity  : %s\n",
           cfg->min_alert_severity == SEV_INFO ? "INFO" :
           (cfg->min_alert_severity == SEV_LOW ? "LOW" :
           (cfg->min_alert_severity == SEV_MEDIUM ? "MEDIUM" :
           (cfg->min_alert_severity == SEV_HIGH ? "HIGH" : "CRITICAL"))));
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
        if (strncmp(cfg->excluded_paths[i], "glob:", 5) == 0) {
            printf("   - (glob) %s\n", cfg->excluded_paths[i] + 5);
        } else {
            printf("   - %s\n", cfg->excluded_paths[i]);
        }
    }
    printf("============================================================\n");
}
