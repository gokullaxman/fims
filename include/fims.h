#ifndef FIMS_H
#define FIMS_H

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

/* ============================================================================
 * System Constants & Limits
 * ============================================================================ */
#define FIMS_VERSION            "1.0.0"
#define FIMS_MAX_PATH           4096
#define FIMS_HASH_BYTES         32
#define FIMS_HASH_HEX_LEN       65      /* 64 hex chars + NUL terminator */
#define FIMS_CHUNK_SIZE         65536   /* 64 KB streaming read buffer */
#define FIMS_MAX_DIRS           32
#define FIMS_MAX_EXCLUDES       64
#define FIMS_MAX_LINE           8192
#define FIMS_BASELINE_MAGIC     "FIMS_BASELINE_V1"
#define FIMS_MAX_SCAN_DEPTH     128

/* Exit Codes */
#define FIMS_EXIT_OK      0
#define FIMS_EXIT_ERROR   1
#define FIMS_EXIT_CORRUPT 2
#define FIMS_EXIT_CHANGES 3

/* Default paths relative to working directory (or overridden via config/env) */
#define FIMS_DEFAULT_BASELINE   "data/baseline.dat"
#define FIMS_DEFAULT_LOG        "logs/fims.log"
#define FIMS_DEFAULT_REPORT     "data/last_report.dat"
#define FIMS_DEFAULT_STATE      "data/status.dat"
#define FIMS_DEFAULT_CONFIG     "data/fims.conf"

/* ============================================================================
 * Safe String & Path Helpers (Bounds-Checked, Zero Truncation Warnings)
 * ============================================================================ */
static inline bool fims_str_copy(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0) return false;
    if (!src) {
        dst[0] = '\0';
        return false;
    }
    size_t len = strlen(src);
    if (len >= dst_sz) {
        memcpy(dst, src, dst_sz - 1);
        dst[dst_sz - 1] = '\0';
        return false;
    }
    memcpy(dst, src, len + 1);
    return true;
}

static inline bool fims_path_join(char *dst, size_t dst_sz, const char *dir, const char *name) {
    if (!dst || dst_sz == 0 || !dir || !name) return false;
    size_t dlen = strlen(dir);
    while (dlen > 1 && dir[dlen - 1] == '/') {
        dlen--;
    }
    if (dlen == 1 && dir[0] == '/') {
        dlen = 0;
    }
    while (*name == '/') {
        name++;
    }
    size_t nlen = strlen(name);
    if (dlen + 1 + nlen >= dst_sz) {
        return false;
    }
    if (dlen > 0) {
        memcpy(dst, dir, dlen);
    }
    dst[dlen] = '/';
    memcpy(dst + dlen + 1, name, nlen + 1);
    return true;
}

/* ============================================================================
 * Error / Status Codes
 * ============================================================================ */
typedef enum {
    FIMS_OK = 0,
    FIMS_ERR_INVALID_ARG = -1,
    FIMS_ERR_IO = -2,
    FIMS_ERR_NOMEM = -3,
    FIMS_ERR_CRYPTO = -4,
    FIMS_ERR_CORRUPT = -5,
    FIMS_ERR_EXISTS = -6,
    FIMS_ERR_NOT_FOUND = -7,
    FIMS_ERR_PERMISSION = -8,
    FIMS_ERR_PATH_SAFETY = -9,
    FIMS_ERR_INOTIFY = -10
} fims_status_t;

/* ============================================================================
 * Integrity Event Types & Bitmask Flags
 * ============================================================================ */
typedef enum {
    EVENT_NONE = 0,
    EVENT_FILE_ADDED,
    EVENT_FILE_MODIFIED,
    EVENT_FILE_DELETED,
    EVENT_FILE_RENAMED,
    EVENT_PERMISSION_CHANGED,
    EVENT_SIZE_CHANGED,
    EVENT_METADATA_CHANGED,
    EVENT_UNREADABLE
} fims_event_type_t;

#define FIMS_FLAG_NONE               0x00U
#define FIMS_FLAG_FILE_ADDED         (1U << 0)
#define FIMS_FLAG_FILE_MODIFIED      (1U << 1)
#define FIMS_FLAG_FILE_DELETED       (1U << 2)
#define FIMS_FLAG_FILE_RENAMED       (1U << 3)
#define FIMS_FLAG_PERMISSION_CHANGED (1U << 4)
#define FIMS_FLAG_SIZE_CHANGED       (1U << 5)
#define FIMS_FLAG_METADATA_CHANGED   (1U << 6)
#define FIMS_FLAG_UNREADABLE         (1U << 7)

/* ============================================================================
 * Alert Severity Levels
 * ============================================================================ */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW = 1,
    SEV_MEDIUM = 2,
    SEV_HIGH = 3,
    SEV_CRITICAL = 4
} fims_severity_t;

/* ============================================================================
 * Monitoring Mode
 * ============================================================================ */
typedef enum {
    MODE_PASSIVE_SCAN = 0,
    MODE_REALTIME_INOTIFY = 1,
    MODE_HYBRID = 2
} fims_monitor_mode_t;

/* ============================================================================
 * Core Data Structures
 * ============================================================================ */

/**
 * Represents a single regular file's metadata and cryptographic state.
 */
typedef struct {
    char     path[FIMS_MAX_PATH];
    uint64_t dev;
    uint64_t inode;
    uint64_t size;
    uint32_t mode;      /* Permission bits (st_mode & 07777) */
    uint32_t uid;
    uint32_t gid;
    int64_t  mtime;
    int64_t  ctime;
    char     sha256[FIMS_HASH_HEX_LEN];
    bool     unreadable;
} fims_file_record_t;

/**
 * Dynamic array of scanned/baseline file records.
 */
typedef struct {
    fims_file_record_t *records;
    size_t              count;
    size_t              capacity;
    size_t              skipped_inaccessible;
    size_t              skipped_symlinks;
    char                root_dirs[FIMS_MAX_DIRS][FIMS_MAX_PATH];
    size_t              root_dir_count;
    int64_t             created_at;
} fims_file_list_t;

/**
 * Represents a single detected integrity change event.
 */
typedef struct {
    time_t            timestamp;
    char              path[FIMS_MAX_PATH];
    char              old_path[FIMS_MAX_PATH]; /* Populated for EVENT_FILE_RENAMED */
    fims_event_type_t event_type;
    uint32_t          change_flags;
    char              prev_hash[FIMS_HASH_HEX_LEN];
    char              curr_hash[FIMS_HASH_HEX_LEN];
    uint64_t          prev_size;
    uint64_t          curr_size;
    uint32_t          prev_mode;
    uint32_t          curr_mode;
    fims_severity_t   severity;
    char              description[512];
} fims_alert_t;

/**
 * Dynamic collection of alerts generated during an integrity check.
 */
typedef struct {
    fims_alert_t *alerts;
    size_t        count;
    size_t        capacity;
    size_t        total_files_checked;
    size_t        unchanged_files;
    size_t        added_count;
    size_t        modified_count;
    size_t        deleted_count;
    size_t        renamed_count;
    size_t        perm_changed_count;
    size_t        size_changed_count;
    size_t        meta_changed_count;
    time_t        scan_timestamp;
} fims_report_t;

/**
 * System Configuration structure.
 */
typedef struct {
    char                monitored_dirs[FIMS_MAX_DIRS][FIMS_MAX_PATH];
    size_t              monitored_dir_count;
    char                excluded_paths[FIMS_MAX_EXCLUDES][FIMS_MAX_PATH];
    size_t              excluded_count;
    uint32_t            scan_interval_sec;
    char                log_file[FIMS_MAX_PATH];
    char                baseline_file[FIMS_MAX_PATH];
    char                report_file[FIMS_MAX_PATH];
    char                state_file[FIMS_MAX_PATH];
    char                config_file[FIMS_MAX_PATH];
    fims_monitor_mode_t monitor_mode;
    fims_severity_t     min_alert_severity;
    uint32_t            alert_threshold_count;
    bool                follow_symlinks;
    bool                detect_renames;
} fims_config_t;

#endif /* FIMS_H */
