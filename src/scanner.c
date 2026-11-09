#include "scanner.h"
#include "hash.h"
#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifndef FIMS_MAX_SCAN_DEPTH
#define FIMS_MAX_SCAN_DEPTH 128
#endif

typedef struct {
    uint64_t dev;
    uint64_t inode;
} dir_visit_t;

/* Internal counters for diagnostic queries (Items 7 and 13) */
static size_t g_missing_root_count = 0;
static size_t g_depth_limit_reached_count = 0;

size_t fims_scanner_get_missing_root_count(void) {
    return g_missing_root_count;
}

void fims_scanner_reset_missing_root_count(void) {
    g_missing_root_count = 0;
}

size_t fims_scanner_get_depth_limit_reached_count(void) {
    return g_depth_limit_reached_count;
}

void fims_scanner_reset_depth_limit_reached_count(void) {
    g_depth_limit_reached_count = 0;
}

static void add_root_dir_if_absent(fims_file_list_t *list, const char *dir_path) {
    if (!list || !dir_path) return;
    for (size_t i = 0; i < list->root_dir_count; i++) {
        if (strcmp(list->root_dirs[i], dir_path) == 0) {
            return;
        }
    }
    if (list->root_dir_count < FIMS_MAX_DIRS) {
        snprintf(list->root_dirs[list->root_dir_count], FIMS_MAX_PATH, "%s", dir_path);
        list->root_dir_count++;
    }
}

fims_status_t fims_file_list_init(fims_file_list_t *list) {
    if (!list) return FIMS_ERR_INVALID_ARG;
    memset(list, 0, sizeof(*list));
    list->capacity = 64;
    list->records = (fims_file_record_t *)calloc(list->capacity, sizeof(fims_file_record_t));
    if (!list->records) {
        list->capacity = 0;
        return FIMS_ERR_NOMEM;
    }
    list->created_at = (int64_t)time(NULL);
    return FIMS_OK;
}

void fims_file_list_free(fims_file_list_t *list) {
    if (!list) return;
    free(list->records);
    list->records = NULL;
    list->count = 0;
    list->capacity = 0;
}

fims_status_t fims_file_list_append(fims_file_list_t *list, const fims_file_record_t *rec) {
    if (!list || !rec) return FIMS_ERR_INVALID_ARG;

    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 64 : list->capacity * 2;
        fims_file_record_t *new_recs = (fims_file_record_t *)realloc(
            list->records, new_cap * sizeof(fims_file_record_t));
        if (!new_recs) {
            return FIMS_ERR_NOMEM;
        }
        list->records = new_recs;
        list->capacity = new_cap;
    }

    list->records[list->count++] = *rec;
    return FIMS_OK;
}

static int compare_file_records(const void *a, const void *b) {
    const fims_file_record_t *ra = (const fims_file_record_t *)a;
    const fims_file_record_t *rb = (const fims_file_record_t *)b;
    return strcmp(ra->path, rb->path);
}

void fims_file_list_sort(fims_file_list_t *list) {
    if (!list || !list->records || list->count <= 1) return;
    qsort(list->records, list->count, sizeof(fims_file_record_t), compare_file_records);

    /* Deduplicate identical paths if overlapping directories were scanned */
    size_t write_idx = 0;
    for (size_t read_idx = 0; read_idx < list->count; read_idx++) {
        if (write_idx == 0 || strcmp(list->records[write_idx - 1].path, list->records[read_idx].path) != 0) {
            if (write_idx != read_idx) {
                list->records[write_idx] = list->records[read_idx];
            }
            write_idx++;
        }
    }
    list->count = write_idx;
}

/**
 * Internal helper (Item 12): Hashes an open file descriptor directly and populates metadata
 * from fstat on that same descriptor, eliminating TOCTOU race condition between stat and open.
 */
static fims_status_t scan_and_hash_open_fd(int fd, const char *file_path, fims_file_record_t *out_rec) {
    if (fd < 0 || !file_path || !out_rec) {
        return FIMS_ERR_INVALID_ARG;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        return FIMS_ERR_IO;
    }

    /* Cleanly reject FIFOs, sockets, character devices, block devices, and non-regular files */
    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) || S_ISCHR(st.st_mode) ||
        S_ISBLK(st.st_mode) || !S_ISREG(st.st_mode)) {
        return FIMS_ERR_INVALID_ARG;
    }

    memset(out_rec, 0, sizeof(*out_rec));
    snprintf(out_rec->path, sizeof(out_rec->path), "%s", file_path);
    out_rec->dev        = (uint64_t)st.st_dev;
    out_rec->inode      = (uint64_t)st.st_ino;
    out_rec->size       = (uint64_t)st.st_size;
    out_rec->mode       = (uint32_t)(st.st_mode & 07777);
    out_rec->uid        = (uint32_t)st.st_uid;
    out_rec->gid        = (uint32_t)st.st_gid;
    out_rec->mtime      = (int64_t)st.st_mtime;
    out_rec->ctime      = (int64_t)st.st_ctime;
    out_rec->unreadable = false;

    return fims_hash_fd_sha256(fd, out_rec->sha256);
}

fims_status_t fims_scan_single_file(const char *file_path, fims_file_record_t *out_rec) {
    if (!file_path || !out_rec) return FIMS_ERR_INVALID_ARG;

    /* Open with O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK (Item 12):
     * Non-blocking open ensures FIFOs do not hang waiting for a writer */
    int fd;
    do {
        fd = open(file_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        /* Item 10: When a file cannot be read/opened due to EACCES / permission errors:
         * Obtain metadata via lstat, fill record with empty sha256 and unreadable=true,
         * and return FIMS_OK so the file is preserved in the file list */
        if (errno == EACCES || errno == EPERM) {
            struct stat lst;
            if (lstat(file_path, &lst) != 0) {
                return FIMS_ERR_PERMISSION;
            }
            if (S_ISLNK(lst.st_mode)) {
                return FIMS_ERR_INVALID_ARG;
            }
            if (!S_ISREG(lst.st_mode)) {
                return FIMS_ERR_INVALID_ARG;
            }

            memset(out_rec, 0, sizeof(*out_rec));
            snprintf(out_rec->path, sizeof(out_rec->path), "%s", file_path);
            out_rec->dev        = (uint64_t)lst.st_dev;
            out_rec->inode      = (uint64_t)lst.st_ino;
            out_rec->size       = (uint64_t)lst.st_size;
            out_rec->mode       = (uint32_t)(lst.st_mode & 07777);
            out_rec->uid        = (uint32_t)lst.st_uid;
            out_rec->gid        = (uint32_t)lst.st_gid;
            out_rec->mtime      = (int64_t)lst.st_mtime;
            out_rec->ctime      = (int64_t)lst.st_ctime;
            out_rec->sha256[0]  = '\0';
            out_rec->unreadable = true;
            return FIMS_OK;
        }

        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        if (errno == ELOOP) return FIMS_ERR_INVALID_ARG; /* Symlink rejected */
        return FIMS_ERR_IO;
    }

    fims_status_t st = scan_and_hash_open_fd(fd, file_path, out_rec);
    close(fd);
    return st;
}

static fims_status_t scan_dir_recursive(const char *current_dir,
                                        const fims_config_t *cfg,
                                        fims_file_list_t *out_list,
                                        dir_visit_t *ancestors,
                                        size_t depth) {
    /* Item 13: Enforce FIMS_MAX_SCAN_DEPTH and log a warning when depth cap is reached */
    if (depth >= FIMS_MAX_SCAN_DEPTH) {
        g_depth_limit_reached_count++;
        if (cfg && cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_HIGH,
                             "Maximum directory scan depth (%d) reached at: %s",
                             FIMS_MAX_SCAN_DEPTH, current_dir);
        }
        return FIMS_OK;
    }

    if (cfg && fims_config_is_excluded(cfg, current_dir)) {
        return FIMS_OK;
    }

    struct stat dir_st;
    if (lstat(current_dir, &dir_st) != 0) {
        if (errno == EACCES || errno == EPERM) {
            out_list->skipped_inaccessible++;
            return FIMS_OK;
        }
        return FIMS_ERR_IO;
    }

    if (S_ISLNK(dir_st.st_mode)) {
        out_list->skipped_symlinks++;
        return FIMS_OK;
    }

    if (!S_ISDIR(dir_st.st_mode)) {
        return FIMS_ERR_INVALID_ARG;
    }

    /* Check ancestor stack for directory cycle (e.g. bind mounts or hardlinked dirs) */
    uint64_t cur_dev = (uint64_t)dir_st.st_dev;
    uint64_t cur_ino = (uint64_t)dir_st.st_ino;
    for (size_t i = 0; i < depth; i++) {
        if (ancestors[i].dev == cur_dev && ancestors[i].inode == cur_ino) {
            return FIMS_OK; /* Cycle detected; stop descending */
        }
    }
    ancestors[depth].dev = cur_dev;
    ancestors[depth].inode = cur_ino;

    DIR *dirp = opendir(current_dir);
    if (!dirp) {
        if (errno == EACCES || errno == EPERM) {
            out_list->skipped_inaccessible++;
            if (cfg && cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_LOW,
                                 "Skipped inaccessible directory during scan: %s", current_dir);
            }
            return FIMS_OK;
        }
        return FIMS_ERR_IO;
    }

    struct dirent *entry;
    while ((entry = readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child_path[FIMS_MAX_PATH];
        int n = snprintf(child_path, sizeof(child_path), "%s/%s",
                         (strcmp(current_dir, "/") == 0) ? "" : current_dir,
                         entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child_path)) {
            continue; /* Skip overly long path */
        }

        if (cfg && fims_config_is_excluded(cfg, child_path)) {
            continue;
        }

        struct stat st;
        if (lstat(child_path, &st) != 0) {
            if (errno == EACCES || errno == EPERM) {
                out_list->skipped_inaccessible++;
            }
            continue;
        }

        /* Security-critical: Do not follow symbolic links to prevent infinite loops */
        if (S_ISLNK(st.st_mode)) {
            out_list->skipped_symlinks++;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            fims_status_t sub_st = scan_dir_recursive(child_path, cfg, out_list, ancestors, depth + 1);
            if (sub_st == FIMS_ERR_NOMEM) {
                closedir(dirp);
                return FIMS_ERR_NOMEM;
            }
        } else if (S_ISREG(st.st_mode)) {
            fims_file_record_t rec;
            fims_status_t file_st = fims_scan_single_file(child_path, &rec);
            if (file_st == FIMS_OK) {
                if (fims_file_list_append(out_list, &rec) != FIMS_OK) {
                    closedir(dirp);
                    return FIMS_ERR_NOMEM;
                }
            } else if (file_st == FIMS_ERR_PERMISSION) {
                out_list->skipped_inaccessible++;
                if (cfg && cfg->log_file[0]) {
                    fims_log_message(cfg->log_file, SEV_LOW,
                                     "Skipped inaccessible file during scan: %s", child_path);
                }
            }
        }
    }

    closedir(dirp);
    return FIMS_OK;
}

fims_status_t fims_scan_directory(const char *dir_path, const fims_config_t *cfg, fims_file_list_t *out_list) {
    if (!dir_path || !out_list) return FIMS_ERR_INVALID_ARG;

    char clean_dir[FIMS_MAX_PATH];
    fims_status_t st = fims_sanitize_path(dir_path, clean_dir, sizeof(clean_dir));
    if (st != FIMS_OK) return st;

    struct stat dir_st;
    if (lstat(clean_dir, &dir_st) != 0) {
        /* Item 7: If a monitored root directory is missing (ENOENT), unreadable (EACCES/EPERM),
         * or not a directory (ENOTDIR):
         * - Do NOT abort or return an error.
         * - Treat it as an empty root directory: record root path in list->root_dirs,
         *   increment list->root_dir_count, track count in internal counter, and return FIMS_OK. */
        if (errno == ENOENT || errno == EACCES || errno == EPERM || errno == ENOTDIR) {
            g_missing_root_count++;
            add_root_dir_if_absent(out_list, clean_dir);
            if (cfg && cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_HIGH,
                                 "Monitored root directory is inaccessible or missing: %s", clean_dir);
            }
            return FIMS_OK;
        }
        return FIMS_ERR_IO;
    }

    if (!S_ISDIR(dir_st.st_mode)) {
        /* Item 7: Non-directory root path treated gracefully as empty root */
        g_missing_root_count++;
        add_root_dir_if_absent(out_list, clean_dir);
        if (cfg && cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_HIGH,
                             "Monitored root path is not a directory: %s", clean_dir);
        }
        return FIMS_OK;
    }

    /* Record root directory in out_list if not already present */
    add_root_dir_if_absent(out_list, clean_dir);

    dir_visit_t ancestors[FIMS_MAX_SCAN_DEPTH];
    memset(ancestors, 0, sizeof(ancestors));

    st = scan_dir_recursive(clean_dir, cfg, out_list, ancestors, 0);
    if (st == FIMS_OK) {
        fims_file_list_sort(out_list);
    }
    return st;
}

fims_status_t fims_scan_directories(const char dirs[][FIMS_MAX_PATH], size_t dir_count,
                                    const fims_config_t *cfg, fims_file_list_t *out_list) {
    if (!dirs || dir_count == 0 || !out_list) return FIMS_ERR_INVALID_ARG;

    for (size_t i = 0; i < dir_count; i++) {
        fims_status_t st = fims_scan_directory(dirs[i], cfg, out_list);
        if (st != FIMS_OK) {
            return st;
        }
    }
    fims_file_list_sort(out_list);
    return FIMS_OK;
}
