#include "baseline.h"
#include "scanner.h"
#include "hash.h"
#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>

static void ensure_parent_directory(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    fims_str_copy(tmp, sizeof(tmp), file_path);
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

static bool is_valid_hex64(const char *s) {
    if (!s) return false;
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)s[i])) return false;
    }
    return s[64] == '\0';
}

static int format_record_line(const fims_file_record_t *rec, char *buf, size_t buf_sz) {
    return snprintf(buf, buf_sz,
                    "%llu\t%llu\t%llu\t%04o\t%u\t%u\t%lld\t%lld\t%s\t%s\n",
                    (unsigned long long)rec->dev,
                    (unsigned long long)rec->inode,
                    (unsigned long long)rec->size,
                    rec->mode & 07777U,
                    rec->uid,
                    rec->gid,
                    (long long)rec->mtime,
                    (long long)rec->ctime,
                    rec->sha256,
                    rec->path);
}

fims_status_t fims_baseline_save(const char *baseline_path,
                                 const fims_file_list_t *list,
                                 bool allow_overwrite) {
    if (!baseline_path || !list || baseline_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    /* Security requirement: Prevent accidental overwriting of an existing baseline */
    if (!allow_overwrite && access(baseline_path, F_OK) == 0) {
        return FIMS_ERR_EXISTS;
    }

    ensure_parent_directory(baseline_path);

    /* Compute SHA-256 digest over all serialized record lines */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return FIMS_ERR_CRYPTO;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return FIMS_ERR_CRYPTO;
    }

    char line_buf[FIMS_MAX_LINE];
    for (size_t i = 0; i < list->count; i++) {
        int len = format_record_line(&list->records[i], line_buf, sizeof(line_buf));
        if (len < 0 || (size_t)len >= sizeof(line_buf)) {
            EVP_MD_CTX_free(ctx);
            return FIMS_ERR_INVALID_ARG;
        }
        if (EVP_DigestUpdate(ctx, line_buf, (size_t)len) != 1) {
            EVP_MD_CTX_free(ctx);
            return FIMS_ERR_CRYPTO;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != FIMS_HASH_BYTES) {
        EVP_MD_CTX_free(ctx);
        return FIMS_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);

    char body_sha256[FIMS_HASH_HEX_LEN];
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; i++) {
        body_sha256[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        body_sha256[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    body_sha256[64] = '\0';

    /* Write to temporary file with restrictive 0600 permissions, then rename atomically */
    char tmp_path[FIMS_MAX_PATH + 32];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", baseline_path, (int)getpid());

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return FIMS_ERR_IO;
    }
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    int64_t ts = list->created_at ? list->created_at : (int64_t)time(NULL);
    fprintf(fp, "%s\n", FIMS_BASELINE_MAGIC);
    fprintf(fp, "CREATED_AT=%lld\n", (long long)ts);
    fprintf(fp, "RECORD_COUNT=%zu\n", list->count);
    for (size_t i = 0; i < list->root_dir_count; i++) {
        fprintf(fp, "ROOT_DIR=%s\n", list->root_dirs[i]);
    }
    fprintf(fp, "BODY_SHA256=%s\n", body_sha256);
    fprintf(fp, "---BEGIN_RECORDS---\n");

    for (size_t i = 0; i < list->count; i++) {
        format_record_line(&list->records[i], line_buf, sizeof(line_buf));
        if (fputs(line_buf, fp) == EOF) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    }

    fprintf(fp, "---END_RECORDS---\n");
    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }
    fsync(fd);
    fclose(fp);

    if (rename(tmp_path, baseline_path) != 0) {
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    return FIMS_OK;
}

static bool parse_record_line(const char *line, fims_file_record_t *out_rec) {
    if (!line || !out_rec) return false;
    memset(out_rec, 0, sizeof(*out_rec));

    char copy[FIMS_MAX_LINE];
    if (!fims_str_copy(copy, sizeof(copy), line)) return false;
    size_t len = strlen(copy);
    if (len > 0 && copy[len - 1] == '\n') {
        copy[len - 1] = '\0';
        len--;
    }
    if (len > 0 && copy[len - 1] == '\r') {
        copy[len - 1] = '\0';
        len--;
    }

    /* Split strictly on 9 tab characters into 10 fields */
    char *fields[10];
    char *p = copy;
    for (int i = 0; i < 9; i++) {
        char *tab = strchr(p, '\t');
        if (!tab) return false;
        *tab = '\0';
        fields[i] = p;
        p = tab + 1;
    }
    fields[9] = p; /* 10th field is the file path */

    /* Ensure no extra tabs or empty fields */
    for (int i = 0; i < 10; i++) {
        if (fields[i][0] == '\0') return false;
    }
    if (strchr(fields[9], '\t') != NULL) return false;

    char *endptr = NULL;
    errno = 0;
    out_rec->dev = (uint64_t)strtoull(fields[0], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    out_rec->inode = (uint64_t)strtoull(fields[1], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    out_rec->size = (uint64_t)strtoull(fields[2], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    unsigned long mode_val = strtoul(fields[3], &endptr, 8);
    if (errno != 0 || !endptr || *endptr != '\0' || mode_val > 07777UL) return false;
    out_rec->mode = (uint32_t)mode_val;

    out_rec->uid = (uint32_t)strtoul(fields[4], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    out_rec->gid = (uint32_t)strtoul(fields[5], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    out_rec->mtime = (int64_t)strtoll(fields[6], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    out_rec->ctime = (int64_t)strtoll(fields[7], &endptr, 10);
    if (errno != 0 || !endptr || *endptr != '\0') return false;

    if (!is_valid_hex64(fields[8])) return false;
    fims_str_copy(out_rec->sha256, sizeof(out_rec->sha256), fields[8]);

    /* Path safety check: Must be an absolute path without '..' segments */
    if (fields[9][0] != '/' || strlen(fields[9]) >= FIMS_MAX_PATH) return false;
    if (strstr(fields[9], "/../") != NULL) return false;
    fims_str_copy(out_rec->path, sizeof(out_rec->path), fields[9]);

    return true;
}

fims_status_t fims_baseline_load(const char *baseline_path, fims_file_list_t *out_list) {
    if (!baseline_path || !out_list || baseline_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    int fd = open(baseline_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        if (errno == EACCES || errno == EPERM) return FIMS_ERR_PERMISSION;
        return FIMS_ERR_IO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return FIMS_ERR_CORRUPT;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        return FIMS_ERR_IO;
    }

    fims_status_t init_st = fims_file_list_init(out_list);
    if (init_st != FIMS_OK) {
        fclose(fp);
        return init_st;
    }

    char line[FIMS_MAX_LINE];
    /* 1. Verify Magic Header */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CORRUPT;
    }
    line[strcspn(line, "\r\n")] = '\0';
    if (strcmp(line, FIMS_BASELINE_MAGIC) != 0) {
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CORRUPT;
    }

    bool has_created = false;
    bool has_count = false;
    bool has_sha = false;
    bool in_records = false;
    bool end_records_seen = false;
    size_t expected_count = 0;
    char expected_sha[FIMS_HASH_HEX_LEN] = {0};

    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "---BEGIN_RECORDS---") == 0) {
            in_records = true;
            break;
        }
        if (strncmp(line, "CREATED_AT=", 11) == 0) {
            char *endp = NULL;
            out_list->created_at = (int64_t)strtoll(line + 11, &endp, 10);
            if (!endp || *endp != '\0') {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            has_created = true;
        } else if (strncmp(line, "RECORD_COUNT=", 13) == 0) {
            char *endp = NULL;
            expected_count = (size_t)strtoull(line + 13, &endp, 10);
            if (!endp || *endp != '\0') {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            has_count = true;
        } else if (strncmp(line, "ROOT_DIR=", 9) == 0) {
            if (out_list->root_dir_count < FIMS_MAX_DIRS && line[9] == '/' &&
                fims_str_copy(out_list->root_dirs[out_list->root_dir_count], FIMS_MAX_PATH, line + 9)) {
                out_list->root_dir_count++;
            } else {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
        } else if (strncmp(line, "BODY_SHA256=", 12) == 0) {
            if (!is_valid_hex64(line + 12)) {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            fims_str_copy(expected_sha, sizeof(expected_sha), line + 12);
            has_sha = true;
        } else {
            /* Unknown header line -> malformed baseline */
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }
    }

    if (!has_created || !has_count || !has_sha || !in_records) {
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CORRUPT;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strcmp(line, "---END_RECORDS---\n") == 0 || strcmp(line, "---END_RECORDS---\r\n") == 0 ||
            strcmp(line, "---END_RECORDS---") == 0) {
            end_records_seen = true;
            break;
        }

        size_t raw_len = strlen(line);
        if (EVP_DigestUpdate(ctx, line, raw_len) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CRYPTO;
        }

        fims_file_record_t rec;
        if (!parse_record_line(line, &rec)) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }

        if (fims_file_list_append(out_list, &rec) != FIMS_OK) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_NOMEM;
        }
    }

    fclose(fp);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != FIMS_HASH_BYTES) {
        EVP_MD_CTX_free(ctx);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(ctx);

    char actual_sha[FIMS_HASH_HEX_LEN];
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; i++) {
        actual_sha[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        actual_sha[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    actual_sha[64] = '\0';

    if (!end_records_seen || out_list->count != expected_count || strcmp(actual_sha, expected_sha) != 0) {
        fims_file_list_free(out_list);
        return FIMS_ERR_CORRUPT;
    }

    return FIMS_OK;
}

fims_status_t fims_baseline_validate(const char *baseline_path) {
    fims_file_list_t list;
    fims_status_t st = fims_baseline_load(baseline_path, &list);
    if (st == FIMS_OK) {
        fims_file_list_free(&list);
    }
    return st;
}

fims_status_t fims_baseline_init_from_dir(const char *dir_path,
                                          fims_config_t *cfg,
                                          bool allow_overwrite,
                                          size_t *out_file_count) {
    if (!dir_path || !cfg) return FIMS_ERR_INVALID_ARG;

    if (!allow_overwrite && access(cfg->baseline_file, F_OK) == 0) {
        return FIMS_ERR_EXISTS;
    }

    fims_file_list_t list;
    fims_status_t st = fims_file_list_init(&list);
    if (st != FIMS_OK) return st;

    st = fims_scan_directory(dir_path, cfg, &list);
    if (st != FIMS_OK) {
        fims_file_list_free(&list);
        return st;
    }

    st = fims_baseline_save(cfg->baseline_file, &list, allow_overwrite);
    if (st == FIMS_OK) {
        if (out_file_count) *out_file_count = list.count;
        fims_config_add_dir(cfg, dir_path);
        if (cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_INFO,
                             "Baseline initialized for directory '%s' (%zu files recorded)",
                             list.root_dirs[0], list.count);
        }
    }

    fims_file_list_free(&list);
    return st;
}

fims_status_t fims_baseline_show(const char *baseline_path) {
    fims_file_list_t list;
    fims_status_t st = fims_baseline_load(baseline_path, &list);
    if (st != FIMS_OK) {
        return st;
    }

    time_t created = (time_t)list.created_at;
    char ts_buf[64];
    struct tm tm_info;
    if (localtime_r(&created, &tm_info) != NULL) {
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S %z", &tm_info);
    } else {
        snprintf(ts_buf, sizeof(ts_buf), "%lld", (long long)list.created_at);
    }

    printf("================================================================================\n");
    printf(" FIMS Trusted Baseline Summary\n");
    printf("================================================================================\n");
    printf(" Baseline File  : %s\n", baseline_path);
    printf(" Integrity      : VERIFIED (SHA-256 checksum valid)\n");
    printf(" Created At     : %s\n", ts_buf);
    printf(" Total Files    : %zu\n", list.count);
    for (size_t i = 0; i < list.root_dir_count; i++) {
        printf(" Monitored Root : %s\n", list.root_dirs[i]);
    }
    printf("--------------------------------------------------------------------------------\n");
    printf(" %-6s %-10s %-16s %s\n", "MODE", "SIZE(B)", "SHA-256 (PREFIX)", "FILE PATH");
    printf("--------------------------------------------------------------------------------\n");
    for (size_t i = 0; i < list.count; i++) {
        const fims_file_record_t *r = &list.records[i];
        printf(" %04o   %-10llu %.16s... %s\n",
               r->mode,
               (unsigned long long)r->size,
               r->sha256,
               r->path);
    }
    printf("================================================================================\n");

    fims_file_list_free(&list);
    return FIMS_OK;
}
