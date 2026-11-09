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
#include <sys/types.h>
#include <openssl/evp.h>

/* ============================================================================
 * Internal Cryptographic Digest Abstraction (SHA-256 and HMAC-SHA256)
 * ============================================================================ */
typedef struct {
    bool is_hmac;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY *pkey;
} baseline_digest_ctx_t;

static bool digest_init(baseline_digest_ctx_t *dctx, const unsigned char *key, size_t key_len) {
    if (!dctx) return false;
    memset(dctx, 0, sizeof(*dctx));
    dctx->md_ctx = EVP_MD_CTX_new();
    if (!dctx->md_ctx) return false;

    if (key && key_len > 0) {
        dctx->is_hmac = true;
        dctx->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, key_len);
        if (!dctx->pkey) {
            EVP_MD_CTX_free(dctx->md_ctx);
            dctx->md_ctx = NULL;
            return false;
        }
        if (EVP_DigestSignInit(dctx->md_ctx, NULL, EVP_sha256(), NULL, dctx->pkey) != 1) {
            EVP_PKEY_free(dctx->pkey);
            dctx->pkey = NULL;
            EVP_MD_CTX_free(dctx->md_ctx);
            dctx->md_ctx = NULL;
            return false;
        }
    } else {
        dctx->is_hmac = false;
        dctx->pkey = NULL;
        if (EVP_DigestInit_ex(dctx->md_ctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(dctx->md_ctx);
            dctx->md_ctx = NULL;
            return false;
        }
    }
    return true;
}

static bool digest_update(baseline_digest_ctx_t *dctx, const void *data, size_t len) {
    if (!dctx || !dctx->md_ctx) return false;
    if (dctx->is_hmac) {
        return (EVP_DigestSignUpdate(dctx->md_ctx, data, len) == 1);
    } else {
        return (EVP_DigestUpdate(dctx->md_ctx, data, len) == 1);
    }
}

static bool digest_final(baseline_digest_ctx_t *dctx, char *out_hex) {
    if (!dctx || !dctx->md_ctx || !out_hex) return false;
    unsigned char digest[EVP_MAX_MD_SIZE];
    bool ok = false;
    size_t out_len = sizeof(digest);

    if (dctx->is_hmac) {
        if (EVP_DigestSignFinal(dctx->md_ctx, digest, &out_len) == 1 && out_len == FIMS_HASH_BYTES) {
            ok = true;
        }
    } else {
        unsigned int ulen = 0;
        if (EVP_DigestFinal_ex(dctx->md_ctx, digest, &ulen) == 1 && ulen == FIMS_HASH_BYTES) {
            out_len = (size_t)ulen;
            ok = true;
        }
    }

    if (dctx->pkey) {
        EVP_PKEY_free(dctx->pkey);
        dctx->pkey = NULL;
    }
    EVP_MD_CTX_free(dctx->md_ctx);
    dctx->md_ctx = NULL;

    if (!ok) return false;

    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < out_len; i++) {
        out_hex[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    out_hex[out_len * 2] = '\0';
    return true;
}

static void digest_cleanup(baseline_digest_ctx_t *dctx) {
    if (!dctx) return;
    if (dctx->pkey) {
        EVP_PKEY_free(dctx->pkey);
        dctx->pkey = NULL;
    }
    if (dctx->md_ctx) {
        EVP_MD_CTX_free(dctx->md_ctx);
        dctx->md_ctx = NULL;
    }
}

/* ============================================================================
 * HMAC Key File Loader & Validator (Item 8)
 * ============================================================================ */
static fims_status_t load_hmac_key(unsigned char *key_buf, size_t key_buf_max,
                                   size_t *out_key_len, bool *out_has_key) {
    *out_has_key = false;
    *out_key_len = 0;

    const char *key_path = getenv("FIMS_HMAC_KEY_FILE");
    if (!key_path || key_path[0] == '\0') {
        return FIMS_OK;
    }

    struct stat st;
    if (stat(key_path, &st) != 0) {
        return FIMS_ERR_PERMISSION;
    }

    /* Requirement: Mode must be strictly 0600 */
    if ((st.st_mode & 0777) != 0600) {
        return FIMS_ERR_PERMISSION;
    }

    /* Requirement: Owned by current user or root */
    if (st.st_uid != getuid() && st.st_uid != 0) {
        return FIMS_ERR_PERMISSION;
    }

    int fd = open(key_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return FIMS_ERR_PERMISSION;
    }

    ssize_t n = read(fd, key_buf, key_buf_max);
    close(fd);
    if (n <= 0) {
        return FIMS_ERR_CORRUPT;
    }

    /* Strip trailing newline characters if present */
    while (n > 0 && (key_buf[n - 1] == '\n' || key_buf[n - 1] == '\r')) {
        n--;
    }
    if (n == 0) {
        return FIMS_ERR_CORRUPT;
    }

    *out_key_len = (size_t)n;
    *out_has_key = true;
    return FIMS_OK;
}

/* ============================================================================
 * Path Percent-Encoding & Validation (Items 4 & 24)
 * ============================================================================ */
static int percent_encode_path(const char *src, char *dst, size_t dst_sz) {
    if (!src || !dst || dst_sz == 0) return -1;
    size_t out_idx = 0;
    static const char hex_upper[] = "0123456789ABCDEF";

    for (size_t i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '%' || c == '\t' || c == '\n' || c == '\r' || c < 0x20 || c == 0x7F) {
            if (out_idx + 3 >= dst_sz) {
                return -1;
            }
            dst[out_idx++] = '%';
            dst[out_idx++] = hex_upper[(c >> 4) & 0x0F];
            dst[out_idx++] = hex_upper[c & 0x0F];
        } else {
            if (out_idx + 1 >= dst_sz) {
                return -1;
            }
            dst[out_idx++] = (char)c;
        }
    }
    dst[out_idx] = '\0';
    return (int)out_idx;
}

static bool percent_decode_path(const char *src, char *dst, size_t dst_sz) {
    if (!src || !dst || dst_sz == 0) return false;
    size_t out_idx = 0;
    for (size_t i = 0; src[i] != '\0'; ) {
        if (src[i] == '%') {
            if (!isxdigit((unsigned char)src[i + 1]) || !isxdigit((unsigned char)src[i + 2])) {
                return false;
            }
            char hex_buf[3];
            hex_buf[0] = src[i + 1];
            hex_buf[1] = src[i + 2];
            hex_buf[2] = '\0';
            unsigned long val = strtoul(hex_buf, NULL, 16);
            if (val == 0) {
                /* Embedded NUL byte in path is prohibited */
                return false;
            }
            if (out_idx + 1 >= dst_sz) return false;
            dst[out_idx++] = (char)(unsigned char)val;
            i += 3;
        } else {
            if (out_idx + 1 >= dst_sz) return false;
            dst[out_idx++] = src[i++];
        }
    }
    dst[out_idx] = '\0';
    return true;
}

static bool is_valid_baseline_path(const char *path) {
    if (!path || path[0] != '/' || strlen(path) >= FIMS_MAX_PATH) {
        return false;
    }
    /* Item 24: Reject path traversal sequences */
    if (strstr(path, "/../") != NULL || strstr(path, "/./") != NULL) {
        return false;
    }
    size_t len = strlen(path);
    /* Item 24: Reject paths ending in "/.." */
    if (len >= 3 && strcmp(path + len - 3, "/..") == 0) {
        return false;
    }
    /* Item 24: Reject paths ending in "/." */
    if (len >= 2 && strcmp(path + len - 2, "/.") == 0) {
        return false;
    }
    if (strcmp(path, ".") == 0 || strcmp(path, "..") == 0) {
        return false;
    }
    return true;
}

static void ensure_parent_directory(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    if (!fims_str_copy(tmp, sizeof(tmp), file_path)) return;
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

/* Item 16: fsync parent directory descriptor after atomic replacement */
static void fsync_parent_directory(const char *file_path) {
    if (!file_path) return;
    char tmp[FIMS_MAX_PATH];
    if (!fims_str_copy(tmp, sizeof(tmp), file_path)) return;
    char *slash = strrchr(tmp, '/');
    const char *dir_path = ".";
    if (slash == tmp) {
        dir_path = "/";
    } else if (slash) {
        *slash = '\0';
        dir_path = tmp;
    }
    int dfd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
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
    if (!rec || !buf || buf_sz == 0) return -1;
    if (!is_valid_baseline_path(rec->path)) return -1;

    char enc_path[FIMS_MAX_PATH * 3 + 1];
    if (percent_encode_path(rec->path, enc_path, sizeof(enc_path)) < 0) {
        return -1;
    }

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
                    enc_path);
}

/* ============================================================================
 * fims_baseline_save (Items 4, 8, 16, 24)
 * ============================================================================ */
fims_status_t fims_baseline_save(const char *baseline_path,
                                 const fims_file_list_t *list,
                                 bool allow_overwrite) {
    if (!baseline_path || !list || baseline_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    ensure_parent_directory(baseline_path);

    /* Check HMAC key configuration */
    unsigned char key[256];
    size_t key_len = 0;
    bool has_key = false;
    fims_status_t key_st = load_hmac_key(key, sizeof(key), &key_len, &has_key);
    if (key_st != FIMS_OK) {
        return key_st;
    }

    /* Compute digest over ALL header lines and record lines */
    baseline_digest_ctx_t dctx;
    if (!digest_init(&dctx, has_key ? key : NULL, key_len)) {
        return FIMS_ERR_CRYPTO;
    }

    int64_t ts = list->created_at ? list->created_at : (int64_t)time(NULL);

    char hdr_buf[FIMS_MAX_LINE];
    int hlen = snprintf(hdr_buf, sizeof(hdr_buf), "%s\n", FIMS_BASELINE_MAGIC);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        return FIMS_ERR_CRYPTO;
    }

    hlen = snprintf(hdr_buf, sizeof(hdr_buf), "CREATED_AT=%lld\n", (long long)ts);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        return FIMS_ERR_CRYPTO;
    }

    hlen = snprintf(hdr_buf, sizeof(hdr_buf), "RECORD_COUNT=%zu\n", list->count);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        return FIMS_ERR_CRYPTO;
    }

    for (size_t i = 0; i < list->root_dir_count; i++) {
        hlen = snprintf(hdr_buf, sizeof(hdr_buf), "ROOT_DIR=%s\n", list->root_dirs[i]);
        if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
            digest_cleanup(&dctx);
            return FIMS_ERR_CRYPTO;
        }
    }

    /* Feed all formatted (percent-encoded) record lines to digest */
    char line_buf[FIMS_MAX_LINE];
    for (size_t i = 0; i < list->count; i++) {
        int len = format_record_line(&list->records[i], line_buf, sizeof(line_buf));
        if (len < 0 || (size_t)len >= sizeof(line_buf)) {
            digest_cleanup(&dctx);
            return FIMS_ERR_INVALID_ARG;
        }
        if (!digest_update(&dctx, line_buf, (size_t)len)) {
            digest_cleanup(&dctx);
            return FIMS_ERR_CRYPTO;
        }
    }

    char digest_hex[FIMS_HASH_HEX_LEN];
    if (!digest_final(&dctx, digest_hex)) {
        return FIMS_ERR_CRYPTO;
    }

    /* Item 16: Temporary file with O_CREAT | O_EXCL | O_WRONLY, mode 0600 */
    char tmp_path[FIMS_MAX_PATH + 32];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", baseline_path, (int)getpid());
    unlink(tmp_path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        return FIMS_ERR_IO;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    /* Check return values of EVERY fprintf / fputs call */
    if (fprintf(fp, "%s\n", FIMS_BASELINE_MAGIC) < 0 ||
        fprintf(fp, "CREATED_AT=%lld\n", (long long)ts) < 0 ||
        fprintf(fp, "RECORD_COUNT=%zu\n", list->count) < 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    for (size_t i = 0; i < list->root_dir_count; i++) {
        if (fprintf(fp, "ROOT_DIR=%s\n", list->root_dirs[i]) < 0) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    }

    if (has_key) {
        if (fprintf(fp, "HMAC: %s\n", digest_hex) < 0) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    } else {
        if (fprintf(fp, "CHECKSUM: %s\n", digest_hex) < 0) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    }

    if (fprintf(fp, "---BEGIN_RECORDS---\n") < 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    for (size_t i = 0; i < list->count; i++) {
        int len = format_record_line(&list->records[i], line_buf, sizeof(line_buf));
        if (len < 0 || (size_t)len >= sizeof(line_buf)) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_INVALID_ARG;
        }
        if (fputs(line_buf, fp) == EOF) {
            fclose(fp);
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    }

    if (fprintf(fp, "---END_RECORDS---\n") < 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    /* Check fflush, fsync, and fclose */
    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    if (fsync(fd) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    if (fclose(fp) != 0) {
        unlink(tmp_path);
        return FIMS_ERR_IO;
    }

    /* Item 16: Replace access() overwrite check with link() / O_EXCL atomic semantics */
    if (!allow_overwrite) {
        if (link(tmp_path, baseline_path) != 0) {
            int err = errno;
            unlink(tmp_path);
            if (err == EEXIST) {
                return FIMS_ERR_EXISTS;
            }
            return FIMS_ERR_IO;
        }
        unlink(tmp_path);
    } else {
        if (rename(tmp_path, baseline_path) != 0) {
            unlink(tmp_path);
            return FIMS_ERR_IO;
        }
    }

    /* Item 16: fsync parent directory descriptor */
    fsync_parent_directory(baseline_path);

    return FIMS_OK;
}

/* ============================================================================
 * parse_record_line (Items 4 & 24)
 * ============================================================================ */
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
    fields[9] = p; /* 10th field is the percent-encoded file path */

    /* Item 10: fields 0-7 and 9 must not be empty.
     * Field 8 (sha256) may be empty for unreadable / inaccessible files */
    for (int i = 0; i < 10; i++) {
        if (i == 8) continue;
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

    if (fields[8][0] == '\0') {
        out_rec->sha256[0] = '\0';
        out_rec->unreadable = true;
    } else {
        if (!is_valid_hex64(fields[8])) return false;
        fims_str_copy(out_rec->sha256, sizeof(out_rec->sha256), fields[8]);
        out_rec->unreadable = false;
    }

    /* Item 4: Decode percent-encoded path */
    char decoded_path[FIMS_MAX_PATH];
    if (!percent_decode_path(fields[9], decoded_path, sizeof(decoded_path))) {
        return false;
    }

    /* Item 24: Path safety check */
    if (!is_valid_baseline_path(decoded_path)) {
        return false;
    }

    fims_str_copy(out_rec->path, sizeof(out_rec->path), decoded_path);
    return true;
}

/* ============================================================================
 * fims_baseline_load (Items 4, 8, 24)
 * ============================================================================ */
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
    bool has_expected_digest = false;
    bool header_is_hmac = false;
    bool in_records = false;
    bool end_records_seen = false;
    size_t expected_count = 0;
    char expected_digest[FIMS_HASH_HEX_LEN] = {0};

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
        } else if (strncmp(line, "HMAC: ", 6) == 0 || strncmp(line, "HMAC=", 5) == 0) {
            const char *val = (line[4] == ':') ? line + 6 : line + 5;
            if (!is_valid_hex64(val)) {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            fims_str_copy(expected_digest, sizeof(expected_digest), val);
            has_expected_digest = true;
            header_is_hmac = true;
        } else if (strncmp(line, "CHECKSUM: ", 10) == 0 || strncmp(line, "CHECKSUM=", 9) == 0) {
            const char *val = (line[8] == ':') ? line + 10 : line + 9;
            if (!is_valid_hex64(val)) {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            fims_str_copy(expected_digest, sizeof(expected_digest), val);
            has_expected_digest = true;
            header_is_hmac = false;
        } else if (strncmp(line, "BODY_SHA256=", 12) == 0) {
            if (!is_valid_hex64(line + 12)) {
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
            fims_str_copy(expected_digest, sizeof(expected_digest), line + 12);
            has_expected_digest = true;
            header_is_hmac = false;
        } else {
            /* Unknown header line */
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }
    }

    if (!has_created || !has_count || !has_expected_digest || !in_records) {
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CORRUPT;
    }

    /* Check HMAC key configuration */
    unsigned char key[256];
    size_t key_len = 0;
    bool has_key = false;
    const char *key_env = getenv("FIMS_HMAC_KEY_FILE");
    if (key_env && key_env[0] != '\0') {
        fims_status_t kst = load_hmac_key(key, sizeof(key), &key_len, &has_key);
        if (kst != FIMS_OK || !has_key) {
            /* Item 8: Missing or invalid key file means FIMS_ERR_CORRUPT */
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }
        if (!header_is_hmac) {
            /* Baseline missing HMAC header when HMAC key configured */
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }
    } else {
        if (header_is_hmac) {
            /* Baseline requires HMAC but no key file configured */
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }
    }

    baseline_digest_ctx_t dctx;
    if (!digest_init(&dctx, has_key ? key : NULL, key_len)) {
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    /* Item 8: Include ALL header lines in the digest */
    char hdr_buf[FIMS_MAX_LINE];
    int hlen = snprintf(hdr_buf, sizeof(hdr_buf), "%s\n", FIMS_BASELINE_MAGIC);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    hlen = snprintf(hdr_buf, sizeof(hdr_buf), "CREATED_AT=%lld\n", (long long)out_list->created_at);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    hlen = snprintf(hdr_buf, sizeof(hdr_buf), "RECORD_COUNT=%zu\n", expected_count);
    if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
        digest_cleanup(&dctx);
        fclose(fp);
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    for (size_t i = 0; i < out_list->root_dir_count; i++) {
        hlen = snprintf(hdr_buf, sizeof(hdr_buf), "ROOT_DIR=%s\n", out_list->root_dirs[i]);
        if (hlen < 0 || !digest_update(&dctx, hdr_buf, (size_t)hlen)) {
            digest_cleanup(&dctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CRYPTO;
        }
    }

    /* Process record lines */
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strcmp(line, "---END_RECORDS---\n") == 0 ||
            strcmp(line, "---END_RECORDS---\r\n") == 0 ||
            strcmp(line, "---END_RECORDS---") == 0) {
            end_records_seen = true;
            break;
        }

        size_t raw_len = strlen(line);
        if (!digest_update(&dctx, line, raw_len)) {
            digest_cleanup(&dctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CRYPTO;
        }

        fims_file_record_t rec;
        if (!parse_record_line(line, &rec)) {
            digest_cleanup(&dctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_CORRUPT;
        }

        if (fims_file_list_append(out_list, &rec) != FIMS_OK) {
            digest_cleanup(&dctx);
            fclose(fp);
            fims_file_list_free(out_list);
            return FIMS_ERR_NOMEM;
        }
    }

    if (end_records_seen) {
        /* Check for trailing garbage after ---END_RECORDS--- */
        while (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0] != '\0') {
                digest_cleanup(&dctx);
                fclose(fp);
                fims_file_list_free(out_list);
                return FIMS_ERR_CORRUPT;
            }
        }
    }

    fclose(fp);

    char actual_digest[FIMS_HASH_HEX_LEN];
    if (!digest_final(&dctx, actual_digest)) {
        fims_file_list_free(out_list);
        return FIMS_ERR_CRYPTO;
    }

    if (!end_records_seen || out_list->count != expected_count ||
        strcmp(actual_digest, expected_digest) != 0) {
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

/* ============================================================================
 * Multi-Root Support (Item 23)
 * ============================================================================ */
fims_status_t fims_baseline_add_root_dir(fims_file_list_t *list, const char *root_dir) {
    if (!list || !root_dir || root_dir[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < list->root_dir_count; i++) {
        if (strcmp(list->root_dirs[i], root_dir) == 0) {
            return FIMS_OK; /* Already registered */
        }
    }
    if (list->root_dir_count >= FIMS_MAX_DIRS) {
        return FIMS_ERR_INVALID_ARG;
    }
    if (!fims_str_copy(list->root_dirs[list->root_dir_count], FIMS_MAX_PATH, root_dir)) {
        return FIMS_ERR_INVALID_ARG;
    }
    list->root_dir_count++;
    return FIMS_OK;
}

fims_status_t fims_baseline_add_root(const char *baseline_path,
                                     const char *new_dir_path,
                                     fims_config_t *cfg) {
    if (!baseline_path || !new_dir_path || !cfg ||
        baseline_path[0] == '\0' || new_dir_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }

    char resolved_dir[FIMS_MAX_PATH];
    if (realpath(new_dir_path, resolved_dir) == NULL) {
        if (!fims_str_copy(resolved_dir, sizeof(resolved_dir), new_dir_path)) {
            return FIMS_ERR_INVALID_ARG;
        }
    }

    struct stat st;
    if (stat(resolved_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return FIMS_ERR_NOT_FOUND;
    }

    fims_file_list_t base_list;
    fims_status_t status = fims_baseline_load(baseline_path, &base_list);
    if (status != FIMS_OK) {
        return status;
    }

    status = fims_baseline_add_root_dir(&base_list, resolved_dir);
    if (status != FIMS_OK) {
        fims_file_list_free(&base_list);
        return status;
    }

    fims_file_list_t new_files;
    status = fims_file_list_init(&new_files);
    if (status != FIMS_OK) {
        fims_file_list_free(&base_list);
        return status;
    }

    status = fims_scan_directory(resolved_dir, cfg, &new_files);
    if (status != FIMS_OK) {
        fims_file_list_free(&new_files);
        fims_file_list_free(&base_list);
        return status;
    }

    for (size_t i = 0; i < new_files.count; i++) {
        const fims_file_record_t *rec = &new_files.records[i];
        bool found = false;
        for (size_t j = 0; j < base_list.count; j++) {
            if (strcmp(base_list.records[j].path, rec->path) == 0) {
                base_list.records[j] = *rec;
                found = true;
                break;
            }
        }
        if (!found) {
            status = fims_file_list_append(&base_list, rec);
            if (status != FIMS_OK) {
                fims_file_list_free(&new_files);
                fims_file_list_free(&base_list);
                return status;
            }
        }
    }

    fims_file_list_free(&new_files);

    fims_file_list_sort(&base_list);

    status = fims_baseline_save(baseline_path, &base_list, true);
    fims_file_list_free(&base_list);

    return status;
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
    printf(" Integrity      : VERIFIED (Cryptographic digest valid)\n");
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
        if (r->unreadable || r->sha256[0] == '\0') {
            printf(" %04o   %-10llu %-16s %s\n",
                   r->mode,
                   (unsigned long long)r->size,
                   "[UNREADABLE]",
                   r->path);
        } else {
            printf(" %04o   %-10llu %.16s... %s\n",
                   r->mode,
                   (unsigned long long)r->size,
                   r->sha256,
                   r->path);
        }
    }
    printf("================================================================================\n");

    fims_file_list_free(&list);
    return FIMS_OK;
}
