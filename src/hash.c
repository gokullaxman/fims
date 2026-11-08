#include "hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>

static void bytes_to_hex(const unsigned char *digest, unsigned int digest_len, char *out_hex) {
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; i++) {
        out_hex[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    out_hex[digest_len * 2] = '\0';
}

fims_status_t fims_hash_file_sha256(const char *file_path, char out_hex[FIMS_HASH_HEX_LEN]) {
    if (!file_path || !out_hex || file_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }
    out_hex[0] = '\0';

    /* Security-critical: Open with O_NOFOLLOW so symlinks are rejected at open time */
    int fd;
    do {
        fd = open(file_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return FIMS_ERR_PERMISSION;
        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        return FIMS_ERR_IO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return FIMS_ERR_INVALID_ARG;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return FIMS_ERR_CRYPTO;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return FIMS_ERR_CRYPTO;
    }

    /* Allocate chunk buffer on heap to keep stack frame small and never load full file in memory */
    unsigned char *buffer = (unsigned char *)malloc(FIMS_CHUNK_SIZE);
    if (!buffer) {
        EVP_MD_CTX_free(ctx);
        close(fd);
        return FIMS_ERR_NOMEM;
    }

    fims_status_t status = FIMS_OK;
    for (;;) {
        ssize_t bytes_read = read(fd, buffer, FIMS_CHUNK_SIZE);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue; /* Retry interrupted system call */
            }
            status = FIMS_ERR_IO;
            break;
        }
        if (bytes_read == 0) {
            break; /* EOF reached */
        }
        if (EVP_DigestUpdate(ctx, buffer, (size_t)bytes_read) != 1) {
            status = FIMS_ERR_CRYPTO;
            break;
        }
    }

    if (status == FIMS_OK) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != FIMS_HASH_BYTES) {
            status = FIMS_ERR_CRYPTO;
        } else {
            bytes_to_hex(digest, digest_len, out_hex);
        }
    }

    free(buffer);
    EVP_MD_CTX_free(ctx);
    close(fd);
    return status;
}

fims_status_t fims_hash_buffer_sha256(const void *data, size_t len, char out_hex[FIMS_HASH_HEX_LEN]) {
    if ((!data && len > 0) || !out_hex) {
        return FIMS_ERR_INVALID_ARG;
    }
    out_hex[0] = '\0';

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return FIMS_ERR_CRYPTO;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return FIMS_ERR_CRYPTO;
    }

    if (len > 0) {
        if (EVP_DigestUpdate(ctx, data, len) != 1) {
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

    bytes_to_hex(digest, digest_len, out_hex);
    EVP_MD_CTX_free(ctx);
    return FIMS_OK;
}
