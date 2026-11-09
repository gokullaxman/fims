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

fims_status_t fims_hash_fd_sha256(int fd, char out_hex[FIMS_HASH_HEX_LEN]) {
    if (fd < 0 || !out_hex) {
        return FIMS_ERR_INVALID_ARG;
    }
    out_hex[0] = '\0';

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return FIMS_ERR_CRYPTO;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return FIMS_ERR_CRYPTO;
    }

    /* Allocate chunk buffer on heap to keep stack frame small */
    unsigned char *buffer = (unsigned char *)malloc(FIMS_CHUNK_SIZE);
    if (!buffer) {
        EVP_MD_CTX_free(ctx);
        return FIMS_ERR_NOMEM;
    }

    fims_status_t status = FIMS_OK;
    for (;;) {
        ssize_t bytes_read = read(fd, buffer, FIMS_CHUNK_SIZE);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue; /* Retry interrupted system call */
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Non-blocking descriptor with no data pending */
                break;
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
    return status;
}

fims_status_t fims_hash_file_sha256(const char *file_path, char out_hex[FIMS_HASH_HEX_LEN]) {
    if (!file_path || !out_hex || file_path[0] == '\0') {
        return FIMS_ERR_INVALID_ARG;
    }
    out_hex[0] = '\0';

    /* Open with O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK (Item 12):
     * - O_NOFOLLOW: rejects symlinks immediately (ELOOP)
     * - O_NONBLOCK: avoids indefinite hang on FIFOs and special files */
    int fd;
    do {
        fd = open(file_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return FIMS_ERR_PERMISSION;
        if (errno == ENOENT) return FIMS_ERR_NOT_FOUND;
        if (errno == ELOOP) return FIMS_ERR_INVALID_ARG;
        return FIMS_ERR_IO;
    }

    /* Verify file descriptor refers to a regular file via fstat on the open fd */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return FIMS_ERR_IO;
    }

    /* Cleanly reject FIFOs, sockets, character devices, block devices */
    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode) || S_ISCHR(st.st_mode) ||
        S_ISBLK(st.st_mode) || !S_ISREG(st.st_mode)) {
        close(fd);
        return FIMS_ERR_INVALID_ARG;
    }

    fims_status_t status = fims_hash_fd_sha256(fd, out_hex);
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
