#ifndef FIMS_HASH_H
#define FIMS_HASH_H

#include "../include/fims.h"

/**
 * Compute the SHA-256 cryptographic hash of a file using the OpenSSL EVP API.
 *
 * Security & Design guarantees:
 * - Processes the file in fixed 64 KB chunks (never loads entire file into RAM).
 * - Opens file with O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK to prevent symlink following
 *   and avoid blocking indefinitely on FIFOs or special pipes (Item 12).
 * - Handles EINTR on read() calls gracefully.
 * - Verifies that the opened descriptor refers to a regular file (S_ISREG) via fstat,
 *   rejecting FIFOs, sockets, character devices, and block devices cleanly.
 *
 * @param file_path Absolute or relative path to the regular file.
 * @param out_hex   Output buffer of at least FIMS_HASH_HEX_LEN (65) bytes.
 * @return FIMS_OK on success, or an appropriate error status code.
 */
fims_status_t fims_hash_file_sha256(const char *file_path, char out_hex[FIMS_HASH_HEX_LEN]);

/**
 * Compute the SHA-256 cryptographic hash of an open file descriptor using OpenSSL EVP.
 * Reads in fixed 64 KB chunks until EOF. Does not close the file descriptor.
 *
 * @param fd      Open file descriptor to read and hash.
 * @param out_hex Output buffer of at least FIMS_HASH_HEX_LEN (65) bytes.
 * @return FIMS_OK on success, or an appropriate error status code.
 */
fims_status_t fims_hash_fd_sha256(int fd, char out_hex[FIMS_HASH_HEX_LEN]);

/**
 * Compute the SHA-256 cryptographic hash of an in-memory buffer using OpenSSL EVP.
 * Used for baseline integrity self-validation (HMAC/checksum header verification).
 */
fims_status_t fims_hash_buffer_sha256(const void *data, size_t len, char out_hex[FIMS_HASH_HEX_LEN]);

#endif /* FIMS_HASH_H */
