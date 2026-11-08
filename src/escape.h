#ifndef FIMS_ESCAPE_H
#define FIMS_ESCAPE_H

#include <stddef.h>

/**
 * Escapes characters for safe inclusion in logs, reports, and console output.
 * Specifically escapes:
 *   - Double quote: '"'
 *   - Backslash: '\\'
 *   - Control characters: < 0x20 (including ESC 0x1b)
 *   - DEL: 0x7f
 * Output format for escaped characters: \xNN (hexadecimal representation).
 *
 * Guarantees:
 *   - If out != NULL and out_sz > 0, out is always NUL-terminated.
 *   - Returns the total length of the escaped string that would be produced
 *     (excluding the terminating NUL byte), snprintf-style.
 *
 * @param in     Input string to escape (if NULL, treated as empty string).
 * @param out    Output buffer to receive escaped string (can be NULL if out_sz == 0).
 * @param out_sz Size of the output buffer in bytes.
 * @return Total length the escaped string would need, excluding terminating NUL.
 */
size_t fims_escape_for_log(const char *in, char *out, size_t out_sz);

#endif /* FIMS_ESCAPE_H */
