#include "escape.h"
#include <stdbool.h>
#include <stdint.h>

static const char hex_digits[] = "0123456789abcdef";

size_t fims_escape_for_log(const char *in, char *out, size_t out_sz) {
    if (!in) {
        if (out && out_sz > 0) {
            out[0] = '\0';
        }
        return 0;
    }

    size_t total_len = 0;
    size_t out_idx = 0;

    for (const char *p = in; *p != '\0'; p++) {
        unsigned char uc = (unsigned char)*p;
        bool escape = false;
        if (uc == '"' || uc == '\\' || uc < 0x20 || uc == 0x7f) {
            escape = true;
        }

        if (escape) {
            char seq[4];
            seq[0] = '\\';
            seq[1] = 'x';
            seq[2] = hex_digits[(uc >> 4) & 0x0f];
            seq[3] = hex_digits[uc & 0x0f];

            for (int i = 0; i < 4; i++) {
                if (out && out_sz > 0 && out_idx + 1 < out_sz) {
                    out[out_idx++] = seq[i];
                }
                total_len++;
            }
        } else {
            if (out && out_sz > 0 && out_idx + 1 < out_sz) {
                out[out_idx++] = (char)uc;
            }
            total_len++;
        }
    }

    if (out && out_sz > 0) {
        out[out_idx] = '\0';
    }

    return total_len;
}
