#include "escape.h"
#include <string.h>

/**
 * Stub implementation of fims_escape_for_log that performs a simple copy
 * to ensure linking succeeds during early integration phases.
 */
size_t fims_escape_for_log(const char *in, char *out, size_t out_sz) {
    if (!in) {
        if (out && out_sz > 0) {
            out[0] = '\0';
        }
        return 0;
    }

    size_t in_len = strlen(in);
    if (out && out_sz > 0) {
        size_t copy_len = (in_len < out_sz - 1) ? in_len : (out_sz - 1);
        memcpy(out, in, copy_len);
        out[copy_len] = '\0';
    }
    return in_len;
}
