#define _GNU_SOURCE
#include "ui.h"
#include "escape.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>

static bool g_colors_enabled = false;
static bool g_ui_initialized = false;

/* ============================================================================
 * Terminal Environment & State Management
 * ============================================================================ */

void fims_ui_init(bool force_no_color, bool force_color) {
    g_ui_initialized = true;

    if (force_no_color) {
        g_colors_enabled = false;
        return;
    }

    if (force_color) {
        g_colors_enabled = true;
        return;
    }

    /* Check NO_COLOR standard (https://no-color.org/) */
    const char *no_color_env = getenv("NO_COLOR");
    if (no_color_env && no_color_env[0] != '\0') {
        g_colors_enabled = false;
        return;
    }

    /* Check TERM environment variable */
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb") == 0) {
        g_colors_enabled = false;
        return;
    }

    /* Default: enable colors if stdout is an interactive terminal */
    g_colors_enabled = (isatty(STDOUT_FILENO) == 1);
}

bool fims_ui_colors_active(void) {
    if (!g_ui_initialized) {
        fims_ui_init(false, false);
    }
    return g_colors_enabled;
}

const char *fims_ui_color(fims_ui_color_t c) {
    if (!fims_ui_colors_active()) {
        return "";
    }

    switch (c) {
        case UI_COLOR_RESET:         return "\033[0m";
        case UI_COLOR_BOLD:          return "\033[1m";
        case UI_COLOR_DIM:           return "\033[90m";
        case UI_COLOR_CYAN:          return "\033[36m";
        case UI_COLOR_BOLD_CYAN:     return "\033[1;36m";
        case UI_COLOR_GREEN:         return "\033[32m";
        case UI_COLOR_BOLD_GREEN:    return "\033[1;32m";
        case UI_COLOR_RED:           return "\033[31m";
        case UI_COLOR_BOLD_RED:      return "\033[1;31m";
        case UI_COLOR_YELLOW:        return "\033[33m";
        case UI_COLOR_BOLD_YELLOW:   return "\033[1;33m";
        case UI_COLOR_BLUE:          return "\033[34m";
        case UI_COLOR_BOLD_BLUE:     return "\033[1;34m";
        case UI_COLOR_MAGENTA:       return "\033[35m";
        case UI_COLOR_BOLD_MAGENTA:  return "\033[1;35m";
        case UI_COLOR_WHITE:         return "\033[37m";
        case UI_COLOR_BOLD_WHITE:    return "\033[1;37m";
        default:                     return "";
    }
}

int fims_ui_get_term_width(void) {
    struct winsize ws;
    if (isatty(STDOUT_FILENO) && ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        if (ws.ws_col < 60) return 60;
        if (ws.ws_col > 120) return 120;
        return (int)ws.ws_col;
    }
    return 80;
}

/* ============================================================================
 * Branding & Header Presentation
 * ============================================================================ */

void fims_ui_banner(void) {
    const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_grn  = fims_ui_color(UI_COLOR_BOLD_GREEN);
    const char *c_wht  = fims_ui_color(UI_COLOR_BOLD_WHITE);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    printf("%s╭──────────────────────────────────────────────────────────────────────────────╮%s\n", c_cyan, c_rst);
    printf("%s│%s  %s◈ FIMS%s  │  %sFile Integrity Monitoring System%s  v%s                  %s│%s\n",
           c_cyan, c_rst, c_cyan, c_rst, c_wht, c_rst, FIMS_VERSION, c_cyan, c_rst);
    printf("%s│%s  %sLinux Enterprise Threat Defense & Integrity Engine • ISO C11%s             %s│%s\n",
           c_cyan, c_rst, c_dim, c_rst, c_cyan, c_rst);
    printf("%s│%s  %sStatus: %s● PROTECTED%s %s(OpenSSL EVP SHA-256 • Linux inotify Subsystem)%s          %s│%s\n",
           c_cyan, c_rst, c_dim, c_grn, c_rst, c_dim, c_rst, c_cyan, c_rst);
    printf("%s╰──────────────────────────────────────────────────────────────────────────────╯%s\n", c_cyan, c_rst);
}

void fims_ui_header(const char *module_name) {
    int width = fims_ui_get_term_width();
    const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
    const char *c_wht  = fims_ui_color(UI_COLOR_BOLD_WHITE);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    const char *mod = module_name ? module_name : "SECURITY";
    printf("\n%s◆ FIMS%s › %s%s%s %s", c_cyan, c_rst, c_wht, mod, c_rst, c_dim);

    int pad = width - 12 - (int)strlen(mod);
    if (pad < 4) pad = 4;
    for (int i = 0; i < pad; i++) {
        printf("─");
    }
    printf("%s\n\n", c_rst);
}

void fims_ui_divider(void) {
    int width = fims_ui_get_term_width();
    const char *c_dim = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("%s", c_dim);
    for (int i = 0; i < width; i++) {
        printf("─");
    }
    printf("%s\n", c_rst);
}

void fims_ui_section(const char *section_title) {
    const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    printf("\n%s● %s%s\n", c_cyan, section_title, c_rst);
    printf("%s  ──────────────────────────────────────────────────────────%s\n", c_dim, c_rst);
}

/* ============================================================================
 * Status & Feedback Indicators
 * ============================================================================ */

void fims_ui_info(const char *fmt, ...) {
    const char *c_blu = fims_ui_color(UI_COLOR_BOLD_BLUE);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("%s● [INFO]%s ", c_blu, c_rst);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

void fims_ui_success(const char *fmt, ...) {
    const char *c_grn = fims_ui_color(UI_COLOR_BOLD_GREEN);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("%s✔ [OK]%s ", c_grn, c_rst);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

void fims_ui_warn(const char *fmt, ...) {
    const char *c_yel = fims_ui_color(UI_COLOR_BOLD_YELLOW);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("%s▲ [WARNING]%s ", c_yel, c_rst);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

void fims_ui_error(const char *fmt, ...) {
    const char *c_red = fims_ui_color(UI_COLOR_BOLD_RED);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    fprintf(stderr, "%s✖ [ERROR]%s ", c_red, c_rst);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
}

void fims_ui_critical(const char *fmt, ...) {
    const char *c_red = fims_ui_color(UI_COLOR_BOLD_RED);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    fprintf(stderr, "%s✖ [CRITICAL]%s ", c_red, c_rst);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
}

/* ============================================================================
 * Structured Display: Cards, Tables & Boxes
 * ============================================================================ */

void fims_ui_field(const char *label, const char *fmt, ...) {
    const char *c_dim = fims_ui_color(UI_COLOR_DIM);
    const char *c_wht = fims_ui_color(UI_COLOR_BOLD_WHITE);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("  %s%-22s%s : %s", c_dim, label ? label : "", c_rst, c_wht);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("%s\n", c_rst);
}

void fims_ui_alert_card(const fims_alert_t *alert) {
    if (!alert) return;

    /* Escape paths and description against terminal injection */
    char esc_path[FIMS_MAX_PATH * 4];
    char esc_old_path[FIMS_MAX_PATH * 4];
    char esc_desc[sizeof(alert->description) * 4];

    fims_escape_for_log(alert->path, esc_path, sizeof(esc_path));
    fims_escape_for_log(alert->old_path, esc_old_path, sizeof(esc_old_path));
    fims_escape_for_log(alert->description, esc_desc, sizeof(esc_desc));

    const char *event_str = (alert->event_type == EVENT_UNREADABLE) ?
                            "UNREADABLE" : fims_event_type_str(alert->event_type);
    const char *sev_str   = fims_severity_str(alert->severity);

    const char *sev_color = fims_ui_color(UI_COLOR_BOLD_YELLOW);
    if (alert->severity == SEV_CRITICAL) {
        sev_color = fims_ui_color(UI_COLOR_BOLD_RED);
    } else if (alert->severity == SEV_HIGH) {
        sev_color = fims_ui_color(UI_COLOR_RED);
    } else if (alert->severity == SEV_MEDIUM) {
        sev_color = fims_ui_color(UI_COLOR_BOLD_YELLOW);
    } else if (alert->severity == SEV_LOW) {
        sev_color = fims_ui_color(UI_COLOR_CYAN);
    } else if (alert->severity == SEV_INFO) {
        sev_color = fims_ui_color(UI_COLOR_BLUE);
    }

    const char *c_dim = fims_ui_color(UI_COLOR_DIM);
    const char *c_mag = fims_ui_color(UI_COLOR_MAGENTA);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    /*
     * Primary Alert Header Line:
     * Starts with "[ALERT] " and includes event and path on one line
     * for seamless compatibility with test scripts (e.g. repro_B).
     */
    if (alert->event_type == EVENT_FILE_RENAMED && esc_old_path[0] != '\0') {
        printf("[ALERT] %s[%s] %s%s: %s -> %s\n",
               sev_color, sev_str, event_str, c_rst, esc_old_path, esc_path);
    } else {
        printf("[ALERT] %s[%s] %s%s: %s\n",
               sev_color, sev_str, event_str, c_rst, esc_path);
    }

    /* Structured metadata card */
    printf("        %sSeverity   %s: %s%s%s\n", c_dim, c_rst, sev_color, sev_str, c_rst);
    printf("        %sPrev Hash  %s: %s%s%s\n", c_dim, c_rst, c_mag, alert->prev_hash[0] ? alert->prev_hash : "NONE", c_rst);
    printf("        %sCurr Hash  %s: %s%s%s\n", c_dim, c_rst, c_mag, alert->curr_hash[0] ? alert->curr_hash : "NONE", c_rst);
    printf("        %sDescription%s: %s\n", c_dim, c_rst, esc_desc[0] ? esc_desc : "Integrity change detected");

    char ts_buf[64];
    time_t t = alert->timestamp ? alert->timestamp : time(NULL);
    struct tm tm_info;
    if (localtime_r(&t, &tm_info) != NULL) {
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S %z", &tm_info);
        printf("        %sTimestamp  %s: %s%s%s\n", c_dim, c_rst, c_dim, ts_buf, c_rst);
    }
}

void fims_ui_status_box(const char *status_str, bool is_ok, const char *detail) {
    const char *c_badge = is_ok ? fims_ui_color(UI_COLOR_BOLD_GREEN) : fims_ui_color(UI_COLOR_BOLD_RED);
    const char *c_dim   = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst   = fims_ui_color(UI_COLOR_RESET);

    printf("\n  %s● STATUS:%s  %s%s %s%s",
           c_dim, c_rst,
           c_badge, is_ok ? "✔" : "▲", status_str ? status_str : (is_ok ? "PROTECTED" : "ATTENTION REQUIRED"), c_rst);
    if (detail && detail[0]) {
        printf(" %s• %s%s", c_dim, detail, c_rst);
    }
    printf("\n\n");
}

void fims_ui_execution_summary(const fims_execution_summary_t *summary) {
    if (!summary) return;

    const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
    const char *c_wht  = fims_ui_color(UI_COLOR_BOLD_WHITE);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_grn  = fims_ui_color(UI_COLOR_BOLD_GREEN);
    const char *c_red  = fims_ui_color(UI_COLOR_BOLD_RED);
    const char *c_yel  = fims_ui_color(UI_COLOR_BOLD_YELLOW);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    const char *c_status = summary->is_success ? c_grn : (summary->exit_code == 3 ? c_red : c_yel);
    const char *status_icon = summary->is_success ? "✔" : (summary->exit_code == 3 ? "✖" : "▲");

    printf("\n%s╭─ EXECUTION SUMMARY ──────────────────────────────────────────────────────────╮%s\n", c_cyan, c_rst);
    printf("%s│%s                                                                              %s│%s\n", c_cyan, c_rst, c_cyan, c_rst);
    printf("%s│%s  %s● Command%s          : %s%-47s%s %s│%s\n",
           c_cyan, c_rst, c_dim, c_rst, c_wht, summary->command_name ? summary->command_name : "UNKNOWN", c_rst, c_cyan, c_rst);
    printf("%s│%s  %s● Status%s           : %s%s %-45s%s %s│%s\n",
           c_cyan, c_rst, c_dim, c_rst, c_status, status_icon, summary->status_str ? summary->status_str : (summary->is_success ? "SUCCESS" : "FAILED"), c_rst, c_cyan, c_rst);
    printf("%s│%s  %s● Exit Code%s        : %s%-47d%s %s│%s\n",
           c_cyan, c_rst, c_dim, c_rst, c_wht, summary->exit_code, c_rst, c_cyan, c_rst);

    if (summary->duration_ms > 0) {
        char dur_str[64];
        snprintf(dur_str, sizeof(dur_str), "%.2f ms", summary->duration_ms);
        printf("%s│%s  %s● Duration%s         : %s%-47s%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_wht, dur_str, c_rst, c_cyan, c_rst);
    }
    if (summary->target_dir && summary->target_dir[0]) {
        printf("%s│%s  %s● Monitored Path%s   : %s%-47.47s%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_wht, summary->target_dir, c_rst, c_cyan, c_rst);
    }

    if (summary->files_total > 0) {
        printf("%s│%s                                                                              %s│%s\n", c_cyan, c_rst, c_cyan, c_rst);
        printf("%s│%s  %s┌─ Audit Breakdown ────────────────────────────────────────────────────────┐%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_cyan, c_rst);
        printf("%s│%s  %s│%s  Files Checked : %-12zu  Unchanged : %s%-12zu%s            %s│%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, summary->files_total, c_grn, summary->files_unchanged, c_rst, c_dim, c_rst, c_cyan, c_rst);
        printf("%s│%s  %s│%s  Modified      : %s%-12zu%s  Added     : %s%-12zu%s            %s│%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst,
               summary->files_modified > 0 ? c_red : c_wht, summary->files_modified, c_rst,
               summary->files_added > 0 ? c_yel : c_wht, summary->files_added, c_rst,
               c_dim, c_rst, c_cyan, c_rst);
        printf("%s│%s  %s│%s  Deleted       : %s%-12zu%s  Renamed   : %s%-12zu%s            %s│%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst,
               summary->files_deleted > 0 ? c_red : c_wht, summary->files_deleted, c_rst,
               summary->files_renamed > 0 ? c_yel : c_wht, summary->files_renamed, c_rst,
               c_dim, c_rst, c_cyan, c_rst);
        printf("%s│%s  %s└──────────────────────────────────────────────────────────────────────────┘%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_cyan, c_rst);
    }

    if (summary->details && summary->details[0]) {
        printf("%s│%s  %s◈ Cryptography%s     : %s%-47.47s%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_wht, summary->details, c_rst, c_cyan, c_rst);
    }
    if (summary->verdict && summary->verdict[0]) {
        printf("%s│%s  %s◈ Verdict%s          : %s%-47.47s%s %s│%s\n",
               c_cyan, c_rst, c_dim, c_rst, c_status, summary->verdict, c_rst, c_cyan, c_rst);
    }

    printf("%s╰──────────────────────────────────────────────────────────────────────────────╯%s\n\n", c_cyan, c_rst);
}

/* ============================================================================
 * Progress Indicators
 * ============================================================================ */

void fims_ui_progress(const char *action, size_t current, size_t total) {
    /* Only render live progress line on interactive terminals */
    if (!isatty(STDOUT_FILENO)) return;

    const char *c_cyan = fims_ui_color(UI_COLOR_CYAN);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    if (total > 0) {
        int pct = (int)((current * 100) / total);
        printf("\r  %s[%3d%%]%s %s... %s(%zu/%zu)%s", c_cyan, pct, c_rst, action, c_dim, current, total, c_rst);
    } else {
        printf("\r  %s[*]%s %s... %s(%zu)%s", c_cyan, c_rst, action, c_dim, current, c_rst);
    }
    fflush(stdout);
}

void fims_ui_progress_done(const char *action, size_t total) {
    if (!isatty(STDOUT_FILENO)) return;

    const char *c_grn = fims_ui_color(UI_COLOR_BOLD_GREEN);
    const char *c_dim = fims_ui_color(UI_COLOR_DIM);
    const char *c_rst = fims_ui_color(UI_COLOR_RESET);

    printf("\r  %s[100%%]%s %s completed. %s(%zu total)%s    \n",
           c_grn, c_rst, action, c_dim, total, c_rst);
    fflush(stdout);
}
