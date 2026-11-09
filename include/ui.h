#ifndef FIMS_UI_H
#define FIMS_UI_H

#include "fims.h"
#include <stdbool.h>
#include <stddef.h>

/* ============================================================================
 * FIMS ANSI Terminal Color Palette
 * ============================================================================ */
typedef enum {
    UI_COLOR_RESET,
    UI_COLOR_BOLD,
    UI_COLOR_DIM,
    UI_COLOR_CYAN,
    UI_COLOR_BOLD_CYAN,
    UI_COLOR_GREEN,
    UI_COLOR_BOLD_GREEN,
    UI_COLOR_RED,
    UI_COLOR_BOLD_RED,
    UI_COLOR_YELLOW,
    UI_COLOR_BOLD_YELLOW,
    UI_COLOR_BLUE,
    UI_COLOR_BOLD_BLUE,
    UI_COLOR_MAGENTA,
    UI_COLOR_BOLD_MAGENTA,
    UI_COLOR_WHITE,
    UI_COLOR_BOLD_WHITE
} fims_ui_color_t;

/* ============================================================================
 * Terminal Environment & State Management
 * ============================================================================ */

/**
 * Initialize terminal UI system.
 * Detects TTY, checks NO_COLOR env var, and handles --no-color / --color flags.
 */
void fims_ui_init(bool force_no_color, bool force_color);

/**
 * Check if ANSI colors are currently active.
 */
bool fims_ui_colors_active(void);

/**
 * Get ANSI escape sequence string for a color (or "" if colors disabled).
 */
const char *fims_ui_color(fims_ui_color_t c);

/**
 * Get current terminal width (clamped between 60 and 120, default 80).
 */
int fims_ui_get_term_width(void);

/* ============================================================================
 * Branding & Header Presentation
 * ============================================================================ */

/**
 * Render full FIMS ASCII cybersecurity banner with version and mission statement.
 * Adapts to terminal width.
 */
void fims_ui_banner(void);

/**
 * Render compact command header bar.
 * e.g.: "── [ FIMS | INTEGRITY SCAN ] ──────────────────────────────────────────"
 */
void fims_ui_header(const char *module_name);

/**
 * Render section divider line.
 */
void fims_ui_divider(void);

/**
 * Render section sub-heading.
 */
void fims_ui_section(const char *section_title);

/* ============================================================================
 * Status & Feedback Indicators
 * ============================================================================ */

void fims_ui_info(const char *fmt, ...);
void fims_ui_success(const char *fmt, ...);
void fims_ui_warn(const char *fmt, ...);
void fims_ui_error(const char *fmt, ...);
void fims_ui_critical(const char *fmt, ...);

/* ============================================================================
 * Structured Display: Cards, Tables & Boxes
 * ============================================================================ */

/**
 * Print a structured key-value line with uniform alignment.
 * Label is right-padded to 22 chars.
 */
void fims_ui_field(const char *label, const char *fmt, ...);

/**
 * Print an alert card with color-coded severity badge and safely escaped path.
 */
void fims_ui_alert_card(const fims_alert_t *alert);

/**
 * Print a status box summarizing system protection state.
 */
void fims_ui_status_box(const char *status_str, bool is_ok, const char *detail);

/* ============================================================================
 * Progress Indicators
 * ============================================================================ */

/**
 * Print live scan progress (only if interactive TTY).
 */
void fims_ui_progress(const char *action, size_t current, size_t total);

/**
 * Conclude progress line cleanly.
 */
void fims_ui_progress_done(const char *action, size_t total);

#endif /* FIMS_UI_H */
