#ifndef FIMS_UI_DIALOGS_H
#define FIMS_UI_DIALOGS_H

#define _GNU_SOURCE
#include <ncurses.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Display an interactive modal confirmation dialog with Cancel / Confirm buttons.
 * Allows switching buttons with LEFT/RIGHT, confirming with ENTER, cancelling with ESC.
 * Returns true if confirmed, false if cancelled.
 */
bool fims_dialog_confirm(const char *title, const char *message, const char *btn_cancel, const char *btn_confirm);

/**
 * Display an informational, warning, or error modal dialog.
 * Dismissed with ENTER, SPACE, or ESC.
 */
void fims_dialog_message(const char *title, const char *message, int color_pair);

/**
 * Display an interactive text input modal dialog.
 * Allows editing string in buffer, confirming with ENTER, cancelling with ESC.
 * Returns true if input submitted, false if cancelled.
 */
bool fims_dialog_input(const char *title, const char *prompt, char *buffer, size_t buf_sz);

/**
 * Display a live progress dialog overlay.
 */
void fims_dialog_progress_draw(const char *title, const char *action, size_t current, size_t total);

/**
 * Display a structured Execution Summary modal dialog in TUI mode.
 * Dismissed with ENTER, SPACE, or ESC.
 */
void fims_dialog_summary(const char *cmd_name,
                         bool is_ok,
                         const char *status_badge,
                         size_t scanned,
                         size_t unchanged,
                         size_t mod,
                         size_t add,
                         size_t del,
                         double duration_ms,
                         const char *details);

#endif /* FIMS_UI_DIALOGS_H */
