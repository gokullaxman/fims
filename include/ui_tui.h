#ifndef FIMS_UI_TUI_H
#define FIMS_UI_TUI_H

#define _GNU_SOURCE
#include <ncurses.h>
#include <stdbool.h>
#include "fims.h"

/* ============================================================================
 * Screen Identifiers & State Management
 * ============================================================================ */
typedef enum {
    SCREEN_DASHBOARD = 0,
    SCREEN_INIT,
    SCREEN_SCAN,
    SCREEN_MONITOR,
    SCREEN_BASELINE,
    SCREEN_ALERTS,
    SCREEN_REPORTS,
    SCREEN_CONFIG,
    SCREEN_SYSINFO,
    SCREEN_HELP,
    SCREEN_EXIT,
    SCREEN_COUNT
} fims_tui_screen_t;

typedef enum {
    FOCUS_NAV = 0,
    FOCUS_CONTENT
} fims_tui_focus_t;

typedef struct {
    fims_config_t     *cfg;
    fims_tui_screen_t  active_screen;
    fims_tui_focus_t   focus;
    int                nav_selected;
    bool               running;
    int                term_h;
    int                term_w;
    WINDOW            *win_header;
    WINDOW            *win_nav;
    WINDOW            *win_content;
    WINDOW            *win_footer;
} fims_tui_state_t;

/**
 * Main Interactive TUI Entry Point.
 * Returns process exit code.
 */
int fims_tui_main(fims_config_t *cfg);

/* ============================================================================
 * Individual Screen Handlers & Renderers
 * ============================================================================ */
void fims_screen_render_dashboard(fims_tui_state_t *st);
void fims_screen_handle_dashboard(fims_tui_state_t *st, int ch);

void fims_screen_render_init(fims_tui_state_t *st);
void fims_screen_handle_init(fims_tui_state_t *st, int ch);

void fims_screen_render_scan(fims_tui_state_t *st);
void fims_screen_handle_scan(fims_tui_state_t *st, int ch);

void fims_screen_render_monitor(fims_tui_state_t *st);
void fims_screen_handle_monitor(fims_tui_state_t *st, int ch);

void fims_screen_render_baseline(fims_tui_state_t *st);
void fims_screen_handle_baseline(fims_tui_state_t *st, int ch);

void fims_screen_render_alerts(fims_tui_state_t *st);
void fims_screen_handle_alerts(fims_tui_state_t *st, int ch);

void fims_screen_render_reports(fims_tui_state_t *st);
void fims_screen_handle_reports(fims_tui_state_t *st, int ch);

void fims_screen_render_config(fims_tui_state_t *st);
void fims_screen_handle_config(fims_tui_state_t *st, int ch);

void fims_screen_render_sysinfo(fims_tui_state_t *st);
void fims_screen_handle_sysinfo(fims_tui_state_t *st, int ch);

void fims_screen_render_help(fims_tui_state_t *st);
void fims_screen_handle_help(fims_tui_state_t *st, int ch);

#endif /* FIMS_UI_TUI_H */
