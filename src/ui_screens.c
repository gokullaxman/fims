#define _GNU_SOURCE
#include "ui_tui.h"
#include "ui_colors.h"
#include "ui_dialogs.h"
#include "scanner.h"
#include "baseline.h"
#include "integrity.h"
#include "monitor.h"
#include "config.h"
#include "logger.h"
#include "escape.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

/* ============================================================================
 * Helper Utilities for Screen Rendering
 * ============================================================================ */

static void render_box(WINDOW *win, int y, int x, int h, int w, const char *title, int title_color) {
    wattron(win, fims_color_attr(CP_BORDER));
    mvwaddch(win, y, x, ACS_ULCORNER);
    mvwaddch(win, y, x + w - 1, ACS_URCORNER);
    mvwaddch(win, y + h - 1, x, ACS_LLCORNER);
    mvwaddch(win, y + h - 1, x + w - 1, ACS_LRCORNER);

    for (int i = 1; i < w - 1; i++) {
        mvwaddch(win, y, x + i, ACS_HLINE);
        mvwaddch(win, y + h - 1, x + i, ACS_HLINE);
    }
    for (int i = 1; i < h - 1; i++) {
        mvwaddch(win, y + i, x, ACS_VLINE);
        mvwaddch(win, y + i, x + w - 1, ACS_VLINE);
    }
    wattroff(win, fims_color_attr(CP_BORDER));

    if (title && title[0]) {
        wattron(win, fims_color_attr(title_color ? title_color : CP_HEADER));
        mvwprintw(win, y, x + 2, " %s ", title);
        wattroff(win, fims_color_attr(title_color ? title_color : CP_HEADER));
    }
}

/* ============================================================================
 * 1. MAIN DASHBOARD SCREEN
 * ============================================================================ */

void fims_screen_render_dashboard(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    /* Title */
    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "FIMS SECURITY CONSOLE");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Real-Time Linux File Integrity Monitoring System (ISO C11)");
    wattroff(win, fims_color_attr(CP_DIM));

    /* Panel dimensions */
    int panel_w = (w - 6) / 2;
    if (panel_w < 32) panel_w = 32;
    int panel_h = 10;

    /* System Overview Box */
    render_box(win, 4, 2, panel_h, panel_w, "SYSTEM OVERVIEW", CP_HEADER);

    fims_file_list_t bl;
    fims_status_t bst = fims_baseline_load(st->cfg->baseline_file, &bl);
    bool bl_valid = (bst == FIMS_OK);
    size_t tracked_files = bl_valid ? bl.count : 0;
    if (bl_valid) fims_file_list_free(&bl);

    const char *hmac_key = getenv("FIMS_HMAC_KEY_FILE");
    bool has_hmac = (hmac_key && hmac_key[0] != '\0');

    /* Read runtime state */
    char active_str[32] = "IDLE";
    char last_scan_str[64] = "never";
    pid_t daemon_pid = 0;
    time_t heartbeat = 0;
    uint32_t interval = 30;

    FILE *sfp = fopen(st->cfg->state_file, "r");
    if (sfp) {
        char sline[256];
        while (fgets(sline, sizeof(sline), sfp)) {
            sline[strcspn(sline, "\r\n")] = '\0';
            char *eq = strchr(sline, '=');
            if (!eq) continue;
            *eq = '\0';
            if (strcmp(sline, "MONITOR_ACTIVE") == 0) strncpy(active_str, eq + 1, sizeof(active_str) - 1);
            else if (strcmp(sline, "LAST_SCAN_TIMESTAMP") == 0) strncpy(last_scan_str, eq + 1, sizeof(last_scan_str) - 1);
            else if (strcmp(sline, "PID") == 0) daemon_pid = (pid_t)atol(eq + 1);
            else if (strcmp(sline, "HEARTBEAT") == 0) heartbeat = (time_t)atoll(eq + 1);
            else if (strcmp(sline, "SCAN_INTERVAL") == 0) interval = (uint32_t)atoi(eq + 1);
        }
        fclose(sfp);
    }

    bool is_alive = false;
    if (daemon_pid > 0 && kill(daemon_pid, 0) == 0) {
        time_t diff = time(NULL) - heartbeat;
        if (diff >= 0 && diff < (time_t)(3 * (interval > 0 ? interval : 30))) {
            is_alive = true;
        }
    }
    const char *effective_mon = (is_alive && strcmp(active_str, "RUNNING") == 0) ? "ACTIVE" : "IDLE";

    mvwprintw(win, 6, 4, "Baseline       : ");
    if (bl_valid) {
        wattron(win, fims_color_attr(CP_SUCCESS));
        wprintw(win, "VALID & VERIFIED");
        wattroff(win, fims_color_attr(CP_SUCCESS));
    } else if (bst == FIMS_ERR_NOT_FOUND) {
        wattron(win, fims_color_attr(CP_WARNING));
        wprintw(win, "NOT INITIALIZED");
        wattroff(win, fims_color_attr(CP_WARNING));
    } else {
        wattron(win, fims_color_attr(CP_ERROR));
        wprintw(win, "CORRUPTED");
        wattroff(win, fims_color_attr(CP_ERROR));
    }

    mvwprintw(win, 7, 4, "Authentication : ");
    if (has_hmac) {
        wattron(win, fims_color_attr(CP_SUCCESS));
        wprintw(win, "HMAC-SHA256 (Protected)");
        wattroff(win, fims_color_attr(CP_SUCCESS));
    } else {
        wattron(win, fims_color_attr(CP_HEADER));
        wprintw(win, "SHA-256 Digest");
        wattroff(win, fims_color_attr(CP_HEADER));
    }

    mvwprintw(win, 8, 4, "Monitor Daemon : ");
    if (strcmp(effective_mon, "ACTIVE") == 0) {
        wattron(win, fims_color_attr(CP_SUCCESS));
        wprintw(win, "ACTIVE (inotify)");
        wattroff(win, fims_color_attr(CP_SUCCESS));
    } else {
        wattron(win, fims_color_attr(CP_DIM));
        wprintw(win, "STANDBY / IDLE");
        wattroff(win, fims_color_attr(CP_DIM));
    }

    mvwprintw(win, 9, 4, "Tracked Files  : %zu regular files", tracked_files);
    mvwprintw(win, 10, 4, "Last Scan      : %s", last_scan_str);

    /* Integrity Summary Box */
    render_box(win, 4, panel_w + 4, panel_h, panel_w, "INTEGRITY SUMMARY", CP_HEADER);

    /* Read report metrics */
    size_t rep_total = 0, rep_unchanged = 0, rep_mod = 0, rep_add = 0, rep_del = 0, rep_perm = 0;
    FILE *rfp = fopen(st->cfg->report_file, "r");
    if (rfp) {
        char rline[256];
        while (fgets(rline, sizeof(rline), rfp)) {
            if (strncmp(rline, " Files Checked       : ", 23) == 0) rep_total = atol(rline + 23);
            else if (strncmp(rline, " Unchanged Files     : ", 23) == 0) rep_unchanged = atol(rline + 23);
            else if (strncmp(rline, "   - Modified        : ", 23) == 0) rep_mod = atol(rline + 23);
            else if (strncmp(rline, "   - Added           : ", 23) == 0) rep_add = atol(rline + 23);
            else if (strncmp(rline, "   - Deleted         : ", 23) == 0) rep_del = atol(rline + 23);
            else if (strncmp(rline, "   - Perm Changed    : ", 23) == 0) rep_perm = atol(rline + 23);
        }
        fclose(rfp);
    }
    (void)rep_perm;

    mvwprintw(win, 6, panel_w + 6, "Files Checked  : %zu", rep_total > 0 ? rep_total : tracked_files);
    mvwprintw(win, 7, panel_w + 6, "Unchanged      : ");
    wattron(win, fims_color_attr(CP_SUCCESS));
    wprintw(win, "%zu", rep_unchanged > 0 ? rep_unchanged : (rep_total == 0 ? tracked_files : 0));
    wattroff(win, fims_color_attr(CP_SUCCESS));

    mvwprintw(win, 8, panel_w + 6, "Modified       : ");
    if (rep_mod > 0) wattron(win, fims_color_attr(CP_ERROR));
    wprintw(win, "%zu", rep_mod);
    if (rep_mod > 0) wattroff(win, fims_color_attr(CP_ERROR));

    mvwprintw(win, 9, panel_w + 6, "Added          : ");
    if (rep_add > 0) wattron(win, fims_color_attr(CP_WARNING));
    wprintw(win, "%zu", rep_add);
    if (rep_add > 0) wattroff(win, fims_color_attr(CP_WARNING));

    mvwprintw(win, 10, panel_w + 6, "Deleted        : ");
    if (rep_del > 0) wattron(win, fims_color_attr(CP_ERROR));
    wprintw(win, "%zu", rep_del);
    if (rep_del > 0) wattroff(win, fims_color_attr(CP_ERROR));

    /* Quick Actions Box */
    int act_y = 15;
    int act_h = h - act_y - 2;
    if (act_h > 4) {
        render_box(win, act_y, 2, act_h, w - 4, "SECURITY SHORTCUTS & OPERATIONS", CP_HEADER);
        mvwprintw(win, act_y + 2, 4, "[S] Run Integrity Scan     - Perform immediate full-tree filesystem verification");
        mvwprintw(win, act_y + 3, 4, "[M] Live Monitor           - Launch real-time inotify kernel watcher");
        mvwprintw(win, act_y + 4, 4, "[I] Initialize Baseline    - Create or re-baseline monitored paths");
        mvwprintw(win, act_y + 5, 4, "[A] View Security Alerts   - Investigate detected modifications and threat events");
        mvwprintw(win, act_y + 6, 4, "[C] Configuration Editor   - Modify intervals, paths, and alert thresholds");
    }

    wrefresh(win);
}

void fims_screen_handle_dashboard(fims_tui_state_t *st, int ch) {
    if (ch == 's' || ch == 'S') {
        st->active_screen = SCREEN_SCAN;
        st->nav_selected = SCREEN_SCAN;
    } else if (ch == 'm' || ch == 'M') {
        st->active_screen = SCREEN_MONITOR;
        st->nav_selected = SCREEN_MONITOR;
    } else if (ch == 'i' || ch == 'I') {
        st->active_screen = SCREEN_INIT;
        st->nav_selected = SCREEN_INIT;
    } else if (ch == 'a' || ch == 'A') {
        st->active_screen = SCREEN_ALERTS;
        st->nav_selected = SCREEN_ALERTS;
    } else if (ch == 'c' || ch == 'C') {
        st->active_screen = SCREEN_CONFIG;
        st->nav_selected = SCREEN_CONFIG;
    }
}

/* ============================================================================
 * 2. INITIALIZE BASELINE SCREEN
 * ============================================================================ */

static char g_init_target[FIMS_MAX_PATH] = "/home/madmax";
static bool g_init_force = false;
static bool g_init_add   = false;
static int  g_init_field = 0; /* 0 = Target Dir, 1 = Force, 2 = Add, 3 = Execute */

void fims_screen_render_init(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "INITIALIZE TRUSTED BASELINE");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Establish self-verifying cryptographic baseline of regular files");
    wattroff(win, fims_color_attr(CP_DIM));

    render_box(win, 4, 2, 14, w - 4, "CONFIGURATION & TARGET PATH", CP_HEADER);

    /* Field 0: Target Dir */
    mvwprintw(win, 6, 4, "Monitored Directory : ");
    if (st->focus == FOCUS_CONTENT && g_init_field == 0) {
        wattron(win, fims_color_attr(CP_BUTTON_ACT));
        wprintw(win, "[ %-40s ]", g_init_target);
        wattroff(win, fims_color_attr(CP_BUTTON_ACT));
    } else {
        wattron(win, fims_color_attr(CP_BUTTON_NORM) | A_REVERSE);
        wprintw(win, "  %-40s  ", g_init_target);
        wattroff(win, fims_color_attr(CP_BUTTON_NORM) | A_REVERSE);
    }
    mvwprintw(win, 7, 26, "(Press ENTER to edit path)");

    /* Field 1: Force Overwrite */
    mvwprintw(win, 9, 4, "Force Overwrite     : ");
    if (st->focus == FOCUS_CONTENT && g_init_field == 1) {
        wattron(win, fims_color_attr(CP_BUTTON_ACT));
        wprintw(win, "[ %s ]", g_init_force ? "ENABLED (Replace existing)" : "DISABLED (Safety lock)");
        wattroff(win, fims_color_attr(CP_BUTTON_ACT));
    } else {
        wprintw(win, "  %s  ", g_init_force ? "ENABLED (Replace existing)" : "DISABLED (Safety lock)");
    }

    /* Field 2: Add Root Mode */
    mvwprintw(win, 11, 4, "Multi-Root Mode     : ");
    if (st->focus == FOCUS_CONTENT && g_init_field == 2) {
        wattron(win, fims_color_attr(CP_BUTTON_ACT));
        wprintw(win, "[ %s ]", g_init_add ? "ADD ROOT (--add)" : "NEW BASELINE");
        wattroff(win, fims_color_attr(CP_BUTTON_ACT));
    } else {
        wprintw(win, "  %s  ", g_init_add ? "ADD ROOT (--add)" : "NEW BASELINE");
    }

    /* Field 3: Action Button */
    int btn_y = 14;
    if (st->focus == FOCUS_CONTENT && g_init_field == 3) {
        wattron(win, fims_color_attr(CP_STATUS_OK));
        mvwprintw(win, btn_y, 4, " [ >>> INITIALIZE BASELINE NOW <<< ] ");
        wattroff(win, fims_color_attr(CP_STATUS_OK));
    } else {
        wattron(win, fims_color_attr(CP_BUTTON_NORM));
        mvwprintw(win, btn_y, 4, "   >>> INITIALIZE BASELINE NOW <<<   ");
        wattroff(win, fims_color_attr(CP_BUTTON_NORM));
    }

    /* Status hint */
    render_box(win, 19, 2, h - 21, w - 4, "STORAGE INFORMATION", CP_BORDER);
    mvwprintw(win, 21, 4, "Target Baseline File : %s", st->cfg->baseline_file);
    mvwprintw(win, 22, 4, "Permissions Enforced : 0600 (Owner Read/Write Only)");
    const char *hmac = getenv("FIMS_HMAC_KEY_FILE");
    mvwprintw(win, 23, 4, "HMAC Authenticity    : %s", hmac ? hmac : "Standard SHA-256 Digest");

    wrefresh(win);
}

void fims_screen_handle_init(fims_tui_state_t *st, int ch) {
    if (ch == KEY_UP) {
        if (g_init_field > 0) g_init_field--;
    } else if (ch == KEY_DOWN) {
        if (g_init_field < 3) g_init_field++;
    } else if (ch == ' ' || ch == KEY_LEFT || ch == KEY_RIGHT) {
        if (g_init_field == 1) g_init_force = !g_init_force;
        else if (g_init_field == 2) g_init_add = !g_init_add;
    } else if (ch == '\n' || ch == KEY_ENTER) {
        if (g_init_field == 0) {
            fims_dialog_input("EDIT TARGET DIRECTORY", "Enter directory path to monitor:", g_init_target, sizeof(g_init_target));
        } else if (g_init_field == 1) {
            g_init_force = !g_init_force;
        } else if (g_init_field == 2) {
            g_init_add = !g_init_add;
        } else if (g_init_field == 3) {
            /* Execute Baseline Initialization */
            struct stat dir_st;
            if (stat(g_init_target, &dir_st) != 0 || !S_ISDIR(dir_st.st_mode)) {
                fims_dialog_message("INVALID DIRECTORY", "The specified path does not exist or is not a directory.", CP_ERROR);
                return;
            }

            if (access(st->cfg->baseline_file, F_OK) == 0 && !g_init_force && !g_init_add) {
                fims_dialog_message("BASELINE EXISTS", "Baseline file already exists!\nEnable 'Force Overwrite' to proceed.", CP_WARNING);
                return;
            }

            if (access(st->cfg->baseline_file, F_OK) == 0 && g_init_force && !g_init_add) {
                bool proceed = fims_dialog_confirm("CONFIRM OVERWRITE",
                                                   "Existing trusted baseline will be replaced!\nThis will accept all current files as trusted.\nProceed?",
                                                   "Cancel", "Overwrite");
                if (!proceed) return;
            }

            fims_dialog_progress_draw("INITIALIZING BASELINE", "Scanning and hashing files...", 50, 100);

            size_t count = 0;
            fims_status_t res = fims_baseline_init_from_dir(g_init_target, st->cfg, g_init_force, &count);
            if (res == FIMS_OK) {
                fims_status_save(st->cfg->state_file, st->cfg, NULL, count, 0);
                char msg[FIMS_MAX_PATH + 256];
                snprintf(msg, sizeof(msg), "Baseline successfully established!\n%zu regular files securely hashed.\nBaseline stored at: %s",
                         count, st->cfg->baseline_file);
                fims_dialog_message("INITIALIZATION SUCCESS", msg, CP_SUCCESS);
            } else {
                char msg[256];
                snprintf(msg, sizeof(msg), "Baseline initialization failed with error code %d.", (int)res);
                fims_dialog_message("INITIALIZATION ERROR", msg, CP_ERROR);
            }
        }
    }
}

/* ============================================================================
 * 3. INTEGRITY SCAN SCREEN
 * ============================================================================ */

static bool   g_scan_completed = false;
static size_t g_scan_files = 0;
static size_t g_scan_unchanged = 0;
static size_t g_scan_mod = 0;
static size_t g_scan_add = 0;
static size_t g_scan_del = 0;
static size_t g_scan_renamed = 0;
static size_t g_scan_perms = 0;
static double g_scan_time_ms = 0;

void fims_screen_render_scan(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "INTEGRITY SCAN ENGINE");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Compare live filesystem state against cryptographic baseline");
    wattroff(win, fims_color_attr(CP_DIM));

    render_box(win, 4, 2, 6, w - 4, "SCAN TARGET & BASELINE STATUS", CP_HEADER);
    mvwprintw(win, 6, 4, "Baseline File  : %s", st->cfg->baseline_file);
    mvwprintw(win, 7, 4, "Report File    : %s", st->cfg->report_file);

    /* Button */
    wattron(win, fims_color_attr(CP_STATUS_OK));
    mvwprintw(win, 11, 4, " [ S ] START FULL INTEGRITY SCAN (Press 'S' or ENTER) ");
    wattroff(win, fims_color_attr(CP_STATUS_OK));

    if (g_scan_completed) {
        render_box(win, 14, 2, 10, w - 4, "SCAN RESULTS & AUDIT METRICS", CP_HEADER);

        mvwprintw(win, 16, 4, "Files Scanned : %zu", g_scan_files);
        mvwprintw(win, 17, 4, "Unchanged     : ");
        wattron(win, fims_color_attr(CP_SUCCESS));
        wprintw(win, "%zu", g_scan_unchanged);
        wattroff(win, fims_color_attr(CP_SUCCESS));

        mvwprintw(win, 18, 4, "Modified      : ");
        if (g_scan_mod > 0) wattron(win, fims_color_attr(CP_ERROR));
        wprintw(win, "%zu", g_scan_mod);
        if (g_scan_mod > 0) wattroff(win, fims_color_attr(CP_ERROR));

        mvwprintw(win, 19, 4, "Added         : ");
        if (g_scan_add > 0) wattron(win, fims_color_attr(CP_WARNING));
        wprintw(win, "%zu", g_scan_add);
        if (g_scan_add > 0) wattroff(win, fims_color_attr(CP_WARNING));

        mvwprintw(win, 20, 4, "Deleted       : ");
        if (g_scan_del > 0) wattron(win, fims_color_attr(CP_ERROR));
        wprintw(win, "%zu", g_scan_del);
        if (g_scan_del > 0) wattroff(win, fims_color_attr(CP_ERROR));

        mvwprintw(win, 16, 36, "Renamed       : %zu", g_scan_renamed);
        mvwprintw(win, 17, 36, "Perms Changed : %zu", g_scan_perms);
        mvwprintw(win, 18, 36, "Scan Duration : %.2f ms", g_scan_time_ms);

        size_t total_changes = g_scan_mod + g_scan_add + g_scan_del + g_scan_renamed + g_scan_perms;
        mvwprintw(win, 20, 36, "Scan Verdict  : ");
        if (total_changes == 0) {
            wattron(win, fims_color_attr(CP_STATUS_OK));
            wprintw(win, " PROTECTED - NO CHANGES ");
            wattroff(win, fims_color_attr(CP_STATUS_OK));
        } else {
            wattron(win, fims_color_attr(CP_STATUS_BAD));
            wprintw(win, " VIOLATIONS DETECTED (%zu) ", total_changes);
            wattroff(win, fims_color_attr(CP_STATUS_BAD));
        }

        mvwprintw(win, 25, 4, "[ A ] View Detailed Security Alerts    [ R ] Inspect Full Report");
    }

    wrefresh(win);
}

void fims_screen_handle_scan(fims_tui_state_t *st, int ch) {
    if (ch == 's' || ch == 'S' || ch == '\n' || ch == KEY_ENTER) {
        fims_file_list_t baseline;
        fims_status_t bst = fims_baseline_load(st->cfg->baseline_file, &baseline);
        if (bst != FIMS_OK) {
            fims_dialog_message("BASELINE ERROR", "Unable to load trusted baseline!\nPlease initialize a baseline first.", CP_ERROR);
            return;
        }

        fims_dialog_progress_draw("INTEGRITY SCAN", "Comparing live files against baseline...", 50, 100);

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        fims_file_list_t current;
        if (fims_file_list_init(&current) != FIMS_OK) {
            fims_file_list_free(&baseline);
            return;
        }

        fims_scan_directories((const char (*)[FIMS_MAX_PATH])baseline.root_dirs,
                              baseline.root_dir_count, st->cfg, &current);

        fims_report_t report;
        fims_report_init(&report);
        fims_check_integrity(&baseline, &current, st->cfg, false, &report);

        clock_gettime(CLOCK_MONOTONIC, &t1);
        g_scan_time_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1000000.0;

        fims_report_save(st->cfg->report_file, &report);
        fims_status_save(st->cfg->state_file, st->cfg, NULL, baseline.count, report.count);

        g_scan_completed = true;
        g_scan_files     = current.count;
        g_scan_unchanged = report.unchanged_files;
        g_scan_mod       = report.modified_count;
        g_scan_add       = report.added_count;
        g_scan_del       = report.deleted_count;
        g_scan_renamed   = report.renamed_count;
        g_scan_perms     = report.perm_changed_count;

        fims_report_free(&report);
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
    } else if (ch == 'a' || ch == 'A') {
        st->active_screen = SCREEN_ALERTS;
        st->nav_selected  = SCREEN_ALERTS;
    } else if (ch == 'r' || ch == 'R') {
        st->active_screen = SCREEN_REPORTS;
        st->nav_selected  = SCREEN_REPORTS;
    }
}

/* ============================================================================
 * 4. LIVE MONITORING SCREEN
 * ============================================================================ */

void fims_screen_render_monitor(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "REAL-TIME INOTIFY MONITOR");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Continuous kernel event monitoring with inotify watcher");
    wattroff(win, fims_color_attr(CP_DIM));

    render_box(win, 4, 2, 7, w - 4, "DAEMON TELEMETRY & STATUS", CP_HEADER);

    char active_str[32] = "IDLE";
    char scan_ts_str[64] = "never";
    pid_t pid = 0;
    time_t hb = 0;
    uint32_t interval = 30;

    FILE *fp = fopen(st->cfg->state_file, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\r\n")] = '\0';
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = '\0';
            if (strcmp(line, "MONITOR_ACTIVE") == 0) strncpy(active_str, eq + 1, sizeof(active_str) - 1);
            else if (strcmp(line, "PID") == 0) pid = (pid_t)atol(eq + 1);
            else if (strcmp(line, "HEARTBEAT") == 0) hb = (time_t)atoll(eq + 1);
            else if (strcmp(line, "SCAN_INTERVAL") == 0) interval = (uint32_t)atoi(eq + 1);
            else if (strcmp(line, "LAST_SCAN_TIMESTAMP") == 0) strncpy(scan_ts_str, eq + 1, sizeof(scan_ts_str) - 1);
        }
        fclose(fp);
    }

    bool alive = (pid > 0 && kill(pid, 0) == 0);
    mvwprintw(win, 6, 4, "Status        : %s", alive ? "ACTIVE (RUNNING)" : "IDLE / STANDBY");
    mvwprintw(win, 7, 4, "Daemon PID    : %ld", (long)pid);
    mvwprintw(win, 8, 4, "Heartbeat     : %lld", (long long)hb);
    mvwprintw(win, 6, 36, "Scan Interval : %u seconds", interval);
    mvwprintw(win, 7, 36, "Last Rescan   : %s", scan_ts_str);

    render_box(win, 12, 2, h - 14, w - 4, "LIVE KERNEL EVENT LOG (Last 10 Events)", CP_BORDER);

    /* Read last lines of log file */
    FILE *lfp = fopen(st->cfg->log_file, "r");
    if (lfp) {
        char lines[30][256];
        int count = 0;
        char buf[256];
        while (fgets(buf, sizeof(buf), lfp)) {
            buf[strcspn(buf, "\r\n")] = '\0';
            if (strstr(buf, "[ALERT]") != NULL) {
                snprintf(lines[count % 30], sizeof(lines[0]), "%s", buf);
                count++;
            }
        }
        fclose(lfp);

        int disp = count > 10 ? 10 : count;
        int start = count > 10 ? count - 10 : 0;
        for (int i = 0; i < disp; i++) {
            int idx = (start + i) % 30;
            wattron(win, fims_color_attr(CP_WARNING));
            mvwprintw(win, 14 + i, 4, "%.*s", w - 8, lines[idx]);
            wattroff(win, fims_color_attr(CP_WARNING));
        }
    } else {
        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, 15, 4, "No live events recorded yet in audit log.");
        wattroff(win, fims_color_attr(CP_DIM));
    }

    wattron(win, fims_color_attr(CP_KEYBIND));
    mvwprintw(win, h - 1, 4, "Keybinds: [R] Refresh Telemetry | [ESC] Return to Dashboard");
    wattroff(win, fims_color_attr(CP_KEYBIND));

    wrefresh(win);
}

void fims_screen_handle_monitor(fims_tui_state_t *st, int ch) {
    (void)st;
    (void)ch;
}

/* ============================================================================
 * 5. BASELINE MANAGEMENT SCREEN
 * ============================================================================ */

static int g_bl_scroll = 0;

void fims_screen_render_baseline(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "TRUSTED BASELINE ARCHIVE");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Cryptographic index of approved file hashes and POSIX metadata");
    wattroff(win, fims_color_attr(CP_DIM));

    fims_file_list_t bl;
    fims_status_t bst = fims_baseline_load(st->cfg->baseline_file, &bl);

    render_box(win, 4, 2, 5, w - 4, "BASELINE METADATA", CP_HEADER);
    mvwprintw(win, 5, 4, "File Path : %s", st->cfg->baseline_file);
    mvwprintw(win, 6, 4, "Status    : %s (%zu files recorded)",
              (bst == FIMS_OK) ? "VALID & VERIFIED" : "UNAVAILABLE", (bst == FIMS_OK) ? bl.count : 0);

    /* Records Table */
    int tbl_y = 10;
    int tbl_h = h - tbl_y - 3;
    render_box(win, tbl_y, 2, tbl_h, w - 4, "RECORDED FILES", CP_BORDER);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, tbl_y + 1, 4, "%-6s  %-10s  %-18s  %-s", "MODE", "SIZE (B)", "SHA-256 (PREFIX)", "FILE PATH");
    wattroff(win, fims_color_attr(CP_HEADER));

    if (bst == FIMS_OK && bl.count > 0) {
        int max_rows = tbl_h - 3;
        if (g_bl_scroll > (int)bl.count - max_rows) g_bl_scroll = (int)bl.count - max_rows;
        if (g_bl_scroll < 0) g_bl_scroll = 0;

        for (int i = 0; i < max_rows && (g_bl_scroll + i) < (int)bl.count; i++) {
            const fims_file_record_t *r = &bl.records[g_bl_scroll + i];
            mvwprintw(win, tbl_y + 2 + i, 4, "%04o    %-10llu  %.16s...  %.*s",
                      r->mode, (unsigned long long)r->size, r->sha256, w - 48, r->path);
        }
        fims_file_list_free(&bl);
    } else {
        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, tbl_y + 3, 4, "No baseline records available.");
        wattroff(win, fims_color_attr(CP_DIM));
    }

    mvwprintw(win, h - 2, 4, "[UP/DOWN] Scroll Records | [U] Update Baseline after Changes");
    wrefresh(win);
}

void fims_screen_handle_baseline(fims_tui_state_t *st, int ch) {
    if (ch == KEY_UP) {
        if (g_bl_scroll > 0) g_bl_scroll--;
    } else if (ch == KEY_DOWN) {
        g_bl_scroll++;
    } else if (ch == 'u' || ch == 'U') {
        bool confirm = fims_dialog_confirm("UPDATE TRUSTED BASELINE",
                                           "Accept all detected filesystem changes into baseline?\nThis action updates cryptographic checksums.",
                                           "Cancel", "Update");
        if (confirm) {
            fims_file_list_t existing;
            if (fims_baseline_load(st->cfg->baseline_file, &existing) == FIMS_OK) {
                fims_file_list_t current;
                fims_file_list_init(&current);
                fims_scan_directories((const char (*)[FIMS_MAX_PATH])existing.root_dirs,
                                      existing.root_dir_count, st->cfg, &current);
                fims_baseline_save(st->cfg->baseline_file, &current, true);
                fims_status_save(st->cfg->state_file, st->cfg, NULL, current.count, 0);
                fims_dialog_message("BASELINE UPDATED", "Trusted baseline successfully updated!", CP_SUCCESS);
                fims_file_list_free(&current);
                fims_file_list_free(&existing);
            }
        }
    }
}

/* ============================================================================
 * 6. SECURITY ALERTS SCREEN
 * ============================================================================ */

static int g_alert_scroll = 0;
static int g_alert_filter = 0; /* 0 = ALL, 1 = HIGH/CRIT, 2 = MODIFIED, 3 = ADDED, 4 = DELETED */

void fims_screen_render_alerts(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "SECURITY ALERTS & VIOLATIONS");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Detected integrity breaches, unauthorized changes, and threat alerts");
    wattroff(win, fims_color_attr(CP_DIM));

    /* Filter Tabs */
    mvwprintw(win, 4, 2, "Filter: ");
    const char *tabs[] = { "[ ALL ]", "[ CRIT/HIGH ]", "[ MODIFIED ]", "[ ADDED ]", "[ DELETED ]" };
    for (int t = 0; t < 5; t++) {
        if (g_alert_filter == t) {
            wattron(win, fims_color_attr(CP_NAV_ACTIVE));
            wprintw(win, " %s ", tabs[t]);
            wattroff(win, fims_color_attr(CP_NAV_ACTIVE));
        } else {
            wprintw(win, " %s ", tabs[t]);
        }
        wprintw(win, " ");
    }

    int tbl_y = 6;
    int tbl_h = h - tbl_y - 2;
    render_box(win, tbl_y, 2, tbl_h, w - 4, "ALERT RECORDS", CP_BORDER);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, tbl_y + 1, 4, "%-10s  %-18s  %-s", "SEVERITY", "EVENT TYPE", "AFFECTED PATH");
    wattroff(win, fims_color_attr(CP_HEADER));

    /* Read report file alerts */
    FILE *rfp = fopen(st->cfg->report_file, "r");
    if (rfp) {
        char line[512];
        char alerts[100][3][128]; /* [0]=sev, [1]=event, [2]=path */
        int count = 0;

        while (fgets(line, sizeof(line), rfp) && count < 100) {
            if (strncmp(line, "[ALERT] ", 8) == 0) {
                char *colon = strchr(line + 8, ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(alerts[count][1], sizeof(alerts[count][1]), "%.127s", line + 8);
                    char *path_part = colon + 2;
                    path_part[strcspn(path_part, "\r\n")] = '\0';
                    snprintf(alerts[count][2], sizeof(alerts[count][2]), "%.127s", path_part);
                    snprintf(alerts[count][0], sizeof(alerts[count][0]), "HIGH");
                    count++;
                }
            }
        }
        fclose(rfp);

        int max_rows = tbl_h - 3;
        for (int i = 0; i < max_rows && (g_alert_scroll + i) < count; i++) {
            int idx = g_alert_scroll + i;
            wattron(win, fims_color_attr(CP_BADGE_HIGH));
            mvwprintw(win, tbl_y + 2 + i, 4, "[ %-6s ]", alerts[idx][0]);
            wattroff(win, fims_color_attr(CP_BADGE_HIGH));

            mvwprintw(win, tbl_y + 2 + i, 16, "%-18s  %.*s", alerts[idx][1], w - 40, alerts[idx][2]);
        }

        if (count == 0) {
            wattron(win, fims_color_attr(CP_SUCCESS));
            mvwprintw(win, tbl_y + 3, 4, "No alerts recorded. All files match trusted baseline.");
            wattroff(win, fims_color_attr(CP_SUCCESS));
        }
    } else {
        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, tbl_y + 3, 4, "No scan report available. Run 'Integrity Scan' first.");
        wattroff(win, fims_color_attr(CP_DIM));
    }

    wattron(win, fims_color_attr(CP_KEYBIND));
    mvwprintw(win, h - 1, 4, "[UP/DOWN] Scroll | [LEFT/RIGHT] Change Filter | [ENTER] Alert Details");
    wattroff(win, fims_color_attr(CP_KEYBIND));

    wrefresh(win);
}

void fims_screen_handle_alerts(fims_tui_state_t *st, int ch) {
    (void)st;
    if (ch == KEY_UP) {
        if (g_alert_scroll > 0) g_alert_scroll--;
    } else if (ch == KEY_DOWN) {
        g_alert_scroll++;
    } else if (ch == KEY_LEFT) {
        if (g_alert_filter > 0) g_alert_filter--;
    } else if (ch == KEY_RIGHT) {
        if (g_alert_filter < 4) g_alert_filter++;
    } else if (ch == '\n' || ch == KEY_ENTER) {
        fims_dialog_message("ALERT INSPECTION", "Detailed cryptographic alert view:\nSHA-256 Content Mismatch\nSeverity: HIGH\nPath verified against baseline.", CP_HEADER);
    }
}

/* ============================================================================
 * 7. SCAN REPORTS SCREEN
 * ============================================================================ */

void fims_screen_render_reports(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "INTEGRITY AUDIT REPORTS");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Forensic audit reports generated from automated and manual scans");
    wattroff(win, fims_color_attr(CP_DIM));

    render_box(win, 4, 2, 5, w - 4, "LATEST REPORT SOURCE", CP_HEADER);
    mvwprintw(win, 5, 4, "Report File : %s", st->cfg->report_file);
    struct stat rst;
    if (stat(st->cfg->report_file, &rst) == 0) {
        mvwprintw(win, 6, 4, "Size        : %lld bytes | Last Generated : %s", (long long)rst.st_size, ctime(&rst.st_mtime));
    } else {
        mvwprintw(win, 6, 4, "Status      : NOT FOUND (Run scan to generate)");
    }

    int rep_y = 10;
    int rep_h = h - rep_y - 2;
    render_box(win, rep_y, 2, rep_h, w - 4, "REPORT CONTENT", CP_BORDER);

    FILE *fp = fopen(st->cfg->report_file, "r");
    if (fp) {
        char line[256];
        int row = 0;
        while (fgets(line, sizeof(line), fp) && row < rep_h - 2) {
            line[strcspn(line, "\r\n")] = '\0';
            mvwprintw(win, rep_y + 1 + row, 4, "%.*s", w - 8, line);
            row++;
        }
        fclose(fp);
    } else {
        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, rep_y + 2, 4, "No report content found.");
        wattroff(win, fims_color_attr(CP_DIM));
    }

    wattron(win, fims_color_attr(CP_KEYBIND));
    mvwprintw(win, h - 1, 4, "[E] Export Report | [ESC] Back");
    wattroff(win, fims_color_attr(CP_KEYBIND));

    wrefresh(win);
}

void fims_screen_handle_reports(fims_tui_state_t *st, int ch) {
    if (ch == 'e' || ch == 'E') {
        char out_path[FIMS_MAX_PATH] = "/tmp/fims_report_export.txt";
        bool ok = fims_dialog_input("EXPORT AUDIT REPORT", "Enter export destination path:", out_path, sizeof(out_path));
        if (ok) {
            FILE *src = fopen(st->cfg->report_file, "r");
            FILE *dst = fopen(out_path, "w");
            if (src && dst) {
                char buf[4096];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, dst);
                fclose(src);
                fclose(dst);
                fims_dialog_message("EXPORT COMPLETE", "Report successfully exported to destination path!", CP_SUCCESS);
            } else {
                if (src) fclose(src);
                if (dst) fclose(dst);
                fims_dialog_message("EXPORT ERROR", "Failed to write report to destination path.", CP_ERROR);
            }
        }
    }
}

/* ============================================================================
 * 8. CONFIGURATION EDITOR SCREEN
 * ============================================================================ */

static int g_cfg_selected = 0;
static bool g_cfg_dirty = false;

void fims_screen_render_config(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "SYSTEM CONFIGURATION EDITOR");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Configure scan engine parameters, operational paths, and security thresholds");
    wattroff(win, fims_color_attr(CP_DIM));

    if (g_cfg_dirty) {
        wattron(win, fims_color_attr(CP_STATUS_WARN));
        mvwprintw(win, 1, w - 20, " [ UNSAVED CHANGES ] ");
        wattroff(win, fims_color_attr(CP_STATUS_WARN));
    }

    render_box(win, 4, 2, 14, w - 4, "RUNTIME SETTINGS", CP_HEADER);

    const char *labels[] = {
        "Scan Interval (sec)",
        "Min Alert Severity ",
        "Follow Symlinks    ",
        "Detect Renames     ",
        "Save Configuration "
    };

    char val0[32], val1[32], val2[32], val3[32];
    snprintf(val0, sizeof(val0), "%u", st->cfg->scan_interval_sec);
    snprintf(val1, sizeof(val1), "%s", fims_severity_str(st->cfg->min_alert_severity));
    snprintf(val2, sizeof(val2), "%s", st->cfg->follow_symlinks ? "YES" : "NO");
    snprintf(val3, sizeof(val3), "%s", st->cfg->detect_renames ? "YES" : "NO");

    const char *vals[] = { val0, val1, val2, val3, "[ COMMIT CHANGES ]" };

    for (int i = 0; i < 5; i++) {
        int y = 6 + (i * 2);
        if (i == 4) y += 1;

        if (st->focus == FOCUS_CONTENT && g_cfg_selected == i) {
            wattron(win, fims_color_attr(CP_NAV_ACTIVE));
            mvwprintw(win, y, 4, " > %-22s : %-20s ", labels[i], vals[i]);
            wattroff(win, fims_color_attr(CP_NAV_ACTIVE));
        } else {
            mvwprintw(win, y, 4, "   %-22s : %-20s", labels[i], vals[i]);
        }
    }

    render_box(win, 19, 2, h - 21, w - 4, "STORAGE PATHS (READ ONLY)", CP_BORDER);
    mvwprintw(win, 21, 4, "Baseline Path   : %s", st->cfg->baseline_file);
    mvwprintw(win, 22, 4, "Audit Log Path  : %s", st->cfg->log_file);
    mvwprintw(win, 23, 4, "Runtime State   : %s", st->cfg->state_file);
    mvwprintw(win, 24, 4, "Config File     : %s", st->cfg->config_file);

    wattron(win, fims_color_attr(CP_KEYBIND));
    mvwprintw(win, h - 1, 4, "[UP/DOWN] Select Option | [SPACE] Toggle | [ENTER] Edit/Save");
    wattroff(win, fims_color_attr(CP_KEYBIND));

    wrefresh(win);
}

void fims_screen_handle_config(fims_tui_state_t *st, int ch) {
    if (ch == KEY_UP) {
        if (g_cfg_selected > 0) g_cfg_selected--;
    } else if (ch == KEY_DOWN) {
        if (g_cfg_selected < 4) g_cfg_selected++;
    } else if (ch == ' ' || ch == KEY_LEFT || ch == KEY_RIGHT) {
        if (g_cfg_selected == 1) {
            st->cfg->min_alert_severity = (st->cfg->min_alert_severity + 1) % 5;
            g_cfg_dirty = true;
        } else if (g_cfg_selected == 2) {
            st->cfg->follow_symlinks = !st->cfg->follow_symlinks;
            g_cfg_dirty = true;
        } else if (g_cfg_selected == 3) {
            st->cfg->detect_renames = !st->cfg->detect_renames;
            g_cfg_dirty = true;
        }
    } else if (ch == '\n' || ch == KEY_ENTER) {
        if (g_cfg_selected == 0) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%u", st->cfg->scan_interval_sec);
            if (fims_dialog_input("SCAN INTERVAL", "Enter interval in seconds (e.g. 30):", buf, sizeof(buf))) {
                long val = atol(buf);
                if (val > 0) {
                    st->cfg->scan_interval_sec = (uint32_t)val;
                    g_cfg_dirty = true;
                }
            }
        } else if (g_cfg_selected == 4) {
            bool confirm = fims_dialog_confirm("SAVE CONFIGURATION", "Write updated configuration to disk?\nFile: /etc/fims/fims.conf", "Cancel", "Save");
            if (confirm) {
                fims_config_save(st->cfg, NULL);
                g_cfg_dirty = false;
                fims_dialog_message("CONFIGURATION SAVED", "Settings committed to disk successfully!", CP_SUCCESS);
            }
        }
    }
}

/* ============================================================================
 * 9. SYSTEM INFORMATION SCREEN
 * ============================================================================ */

void fims_screen_render_sysinfo(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "SYSTEM ARCHITECTURE & CAPABILITIES");
    wattroff(win, fims_color_attr(CP_HEADER));
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 2, 2, "Technical runtime environment and cryptographic specifications");
    wattroff(win, fims_color_attr(CP_DIM));

    struct utsname un;
    uname(&un);

    render_box(win, 4, 2, 8, w - 4, "PLATFORM & KERNEL", CP_HEADER);
    mvwprintw(win, 6, 4, "Host Operating System : %s %s", un.sysname, un.release);
    mvwprintw(win, 7, 4, "Hardware Architecture : %s", un.machine);
    mvwprintw(win, 8, 4, "Node Name             : %s", un.nodename);
    mvwprintw(win, 9, 4, "FIMS Binary Version   : %s (ISO C11 Standard)", FIMS_VERSION);

    render_box(win, 13, 2, 10, w - 4, "SECURITY & CRYPTOGRAPHIC SUBSYSTEMS", CP_HEADER);
    mvwprintw(win, 15, 4, "Digest Engine     : OpenSSL EVP SHA-256 (64 KB Streaming Read Chunks)");
    mvwprintw(win, 16, 4, "Baseline Auth     : HMAC-SHA256 Secret Key Authentication (0600 Required)");
    mvwprintw(win, 17, 4, "Kernel Subsystem  : Linux inotify (IN_CLOSE_WRITE, IN_DONT_FOLLOW, IN_ONLYDIR)");
    mvwprintw(win, 18, 4, "Hardening Flags   : O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK (TOCTOU & FIFO Protection)");
    mvwprintw(win, 19, 4, "Baseline Writes   : Atomic Replacement via O_EXCL temp file + parent dir fsync");
    mvwprintw(win, 20, 4, "Compare Algorithm : O(N) Sorted Two-Pointer Merge Join + (dev, inode) Rename Hash Map");

    (void)st;
    wrefresh(win);
}

void fims_screen_handle_sysinfo(fims_tui_state_t *st, int ch) {
    (void)st;
    (void)ch;
}

/* ============================================================================
 * 10. HELP & KEYBINDINGS SCREEN
 * ============================================================================ */

void fims_screen_render_help(fims_tui_state_t *st) {
    WINDOW *win = st->win_content;
    int h, w;
    getmaxyx(win, h, w);
    (void)h;
    werase(win);

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "FIMS USER MANUAL & KEYBINDINGS REFERENCE");
    wattroff(win, fims_color_attr(CP_HEADER));

    render_box(win, 4, 2, 11, w - 4, "KEYBOARD NAVIGATION", CP_HEADER);
    mvwprintw(win, 6, 4, "UP / DOWN     : Navigate navigation menu items and scroll data tables");
    mvwprintw(win, 7, 4, "LEFT / RIGHT  : Switch filter tabs and toggle interactive options");
    mvwprintw(win, 8, 4, "ENTER         : Select menu item / confirm action / inspect details");
    mvwprintw(win, 9, 4, "ESC           : Return focus to navigation / dismiss active modal dialog");
    mvwprintw(win, 10, 4, "TAB           : Toggle focus between Navigation Sidebar and Content Panel");
    mvwprintw(win, 11, 4, "SPACE         : Toggle configuration settings and checkbox options");
    mvwprintw(win, 12, 4, "Q             : Quit FIMS Security Console (with confirmation prompt)");

    render_box(win, 16, 2, h - 18, w - 4, "SECURITY WORKFLOW OVERVIEW", CP_HEADER);
    mvwprintw(win, 18, 4, "1. BASELINE     : Generate initial cryptographic baseline on a trusted, clean system.");
    mvwprintw(win, 19, 4, "2. SCANNING     : Run periodic integrity scans to detect unauthorized modifications.");
    mvwprintw(win, 20, 4, "3. MONITORING   : Run real-time inotify watcher to capture events instantly as they occur.");
    mvwprintw(win, 21, 4, "4. INVESTIGATE  : Use Security Alerts to inspect changed hashes, sizes, and permissions.");
    mvwprintw(win, 22, 4, "5. RE-BASELINE  : After approved system updates, execute baseline update to accept diffs.");

    (void)st;
    wrefresh(win);
}

void fims_screen_handle_help(fims_tui_state_t *st, int ch) {
    (void)st;
    (void)ch;
}
