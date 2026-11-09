#define _GNU_SOURCE
#include "ui_tui.h"
#include "ui_colors.h"
#include "ui_dialogs.h"
#include "config.h"
#include "fims.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

static volatile sig_atomic_t g_need_resize = 0;
static volatile sig_atomic_t g_interrupted = 0;
static bool g_tui_initialized = false;

static void tui_sigwinch_handler(int sig) {
    (void)sig;
    g_need_resize = 1;
}

static void tui_sigint_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
}

static void tui_atexit_cleanup(void) {
    if (g_tui_initialized) {
        endwin();
        g_tui_initialized = false;
    }
}

typedef struct {
    fims_tui_screen_t screen;
    const char       *label;
    char              shortcut;
} nav_entry_t;

static const nav_entry_t NAV_ENTRIES[] = {
    { SCREEN_DASHBOARD, "Dashboard",         'D' },
    { SCREEN_INIT,      "Initialize Base",   'I' },
    { SCREEN_SCAN,      "Integrity Scan",    'S' },
    { SCREEN_MONITOR,   "Live Monitor",      'M' },
    { SCREEN_BASELINE,  "Baseline Records",  'B' },
    { SCREEN_ALERTS,    "Security Alerts",   'A' },
    { SCREEN_REPORTS,   "Scan Reports",      'R' },
    { SCREEN_CONFIG,    "Configuration",     'C' },
    { SCREEN_SYSINFO,   "System Info",       'Y' },
    { SCREEN_HELP,      "Help & Manual",     'H' },
    { SCREEN_EXIT,      "Exit Console",      'Q' }
};
#define NAV_ENTRY_COUNT ((int)(sizeof(NAV_ENTRIES) / sizeof(NAV_ENTRIES[0])))

static void destroy_windows(fims_tui_state_t *st) {
    if (st->win_header)  { delwin(st->win_header);  st->win_header = NULL; }
    if (st->win_nav)     { delwin(st->win_nav);     st->win_nav = NULL; }
    if (st->win_content) { delwin(st->win_content); st->win_content = NULL; }
    if (st->win_footer)  { delwin(st->win_footer);  st->win_footer = NULL; }
}

static bool create_windows(fims_tui_state_t *st) {
    getmaxyx(stdscr, st->term_h, st->term_w);

    if (st->term_h < 15 || st->term_w < 60) {
        werase(stdscr);
        attron(fims_color_attr(CP_ERROR));
        mvprintw(st->term_h / 2, (st->term_w - 44) / 2, "Terminal too small (min 60x15). Please enlarge.");
        attroff(fims_color_attr(CP_ERROR));
        refresh();
        return false;
    }

    int header_h = 3;
    int footer_h = 2;
    int nav_w = (st->term_w >= 100) ? 25 : 22;
    int body_h = st->term_h - header_h - footer_h;
    int content_w = st->term_w - nav_w;

    st->win_header  = newwin(header_h, st->term_w, 0, 0);
    st->win_nav     = newwin(body_h, nav_w, header_h, 0);
    st->win_content = newwin(body_h, content_w, header_h, nav_w);
    st->win_footer  = newwin(footer_h, st->term_w, st->term_h - footer_h, 0);

    if (!st->win_header || !st->win_nav || !st->win_content || !st->win_footer) {
        destroy_windows(st);
        return false;
    }

    keypad(st->win_nav, TRUE);
    keypad(st->win_content, TRUE);

    return true;
}

static void render_header(fims_tui_state_t *st) {
    WINDOW *win = st->win_header;
    if (!win) return;
    werase(win);

    int w = st->term_w;

    /* Top branding title */
    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 1, 2, "FIMS | FILE INTEGRITY MONITORING SYSTEM");
    wattroff(win, fims_color_attr(CP_HEADER));

    wattron(win, fims_color_attr(CP_DIM));
    const char *ver_str = "v" FIMS_VERSION " (Linux Security)";
    int v_len = (int)strlen(ver_str);
    if (w - v_len - 3 > 45) {
        mvwprintw(win, 1, w - v_len - 3, "%s", ver_str);
    }
    wattroff(win, fims_color_attr(CP_DIM));

    /* Divider line */
    wattron(win, fims_color_attr(CP_BORDER));
    for (int x = 0; x < w; x++) {
        mvwaddch(win, 2, x, ACS_HLINE);
    }
    wattroff(win, fims_color_attr(CP_BORDER));

    wrefresh(win);
}

static void render_footer(fims_tui_state_t *st) {
    WINDOW *win = st->win_footer;
    if (!win) return;
    werase(win);

    int w = st->term_w;

    /* Top divider */
    wattron(win, fims_color_attr(CP_BORDER));
    for (int x = 0; x < w; x++) {
        mvwaddch(win, 0, x, ACS_HLINE);
    }
    wattroff(win, fims_color_attr(CP_BORDER));

    /* Key bindings helper */
    wattron(win, fims_color_attr(CP_DIM));
    mvwprintw(win, 1, 2, "UP/DOWN: Nav | ENTER: Select | TAB: Focus | SPACE: Toggle | ESC: Back | Q: Quit");
    wattroff(win, fims_color_attr(CP_DIM));

    /* Focus badge */
    const char *foc_str = (st->focus == FOCUS_NAV) ? "[FOCUS: NAV]" : "[FOCUS: PANEL]";
    int f_len = (int)strlen(foc_str);
    if (w - f_len - 3 > 70) {
        wattron(win, fims_color_attr(st->focus == FOCUS_NAV ? CP_HEADER : CP_SUCCESS));
        mvwprintw(win, 1, w - f_len - 3, "%s", foc_str);
        wattroff(win, fims_color_attr(st->focus == FOCUS_NAV ? CP_HEADER : CP_SUCCESS));
    }

    wrefresh(win);
}

static void render_navigation(fims_tui_state_t *st) {
    WINDOW *win = st->win_nav;
    if (!win) return;
    werase(win);

    int h, w;
    getmaxyx(win, h, w);
    (void)w;

    /* Sidebar Box */
    int border_pair = (st->focus == FOCUS_NAV) ? CP_HEADER : CP_BORDER;
    wattron(win, fims_color_attr(border_pair));
    box(win, 0, 0);
    wattroff(win, fims_color_attr(border_pair));

    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 0, 2, " NAVIGATION ");
    wattroff(win, fims_color_attr(CP_HEADER));

    int start_y = 2;
    for (int i = 0; i < NAV_ENTRY_COUNT && start_y + i < h - 1; i++) {
        int y = start_y + i;
        bool is_selected = (st->nav_selected == i);
        bool is_active   = (st->active_screen == NAV_ENTRIES[i].screen);

        if (is_selected && st->focus == FOCUS_NAV) {
            wattron(win, fims_color_attr(CP_NAV_ACTIVE));
            mvwprintw(win, y, 1, " > %-16s ", NAV_ENTRIES[i].label);
            wattroff(win, fims_color_attr(CP_NAV_ACTIVE));
        } else if (is_selected) {
            wattron(win, fims_color_attr(CP_NAV_NORMAL) | A_REVERSE);
            mvwprintw(win, y, 1, " > %-16s ", NAV_ENTRIES[i].label);
            wattroff(win, fims_color_attr(CP_NAV_NORMAL) | A_REVERSE);
        } else if (is_active) {
            wattron(win, fims_color_attr(CP_SUCCESS));
            mvwprintw(win, y, 1, " * %-16s ", NAV_ENTRIES[i].label);
            wattroff(win, fims_color_attr(CP_SUCCESS));
        } else {
            wattron(win, fims_color_attr(CP_NAV_NORMAL));
            mvwprintw(win, y, 1, "   %-16s ", NAV_ENTRIES[i].label);
            wattroff(win, fims_color_attr(CP_NAV_NORMAL));
        }
    }

    wrefresh(win);
}

static void render_screen(fims_tui_state_t *st) {
    if (!st->win_content) return;
    switch (st->active_screen) {
        case SCREEN_DASHBOARD: fims_screen_render_dashboard(st); break;
        case SCREEN_INIT:      fims_screen_render_init(st); break;
        case SCREEN_SCAN:      fims_screen_render_scan(st); break;
        case SCREEN_MONITOR:   fims_screen_render_monitor(st); break;
        case SCREEN_BASELINE:  fims_screen_render_baseline(st); break;
        case SCREEN_ALERTS:    fims_screen_render_alerts(st); break;
        case SCREEN_REPORTS:   fims_screen_render_reports(st); break;
        case SCREEN_CONFIG:    fims_screen_render_config(st); break;
        case SCREEN_SYSINFO:   fims_screen_render_sysinfo(st); break;
        case SCREEN_HELP:      fims_screen_render_help(st); break;
        default: break;
    }
}

static void handle_screen_key(fims_tui_state_t *st, int ch) {
    switch (st->active_screen) {
        case SCREEN_DASHBOARD: fims_screen_handle_dashboard(st, ch); break;
        case SCREEN_INIT:      fims_screen_handle_init(st, ch); break;
        case SCREEN_SCAN:      fims_screen_handle_scan(st, ch); break;
        case SCREEN_MONITOR:   fims_screen_handle_monitor(st, ch); break;
        case SCREEN_BASELINE:  fims_screen_handle_baseline(st, ch); break;
        case SCREEN_ALERTS:    fims_screen_handle_alerts(st, ch); break;
        case SCREEN_REPORTS:   fims_screen_handle_reports(st, ch); break;
        case SCREEN_CONFIG:    fims_screen_handle_config(st, ch); break;
        case SCREEN_SYSINFO:   fims_screen_handle_sysinfo(st, ch); break;
        case SCREEN_HELP:      fims_screen_handle_help(st, ch); break;
        default: break;
    }
}

static void redraw_all(fims_tui_state_t *st) {
    touchwin(stdscr);
    refresh();
    render_header(st);
    render_navigation(st);
    render_footer(st);
    render_screen(st);
}

int fims_tui_main(fims_config_t *cfg) {
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "Error: FIMS interactive TUI requires a terminal (TTY).\n");
        return 1;
    }

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);

    g_tui_initialized = true;
    atexit(tui_atexit_cleanup);

    struct sigaction sa_winch;
    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = tui_sigwinch_handler;
    sigaction(SIGWINCH, &sa_winch, NULL);

    struct sigaction sa_int;
    memset(&sa_int, 0, sizeof(sa_int));
    sa_int.sa_handler = tui_sigint_handler;
    sigaction(SIGINT, &sa_int, NULL);
    sigaction(SIGTERM, &sa_int, NULL);

    fims_colors_init();

    fims_tui_state_t st;
    memset(&st, 0, sizeof(st));
    st.cfg           = cfg;
    st.active_screen = SCREEN_DASHBOARD;
    st.focus         = FOCUS_NAV;
    st.nav_selected  = 0;
    st.running       = true;

    if (!create_windows(&st)) {
        /* Wait for terminal to be enlarged or key press */
        nodelay(stdscr, FALSE);
        getch();
        destroy_windows(&st);
        endwin();
        g_tui_initialized = false;
        return 1;
    }

    redraw_all(&st);

    while (st.running && !g_interrupted) {
        if (g_need_resize) {
            endwin();
            refresh();
            clear();
            destroy_windows(&st);
            if (create_windows(&st)) {
                redraw_all(&st);
            }
            g_need_resize = 0;
            continue;
        }

        WINDOW *active_win = (st.focus == FOCUS_NAV) ? st.win_nav : st.win_content;
        wtimeout(active_win, 300); /* 300ms polling for live daemon telemetry */
        int ch = wgetch(active_win);

        if (g_interrupted) break;

        if (g_need_resize || ch == KEY_RESIZE) {
            endwin();
            refresh();
            clear();
            destroy_windows(&st);
            if (create_windows(&st)) {
                redraw_all(&st);
            }
            g_need_resize = 0;
            continue;
        }

        if (ch == ERR) {
            /* Timeout: auto-refresh telemetry screens */
            if (st.active_screen == SCREEN_MONITOR || st.active_screen == SCREEN_DASHBOARD) {
                render_screen(&st);
            }
            continue;
        }

        /* TAB: switch focus between navigation panel and content panel */
        if (ch == '\t') {
            st.focus = (st.focus == FOCUS_NAV) ? FOCUS_CONTENT : FOCUS_NAV;
            render_navigation(&st);
            render_footer(&st);
            render_screen(&st);
            continue;
        }

        /* ESC: return focus to navigation sidebar */
        if (ch == 27) {
            if (st.focus == FOCUS_CONTENT) {
                st.focus = FOCUS_NAV;
                render_navigation(&st);
                render_footer(&st);
                render_screen(&st);
                continue;
            }
        }

        /* F1 or '?' opens Help screen */
        if (ch == KEY_F(1) || (st.focus == FOCUS_NAV && ch == '?')) {
            st.active_screen = SCREEN_HELP;
            st.nav_selected  = SCREEN_HELP;
            redraw_all(&st);
            continue;
        }

        /* Q in navigation focus: prompt exit confirmation */
        if (st.focus == FOCUS_NAV && (ch == 'q' || ch == 'Q')) {
            bool confirm = fims_dialog_confirm("EXIT FIMS CONSOLE", "Are you sure you want to exit FIMS Security Console?", "Cancel", "Exit");
            redraw_all(&st);
            if (confirm) {
                st.running = false;
                break;
            }
            continue;
        }

        /* FOCUS: NAVIGATION */
        if (st.focus == FOCUS_NAV) {
            if (ch == KEY_UP) {
                if (st.nav_selected > 0) {
                    st.nav_selected--;
                    render_navigation(&st);
                }
            } else if (ch == KEY_DOWN) {
                if (st.nav_selected < NAV_ENTRY_COUNT - 1) {
                    st.nav_selected++;
                    render_navigation(&st);
                }
            } else if (ch == '\n' || ch == KEY_ENTER) {
                if (NAV_ENTRIES[st.nav_selected].screen == SCREEN_EXIT) {
                    bool confirm = fims_dialog_confirm("EXIT FIMS CONSOLE", "Are you sure you want to exit FIMS Security Console?", "Cancel", "Exit");
                    redraw_all(&st);
                    if (confirm) {
                        st.running = false;
                        break;
                    }
                } else {
                    st.active_screen = NAV_ENTRIES[st.nav_selected].screen;
                    st.focus         = FOCUS_CONTENT;
                    redraw_all(&st);
                }
            } else if (ch == KEY_RIGHT) {
                st.focus = FOCUS_CONTENT;
                redraw_all(&st);
            } else {
                /* Shortcut letter keys */
                char uc = (char)toupper((unsigned char)ch);
                for (int i = 0; i < NAV_ENTRY_COUNT; i++) {
                    if (NAV_ENTRIES[i].shortcut == uc) {
                        st.nav_selected = i;
                        if (NAV_ENTRIES[i].screen == SCREEN_EXIT) {
                            bool confirm = fims_dialog_confirm("EXIT FIMS CONSOLE", "Are you sure you want to exit FIMS Security Console?", "Cancel", "Exit");
                            redraw_all(&st);
                            if (confirm) {
                                st.running = false;
                            }
                        } else {
                            st.active_screen = NAV_ENTRIES[i].screen;
                            st.focus         = FOCUS_CONTENT;
                            redraw_all(&st);
                        }
                        break;
                    }
                }
            }
        }
        /* FOCUS: CONTENT PANEL */
        else {
            if (ch == 'q' || ch == 'Q') {
                /* If screen has internal quit or wants to exit to nav */
                st.focus = FOCUS_NAV;
                render_navigation(&st);
                render_footer(&st);
                render_screen(&st);
            } else {
                handle_screen_key(&st, ch);
                render_screen(&st);
                render_navigation(&st);
                render_footer(&st);
            }
        }
    }

    destroy_windows(&st);
    endwin();
    g_tui_initialized = false;
    return 0;
}
