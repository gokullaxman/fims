#define _GNU_SOURCE
#include "ui_dialogs.h"
#include "ui_colors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

bool fims_dialog_confirm(const char *title, const char *message, const char *btn_cancel, const char *btn_confirm) {
    int w = 54;
    int h = 10;
    int start_y = (LINES - h) / 2;
    int start_x = (COLS - w) / 2;

    if (start_y < 0) start_y = 0;
    if (start_x < 0) start_x = 0;

    WINDOW *win = newwin(h, w, start_y, start_x);
    if (!win) return false;

    keypad(win, TRUE);
    int selected = 0; /* 0 = Cancel, 1 = Confirm */

    const char *lbl_cancel  = btn_cancel ? btn_cancel : "Cancel";
    const char *lbl_confirm = btn_confirm ? btn_confirm : "Confirm";

    while (1) {
        werase(win);
        wattron(win, fims_color_attr(CP_BORDER));
        box(win, 0, 0);
        wattroff(win, fims_color_attr(CP_BORDER));

        /* Title */
        if (title) {
            wattron(win, fims_color_attr(CP_HEADER));
            mvwprintw(win, 0, (w - (int)strlen(title) - 6) / 2, " ◈ %s ◈ ", title);
            wattroff(win, fims_color_attr(CP_HEADER));
        }

        /* Message */
        if (message) {
            wattron(win, fims_color_attr(CP_DEFAULT));
            char msg_copy[512];
            strncpy(msg_copy, message, sizeof(msg_copy) - 1);
            msg_copy[sizeof(msg_copy) - 1] = '\0';

            char *line = strtok(msg_copy, "\n");
            int line_y = 2;
            while (line && line_y < h - 3) {
                mvwprintw(win, line_y++, (w - (int)strlen(line)) / 2, "%s", line);
                line = strtok(NULL, "\n");
            }
            wattroff(win, fims_color_attr(CP_DEFAULT));
        }

        /* Buttons */
        int btn_y = h - 3;
        int btn1_x = (w / 2) - (int)strlen(lbl_cancel) - 5;
        int btn2_x = (w / 2) + 4;

        if (selected == 0) {
            wattron(win, fims_color_attr(CP_BUTTON_ACT));
            mvwprintw(win, btn_y, btn1_x, "[ %s ]", lbl_cancel);
            wattroff(win, fims_color_attr(CP_BUTTON_ACT));

            wattron(win, fims_color_attr(CP_BUTTON_NORM));
            mvwprintw(win, btn_y, btn2_x, "  %s  ", lbl_confirm);
            wattroff(win, fims_color_attr(CP_BUTTON_NORM));
        } else {
            wattron(win, fims_color_attr(CP_BUTTON_NORM));
            mvwprintw(win, btn_y, btn1_x, "  %s  ", lbl_cancel);
            wattroff(win, fims_color_attr(CP_BUTTON_NORM));

            wattron(win, fims_color_attr(CP_BUTTON_ACT));
            mvwprintw(win, btn_y, btn2_x, "[ %s ]", lbl_confirm);
            wattroff(win, fims_color_attr(CP_BUTTON_ACT));
        }

        wrefresh(win);

        int ch = wgetch(win);
        if (ch == KEY_LEFT || ch == KEY_RIGHT || ch == '\t') {
            selected = 1 - selected;
        } else if (ch == '\n' || ch == KEY_ENTER) {
            delwin(win);
            touchwin(stdscr);
            refresh();
            return (selected == 1);
        } else if (ch == 27 || ch == 'q' || ch == 'Q') {
            delwin(win);
            touchwin(stdscr);
            refresh();
            return false;
        }
    }
}

void fims_dialog_message(const char *title, const char *message, int color_pair) {
    int w = 54;
    int h = 9;
    int start_y = (LINES - h) / 2;
    int start_x = (COLS - w) / 2;

    if (start_y < 0) start_y = 0;
    if (start_x < 0) start_x = 0;

    WINDOW *win = newwin(h, w, start_y, start_x);
    if (!win) return;

    keypad(win, TRUE);

    werase(win);
    wattron(win, fims_color_attr(color_pair ? color_pair : CP_BORDER));
    box(win, 0, 0);
    wattroff(win, fims_color_attr(color_pair ? color_pair : CP_BORDER));

    if (title) {
        wattron(win, fims_color_attr(color_pair ? color_pair : CP_HEADER));
        mvwprintw(win, 0, (w - (int)strlen(title) - 6) / 2, " ◈ %s ◈ ", title);
        wattroff(win, fims_color_attr(color_pair ? color_pair : CP_HEADER));
    }

    if (message) {
        wattron(win, fims_color_attr(CP_DEFAULT));
        char msg_copy[512];
        strncpy(msg_copy, message, sizeof(msg_copy) - 1);
        msg_copy[sizeof(msg_copy) - 1] = '\0';

        char *line = strtok(msg_copy, "\n");
        int line_y = 2;
        while (line && line_y < h - 3) {
            mvwprintw(win, line_y++, (w - (int)strlen(line)) / 2, "%s", line);
            line = strtok(NULL, "\n");
        }
        wattroff(win, fims_color_attr(CP_DEFAULT));
    }

    wattron(win, fims_color_attr(CP_BUTTON_ACT));
    mvwprintw(win, h - 3, (w - 8) / 2, "[  OK  ]");
    wattroff(win, fims_color_attr(CP_BUTTON_ACT));

    wrefresh(win);

    while (1) {
        int ch = wgetch(win);
        if (ch == '\n' || ch == KEY_ENTER || ch == 27 || ch == ' ' || ch == 'q' || ch == 'Q') {
            break;
        }
    }

    delwin(win);
    touchwin(stdscr);
    refresh();
}

bool fims_dialog_input(const char *title, const char *prompt, char *buffer, size_t buf_sz) {
    if (!buffer || buf_sz == 0) return false;

    int w = 60;
    int h = 9;
    int start_y = (LINES - h) / 2;
    int start_x = (COLS - w) / 2;

    if (start_y < 0) start_y = 0;
    if (start_x < 0) start_x = 0;

    WINDOW *win = newwin(h, w, start_y, start_x);
    if (!win) return false;

    keypad(win, TRUE);

    char edit_buf[512];
    strncpy(edit_buf, buffer, sizeof(edit_buf) - 1);
    edit_buf[sizeof(edit_buf) - 1] = '\0';
    int cursor = (int)strlen(edit_buf);

    curs_set(1);

    while (1) {
        werase(win);
        wattron(win, fims_color_attr(CP_BORDER));
        box(win, 0, 0);
        wattroff(win, fims_color_attr(CP_BORDER));

        if (title) {
            wattron(win, fims_color_attr(CP_HEADER));
            mvwprintw(win, 0, (w - (int)strlen(title) - 6) / 2, " ◈ %s ◈ ", title);
            wattroff(win, fims_color_attr(CP_HEADER));
        }

        if (prompt) {
            wattron(win, fims_color_attr(CP_DEFAULT));
            mvwprintw(win, 2, 4, "› %s", prompt);
            wattroff(win, fims_color_attr(CP_DEFAULT));
        }

        /* Input field background */
        wattron(win, fims_color_attr(CP_BUTTON_NORM) | A_REVERSE);
        mvwprintw(win, 4, 4, "%-50s", edit_buf);
        wattroff(win, fims_color_attr(CP_BUTTON_NORM) | A_REVERSE);

        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, 6, (w - 24) / 2, "↵ Confirm  •  ⎋ Cancel");
        wattroff(win, fims_color_attr(CP_DIM));

        wmove(win, 4, 4 + cursor);
        wrefresh(win);

        int ch = wgetch(win);
        if (ch == 27) { /* ESC */
            curs_set(0);
            delwin(win);
            touchwin(stdscr);
            refresh();
            return false;
        } else if (ch == '\n' || ch == KEY_ENTER) {
            strncpy(buffer, edit_buf, buf_sz - 1);
            buffer[buf_sz - 1] = '\0';
            curs_set(0);
            delwin(win);
            touchwin(stdscr);
            refresh();
            return true;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (cursor > 0) {
                memmove(edit_buf + cursor - 1, edit_buf + cursor, strlen(edit_buf) - cursor + 1);
                cursor--;
            }
        } else if (ch == KEY_DC) { /* Delete */
            if (cursor < (int)strlen(edit_buf)) {
                memmove(edit_buf + cursor, edit_buf + cursor + 1, strlen(edit_buf) - cursor);
            }
        } else if (ch == KEY_LEFT) {
            if (cursor > 0) cursor--;
        } else if (ch == KEY_RIGHT) {
            if (cursor < (int)strlen(edit_buf)) cursor++;
        } else if (ch == KEY_HOME) {
            cursor = 0;
        } else if (ch == KEY_END) {
            cursor = (int)strlen(edit_buf);
        } else if (isprint(ch) && strlen(edit_buf) < 48 && strlen(edit_buf) < sizeof(edit_buf) - 2) {
            memmove(edit_buf + cursor + 1, edit_buf + cursor, strlen(edit_buf) - cursor + 1);
            edit_buf[cursor++] = (char)ch;
        }
    }
}

void fims_dialog_progress_draw(const char *title, const char *action, size_t current, size_t total) {
    int w = 54;
    int h = 7;
    int start_y = (LINES - h) / 2;
    int start_x = (COLS - w) / 2;

    if (start_y < 0) start_y = 0;
    if (start_x < 0) start_x = 0;

    WINDOW *win = newwin(h, w, start_y, start_x);
    if (!win) return;

    wattron(win, fims_color_attr(CP_BORDER));
    box(win, 0, 0);
    wattroff(win, fims_color_attr(CP_BORDER));

    if (title) {
        wattron(win, fims_color_attr(CP_HEADER));
        mvwprintw(win, 0, (w - (int)strlen(title) - 6) / 2, " ◈ %s ◈ ", title);
        wattroff(win, fims_color_attr(CP_HEADER));
    }

    wattron(win, fims_color_attr(CP_DEFAULT));
    mvwprintw(win, 2, 4, "%-44s", action ? action : "Processing...");
    wattroff(win, fims_color_attr(CP_DEFAULT));

    /* Progress bar */
    int bar_width = 44;
    int fill = 0;
    if (total > 0) {
        fill = (int)((current * bar_width) / total);
        if (fill > bar_width) fill = bar_width;
    }

    wattron(win, fims_color_attr(CP_PROGRESS));
    for (int i = 0; i < fill; i++) {
        mvwaddch(win, 4, 4 + i, ' ' | A_REVERSE);
    }
    wattroff(win, fims_color_attr(CP_PROGRESS));

    wattron(win, fims_color_attr(CP_DIM));
    for (int i = fill; i < bar_width; i++) {
        mvwaddch(win, 4, 4 + i, '-');
    }
    wattroff(win, fims_color_attr(CP_DIM));

    wrefresh(win);
    delwin(win);
}

void fims_dialog_summary(const char *cmd_name,
                         bool is_ok,
                         const char *status_badge,
                         size_t scanned,
                         size_t unchanged,
                         size_t mod,
                         size_t add,
                         size_t del,
                         double duration_ms,
                         const char *details) {
    int w = 62;
    int h = 15;
    int start_y = (LINES - h) / 2;
    int start_x = (COLS - w) / 2;

    if (start_y < 0) start_y = 0;
    if (start_x < 0) start_x = 0;

    WINDOW *win = newwin(h, w, start_y, start_x);
    if (!win) return;

    keypad(win, TRUE);

    werase(win);
    wattron(win, fims_color_attr(is_ok ? CP_SUCCESS : CP_ERROR));
    box(win, 0, 0);
    wattroff(win, fims_color_attr(is_ok ? CP_SUCCESS : CP_ERROR));

    /* Header */
    wattron(win, fims_color_attr(CP_HEADER));
    mvwprintw(win, 0, (w - 25) / 2, " ◈ EXECUTION SUMMARY ◈ ");
    wattroff(win, fims_color_attr(CP_HEADER));

    /* Fields */
    mvwprintw(win, 2, 4, "Command Executed : ");
    wattron(win, fims_color_attr(CP_DEFAULT) | A_BOLD);
    wprintw(win, "%s", cmd_name ? cmd_name : "OPERATION");
    wattroff(win, fims_color_attr(CP_DEFAULT) | A_BOLD);

    mvwprintw(win, 3, 4, "Execution Status : ");
    wattron(win, fims_color_attr(is_ok ? CP_STATUS_OK : CP_STATUS_BAD));
    wprintw(win, " %s ", status_badge ? status_badge : (is_ok ? "● OK" : "● FAILED"));
    wattroff(win, fims_color_attr(is_ok ? CP_STATUS_OK : CP_STATUS_BAD));

    if (duration_ms > 0) {
        mvwprintw(win, 4, 4, "Duration         : %.2f ms", duration_ms);
    } else {
        mvwprintw(win, 4, 4, "Duration         : < 1 ms");
    }

    /* Divider */
    wattron(win, fims_color_attr(CP_BORDER));
    for (int i = 1; i < w - 1; i++) {
        mvwaddch(win, 5, i, ACS_HLINE);
    }
    wattroff(win, fims_color_attr(CP_BORDER));

    mvwprintw(win, 6, 4, "Files Processed  : %zu", scanned);

    mvwprintw(win, 7, 4, "  ● Unchanged    : ");
    wattron(win, fims_color_attr(CP_SUCCESS));
    wprintw(win, "%zu", unchanged);
    wattroff(win, fims_color_attr(CP_SUCCESS));

    mvwprintw(win, 8, 4, "  ✖ Modified     : ");
    if (mod > 0) wattron(win, fims_color_attr(CP_ERROR));
    wprintw(win, "%zu", mod);
    if (mod > 0) wattroff(win, fims_color_attr(CP_ERROR));

    mvwprintw(win, 9, 4, "  ▲ Added        : ");
    if (add > 0) wattron(win, fims_color_attr(CP_WARNING));
    wprintw(win, "%zu", add);
    if (add > 0) wattroff(win, fims_color_attr(CP_WARNING));

    mvwprintw(win, 10, 4, "  ✖ Deleted      : ");
    if (del > 0) wattron(win, fims_color_attr(CP_ERROR));
    wprintw(win, "%zu", del);
    if (del > 0) wattroff(win, fims_color_attr(CP_ERROR));

    if (details && details[0]) {
        wattron(win, fims_color_attr(CP_DIM));
        mvwprintw(win, 11, 4, "Target / Notes   : %.*s", w - 24, details);
        wattroff(win, fims_color_attr(CP_DIM));
    }

    /* Dismiss button */
    wattron(win, fims_color_attr(CP_BUTTON_ACT));
    mvwprintw(win, h - 2, (w - 24) / 2, " [ ↵ Close Summary ] ");
    wattroff(win, fims_color_attr(CP_BUTTON_ACT));

    wrefresh(win);

    while (1) {
        int ch = wgetch(win);
        if (ch == '\n' || ch == KEY_ENTER || ch == ' ' || ch == 27 || ch == 'q' || ch == 'Q') {
            break;
        }
    }

    delwin(win);
    touchwin(stdscr);
    refresh();
}
