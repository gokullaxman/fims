#define _GNU_SOURCE
#include "ui_colors.h"
#include <ncurses.h>

static bool g_colors_initialized = false;
static bool g_has_colors = false;

void fims_colors_init(void) {
    if (g_colors_initialized) return;
    g_colors_initialized = true;

    if (!has_colors()) {
        g_has_colors = false;
        return;
    }

    start_color();
    g_has_colors = true;

#ifdef NCURSES_VERSION
    use_default_colors();
#endif

    init_pair(CP_DEFAULT,     COLOR_WHITE,   COLOR_BLACK);
    init_pair(CP_HEADER,      COLOR_CYAN,    COLOR_BLACK);
    init_pair(CP_BORDER,      COLOR_CYAN,    COLOR_BLACK);
    init_pair(CP_NAV_NORMAL,  COLOR_WHITE,   COLOR_BLACK);
    init_pair(CP_NAV_ACTIVE,  COLOR_BLACK,   COLOR_CYAN);
    init_pair(CP_SUCCESS,     COLOR_GREEN,   COLOR_BLACK);
    init_pair(CP_WARNING,     COLOR_YELLOW,  COLOR_BLACK);
    init_pair(CP_ERROR,       COLOR_RED,     COLOR_BLACK);
    init_pair(CP_INFO,        COLOR_BLUE,    COLOR_BLACK);
    init_pair(CP_METADATA,    COLOR_MAGENTA, COLOR_BLACK);
    init_pair(CP_DIM,         COLOR_WHITE,   COLOR_BLACK);
    init_pair(CP_STATUS_OK,   COLOR_BLACK,   COLOR_GREEN);
    init_pair(CP_STATUS_WARN, COLOR_BLACK,   COLOR_YELLOW);
    init_pair(CP_STATUS_BAD,  COLOR_WHITE,   COLOR_RED);
    init_pair(CP_BADGE_CRIT,  COLOR_WHITE,   COLOR_RED);
    init_pair(CP_BADGE_HIGH,  COLOR_RED,     COLOR_BLACK);
    init_pair(CP_BADGE_MED,   COLOR_YELLOW,  COLOR_BLACK);
    init_pair(CP_BADGE_LOW,   COLOR_BLUE,    COLOR_BLACK);
    init_pair(CP_BADGE_INFO,  COLOR_CYAN,    COLOR_BLACK);
    init_pair(CP_TITLEBAR,    COLOR_BLACK,   COLOR_CYAN);
    init_pair(CP_DIALOG,      COLOR_WHITE,   COLOR_BLACK);
    init_pair(CP_BUTTON_NORM, COLOR_WHITE,   COLOR_BLACK);
    init_pair(CP_BUTTON_ACT,  COLOR_BLACK,   COLOR_GREEN);
    init_pair(CP_PROGRESS,    COLOR_BLACK,   COLOR_GREEN);
    init_pair(CP_KEYBIND,     COLOR_CYAN,    COLOR_BLACK);
}

bool fims_colors_available(void) {
    return g_has_colors;
}

chtype fims_color_attr(int pair_id) {
    if (!g_has_colors) {
        if (pair_id == CP_NAV_ACTIVE || pair_id == CP_BUTTON_ACT) {
            return A_REVERSE | A_BOLD;
        }
        if (pair_id == CP_HEADER || pair_id == CP_STATUS_OK || pair_id == CP_BADGE_CRIT) {
            return A_BOLD;
        }
        if (pair_id == CP_DIM) {
            return A_DIM;
        }
        return A_NORMAL;
    }

    chtype base = COLOR_PAIR(pair_id);

    switch (pair_id) {
        case CP_HEADER:
        case CP_NAV_ACTIVE:
        case CP_SUCCESS:
        case CP_WARNING:
        case CP_ERROR:
        case CP_STATUS_OK:
        case CP_STATUS_WARN:
        case CP_STATUS_BAD:
        case CP_BADGE_CRIT:
        case CP_BADGE_HIGH:
        case CP_BUTTON_ACT:
        case CP_TITLEBAR:
            return base | A_BOLD;

        case CP_DIM:
            return base | A_DIM;

        default:
            return base;
    }
}
