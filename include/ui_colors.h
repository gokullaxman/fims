#ifndef FIMS_UI_COLORS_H
#define FIMS_UI_COLORS_H

#define _GNU_SOURCE
#include <ncurses.h>
#include <stdbool.h>

/* ============================================================================
 * FIMS Ncurses Color Pair Enumerations
 * ============================================================================ */
#define CP_DEFAULT       1
#define CP_HEADER        2
#define CP_BORDER        3
#define CP_NAV_NORMAL    4
#define CP_NAV_ACTIVE    5
#define CP_SUCCESS       6
#define CP_WARNING       7
#define CP_ERROR         8
#define CP_INFO          9
#define CP_METADATA      10
#define CP_DIM           11
#define CP_STATUS_OK     12
#define CP_STATUS_WARN   13
#define CP_STATUS_BAD    14
#define CP_BADGE_CRIT    15
#define CP_BADGE_HIGH    16
#define CP_BADGE_MED     17
#define CP_BADGE_LOW     18
#define CP_BADGE_INFO    19
#define CP_TITLEBAR      20
#define CP_DIALOG        21
#define CP_BUTTON_NORM   22
#define CP_BUTTON_ACT    23
#define CP_PROGRESS      24
#define CP_KEYBIND       25

/**
 * Initialize all ncurses color pairs and terminal attributes.
 * Falls back safely to monochrome attributes if colors are unsupported.
 */
void fims_colors_init(void);

/**
 * Check whether terminal color capability is active.
 */
bool fims_colors_available(void);

/**
 * Helper to obtain chtype attributes for a given color pair ID.
 */
chtype fims_color_attr(int pair_id);

#endif /* FIMS_UI_COLORS_H */
