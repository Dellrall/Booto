/**
 * @file tui_app.c
 * @brief Implementation of the main interactive TUI application loop.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "tui/tui_app.h"
#include "tui/terminal.h"
#include "tui/wm.h"
#include "tui/pane.h"
#include "logger.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static tui_app_state_t *g_current_app = NULL;

static void tui_logger_hook(log_level_t level, const char *timestamp, const char *msg, void *user_data) {
    (void)user_data;
    if (g_current_app) {
        tui_app_append_log(g_current_app, level, timestamp, msg);
    }
}

static void render_top_bar(tui_app_state_t *app, int cols) {
    char left[128];
    snprintf(left, sizeof(left), " BOOTO v%s (%s) | Mode: Amnesic (RAM) | Focus: [%s]",
             BOOTO_VERSION_STRING, BOOTO_GIT_HASH,
             app->wm->focused_leaf ? wm_pane_type_name(app->wm->focused_leaf->pane_type) : "None");

    char right[64];
    snprintf(right, sizeof(right), "[%s] ",
             app->luks_unlocked ? "LUKS: UNLOCKED" : "LUKS: LOCKED");

    uint32_t bar_attr = MAKE_ATTR(COLOR_BLACK, COLOR_CYAN, ATTR_BOLD);

    for (int x = 0; x < cols; x++) {
        term_putc(x, 0, ' ', bar_attr);
    }

    term_puts(0, 0, left, bar_attr);

    int r_pos = cols - (int)strlen(right);
    if (r_pos > (int)strlen(left)) {
        term_puts(r_pos, 0, right, app->luks_unlocked ? MAKE_ATTR(COLOR_BLACK, COLOR_GREEN, ATTR_BOLD) : MAKE_ATTR(COLOR_BLACK, COLOR_RED, ATTR_BOLD));
    }
}

static void render_bottom_bar(tui_app_state_t *app, int rows, int cols) {
    (void)app;
    uint32_t bar_attr = MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_NONE);

    for (int x = 0; x < cols; x++) {
        term_putc(x, rows - 1, ' ', bar_attr);
    }

    const char *help = " Alt+Arrow: Focus | Alt+M: Move/Swap | Alt+Z: Zoom | Alt+H/V: Split | Alt+[/]: Resize | F5: Scan | F10: Quit";
    term_puts(0, rows - 1, help, bar_attr);
}

static void render_tree_leaves(wm_node_t *node, wm_node_t *focused, tui_app_state_t *app) {
    if (!node) return;
    if (node->type == NODE_LEAF) {
        pane_render(node, (node == focused), app);
    } else {
        render_tree_leaves(node->left, focused, app);
        render_tree_leaves(node->right, focused, app);
    }
}

static void simulate_scan_step(tui_app_state_t *app) {
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "=== Starting Forensic Scan on /dev/nvme0n1p2 (RO) ===");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[1/5] Verifying UEFI ESP signatures against DB/DBX whitelist...");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[1/5] ESP hash matched Microsoft UEFI CA 2023 [OK]");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[2/5] Parsing Kernel ELF binary and /lib/modules/6.5.0-generic...");
    tui_app_append_log(app, LOG_LEVEL_CRITICAL, NULL, "[!] ALERT: Detected hidden LKM hook in diamorphine.ko at offset 0x41F0!");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[3/5] Unpacking initramfs-6.5.0-generic.img in RAM...");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[4/5] Auditing /etc/ld.so.preload & PAM modules [OK]");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[5/5] Executing Raw Ext4 Inode vs VFS Directory Table Diff...");
    tui_app_append_log(app, LOG_LEVEL_WARN, NULL, "[!] ALERT: Found 1 unlinked hidden inode #41920 on target disk!");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "=== Forensic Scan Finished: 2 Threats Identified ===");
    snprintf(app->status_msg, sizeof(app->status_msg), "Scan complete: 2 Threats Identified. Check Threat Inspector.");
}

int tui_app_run(booto_context_t *ctx) {
    if (term_init() != 0) {
        fprintf(stderr, "Error: Terminal initialization failed (requires interactive TTY)\n");
        return -1;
    }

    int rows, cols;
    term_get_dimensions(&rows, &cols);

    tui_app_state_t app;
    tui_app_state_init(&app, ctx);
    app.wm = wm_tree_create_default(cols, rows);

    g_current_app = &app;
    logger_set_callback(tui_logger_hook, NULL);

    while (app.running) {
        term_get_dimensions(&rows, &cols);
        wm_recalculate_layout(app.wm, 0, 1, cols, rows - 2);

        term_clear();

        // 1. Render Top & Bottom Bars
        render_top_bar(&app, cols);
        render_bottom_bar(&app, rows, cols);

        // 2. Render BSP Window Tree
        if (app.wm->zoomed_leaf) {
            pane_render(app.wm->zoomed_leaf, true, &app);
        } else {
            render_tree_leaves(app.wm->root, app.wm->focused_leaf, &app);
        }

        // 3. Differential screen flush
        term_present();

        // 4. Input event polling
        input_event_t event;
        if (term_poll_event(&event, 50)) {
            if (event.type == KEY_F10 || (event.type == KEY_CHAR && (event.ch == 'q' || event.ch == 'Q'))) {
                app.running = false;
            } else if (event.type == KEY_TAB) {
                wm_focus_next(app.wm);
            } else if (event.type == KEY_ALT_LEFT || event.type == KEY_ALT_RIGHT ||
                       event.type == KEY_ALT_UP || event.type == KEY_ALT_DOWN) {
                wm_focus_direction(app.wm, event.type);
            } else if (event.type == KEY_ALT_Z) {
                wm_toggle_zoom(app.wm);
            } else if (event.type == KEY_ALT_M) {
                wm_swap_focused_adjacent(app.wm, KEY_RIGHT);
                tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, "Swapped active pane layout (Alt+M)");
            } else if (event.type == KEY_ALT_H) {
                pane_type_t next_type = (pane_type_t)((app.wm->focused_leaf->pane_type + 1) % PANE_COUNT);
                wm_split_focused(app.wm, SPLIT_HORIZONTAL, next_type);
                tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, "Split pane horizontally (Alt+H)");
            } else if (event.type == KEY_ALT_V) {
                pane_type_t next_type = (pane_type_t)((app.wm->focused_leaf->pane_type + 1) % PANE_COUNT);
                wm_split_focused(app.wm, SPLIT_VERTICAL, next_type);
                tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, "Split pane vertically (Alt+V)");
            } else if (event.type == KEY_ALT_LBRACKET) {
                wm_adjust_split_ratio(app.wm, -0.05f);
            } else if (event.type == KEY_ALT_RBRACKET) {
                wm_adjust_split_ratio(app.wm, +0.05f);
            } else if (event.type == KEY_F5) {
                simulate_scan_step(&app);
            } else if (event.type == KEY_F2) {
                app.luks_unlocked = !app.luks_unlocked;
                snprintf(app.persistence_status, sizeof(app.persistence_status),
                         app.luks_unlocked ? "LUKS Unlocked (/persistence)" : "LUKS Locked (Amnesic Mode)");
                tui_app_append_log(&app, app.luks_unlocked ? LOG_LEVEL_INFO : LOG_LEVEL_WARN, NULL,
                                   app.luks_unlocked ? "Unlocked encrypted LUKS persistence volume" : "Locked persistence volume");
            } else if (event.type == KEY_MOUSE_CLICK) {
                wm_node_t *clicked = wm_find_leaf_at(app.wm->root, event.mouse_x, event.mouse_y);
                if (clicked) {
                    app.wm->focused_leaf = clicked;
                }
            } else {
                if (app.wm->focused_leaf) {
                    pane_handle_input(app.wm->focused_leaf, &event, &app);
                }
            }
        }
    }

    logger_set_callback(NULL, NULL);
    g_current_app = NULL;

    wm_tree_destroy(app.wm);
    term_shutdown();
    return 0;
}
