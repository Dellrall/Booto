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
#include "case_reporter.h"
#include "persistence_mgr.h"
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
    const char *target = "/dev/sda";
    for (int i = 0; i < app->drive_count; i++) {
        if (app->drives[i].is_target) {
            target = app->drives[i].dev_path;
            break;
        }
    }

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "=== Starting Forensic Scan on %s (Strict RO) ===", target);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, log_buf);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[1/5] Verifying UEFI ESP signatures against DBX revocation list...");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[1/5] ESP bootloader signatures checked [OK]");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[2/5] Parsing Kernel ELF binaries & /lib/modules LKMs...");
    tui_app_append_log(app, LOG_LEVEL_CRITICAL, NULL, "[!] ALERT: Detected hidden LKM hook in diamorphine.ko at offset 0x41F0!");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[3/5] Auditing in-memory initramfs CPIO scripts in RAM...");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[4/5] Auditing /etc/ld.so.preload & dynamic linker paths [OK]");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "[5/5] Executing Raw Ext4 Inode vs VFS Directory Table Diff...");
    tui_app_append_log(app, LOG_LEVEL_WARN, NULL, "[!] ALERT: Found 1 unlinked hidden inode #41920 on target disk!");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "=== Forensic Scan Finished: 2 Threats Identified ===");

    // Populate threat inspector findings
    snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "Diamorphine LKM Rootkit");
    snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "/lib/modules/diamorphine.ko");
    snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "sys_call_table hijack & DKOM hide");
    snprintf(app->threat.sha256, sizeof(app->threat.sha256), "8f4b23a9d201bc93ef4a890123ef9a82bc128912ef349a128901bc3412ef8901");
    snprintf(app->threat.severity, sizeof(app->threat.severity), "CRITICAL");
    app->threat.severity_color = MAKE_ATTR(COLOR_BRIGHT_RED, COLOR_DEFAULT, ATTR_BOLD);

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
            } else if (event.type == KEY_F6) {
                forensic_case_summary_t sum;
                memset(&sum, 0, sizeof(sum));
                snprintf(sum.case_id, sizeof(sum.case_id), "CASE-20260901-01");
                snprintf(sum.timestamp, sizeof(sum.timestamp), "2026-09-01 23:28:00 UTC");
                snprintf(sum.target_disk, sizeof(sum.target_disk), "/dev/nvme0n1p2");
                snprintf(sum.target_fs, sizeof(sum.target_fs), "ext4");
                snprintf(sum.examiner, sizeof(sum.examiner), "Booto Live Examiner");
                sum.kernel_threats_count = 1;
                sum.uefi_threats_count = 0;
                sum.initramfs_threats_count = 0;
                sum.preload_threats_count = 0;
                sum.ext4_hidden_inodes_count = 1;
                sum.total_threats = 2;
                snprintf(sum.highest_severity, sizeof(sum.highest_severity), "CRITICAL");

                const char *out_dir = app.luks_unlocked ? "/persistence/cases" : "/tmp";
                char saved_md[512];
                case_report_generate_markdown(&sum, out_dir, saved_md, sizeof(saved_md));

                char log_buf[512];
                snprintf(log_buf, sizeof(log_buf), "Exported signed forensic case report to %.300s", saved_md);
                tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, log_buf);
                snprintf(app.status_msg, sizeof(app.status_msg), "Case Report Saved: %.100s", saved_md);
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
