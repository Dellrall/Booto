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
#include "disk_mount.h"
#include "forensic_scan.h"
#include "logger.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    uint32_t bar_attr = MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_NONE);

    for (int x = 0; x < cols; x++) {
        term_putc(x, rows - 1, ' ', bar_attr);
    }

    // Alt+M has no direction: it swaps the focused pane with the next pane in Tab order.
    const char *help = "Alt+Arrow: Focus | Alt+M: Swap w/ Next | Alt+Z: Zoom | F3: Decrypt LUKS | F5: Scan | F6: Export | F10/Q: Exit";
    char line[512];
    if (atomic_load(&app->scan_active)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        char spin = "|/-\\"[(ts.tv_nsec / 125000000L) % 4];
        snprintf(line, sizeof(line), " %c Scanning [%d/%d] | %.200s | %s", spin, atomic_load(&app->scan_step),
                 (int)SCAN_MOD_COUNT, app->status_msg, help);
    } else {
        snprintf(line, sizeof(line), " %.200s | %s", app->status_msg, help);
    }
    term_puts(0, rows - 1, line, bar_attr);
}

static void render_exit_modal(tui_app_state_t *app, int rows, int cols) {
    (void)app;
    int mw = 64;
    int mh = 11;
    int mx = (cols - mw) / 2;
    int my = (rows - mh) / 2;
    if (mx < 0) mx = 0;
    if (my < 0) my = 0;

    uint32_t border_attr = MAKE_ATTR(COLOR_BRIGHT_RED, COLOR_BLACK, ATTR_BOLD);
    uint32_t title_attr = MAKE_ATTR(COLOR_BLACK, COLOR_BRIGHT_RED, ATTR_BOLD);
    uint32_t text_attr = MAKE_ATTR(COLOR_WHITE, COLOR_BLACK, ATTR_NONE);
    uint32_t key_attr = MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_BLACK, ATTR_BOLD);

    // Clear background behind modal
    for (int y = my; y < my + mh && y < rows; y++) {
        for (int x = mx; x < mx + mw && x < cols; x++) {
            term_putc(x, y, ' ', text_attr);
        }
    }

    term_draw_box(mx, my, mw, mh, " System Power & Exit Menu ", border_attr, title_attr);

    term_puts(mx + 4, my + 2, "Select an action to proceed:", text_attr);

    term_puts(mx + 6, my + 4, "[P]", key_attr);
    term_puts(mx + 10, my + 4, "Power Off System (Shutdown Machine)", text_attr);

    term_puts(mx + 6, my + 5, "[R]", key_attr);
    term_puts(mx + 10, my + 5, "Reboot System    (Restart Machine)", text_attr);

    term_puts(mx + 6, my + 6, "[S]", key_attr);
    term_puts(mx + 10, my + 6, "Drop to Root Interactive Shell (Bash)", text_attr);

    term_puts(mx + 6, my + 8, "[ESC/C]", key_attr);
    term_puts(mx + 14, my + 8, "Cancel and Return to Booto TUI", text_attr);
}

static void render_luks_modal(tui_app_state_t *app, int rows, int cols) {
    int mw = 68;
    int mh = 12;
    int mx = (cols - mw) / 2;
    int my = (rows - mh) / 2;
    if (mx < 0) mx = 0;
    if (my < 0) my = 0;

    uint32_t border_attr = MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_BLACK, ATTR_BOLD);
    uint32_t title_attr = MAKE_ATTR(COLOR_BLACK, COLOR_BRIGHT_CYAN, ATTR_BOLD);
    uint32_t text_attr = MAKE_ATTR(COLOR_WHITE, COLOR_BLACK, ATTR_NONE);
    uint32_t key_attr = MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_BLACK, ATTR_BOLD);
    uint32_t input_attr = MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_BOLD);
    uint32_t alert_attr = MAKE_ATTR(COLOR_BRIGHT_RED, COLOR_BLACK, ATTR_BOLD);

    // Clear background behind modal
    for (int y = my; y < my + mh && y < rows; y++) {
        for (int x = mx; x < mx + mw && x < cols; x++) {
            term_putc(x, y, ' ', text_attr);
        }
    }

    term_draw_box(mx, my, mw, mh, " LUKS Encrypted Target Partition Unlock ", border_attr, title_attr);

    char prompt[256];
    snprintf(prompt, sizeof(prompt), "Target device %.64s is encrypted with LUKS.", app->luks_target_dev);
    term_puts(mx + 4, my + 2, prompt, text_attr);
    term_puts(mx + 4, my + 3, "Enter passphrase to map volume strictly READ-ONLY:", text_attr);

    // Render passphrase input box
    int box_w = 48;
    for (int x = mx + 6; x < mx + 6 + box_w && x < cols; x++) {
        term_putc(x, my + 5, ' ', input_attr);
    }
    char masked[64];
    int mask_len = (app->luks_passphrase_len < 40) ? app->luks_passphrase_len : 40;
    for (int i = 0; i < mask_len; i++) masked[i] = '*';
    masked[mask_len] = '\0';
    term_puts(mx + 7, my + 5, masked, input_attr);
    if (mx + 7 + mask_len < cols) {
        term_putc(mx + 7 + mask_len, my + 5, '_', MAKE_ATTR(COLOR_RED, COLOR_WHITE, ATTR_BOLD));
    }

    if (app->luks_status_msg[0] != '\0') {
        term_puts(mx + 6, my + 7, app->luks_status_msg, alert_attr);
    }

    term_puts(mx + 6, my + 9, "[ENTER]", key_attr);
    term_puts(mx + 14, my + 9, "Unlock Read-Only", text_attr);

    term_puts(mx + 34, my + 9, "[ESC]", key_attr);
    term_puts(mx + 40, my + 9, "Cancel / Skip", text_attr);
}

static void render_tree_leaves(wm_node_t *node, wm_node_t *focused, tui_app_state_t *app) {
    if (!node) return;
    if (node->type == NODE_LEAF) {
        pane_render(node, node == focused, app);
    } else {
        render_tree_leaves(node->left, focused, app);
        render_tree_leaves(node->right, focused, app);
    }
}

static void scan_progress_cb(int step, int total, const char *msg, void *user) {
    tui_app_state_t *app = user;
    atomic_store(&app->scan_step, step);
    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "[%d/%d] %.200s", step, total, msg ? msg : "");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, log_buf);
}

static scan_module_id_t pane_module_to_scan_id(const char *name) {
    if (strncmp(name, "MBR", 3) == 0) return SCAN_MOD_MBR;
    if (strncmp(name, "UEFI", 4) == 0) return SCAN_MOD_UEFI;
    if (strncmp(name, "Kernel", 6) == 0) return SCAN_MOD_KERNEL;
    if (strstr(name, "Initramfs")) return SCAN_MOD_INITRAMFS;
    if (strncmp(name, "LD_PRELOAD", 10) == 0) return SCAN_MOD_PRELOAD;
    if (strstr(name, "Ext4")) return SCAN_MOD_EXT4;
    return SCAN_MOD_COUNT;
}

static int module_threats(const forensic_scan_report_t *r, int m) {
    switch (m) {
        case SCAN_MOD_MBR: return r->mbr.threats_detected;
        case SCAN_MOD_UEFI: return r->uefi.bootkits_detected;
        case SCAN_MOD_KERNEL: return r->kernel.threats_detected;
        case SCAN_MOD_INITRAMFS: return r->initramfs.threats_detected;
        case SCAN_MOD_PRELOAD: return r->preload.threats_detected;
        default: return 0;
    }
}

/* Worker thread: touches only its own pending_* / scan_* inputs, the log (locked) and the atomics. */
static void *scan_worker(void *arg) {
    tui_app_state_t *app = arg;
    app->pending_err = forensic_scan_run(app->scan_target, NULL, app->scan_enabled, scan_progress_cb, app,
                                         app->pending_scan);
    atomic_store(&app->scan_done, true);
    return NULL;
}

static void start_forensic_scan(tui_app_state_t *app) {
    if (atomic_load(&app->scan_active)) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan already running");
        return;
    }
    const char *target_dev = NULL;
    for (int i = 0; i < app->drive_count; i++) {
        if (app->drives[i].is_target) {
            target_dev = app->drives[i].name;
            break;
        }
    }
    if (!target_dev) {
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, "No target drive selected; scan not started");
        snprintf(app->status_msg, sizeof(app->status_msg), "No target drive selected: mark a target in Storage pane first.");
        return;
    }

    app->pending_scan = calloc(1, sizeof(*app->pending_scan));
    if (!app->pending_scan) {
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, "Out of memory allocating scan report");
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan failed: out of memory.");
        return;
    }
    // Copy inputs so the UI may keep editing drives/modules while the worker runs.
    snprintf(app->scan_target, sizeof(app->scan_target), "%s", target_dev);
    memset(app->scan_enabled, 0, sizeof(app->scan_enabled));
    for (int i = 0; i < app->module_count; i++) {
        scan_module_id_t id = pane_module_to_scan_id(app->modules[i].name);
        if (id < SCAN_MOD_COUNT) app->scan_enabled[id] = app->modules[i].enabled;
    }

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "=== Starting Forensic Scan on %.120s (Strict Read-Only) ===", app->scan_target);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, log_buf);

    atomic_store(&app->scan_step, 0);
    atomic_store(&app->scan_done, false);
    atomic_store(&app->scan_active, true);
    int rc = pthread_create(&app->scan_thread, NULL, scan_worker, app);
    if (rc != 0) {
        atomic_store(&app->scan_active, false);
        free(app->pending_scan);
        app->pending_scan = NULL;
        snprintf(log_buf, sizeof(log_buf), "Could not start scan thread (%s)", strerror(rc));
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, log_buf);
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan failed to start (%.200s).", strerror(rc));
        return;
    }
    snprintf(app->status_msg, sizeof(app->status_msg), "Scanning %.120s ...", app->scan_target);
}

/* Main thread only: joins the worker (blocking if it is still running) and publishes its report. */
static void finish_forensic_scan(tui_app_state_t *app) {
    pthread_join(app->scan_thread, NULL);
    atomic_store(&app->scan_done, false);
    atomic_store(&app->scan_active, false);

    forensic_scan_report_t *r = app->pending_scan;
    app->pending_scan = NULL;
    const char *target_dev = app->scan_target;
    char log_buf[256];
    booto_error_t err = app->pending_err;
    if (err != BOOTO_OK) {
        free(r);
        snprintf(log_buf, sizeof(log_buf), "Forensic scan could not run (error %d)", (int)err);
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, log_buf);
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan failed to run (error %d).", (int)err);
        return;
    }
    free(app->last_scan);
    app->last_scan = r;

    int ok_count = 0;
    for (int m = 0; m < SCAN_MOD_COUNT; m++) {
        if (r->status[m] == SCAN_STATUS_OK) ok_count++;
        snprintf(log_buf, sizeof(log_buf), "%.20s: %.8s (%d) %.96s",
                 forensic_scan_module_name((scan_module_id_t)m), forensic_scan_status_str(r->status[m]),
                 module_threats(r, m), r->note[m]);
        tui_app_append_log(app, r->status[m] == SCAN_STATUS_OK ? LOG_LEVEL_INFO : LOG_LEVEL_WARN, NULL, log_buf);
    }

    snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", target_dev);
    snprintf(app->threat.hex_dump, sizeof(app->threat.hex_dump), "-");

    if (r->verdict == SCAN_VERDICT_THREATS) {
        snprintf(log_buf, sizeof(log_buf), "=== Forensic Scan Finished: %d Threat(s) Identified ===", r->total_threats);
        tui_app_append_log(app, LOG_LEVEL_CRITICAL, NULL, log_buf);
        app->threat.severity_color = MAKE_ATTR(COLOR_BRIGHT_RED, COLOR_DEFAULT, ATTR_BOLD);
        snprintf(app->threat.severity, sizeof(app->threat.severity), "CRITICAL");

        if (r->mbr.threats_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "%.60s", r->mbr.findings[0].threat_name);
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.70s (LBA %llu)",
                     r->mbr.findings[0].target_device, (unsigned long long)r->mbr.findings[0].sector_lba);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "Rule: %.50s", r->mbr.findings[0].rule_id);
            snprintf(app->threat.sha256, sizeof(app->threat.sha256), "%.64s", r->mbr.findings[0].sha256);
            snprintf(app->threat.severity, sizeof(app->threat.severity), "%.15s", mbr_severity_to_string(r->mbr.findings[0].severity));
        } else if (r->uefi.bootkits_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "%.60s", r->uefi.findings[0].threat_name);
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", r->uefi.findings[0].file_path);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "Rule: %.50s", r->uefi.findings[0].rule_id);
            snprintf(app->threat.sha256, sizeof(app->threat.sha256), "%.64s", r->uefi.findings[0].sha256);
        } else if (r->kernel.threats_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "%.60s", r->kernel.findings[0].threat_name);
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", r->kernel.findings[0].file_path);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "%.30s: %.25s",
                     r->kernel.findings[0].detection_rule, r->kernel.findings[0].matched_symbol);
            snprintf(app->threat.sha256, sizeof(app->threat.sha256), "%.64s", r->kernel.findings[0].sha256);
            snprintf(app->threat.severity, sizeof(app->threat.severity), "%.15s", kernel_severity_to_string(r->kernel.findings[0].severity));
        } else if (r->initramfs.threats_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "%.60s", r->initramfs.findings[0].threat_name);
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", r->initramfs.findings[0].file_path);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "Pattern: %.50s", r->initramfs.findings[0].matched_pattern);
            snprintf(app->threat.sha256, sizeof(app->threat.sha256), "-");
        } else if (r->preload.threats_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "%.60s", r->preload.findings[0].threat_name);
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", r->preload.findings[0].file_path);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "Target: %.50s", r->preload.findings[0].target_library);
            snprintf(app->threat.sha256, sizeof(app->threat.sha256), "%.64s", r->preload.findings[0].sha256);
        }
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan complete: %d Threats Identified. Check Threat Inspector.", r->total_threats);
    } else if (r->verdict == SCAN_VERDICT_INCOMPLETE) {
        int failed = SCAN_MOD_COUNT - ok_count;
        tui_app_append_log(app, LOG_LEVEL_WARN, NULL, "=== Forensic Scan Finished: INCOMPLETE (not all engines ran) ===");
        snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "Scan Incomplete");
        snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "%d engine(s) failed or skipped", failed);
        snprintf(app->threat.sha256, sizeof(app->threat.sha256), "-");
        snprintf(app->threat.severity, sizeof(app->threat.severity), "INCOMPLETE");
        app->threat.severity_color = MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_DEFAULT, ATTR_BOLD);
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan INCOMPLETE: %d engine(s) failed or skipped. See log.", failed);
    } else {
        tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "=== Forensic Scan Finished: CLEAN (all engines OK, 0 threats) ===");
        snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "No Threats Found");
        snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "%d engine(s) OK", ok_count);
        snprintf(app->threat.sha256, sizeof(app->threat.sha256), "-");
        snprintf(app->threat.severity, sizeof(app->threat.severity), "CLEAN");
        app->threat.severity_color = MAKE_ATTR(COLOR_BRIGHT_GREEN, COLOR_DEFAULT, ATTR_BOLD);
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan complete: CLEAN (%d engine(s) OK, 0 threats).", ok_count);
    }
}

static void export_case_report(tui_app_state_t *app) {
    if (!app->last_scan) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Run a scan first (F5)");
        return;
    }
    char case_id[32];
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    strftime(case_id, sizeof(case_id), "CASE-%Y%m%d-%H%M%S", &tm_utc);
    const char *examiner = getenv("USER");
    if (!examiner || !examiner[0]) examiner = "unknown";

    forensic_case_summary_t sum;
    memset(&sum, 0, sizeof(sum));
    forensic_scan_fill_case_summary(app->last_scan, case_id, examiner, &sum);

    const char *out_dir = "/persistence/cases";
    booto_error_t err = disk_ensure_private_dir(out_dir);
    if (err != BOOTO_OK) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Export failed: cannot create %s (error %d)", out_dir, (int)err);
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, app->status_msg);
        return;
    }

    char saved_json[512] = "";
    char saved_md[512] = "";
    booto_error_t jerr = case_report_generate_json(&sum, out_dir, saved_json, sizeof(saved_json));
    booto_error_t merr = case_report_generate_markdown(&sum, out_dir, saved_md, sizeof(saved_md));
    if (jerr != BOOTO_OK || merr != BOOTO_OK) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Export failed: JSON error %d, Markdown error %d", (int)jerr, (int)merr);
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, app->status_msg);
        return;
    }
    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf), "Exported case report %.31s to %.200s", case_id, saved_md);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, log_buf);
    snprintf(app->status_msg, sizeof(app->status_msg), "Case Report Saved: %.200s", saved_md);
}

/* Quit/power paths: never exit (or free last_scan) under a running worker; block until it finishes. */
static void wait_scan_before_exit(tui_app_state_t *app, int rows, int cols) {
    if (!atomic_load(&app->scan_active)) return;
    snprintf(app->status_msg, sizeof(app->status_msg), "Waiting for the running scan to finish before exiting...");
    render_bottom_bar(app, rows, cols);
    term_present();
    finish_forensic_scan(app);
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
        if (atomic_load(&app.scan_done)) finish_forensic_scan(&app);

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

        // 3. Render Modal Overlays if active
        if (app.show_exit_modal) {
            render_exit_modal(&app, rows, cols);
        } else if (app.show_luks_modal) {
            render_luks_modal(&app, rows, cols);
        }

        // 4. Differential screen flush
        term_present();

        // 5. Input event polling (the timeout keeps the loop redrawing ~20x/s while a scan runs)
        input_event_t event;
        if (term_poll_event(&event, 50)) {
            if (app.show_exit_modal) {
                if (event.type == KEY_CHAR && (event.ch == 'p' || event.ch == 'P' || event.ch == '1')) {
                    wait_scan_before_exit(&app, rows, cols);
                    term_shutdown();
                    int res = system("systemctl poweroff -i 2>/dev/null || poweroff -f 2>/dev/null || halt -p 2>/dev/null");
                    (void)res;
                    exit(0);
                } else if (event.type == KEY_CHAR && (event.ch == 'r' || event.ch == 'R' || event.ch == '2')) {
                    wait_scan_before_exit(&app, rows, cols);
                    term_shutdown();
                    int res = system("systemctl reboot -i 2>/dev/null || reboot -f 2>/dev/null");
                    (void)res;
                    exit(0);
                } else if (event.type == KEY_CHAR && (event.ch == 's' || event.ch == 'S' || event.ch == '3' || event.ch == 'q' || event.ch == 'Q')) {
                    app.running = false;
                } else if (event.type == KEY_ESC || event.type == KEY_F10 || (event.type == KEY_CHAR && (event.ch == 'c' || event.ch == 'C'))) {
                    app.show_exit_modal = false;
                }
                continue;
            }

            if (app.show_luks_modal) {
                if (event.type == KEY_ESC) {
                    app.show_luks_modal = false;
                    memset(app.luks_passphrase_input, 0, sizeof(app.luks_passphrase_input));
                    app.luks_passphrase_len = 0;
                } else if (event.type == KEY_BACKSPACE) {
                    if (app.luks_passphrase_len > 0) {
                        app.luks_passphrase_len--;
                        app.luks_passphrase_input[app.luks_passphrase_len] = '\0';
                    }
                } else if (event.type == KEY_CHAR && event.ch >= 32 && event.ch <= 126) {
                    if (app.luks_passphrase_len < (int)sizeof(app.luks_passphrase_input) - 1) {
                        app.luks_passphrase_input[app.luks_passphrase_len++] = (char)event.ch;
                        app.luks_passphrase_input[app.luks_passphrase_len] = '\0';
                    }
                } else if (event.type == KEY_ENTER) {
                    booto_error_t err = disk_luks_open_ro(app.luks_target_dev, "booto_target_luks", app.luks_passphrase_input);
                    explicit_bzero(app.luks_passphrase_input, sizeof(app.luks_passphrase_input));
                    app.luks_passphrase_len = 0;
                    if (err == BOOTO_OK) {
                        app.luks_unlocked = true;
                        tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, "Successfully unlocked target LUKS volume (READ-ONLY)");
                        snprintf(app.status_msg, sizeof(app.status_msg), "LUKS target unlocked: /dev/mapper/booto_target_luks");

                        // Add mapped volume to drives list and mark as target
                        if (app.drive_count < MAX_DRIVES) {
                            int idx = app.drive_count++;
                            snprintf(app.drives[idx].name, sizeof(app.drives[idx].name), "/dev/mapper/booto_target_luks");
                            snprintf(app.drives[idx].size, sizeof(app.drives[idx].size), "Decrypted");
                            snprintf(app.drives[idx].fs_type, sizeof(app.drives[idx].fs_type), "ext4");
                            snprintf(app.drives[idx].label, sizeof(app.drives[idx].label), "Decrypted Target Rootfs");
                            for (int d = 0; d < app.drive_count - 1; d++) app.drives[d].is_target = false;
                            app.drives[idx].is_target = true;
                            app.drive_cursor = idx;
                        }
                        app.show_luks_modal = false;
                    } else {
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Failed to unlock: Invalid passphrase");
                    }
                }
                continue;
            }

            if (event.type == KEY_F10 || (event.type == KEY_CHAR && (event.ch == 'q' || event.ch == 'Q'))) {
                app.show_exit_modal = true;
            } else if (event.type == KEY_F3 && atomic_load(&app.scan_active)) {
                snprintf(app.status_msg, sizeof(app.status_msg), "Scan in progress: LUKS unlock disabled");
            } else if (event.type == KEY_F3) {
                const char *target = (app.drive_count > 0) ? app.drives[app.drive_cursor].name : "/dev/nvme0n1p3";
                snprintf(app.luks_target_dev, sizeof(app.luks_target_dev), "%s", target);
                app.luks_passphrase_len = 0;
                app.luks_passphrase_input[0] = '\0';
                app.luks_status_msg[0] = '\0';
                app.show_luks_modal = true;
            } else if (event.type == KEY_TAB) {
                wm_focus_next(app.wm);
            } else if (event.type == KEY_ALT_LEFT || event.type == KEY_ALT_RIGHT ||
                       event.type == KEY_ALT_UP || event.type == KEY_ALT_DOWN) {
                wm_focus_direction(app.wm, event.type);
            } else if (event.type == KEY_ALT_Z) {
                wm_toggle_zoom(app.wm);
            } else if (event.type == KEY_ALT_M) {
                // Alt+M carries no direction: swap the focused pane with the next leaf in Tab order.
                wm_node_t *orig = app.wm->focused_leaf;
                wm_focus_next(app.wm);
                wm_node_t *next = app.wm->focused_leaf;
                if (orig && next && next != orig) {
                    pane_type_t tmp_type = orig->pane_type;
                    void *tmp_data = orig->pane_data;
                    orig->pane_type = next->pane_type;
                    orig->pane_data = next->pane_data;
                    next->pane_type = tmp_type;
                    next->pane_data = tmp_data;
                    tui_app_append_log(&app, LOG_LEVEL_INFO, NULL, "Swapped focused pane with next pane (Alt+M)");
                }
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
                start_forensic_scan(&app);
            } else if (event.type == KEY_F6) {
                if (atomic_load(&app.scan_active)) {
                    snprintf(app.status_msg, sizeof(app.status_msg), "Scan in progress");
                } else {
                    export_case_report(&app);
                }
            } else if (event.type == KEY_MOUSE_CLICK) {
                wm_node_t *clicked = wm_find_leaf_at(app.wm->root, event.mouse_x, event.mouse_y);
                if (clicked) {
                    app.wm->focused_leaf = clicked;
                }
            } else if (atomic_load(&app.scan_active) && event.type == KEY_ENTER && app.wm->focused_leaf &&
                       app.wm->focused_leaf->pane_type == PANE_STORAGE_DEVICES) {
                snprintf(app.status_msg, sizeof(app.status_msg), "Scan in progress: mount/unmount and LUKS unlock disabled");
            } else {
                if (app.wm->focused_leaf) {
                    pane_handle_input(app.wm->focused_leaf, &event, &app);
                }
            }
        }
    }

    wait_scan_before_exit(&app, rows, cols);
    logger_set_callback(NULL, NULL);
    g_current_app = NULL;

    wm_tree_destroy(app.wm);
    free(app.last_scan);
    pthread_mutex_destroy(&app.log_lock);
    term_shutdown();
    return 0;
}
