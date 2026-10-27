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

/* Draws s at (*x, y) clipped to end (exclusive) and advances *x. */
static void put_clip(int *x, int y, int end, const char *s, uint32_t attr) {
    if (*x < end) *x += term_puts_clip(*x, y, end - *x, s, attr);
}

static void render_top_bar(tui_app_state_t *app, int cols) {
    char scan[32] = "";
    if (atomic_load(&app->scan_active)) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        snprintf(scan, sizeof(scan), "%c Scanning %d/%d", "|/-\\"[(ts.tv_nsec / 125000000L) % 4],
                 atomic_load(&app->scan_step), (int)SCAN_MOD_COUNT);
    }
    const char *luks = app->luks_unlocked ? "LUKS unlocked" : "LUKS locked";
    const char *ram = "RAM only";

    /* Right side: scan status, "RAM only", LUKS state, two spaces apart. Drop items until "Booto" still fits. */
    int min_left = 1 + 5 + 2;
    int scan_w = scan[0] ? (int)strlen(scan) + 2 : 0;
    int ram_w = (int)strlen(ram) + 2;
    int luks_w = (int)strlen(luks);
    if (min_left + scan_w + ram_w + luks_w > cols - 1) ram_w = 0;
    if (min_left + scan_w + ram_w + luks_w > cols - 1) scan_w = 0;
    if (min_left + scan_w + ram_w + luks_w > cols - 1) luks_w = 0;
    int rw = scan_w + ram_w + luks_w;

    int x = cols - 1 - rw;
    if (scan_w) x += term_puts(x, 0, scan, A_WARN) + 2;
    if (ram_w) x += term_puts(x, 0, ram, A_MUTED) + 2;
    if (luks_w) term_puts(x, 0, luks, app->luks_unlocked ? A_OK : A_BAD);

    int end = cols - 1 - rw - (rw ? 2 : 0);
    x = 1;
    put_clip(&x, 0, end, "Booto", A_STRONG);
    x++;
    put_clip(&x, 0, end, BOOTO_VERSION_STRING, A_MUTED);

    const drive_item_t *t = NULL;
    for (int i = 0; i < app->drive_count; i++) {
        if (app->drives[i].is_target) {
            t = &app->drives[i];
            break;
        }
    }
    x += 2;
    if (!t) {
        put_clip(&x, 0, end, "No target selected", A_MUTED);
        return;
    }
    int head_w = 9; /* "Target ♦ " */
    if (end - x < head_w + 4) return;
    int path_w = (int)strlen(t->name);
    char meta[80];
    snprintf(meta, sizeof(meta), "%.31s %.31s", t->fs_type, t->size);
    bool show_meta = x + head_w + path_w + 2 + (int)strlen(meta) <= end;
    put_clip(&x, 0, end, "Target ", A_MUTED);
    term_put_glyph(x, 0, TERM_G_TARGET, A_TARGET);
    x += 2;
    put_clip(&x, 0, end, t->name, A_TARGET);
    if (show_meta) {
        x += 2;
        put_clip(&x, 0, end, meta, A_MUTED);
    }
}

static void render_bottom_bar(tui_app_state_t *app, int rows, int cols) {
    static const struct {
        const char *key;
        const char *label;
    } hints[] = {
        {" F5 ", " Scan"},       {" F6 ", " Export"}, {" F3 ", " Unlock"},
        {" Tab ", " Next pane"}, {" Alt+Z ", " Zoom"}, {" F10 ", " Exit"},
    };
    enum { HINT_COUNT = (int)(sizeof(hints) / sizeof(hints[0])) };
    static const int drop_order[] = {4, 3, 2, 1}; /* Zoom, Tab, F3, F6; F5 and F10 always stay */
    bool shown[HINT_COUNT];
    int hw = -2;
    for (int i = 0; i < HINT_COUNT; i++) {
        shown[i] = true;
        hw += (int)(strlen(hints[i].key) + strlen(hints[i].label)) + 2;
    }
    int status_w = (int)strlen(app->status_msg);
    for (size_t d = 0; d < sizeof(drop_order) / sizeof(drop_order[0]); d++) {
        if (1 + status_w + 2 + hw <= cols - 1) break;
        int i = drop_order[d];
        shown[i] = false;
        hw -= (int)(strlen(hints[i].key) + strlen(hints[i].label)) + 2;
    }

    int y = rows - 1;
    int hx = cols - 1 - hw;
    if (hx < 1) hx = 1;
    int x = 1;
    put_clip(&x, y, hx - 2, app->status_msg, A_TEXT);

    x = hx;
    for (int i = 0; i < HINT_COUNT; i++) {
        if (!shown[i]) continue;
        put_clip(&x, y, cols - 1, hints[i].key, A_KEYCAP);
        put_clip(&x, y, cols - 1, hints[i].label, A_TEXT);
        x += 2;
    }
}

/* Centres a w x h modal (clamped to the screen), clears it and draws its frame. */
static void modal_frame(int rows, int cols, int w, int h, const char *title, int *mx, int *my, int *mw) {
    if (w > cols) w = cols;
    if (h > rows) h = rows;
    *mx = (cols - w) / 2;
    *my = (rows - h) / 2;
    *mw = w;
    term_fill(*mx, *my, w, h, A_TEXT);
    term_draw_box(*mx, *my, w, h, title, A_FRAME, A_STRONG);
}

/* Draws a keycap and its label at (x, y), clipped to end; returns the x after the label. */
static int modal_key(int x, int y, int end, const char *key, const char *label) {
    put_clip(&x, y, end, key, A_KEYCAP);
    put_clip(&x, y, end, label, A_TEXT);
    return x;
}

static void render_exit_modal(tui_app_state_t *app, int rows, int cols) {
    (void)app;
    int mx, my, mw;
    modal_frame(rows, cols, 40, 9, "Exit", &mx, &my, &mw);
    int end = mx + mw - 2;
    static const struct {
        const char *key;
        const char *label;
        int dy;
    } items[] = {
        {" P ", "Power off", 2},
        {" R ", "Reboot", 3},
        {" S ", "Open a root shell", 4},
        {" Esc ", "Back to Booto", 6},
    };
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        int x = mx + 3;
        put_clip(&x, my + items[i].dy, end, items[i].key, A_KEYCAP);
        x = mx + 3 + 7; /* labels aligned after the widest keycap (" Esc ") */
        put_clip(&x, my + items[i].dy, end, items[i].label, A_TEXT);
    }
}

static void render_luks_modal(tui_app_state_t *app, int rows, int cols) {
    int mx, my, mw;
    modal_frame(rows, cols, 60, 11, "Unlock LUKS volume (read-only)", &mx, &my, &mw);
    int end = mx + mw - 2;

    int x = mx + 3;
    put_clip(&x, my + 2, end, "Device ", A_MUTED);
    put_clip(&x, my + 2, end, app->luks_target_dev, A_STRONG);

    /* Passphrase field: muted underline row, one '*' per character, block cursor. */
    int fx = mx + 3;
    int fw = end - fx;
    if (fw > 0) {
        term_hline(fx, my + 4, fw, A_MUTED);
        int stars = app->luks_passphrase_len < fw - 1 ? app->luks_passphrase_len : fw - 1;
        for (int i = 0; i < stars; i++) term_putc(fx + i, my + 4, '*', A_STRONG);
        term_put_glyph(fx + stars, my + 4, TERM_G_BLOCK, A_STRONG);
    }

    if (app->luks_status_msg[0] != '\0') {
        x = mx + 3;
        put_clip(&x, my + 6, end, app->luks_status_msg, A_BAD);
    }

    x = modal_key(mx + 3, my + 8, end, " Enter ", " Unlock read-only");
    modal_key(x + 3, my + 8, end, " Esc ", " Cancel");
}

static void render_unfocused_leaves(wm_node_t *node, wm_node_t *focused, tui_app_state_t *app) {
    if (!node) return;
    if (node->type == NODE_LEAF) {
        if (node != focused) pane_render(node, false, app);
    } else {
        render_unfocused_leaves(node->left, focused, app);
        render_unfocused_leaves(node->right, focused, app);
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
        snprintf(app->status_msg, sizeof(app->status_msg), "A scan is already running.");
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
        snprintf(app->status_msg, sizeof(app->status_msg), "No target selected. Mark a target in Storage first.");
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
    snprintf(log_buf, sizeof(log_buf), "Scan started on %.120s (read-only).", app->scan_target);
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
    snprintf(app->status_msg, sizeof(app->status_msg), "Scanning %.120s.", app->scan_target);
}

/* Main thread only: joins the worker (blocking if it is still running) and publishes its report. */
static void finish_forensic_scan(tui_app_state_t *app) {
    pthread_join(app->scan_thread, NULL);
    atomic_store(&app->scan_done, false);
    atomic_store(&app->scan_active, false);

    forensic_scan_report_t *r = app->pending_scan;
    app->pending_scan = NULL;
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
    }

    if (r->verdict == SCAN_VERDICT_THREATS) {
        snprintf(log_buf, sizeof(log_buf), "Scan finished: %d threat%s found.", r->total_threats, r->total_threats == 1 ? "" : "s");
        tui_app_append_log(app, LOG_LEVEL_CRITICAL, NULL, log_buf);
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
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan finished: %d threat%s found. See Findings.",
                 r->total_threats, r->total_threats == 1 ? "" : "s");
    } else if (r->verdict == SCAN_VERDICT_INCOMPLETE) {
        int failed = SCAN_MOD_COUNT - ok_count;
        snprintf(log_buf, sizeof(log_buf), "Scan incomplete: %d of %d engines could not run.", failed, (int)SCAN_MOD_COUNT);
        tui_app_append_log(app, LOG_LEVEL_WARN, NULL, log_buf);
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan incomplete: %d engine%s could not run. See Log.",
                 failed, failed == 1 ? "" : "s");
    } else {
        tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Scan finished: no threats found.");
        snprintf(app->status_msg, sizeof(app->status_msg), "Scan finished: no threats found.");
    }
}

static void export_case_report(tui_app_state_t *app) {
    if (!app->last_scan) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Nothing to export yet. Run a scan first.");
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
    snprintf(app->status_msg, sizeof(app->status_msg), "Report saved to %.200s.", saved_md);
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
            // Focused pane last so its border wins on shared edges.
            render_unfocused_leaves(app.wm->root, app.wm->focused_leaf, &app);
            if (app.wm->focused_leaf) pane_render(app.wm->focused_leaf, true, &app);
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
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Could not unlock: wrong passphrase.");
                    }
                }
                continue;
            }

            if (event.type == KEY_F10 || (event.type == KEY_CHAR && (event.ch == 'q' || event.ch == 'Q'))) {
                app.show_exit_modal = true;
            } else if (event.type == KEY_F3 && atomic_load(&app.scan_active)) {
                snprintf(app.status_msg, sizeof(app.status_msg), "LUKS unlock is disabled while a scan runs.");
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
                    snprintf(app.status_msg, sizeof(app.status_msg), "Export is disabled while a scan runs.");
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
                snprintf(app.status_msg, sizeof(app.status_msg), "Mount and LUKS unlock are disabled while a scan runs.");
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
