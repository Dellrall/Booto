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
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static tui_app_state_t *g_current_app = NULL;

#define CTRL_R 18 /* raw-mode byte for Ctrl+R */

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
    if (luks_w) term_puts(x, 0, luks, app->luks_unlocked ? A_OK : A_STRONG); /* locked is the normal start state, not a failure */

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
        key_type_t type;
        int ch;
    } hints[] = {
        {" F5 ", " Scan", KEY_F5, 0},       {" F6 ", " Export", KEY_F6, 0}, {" F3 ", " Unlock", KEY_F3, 0},
        {" Tab ", " Next pane", KEY_TAB, 0}, {" Alt+Z ", " Zoom", KEY_ALT_Z, 0}, {" ^R ", " Resize", KEY_CHAR, CTRL_R},
        {" F10 ", " Exit", KEY_F10, 0},
    };
    enum { HINT_COUNT = (int)(sizeof(hints) / sizeof(hints[0])) };
    static const int drop_order[] = {5, 4, 3, 2, 1}; /* Resize, Zoom, Tab, F3, F6; F5 and F10 always stay */
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
        int x0 = x;
        put_clip(&x, y, cols - 1, hints[i].key, A_KEYCAP);
        put_clip(&x, y, cols - 1, hints[i].label, A_TEXT);
        term_add_click_zone(x0, x, y, hints[i].type, hints[i].ch);
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
static int modal_key(int x, int y, int end, const char *key, const char *label, key_type_t type) {
    int x0 = x;
    put_clip(&x, y, end, key, A_KEYCAP);
    put_clip(&x, y, end, label, A_TEXT);
    term_add_click_zone(x0, x, y, type, 0);
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
        key_type_t type;
        int ch;
    } items[] = {
        {" P ", "Power off", 2, KEY_CHAR, 'p'},
        {" R ", "Reboot", 3, KEY_CHAR, 'r'},
        {" S ", "Open a root shell", 4, KEY_CHAR, 's'},
        {" Esc ", "Back to Booto", 6, KEY_ESC, 0},
    };
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        int x = mx + 3;
        put_clip(&x, my + items[i].dy, end, items[i].key, A_KEYCAP);
        x = mx + 3 + 7; /* labels aligned after the widest keycap (" Esc ") */
        put_clip(&x, my + items[i].dy, end, items[i].label, A_TEXT);
        term_add_click_zone(mx + 3, x, my + items[i].dy, items[i].type, items[i].ch);
    }
}

/* Lines of the Inspect tab: Map = facts, section table and entropy strip; Hex = 16 bytes per line. */
static int inspect_lines(const inspect_sample_t *s, int tab, int width) {
    if (tab == 1) return (int)((s->len + 15) / 16);
    int per = width > 0 ? width : 1;
    int blocks = (int)((s->len + INSPECT_BLOCK - 1) / INSPECT_BLOCK);
    return 7 + 2 + s->region_count + (s->regions_total > s->region_count) + 2 + (blocks + per - 1) / per + 1;
}

static void render_inspect_modal(tui_app_state_t *app, int rows, int cols) {
    const inspect_sample_t *s = &app->last_scan->inspect;
    int mx, my, mw;
    modal_frame(rows, cols, cols, rows - 2, "Inspect (read-only)", &mx, &my, &mw); /* covers every pane, keeps both bars */
    int mh = rows - 2;
    int x0 = mx + 2, end = mx + mw - 2, iw = end - x0;
    int x = x0;
    x = modal_key(x, my + 1, end, " 1 ", " Map ", KEY_CHAR);
    term_add_click_zone(x0, x, my + 1, KEY_CHAR, '1');
    int hx = x + 2;
    x = modal_key(hx, my + 1, end, " 2 ", " Hex ", KEY_CHAR);
    term_add_click_zone(hx, x, my + 1, KEY_CHAR, '2');
    term_puts_clip(app->inspect_tab == 0 ? x0 + 3 : hx + 3, my + 1, 5, app->inspect_tab == 0 ? " Map " : " Hex ",
                   A_CURSOR);
    modal_key(x + 2, my + 1, end, " Esc ", " Close", KEY_ESC);

    int top = my + 3, vis = my + mh - 1 - top;
    if (vis < 1) return;
    int total = inspect_lines(s, app->inspect_tab, iw);
    if (app->inspect_scroll > total - vis) app->inspect_scroll = total - vis;
    if (app->inspect_scroll < 0) app->inspect_scroll = 0;
    int first = app->inspect_scroll;
    char line[256];
#define LINE(i, text, attr) do { int r_ = (i) - first; if (r_ >= 0 && r_ < vis) term_puts_clip(x0, top + r_, iw, text, attr); } while (0)
    if (app->inspect_tab == 1) {
        for (int r = 0; r < vis && first + r < total; r++) {
            inspect_hex_row(s, (size_t)(first + r) * 16, line, sizeof(line));
            term_puts_clip(x0, top + r, iw, line, A_TEXT);
        }
    } else {
        int i = 0;
        snprintf(line, sizeof(line), "File     %.200s", s->path);
        LINE(i, line, A_STRONG); i++;
        snprintf(line, sizeof(line), "Format   %s", s->format);
        LINE(i, line, A_TEXT); i++;
        snprintf(line, sizeof(line), "Size     %llu bytes", (unsigned long long)s->file_size);
        LINE(i, line, A_TEXT); i++;
        snprintf(line, sizeof(line), "SHA-256  %s", s->sha256);
        LINE(i, line, A_TEXT); i++;
        snprintf(line, sizeof(line), "MD5      %s", s->md5);
        LINE(i, line, A_TEXT); i++;
        if (s->hashed_len < s->file_size)
            snprintf(line, sizeof(line), "Hashes cover the first %llu bytes only.", (unsigned long long)s->hashed_len);
        else
            snprintf(line, sizeof(line), "Hashes cover the whole file.");
        LINE(i, line, A_MUTED); i++;
        i++;
        LINE(i, "Sections", A_MUTED); i++;
        LINE(i, "Name                 Offset      Size        Entropy  Code", A_MUTED); i++;
        for (int k = 0; k < s->region_count; k++, i++) {
            const inspect_region_t *g = &s->regions[k];
            snprintf(line, sizeof(line), "%-20.20s %08llx    %-10llu  %4.2f     %s", g->name,
                     (unsigned long long)g->offset, (unsigned long long)g->size, g->entropy, g->exec ? "yes" : "");
            /* Over 7.2 bits/byte is packed or encrypted data; in code that is how bootkits hide a payload. */
            LINE(i, line, g->entropy > 7.2 ? A_WARN : A_TEXT);
        }
        if (s->region_count == 0) { LINE(i, "No section table: raw data.", A_TEXT); i++; }
        if (s->regions_total > s->region_count) {
            snprintf(line, sizeof(line), "+%d more not shown", s->regions_total - s->region_count);
            LINE(i, line, A_MUTED); i++;
        }
        i++;
        snprintf(line, sizeof(line), "Entropy map: one cell per %u KiB of the first %zu KiB (' ' = 0 bits, '@' = 8 bits)",
                 INSPECT_BLOCK / 1024, (s->len + 1023) / 1024);
        LINE(i, line, A_MUTED); i++;
        size_t blocks = (s->len + INSPECT_BLOCK - 1) / INSPECT_BLOCK, per = (size_t)(iw > 0 ? iw : 1);
        for (size_t b = 0; b < blocks; b += per, i++) {
            int r = i - first;
            if (r < 0 || r >= vis) continue;
            for (size_t c = 0; c < per && b + c < blocks; c++) {
                double e = inspect_block_entropy(s, b + c);
                term_putc(x0 + (int)c, top + r, inspect_entropy_char(e), e > 7.2 ? A_WARN : A_TEXT);
            }
        }
    }
#undef LINE
    if (first > 0) term_puts_clip(end - 1, top, 1, "^", A_MUTED);
    if (first + vis < total) term_puts_clip(end - 1, top + vis - 1, 1, "v", A_MUTED);
}

/* Inspect keys: 1/2/Tab switch tabs, arrows or j/k scroll a line, PgUp/PgDn a page, Home/End or g/G the ends. */
static void inspect_input(tui_app_state_t *app, const input_event_t *ev, int rows) {
    int page = rows - 6 > 1 ? rows - 6 : 1, c = ev->type == KEY_CHAR ? ev->ch : 0;
    if (ev->type == KEY_ESC || c == 'q') app->show_inspect = false;
    else if (c == '1' || c == '2') { app->inspect_tab = c - '1'; app->inspect_scroll = 0; }
    else if (ev->type == KEY_TAB) { app->inspect_tab ^= 1; app->inspect_scroll = 0; }
    else if (ev->type == KEY_UP || ev->type == KEY_MOUSE_WHEEL_UP || c == 'k') app->inspect_scroll -= ev->type == KEY_MOUSE_WHEEL_UP ? 3 : 1;
    else if (ev->type == KEY_DOWN || ev->type == KEY_MOUSE_WHEEL_DOWN || c == 'j') app->inspect_scroll += ev->type == KEY_MOUSE_WHEEL_DOWN ? 3 : 1;
    else if (ev->type == KEY_PGUP) app->inspect_scroll -= page;
    else if (ev->type == KEY_PGDN || c == ' ') app->inspect_scroll += page;
    else if (ev->type == KEY_HOME || c == 'g') app->inspect_scroll = 0;
    else if (ev->type == KEY_END || c == 'G') app->inspect_scroll = 1 << 30; /* clamped at the next render */
}

static void render_luks_modal(tui_app_state_t *app, int rows, int cols) {
    bool persist = app->luks_modal_for_persist;
    int mx, my, mw;
    modal_frame(rows, cols, 60, 11, persist ? "Unlock report storage" : "Unlock LUKS volume (read-only)", &mx, &my, &mw);
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

    x = modal_key(mx + 3, my + 8, end, " Enter ", persist ? " Unlock" : " Unlock read-only", KEY_ENTER);
    modal_key(x + 3, my + 8, end, " Esc ", persist ? " Skip (reports stay in RAM)" : " Cancel", KEY_ESC);
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
    if (strncmp(name, "Package", 7) == 0) return SCAN_MOD_PKG;
    return SCAN_MOD_COUNT;
}

/* Worker thread: touches only its own pending_* / scan_* inputs, the log (locked) and the atomics. */
static void *scan_worker(void *arg) {
    tui_app_state_t *app = arg;
    app->pending_err = forensic_scan_run(app->scan_target, NULL, app->scan_enabled,
                                         app->scan_quarantine_dir[0] ? app->scan_quarantine_dir : NULL, scan_progress_cb, app,
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
    app->scan_quarantine_dir[0] = '\0';
    if (app->quarantine) {
        if (!persistence_is_unlocked(&app->persist)) {
            tui_app_append_log(app, LOG_LEVEL_WARN, NULL, "Quarantine needs report storage (F4); scanning without it");
        } else {
            snprintf(app->scan_quarantine_dir, sizeof(app->scan_quarantine_dir), "%s/quarantine", app->persist.mount_path);
            if (disk_ensure_private_dir(app->scan_quarantine_dir) != BOOTO_OK) {
                snprintf(log_buf, sizeof(log_buf), "Unsafe or unusable quarantine directory %.150s; scanning without it",
                         app->scan_quarantine_dir);
                tui_app_append_log(app, LOG_LEVEL_WARN, NULL, log_buf);
                app->scan_quarantine_dir[0] = '\0';
            }
        }
    }
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
    app->pane_scroll[PANE_THREAT_INSPECTOR] = 0;
    app->show_inspect = false;
    if (r->quarantine_zip[0]) {
        snprintf(log_buf, sizeof(log_buf), "Quarantined %d file%s to %.180s (ZIP password \"infected\").", r->quarantined,
                 r->quarantined == 1 ? "" : "s", r->quarantine_zip);
        tui_app_append_log(app, LOG_LEVEL_WARN, NULL, log_buf);
    } else if (r->quarantined < 0) {
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, "Quarantine archive could not be finished");
    }

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
            snprintf(app->threat.severity, sizeof(app->threat.severity), "%.15s", booto_severity_str(r->mbr.findings[0].severity));
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
            snprintf(app->threat.severity, sizeof(app->threat.severity), "%.15s", booto_severity_str(r->kernel.findings[0].severity));
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
        } else if (r->pkg.threats_detected > 0) {
            snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "Modified package file");
            snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "%.120s", r->pkg.findings[0].file_path);
            snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "%.30s (%.25s)", r->pkg.findings[0].reason,
                     r->pkg.findings[0].package);
            const char *h = r->pkg.findings[0].actual_hash;
            if (strlen(h) == 32) snprintf(app->threat.sha256, sizeof(app->threat.sha256), "MD5 %.32s", h);
            else snprintf(app->threat.sha256, sizeof(app->threat.sha256), "%.64s", h);
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
    forensic_case_summary_t sum;
    forensic_scan_fill_case_summary(app->last_scan, NULL, NULL, &sum);

    bool on_usb = persistence_is_unlocked(&app->persist);
    const char *out_dir = app->persist.cases_dir;
    booto_error_t err = disk_ensure_private_dir(out_dir);
    if (err != BOOTO_OK) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Export failed: cannot create %.150s (error %d)", out_dir, (int)err);
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
    snprintf(log_buf, sizeof(log_buf), "Exported case report %.63s to %.200s", sum.case_id, saved_md);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, log_buf);
    snprintf(app->status_msg, sizeof(app->status_msg), "Report saved to %.180s%s", saved_md,
             on_usb ? "." : " (RAM only: lost at power-off, press F4 to unlock storage).");
}

static void open_persist_modal(tui_app_state_t *app) {
    snprintf(app->luks_target_dev, sizeof(app->luks_target_dev), "%s", app->persist.dev_path);
    app->luks_passphrase_len = 0;
    app->luks_passphrase_input[0] = '\0';
    app->luks_status_msg[0] = '\0';
    app->luks_modal_for_persist = true;
    app->show_luks_modal = true;
}

static void report_persist_result(tui_app_state_t *app, booto_error_t err) {
    if (err == BOOTO_OK) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Report storage ready: %.150s, %llu MiB free.",
                 app->persist.cases_dir, (unsigned long long)(app->persist.free_bytes >> 20));
        tui_app_append_log(app, LOG_LEVEL_INFO, NULL, app->status_msg);
    } else {
        snprintf(app->status_msg, sizeof(app->status_msg), "Report storage %s not mounted (error %d); reports stay in RAM.",
                 app->persist.dev_path, (int)err);
        tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, app->status_msg);
    }
}

/* Runs an interactive shell on a clean screen and returns to the TUI when it exits; scans keep running. */
static bool run_shell(void) {
    term_shutdown();
    static const char banner[] = "\033[2J\033[HBooto root shell. Type 'exit' to return to Booto.\n\n";
    ssize_t w = write(STDOUT_FILENO, banner, sizeof(banner) - 1);
    (void)w;

    /* Like system(): the shell owns Ctrl-C while it runs, so Booto must not die from it. */
    struct sigaction ign, old_int, old_quit, old_ttou;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGINT, &ign, &old_int);
    sigaction(SIGQUIT, &ign, &old_quit);

    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);
        /* getty sends Booto's stderr to the journal; bash -i draws its prompt and echo on stderr. */
        dup2(STDOUT_FILENO, STDERR_FILENO);
        execl("/bin/bash", "bash", "-i", (char *)NULL);
        execl("/bin/sh", "sh", "-i", (char *)NULL);
        _exit(127);
    }
    if (pid > 0) {
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    /* bash -i makes itself the terminal's foreground group; take it back or the next tty read stops Booto. */
    sigaction(SIGTTOU, &ign, &old_ttou);
    tcsetpgrp(STDIN_FILENO, getpgrp());
    sigaction(SIGTTOU, &old_ttou, NULL);
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGQUIT, &old_quit, NULL);
    return term_init() == 0; /* re-entering resets the front buffer, so the next frame repaints fully */
}

/* Quit/power paths: never exit (or free last_scan) under a running worker; block until it finishes,
 * then unmount report storage so no report is lost when the USB is pulled. */
static void prepare_exit(tui_app_state_t *app, int rows, int cols) {
    if (atomic_load(&app->scan_active)) {
        snprintf(app->status_msg, sizeof(app->status_msg), "Waiting for the running scan to finish before exiting...");
        render_bottom_bar(app, rows, cols);
        term_present();
        finish_forensic_scan(app);
    }
    persistence_lock(&app->persist);
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

    // Report storage: encrypted -> ask for the passphrase now (Esc skips); plain -> mount without asking.
    if (persistence_init(&app.persist, NULL) == BOOTO_OK && app.persist.state == PERSISTENCE_STATE_LOCKED) {
        if (app.persist.encrypted) open_persist_modal(&app);
        else report_persist_result(&app, persistence_unlock(&app.persist, NULL));
    }

    bool resize_mode = false;
    wm_node_t *drag_split = NULL; /* split whose border the mouse is dragging */
    int drag_dx = 0, drag_dy = 0; /* border minus grab cell: a grab beside the border must not jump it */
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

        // Border under the pointer: <-> or up-down arrow pointer; the dragged one also lights up.
        bool modal = app.show_exit_modal || app.show_luks_modal || app.show_inspect;
        int px, py;
        wm_node_t *hover = drag_split;
        if (!hover && !modal && !app.wm->zoomed_leaf && term_get_pointer(&px, &py))
            hover = wm_find_divider_at(app.wm->root, px, py);
        if (drag_split) {
            const wm_node_t *a = drag_split->left;
            if (drag_split->split_dir == SPLIT_VERTICAL) term_vline(a->x + a->w - 1, drag_split->y, drag_split->h, A_DRAG);
            else term_hline(drag_split->x, a->y + a->h - 1, drag_split->w, A_DRAG);
        }
        term_set_pointer_glyph(!hover ? 0 : hover->split_dir == SPLIT_VERTICAL ? TERM_G_ARROW_LR : TERM_G_ARROW_UD);

        // 3. Render Modal Overlays if active
        if (app.show_exit_modal) {
            render_exit_modal(&app, rows, cols);
        } else if (app.show_luks_modal) {
            render_luks_modal(&app, rows, cols);
        } else if (app.show_inspect) {
            render_inspect_modal(&app, rows, cols);
        }

        // 4. Differential screen flush
        term_present();

        // 5. Input event polling (the timeout keeps the loop redrawing ~20x/s while a scan runs)
        input_event_t event;
        if (term_poll_event(&event, 50)) {
            term_apply_click_zone(&event); /* bottom-bar hints and modal buttons act as their keys */
            if (app.show_exit_modal) {
                if (event.type == KEY_CHAR && (event.ch == 'p' || event.ch == 'P' || event.ch == '1')) {
                    prepare_exit(&app, rows, cols);
                    term_shutdown();
                    int res = system("systemctl poweroff -i 2>/dev/null || poweroff -f 2>/dev/null || halt -p 2>/dev/null");
                    (void)res;
                    exit(0);
                } else if (event.type == KEY_CHAR && (event.ch == 'r' || event.ch == 'R' || event.ch == '2')) {
                    prepare_exit(&app, rows, cols);
                    term_shutdown();
                    int res = system("systemctl reboot -i 2>/dev/null || reboot -f 2>/dev/null");
                    (void)res;
                    exit(0);
                } else if (event.type == KEY_CHAR && (event.ch == 's' || event.ch == 'S' || event.ch == '3')) {
                    app.show_exit_modal = false;
                    if (!run_shell()) app.running = false;
                } else if (event.type == KEY_CHAR && (event.ch == 'q' || event.ch == 'Q')) {
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
                    if (app.luks_modal_for_persist) {
                        snprintf(app.status_msg, sizeof(app.status_msg),
                                 "Report storage locked: reports stay in RAM. Press F4 to unlock it.");
                    }
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
                } else if (event.type == KEY_ENTER && app.luks_modal_for_persist) {
                    booto_error_t err = persistence_unlock(&app.persist, app.luks_passphrase_input);
                    explicit_bzero(app.luks_passphrase_input, sizeof(app.luks_passphrase_input));
                    app.luks_passphrase_len = 0;
                    if (err == BOOTO_ERR_PERMISSION_DENIED && disk_is_running_as_root()) {
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Could not unlock: wrong passphrase.");
                    } else {
                        app.show_luks_modal = false;
                        report_persist_result(&app, err);
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
                    } else if (err == BOOTO_ERR_PERMISSION_DENIED && disk_is_running_as_root()) {
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Could not unlock: wrong passphrase.");
                    } else if (err == BOOTO_ERR_PERMISSION_DENIED) {
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Could not unlock: Booto must run as root.");
                    } else {
                        snprintf(app.luks_status_msg, sizeof(app.luks_status_msg), "Could not unlock: cryptsetup failed (see Logs).");
                    }
                }
                continue;
            }

            if (app.show_inspect) {
                inspect_input(&app, &event, rows);
                continue;
            }

            bool mouse = event.type == KEY_MOUSE_CLICK || event.type == KEY_MOUSE_WHEEL_UP ||
                         event.type == KEY_MOUSE_WHEEL_DOWN || event.type == KEY_MOUSE_DRAG || event.type == KEY_MOUSE_RELEASE;
            if (!mouse) drag_split = NULL; /* a key may split panes; never hold a split pointer across it */
            if (resize_mode && !mouse) {
                /* Ctrl+R mode: h/j/k/l or arrows move the focused pane's border 1 cell, H/J/K/L by 5. */
                int c = event.type == KEY_CHAR ? event.ch : 0;
                key_type_t dir = c == 'h' || c == 'H' ? KEY_LEFT : c == 'l' || c == 'L' ? KEY_RIGHT
                               : c == 'k' || c == 'K' ? KEY_UP : c == 'j' || c == 'J' ? KEY_DOWN
                               : (event.type >= KEY_UP && event.type <= KEY_RIGHT) ? event.type : KEY_NONE;
                if (dir != KEY_NONE) {
                    if (!wm_resize_focused(app.wm, dir, c >= 'A' && c <= 'Z' ? 5 : 1))
                        snprintf(app.status_msg, sizeof(app.status_msg), "No border to move that way%s.",
                                 app.wm->zoomed_leaf ? " while zoomed (Alt+Z)" : "");
                } else if (event.type == KEY_ESC || event.type == KEY_ENTER || c == CTRL_R || c == 'q') {
                    resize_mode = false;
                    snprintf(app.status_msg, sizeof(app.status_msg), "Layout kept.");
                }
                continue;
            }

            if (event.type == KEY_CHAR && event.ch == CTRL_R) {
                resize_mode = true;
                snprintf(app.status_msg, sizeof(app.status_msg),
                         "Resize: h/j/k/l move the border, H/J/K/L by 5, Esc when done.");
            } else if (event.type == KEY_F10 || (event.type == KEY_CHAR && (event.ch == 'q' || event.ch == 'Q'))) {
                app.show_exit_modal = true;
            } else if (event.type == KEY_F3 && atomic_load(&app.scan_active)) {
                snprintf(app.status_msg, sizeof(app.status_msg), "LUKS unlock is disabled while a scan runs.");
            } else if (event.type == KEY_F3 && app.luks_unlocked) {
                snprintf(app.status_msg, sizeof(app.status_msg), "A LUKS volume is already unlocked at /dev/mapper/booto_target_luks.");
            } else if (event.type == KEY_F3 && app.drive_count == 0) {
                snprintf(app.status_msg, sizeof(app.status_msg), "No drives found to unlock.");
            } else if (event.type == KEY_F3 && strcmp(app.drives[app.drive_cursor].fs_type, "crypto_LUKS") != 0) {
                snprintf(app.status_msg, sizeof(app.status_msg), "%.200s is not an encrypted (LUKS) volume.", app.drives[app.drive_cursor].name);
            } else if (event.type == KEY_F3) {
                snprintf(app.luks_target_dev, sizeof(app.luks_target_dev), "%s", app.drives[app.drive_cursor].name);
                app.luks_passphrase_len = 0;
                app.luks_passphrase_input[0] = '\0';
                app.luks_status_msg[0] = '\0';
                app.luks_modal_for_persist = false;
                app.show_luks_modal = true;
            } else if (event.type == KEY_F4) {
                if (persistence_is_unlocked(&app.persist)) {
                    snprintf(app.status_msg, sizeof(app.status_msg), "Report storage is already mounted at %.150s.", app.persist.mount_path);
                } else if (app.persist.state == PERSISTENCE_STATE_ABSENT) {
                    snprintf(app.status_msg, sizeof(app.status_msg), "No %s partition on the boot USB; reports stay in RAM.", PERSISTENCE_PART_LABEL);
                } else if (app.persist.encrypted) {
                    open_persist_modal(&app);
                } else {
                    report_persist_result(&app, persistence_unlock(&app.persist, NULL));
                }
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
            } else if (event.type == KEY_F7) {
                app.quarantine = !app.quarantine;
                snprintf(app.status_msg, sizeof(app.status_msg), "Quarantine %s for the next scan.",
                         app.quarantine ? "on: flagged files go to an encrypted ZIP on report storage" : "off");
            } else if (event.type == KEY_F6) {
                if (atomic_load(&app.scan_active)) {
                    snprintf(app.status_msg, sizeof(app.status_msg), "Export is disabled while a scan runs.");
                } else {
                    export_case_report(&app);
                }
            } else if (event.type == KEY_MOUSE_DRAG || event.type == KEY_MOUSE_RELEASE) {
                /* Live drag where the terminal reports motion; the Linux console sends only the release, which still lands it. */
                if (drag_split) wm_move_divider(app.wm, drag_split, event.mouse_x + drag_dx, event.mouse_y + drag_dy);
                if (event.type == KEY_MOUSE_RELEASE) drag_split = NULL;
            } else if (mouse) {
                wm_node_t *border = event.type == KEY_MOUSE_CLICK && event.mouse_btn == 0 && !app.wm->zoomed_leaf
                                        ? wm_find_divider_at(app.wm->root, event.mouse_x, event.mouse_y) : NULL;
                wm_node_t *hit = border ? NULL : wm_find_leaf_at(app.wm->root, event.mouse_x, event.mouse_y);
                drag_split = border;
                if (border) {
                    const wm_node_t *a = border->left;
                    bool vert = border->split_dir == SPLIT_VERTICAL;
                    drag_dx = vert ? a->x + a->w - 1 - event.mouse_x : 0;
                    drag_dy = vert ? 0 : a->y + a->h - 1 - event.mouse_y;
                }
                if (hit) {
                    app.wm->focused_leaf = hit;
                    if (event.type != KEY_MOUSE_CLICK) {
                        input_event_t step = {.type = event.type == KEY_MOUSE_WHEEL_UP ? KEY_UP : KEY_DOWN};
                        pane_handle_input(hit, &step, &app);
                    } else if (event.mouse_btn == 0) {
                        pane_handle_click(hit, event.mouse_x, event.mouse_y, &app);
                    }
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

    prepare_exit(&app, rows, cols);
    logger_set_callback(NULL, NULL);
    g_current_app = NULL;

    wm_tree_destroy(app.wm);
    free(app.last_scan);
    pthread_mutex_destroy(&app.log_lock);
    term_shutdown();
    return 0;
}
