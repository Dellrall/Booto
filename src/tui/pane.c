/**
 * @file pane.c
 * @brief Implementations of TUI pane renderers and interactive handlers.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "tui/pane.h"
#include "disk_mount.h"
#include "logger.h"
#include "firmware_auditor.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Modules are listed in scan_module_id_t order, so modules[i] is engine i. */
static const struct {
    const char *name;
    const char *path;
} MODULE_DEFS[] = {
    {"MBR/VBR boot code", "sector 0, track 0 gap, VBRs"},
    {"UEFI boot files", "/boot/efi"},
    {"Kernel modules", "/lib/modules"},
    {"Initramfs scripts", "/boot/initrd.img*"},
    {"LD_PRELOAD & load hooks", "ld.so.preload, modprobe.d, udev"},
    {"Package integrity", "dpkg md5sums, pacman mtree"},
    {"Windows boot files", "winload, ntoskrnl, drivers"},
};

void tui_app_state_init(tui_app_state_t *app, booto_context_t *ctx) {
    if (!app) return;
    memset(app, 0, sizeof(*app));
    pthread_mutex_init(&app->log_lock, NULL);
    atomic_init(&app->scan_active, false);
    atomic_init(&app->scan_done, false);
    atomic_init(&app->scan_step, 0);
    app->ctx = ctx;
    app->running = true;
    app->luks_unlocked = false;
    snprintf(app->status_msg, sizeof(app->status_msg), "Select a target in Storage, then press F5 to scan.");

    // Dynamic Storage Discovery via disk_mount.c
    disk_discovery_result_t disk_res;
    disk_discover_partitions(&disk_res, ctx ? ctx->mock_drives : false);

    app->drive_count = (disk_res.count > MAX_DRIVES) ? MAX_DRIVES : disk_res.count;
    app->drive_cursor = 0;

    for (int i = 0; i < app->drive_count; i++) {
        snprintf(app->drives[i].name, sizeof(app->drives[i].name), "%s", disk_res.partitions[i].dev_path);
        snprintf(app->drives[i].size, sizeof(app->drives[i].size), "%s", disk_res.partitions[i].size_str);
        snprintf(app->drives[i].fs_type, sizeof(app->drives[i].fs_type), "%s", disk_res.partitions[i].fs_type);
        snprintf(app->drives[i].label, sizeof(app->drives[i].label), "%s", disk_res.partitions[i].label);
        app->drives[i].is_target = disk_res.partitions[i].is_target;
        app->drives[i].is_ro_mounted = false;
    }

    app->module_count = (int)(sizeof(MODULE_DEFS) / sizeof(MODULE_DEFS[0]));
    app->module_cursor = 0;
    for (int i = 0; i < app->module_count; i++) {
        snprintf(app->modules[i].name, sizeof(app->modules[i].name), "%s", MODULE_DEFS[i].name);
        snprintf(app->modules[i].target_path, sizeof(app->modules[i].target_path), "%s", MODULE_DEFS[i].path);
        app->modules[i].enabled = true;
    }

    char found[96];
    snprintf(found, sizeof(found), "Found %d disks and partitions. Select a target and press F5.", app->drive_count);
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Booto started. Running from RAM; nothing is written to disks.");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Persistence is locked.");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, found);
}

void tui_app_append_log(tui_app_state_t *app, log_level_t level, const char *timestamp, const char *msg) {
    if (!app) return;
    pthread_mutex_lock(&app->log_lock);
    int idx = (app->log_head + app->log_count) % MAX_LOG_LINES;
    if (app->log_count == MAX_LOG_LINES) {
        app->log_head = (app->log_head + 1) % MAX_LOG_LINES;
    } else {
        app->log_count++;
    }

    log_entry_t *entry = &app->log_ring[idx];
    if (timestamp) {
        /* Keep the trailing HH:MM:SS of a full "YYYY-MM-DD HH:MM:SS" logger timestamp. */
        size_t tl = strlen(timestamp);
        snprintf(entry->timestamp, sizeof(entry->timestamp), "%s", tl > 8 ? timestamp + tl - 8 : timestamp);
    } else {
        time_t now = time(NULL);
        struct tm tm;
        if (!localtime_r(&now, &tm) || strftime(entry->timestamp, sizeof(entry->timestamp), "%H:%M:%S", &tm) == 0)
            snprintf(entry->timestamp, sizeof(entry->timestamp), "--:--:--");
    }
    snprintf(entry->msg, sizeof(entry->msg), "%s", msg ? msg : "");
    entry->level = level;
    pthread_mutex_unlock(&app->log_lock);
}

/* ---- shared drawing helpers ---- */

static void draw_frame(const wm_node_t *n, bool focused, const char *title) {
    term_draw_box(n->x, n->y, n->w, n->h, title, focused ? A_FRAME : A_MUTED, focused ? A_STRONG : A_TEXT);
}

/* The cursor row reverses each cell instead of repainting it, so a target, a failure or a count keeps its color. */
static uint32_t row_attr(bool cursor_row, uint32_t attr) {
    return cursor_row ? (attr & ~(uint32_t)ATTR_DIM) | ATTR_REVERSE : attr;
}

/* First visible index of a list so that `cursor` stays on screen. */
static int list_first(int cursor, int vis) {
    int first = cursor - vis + 1;
    return first > 0 ? first : 0;
}

/* Scroll indicators live in the last inner column of the first/last visible row, never on the border. */
static void draw_scroll_marks(const wm_node_t *n, int top, int vis, bool up, bool down, int cursor_row) {
    int cx = n->x + n->w - 3;
    if (up) term_put_glyph(cx, top, TERM_G_UP, row_attr(top == cursor_row, A_MUTED));
    if (down) term_put_glyph(cx, top + vis - 1, TERM_G_DOWN, row_attr(top + vis - 1 == cursor_row, A_MUTED));
}

static const char *const STATUS_WORD[] = {"not run", "ok", "error", "skipped"};

static const char *status_word(scan_status_t s) {
    return (unsigned)s <= (unsigned)SCAN_STATUS_SKIPPED ? STATUS_WORD[s] : "unknown";
}

static uint32_t status_attr(scan_status_t s) {
    switch (s) {
        case SCAN_STATUS_OK: return A_OK;
        case SCAN_STATUS_ERROR: return A_BAD;
        case SCAN_STATUS_SKIPPED: return A_WARN;
        default: return A_MUTED;
    }
}

static uint32_t severity_attr(booto_severity_t s) {
    return s >= SEVERITY_HIGH ? A_BAD : s == SEVERITY_MEDIUM ? A_WARN : A_MUTED;
}

/* ---- panes ---- */

static void render_storage_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Storage");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1;
    if (iw <= 0 || n->h < 3) return;

    if (app->drive_count == 0) {
        term_puts_clip(x0, top, iw, "No disks found. Run as root, or start with -m for test drives.", A_MUTED);
        return;
    }

    /* marker(2) device fs size label; Label goes first when narrow, then FS. */
    int size_w = 9, fs_w = 7, label_w = 0;
    int dev_w = iw - 2 - fs_w - size_w;
    if (dev_w > 16) {
        label_w = dev_w - 16;
        dev_w = 16;
        if (label_w < 6) {
            dev_w += label_w;
            label_w = 0;
        }
    }
    if (dev_w < 8) {
        dev_w += fs_w;
        fs_w = 0;
    }
    int dev_x = x0 + 2, fs_x = dev_x + dev_w, size_x = fs_x + fs_w, label_x = size_x + size_w;
    int size_cw = label_w ? size_w - 1 : right - size_x;

    term_puts_clip(x0, top, 2 + dev_w - 1, "Device", A_MUTED);
    if (fs_w) term_puts_clip(fs_x, top, fs_w - 1, "FS", A_MUTED);
    term_puts_clip(size_x, top, size_cw, "Size", A_MUTED);
    if (label_w) term_puts_clip(label_x, top, right - label_x, "Label", A_MUTED);

    int vis = n->h - 3;
    if (vis <= 0) return;
    int first = list_first(app->drive_cursor, vis);
    int cursor_row = -1;
    for (int r = 0; r < vis && first + r < app->drive_count; r++) {
        const drive_item_t *d = &app->drives[first + r];
        int y = top + 1 + r;
        bool cur = focused && first + r == app->drive_cursor;
        if (cur) {
            cursor_row = y;
            term_fill(n->x + 1, y, n->w - 2, 1, A_CURSOR);
        }
        if (d->is_target) term_put_glyph(x0, y, TERM_G_TARGET, row_attr(cur, A_TARGET));
        const char *name = strncmp(d->name, "/dev/", 5) == 0 ? d->name + 5 : d->name;
        term_puts_clip(dev_x, y, dev_w - 1, name, row_attr(cur, d->is_target ? A_TARGET : A_TEXT));
        if (fs_w) {
            bool unknown = strcmp(d->fs_type, "unknown") == 0 || d->fs_type[0] == '\0';
            term_puts_clip(fs_x, y, fs_w - 1, unknown ? "-" : d->fs_type, row_attr(cur, unknown ? A_MUTED : A_TEXT));
        }
        term_puts_clip(size_x, y, size_cw, d->size, row_attr(cur, A_MUTED));
        if (label_w) {
            term_puts_clip(label_x, y, right - label_x, d->is_ro_mounted ? "mounted RO" : d->label,
                           row_attr(cur, d->is_ro_mounted ? A_OK : A_TEXT));
        }
    }
    draw_scroll_marks(n, top + 1, vis, first > 0, first + vis < app->drive_count, cursor_row);
}

static void render_modules_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Engines");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1, vis = n->h - 2;
    if (iw <= 0 || vis <= 0) return;

    bool scanning = atomic_load(&app->scan_active);
    int step = atomic_load(&app->scan_step);
    if (step < 1) step = 1;
    const forensic_scan_report_t *rep = app->last_scan;

    int first = list_first(app->module_cursor, vis);
    int cursor_row = -1;
    for (int r = 0; r < vis && first + r < app->module_count; r++) {
        int i = first + r;
        const module_item_t *m = &app->modules[i];
        int y = top + r;
        bool cur = focused && i == app->module_cursor;
        if (cur) {
            cursor_row = y;
            term_fill(n->x + 1, y, n->w - 2, 1, A_CURSOR);
        }

        const char *word = "ready";
        uint32_t word_attr = A_MUTED;
        int found = 0;
        if (!m->enabled) {
            word = "off";
        } else if (scanning) {
            if (i + 1 == step) {
                word = "running";
                word_attr = A_WARN;
            } else {
                word = i + 1 > step ? "queued" : "done";
            }
        } else if (rep && i < SCAN_MOD_COUNT) {
            word = status_word(rep->status[i]);
            word_attr = status_attr(rep->status[i]);
            found = forensic_scan_module_threats(rep, (scan_module_id_t)i);
        }

        char cnt[24] = "";
        if (found > 0) snprintf(cnt, sizeof(cnt), "%d found", found);
        int res_w = (int)strlen(word) + (cnt[0] ? 1 + (int)strlen(cnt) : 0);
        int rx = right - res_w;
        if (rx < x0 + 2) rx = x0 + 2;

        if (m->enabled) term_put_glyph(x0, y, TERM_G_SQUARE, row_attr(cur, A_TEXT));
        else term_put_glyph(x0, y, TERM_G_DOT, row_attr(cur, A_MUTED));
        term_puts_clip(x0 + 2, y, rx - 1 - (x0 + 2), m->name, row_attr(cur, A_TEXT));
        int wn = term_puts_clip(rx, y, right - rx, word, row_attr(cur, word_attr));
        if (cnt[0]) term_puts_clip(rx + wn + 1, y, right - (rx + wn + 1), cnt, row_attr(cur, A_BAD));
    }
    draw_scroll_marks(n, top, vis, first > 0, first + vis < app->module_count, cursor_row);
}

static const char *const LEVEL_WORD[] = {"debug", "info", "warn", "error", "crit"};

static void render_logs_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    pthread_mutex_lock(&app->log_lock);
    char title[32];
    snprintf(title, sizeof(title), "Log (%d)", app->log_count);
    draw_frame(n, focused, title);

    int x0 = n->x + 2, right = x0 + n->w - 4, top = n->y + 1, vis = n->h - 2;
    if (right > x0 && vis > 0) {
        int start = app->log_count - vis - app->log_scroll;
        if (start < 0) start = 0;
        for (int i = 0; i < vis && start + i < app->log_count; i++) {
            const log_entry_t *e = &app->log_ring[(app->log_head + start + i) % MAX_LOG_LINES];
            int y = top + i;
            bool known = (unsigned)e->level <= (unsigned)LOG_LEVEL_CRITICAL;
            bool severe = e->level >= LOG_LEVEL_ERROR;
            uint32_t level_attr = severe ? A_BAD : e->level == LOG_LEVEL_WARN ? A_WARN : A_MUTED;
            term_puts_clip(x0, y, right - x0, e->timestamp, A_MUTED);
            term_puts_clip(x0 + 9, y, right - (x0 + 9), known ? LEVEL_WORD[e->level] : "log", level_attr);
            term_puts_clip(x0 + 15, y, right - (x0 + 15), e->msg, severe ? A_BAD : A_TEXT);
        }
        if (app->log_scroll > 0) draw_scroll_marks(n, top, vis, start > 0, true, -1);
    }
    pthread_mutex_unlock(&app->log_lock);
}

/* Scrolled pane body: rows [top, bottom) show content shifted up by pane_scroll; returns that shift. */
static int scroll_begin(tui_app_state_t *app, pane_type_t t, int top, int bottom) {
    term_set_clip_rows(top, bottom);
    return -app->pane_scroll[t];
}

/* y_end = row after the last content row drawn; records how far the body can scroll and marks hidden rows. */
static void scroll_end(const wm_node_t *n, tui_app_state_t *app, int top, int bottom, int y_end) {
    pane_type_t t = n->pane_type;
    term_set_clip_rows(0, -1);
    int over = y_end - bottom;
    app->pane_scroll_max[t] = app->pane_scroll[t] + (over > 0 ? over : 0);
    if (app->pane_scroll[t] > app->pane_scroll_max[t]) app->pane_scroll[t] = app->pane_scroll_max[t];
    if (bottom > top) draw_scroll_marks(n, top, bottom - top, app->pane_scroll[t] > 0, over > 0, -1);
}

/* Appends one clipped line at *y if it is still inside the pane, then advances *y. */
static void put_row(int x, int *y, int bottom, int w, const char *s, uint32_t attr) {
    if (*y < bottom) term_puts_clip(x, *y, w, s, attr);
    (*y)++;
}

static void render_findings_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Findings");
    if (n->w < 5 || n->h < 3) return;
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, bottom = n->y + n->h - 1;

    const forensic_scan_report_t *r = app->last_scan;
    bool scanning = atomic_load(&app->scan_active);
    const char *word;
    char summary[128];
    uint32_t band = A_V_NONE;
    if (scanning) {
        int step = atomic_load(&app->scan_step);
        if (step < 1) step = 1;
        if (step > SCAN_MOD_COUNT) step = SCAN_MOD_COUNT;
        const char *name = step <= app->module_count ? app->modules[step - 1].name
                                                     : forensic_scan_module_name((scan_module_id_t)(step - 1));
        word = " SCANNING ";
        snprintf(summary, sizeof(summary), "Engine %d of %d: %.64s", step, (int)SCAN_MOD_COUNT, name);
    } else if (!r) {
        word = " NOT SCANNED ";
        snprintf(summary, sizeof(summary), "Press F5 to scan the target");
    } else {
        int ok = 0;
        for (int m = 0; m < SCAN_MOD_COUNT; m++) ok += r->status[m] == SCAN_STATUS_OK;
        if (r->verdict == SCAN_VERDICT_THREATS) {
            band = A_V_THREATS;
            word = " THREATS ";
            snprintf(summary, sizeof(summary), "%d %s found", r->total_threats, r->total_threats == 1 ? "threat" : "threats");
        } else if (r->verdict == SCAN_VERDICT_INCOMPLETE) {
            band = A_V_INCOMPL;
            word = " INCOMPLETE ";
            snprintf(summary, sizeof(summary), "%d of %d engines could not run", SCAN_MOD_COUNT - ok, (int)SCAN_MOD_COUNT);
        } else {
            band = A_V_CLEAN;
            word = " CLEAN ";
            snprintf(summary, sizeof(summary), "No threats found by %d engines", ok);
        }
    }

    /* The verdict band spans the full inner width, up to (not onto) the border. */
    int bx = n->x + 1, bw = n->w - 2, y = n->y + 1;
    term_fill(bx, y, bw, 1, band);
    int wn = term_puts_clip(bx, y, bw, word, band);
    term_puts_clip(bx + wn + 1, y, bw - wn - 1, summary, band);
    y += 2;
    if (scanning) return;
    if (!r) {
        /* Before the first scan: say what F5 will do. */
        const drive_item_t *t = NULL;
        for (int i = 0; i < app->drive_count; i++) {
            if (app->drives[i].is_target) { t = &app->drives[i]; break; }
        }
        int enabled = 0;
        for (int i = 0; i < app->module_count; i++) enabled += app->modules[i].enabled;
        char line[192];
        if (y < bottom) {
            int w = term_puts_clip(x0, y, iw, "Target   ", A_MUTED);
            if (t) {
                term_put_glyph(x0 + w, y, TERM_G_TARGET, A_TARGET);
                snprintf(line, sizeof(line), " %.100s  %.20s  %.20s", t->name, t->fs_type, t->size);
                term_puts_clip(x0 + w + 1, y, iw - w - 1, line, A_TARGET);
            } else {
                term_puts_clip(x0 + w, y, iw - w, "none selected", A_TEXT);
            }
            y++;
        }
        if (y < bottom) {
            int w = term_puts_clip(x0, y, iw, "Engines  ", A_MUTED);
            snprintf(line, sizeof(line), "%d of %d enabled", enabled, app->module_count);
            term_puts_clip(x0 + w, y, iw - w, line, A_TEXT);
            y++;
        }
        if (y < bottom) {
            int w = term_puts_clip(x0, y, iw, "Quarantine ", A_MUTED);
            term_puts_clip(x0 + w, y, iw - w, app->quarantine ? "on (F7)" : "off (F7)", A_TEXT);
            y += 2;
        }
        if (y < bottom) {
            term_puts_clip(x0, y, iw, "The disk is made read-only before it is mounted.", A_MUTED);
        }
        return;
    }

    int top = y;
    app->inspect_hint_y = -1;
    y += scroll_begin(app, n->pane_type, top, bottom);
    /* Engine / Result / Found / Note; Note, then Found, then Result drop out when narrow. */
    int rx = x0 + 14, fx = rx + 10, nx = fx + 7;
    bool show_res = rx + 7 <= right, show_found = fx + 5 <= right, show_note = nx + 4 <= right;
    int ew = show_res ? rx - x0 - 1 : iw;
    if (y < bottom) {
        term_puts_clip(x0, y, ew, "Engine", A_MUTED);
        if (show_res) term_puts_clip(rx, y, fx - rx - 1, "Result", A_MUTED);
        if (show_found) term_puts_clip(fx, y, 5, "Found", A_MUTED);
        if (show_note) term_puts_clip(nx, y, right - nx, "Note", A_MUTED);
    }
    y++;
    for (int m = 0; m < SCAN_MOD_COUNT; m++, y++) {
        int found = forensic_scan_module_threats(r, (scan_module_id_t)m);
        char num[16];
        snprintf(num, sizeof(num), "%d", found);
        term_puts_clip(x0, y, ew, forensic_scan_module_name((scan_module_id_t)m), A_TEXT);
        if (show_res) term_puts_clip(rx, y, fx - rx - 1, status_word(r->status[m]), status_attr(r->status[m]));
        if (show_found) term_puts_clip(fx + 5 - (int)strlen(num), y, 5, num, found > 0 ? A_BAD : A_TEXT);
        if (show_note) term_puts_clip(nx, y, right - nx, r->note[m], A_MUTED);
    }

    scan_finding_t f;
    if (forensic_scan_finding(r, 0, &f)) {
        y++;
        char line[64];
        int nf = forensic_scan_finding_count(r);
        snprintf(line, sizeof(line), "%d finding%s. Press 2 to list them all.", nf, nf == 1 ? "" : "s");
        put_row(x0, &y, bottom, iw, line, A_MUTED);
        put_row(x0, &y, bottom, iw, f.name, A_STRONG);
        put_row(x0, &y, bottom, iw, booto_severity_str(f.severity), severity_attr(f.severity));
        put_row(x0, &y, bottom, iw, f.where, A_TEXT);
        if (r->inspect.path[0]) {
            app->inspect_hint_y = y >= top && y < bottom ? y : -1;
            put_row(x0, &y, bottom, iw, "Enter  Inspect bytes and map", A_STRONG);
        }
    }

    if (r->firmware_ran) {
        int cnt[FW_RESULT_NA + 1] = {0};
        for (int c = 0; c < FW_CHECK_COUNT; c++)
            if ((unsigned)r->firmware.checks[c].result <= FW_RESULT_NA) cnt[r->firmware.checks[c].result]++;
        char line[96];
        snprintf(line, sizeof(line), "Firmware: %d fail, %d unknown, %d pass. Press 3.", cnt[FW_RESULT_FAIL],
                 cnt[FW_RESULT_UNKNOWN], cnt[FW_RESULT_PASS]);
        y++;
        put_row(x0, &y, bottom, iw, line, cnt[FW_RESULT_FAIL] ? A_BAD : cnt[FW_RESULT_UNKNOWN] ? A_WARN : A_OK);
    }
    scroll_end(n, app, top, bottom, y);
}

static void render_persistence_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Reports");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1, bottom = n->y + n->h - 1;
    if (iw <= 0) return;
    int y = top + scroll_begin(app, n->pane_type, top, bottom);

    if (y < bottom) {
        const persistence_mgr_t *p = &app->persist;
        char state[96];
        if (p->state == PERSISTENCE_STATE_UNLOCKED) {
            snprintf(state, sizeof(state), "on USB, %llu MiB free", (unsigned long long)(p->free_bytes >> 20));
        } else {
            snprintf(state, sizeof(state), "%s", p->state == PERSISTENCE_STATE_LOCKED ? "locked, saving to RAM" : "RAM only (no USB storage)");
        }
        int w = term_puts_clip(x0, y, iw, "Storage", A_TEXT);
        term_puts_clip(x0 + w + 1, y, right - (x0 + w + 1), state,
                       p->state == PERSISTENCE_STATE_UNLOCKED ? A_OK : A_STRONG);
    }
    y += 2;

    static const struct {
        const char *key;
        const char *what;
    } HINTS[] = {
        {" F3 ", "Unlock a LUKS target"},
        {" F4 ", "Unlock report storage on the boot USB"},
        {" F6 ", "Export case report (JSON + Markdown, SHA-256 checksum)"},
        {" F7 ", "Toggle quarantine: flagged files to an encrypted ZIP"},
    };
    for (size_t i = 0; i < sizeof(HINTS) / sizeof(HINTS[0]); i++, y++) {
        int w = term_puts_clip(x0, y, iw, HINTS[i].key, A_KEYCAP);
        term_puts_clip(x0 + w + 1, y, right - (x0 + w + 1), HINTS[i].what, A_TEXT);
    }
    scroll_end(n, app, top, bottom, y);
}

/* ---- pages: full-screen panes for the last scan ---- */

/* Wraps s over rows from *y up to bottom at width w, breaking at spaces when it can. */
static void put_wrapped(int x, int *y, int bottom, int w, const char *s, uint32_t attr) {
    if (w > 400) w = 400;
    while (*s && *y < bottom && w > 0) {
        int take = (int)strnlen(s, (size_t)w + 1);
        if (take > w) {
            take = w;
            int sp = take;
            while (sp > 0 && s[sp] != ' ') sp--;
            if (sp > 0) take = sp;
        }
        char buf[404];
        snprintf(buf, sizeof(buf), "%.*s", take, s);
        term_puts_clip(x, *y, w, buf, attr);
        (*y)++;
        s += take;
        while (*s == ' ') s++;
    }
}

static void render_findings_list(wm_node_t *n, bool focused, tui_app_state_t *app) {
    const forensic_scan_report_t *r = app->last_scan;
    int count = forensic_scan_finding_count(r);
    char title[40];
    snprintf(title, sizeof(title), "All findings (%d)", count);
    draw_frame(n, focused, title);
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1, bottom = n->y + n->h - 1;
    app->finding_vis = 0;
    if (iw <= 0 || bottom <= top) return;
    if (count == 0) {
        const char *msg = !r ? "No scan yet. Press F5 to scan the target."
                        : r->verdict == SCAN_VERDICT_INCOMPLETE ? "No findings, but some engines could not run: see Evidence (4)."
                                                                 : "No findings: every engine that ran came back clean.";
        term_puts_clip(x0, top, iw, msg, A_MUTED);
        return;
    }
    if (app->finding_cursor >= count) app->finding_cursor = count - 1;
    if (app->finding_cursor < 0) app->finding_cursor = 0;

    /* The selected finding's detail takes the lower rows when the pane is tall enough. */
    int detail_h = n->h >= 16 ? 8 : 0, list_bottom = bottom - detail_h;
    int sev_w = 10, eng_w = 14, name_x = x0 + sev_w + eng_w, name_w = (right - name_x) / 2;
    if (name_w < 16) name_w = right - name_x;
    int where_x = name_x + name_w;
    term_puts_clip(x0, top, sev_w - 1, "Severity", A_MUTED);
    term_puts_clip(x0 + sev_w, top, eng_w - 1, "Engine", A_MUTED);
    term_puts_clip(name_x, top, name_w - 1, "Finding", A_MUTED);
    if (where_x < right) term_puts_clip(where_x, top, right - where_x, "Where", A_MUTED);

    int vis = list_bottom - (top + 1);
    if (vis <= 0) return;
    int first = list_first(app->finding_cursor, vis), cursor_row = -1;
    app->finding_first = first;
    app->finding_list_y = top + 1;
    app->finding_vis = vis;
    scan_finding_t f;
    for (int row = 0; row < vis && forensic_scan_finding(r, first + row, &f); row++) {
        int y = top + 1 + row;
        bool cur = focused && first + row == app->finding_cursor;
        if (cur) {
            cursor_row = y;
            term_fill(n->x + 1, y, n->w - 2, 1, A_CURSOR);
        }
        term_puts_clip(x0, y, sev_w - 1, booto_severity_str(f.severity), row_attr(cur, severity_attr(f.severity)));
        term_puts_clip(x0 + sev_w, y, eng_w - 1, forensic_scan_module_name(f.engine), row_attr(cur, A_TEXT));
        term_puts_clip(name_x, y, name_w - 1, f.name, row_attr(cur, A_STRONG));
        if (where_x < right) term_puts_clip(where_x, y, right - where_x, f.where, row_attr(cur, A_TEXT));
    }
    draw_scroll_marks(n, top + 1, vis, first > 0, first + vis < count, cursor_row);

    if (!detail_h || !forensic_scan_finding(r, app->finding_cursor, &f)) return;
    int y = list_bottom;
    term_hline(n->x + 1, y++, n->w - 2, A_MUTED);
    static const char *const LABEL[] = {"Finding", "Where", "Rule", "Hash", "Detail"};
    const char *val[] = {f.name, f.where, f.rule[0] ? f.rule : "-", f.hash[0] ? f.hash : "-", f.detail[0] ? f.detail : "-"};
    for (int k = 0; k < 5 && y < bottom; k++) {
        term_puts_clip(x0, y, iw, LABEL[k], A_MUTED);
        if (k < 4) term_puts_clip(x0 + 9, y++, iw - 9, val[k], k == 0 ? A_STRONG : A_TEXT);
        else put_wrapped(x0 + 9, &y, bottom, iw - 9, val[k], A_TEXT);
    }
}

static void render_firmware_page(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Firmware of this machine");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1, bottom = n->y + n->h - 1;
    if (iw <= 0 || bottom <= top) return;
    const forensic_scan_report_t *r = app->last_scan;
    if (!r || !r->firmware_ran) {
        term_puts_clip(x0, top, iw, r ? "The firmware audit did not run for this scan."
                                      : "No scan yet. F5 scans the target and also audits this machine's firmware.", A_MUTED);
        return;
    }
    int y = top + scroll_begin(app, n->pane_type, top, bottom);
    put_row(x0, &y, bottom, iw, "Checks the machine Booto runs on, not the target disk. Never part of the verdict.", A_MUTED);
    y++;
    /* Check names run to 27 columns. */
    int frx = x0 + 29, fdx = frx + 9;
    bool show_fres = frx + 4 <= right, show_fdet = fdx + 4 <= right;
    int fnw = show_fres ? frx - x0 - 1 : iw;
    term_puts_clip(x0, y, fnw, "Check", A_MUTED);
    if (show_fres) term_puts_clip(frx, y, fdx - frx - 1, "Result", A_MUTED);
    if (show_fdet) term_puts_clip(fdx, y, right - fdx, "Detail", A_MUTED);
    y++;
    for (int c = 0; c < FW_CHECK_COUNT; c++, y++) {
        const fw_check_t *k = &r->firmware.checks[c];
        uint32_t ra = k->result == FW_RESULT_PASS ? A_OK : k->result == FW_RESULT_FAIL ? A_BAD
                    : k->result == FW_RESULT_UNKNOWN ? A_WARN : A_MUTED;
        term_puts_clip(x0, y, fnw, firmware_check_name((fw_check_id_t)c), A_TEXT);
        if (show_fres) term_puts_clip(frx, y, fdx - frx - 1, firmware_result_str(k->result), ra);
        if (show_fdet) term_puts_clip(fdx, y, right - fdx, k->detail, A_MUTED);
    }
    if (r->firmware.chipset_unconfirmed) {
        y++;
        put_row(x0, &y, bottom, iw, "Chipset not confirmed yet: run booto -c -t <disk> to see how to help.", A_WARN);
    }
    scroll_end(n, app, top, bottom, y);
}

/* One "label  value" row of the Evidence page. */
static void put_kv(int x0, int *y, int bottom, int iw, const char *k, const char *v, uint32_t attr) {
    if (*y < bottom) {
        term_puts_clip(x0, *y, iw, k, A_MUTED);
        term_puts_clip(x0 + 18, *y, iw - 18, v, attr);
    }
    (*y)++;
}

static void render_evidence_page(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Evidence");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, top = n->y + 1, bottom = n->y + n->h - 1;
    if (iw <= 0 || bottom <= top) return;
    const forensic_scan_report_t *r = app->last_scan;
    if (!r) {
        term_puts_clip(x0, top, iw, "No scan yet. After a scan this page shows what was read and whether the target changed.", A_MUTED);
        return;
    }
    int y = top + scroll_begin(app, n->pane_type, top, bottom);
    char v[384];
    put_kv(x0, &y, bottom, iw, "Target", r->target_dev[0] ? r->target_dev : "-", A_TARGET);
    snprintf(v, sizeof(v), "%.255s%s", r->scan_root[0] ? r->scan_root : "-", r->mounted ? " (mounted read-only by Booto)" : "");
    put_kv(x0, &y, bottom, iw, "Scanned at", v, A_TEXT);
    put_kv(x0, &y, bottom, iw, "EFI partition", r->esp_dev[0] ? r->esp_dev : "none found", r->esp_dev[0] ? A_TEXT : A_MUTED);
    y++;
    bool hashed = r->head_before[0] && r->head_after[0];
    bool same = hashed && strcmp(r->head_before, r->head_after) == 0;
    put_kv(x0, &y, bottom, iw, "First 1 MiB", hashed ? (same ? "unchanged by the scan" : "CHANGED during the scan")
                                                 : "not checked (could not read the disk)",
           hashed ? (same ? A_OK : A_BAD) : A_WARN);
    put_kv(x0, &y, bottom, iw, "  SHA-256 before", r->head_before[0] ? r->head_before : "-", A_MUTED);
    put_kv(x0, &y, bottom, iw, "  SHA-256 after", r->head_after[0] ? r->head_after : "-", A_MUTED);
    y++;
    if (r->quarantined < 0) snprintf(v, sizeof(v), "archive could not be finished");
    else if (r->quarantine_zip[0]) snprintf(v, sizeof(v), "%d file%s in %.300s", r->quarantined, r->quarantined == 1 ? "" : "s", r->quarantine_zip);
    else snprintf(v, sizeof(v), "nothing exported (off, or nothing flagged)");
    put_kv(x0, &y, bottom, iw, "Quarantine", v, r->quarantined < 0 ? A_BAD : r->quarantine_zip[0] ? A_WARN : A_MUTED);
    put_kv(x0, &y, bottom, iw, "Measured boot", r->measured_note[0] ? r->measured_note : "not checked", A_TEXT);
    y++;
    put_row(x0, &y, bottom, iw, "What each engine read", A_STRONG);
    for (int m = 0; m < SCAN_MOD_COUNT; m++) {
        switch ((scan_module_id_t)m) {
            case SCAN_MOD_MBR:
                snprintf(v, sizeof(v), "%d sectors, %d VBRs; boot code: %.60s", r->mbr.sectors_scanned, r->mbr.vbr_scanned,
                         r->mbr.mbr_info.bootloader_name ? r->mbr.mbr_info.bootloader_name : "unknown");
                break;
            case SCAN_MOD_UEFI: snprintf(v, sizeof(v), "%d EFI files", r->uefi.efi_files_scanned); break;
            case SCAN_MOD_KERNEL: snprintf(v, sizeof(v), "%d modules", r->kernel.modules_scanned); break;
            case SCAN_MOD_INITRAMFS:
                snprintf(v, sizeof(v), "%d archives (%.15s), %d files, %d scripts", r->initramfs.segments_parsed,
                         r->initramfs.compression[0] ? r->initramfs.compression : "-", r->initramfs.files_extracted,
                         r->initramfs.scripts_audited);
                break;
            case SCAN_MOD_PRELOAD: snprintf(v, sizeof(v), "%d files", r->preload.files_scanned); break;
            case SCAN_MOD_PKG:
                snprintf(v, sizeof(v), "%d packages, %d files hashed, %d missing, %d unreadable", r->pkg.packages_checked,
                         r->pkg.files_checked, r->pkg.files_missing, r->pkg.files_unreadable);
                break;
            default:
                snprintf(v, sizeof(v), "%d files, %d boot-start drivers, %d unsigned, %d third-party, %d not checked",
                         r->winboot.files_checked, r->winboot.boot_start, r->winboot.drivers_unsigned,
                         r->winboot.drivers_third_party, r->winboot.not_checked);
                break;
        }
        if (y < bottom) {
            term_puts_clip(x0, y, iw, forensic_scan_module_name((scan_module_id_t)m), A_TEXT);
            term_puts_clip(x0 + 14, y, iw - 14, status_word(r->status[m]), status_attr(r->status[m]));
            if (r->status[m] == SCAN_STATUS_OK) term_puts_clip(x0 + 23, y, right - (x0 + 23), v, A_MUTED);
        }
        y++;
        if (r->note[m][0]) put_row(x0 + 23, &y, bottom, right - (x0 + 23), r->note[m], A_MUTED);
    }
    scroll_end(n, app, top, bottom, y);
}

void pane_render(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    if (!node || node->type != NODE_LEAF) return;

    switch (node->pane_type) {
        case PANE_STORAGE_DEVICES:
            render_storage_pane(node, is_focused, app);
            break;
        case PANE_SCANNER_MODULES:
            render_modules_pane(node, is_focused, app);
            break;
        case PANE_LIVE_LOGS:
            render_logs_pane(node, is_focused, app);
            break;
        case PANE_THREAT_INSPECTOR:
            render_findings_pane(node, is_focused, app);
            break;
        case PANE_PERSISTENCE:
            render_persistence_pane(node, is_focused, app);
            break;
        case PANE_FINDINGS_LIST:
            render_findings_list(node, is_focused, app);
            break;
        case PANE_FIRMWARE:
            render_firmware_page(node, is_focused, app);
            break;
        case PANE_EVIDENCE:
            render_evidence_page(node, is_focused, app);
            break;
        default:
            draw_frame(node, is_focused, "Empty");
            break;
    }
}

bool pane_handle_click(wm_node_t *node, int x, int y, tui_app_state_t *app) {
    if (!node || !app) return false;
    bool on_glyph = x == node->x + 2;
    /* Row maths mirror render_*_pane: drives list starts below its header, modules list at the first inner row. */
    if (node->pane_type == PANE_STORAGE_DEVICES) {
        int vis = node->h - 3, i = list_first(app->drive_cursor, vis) + y - (node->y + 2);
        if (vis <= 0 || y < node->y + 2 || i >= app->drive_count) return false;
        app->drive_cursor = i;
        if (on_glyph) pane_handle_input(node, &(input_event_t){.type = KEY_CHAR, .ch = ' '}, app);
        return true;
    } else if (node->pane_type == PANE_SCANNER_MODULES) {
        int vis = node->h - 2, i = list_first(app->module_cursor, vis) + y - (node->y + 1);
        if (vis <= 0 || y < node->y + 1 || i >= app->module_count) return false;
        app->module_cursor = i;
        if (on_glyph) pane_handle_input(node, &(input_event_t){.type = KEY_CHAR, .ch = ' '}, app);
        return true;
    } else if (node->pane_type == PANE_FINDINGS_LIST) {
        int row = y - app->finding_list_y, i = app->finding_first + row;
        if (row < 0 || row >= app->finding_vis || i >= forensic_scan_finding_count(app->last_scan)) return false;
        app->finding_cursor = i;
        return true;
    } else if (node->pane_type == PANE_THREAT_INSPECTOR && y == app->inspect_hint_y) {
        pane_handle_input(node, &(input_event_t){.type = KEY_ENTER}, app);
    }
    return false;
}

bool pane_handle_input(wm_node_t *node, const input_event_t *event, tui_app_state_t *app) {
    if (!node || !event || !app) return false;

    if (node->pane_type == PANE_STORAGE_DEVICES) {
        if (event->type == KEY_UP || (event->type == KEY_CHAR && event->ch == 'k')) {
            if (app->drive_cursor > 0) app->drive_cursor--;
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            if (app->drive_cursor < app->drive_count - 1) app->drive_cursor++;
            return true;
        }
        if (event->type == KEY_CHAR && event->ch == ' ') {
            app->drives[app->drive_cursor].is_target = !app->drives[app->drive_cursor].is_target;
            snprintf(app->status_msg, sizeof(app->status_msg), "Toggled target flag for %.200s", app->drives[app->drive_cursor].name);
            return true;
        }
        if (event->type == KEY_ENTER) {
            if (strcmp(app->drives[app->drive_cursor].fs_type, "crypto_LUKS") == 0) {
                snprintf(app->luks_target_dev, sizeof(app->luks_target_dev), "%s", app->drives[app->drive_cursor].name);
                app->luks_passphrase_len = 0;
                app->luks_passphrase_input[0] = '\0';
                app->luks_status_msg[0] = '\0';
                app->luks_modal_for_persist = false;
                app->show_luks_modal = true;
                return true;
            }

            if (!app->drives[app->drive_cursor].is_ro_mounted) {
                booto_error_t err = disk_mount_ro(app->drives[app->drive_cursor].name,
                                                   DEFAULT_RO_MOUNT_POINT,
                                                   app->drives[app->drive_cursor].fs_type);
                if (err == BOOTO_OK) {
                    app->drives[app->drive_cursor].is_ro_mounted = true;
                    tui_app_append_log(app, LOG_LEVEL_INFO, NULL,
                                       "Forensically mounted target storage strictly READ-ONLY (MS_RDONLY, noload)");
                } else {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "Failed to mount %.100s read-only (error %d)",
                             app->drives[app->drive_cursor].name, (int)err);
                    tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, msg);
                }
            } else {
                booto_error_t uerr = disk_unmount(DEFAULT_RO_MOUNT_POINT);
                if (uerr == BOOTO_OK) {
                    app->drives[app->drive_cursor].is_ro_mounted = false;
                    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Cleanly unmounted target storage");
                } else {
                    char msg[96];
                    snprintf(msg, sizeof(msg), "Failed to unmount target storage (error %d)", (int)uerr);
                    tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, msg);
                }
            }
            return true;
        }
    } else if (node->pane_type == PANE_SCANNER_MODULES) {
        if (event->type == KEY_UP || (event->type == KEY_CHAR && event->ch == 'k')) {
            if (app->module_cursor > 0) app->module_cursor--;
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            if (app->module_cursor < app->module_count - 1) app->module_cursor++;
            return true;
        }
        if (event->type == KEY_CHAR && event->ch == ' ') {
            app->modules[app->module_cursor].enabled = !app->modules[app->module_cursor].enabled;
            snprintf(app->status_msg, sizeof(app->status_msg), "Toggled module: %.200s", app->modules[app->module_cursor].name);
            return true;
        }
    } else if (node->pane_type == PANE_FINDINGS_LIST) {
        if (event->type == KEY_UP || (event->type == KEY_CHAR && event->ch == 'k')) {
            if (app->finding_cursor > 0) app->finding_cursor--;
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            if (app->finding_cursor < forensic_scan_finding_count(app->last_scan) - 1) app->finding_cursor++;
            return true;
        }
    } else if (node->pane_type == PANE_THREAT_INSPECTOR || node->pane_type == PANE_PERSISTENCE ||
               node->pane_type == PANE_FIRMWARE || node->pane_type == PANE_EVIDENCE) {
        int *s = &app->pane_scroll[node->pane_type];
        if (event->type == KEY_ENTER && node->pane_type == PANE_THREAT_INSPECTOR) {
            if (app->last_scan && app->last_scan->inspect.path[0]) {
                app->show_inspect = true;
                app->inspect_scroll = 0;
            } else {
                snprintf(app->status_msg, sizeof(app->status_msg), "Nothing to inspect: the last scan flagged no readable file.");
            }
            return true;
        }
        if (event->type == KEY_UP || (event->type == KEY_CHAR && event->ch == 'k')) {
            if (*s > 0) (*s)--;
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            if (*s < app->pane_scroll_max[node->pane_type]) (*s)++;
            return true;
        }
    } else if (node->pane_type == PANE_LIVE_LOGS) {
        if (event->type == KEY_UP || (event->type == KEY_CHAR && event->ch == 'k')) {
            pthread_mutex_lock(&app->log_lock);
            if (app->log_scroll < app->log_count - 5) app->log_scroll++;
            pthread_mutex_unlock(&app->log_lock);
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            pthread_mutex_lock(&app->log_lock);
            if (app->log_scroll > 0) app->log_scroll--;
            pthread_mutex_unlock(&app->log_lock);
            return true;
        }
    }

    return false;
}
