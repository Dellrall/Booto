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
    {"LD_PRELOAD hooks", "/etc/ld.so.preload, /etc/environment"},
    {"Ext4 superblock", "superblock"},
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

static uint32_t row_attr(bool cursor_row, uint32_t attr) {
    return cursor_row ? A_CURSOR : attr;
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
            y += 2;
        }
        if (y < bottom) {
            term_puts_clip(x0, y, iw, "The disk is made read-only before it is mounted.", A_MUTED);
        }
        return;
    }

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
    for (int m = 0; m < SCAN_MOD_COUNT && y < bottom; m++, y++) {
        int found = forensic_scan_module_threats(r, (scan_module_id_t)m);
        char num[16];
        snprintf(num, sizeof(num), "%d", found);
        term_puts_clip(x0, y, ew, forensic_scan_module_name((scan_module_id_t)m), A_TEXT);
        if (show_res) term_puts_clip(rx, y, fx - rx - 1, status_word(r->status[m]), status_attr(r->status[m]));
        if (show_found) term_puts_clip(fx + 5 - (int)strlen(num), y, 5, num, found > 0 ? A_BAD : A_TEXT);
        if (show_note) term_puts_clip(nx, y, right - nx, r->note[m], A_MUTED);
    }

    if (r->total_threats <= 0) return;
    y++;
    char sha[80];
    snprintf(sha, sizeof(sha), "SHA-256 %s", app->threat.sha256);
    put_row(x0, &y, bottom, iw, "First finding", A_MUTED);
    put_row(x0, &y, bottom, iw, app->threat.threat_name, A_STRONG);
    put_row(x0, &y, bottom, iw, app->threat.severity, A_BAD);
    put_row(x0, &y, bottom, iw, app->threat.infected_file, A_TEXT);
    put_row(x0, &y, bottom, iw, app->threat.hook_type, A_TEXT);
    put_row(x0, &y, bottom, iw, sha, A_MUTED);
}

static void render_persistence_pane(wm_node_t *n, bool focused, tui_app_state_t *app) {
    draw_frame(n, focused, "Reports");
    int x0 = n->x + 2, iw = n->w - 4, right = x0 + iw, y = n->y + 1, bottom = n->y + n->h - 1;
    if (iw <= 0) return;

    if (y < bottom) {
        int w = term_puts_clip(x0, y, iw, "Persistence", A_TEXT);
        term_puts_clip(x0 + w + 1, y, right - (x0 + w + 1), app->luks_unlocked ? "unlocked" : "locked",
                       app->luks_unlocked ? A_OK : A_BAD);
    }
    y += 2;

    static const struct {
        const char *key;
        const char *what;
    } HINTS[] = {
        {" F3 ", "Unlock a LUKS target"},
        {" F6 ", "Export case report (JSON + Markdown, SHA-256 checksum)"},
    };
    for (size_t i = 0; i < sizeof(HINTS) / sizeof(HINTS[0]) && y < bottom; i++, y++) {
        int w = term_puts_clip(x0, y, iw, HINTS[i].key, A_KEYCAP);
        term_puts_clip(x0 + w + 1, y, right - (x0 + w + 1), HINTS[i].what, A_TEXT);
    }
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
        default:
            draw_frame(node, is_focused, "Empty");
            break;
    }
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
