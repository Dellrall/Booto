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

void tui_app_state_init(tui_app_state_t *app, booto_context_t *ctx) {
    if (!app) return;
    memset(app, 0, sizeof(*app));
    app->ctx = ctx;
    app->running = true;
    app->luks_unlocked = false;
    snprintf(app->persistence_status, sizeof(app->persistence_status), "LUKS Locked (Amnesic Mode)");
    snprintf(app->status_msg, sizeof(app->status_msg), "Press F5 to start scan | Alt+M to move/swap | Alt+Z to zoom");

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

    // Initialize forensic modules
    // Initialize forensic modules
    app->module_count = 6;
    app->module_cursor = 0;

    snprintf(app->modules[0].name, sizeof(app->modules[0].name), "MBR, VBR & Track 0 Slack Auditor");
    snprintf(app->modules[0].target_path, sizeof(app->modules[0].target_path), "Sector 0, LBA 1-63, VBRs");
    app->modules[0].enabled = true;
    snprintf(app->modules[0].status_text, sizeof(app->modules[0].status_text), "READY");
    app->modules[0].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    snprintf(app->modules[1].name, sizeof(app->modules[1].name), "UEFI & ESP Bootkit Analyzer");
    snprintf(app->modules[1].target_path, sizeof(app->modules[1].target_path), "/boot/efi/EFI/*");
    app->modules[1].enabled = true;
    snprintf(app->modules[1].status_text, sizeof(app->modules[1].status_text), "READY");
    app->modules[1].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    snprintf(app->modules[2].name, sizeof(app->modules[2].name), "Kernel LKM & Symbol Hook Scanner");
    snprintf(app->modules[2].target_path, sizeof(app->modules[2].target_path), "/lib/modules, vmlinuz");
    app->modules[2].enabled = true;
    snprintf(app->modules[2].status_text, sizeof(app->modules[2].status_text), "READY");
    app->modules[2].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    snprintf(app->modules[3].name, sizeof(app->modules[3].name), "In-Memory Initramfs Auditor");
    snprintf(app->modules[3].target_path, sizeof(app->modules[3].target_path), "/boot/initrd.img*");
    app->modules[3].enabled = true;
    snprintf(app->modules[3].status_text, sizeof(app->modules[3].status_text), "READY");
    app->modules[3].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    snprintf(app->modules[4].name, sizeof(app->modules[4].name), "LD_PRELOAD & PAM Interceptors");
    snprintf(app->modules[4].target_path, sizeof(app->modules[4].target_path), "/etc/ld.so.preload");
    app->modules[4].enabled = true;
    snprintf(app->modules[4].status_text, sizeof(app->modules[4].status_text), "READY");
    app->modules[4].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    snprintf(app->modules[5].name, sizeof(app->modules[5].name), "Raw Ext4 Inode vs VFS Diff");
    snprintf(app->modules[5].target_path, sizeof(app->modules[5].target_path), "Raw Block Inodes");
    app->modules[5].enabled = true;
    snprintf(app->modules[5].status_text, sizeof(app->modules[5].status_text), "READY");
    app->modules[5].status_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);

    // Initial clean/idle threat inspector state
    snprintf(app->threat.threat_name, sizeof(app->threat.threat_name), "None (System Idle)");
    snprintf(app->threat.infected_file, sizeof(app->threat.infected_file), "Waiting for target scan analysis");
    snprintf(app->threat.hook_type, sizeof(app->threat.hook_type), "Press F5 to initiate forensic scan");
    snprintf(app->threat.sha256, sizeof(app->threat.sha256), "0000000000000000000000000000000000000000000000000000000000000000");
    snprintf(app->threat.severity, sizeof(app->threat.severity), "CLEAN / IDLE");
    app->threat.severity_color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD);
    snprintf(app->threat.hex_dump, sizeof(app->threat.hex_dump), "Ready to inspect host storage for Ring-0/Ring-3 rootkits.");

    // Initial logs
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Booto forensic TUI window manager initialized");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Amnesic live operating system verified in RAM (tmpfs)");
    tui_app_append_log(app, LOG_LEVEL_WARN, NULL, "Persistence partition is currently LOCKED (Amnesic)");
    tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Host storage discovery completed: Press F5 to scan target");
}

void tui_app_append_log(tui_app_state_t *app, log_level_t level, const char *timestamp, const char *msg) {
    if (!app) return;
    int idx = (app->log_head + app->log_count) % MAX_LOG_LINES;
    if (app->log_count == MAX_LOG_LINES) {
        app->log_head = (app->log_head + 1) % MAX_LOG_LINES;
    } else {
        app->log_count++;
    }

    log_entry_t *entry = &app->log_ring[idx];
    snprintf(entry->timestamp, sizeof(entry->timestamp), "%s", timestamp ? timestamp : "--:--:--");
    snprintf(entry->msg, sizeof(entry->msg), "%s", msg ? msg : "");

    switch (level) {
        case LOG_LEVEL_DEBUG:
            snprintf(entry->level, sizeof(entry->level), "DEBUG");
            entry->color = MAKE_ATTR(COLOR_CYAN, COLOR_DEFAULT, ATTR_NONE);
            break;
        case LOG_LEVEL_INFO:
            snprintf(entry->level, sizeof(entry->level), "INFO ");
            entry->color = MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_NONE);
            break;
        case LOG_LEVEL_WARN:
            snprintf(entry->level, sizeof(entry->level), "WARN ");
            entry->color = MAKE_ATTR(COLOR_YELLOW, COLOR_DEFAULT, ATTR_BOLD);
            break;
        case LOG_LEVEL_ERROR:
            snprintf(entry->level, sizeof(entry->level), "ERROR");
            entry->color = MAKE_ATTR(COLOR_RED, COLOR_DEFAULT, ATTR_BOLD);
            break;
        case LOG_LEVEL_CRITICAL:
            snprintf(entry->level, sizeof(entry->level), "CRIT ");
            entry->color = MAKE_ATTR(COLOR_BRIGHT_RED, COLOR_DEFAULT, ATTR_BOLD);
            break;
        default:
            snprintf(entry->level, sizeof(entry->level), "LOG  ");
            entry->color = MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
            break;
    }
}

static void render_storage_pane(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    uint32_t border_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
    uint32_t title_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD | ATTR_REVERSE) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_BOLD);

    term_draw_box(node->x, node->y, node->w, node->h, " Target Storage Devices ", border_attr, title_attr);

    int row = node->y + 1;
    char header[512];
    snprintf(header, sizeof(header), "  %-20.20s %-8.8s %-9.9s %-16.16s",
             "Device", "FS", "Size", "Target Status");
    term_puts(node->x + 2, row++, header, MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_DEFAULT, ATTR_UNDERLINE));

    for (int i = 0; i < app->drive_count && row < node->y + node->h - 1; i++) {
        char line[512];
        bool is_cursor = (is_focused && app->drive_cursor == i);
        uint32_t attr = is_cursor ? MAKE_ATTR(COLOR_BLACK, COLOR_CYAN, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);

        char dev_str[64];
        snprintf(dev_str, sizeof(dev_str), "[%c] %.50s",
                 app->drives[i].is_target ? '*' : ' ',
                 app->drives[i].name);

        snprintf(line, sizeof(line), "%c %-20.20s %-8.8s %-9.9s %-16.16s",
                 is_cursor ? '>' : ' ',
                 dev_str,
                 app->drives[i].fs_type,
                 app->drives[i].size,
                 app->drives[i].is_ro_mounted ? "MOUNTED (RO)" : app->drives[i].label);

        term_puts(node->x + 2, row++, line, attr);
    }
}

static void render_modules_pane(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    uint32_t border_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
    uint32_t title_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD | ATTR_REVERSE) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_BOLD);

    term_draw_box(node->x, node->y, node->w, node->h, " Forensic Scanner Modules ", border_attr, title_attr);

    int row = node->y + 1;
    for (int i = 0; i < app->module_count && row < node->y + node->h - 1; i++) {
        char line[512];
        bool is_cursor = (is_focused && app->module_cursor == i);
        uint32_t attr = is_cursor ? MAKE_ATTR(COLOR_BLACK, COLOR_CYAN, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);

        snprintf(line, sizeof(line), "%c [%c] %-32.32s",
                 is_cursor ? '>' : ' ',
                 app->modules[i].enabled ? 'X' : ' ',
                 app->modules[i].name);

        term_puts(node->x + 2, row, line, attr);
        if (node->w > 46) {
            term_puts(node->x + 40, row, app->modules[i].status_text, app->modules[i].status_color);
        }
        row++;
    }
}

static void render_logs_pane(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    uint32_t border_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
    uint32_t title_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD | ATTR_REVERSE) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_BOLD);

    char title[128];
    snprintf(title, sizeof(title), " Live Scan & Event Stream (%d lines) ", app->log_count);
    term_draw_box(node->x, node->y, node->w, node->h, title, border_attr, title_attr);

    int max_visible = node->h - 2;
    if (max_visible <= 0) return;

    int start = app->log_count - max_visible - app->log_scroll;
    if (start < 0) start = 0;

    int row = node->y + 1;
    for (int i = 0; i < max_visible && (start + i) < app->log_count; i++) {
        int idx = (app->log_head + start + i) % MAX_LOG_LINES;
        log_entry_t *entry = &app->log_ring[idx];

        char prefix[64];
        snprintf(prefix, sizeof(prefix), "[%s] [%s] ", entry->timestamp, entry->level);
        term_puts(node->x + 2, row, prefix, entry->color);

        int p_len = (int)strlen(prefix);
        int max_msg = node->w - 4 - p_len;
        if (max_msg > 0) {
            char msg_trunc[512];
            snprintf(msg_trunc, sizeof(msg_trunc), "%s", entry->msg);
            if ((int)strlen(msg_trunc) > max_msg) {
                msg_trunc[max_msg] = '\0';
            }
            term_puts(node->x + 2 + p_len, row, msg_trunc, MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE));
        }
        row++;
    }
}

static void render_threat_pane(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    uint32_t border_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
    uint32_t title_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD | ATTR_REVERSE) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_BOLD);

    term_draw_box(node->x, node->y, node->w, node->h, " Threat Inspector & Disassembly ", border_attr, title_attr);

    int row = node->y + 1;
    char buf[512];

    snprintf(buf, sizeof(buf), "Threat:    %s", app->threat.threat_name);
    term_puts(node->x + 2, row++, buf, MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_DEFAULT, ATTR_BOLD));

    snprintf(buf, sizeof(buf), "Severity:  %s", app->threat.severity);
    term_puts(node->x + 2, row++, buf, app->threat.severity_color);

    snprintf(buf, sizeof(buf), "Location:  %s", app->threat.infected_file);
    term_puts(node->x + 2, row++, buf, MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE));

    snprintf(buf, sizeof(buf), "Mechanism: %s", app->threat.hook_type);
    term_puts(node->x + 2, row++, buf, MAKE_ATTR(COLOR_CYAN, COLOR_DEFAULT, ATTR_NONE));

    if (row < node->y + node->h - 1) {
        snprintf(buf, sizeof(buf), "SHA256:    %.32s...", app->threat.sha256);
        term_puts(node->x + 2, row++, buf, MAKE_ATTR(COLOR_BRIGHT_BLACK, COLOR_DEFAULT, ATTR_NONE));
    }
}

static void render_persistence_pane(wm_node_t *node, bool is_focused, tui_app_state_t *app) {
    uint32_t border_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE);
    uint32_t title_attr = is_focused ? MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_BOLD | ATTR_REVERSE) : MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_BOLD);

    term_draw_box(node->x, node->y, node->w, node->h, " LUKS Persistence & Case Reports ", border_attr, title_attr);

    int row = node->y + 1;
    term_puts(node->x + 2, row++, "Encrypted Persistence Status:", MAKE_ATTR(COLOR_BRIGHT_YELLOW, COLOR_DEFAULT, ATTR_BOLD));

    term_puts(node->x + 4, row++, app->persistence_status,
              app->luks_unlocked ? MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_BOLD) : MAKE_ATTR(COLOR_RED, COLOR_DEFAULT, ATTR_BOLD));

    row++;
    term_puts(node->x + 2, row++, "[F2] Unlock LUKS Volume", MAKE_ATTR(COLOR_BRIGHT_CYAN, COLOR_DEFAULT, ATTR_UNDERLINE));
    term_puts(node->x + 2, row++, "[F6] Export Signed Case Report", MAKE_ATTR(COLOR_BRIGHT_GREEN, COLOR_DEFAULT, ATTR_UNDERLINE));
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
            render_threat_pane(node, is_focused, app);
            break;
        case PANE_PERSISTENCE:
            render_persistence_pane(node, is_focused, app);
            break;
        default:
            term_draw_box(node->x, node->y, node->w, node->h, " Generic Pane ", MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE), MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE));
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
            if (!app->drives[app->drive_cursor].is_ro_mounted) {
                booto_error_t err = disk_mount_ro(app->drives[app->drive_cursor].name,
                                                   DEFAULT_RO_MOUNT_POINT,
                                                   app->drives[app->drive_cursor].fs_type);
                if (err == BOOTO_OK) {
                    app->drives[app->drive_cursor].is_ro_mounted = true;
                    tui_app_append_log(app, LOG_LEVEL_INFO, NULL,
                                       "Forensically mounted target storage strictly READ-ONLY (MS_RDONLY, noload)");
                } else {
                    tui_app_append_log(app, LOG_LEVEL_ERROR, NULL, "Failed to mount target storage");
                }
            } else {
                disk_unmount(DEFAULT_RO_MOUNT_POINT);
                app->drives[app->drive_cursor].is_ro_mounted = false;
                tui_app_append_log(app, LOG_LEVEL_INFO, NULL, "Cleanly unmounted target storage");
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
            if (app->log_scroll < app->log_count - 5) app->log_scroll++;
            return true;
        }
        if (event->type == KEY_DOWN || (event->type == KEY_CHAR && event->ch == 'j')) {
            if (app->log_scroll > 0) app->log_scroll--;
            return true;
        }
    }

    return false;
}
