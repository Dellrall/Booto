/**
 * @file pane.h
 * @brief Pane renderers and interactive state handlers for Booto TUI.
 */
#ifndef BOOTO_PANE_H
#define BOOTO_PANE_H

#include "tui/wm.h"
#include "booto.h"
#include "logger.h"
#include "forensic_scan.h"
#include "persistence_mgr.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_LINES 256
#define MAX_DRIVES    16
#define MAX_MODULES   8

/* Style tokens: black and white; green/yellow/red only mean clean/suspicious/failed (cyan keycaps excepted).
 * 16 ANSI colors only (the Linux console has no more); meaning is always also spelled out in words. */
#define A_TEXT   MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_NONE)
#define A_STRONG MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_BOLD)
#define A_MUTED  MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_DIM)
#define A_FRAME  MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_BOLD) /* focused pane and modals; others use A_MUTED */
#define A_TARGET MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_BOLD)
#define A_OK     MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_NONE)
#define A_WARN   MAKE_ATTR(COLOR_YELLOW, COLOR_DEFAULT, ATTR_NONE)
#define A_BAD    MAKE_ATTR(COLOR_RED, COLOR_DEFAULT, ATTR_BOLD)
#define A_PRIORITY MAKE_ATTR(COLOR_YELLOW, COLOR_DEFAULT, ATTR_NONE) /* non-bold yellow: orange (brown) on the Linux console */
#define A_DRAG   MAKE_ATTR(COLOR_CYAN, COLOR_DEFAULT, ATTR_BOLD) /* border being dragged */
#define A_CURSOR MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_REVERSE)
#define A_KEYCAP MAKE_ATTR(COLOR_BLACK, COLOR_CYAN, ATTR_NONE)
/* Black text stays non-bold: bold black is dark grey on the Linux console and unreadable on the band. */
#define A_V_CLEAN   MAKE_ATTR(COLOR_BLACK, COLOR_GREEN, ATTR_NONE)
#define A_V_THREATS MAKE_ATTR(COLOR_BRIGHT_WHITE, COLOR_RED, ATTR_BOLD)
#define A_V_INCOMPL MAKE_ATTR(COLOR_BLACK, COLOR_YELLOW, ATTR_NONE)
#define A_V_NONE    MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_NONE)

typedef struct {
    char name[128];
    char size[32];
    char fs_type[32];
    char label[64];
    bool is_target;
    bool is_ro_mounted;
    bool is_boot_media;
} drive_item_t;

/* Worth scanning first: an installed system's filesystem or an encrypted volume, never the Booto stick. */
static inline bool pane_drive_is_priority(const drive_item_t *d) {
    static const char *const fs[] = {"ext4", "xfs", "btrfs", "ntfs", "crypto_LUKS", "BitLocker"};
    if (d->is_boot_media) return false;
    for (size_t i = 0; i < sizeof(fs) / sizeof(fs[0]); i++)
        if (strcmp(d->fs_type, fs[i]) == 0) return true;
    return false;
}

/* Still encrypted: a scan of it reads only ciphertext. */
static inline bool pane_drive_is_locked(const drive_item_t *d) {
    return strcmp(d->fs_type, "crypto_LUKS") == 0 || strcmp(d->fs_type, "BitLocker") == 0;
}

/* What the drive holds, in words a new user knows. */
static inline const char *pane_drive_kind(const drive_item_t *d) {
    static const struct { const char *fs, *kind; } k[] = {
        {"ext4", "Linux"}, {"xfs", "Linux"}, {"btrfs", "Linux"}, {"ntfs", "Windows"},
        {"crypto_LUKS", "Encrypted Linux"}, {"BitLocker", "Encrypted Windows"}, {"vfat", "Boot files"},
        {"LVM2_member", "Linux volumes"}, {"swap", "Swap"},
    };
    if (d->is_boot_media) return "Booto USB";
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++)
        if (strcmp(d->fs_type, k[i].fs) == 0) return k[i].kind;
    return "Other";
}

/* The drive to preselect: the first priority one that can be read now, else the first locked one; -1 if none. */
static inline int pane_pick_target(const drive_item_t *d, int n) {
    int locked = -1;
    for (int i = 0; i < n; i++) {
        if (!pane_drive_is_priority(&d[i])) continue;
        if (!pane_drive_is_locked(&d[i])) return i;
        if (locked < 0) locked = i;
    }
    return locked;
}

/* The k-th finding of r at or above min: its index in r (copied to *f), or -1 past the end. */
static inline int pane_finding_index(const forensic_scan_report_t *r, booto_severity_t min, int k, scan_finding_t *f) {
    for (int i = 0; forensic_scan_finding(r, i, f); i++)
        if (f->severity >= min && k-- == 0) return i;
    return -1;
}

static inline int pane_finding_shown(const forensic_scan_report_t *r, booto_severity_t min) {
    int n = 0;
    scan_finding_t f;
    while (pane_finding_index(r, min, n, &f) >= 0) n++;
    return n;
}

/* What a new user should do about a finding of this severity. */
static inline const char *pane_next_step(booto_severity_t s) {
    if (s >= SEVERITY_HIGH) return "What a bootkit does. Save the report (F6) and do not trust this system until it is checked.";
    if (s == SEVERITY_MEDIUM) return "A normal setup can do this too (DKMS module, custom loader). Check that you installed it.";
    return "For information. No action needed unless it is unexpected.";
}

typedef struct {
    char name[64];
    char target_path[64];
    bool enabled;
} module_item_t;

typedef struct {
    char timestamp[24];
    log_level_t level;
    char msg[256];
} log_entry_t;

typedef struct {
    booto_context_t *ctx;
    wm_tree_t *wm;
    bool running;
    bool expert;                        // E: full dashboard (engines, log) instead of the simple view

    // Storage state
    drive_item_t drives[MAX_DRIVES];
    int drive_count;
    int drive_cursor;

    // Module state
    module_item_t modules[MAX_MODULES];
    int module_count;
    int module_cursor;
    int pane_scroll[PANE_COUNT];        // first hidden row count for the Findings and Reports panes
    int pane_scroll_max[PANE_COUNT];    // set by the last render

    // Log state (log_lock guards log_ring/log_head/log_count/log_scroll; appended from any thread)
    pthread_mutex_t log_lock;
    log_entry_t log_ring[MAX_LOG_LINES];
    int log_head;
    int log_count;
    int log_scroll;

    // Scan result and pages (0 = panes, 1 = Findings, 2 = Firmware, 3 = Evidence)
    forensic_scan_report_t *last_scan;  // heap-allocated on first scan, freed at exit
    int page;
    int finding_cursor;                 // selected row of the Findings page (among the rows the filter shows)
    booto_severity_t finding_min_sev;   // f: Findings page shows this severity and above
    int finding_first, finding_list_y, finding_vis; // listed rows: first index, screen row, count (last render)

    // Background scan (F5). Worker owns pending_scan/pending_err/scan_target/scan_enabled until scan_done;
    // the main thread reads them only after pthread_join.
    pthread_t scan_thread;
    atomic_bool scan_active;            // set by main before spawn, cleared by main after join
    atomic_bool scan_done;              // set by worker when forensic_scan_run returns
    long scan_started_ms;               // CLOCK_MONOTONIC ms at F5, for the elapsed time
    _Atomic int scan_step;              // 0..SCAN_MOD_COUNT, from the progress callback
    forensic_scan_report_t *pending_scan;
    booto_error_t pending_err;
    char scan_target[128];
    bool scan_enabled[SCAN_MOD_COUNT];
    char scan_quarantine_dir[300];      // "" = no quarantine export for this scan
    bool quarantine;                    // F7: export flagged files to <report storage>/quarantine

    // Persistence state: luks_unlocked = scan target opened via F3; persist = report storage on the boot USB
    bool luks_unlocked;
    persistence_mgr_t persist;

    // Status bar & modal state
    bool show_welcome;                  // first screen: what Booto does and the four steps
    bool exported;                      // F6 saved the report of last_scan
    bool show_exit_modal;
    bool show_luks_modal;
    bool show_encrypted_modal;          // F5 on a locked target: unlock first, or scan anyway
    bool show_inspect;                  // Inspect view of last_scan->inspect (Enter on Findings)
    int inspect_tab;                    // 0 = Map, 1 = Hex
    int inspect_scroll;                 // first line shown in the current tab
    int inspect_hint_y;                 // screen row of the Findings "Enter  Inspect" line, -1 when hidden
    bool luks_modal_for_persist;        // modal unlocks report storage instead of the scan target
    char luks_target_dev[128];
    char luks_passphrase_input[128];
    int luks_passphrase_len;
    char luks_status_msg[128];
    char status_msg[256];
} tui_app_state_t;

/**
 * @brief Initialize TUI application state with mock/initial forensic data.
 */
void tui_app_state_init(tui_app_state_t *app, booto_context_t *ctx);

/**
 * @brief Append a log entry to the live log ring buffer.
 */
void tui_app_append_log(tui_app_state_t *app, log_level_t level, const char *timestamp, const char *msg);

/**
 * @brief Render a specific pane inside its node coordinates.
 */
void pane_render(wm_node_t *node, bool is_focused, tui_app_state_t *app);

/**
 * @brief Handle user input for the focused pane.
 */
bool pane_handle_input(wm_node_t *node, const input_event_t *event, tui_app_state_t *app);
/** Left click at (x, y) inside node: selects the list row there; a click on its checkbox glyph also toggles it.
 *  Returns true when a list row was selected. */
bool pane_handle_click(wm_node_t *node, int x, int y, tui_app_state_t *app);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PANE_H */
