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

#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_LINES 256
#define MAX_DRIVES    16
#define MAX_MODULES   8

/* Style tokens (see the TUI visual spec). */
#define A_TEXT   MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_NONE)
#define A_STRONG MAKE_ATTR(COLOR_BRIGHT_WHITE, COLOR_DEFAULT, ATTR_BOLD)
#define A_MUTED  MAKE_ATTR(COLOR_BRIGHT_BLACK, COLOR_DEFAULT, ATTR_NONE)
#define A_FRAME  MAKE_ATTR(COLOR_WHITE, COLOR_DEFAULT, ATTR_NONE)
#define A_TARGET MAKE_ATTR(COLOR_YELLOW, COLOR_DEFAULT, ATTR_BOLD)
#define A_OK     MAKE_ATTR(COLOR_GREEN, COLOR_DEFAULT, ATTR_NONE)
#define A_WARN   MAKE_ATTR(COLOR_YELLOW, COLOR_DEFAULT, ATTR_NONE)
#define A_BAD    MAKE_ATTR(COLOR_RED, COLOR_DEFAULT, ATTR_BOLD)
#define A_CURSOR MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_NONE)
#define A_KEYCAP MAKE_ATTR(COLOR_BLACK, COLOR_WHITE, ATTR_NONE)
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
} drive_item_t;

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
    char threat_name[64];
    char infected_file[128];
    char hook_type[64];
    char sha256[65];
    char severity[16];
} threat_detail_t;

typedef struct {
    booto_context_t *ctx;
    wm_tree_t *wm;
    bool running;

    // Storage state
    drive_item_t drives[MAX_DRIVES];
    int drive_count;
    int drive_cursor;

    // Module state
    module_item_t modules[MAX_MODULES];
    int module_count;
    int module_cursor;

    // Log state (log_lock guards log_ring/log_head/log_count/log_scroll; appended from any thread)
    pthread_mutex_t log_lock;
    log_entry_t log_ring[MAX_LOG_LINES];
    int log_head;
    int log_count;
    int log_scroll;

    // Threat state
    threat_detail_t threat;
    forensic_scan_report_t *last_scan;  // heap-allocated on first scan, freed at exit

    // Background scan (F5). Worker owns pending_scan/pending_err/scan_target/scan_enabled until scan_done;
    // the main thread reads them only after pthread_join.
    pthread_t scan_thread;
    atomic_bool scan_active;            // set by main before spawn, cleared by main after join
    atomic_bool scan_done;              // set by worker when forensic_scan_run returns
    _Atomic int scan_step;              // 0..SCAN_MOD_COUNT, from the progress callback
    forensic_scan_report_t *pending_scan;
    booto_error_t pending_err;
    char scan_target[128];
    bool scan_enabled[SCAN_MOD_COUNT];

    // Persistence state
    bool luks_unlocked;

    // Status bar & modal state
    bool show_exit_modal;
    bool show_luks_modal;
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

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_PANE_H */
