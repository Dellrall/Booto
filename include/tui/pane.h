/**
 * @file pane.h
 * @brief Pane renderers and interactive state handlers for Booto TUI.
 */
#ifndef BOOTO_PANE_H
#define BOOTO_PANE_H

#include "tui/wm.h"
#include "booto.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_LINES 256
#define MAX_DRIVES    16
#define MAX_MODULES   8

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
    char status_text[24];
    uint32_t status_color;
} module_item_t;

typedef struct {
    char timestamp[24];
    char level[12];
    char msg[256];
    uint32_t color;
} log_entry_t;

typedef struct {
    char threat_name[64];
    char infected_file[128];
    char hook_type[64];
    char sha256[65];
    char severity[16];
    uint32_t severity_color;
    char hex_dump[256];
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

    // Log state
    log_entry_t log_ring[MAX_LOG_LINES];
    int log_head;
    int log_count;
    int log_scroll;

    // Threat state
    threat_detail_t threat;

    // Persistence state
    bool luks_unlocked;
    char persistence_status[64];

    // Status bar & modal state
    bool show_exit_modal;
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
