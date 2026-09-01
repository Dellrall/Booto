/**
 * @file wm.h
 * @brief Binary Space Partitioning (BSP) dynamic tiling window manager for Booto.
 */
#ifndef BOOTO_WM_H
#define BOOTO_WM_H

#include "tui/terminal.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PANE_STORAGE_DEVICES = 0,
    PANE_SCANNER_MODULES,
    PANE_LIVE_LOGS,
    PANE_THREAT_INSPECTOR,
    PANE_PERSISTENCE,
    PANE_COUNT
} pane_type_t;

typedef enum {
    SPLIT_NONE = 0,
    SPLIT_HORIZONTAL, // Top and Bottom
    SPLIT_VERTICAL    // Left and Right
} split_direction_t;

typedef enum {
    NODE_LEAF = 0,
    NODE_SPLIT
} node_type_t;

typedef struct wm_node {
    node_type_t type;
    int id;
    pane_type_t pane_type;
    int x;
    int y;
    int w;
    int h;
    float split_ratio;
    split_direction_t split_dir;

    struct wm_node *parent;
    struct wm_node *left;  // or top
    struct wm_node *right; // or bottom

    void *pane_data;
} wm_node_t;

typedef struct {
    wm_node_t *root;
    wm_node_t *focused_leaf;
    wm_node_t *zoomed_leaf;
    int next_id;
    int screen_w;
    int screen_h;
} wm_tree_t;

/**
 * @brief Initialize a default 4-pane triage layout.
 */
wm_tree_t *wm_tree_create_default(int screen_w, int screen_h);

/**
 * @brief Recalculate dimensions across all nodes in the BSP tree.
 */
void wm_recalculate_layout(wm_tree_t *tree, int x, int y, int w, int h);

/**
 * @brief Cycle focus to next leaf.
 */
void wm_focus_next(wm_tree_t *tree);

/**
 * @brief Focus leaf in a relative spatial direction.
 */
void wm_focus_direction(wm_tree_t *tree, key_type_t dir);

/**
 * @brief Toggle zoom mode on the focused pane (Alt+Z).
 */
void wm_toggle_zoom(wm_tree_t *tree);

/**
 * @brief Split the focused pane into two (Alt+H / Alt+V).
 */
bool wm_split_focused(wm_tree_t *tree, split_direction_t dir, pane_type_t new_pane);

/**
 * @brief Swap the focused pane with an adjacent pane (Alt+M / Move).
 */
bool wm_swap_focused_adjacent(wm_tree_t *tree, key_type_t dir);

/**
 * @brief Adjust split ratio of the focused pane's parent (Alt+[ / Alt+]).
 */
void wm_adjust_split_ratio(wm_tree_t *tree, float delta);

/**
 * @brief Close the focused pane and collapse parent.
 */
bool wm_close_focused(wm_tree_t *tree);

/**
 * @brief Find leaf node under a given (x, y) coordinate (for mouse clicks).
 */
wm_node_t *wm_find_leaf_at(wm_node_t *node, int x, int y);

/**
 * @brief Destroy the tree and free all nodes.
 */
void wm_tree_destroy(wm_tree_t *tree);

/**
 * @brief Get human-readable name of pane type.
 */
const char *wm_pane_type_name(pane_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_WM_H */
