/**
 * @file wm.c
 * @brief Implementation of the BSP dynamic tiling window manager.
 */
#include "tui/wm.h"

#include <stdlib.h>
#include <string.h>

#define WM_MAX_LEAVES 32

static wm_node_t *create_leaf(int id, pane_type_t type) {
    wm_node_t *node = (wm_node_t *)calloc(1, sizeof(wm_node_t));
    if (!node) return NULL;
    node->type = NODE_LEAF;
    node->id = id;
    node->pane_type = type;
    node->split_ratio = 0.5f;
    return node;
}

static wm_node_t *create_split(split_direction_t dir, float ratio, wm_node_t *left, wm_node_t *right) {
    wm_node_t *node = (wm_node_t *)calloc(1, sizeof(wm_node_t));
    if (!node) return NULL;
    node->type = NODE_SPLIT;
    node->split_dir = dir;
    node->split_ratio = ratio;
    node->left = left;
    node->right = right;
    if (left) left->parent = node;
    if (right) right->parent = node;
    return node;
}

static void free_node(wm_node_t *node) {
    if (!node) return;
    if (node->type == NODE_SPLIT) {
        free_node(node->left);
        free_node(node->right);
    }
    free(node);
}

static void compute_node_layout(wm_node_t *node, int x, int y, int w, int h) {
    if (!node) return;
    node->x = x;
    node->y = y;
    node->w = w;
    node->h = h;

    /* Siblings overlap by one cell so they share a border; term_draw_box merges it into a junction. */
    if (node->type == NODE_SPLIT) {
        if (node->split_dir == SPLIT_VERTICAL) {
            int left_w = (int)((float)w * node->split_ratio);
            if (left_w < 10) left_w = 10;
            if (left_w > w - 10) left_w = w - 10;
            int right_w = w - left_w + 1;

            compute_node_layout(node->left, x, y, left_w, h);
            compute_node_layout(node->right, x + left_w - 1, y, right_w, h);
        } else {
            int top_h = (int)((float)h * node->split_ratio);
            if (top_h < 4) top_h = 4;
            if (top_h > h - 4) top_h = h - 4;
            int bottom_h = h - top_h + 1;

            compute_node_layout(node->left, x, y, w, top_h);
            compute_node_layout(node->right, x, y + top_h - 1, w, bottom_h);
        }
    }
}

void wm_recalculate_layout(wm_tree_t *tree, int x, int y, int w, int h) {
    if (!tree || !tree->root) return;
    tree->screen_w = w;
    tree->screen_h = h;

    if (tree->zoomed_leaf) {
        tree->zoomed_leaf->x = x;
        tree->zoomed_leaf->y = y;
        tree->zoomed_leaf->w = w;
        tree->zoomed_leaf->h = h;
    } else {
        compute_node_layout(tree->root, x, y, w, h);
    }
}

wm_tree_t *wm_tree_create_default(int screen_w, int screen_h) {
    wm_tree_t *tree = (wm_tree_t *)calloc(1, sizeof(wm_tree_t));
    if (!tree) return NULL;

    tree->next_id = 1;

    // Default 4-pane layout:
    // Left column: Storage (top) & Engines (bottom)
    // Right column: Findings (top, holds the verdict) & Log (bottom)
    wm_node_t *p1 = create_leaf(tree->next_id++, PANE_STORAGE_DEVICES);
    wm_node_t *p2 = create_leaf(tree->next_id++, PANE_SCANNER_MODULES);
    wm_node_t *left_col = create_split(SPLIT_HORIZONTAL, 0.62f, p1, p2);

    wm_node_t *p3 = create_leaf(tree->next_id++, PANE_THREAT_INSPECTOR);
    wm_node_t *p4 = create_leaf(tree->next_id++, PANE_LIVE_LOGS);
    wm_node_t *right_col = create_split(SPLIT_HORIZONTAL, 0.55f, p3, p4);

    tree->root = create_split(SPLIT_VERTICAL, 0.40f, left_col, right_col);
    tree->focused_leaf = p1;
    tree->zoomed_leaf = NULL;

    wm_recalculate_layout(tree, 0, 1, screen_w, screen_h - 2);
    return tree;
}

static void collect_leaves(wm_node_t *node, wm_node_t **leaves, int *count, int max) {
    if (!node || *count >= max) return;
    if (node->type == NODE_LEAF) {
        leaves[(*count)++] = node;
    } else {
        collect_leaves(node->left, leaves, count, max);
        collect_leaves(node->right, leaves, count, max);
    }
}

void wm_focus_next(wm_tree_t *tree) {
    if (!tree || !tree->root) return;
    wm_node_t *leaves[WM_MAX_LEAVES];
    int count = 0;
    collect_leaves(tree->root, leaves, &count, WM_MAX_LEAVES);
    if (count <= 1) return;

    for (int i = 0; i < count; i++) {
        if (leaves[i] == tree->focused_leaf) {
            tree->focused_leaf = leaves[(i + 1) % count];
            return;
        }
    }
    tree->focused_leaf = leaves[0];
}

void wm_focus_direction(wm_tree_t *tree, key_type_t dir) {
    if (!tree || !tree->focused_leaf) return;
    wm_node_t *leaves[WM_MAX_LEAVES];
    int count = 0;
    collect_leaves(tree->root, leaves, &count, WM_MAX_LEAVES);
    if (count <= 1) return;

    wm_node_t *curr = tree->focused_leaf;
    int curr_cx = curr->x + curr->w / 2;
    int curr_cy = curr->y + curr->h / 2;

    wm_node_t *best = NULL;
    int best_dist = 999999;

    for (int i = 0; i < count; i++) {
        wm_node_t *cand = leaves[i];
        if (cand == curr) continue;

        int cand_cx = cand->x + cand->w / 2;
        int cand_cy = cand->y + cand->h / 2;

        bool valid = false;
        if ((dir == KEY_LEFT || dir == KEY_ALT_LEFT) && cand_cx < curr_cx) valid = true;
        if ((dir == KEY_RIGHT || dir == KEY_ALT_RIGHT) && cand_cx > curr_cx) valid = true;
        if ((dir == KEY_UP || dir == KEY_ALT_UP) && cand_cy < curr_cy) valid = true;
        if ((dir == KEY_DOWN || dir == KEY_ALT_DOWN) && cand_cy > curr_cy) valid = true;

        if (valid) {
            int dx = cand_cx - curr_cx;
            int dy = cand_cy - curr_cy;
            int dist = dx * dx + dy * dy;
            if (dist < best_dist) {
                best_dist = dist;
                best = cand;
            }
        }
    }

    if (best) {
        tree->focused_leaf = best;
    }
}

void wm_toggle_zoom(wm_tree_t *tree) {
    if (!tree || !tree->focused_leaf) return;
    if (tree->zoomed_leaf) {
        tree->zoomed_leaf = NULL;
    } else {
        tree->zoomed_leaf = tree->focused_leaf;
    }
    wm_recalculate_layout(tree, 0, 1, tree->screen_w, tree->screen_h - 2);
}

bool wm_split_focused(wm_tree_t *tree, split_direction_t dir, pane_type_t new_pane) {
    if (!tree || !tree->focused_leaf) return false;
    wm_node_t *curr = tree->focused_leaf;
    wm_node_t *parent = curr->parent;

    /* collect_leaves callers use 32-slot arrays; also keep each half usable. */
    wm_node_t *leaves[WM_MAX_LEAVES];
    int count = 0;
    collect_leaves(tree->root, leaves, &count, WM_MAX_LEAVES);
    if (count >= WM_MAX_LEAVES) return false;
    if (dir == SPLIT_VERTICAL ? curr->w / 2 < 10 : curr->h / 2 < 3) return false;

    wm_node_t *new_leaf = create_leaf(tree->next_id++, new_pane);
    if (!new_leaf) return false;

    wm_node_t *new_split = create_split(dir, 0.5f, curr, new_leaf);
    if (!new_split) {
        free(new_leaf);
        return false;
    }

    if (parent) {
        if (parent->left == curr) {
            parent->left = new_split;
        } else {
            parent->right = new_split;
        }
        new_split->parent = parent;
    } else {
        tree->root = new_split;
        new_split->parent = NULL;
    }

    tree->focused_leaf = new_leaf;
    wm_recalculate_layout(tree, 0, 1, tree->screen_w, tree->screen_h - 2);
    return true;
}

bool wm_swap_focused_adjacent(wm_tree_t *tree, key_type_t dir) {
    if (!tree || !tree->focused_leaf) return false;
    wm_node_t *orig = tree->focused_leaf;
    wm_focus_direction(tree, dir);
    wm_node_t *target = tree->focused_leaf;

    if (target != orig) {
        // Swap pane types and data
        pane_type_t temp_type = orig->pane_type;
        void *temp_data = orig->pane_data;

        orig->pane_type = target->pane_type;
        orig->pane_data = target->pane_data;

        target->pane_type = temp_type;
        target->pane_data = temp_data;
        return true;
    }
    return false;
}

void wm_adjust_split_ratio(wm_tree_t *tree, float delta) {
    if (!tree || !tree->focused_leaf || !tree->focused_leaf->parent) return;
    wm_node_t *parent = tree->focused_leaf->parent;
    parent->split_ratio += delta;
    if (parent->split_ratio < 0.15f) parent->split_ratio = 0.15f;
    if (parent->split_ratio > 0.85f) parent->split_ratio = 0.85f;
    wm_recalculate_layout(tree, 0, 1, tree->screen_w, tree->screen_h - 2);
}

bool wm_close_focused(wm_tree_t *tree) {
    if (!tree || !tree->focused_leaf || !tree->focused_leaf->parent) return false;
    wm_node_t *curr = tree->focused_leaf;
    wm_node_t *parent = curr->parent;
    wm_node_t *sibling = (parent->left == curr) ? parent->right : parent->left;
    wm_node_t *grandparent = parent->parent;

    if (grandparent) {
        if (grandparent->left == parent) {
            grandparent->left = sibling;
        } else {
            grandparent->right = sibling;
        }
        sibling->parent = grandparent;
    } else {
        tree->root = sibling;
        sibling->parent = NULL;
    }

    parent->left = NULL;
    parent->right = NULL;
    free_node(parent);
    if (tree->zoomed_leaf == curr) tree->zoomed_leaf = NULL;
    free(curr);

    /* sibling may be a split subtree; focus must always be a leaf. */
    while (sibling->type == NODE_SPLIT) sibling = sibling->left;
    tree->focused_leaf = sibling;
    wm_recalculate_layout(tree, 0, 1, tree->screen_w, tree->screen_h - 2);
    return true;
}

wm_node_t *wm_find_leaf_at(wm_node_t *node, int x, int y) {
    if (!node) return NULL;
    if (node->type == NODE_LEAF) {
        if (x >= node->x && x < node->x + node->w && y >= node->y && y < node->y + node->h) {
            return node;
        }
        return NULL;
    }
    wm_node_t *l = wm_find_leaf_at(node->left, x, y);
    if (l) return l;
    return wm_find_leaf_at(node->right, x, y);
}

void wm_tree_destroy(wm_tree_t *tree) {
    if (!tree) return;
    free_node(tree->root);
    free(tree);
}
