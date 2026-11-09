/**
 * @file test_wm_tree.c
 * @brief Unit tests for the Binary Space Partitioning (BSP) window manager tree.
 */
#include "test_framework.h"
#include "tui/wm.h"

static void test_wm_tree_creation(void) {
    TEST_START("test_wm_tree_creation");
    wm_tree_t *tree = wm_tree_create_default(100, 40);
    ASSERT_TRUE(tree != NULL, "Tree must be successfully created");
    ASSERT_TRUE(tree->root != NULL, "Root node must not be NULL");
    ASSERT_TRUE(tree->focused_leaf != NULL, "Focused leaf must not be NULL");
    ASSERT_INT_EQ(tree->focused_leaf->pane_type, PANE_STORAGE_DEVICES, "Default focused pane is Storage Devices");
    ASSERT_TRUE(tree->zoomed_leaf == NULL, "Zoomed leaf is initially NULL");

    wm_tree_destroy(tree);
    TEST_PASS("test_wm_tree_creation");
}

static void test_wm_splits_and_zoom(void) {
    TEST_START("test_wm_splits_and_zoom");
    wm_tree_t *tree = wm_tree_create_default(120, 50);

    // Test Zoom
    wm_toggle_zoom(tree);
    ASSERT_TRUE(tree->zoomed_leaf != NULL, "Zoomed leaf must be active");
    ASSERT_INT_EQ(tree->zoomed_leaf->w, 120, "Zoomed leaf width must occupy full workspace");

    wm_toggle_zoom(tree);
    ASSERT_TRUE(tree->zoomed_leaf == NULL, "Zoomed leaf must be cleared after second toggle");

    // Test Split
    bool split_ok = wm_split_focused(tree, SPLIT_HORIZONTAL, PANE_PERSISTENCE);
    ASSERT_TRUE(split_ok, "Splitting focused pane must succeed");
    ASSERT_INT_EQ(tree->focused_leaf->pane_type, PANE_PERSISTENCE, "New focused pane must be Persistence");

    // Test Split Ratio Adjust
    float prev_ratio = tree->focused_leaf->parent->split_ratio;
    wm_adjust_split_ratio(tree, 0.10f);
    ASSERT_TRUE(tree->focused_leaf->parent->split_ratio > prev_ratio, "Split ratio must increase");

    // Test Close
    bool close_ok = wm_close_focused(tree);
    ASSERT_TRUE(close_ok, "Closing focused pane must succeed");

    wm_tree_destroy(tree);
    TEST_PASS("test_wm_splits_and_zoom");
}

static void test_wm_find_leaf_at(void) {
    TEST_START("test_wm_find_leaf_at");
    wm_tree_t *tree = wm_tree_create_default(100, 40);

    wm_node_t *node = wm_find_leaf_at(tree->root, 5, 5);
    ASSERT_TRUE(node != NULL, "Must find leaf at top-left quadrant (5, 5)");
    ASSERT_INT_EQ(node->type, NODE_LEAF, "Found node must be a LEAF");

    wm_tree_destroy(tree);
    TEST_PASS("test_wm_find_leaf_at");
}

static int count_leaves(const wm_node_t *n) {
    if (!n) return 0;
    if (n->type == NODE_LEAF) return 1;
    return count_leaves(n->left) + count_leaves(n->right);
}

static void test_wm_close_zoomed(void) {
    TEST_START("test_wm_close_zoomed");
    wm_tree_t *tree = wm_tree_create_default(120, 50);
    ASSERT_TRUE(wm_split_focused(tree, SPLIT_VERTICAL, PANE_PERSISTENCE), "Split must succeed");
    wm_toggle_zoom(tree);
    ASSERT_TRUE(tree->zoomed_leaf == tree->focused_leaf, "Focused leaf is zoomed");
    ASSERT_TRUE(wm_close_focused(tree), "Closing zoomed pane must succeed");
    ASSERT_TRUE(tree->zoomed_leaf == NULL, "Zoom must be cleared when zoomed leaf closes");
    ASSERT_INT_EQ(tree->focused_leaf->type, NODE_LEAF, "Focus must land on a leaf");
    wm_recalculate_layout(tree, 0, 1, 120, 48); /* ASan flags any freed-node access */
    wm_tree_destroy(tree);
    TEST_PASS("test_wm_close_zoomed");
}

static void test_wm_split_limits(void) {
    TEST_START("test_wm_split_limits");
    wm_tree_t *tree = wm_tree_create_default(120, 50);
    int guard = 0;
    while (wm_split_focused(tree, SPLIT_VERTICAL, PANE_PERSISTENCE) && guard < 100) guard++;
    ASSERT_TRUE(guard < 100, "Vertical splitting must stop");
    ASSERT_TRUE(tree->focused_leaf->w >= 10, "Pane width stays above minimum");
    wm_tree_destroy(tree);

    /* Huge screen, splits spread across leaves (focus cycles): only the 32-leaf cap can stop splitting. */
    tree = wm_tree_create_default(100000, 100000);
    guard = 0;
    while (wm_split_focused(tree, (guard % 2) ? SPLIT_VERTICAL : SPLIT_HORIZONTAL, PANE_PERSISTENCE) &&
           guard < 100) {
        guard++;
        wm_focus_next(tree);
    }
    ASSERT_INT_EQ(count_leaves(tree->root), 32, "Leaf count capped at 32");
    ASSERT_TRUE(!wm_split_focused(tree, SPLIT_VERTICAL, PANE_PERSISTENCE), "Split beyond cap returns false");
    wm_tree_destroy(tree);
    TEST_PASS("test_wm_split_limits");
}

static void test_wm_swap_directions(void) {
    TEST_START("test_wm_swap_directions");
    wm_tree_t *tree = wm_tree_create_default(120, 50);
    int before = count_leaves(tree->root);
    const key_type_t dirs[] = {KEY_RIGHT, KEY_DOWN, KEY_LEFT, KEY_UP,
                               KEY_ALT_RIGHT, KEY_ALT_DOWN, KEY_ALT_LEFT, KEY_ALT_UP};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)wm_swap_focused_adjacent(tree, dirs[i]);
        ASSERT_INT_EQ(count_leaves(tree->root), before, "Swap keeps leaf count");
        ASSERT_INT_EQ(tree->focused_leaf->type, NODE_LEAF, "Focus stays on a leaf");
    }
    wm_tree_destroy(tree);
    TEST_PASS("test_wm_swap_directions");
}

static void test_wm_resize(void) {
    TEST_START("test_wm_resize");
    wm_tree_t *tree = wm_tree_create_default(100, 40);
    wm_recalculate_layout(tree, 0, 1, 100, 38);
    wm_node_t *storage = tree->focused_leaf;
    int border = storage->x + storage->w - 1;
    wm_node_t *root_split = wm_find_divider_at(tree->root, border, 10);
    ASSERT_TRUE(root_split == tree->root, "Column border belongs to the root split");
    ASSERT_TRUE(wm_find_divider_at(tree->root, border - 3, 10) == NULL, "Inside a pane is not a border");
    ASSERT_TRUE(wm_find_divider_at(tree->root, border - 1, 10) == root_split, "The cell left of a border grabs it");
    ASSERT_TRUE(wm_find_divider_at(tree->root, border + 1, 10) == root_split, "The cell right of a border grabs it");
    wm_node_t *row_split = wm_find_divider_at(tree->root, 5, storage->y + storage->h - 1);
    ASSERT_TRUE(row_split == storage->parent, "Row border belongs to the left column split");
    ASSERT_TRUE(wm_find_divider_at(tree->root, border, storage->y + storage->h - 1) == root_split,
                "On a junction the exact border wins over a near one");
    ASSERT_TRUE(wm_find_divider_at(tree->root, border - 1, storage->y + storage->h - 1) == row_split,
                "Exactly on the row border beats near the column border");

    wm_move_divider(tree, root_split, 30, 10);
    ASSERT_INT_EQ(storage->x + storage->w - 1, 30, "Border lands on the dragged column");
    wm_move_divider(tree, root_split, 0, 10);
    ASSERT_INT_EQ(storage->w, 10, "Dragging past the edge keeps the minimum width");

    wm_move_divider(tree, root_split, 40, 10);
    ASSERT_TRUE(wm_resize_focused(tree, KEY_RIGHT, 2), "Focused pane has a column border");
    ASSERT_INT_EQ(storage->x + storage->w - 1, 42, "l moves the border right");
    int h = storage->h;
    ASSERT_TRUE(wm_resize_focused(tree, KEY_UP, 3), "Focused pane has a row border");
    ASSERT_INT_EQ(storage->h, h - 3, "k moves the border up");
    wm_toggle_zoom(tree);
    ASSERT_TRUE(!wm_resize_focused(tree, KEY_RIGHT, 2), "No resizing while zoomed");
    wm_tree_destroy(tree);
    TEST_PASS("test_wm_resize");
}

int main(void) {
    test_wm_resize();
    printf("\n--- Running BSP Window Manager Tests ---\n");
    test_wm_tree_creation();
    test_wm_splits_and_zoom();
    test_wm_find_leaf_at();
    test_wm_close_zoomed();
    test_wm_split_limits();
    test_wm_swap_directions();
    TEST_SUMMARY();
    return 0;
}
