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

int main(void) {
    printf("\n--- Running BSP Window Manager Tests ---\n");
    test_wm_tree_creation();
    test_wm_splits_and_zoom();
    test_wm_find_leaf_at();
    TEST_SUMMARY();
    return 0;
}
