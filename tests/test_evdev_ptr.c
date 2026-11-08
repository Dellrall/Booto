/**
 * @file test_evdev_ptr.c
 * @brief Absolute pointer (VM tablet) mapping and event decoding.
 */
#include "test_framework.h"
#include "tui/evdev_ptr.h"

#include <linux/input.h>

static void test_abs_pointer(void) {
    TEST_START("test_abs_pointer");
    /* VirtualBox's USB tablet: both axes 0..32767 */
    ASSERT_INT_EQ(term_abs_to_cell(0, 0, 32767, 80), 0, "Left edge is column 0");
    ASSERT_INT_EQ(term_abs_to_cell(32767, 0, 32767, 80), 79, "Right edge is the last column");
    ASSERT_INT_EQ(term_abs_to_cell(16384, 0, 32767, 80), 40, "Middle is the middle column");
    ASSERT_INT_EQ(term_abs_to_cell(-5, 0, 32767, 80), 0, "Below min clamps");
    ASSERT_INT_EQ(term_abs_to_cell(99999, 0, 32767, 80), 79, "Above max clamps");

    term_abs_ptr_t p = {.x_min = 0, .x_max = 32767, .y_min = 0, .y_max = 32767, .x = -1, .y = -1};
        ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 1, 25, 80), PTR_NONE, "No click before a position is known");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_X, 4096, 25, 80), PTR_NONE, "Motion is not an event");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_Y, 32767, 25, 80), PTR_NONE, "Motion is not an event");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 1, 25, 80), PTR_CLICK_LEFT, "Left press is a click");
    ASSERT_INT_EQ(p.x, 10, "Column follows ABS_X");
    ASSERT_INT_EQ(p.y, 24, "Bottom edge stays on the last row");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_X, 4096, 25, 80), PTR_NONE, "Same cell is not a drag");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_X, 8192, 25, 80), PTR_DRAG, "Motion with the button held drags");
    ASSERT_INT_EQ(p.x, 20, "Drag updates the column");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 0, 25, 80), PTR_RELEASE, "Left release ends the drag");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_X, 4096, 25, 80), PTR_NONE, "Motion after release is not a drag");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 0, 25, 80), PTR_NONE, "Stray release is ignored");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_RIGHT, 1, 25, 80), PTR_CLICK_RIGHT, "Right press");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_REL, REL_WHEEL, -1, 25, 80), PTR_WHEEL_DOWN, "Negative wheel scrolls down");
    TEST_PASS("test_abs_pointer");
}

int main(void) {
    test_abs_pointer();
    TEST_SUMMARY();
    return 0;
}
