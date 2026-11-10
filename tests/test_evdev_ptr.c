/**
 * @file test_evdev_ptr.c
 * @brief Evdev pointer mapping and event decoding: VM tablets and relative mice.
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

static void test_rel_mouse(void) {
    TEST_START("test_rel_mouse");
    term_abs_ptr_t p = {.rel = 1, .x = -1, .y = -1};
    ASSERT_INT_EQ(term_abs_feed(&p, EV_REL, REL_X, 3, 25, 80), PTR_NONE, "Small motion stays in the cell");
    ASSERT_INT_EQ(p.x, 40, "First motion starts in the middle column");
    ASSERT_INT_EQ(p.y, 12, "First motion starts in the middle row");
    term_abs_feed(&p, EV_REL, REL_X, 5, 25, 80);
    ASSERT_INT_EQ(p.x, 41, "Counts add up to one column");
    term_abs_feed(&p, EV_REL, REL_Y, -2 * EVDEV_REL_PER_ROW, 25, 80);
    ASSERT_INT_EQ(p.y, 10, "Negative motion moves up");
    term_abs_feed(&p, EV_REL, REL_X, -1000 * EVDEV_REL_PER_COL, 25, 80);
    ASSERT_INT_EQ(p.x, 0, "Clamps at the left edge");
    term_abs_feed(&p, EV_REL, REL_X, EVDEV_REL_PER_COL - 1, 25, 80);
    ASSERT_INT_EQ(p.x, 0, "Motion past the edge is not banked");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 1, 25, 80), PTR_CLICK_LEFT, "Left press is a click");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_REL, REL_X, 2 * EVDEV_REL_PER_COL, 25, 80), PTR_DRAG, "Motion while held drags");
    ASSERT_INT_EQ(p.x, 2, "Drag moves the column");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_LEFT, 0, 25, 80), PTR_RELEASE, "Release ends the drag");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_KEY, BTN_MIDDLE, 1, 25, 80), PTR_CLICK_MIDDLE, "Middle press");
    ASSERT_INT_EQ(term_abs_feed(&p, EV_ABS, ABS_X, 100, 25, 80), PTR_NONE, "A mouse ignores absolute axes");
    ASSERT_INT_EQ(p.x, 2, "Absolute axis leaves the column");
    TEST_PASS("test_rel_mouse");
}

static void test_split_pointer(void) {
    TEST_START("test_split_pointer");
    /* VirtualBox: the tablet moves the pointer, the PS/2 mouse sends only buttons. terminal.c hands the shared cell over. */
    term_abs_ptr_t tablet = {.x_min = 0, .x_max = 32767, .y_min = 0, .y_max = 32767, .x = -1, .y = -1};
    term_abs_ptr_t ps2 = {.rel = 1, .x = -1, .y = -1};
    term_abs_feed(&tablet, EV_ABS, ABS_X, 8192, 25, 80);
    term_abs_feed(&tablet, EV_ABS, ABS_Y, 8192, 25, 80);
    ps2.x = tablet.x;
    ps2.y = tablet.y;
    ASSERT_INT_EQ(term_abs_feed(&ps2, EV_KEY, BTN_LEFT, 1, 25, 80), PTR_CLICK_LEFT, "Button-only mouse clicks at the shared cell");
    ASSERT_INT_EQ(ps2.x, 20, "Click lands on the tablet's column");
    tablet.held = ps2.held;
    ASSERT_INT_EQ(term_abs_feed(&tablet, EV_ABS, ABS_X, 16384, 25, 80), PTR_DRAG, "Tablet motion drags while the PS/2 button is held");
    TEST_PASS("test_split_pointer");
}

int main(void) {
    test_abs_pointer();
    test_rel_mouse();
    test_split_pointer();
    TEST_SUMMARY();
    return 0;
}
