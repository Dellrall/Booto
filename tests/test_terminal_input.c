/**
 * @file test_terminal_input.c
 * @brief SGR mouse decoding: presses and wheel become events; releases and drag motion are ignored.
 */
#include "test_framework.h"
#include "tui/terminal.h"

#include <string.h>

static input_event_t parse(const char *seq) {
    input_event_t e = {.type = KEY_NONE};
    term_parse_csi((const unsigned char *)seq, strlen(seq), &e);
    return e;
}

static void test_sgr_mouse(void) {
    TEST_START("test_sgr_mouse");
    input_event_t e = parse("\033[<0;10;5M");
    ASSERT_INT_EQ(e.type, KEY_MOUSE_CLICK, "Left press is a click");
    ASSERT_INT_EQ(e.mouse_x, 9, "Column is zero-based");
    ASSERT_INT_EQ(e.mouse_y, 4, "Row is zero-based");
    ASSERT_INT_EQ(parse("\033[<64;1;1M").type, KEY_MOUSE_WHEEL_UP, "Button 64 is wheel up");
    ASSERT_INT_EQ(parse("\033[<65;1;1M").type, KEY_MOUSE_WHEEL_DOWN, "Button 65 is wheel down");
    ASSERT_INT_EQ(parse("\033[<0;10;5m").type, KEY_NONE, "Release is ignored");
    ASSERT_INT_EQ(parse("\033[<32;10;5M").type, KEY_NONE, "Drag motion is ignored");
    ASSERT_INT_EQ(parse("\033[<0;x;5M").type, KEY_NONE, "Malformed sequence is ignored");
    TEST_PASS("test_sgr_mouse");
}

int main(void) {
    test_sgr_mouse();
    TEST_SUMMARY();
    return 0;
}
