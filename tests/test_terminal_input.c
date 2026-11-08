/**
 * @file test_terminal_input.c
 * @brief Terminal input and output: SGR mouse decoding and SGR attribute encoding.
 */
#include "test_framework.h"
#include "tui/terminal.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    ASSERT_INT_EQ(parse("\033[<0;10;5m").type, KEY_MOUSE_RELEASE, "Left release");
    ASSERT_INT_EQ(parse("\033[<2;10;5m").type, KEY_NONE, "Right release is ignored");
    e = parse("\033[<32;12;6M");
    ASSERT_TRUE(e.type == KEY_MOUSE_DRAG && e.mouse_x == 11 && e.mouse_y == 5, "Left-button motion is a drag at its cell");
    ASSERT_INT_EQ(parse("\033[<34;10;5M").type, KEY_NONE, "Right-button motion is ignored");
    ASSERT_INT_EQ(parse("\033[<0;x;5M").type, KEY_NONE, "Malformed sequence is ignored");
    TEST_PASS("test_sgr_mouse");
}

static void test_sgr_attrs(void) {
    TEST_START("test_sgr_attrs");
    char b[64];
    term_sgr(MAKE_ATTR(COLOR_DEFAULT, COLOR_DEFAULT, ATTR_NONE), b, sizeof(b));
    ASSERT_TRUE(strcmp(b, "\033[0m") == 0, "Plain text resets only");
    term_sgr(MAKE_ATTR(COLOR_RED, COLOR_DEFAULT, ATTR_BOLD | ATTR_DIM | ATTR_UNDERLINE), b, sizeof(b));
    ASSERT_TRUE(strcmp(b, "\033[0;1;2;4;31m") == 0, "Bold, dim, underline and red fg");
    term_sgr(MAKE_ATTR(COLOR_BRIGHT_WHITE, COLOR_BLUE, ATTR_REVERSE), b, sizeof(b));
    ASSERT_TRUE(strcmp(b, "\033[0;7;97;44m") == 0, "Reverse, bright fg, normal bg");
    setenv("NO_COLOR", "1", 1);
    term_sgr(MAKE_ATTR(COLOR_RED, COLOR_BLUE, ATTR_BOLD | ATTR_REVERSE), b, sizeof(b));
    ASSERT_STR_EQ(b, "\033[0;1;7m", "NO_COLOR keeps attributes and drops colors");
    term_sgr(MAKE_ATTR(COLOR_BLACK, COLOR_CYAN, ATTR_NONE), b, sizeof(b));
    ASSERT_STR_EQ(b, "\033[0;7m", "NO_COLOR shows a background band as reverse");
    unsetenv("NO_COLOR");
    ASSERT_INT_EQ((int)term_sgr(MAKE_ATTR(COLOR_RED, COLOR_BLUE, ATTR_BOLD), b, 4), 0, "Too-small buffer writes nothing usable");
    TEST_PASS("test_sgr_attrs");
}

/* Feeds bytes through stdin to the real reader, as the Linux console would send them. */
static input_event_t feed(const char *bytes, size_t len) {
    int fds[2];
    input_event_t e = {.type = KEY_NONE};
    if (pipe(fds) != 0) return e;
    dup2(fds[0], STDIN_FILENO);
    close(fds[0]);
    if (write(fds[1], bytes, len) != (ssize_t)len) e.type = KEY_NONE;
    close(fds[1]);
    term_poll_event(&e, 100);
    return e;
}

static void test_x10_mouse(void) {
    TEST_START("test_x10_mouse");
    input_event_t e = feed("\033[M *%", 6);
    ASSERT_INT_EQ(e.type, KEY_MOUSE_CLICK, "Console left press is a click");
    ASSERT_INT_EQ(e.mouse_x, 9, "Column is zero-based");
    ASSERT_INT_EQ(e.mouse_y, 4, "Row is zero-based");
    ASSERT_INT_EQ(feed("\033[M#*%", 6).type, KEY_MOUSE_RELEASE, "Console release");
    ASSERT_INT_EQ(feed("\033[M`!!", 6).type, KEY_MOUSE_WHEEL_UP, "Button 64 is wheel up");
    ASSERT_INT_EQ(feed("\033[Ma!!", 6).type, KEY_MOUSE_WHEEL_DOWN, "Button 65 is wheel down");
    ASSERT_INT_EQ(feed("\033[M@!!", 6).type, KEY_MOUSE_DRAG, "Console left drag");
    ASSERT_INT_EQ(feed("\033[21~", 5).type, KEY_F10, "F10 decodes to KEY_F10");
    ASSERT_INT_EQ(feed("\033[A", 3).type, KEY_UP, "Up arrow decodes to KEY_UP");
    ASSERT_INT_EQ(feed("\r", 1).type, KEY_ENTER, "Enter decodes to KEY_ENTER");
    TEST_PASS("test_x10_mouse");
}

static void test_click_zones(void) {
    TEST_START("test_click_zones");
    term_clear();
    term_add_click_zone(10, 20, 3, KEY_F5, 0);
    term_add_click_zone(15, 25, 3, KEY_CHAR, 'p');
    input_event_t e = {.type = KEY_MOUSE_CLICK, .mouse_x = 12, .mouse_y = 3};
    ASSERT_TRUE(term_apply_click_zone(&e) && e.type == KEY_F5, "Click inside a zone becomes its key");
    e = (input_event_t){.type = KEY_MOUSE_CLICK, .mouse_x = 17, .mouse_y = 3};
    ASSERT_TRUE(term_apply_click_zone(&e) && e.type == KEY_CHAR && e.ch == 'p', "Later zone wins on overlap");
    e = (input_event_t){.type = KEY_MOUSE_CLICK, .mouse_x = 25, .mouse_y = 3};
    ASSERT_TRUE(!term_apply_click_zone(&e) && e.type == KEY_MOUSE_CLICK, "End column is outside the zone");
    e = (input_event_t){.type = KEY_MOUSE_CLICK, .mouse_x = 12, .mouse_y = 3, .mouse_btn = 2};
    ASSERT_TRUE(!term_apply_click_zone(&e), "Right click is not a button press");
    term_clear();
    e = (input_event_t){.type = KEY_MOUSE_CLICK, .mouse_x = 12, .mouse_y = 3};
    ASSERT_TRUE(!term_apply_click_zone(&e), "term_clear drops last frame's zones");
    TEST_PASS("test_click_zones");
}

int main(void) {
    test_click_zones();
    test_sgr_mouse();
    test_sgr_attrs();
    test_x10_mouse();
    TEST_SUMMARY();
    return 0;
}
