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
    ASSERT_INT_EQ(parse("\033[<0;10;5m").type, KEY_NONE, "Release is ignored");
    ASSERT_INT_EQ(parse("\033[<32;10;5M").type, KEY_NONE, "Drag motion is ignored");
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
    ASSERT_INT_EQ(feed("\033[M#*%", 6).type, KEY_NONE, "Console release is ignored");
    ASSERT_INT_EQ(feed("\033[M`!!", 6).type, KEY_MOUSE_WHEEL_UP, "Button 64 is wheel up");
    ASSERT_INT_EQ(feed("\033[Ma!!", 6).type, KEY_MOUSE_WHEEL_DOWN, "Button 65 is wheel down");
    ASSERT_INT_EQ(feed("\033[M@!!", 6).type, KEY_NONE, "Drag motion is ignored");
    TEST_PASS("test_x10_mouse");
}

int main(void) {
    test_sgr_mouse();
    test_sgr_attrs();
    test_x10_mouse();
    TEST_SUMMARY();
    return 0;
}
