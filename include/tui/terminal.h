/**
 * @file terminal.h
 * @brief Zero-dependency ANSI/VT100 double-buffered terminal abstraction.
 */
#ifndef BOOTO_TERMINAL_H
#define BOOTO_TERMINAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Text formatting and color attributes */
#define ATTR_NONE       0x0000
#define ATTR_BOLD       0x0001
#define ATTR_DIM        0x0002
#define ATTR_UNDERLINE  0x0004
#define ATTR_REVERSE    0x0008

/* 16 standard ANSI colors (FG: bits 4..7, BG: bits 8..11) */
typedef enum {
    COLOR_DEFAULT = 0,
    COLOR_BLACK,
    COLOR_RED,
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_MAGENTA,
    COLOR_CYAN,
    COLOR_WHITE,
    COLOR_BRIGHT_BLACK,
    COLOR_BRIGHT_RED,
    COLOR_BRIGHT_GREEN,
    COLOR_BRIGHT_YELLOW,
    COLOR_BRIGHT_BLUE,
    COLOR_BRIGHT_MAGENTA,
    COLOR_BRIGHT_CYAN,
    COLOR_BRIGHT_WHITE
} term_color_t;

#define MAKE_ATTR(fg, bg, style) (((uint32_t)(style) & 0x0F) | (((uint32_t)(fg) & 0x1F) << 4) | (((uint32_t)(bg) & 0x1F) << 9))

/* Glyphs that exist in CP437, so they render on a bare Linux console font. */
#define TERM_G_TARGET  0x2666u  /* diamond: evidence target marker */
#define TERM_G_SQUARE  0x25A0u  /* filled square: enabled */
#define TERM_G_DOT     0x00B7u  /* middle dot: disabled / empty */
#define TERM_G_ARROW_R 0x25BAu
#define TERM_G_UP      0x25B2u
#define TERM_G_DOWN    0x25BCu
#define TERM_G_SHADE   0x2591u
#define TERM_G_BLOCK   0x2588u

/* Key definitions */
typedef enum {
    KEY_NONE = 0,
    KEY_CHAR,
    KEY_ENTER,
    KEY_ESC,
    KEY_BACKSPACE,
    KEY_TAB,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_HOME,
    KEY_END,
    KEY_PGUP,
    KEY_PGDN,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_F11,
    KEY_F12,
    KEY_ALT_H,
    KEY_ALT_V,
    KEY_ALT_M,
    KEY_ALT_Z,
    KEY_ALT_LBRACKET,
    KEY_ALT_RBRACKET,
    KEY_ALT_UP,
    KEY_ALT_DOWN,
    KEY_ALT_LEFT,
    KEY_ALT_RIGHT,
    KEY_MOUSE_CLICK,
    KEY_RESIZE
} key_type_t;

typedef struct {
    key_type_t type;
    int ch;
    int mouse_x;
    int mouse_y;
    int mouse_btn;
} input_event_t;

/**
 * @brief Initialize terminal in raw mode, enabling mouse tracking.
 *
 * Installs SIGWINCH plus fatal-signal handlers (TERM/HUP/INT/QUIT/SEGV/BUS/ABRT/FPE)
 * and an atexit hook that restore the terminal; term_shutdown() reinstates the
 * previous signal dispositions.
 */
int term_init(void);

/**
 * @brief Restore original terminal settings.
 */
void term_shutdown(void);

/**
 * @brief Get current terminal dimensions.
 */
void term_get_dimensions(int *rows, int *cols);

/**
 * @brief Poll for input event (non-blocking or timeout in ms).
 */
bool term_poll_event(input_event_t *event, int timeout_ms);

/**
 * @brief Clear back buffer.
 */
void term_clear(void);

/**
 * @brief Put an ASCII character at coordinate with attributes in back buffer.
 */
void term_putc(int x, int y, char c, uint32_t attr);

/**
 * @brief Put a Unicode codepoint (single-width) at coordinate.
 */
void term_put_glyph(int x, int y, uint32_t cp, uint32_t attr);

/**
 * @brief Draw a UTF-8 string; returns columns written.
 */
int term_puts(int x, int y, const char *str, uint32_t attr);

/**
 * @brief Draw a UTF-8 string in at most max_w columns; a cut string ends with '~'. Returns columns written.
 */
int term_puts_clip(int x, int y, int max_w, const char *str, uint32_t attr);

/**
 * @brief Fill a rectangle with spaces in the given attribute.
 */
void term_fill(int x, int y, int w, int h, uint32_t attr);

/**
 * @brief Horizontal / vertical single lines. Lines merge with lines already drawn in a cell (forming junctions).
 */
void term_hline(int x, int y, int w, uint32_t attr);
void term_vline(int x, int y, int h, uint32_t attr);

/**
 * @brief Draw a single-line box (merging with neighbouring boxes) with an optional title at x+2.
 */
void term_draw_box(int x, int y, int w, int h, const char *title, uint32_t border_attr, uint32_t title_attr);

/**
 * @brief Flush changes from back buffer to terminal (differential update).
 */
void term_present(void);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_TERMINAL_H */
