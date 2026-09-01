/**
 * @file terminal.c
 * @brief Double-buffered ANSI terminal driver with mouse & Alt-key parsing.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "tui/terminal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

static struct termios g_orig_termios;
static bool g_raw_active = false;
static volatile sig_atomic_t g_resized = 0;

static int g_rows = 24;
static int g_cols = 80;

static char *g_front_chars = NULL;
static uint32_t *g_front_attrs = NULL;
static char *g_back_chars = NULL;
static uint32_t *g_back_attrs = NULL;

static void handle_sigwinch(int sig) {
    (void)sig;
    g_resized = 1;
}

static void update_dimensions(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        g_rows = ws.ws_row;
        g_cols = ws.ws_col;
    } else {
        g_rows = 24;
        g_cols = 80;
    }

    size_t cells = (size_t)(g_rows * g_cols);
    g_front_chars = (char *)realloc(g_front_chars, cells);
    g_front_attrs = (uint32_t *)realloc(g_front_attrs, cells * sizeof(uint32_t));
    g_back_chars = (char *)realloc(g_back_chars, cells);
    g_back_attrs = (uint32_t *)realloc(g_back_attrs, cells * sizeof(uint32_t));

    if (g_front_chars && g_front_attrs && g_back_chars && g_back_attrs) {
        memset(g_front_chars, 0, cells);
        memset(g_front_attrs, 0xFF, cells * sizeof(uint32_t));
        memset(g_back_chars, ' ', cells);
        memset(g_back_attrs, 0, cells * sizeof(uint32_t));
    }
}

int term_init(void) {
    if (g_raw_active) return 0;

    if (!isatty(STDIN_FILENO)) return -1;
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == -1) return -1;

    struct termios raw = g_orig_termios;
    raw.c_iflag &= (tcflag_t)~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= (tcflag_t)~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 1;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) return -1;
    g_raw_active = true;

    // Install SIGWINCH handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigwinch;
    sigaction(SIGWINCH, &sa, NULL);

    // Enable alternate screen buffer, hide cursor, enable mouse tracking (SGR 1006)
    write(STDOUT_FILENO, "\033[?1049h\033[?25l\033[?1000h\033[?1002h\033[?1006h", 35);

    update_dimensions();
    return 0;
}

void term_shutdown(void) {
    if (!g_raw_active) return;

    // Disable mouse tracking, show cursor, leave alternate screen
    write(STDOUT_FILENO, "\033[?1006l\033[?1002l\033[?1000l\033[?25h\033[?1049l\033[0m", 37);

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
    g_raw_active = false;

    free(g_front_chars);
    free(g_front_attrs);
    free(g_back_chars);
    free(g_back_attrs);
    g_front_chars = NULL;
    g_front_attrs = NULL;
    g_back_chars = NULL;
    g_back_attrs = NULL;
}

void term_get_dimensions(int *rows, int *cols) {
    if (g_resized) {
        g_resized = 0;
        update_dimensions();
    }
    if (rows) *rows = g_rows;
    if (cols) *cols = g_cols;
}

void term_clear(void) {
    if (!g_back_chars || !g_back_attrs) return;
    size_t cells = (size_t)(g_rows * g_cols);
    memset(g_back_chars, ' ', cells);
    memset(g_back_attrs, 0, cells * sizeof(uint32_t));
}

void term_putc(int x, int y, char c, uint32_t attr) {
    if (x < 0 || x >= g_cols || y < 0 || y >= g_rows) return;
    if (!g_back_chars || !g_back_attrs) return;

    int idx = y * g_cols + x;
    g_back_chars[idx] = c;
    g_back_attrs[idx] = attr;
}

void term_puts(int x, int y, const char *str, uint32_t attr) {
    if (!str || y < 0 || y >= g_rows) return;
    int curr_x = x;
    while (*str && curr_x < g_cols) {
        if (curr_x >= 0) {
            term_putc(curr_x, y, *str, attr);
        }
        curr_x++;
        str++;
    }
}

void term_draw_box(int x, int y, int w, int h, const char *title, uint32_t border_attr, uint32_t title_attr) {
    if (w < 2 || h < 2) return;

    term_putc(x, y, '+', border_attr);
    term_putc(x + w - 1, y, '+', border_attr);
    term_putc(x, y + h - 1, '+', border_attr);
    term_putc(x + w - 1, y + h - 1, '+', border_attr);

    for (int i = x + 1; i < x + w - 1; i++) {
        term_putc(i, y, '-', border_attr);
        term_putc(i, y + h - 1, '-', border_attr);
    }

    for (int j = y + 1; j < y + h - 1; j++) {
        term_putc(x, j, '|', border_attr);
        term_putc(x + w - 1, j, '|', border_attr);
    }

    if (title && *title && w > 4) {
        int title_len = (int)strlen(title);
        int max_len = w - 4;
        if (title_len > max_len) title_len = max_len;

        term_putc(x + 1, y, ' ', title_attr);
        for (int i = 0; i < title_len; i++) {
            term_putc(x + 2 + i, y, title[i], title_attr);
        }
        term_putc(x + 2 + title_len, y, ' ', title_attr);
    }
}

static void apply_attr(uint32_t attr, uint32_t prev_attr, char **buf, size_t *rem) {
    if (attr == prev_attr) return;

    int fg = (int)((attr >> 4) & 0x1F);
    int bg = (int)((attr >> 9) & 0x1F);
    uint32_t style = attr & 0x0F;

    int written = snprintf(*buf, *rem, "\033[0");
    if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }

    if (style & ATTR_BOLD) {
        written = snprintf(*buf, *rem, ";1");
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    }
    if (style & ATTR_REVERSE) {
        written = snprintf(*buf, *rem, ";7");
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    }

    if (fg > 0 && fg <= 8) {
        written = snprintf(*buf, *rem, ";%d", 29 + fg);
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    } else if (fg > 8 && fg <= 16) {
        written = snprintf(*buf, *rem, ";%d", 81 + fg);
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    }

    if (bg > 0 && bg <= 8) {
        written = snprintf(*buf, *rem, ";%d", 39 + bg);
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    } else if (bg > 8 && bg <= 16) {
        written = snprintf(*buf, *rem, ";%d", 91 + bg);
        if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
    }

    written = snprintf(*buf, *rem, "m");
    if (written > 0 && (size_t)written < *rem) { *buf += written; *rem -= (size_t)written; }
}

void term_present(void) {
    if (!g_front_chars || !g_back_chars) return;

    char out_buf[65536];
    char *ptr = out_buf;
    size_t rem = sizeof(out_buf) - 64;

    uint32_t current_attr = 0xFFFFFFFF;
    int cursor_y = -1;
    int cursor_x = -1;

    for (int y = 0; y < g_rows; y++) {
        for (int x = 0; x < g_cols; x++) {
            int idx = y * g_cols + x;
            if (g_back_chars[idx] != g_front_chars[idx] || g_back_attrs[idx] != g_front_attrs[idx]) {
                if (cursor_y != y || cursor_x != x) {
                    int w = snprintf(ptr, rem, "\033[%d;%dH", y + 1, x + 1);
                    if (w > 0 && (size_t)w < rem) { ptr += w; rem -= (size_t)w; }
                    cursor_y = y;
                    cursor_x = x;
                }

                if (g_back_attrs[idx] != current_attr) {
                    apply_attr(g_back_attrs[idx], current_attr, &ptr, &rem);
                    current_attr = g_back_attrs[idx];
                }

                *ptr++ = g_back_chars[idx];
                rem--;
                cursor_x++;

                g_front_chars[idx] = g_back_chars[idx];
                g_front_attrs[idx] = g_back_attrs[idx];

                if (rem < 256) {
                    write(STDOUT_FILENO, out_buf, (size_t)(ptr - out_buf));
                    ptr = out_buf;
                    rem = sizeof(out_buf) - 64;
                }
            }
        }
    }

    if (ptr > out_buf) {
        write(STDOUT_FILENO, out_buf, (size_t)(ptr - out_buf));
    }
}

bool term_poll_event(input_event_t *event, int timeout_ms) {
    if (!event) return false;
    memset(event, 0, sizeof(*event));

    if (g_resized) {
        g_resized = 0;
        update_dimensions();
        event->type = KEY_RESIZE;
        return true;
    }

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) {
        return false;
    }

    unsigned char seq[64];
    ssize_t n = read(STDIN_FILENO, seq, sizeof(seq) - 1);
    if (n <= 0) return false;
    seq[n] = '\0';

    if (seq[0] == 27) {
        if (n == 1) {
            event->type = KEY_ESC;
            return true;
        }

        if (n == 2) {
            switch (seq[1]) {
                case 'h': case 'H': event->type = KEY_ALT_H; return true;
                case 'v': case 'V': event->type = KEY_ALT_V; return true;
                case 'm': case 'M': event->type = KEY_ALT_M; return true;
                case 'z': case 'Z': event->type = KEY_ALT_Z; return true;
                case '[':           event->type = KEY_ALT_LBRACKET; return true;
                case ']':           event->type = KEY_ALT_RBRACKET; return true;
                default: break;
            }
        }

        if (seq[1] == 'O') {
            switch (seq[2]) {
                case 'P': event->type = KEY_F1; return true;
                case 'Q': event->type = KEY_F2; return true;
                case 'R': event->type = KEY_F3; return true;
                case 'S': event->type = KEY_F4; return true;
                default: break;
            }
        }

        if (seq[1] == '[') {
            if (seq[2] == '<') {
                int btn = 0, mx = 0, my = 0;
                char action = 'M';
                if (sscanf((char *)seq + 3, "%d;%d;%d%c", &btn, &mx, &my, &action) >= 3) {
                    if (action == 'M' || action == 'm') {
                        event->type = KEY_MOUSE_CLICK;
                        event->mouse_btn = btn;
                        event->mouse_x = mx - 1;
                        event->mouse_y = my - 1;
                        return true;
                    }
                }
            }

            switch (seq[2]) {
                case 'A': event->type = KEY_UP; return true;
                case 'B': event->type = KEY_DOWN; return true;
                case 'C': event->type = KEY_RIGHT; return true;
                case 'D': event->type = KEY_LEFT; return true;
                case 'H': event->type = KEY_HOME; return true;
                case 'F': event->type = KEY_END; return true;
                case '1':
                    if (n >= 4 && seq[3] == ';') {
                        if (seq[4] == '3') {
                            if (seq[5] == 'A') { event->type = KEY_ALT_UP; return true; }
                            if (seq[5] == 'B') { event->type = KEY_ALT_DOWN; return true; }
                            if (seq[5] == 'C') { event->type = KEY_ALT_RIGHT; return true; }
                            if (seq[5] == 'D') { event->type = KEY_ALT_LEFT; return true; }
                        }
                    }
                    if (n >= 4 && seq[3] == '~') { event->type = KEY_HOME; return true; }
                    if (n >= 4 && seq[3] == '5' && seq[4] == '~') { event->type = KEY_F5; return true; }
                    if (n >= 4 && seq[3] == '7' && seq[4] == '~') { event->type = KEY_F6; return true; }
                    if (n >= 4 && seq[3] == '8' && seq[4] == '~') { event->type = KEY_F7; return true; }
                    if (n >= 4 && seq[3] == '9' && seq[4] == '~') { event->type = KEY_F8; return true; }
                    break;
                case '2':
                    if (n >= 4 && seq[3] == '0' && seq[4] == '~') { event->type = KEY_F9; return true; }
                    if (n >= 4 && seq[3] == '1' && seq[4] == '~') { event->type = KEY_F10; return true; }
                    break;
                case '3':
                    if (n >= 4 && seq[3] == '~') { event->type = KEY_BACKSPACE; return true; }
                    break;
                case '5':
                    if (n >= 4 && seq[3] == '~') { event->type = KEY_PGUP; return true; }
                    break;
                case '6':
                    if (n >= 4 && seq[3] == '~') { event->type = KEY_PGDN; return true; }
                    break;
                default: break;
            }
        }
    }

    if (seq[0] == '\r' || seq[0] == '\n') {
        event->type = KEY_ENTER;
        return true;
    }
    if (seq[0] == '\t') {
        event->type = KEY_TAB;
        return true;
    }
    if (seq[0] == 127 || seq[0] == '\b') {
        event->type = KEY_BACKSPACE;
        return true;
    }

    event->type = KEY_CHAR;
    event->ch = seq[0];
    return true;
}
