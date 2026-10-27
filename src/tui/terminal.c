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

/* Disable mouse tracking, reset attributes, show cursor, leave alternate screen. */
static const char RESTORE_SEQ[] = "\033[?1006l\033[?1002l\033[?1000l\033[0m\033[?25h\033[?1049l";
static const char ENTER_SEQ[] = "\033[?1049h\033[?25l\033[?1000h\033[?1002h\033[?1006h";

static struct termios g_orig_termios;
static bool g_raw_active = false;
static bool g_atexit_registered = false;
/* 1 while the tty is in raw/alt-screen state; cleared by whichever restore path runs first. */
static volatile sig_atomic_t g_tty_dirty = 0;
static volatile sig_atomic_t g_resized = 0;

static const int FATAL_SIGNALS[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGSEGV, SIGBUS, SIGABRT, SIGFPE };
#define FATAL_SIGNAL_COUNT (sizeof(FATAL_SIGNALS) / sizeof(FATAL_SIGNALS[0]))
static struct sigaction g_old_fatal_sa[FATAL_SIGNAL_COUNT];
static struct sigaction g_old_winch_sa;

static int g_rows = 24;
static int g_cols = 80;

static char *g_front_chars = NULL;
static uint32_t *g_front_attrs = NULL;
static char *g_back_chars = NULL;
static uint32_t *g_back_attrs = NULL;

/* Unparsed input bytes left over from a read that returned several keys. */
static unsigned char g_pending[64];
static size_t g_pending_len = 0;

/* Async-signal-safe: only tcsetattr() and write(). */
static void restore_tty(int when) {
    if (!g_tty_dirty) return;
    g_tty_dirty = 0;
    ssize_t w = write(STDOUT_FILENO, RESTORE_SEQ, sizeof(RESTORE_SEQ) - 1);
    (void)w;
    tcsetattr(STDIN_FILENO, when, &g_orig_termios);
}

static void restore_tty_atexit(void) {
    restore_tty(TCSANOW);
}

static void handle_fatal_signal(int sig) {
    restore_tty(TCSANOW);
    struct sigaction dfl;
    memset(&dfl, 0, sizeof(dfl));
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(sig, &dfl, NULL);
    raise(sig); /* delivered with the default action once this handler returns */
}

static void handle_sigwinch(int sig) {
    (void)sig;
    g_resized = 1;
}

/* All-or-nothing: on any allocation failure the old buffers and dimensions stay committed. */
static void update_dimensions(void) {
    int rows = 24;
    int cols = 80;
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        rows = ws.ws_row;
        cols = ws.ws_col;
    }

    size_t cells = (size_t)rows * (size_t)cols;
    char *fc = malloc(cells);
    uint32_t *fa = malloc(cells * sizeof(uint32_t));
    char *bc = malloc(cells);
    uint32_t *ba = malloc(cells * sizeof(uint32_t));
    if (!fc || !fa || !bc || !ba) {
        free(fc);
        free(fa);
        free(bc);
        free(ba);
        return;
    }

    free(g_front_chars);
    free(g_front_attrs);
    free(g_back_chars);
    free(g_back_attrs);
    g_front_chars = fc;
    g_front_attrs = fa;
    g_back_chars = bc;
    g_back_attrs = ba;
    g_rows = rows;
    g_cols = cols;

    memset(g_front_chars, 0, cells);
    memset(g_front_attrs, 0xFF, cells * sizeof(uint32_t));
    memset(g_back_chars, ' ', cells);
    memset(g_back_attrs, 0, cells * sizeof(uint32_t));
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

    if (!g_atexit_registered) {
        if (atexit(restore_tty_atexit) != 0) return -1;
        g_atexit_registered = true;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handle_fatal_signal;
    for (size_t i = 0; i < FATAL_SIGNAL_COUNT; i++) {
        sigaction(FATAL_SIGNALS[i], &sa, &g_old_fatal_sa[i]);
    }
    sa.sa_handler = handle_sigwinch;
    sigaction(SIGWINCH, &sa, &g_old_winch_sa);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) {
        for (size_t i = 0; i < FATAL_SIGNAL_COUNT; i++) {
            sigaction(FATAL_SIGNALS[i], &g_old_fatal_sa[i], NULL);
        }
        sigaction(SIGWINCH, &g_old_winch_sa, NULL);
        return -1;
    }
    g_raw_active = true;
    g_tty_dirty = 1;
    g_pending_len = 0;

    ssize_t w = write(STDOUT_FILENO, ENTER_SEQ, sizeof(ENTER_SEQ) - 1);
    (void)w;

    update_dimensions();
    return 0;
}

void term_shutdown(void) {
    if (!g_raw_active) return;

    restore_tty(TCSAFLUSH);
    g_raw_active = false;

    for (size_t i = 0; i < FATAL_SIGNAL_COUNT; i++) {
        sigaction(FATAL_SIGNALS[i], &g_old_fatal_sa[i], NULL);
    }
    sigaction(SIGWINCH, &g_old_winch_sa, NULL);

    free(g_front_chars);
    free(g_front_attrs);
    free(g_back_chars);
    free(g_back_attrs);
    g_front_chars = NULL;
    g_front_attrs = NULL;
    g_back_chars = NULL;
    g_back_attrs = NULL;
    g_pending_len = 0;
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
    size_t cells = (size_t)g_rows * (size_t)g_cols;
    memset(g_back_chars, ' ', cells);
    memset(g_back_attrs, 0, cells * sizeof(uint32_t));
}

void term_putc(int x, int y, char c, uint32_t attr) {
    if (x < 0 || x >= g_cols || y < 0 || y >= g_rows) return;
    if (!g_back_chars || !g_back_attrs) return;

    size_t idx = (size_t)y * (size_t)g_cols + (size_t)x;
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
            size_t idx = (size_t)y * (size_t)g_cols + (size_t)x;
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

/* Decodes a complete CSI sequence s[0..len) (ESC '[' params final, len >= 3); leaves KEY_NONE if unknown. */
static void parse_csi(const unsigned char *s, size_t len, input_event_t *event) {
    unsigned char final = s[len - 1];
    const unsigned char *p = s + 2;
    size_t plen = len - 3;

    if (plen > 0 && p[0] == '<') {
        if (final != 'M' && final != 'm') return;
        char tmp[sizeof(g_pending)];
        memcpy(tmp, p + 1, plen - 1);
        tmp[plen - 1] = '\0';
        int btn = 0, mx = 0, my = 0;
        if (sscanf(tmp, "%d;%d;%d", &btn, &mx, &my) == 3) {
            event->type = KEY_MOUSE_CLICK;
            event->mouse_btn = btn;
            event->mouse_x = mx - 1;
            event->mouse_y = my - 1;
        }
        return;
    }

    int p1 = 0, p2 = 0;
    size_t i = 0;
    for (; i < plen && p[i] >= '0' && p[i] <= '9'; i++) {
        if (p1 < 10000) p1 = p1 * 10 + (p[i] - '0');
    }
    if (i < plen && p[i] == ';') {
        for (i++; i < plen && p[i] >= '0' && p[i] <= '9'; i++) {
            if (p2 < 10000) p2 = p2 * 10 + (p[i] - '0');
        }
    }
    bool alt = (p2 == 3);

    switch (final) {
        case 'A': event->type = alt ? KEY_ALT_UP : KEY_UP; return;
        case 'B': event->type = alt ? KEY_ALT_DOWN : KEY_DOWN; return;
        case 'C': event->type = alt ? KEY_ALT_RIGHT : KEY_RIGHT; return;
        case 'D': event->type = alt ? KEY_ALT_LEFT : KEY_LEFT; return;
        case 'H': event->type = KEY_HOME; return;
        case 'F': event->type = KEY_END; return;
        default: return;
        case '~':
            switch (p1) {
                case 1:  event->type = KEY_HOME; return;
                case 3:  event->type = KEY_BACKSPACE; return;
                case 5:  event->type = KEY_PGUP; return;
                case 6:  event->type = KEY_PGDN; return;
                case 15: event->type = KEY_F5; return;
                case 17: event->type = KEY_F6; return;
                case 18: event->type = KEY_F7; return;
                case 19: event->type = KEY_F8; return;
                case 20: event->type = KEY_F9; return;
                case 21: event->type = KEY_F10; return;
                case 23: event->type = KEY_F11; return;
                case 24: event->type = KEY_F12; return;
                default: return;
            }
    }
}

/* Decodes the first key in buf[0..n) (n >= 1); returns bytes consumed (>= 1). KEY_NONE = unrecognised. */
static size_t parse_input(const unsigned char *buf, size_t n, input_event_t *event) {
    if (buf[0] != 27) {
        switch (buf[0]) {
            case '\r': case '\n': event->type = KEY_ENTER; break;
            case '\t':            event->type = KEY_TAB; break;
            case 127: case '\b':  event->type = KEY_BACKSPACE; break;
            /* Ctrl+C, Ctrl+Q, Ctrl+X -> exit menu */
            case 3: case 17: case 24: event->type = KEY_F10; break;
            default:
                event->type = KEY_CHAR;
                event->ch = buf[0];
                break;
        }
        return 1;
    }

    if (n == 1 || buf[1] == 27) {
        event->type = KEY_ESC;
        return 1;
    }

    if (buf[1] == '[' && n > 2) {
        if (buf[2] == '[') {
            /* Linux console F1-F5: ESC [ [ A..E */
            static const key_type_t console_fkeys[] = { KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5 };
            if (n < 4) return n;
            if (buf[3] >= 'A' && buf[3] <= 'E') event->type = console_fkeys[buf[3] - 'A'];
            return 4;
        }
        size_t end = 2;
        while (end < n && (buf[end] < 0x40 || buf[end] > 0x7E)) end++;
        if (end == n) return n; /* truncated sequence: drop it */
        parse_csi(buf, end + 1, event);
        return end + 1;
    }

    if (buf[1] == 'O' && n > 2) {
        switch (buf[2]) {
            case 'P': event->type = KEY_F1; break;
            case 'Q': event->type = KEY_F2; break;
            case 'R': event->type = KEY_F3; break;
            case 'S': event->type = KEY_F4; break;
            default: break;
        }
        return 3;
    }

    switch (buf[1]) {
        case 'h': case 'H': event->type = KEY_ALT_H; break;
        case 'v': case 'V': event->type = KEY_ALT_V; break;
        case 'm': case 'M': event->type = KEY_ALT_M; break;
        case 'z': case 'Z': event->type = KEY_ALT_Z; break;
        case '[':           event->type = KEY_ALT_LBRACKET; break;
        case ']':           event->type = KEY_ALT_RBRACKET; break;
        default: break;
    }
    return 2;
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

    if (g_pending_len == 0) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) <= 0) return false;

        memset(g_pending, 0, sizeof(g_pending));
        ssize_t n = read(STDIN_FILENO, g_pending, sizeof(g_pending));
        if (n <= 0) return false;
        g_pending_len = (size_t)n;
    }

    while (g_pending_len > 0) {
        size_t used = parse_input(g_pending, g_pending_len, event);
        g_pending_len -= used;
        memmove(g_pending, g_pending + used, g_pending_len);
        if (event->type != KEY_NONE) return true;
        memset(event, 0, sizeof(*event));
    }
    return false;
}
