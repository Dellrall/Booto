/**
 * @file evdev_ptr.c
 * @brief Mice and absolute pointers read straight from evdev: through gpm the console reports only clicks, never motion.
 */
#include "tui/evdev_ptr.h"

#include <fcntl.h>
#include <linux/input.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BIT_SET(arr, bit) ((arr)[(bit) / (8 * sizeof(long))] & (1UL << ((bit) % (8 * sizeof(long)))))

/* Needs root (the live ISO); silently finds nothing otherwise. */
int evdev_ptr_open_all(term_abs_ptr_t *out, int max) {
    int count = 0;
    for (int n = 0; n < 32 && count < max; n++) {
        char path[32];
        snprintf(path, sizeof(path), "/dev/input/event%d", n);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        unsigned long abs_bits[ABS_CNT / (8 * sizeof(long)) + 1] = {0};
        unsigned long rel_bits[REL_CNT / (8 * sizeof(long)) + 1] = {0};
        unsigned long key_bits[KEY_CNT / (8 * sizeof(long)) + 1] = {0};
        unsigned long props[INPUT_PROP_CNT / (8 * sizeof(long)) + 1] = {0};
        struct input_absinfo ax = {0}, ay = {0};
        ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(abs_bits)), abs_bits);
        ioctl(fd, EVIOCGBIT(EV_REL, sizeof(rel_bits)), rel_bits);
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits);
        bool ok = BIT_SET(abs_bits, ABS_X) && BIT_SET(abs_bits, ABS_Y) &&
                  (BIT_SET(key_bits, BTN_LEFT) || BIT_SET(key_bits, BTN_TOUCH)) &&
                  ioctl(fd, EVIOCGABS(ABS_X), &ax) >= 0 && ioctl(fd, EVIOCGABS(ABS_Y), &ay) >= 0 &&
                  ax.maximum > ax.minimum && ay.maximum > ay.minimum;
        /* Touchpads report ABS_X/Y too, but relative to the pad, not the screen: leave them to gpm. */
        if (ok && ioctl(fd, EVIOCGPROP(sizeof(props)), props) >= 0 && BIT_SET(props, INPUT_PROP_POINTER)) ok = false;
        /* A device with screen-mapped axes is a tablet even if it also sends REL events. */
        bool rel = !ok && BIT_SET(rel_bits, REL_X) && BIT_SET(rel_bits, REL_Y) && BIT_SET(key_bits, BTN_LEFT);
        ok = ok || rel;
        /* Grab so mousedev (and gpm behind it) gets nothing: no drifting tablet motion, no doubled mouse clicks. */
        if (!ok || ioctl(fd, EVIOCGRAB, 1) < 0) {
            close(fd);
            continue;
        }
        out[count++] = (term_abs_ptr_t){.fd = fd, .x_min = ax.minimum, .x_max = ax.maximum,
                                        .y_min = ay.minimum, .y_max = ay.maximum, .x = -1, .y = -1, .rel = rel};
    }
    return count;
}

int term_abs_to_cell(int value, int min, int max, int cells) {
    if (cells <= 0 || max <= min) return 0;
    long long c = (long long)(value - min) * cells / ((long long)max - min + 1);
    return c < 0 ? 0 : c >= cells ? cells - 1 : (int)c;
}

ptr_action_t term_abs_feed(term_abs_ptr_t *p, unsigned type, unsigned code, int value, int rows, int cols) {
    if (p->rel && type == EV_REL && (code == REL_X || code == REL_Y)) {
        if (p->x < 0 || p->y < 0) { /* a mouse has no position of its own: start in the middle */
            p->x = cols / 2;
            p->y = rows / 2;
        }
        bool horiz = code == REL_X;
        int *cell = horiz ? &p->x : &p->y, *acc = horiz ? &p->rx : &p->ry;
        int per = horiz ? EVDEV_REL_PER_COL : EVDEV_REL_PER_ROW, cells = horiz ? cols : rows;
        *acc += value;
        int next = *cell + *acc / per;
        *acc %= per;
        if (next < 0 || next >= cells) *acc = 0; /* pushing past an edge must not bank motion */
        next = next < 0 ? 0 : next >= cells ? cells - 1 : next;
        bool moved = next != *cell;
        *cell = next;
        return p->held && moved ? PTR_DRAG : PTR_NONE;
    }
    if (!p->rel && type == EV_ABS && (code == ABS_X || code == ABS_Y)) {
        int *cell = code == ABS_X ? &p->x : &p->y;
        int next = code == ABS_X ? term_abs_to_cell(value, p->x_min, p->x_max, cols)
                                 : term_abs_to_cell(value, p->y_min, p->y_max, rows);
        bool moved = next != *cell;
        *cell = next;
        return p->held && moved && p->x >= 0 && p->y >= 0 ? PTR_DRAG : PTR_NONE;
    }
    if (type == EV_KEY && (code == BTN_LEFT || code == BTN_TOUCH) && value != 2) {
        bool was = p->held;
        p->held = value == 1 && p->x >= 0 && p->y >= 0;
        if (!p->held && value == 1) return PTR_NONE;
        if (value == 1 && !was) return PTR_CLICK_LEFT;
        if (value == 0 && was) return PTR_RELEASE;
        return PTR_NONE;
    }
    if (p->x < 0 || p->y < 0) return PTR_NONE;
    if (type == EV_KEY && value == 1 && code == BTN_RIGHT) return PTR_CLICK_RIGHT;
    if (type == EV_KEY && value == 1 && code == BTN_MIDDLE) return PTR_CLICK_MIDDLE;
    if (type == EV_REL && code == REL_WHEEL && value != 0) return value > 0 ? PTR_WHEEL_UP : PTR_WHEEL_DOWN;
    return PTR_NONE;
}

ptr_action_t evdev_ptr_read(term_abs_ptr_t *p, int rows, int cols) {
    struct input_event ev;
    while (read(p->fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {
        ptr_action_t a = term_abs_feed(p, ev.type, ev.code, ev.value, rows, cols);
        if (a != PTR_NONE) return a;
    }
    return PTR_NONE;
}
