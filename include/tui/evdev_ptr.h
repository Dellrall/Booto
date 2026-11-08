/**
 * @file evdev_ptr.h
 * @brief Absolute pointers (VM tablets, touchscreens) read straight from evdev.
 *
 * Kept apart from terminal.h: <linux/input.h> defines KEY_* macros that clash with key_type_t.
 */
#ifndef BOOTO_EVDEV_PTR_H
#define BOOTO_EVDEV_PTR_H

typedef enum { PTR_NONE, PTR_CLICK_LEFT, PTR_CLICK_RIGHT, PTR_WHEEL_UP, PTR_WHEEL_DOWN } ptr_action_t;

/** One evdev absolute pointer: axis ranges and the last cell it pointed at (-1 until known). */
typedef struct {
    int fd;
    int x_min, x_max, y_min, y_max;
    int x, y;
} term_abs_ptr_t;

/** Opens and grabs up to max screen-mapped absolute pointers (needs root); returns how many. */
int evdev_ptr_open_all(term_abs_ptr_t *out, int max);

/** Maps an absolute axis value in [min, max] onto a cell index in [0, cells). */
int term_abs_to_cell(int value, int min, int max, int cells);

/** Feeds one evdev event (type, code, value) to p; motion only updates p->x/p->y. */
ptr_action_t term_abs_feed(term_abs_ptr_t *p, unsigned type, unsigned code, int value, int rows, int cols);

/** Reads p's pending events until one is a click or wheel step. */
ptr_action_t evdev_ptr_read(term_abs_ptr_t *p, int rows, int cols);

#endif
