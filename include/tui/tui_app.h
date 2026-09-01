/**
 * @file tui_app.h
 * @brief Main TUI application runner and event loop for Booto.
 */
#ifndef BOOTO_TUI_APP_H
#define BOOTO_TUI_APP_H

#include "booto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the interactive TUI application loop.
 * @param ctx Global booto execution context.
 * @return 0 on normal exit, non-zero on error.
 */
int tui_app_run(booto_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* BOOTO_TUI_APP_H */
