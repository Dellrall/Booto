/**
 * @file main.c
 * @brief Booto main entry point and CLI / TUI option dispatcher.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "booto.h"
#include "logger.h"
#include "version.h"
#include "tui/tui_app.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void booto_context_init(booto_context_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = BOOTO_MODE_TUI;
    ctx->verbose = false;
    ctx->mock_drives = false;
    ctx->enable_persistence = false;
    ctx->target_rootfs[0] = '\0';
    ctx->persistence_dir[0] = '\0';
    ctx->output_report_path[0] = '\0';
}

static void print_banner(void) {
    printf("\033[1;36m");
    printf("  ____                   _        \n");
    printf(" | __ )   ___    ___   | |_  ___  \n");
    printf(" |  _ \\  / _ \\  / _ \\  | __|/ _ \\ \n");
    printf(" | |_) || (_) || (_) | | |_| (_) |\n");
    printf(" |____/  \\___/  \\___/   \\__|\\___/ \n");
    printf("\033[0m");
    printf(" Live Linux Forensic Rootkit & Bootkit Detection Suite\n");
    printf(" Version: %s (Git: %s, Built: %s)\n\n",
           BOOTO_VERSION_STRING, BOOTO_GIT_HASH, BOOTO_BUILD_TIMESTAMP);
}

static void print_help(const char *prog_name) {
    print_banner();
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help                 Show this help menu\n");
    printf("  -v, --version              Show version and build details\n");
    printf("  -c, --cli                  Run in headless CLI mode (default: TUI)\n");
    printf("  -d, --dry-run              Run mock scan without mounting real drives\n");
    printf("  -m, --mock-drives          Inject virtual mock drives for TUI testing\n");
    printf("  -s, --scan-dir <path>      Specify local rootfs path to inspect\n");
    printf("  -p, --persistence-dir <dir>Specify directory for encrypted reports\n");
    printf("  -V, --verbose              Enable verbose/debug logging\n\n");
}

int main(int argc, char *argv[]) {
    booto_context_t ctx;
    booto_context_init(&ctx);

    static struct option long_options[] = {
        {"help",            no_argument,       0, 'h'},
        {"version",         no_argument,       0, 'v'},
        {"cli",             no_argument,       0, 'c'},
        {"dry-run",         no_argument,       0, 'd'},
        {"mock-drives",     no_argument,       0, 'm'},
        {"scan-dir",        required_argument, 0, 's'},
        {"persistence-dir", required_argument, 0, 'p'},
        {"verbose",         no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "hvcdms:p:V", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'v':
                printf("Booto version %s (commit %s, built %s)\n",
                       BOOTO_VERSION_STRING, BOOTO_GIT_HASH, BOOTO_BUILD_TIMESTAMP);
                return 0;
            case 'c':
                ctx.mode = BOOTO_MODE_CLI;
                break;
            case 'd':
                ctx.mode = BOOTO_MODE_DRY_RUN;
                break;
            case 'm':
                ctx.mock_drives = true;
                break;
            case 's':
                snprintf(ctx.target_rootfs, sizeof(ctx.target_rootfs), "%s", optarg);
                break;
            case 'p':
                snprintf(ctx.persistence_dir, sizeof(ctx.persistence_dir), "%s", optarg);
                ctx.enable_persistence = true;
                break;
            case 'V':
                ctx.verbose = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if (ctx.mode == BOOTO_MODE_DRY_RUN) {
        logger_init(ctx.verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO, NULL);
        LOG_INFO("Booto Engine initialized (Version: %s, Mode: Dry-Run)", BOOTO_VERSION_STRING);
        if (ctx.mock_drives) {
            LOG_INFO("Mock drive emulation active");
        }
        LOG_INFO("Dry-run execution completed successfully.");
        logger_shutdown();
        return 0;
    } else if (ctx.mode == BOOTO_MODE_CLI) {
        logger_init(ctx.verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO, NULL);
        LOG_INFO("Booto CLI Mode initialized (Version: %s)", BOOTO_VERSION_STRING);
        LOG_INFO("Target rootfs: %s", ctx.target_rootfs[0] ? ctx.target_rootfs : "Auto-discover");
        LOG_INFO("Running CLI scan triage...");
        logger_shutdown();
        return 0;
    } else {
        // Interactive TUI Mode
        return tui_app_run(&ctx);
    }
}
