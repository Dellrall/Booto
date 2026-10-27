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
#include "disk_mount.h"
#include "forensic_scan.h"
#include "tui/tui_app.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

#define EXIT_CLEAN 0
#define EXIT_THREATS 1
#define EXIT_INCOMPLETE 2

void booto_context_init(booto_context_t *ctx) {
    if (!ctx) return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = BOOTO_MODE_TUI;
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
    printf("  -d, --dry-run              Print the planned scan and exit without touching any disk\n");
    printf("  -m, --mock-drives          Inject virtual mock drives for TUI testing\n");
    printf("  -t, --target <dev>         Raw block device to scan (mounted read-only)\n");
    printf("  -s, --scan-dir <path>      Specify local rootfs path to inspect\n");
    printf("  -p, --persistence-dir <dir>Write JSON+Markdown case reports to <dir>\n");
    printf("  -u, --update-rules         Fetch latest DBX revocations & rootkit signatures\n");
    printf("  -V, --verbose              Enable verbose/debug logging\n\n");
    printf("CLI exit codes:\n");
    printf("  0  CLEAN       every enabled engine ran and found nothing\n");
    printf("  1  THREATS     at least one engine reported a threat\n");
    printf("  2  INCOMPLETE  an engine failed, nothing ran, or the scan could not start\n\n");
}

static void scan_progress(int step, int total, const char *msg, void *user) {
    (void)user;
    LOG_INFO("[%d/%d] Running %s engine", step, total, msg);
}

/* Pick the target: -t, else -s alone, else the first auto-discovered partition marked is_target. */
static bool resolve_target(booto_context_t *ctx) {
    if (ctx->target_dev[0] || ctx->target_rootfs[0]) return true;
    disk_discovery_result_t *res = calloc(1, sizeof(*res));
    if (!res) return false;
    bool found = false;
    if (disk_discover_partitions(res, ctx->mock_drives) == BOOTO_OK) {
        for (int i = 0; i < res->count; i++) {
            if (res->partitions[i].is_target) {
                snprintf(ctx->target_dev, sizeof(ctx->target_dev), "%.127s", res->partitions[i].dev_path);
                found = true;
                break;
            }
        }
    }
    free(res);
    return found;
}

static void write_reports(const forensic_scan_report_t *rep, const char *dir) {
    char case_id[64];
    time_t now = time(NULL);
    struct tm tm_utc;
    if (!gmtime_r(&now, &tm_utc) || strftime(case_id, sizeof(case_id), "CASE-%Y%m%d-%H%M%S", &tm_utc) == 0) {
        snprintf(case_id, sizeof(case_id), "CASE-unknown");
    }
    const char *user = getenv("USER");
    forensic_case_summary_t sum;
    forensic_scan_fill_case_summary(rep, case_id, (user && user[0]) ? user : "unknown", &sum);

    char path[512];
    booto_error_t e = case_report_generate_json(&sum, dir, path, sizeof(path));
    if (e == BOOTO_OK) printf("JSON report:     %s\n", path);
    else fprintf(stderr, "Failed to write JSON report to %s (error %d)\n", dir, e);
    e = case_report_generate_markdown(&sum, dir, path, sizeof(path));
    if (e == BOOTO_OK) printf("Markdown report: %s\n", path);
    else fprintf(stderr, "Failed to write Markdown report to %s (error %d)\n", dir, e);
}

static int run_cli(booto_context_t *ctx) {
    LOG_INFO("Booto CLI Mode initialized (Version: %s)", BOOTO_VERSION_STRING);
    if (!resolve_target(ctx)) {
        LOG_ERROR("No scan target: pass -t <dev> or -s <dir> (auto-discovery found no target partition)");
        return EXIT_INCOMPLETE;
    }
    forensic_scan_report_t *rep = calloc(1, sizeof(*rep));
    if (!rep) {
        LOG_ERROR("Out of memory allocating scan report");
        return EXIT_INCOMPLETE;
    }
    booto_error_t e = forensic_scan_run(ctx->target_dev[0] ? ctx->target_dev : NULL,
                                        ctx->target_rootfs[0] ? ctx->target_rootfs : NULL,
                                        NULL, scan_progress, NULL, rep);
    if (e != BOOTO_OK) {
        LOG_ERROR("Scan could not run (error %d)", e);
        free(rep);
        return EXIT_INCOMPLETE;
    }

    printf("\nTarget: %s  Root: %s\n\n", rep->target_dev[0] ? rep->target_dev : "(none)", rep->scan_root);
    printf("%-12s | %-8s | %-7s | %s\n", "Module", "Status", "Threats", "Note");
    printf("-------------+----------+---------+------------------------------\n");
    const int threats[SCAN_MOD_COUNT] = {rep->mbr.threats_detected, rep->uefi.bootkits_detected,
                                         rep->kernel.threats_detected, rep->initramfs.threats_detected,
                                         rep->preload.threats_detected, 0};
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        printf("%-12s | %-8s | %7d | %s\n", forensic_scan_module_name((scan_module_id_t)i),
               forensic_scan_status_str(rep->status[i]), threats[i], rep->note[i]);
    }
    printf("\nVerdict: %s\n", forensic_scan_verdict_str(rep->verdict));

    if (ctx->persistence_dir[0]) write_reports(rep, ctx->persistence_dir);

    int code = rep->verdict == SCAN_VERDICT_CLEAN ? EXIT_CLEAN
             : rep->verdict == SCAN_VERDICT_THREATS ? EXIT_THREATS : EXIT_INCOMPLETE;
    free(rep);
    return code;
}

static void print_dry_run(const booto_context_t *ctx) {
    printf("Dry-run: no disk will be touched.\n");
    if (ctx->target_dev[0]) printf("  Target device : %s\n", ctx->target_dev);
    else if (ctx->target_rootfs[0]) printf("  Target device : (none, rootfs only)\n");
    else printf("  Target device : auto-discover first target partition%s\n", ctx->mock_drives ? " (mock drives included)" : "");
    if (ctx->target_rootfs[0]) printf("  Rootfs        : %s\n", ctx->target_rootfs);
    else printf("  Rootfs        : device mounted read-only at /tmp/booto_scan_target\n");
    printf("  Modules       :");
    for (int i = 0; i < SCAN_MOD_COUNT; i++) printf(" %s%s", forensic_scan_module_name((scan_module_id_t)i), i + 1 < SCAN_MOD_COUNT ? "," : "\n");
    printf("  Report dir    : %s\n", ctx->persistence_dir[0] ? ctx->persistence_dir : "(none)");
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
        {"target",          required_argument, 0, 't'},
        {"scan-dir",        required_argument, 0, 's'},
        {"persistence-dir", required_argument, 0, 'p'},
        {"update-rules",    no_argument,       0, 'u'},
        {"verbose",         no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "hvcdmt:s:p:uV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'v':
                printf("Booto version %s (commit %s, built %s)\n",
                       BOOTO_VERSION_STRING, BOOTO_GIT_HASH, BOOTO_BUILD_TIMESTAMP);
                return 0;
            case 'u':
                logger_init(LOG_LEVEL_INFO, NULL);
                LOG_INFO("Triggering Booto forensic rules and DBX updater...");
                int res = system("./scripts/update_rules.sh");
                logger_shutdown();
                if (res == -1 || !WIFEXITED(res)) return 1;
                return WEXITSTATUS(res);
            case 'c':
                ctx.mode = BOOTO_MODE_CLI;
                break;
            case 'd':
                ctx.mode = BOOTO_MODE_DRY_RUN;
                break;
            case 'm':
                ctx.mock_drives = true;
                break;
            case 't':
                snprintf(ctx.target_dev, sizeof(ctx.target_dev), "%s", optarg);
                break;
            case 's':
                snprintf(ctx.target_rootfs, sizeof(ctx.target_rootfs), "%s", optarg);
                break;
            case 'p':
                snprintf(ctx.persistence_dir, sizeof(ctx.persistence_dir), "%s", optarg);
                break;
            case 'V':
                ctx.verbose = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    logger_init(ctx.verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO, NULL);
    int rc;
    if (ctx.mode == BOOTO_MODE_DRY_RUN) {
        LOG_INFO("Booto Engine initialized (Version: %s, Mode: Dry-Run)", BOOTO_VERSION_STRING);
        print_dry_run(&ctx);
        rc = 0;
    } else if (ctx.mode == BOOTO_MODE_CLI) {
        rc = run_cli(&ctx);
    } else {
        rc = tui_app_run(&ctx);
    }
    logger_shutdown();
    return rc;
}
