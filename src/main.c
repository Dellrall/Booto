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
#include "persistence_mgr.h"
#include "disk_mount.h"
#include "forensic_scan.h"
#include "tui/tui_app.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
    static const char *const logo[] = {
        "######    #####    #####   ########   ##### ",
        "##   ##  ##   ##  ##   ##     ##     ##   ##",
        "######   ##   ##  ##   ##     ##     ##   ##",
        "##   ##  ##   ##  ##   ##     ##     ##   ##",
        "######    #####    #####      ##      ##### ",
    };
    const char *ascii = getenv("BOOTO_ASCII");
    const char *block = (ascii && ascii[0] == '1') ? "#" : "\u2588"; // full block, also in the console's CP437 font
    int color = logger_use_color(stdout);
    if (color) printf("\033[1m"); // bold in the terminal's own text color: white on dark themes, still readable on light ones
    for (size_t i = 0; i < sizeof(logo) / sizeof(logo[0]); i++) {
        printf(" ");
        for (const char *c = logo[i]; *c; c++) fputs(*c == '#' ? block : " ", stdout);
        printf("\n");
    }
    if (color) printf("\033[0m");
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
    printf("  -u, --update-rules         Regenerate rule files (scripts/update_rules.sh)\n");
    printf("  -x, --expert-firmware      CLI, as root: also scan UEFI variables for hidden code and\n");
    printf("                             dump the SPI flash read-only with flashrom (slower; off by default)\n");
    printf("  -q, --quarantine           CLI, with -p: copy flagged files into an encrypted ZIP (password\n");
    printf("                             \"infected\") under <dir>/quarantine for analysis elsewhere\n");
    printf("      --baseline <file>      CLI: also write the boot chain hashes (first 1 MiB, /boot, ESP,\n");
    printf("                             Windows core files) to <file>; run it on a known-good machine\n");
    printf("      --compare <file>       CLI: list what changed in the boot chain since that baseline\n");
    printf("      --bodyfile <file>      CLI: write a Sleuth Kit bodyfile of the scanned root to <file>,\n");
    printf("                             for a timeline with mactime(1)\n");
    printf("      --hashlist <file>      CLI: write SHA-256 of every executable file in the scanned root\n");
    printf("                             to <file> (sha256sum format), to check against NSRL\n");
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
    forensic_case_summary_t sum;
    forensic_scan_fill_case_summary(rep, NULL, NULL, &sum);

    char path[512];
    booto_error_t e = case_report_generate_json(&sum, dir, path, sizeof(path));
    if (e == BOOTO_OK) printf("JSON report:     %s\n", path);
    else fprintf(stderr, "Failed to write JSON report to %s (error %d)\n", dir, e);
    e = case_report_generate_markdown(&sum, dir, path, sizeof(path));
    if (e == BOOTO_OK) printf("Markdown report: %s\n", path);
    else fprintf(stderr, "Failed to write Markdown report to %s (error %d)\n", dir, e);
}

/* Host-machine checks like firmware_audit, so they are reported but never change the verdict. */
static void run_expert_firmware(const char *dir) {
    printf("\nExpert firmware (this machine, not part of the verdict)\n");
    fw_hv_report_t hv;
    firmware_hv_probe(NULL, &hv);
    switch (firmware_hv_classify(&hv)) {
    case FW_HV_ANNOUNCED:
        printf("Hypervisor: running inside a VM (%s); expected in VirtualBox, QEMU or VMware\n",
               hv.vendor[0] ? hv.vendor : hv.sys_type[0] ? hv.sys_type : "CPUID hypervisor bit");
        break;
    case FW_HV_HIDDEN:
        printf("Hypervisor: SUSPICIOUS (medium): none announced, but CPUID takes %u ticks (bare metal stays under %u); "
               "a firmware implant may be running Booto inside a hidden hypervisor. Re-run to confirm\n",
               hv.cpuid_ticks, FW_HV_SLOW_TICKS);
        break;
    case FW_HV_NONE:
        if (hv.cpuid_ticks) printf("Hypervisor: none seen (CPUID %u ticks)\n", hv.cpuid_ticks);
        else printf("Hypervisor: not checked on this CPU type\n");
        break;
    }
    fw_nvram_report_t *nv = calloc(1, sizeof(*nv));
    if (!nv) {
        LOG_ERROR("Out of memory allocating NVRAM report");
        return;
    }
    if (firmware_nvram_scan(NULL, nv) != BOOTO_OK) {
        printf("NVRAM: no UEFI variables to scan (BIOS boot, or efivarfs not mounted)\n");
    } else {
        printf("NVRAM: %d variable(s) read, %d unreadable, %d suspicious\n", nv->vars_scanned, nv->unreadable, nv->count);
        for (int i = 0; i < nv->count; i++)
            printf("  %s (%zu bytes): %s\n", nv->findings[i].name, nv->findings[i].size, nv->findings[i].reason);
    }
    free(nv);

    char image[600], hex[65];
    snprintf(image, sizeof(image), "%s/spi_flash.bin", dir[0] ? dir : "/tmp");
    bool bios_only = false;
    booto_error_t e = firmware_spi_dump(image, hex, &bios_only);
    if (e == BOOTO_OK)
        printf("SPI flash: saved %s%s\n  SHA-256 %s\n  Compare it with the vendor's firmware image for this model.\n", image,
               bios_only ? " (BIOS region only: the chipset locks the rest)" : "", hex);
    if (e == BOOTO_OK) {
        fw_spi_report_t spi;
        if (firmware_spi_analyze(image, &spi) == BOOTO_OK) {
            printf("  %d firmware volume(s), %d/%d LZMA section(s) inflated, %d PE image(s)\n", spi.volumes,
                   spi.lzma_inflated, spi.lzma_sections, spi.pe_images);
            if (spi.windows_pe)
                printf("  SUSPICIOUS (medium): %d Windows executable(s) inside the firmware; implants drop OS payloads "
                       "this way (some vendor tools do too)\n", spi.windows_pe);
            for (int i = 0; i < spi.yara_count; i++)
                printf("  %s (%s): %s\n", spi.yara[i].rule, booto_severity_str(spi.yara[i].severity),
                       spi.yara[i].description);
        }
    }
    else if (e == BOOTO_ERR_NOT_FOUND)
        printf("SPI flash: flashrom is not installed\n");
    else
        printf("SPI flash: flashrom could not read the chip (needs root and iomem=relaxed; some chipsets block reads)\n");
}

static int run_cli(booto_context_t *ctx) {
    LOG_INFO("Booto CLI Mode initialized (Version: %s)", BOOTO_VERSION_STRING);
    if (!resolve_target(ctx)) {
        LOG_ERROR("No scan target: pass -t <dev> or -s <dir> (auto-discovery found no target partition)");
        return EXIT_INCOMPLETE;
    }
    char qdir[600] = "";
    if (ctx->quarantine) {
        if (!ctx->persistence_dir[0]) {
            LOG_ERROR("-q needs -p <dir>: the quarantine archive is written under <dir>/quarantine");
            return EXIT_INCOMPLETE;
        }
        snprintf(qdir, sizeof(qdir), "%s/quarantine", ctx->persistence_dir);
        if (disk_ensure_private_dir(qdir) != BOOTO_OK) {
            LOG_ERROR("Unsafe or unusable quarantine directory %s", qdir);
            return EXIT_INCOMPLETE;
        }
    }
    bool want_hashes = ctx->baseline_out[0] || ctx->baseline_in[0];
    baseline_t *old = ctx->baseline_in[0] ? calloc(1, sizeof(*old)) : NULL;
    baseline_t *cur = want_hashes ? calloc(1, sizeof(*cur)) : NULL;
    forensic_scan_report_t *rep = calloc(1, sizeof(*rep));
    if (!rep || (want_hashes && !cur) || (ctx->baseline_in[0] && !old)) {
        LOG_ERROR("Out of memory allocating scan report");
        free(rep), free(cur), free(old);
        return EXIT_INCOMPLETE;
    }
    if (old) {
        booto_error_t le = baseline_load(ctx->baseline_in, old);
        if (le != BOOTO_OK) {
            LOG_ERROR("Cannot read baseline %s: %s", ctx->baseline_in,
                      le == BOOTO_ERR_CORRUPT_DATA ? "not a Booto baseline file" : "unreadable");
            free(rep), free(cur), free(old);
            return EXIT_INCOMPLETE;
        }
    }
    forensic_scan_set_baseline(cur);
    forensic_scan_set_bodyfile(ctx->bodyfile_out[0] ? ctx->bodyfile_out : NULL);
    forensic_scan_set_hashlist(ctx->hashlist_out[0] ? ctx->hashlist_out : NULL);
    booto_error_t e = forensic_scan_run(ctx->target_dev[0] ? ctx->target_dev : NULL,
                                        ctx->target_rootfs[0] ? ctx->target_rootfs : NULL,
                                        NULL, qdir[0] ? qdir : NULL, scan_progress, NULL, rep);
    forensic_scan_set_baseline(NULL);
    forensic_scan_set_bodyfile(NULL);
    forensic_scan_set_hashlist(NULL);
    if (e != BOOTO_OK) {
        LOG_ERROR("Scan could not run (error %d)", e);
        free(rep), free(cur), free(old);
        return EXIT_INCOMPLETE;
    }

    printf("\nTarget: %s  Root: %s\n\n", rep->target_dev[0] ? rep->target_dev : "(none)", rep->scan_root);
    printf("%-12s | %-8s | %-7s | %s\n", "Module", "Status", "Threats", "Note");
    printf("-------------+----------+---------+------------------------------\n");
    for (int i = 0; i < SCAN_MOD_COUNT; i++) {
        printf("%-12s | %-8s | %7d | %s\n", forensic_scan_module_name((scan_module_id_t)i),
               forensic_scan_status_str(rep->status[i]), forensic_scan_module_threats(rep, (scan_module_id_t)i),
               rep->note[i]);
    }
    printf("\nVerdict: %s\n", forensic_scan_verdict_str(rep->verdict));
    if (rep->firmware_ran) {
        printf("\nHost firmware (this machine, not part of the verdict)\n");
        printf("%-30s | %-7s | %s\n", "Check", "Result", "Detail");
        for (int i = 0; i < FW_CHECK_COUNT; i++) {
            printf("%-30s | %-7s | %s\n", firmware_check_name((fw_check_id_t)i),
                   firmware_result_str(rep->firmware.checks[i].result), rep->firmware.checks[i].detail);
        }
        if (rep->firmware.chipset_unconfirmed) printf("\n%s", FW_CHIPSET_HELP);
    }

    if (rep->measured_note[0]) printf("\nMeasured boot (not part of the verdict): %s\n", rep->measured_note);

    if (rep->quarantine_zip[0])
        printf("\nQuarantine: %d file(s) in %s\n  Password \"infected\". Unpack only on an isolated analysis machine.\n",
               rep->quarantined, rep->quarantine_zip);
    else if (rep->quarantined < 0)
        printf("\nQuarantine: the archive could not be finished; see the log\n");

    if (cur && cur->truncated) printf("\nBaseline: more than %d boot files; the rest were not hashed\n", BASELINE_MAX);
    if (ctx->baseline_out[0]) {
        if (baseline_write(cur, ctx->baseline_out) == BOOTO_OK)
            printf("\nBaseline: %d boot file hash(es) written to %s\n", cur->count, ctx->baseline_out);
        else
            fprintf(stderr, "Failed to write baseline %s\n", ctx->baseline_out);
    }
    if (ctx->bodyfile_out[0]) {
        if (rep->bodyfile_written)
            printf("\nBodyfile: %s timeline written to %s (mactime -b %s)\n", rep->scan_root, ctx->bodyfile_out,
                   ctx->bodyfile_out);
        else
            fprintf(stderr, "Failed to write bodyfile %s\n", ctx->bodyfile_out);
    }
    if (ctx->hashlist_out[0]) {
        if (rep->hashlist_written)
            printf("\nHash list: SHA-256 of %s executables written to %s\n", rep->scan_root, ctx->hashlist_out);
        else
            fprintf(stderr, "Failed to write hash list %s\n", ctx->hashlist_out);
    }
    if (old) {
        printf("\nBoot chain since baseline %s\n", ctx->baseline_in);
        int n = baseline_compare(old, cur, stdout);
        if (n == 0) printf("  no change (%d file(s) compared)\n", cur->count);
        else printf("  %d change(s): expected after an OS or boot loader update, suspicious otherwise\n", n);
    }
    free(cur), free(old);

    if (ctx->expert_firmware) run_expert_firmware(ctx->persistence_dir);
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
    printf("  ESP           : %s/boot/efi, else auto-discover on the target's disk (mounted read-only at /tmp/booto_esp_target)\n",
           ctx->target_rootfs[0] ? ctx->target_rootfs : "/tmp/booto_scan_target");
    printf("  Modules       :");
    for (int i = 0; i < SCAN_MOD_COUNT; i++) printf(" %s%s", forensic_scan_module_name((scan_module_id_t)i), i + 1 < SCAN_MOD_COUNT ? "," : "\n");
    printf("  Firmware      : Secure Boot keys, dbx and DMA protection of this machine (device mode only)\n");
    printf("  Expert fw     : %s\n", ctx->expert_firmware ? "NVRAM scan and read-only SPI flash dump (CLI, root)" : "off");
    printf("  Quarantine    : %s\n", ctx->quarantine ? "flagged files to <report dir>/quarantine, encrypted ZIP" : "off");
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
        {"expert-firmware", no_argument,       0, 'x'},
        {"quarantine",      no_argument,       0, 'q'},
        {"baseline",        required_argument, 0, 'B'},
        {"compare",         required_argument, 0, 'C'},
        {"bodyfile",        required_argument, 0, 'F'},
        {"hashlist",        required_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "hvcdmt:s:p:uVxq", long_options, &option_index)) != -1) {
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
                /* The generator and its sources live in the source tree, not on the live USB. */
                if (access("./scripts/update_rules.sh", X_OK) != 0) {
                    fprintf(stderr, "booto: --update-rules needs the Booto source tree: run it from the repository root.\n"
                                    "On the live USB, copy new rule files and their .sig signatures to /persistence/rules instead.\n");
                    logger_shutdown();
                    return 1;
                }
                int res = system("./scripts/update_rules.sh");
                logger_shutdown();
                if (res == -1 || !WIFEXITED(res)) return 1;
                return WEXITSTATUS(res);
            case 'c':
                if (ctx.mode != BOOTO_MODE_DRY_RUN) ctx.mode = BOOTO_MODE_CLI;   /* dry-run must never be upgraded */
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
            case 'x':
                ctx.expert_firmware = true;
                break;
            case 'q':
                ctx.quarantine = true;
                break;
            case 'B':
                snprintf(ctx.baseline_out, sizeof(ctx.baseline_out), "%s", optarg);
                break;
            case 'C':
                snprintf(ctx.baseline_in, sizeof(ctx.baseline_in), "%s", optarg);
                break;
            case 'F':
                snprintf(ctx.bodyfile_out, sizeof(ctx.bodyfile_out), "%s", optarg);
                break;
            case 'H':
                snprintf(ctx.hashlist_out, sizeof(ctx.hashlist_out), "%s", optarg);
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    logger_init(ctx.verbose ? LOG_LEVEL_DEBUG : LOG_LEVEL_INFO, NULL);
    // On the report partition when it is mounted (also after a later F4 unlock), else in RAM.
    logger_install_crash_handler(BOOTO_VERSION_STRING " (" BOOTO_GIT_HASH ")",
                                 DEFAULT_PERSISTENCE_MOUNT "/logs/booto-crash.txt", "/tmp/booto-crash.txt");
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
