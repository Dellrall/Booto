/**
 * @file test_windows_boot.c
 * @brief Windows boot engine: root detection by any case, core files need a Microsoft signature.
 */
#include "test_framework.h"
#include "forensic_scan.h"
#include "windows_boot.h"
#include "hive_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[] = "/tmp/test_booto_win_XXXXXX";

/* Minimal PE32+; with_cert adds a garbage certificate table, so its signature does not verify. */
static size_t build_pe(uint8_t *b, size_t cap, bool with_cert) {
    memset(b, 0, cap);
    b[0] = 'M'; b[1] = 'Z'; b[0x3C] = 0x80;
    b[0x80] = 'P'; b[0x81] = 'E';
    size_t coff = 0x84, opt = coff + 20;
    b[coff] = 0x64; b[coff + 1] = 0x86;
    b[coff + 2] = 1;
    b[coff + 16] = 0xF0;
    b[opt] = 0x0b; b[opt + 1] = 0x02;
    b[opt + 61] = 0x02;                            // SizeOfHeaders = 0x200
    b[opt + 68] = 1;                               // IMAGE_SUBSYSTEM_NATIVE
    b[opt + 108] = 16;
    size_t sect = opt + 0xF0;
    b[sect + 17] = 0x01;
    b[sect + 21] = 0x02;
    for (size_t i = 0x200; i < 0x300; i++) b[i] = (uint8_t)i;
    if (!with_cert) return 0x300;
    size_t dir = opt + 112 + 32;
    b[dir + 1] = 0x03;
    b[dir + 4] = 0x80;
    memset(b + 0x300, 0xC5, 0x80);
    return 0x380;
}

static void put(const char *rel, const uint8_t *data, size_t len) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    FILE *fp = fopen(p, "wb");
    if (fp) {
        fwrite(data, 1, len, fp);
        fclose(fp);
    }
}

static void mk(const char *rel) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    mkdir(p, 0700);
}

static bool has_finding(const winboot_scan_result_t *r, const char *file, const char *reason) {
    for (int i = 0; i < r->threats_detected; i++)
        if (strstr(r->findings[i].file_path, file) && strstr(r->findings[i].reason, reason)) return true;
    return false;
}

static bool has_rule(const winboot_scan_result_t *r, const char *rule, const char *reason) {
    for (int i = 0; i < r->threats_detected; i++)
        if (strcmp(r->findings[i].rule_id, rule) == 0 && strstr(r->findings[i].reason, reason)) return true;
    return false;
}

static void test_windows_root(void) {
    TEST_START("test_windows_root");
    ASSERT_TRUE(!winboot_is_windows_root(g_root), "Empty dir is not Windows");
    mk("WINDOWS");
    mk("WINDOWS/system32");
    mk("WINDOWS/system32/Drivers");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), false);
    put("WINDOWS/system32/NTOSKRNL.EXE", b, len);
    ASSERT_TRUE(winboot_is_windows_root(g_root), "Names match in any case");
    TEST_PASS("test_windows_root");
}

static void test_scan(void) {
    TEST_START("test_scan");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), false);
    put("WINDOWS/system32/Drivers/plain.sys", b, len);
    put("WINDOWS/system32/hal.dll", (const uint8_t *)"not a PE image", 14);
    len = build_pe(b, sizeof(b), true);
    put("WINDOWS/system32/Drivers/broken.SYS", b, len);
    put("WINDOWS/system32/Drivers/notes.txt", b, len);

    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r->files_checked, 4, "ntoskrnl, hal and two drivers checked; .txt ignored");
    ASSERT_TRUE(has_finding(r, "NTOSKRNL.EXE", "no embedded signature"), "Unsigned kernel flagged");
    ASSERT_TRUE(has_finding(r, "hal.dll", "not a valid PE"), "Non-PE core file flagged");
    ASSERT_TRUE(has_finding(r, "broken.SYS", "does not verify"), "Broken driver signature flagged");
    ASSERT_INT_EQ(r->threats_detected, 3, "Unsigned driver is not a finding");
    ASSERT_INT_EQ(r->drivers_unsigned, 1, "Unsigned driver counted");
    ASSERT_INT_EQ(winboot_scan_rootfs("/nonexistent", r), BOOTO_ERR_NOT_FOUND, "No Windows dir");
    free(r);
    TEST_PASS("test_scan");
}

/* Crypto-agile TCG log: Spec ID (SHA-256 only), then one EFI application event whose digest is `fill`. */
static size_t build_log(uint8_t *b, uint8_t fill) {
    memset(b, 0, 256);
    b[4] = 3;                                         // EV_NO_ACTION
    b[28] = 32;                                       // Spec ID event size
    memcpy(b + 32, "Spec ID Event03", 16);
    b[56] = 1;                                        // one algorithm
    b[60] = 0x0B; b[62] = 32;                         // SHA-256, 32 bytes
    size_t off = 64;
    b[off + 0] = 4;                                   // PCR 4
    b[off + 4] = 0x03; b[off + 7] = 0x80;             // EV_EFI_BOOT_SERVICES_APPLICATION
    b[off + 8] = 1;                                   // one digest
    b[off + 12] = 0x0B;
    memset(b + off + 14, fill, 32);
    return off + 14 + 32 + 4;                         // empty event data
}

static void test_measured_boot(void) {
    TEST_START("test_measured_boot");
    bool found = true;
    char name[64];
    ASSERT_INT_EQ(winboot_measured_has(g_root, "ab", &found, name, sizeof(name)), BOOTO_ERR_NOT_FOUND, "No log dir");
    mk("WINDOWS/Logs");
    mk("WINDOWS/Logs/MeasuredBoot");
    uint8_t b[256];
    size_t len = build_log(b, 0x11);
    put("WINDOWS/Logs/MeasuredBoot/0000000001-0000000000.log", b, len);
    len = build_log(b, 0xAB);
    put("WINDOWS/Logs/MeasuredBoot/0000000002-0000000000.log", b, len);

    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "ab");
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_OK, "Newest log parses");
    ASSERT_TRUE(found, "Hash measured by the last boot is found");
    ASSERT_STR_EQ(name, "0000000002-0000000000.log", "Newest log is used");
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "11");
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_OK, "Newest log parses");
    ASSERT_TRUE(!found, "Hash from an older boot only is not found");

    put("WINDOWS/Logs/MeasuredBoot/0000000003-0000000000.log", b, 40);
    ASSERT_INT_EQ(winboot_measured_has(g_root, hex, &found, name, sizeof(name)), BOOTO_ERR_CORRUPT_DATA,
                  "Truncated log is malformed");
    TEST_PASS("test_measured_boot");
}

static void test_orchestrator(void) {
    TEST_START("test_orchestrator");
    forensic_scan_report_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(forensic_scan_run(NULL, g_root, NULL, NULL, NULL, NULL, r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r->status[SCAN_MOD_WINBOOT], SCAN_STATUS_OK, "Windows engine ran");
    ASSERT_INT_EQ(r->status[SCAN_MOD_KERNEL], SCAN_STATUS_NA, "Linux kernel engine skipped");
    ASSERT_INT_EQ(r->status[SCAN_MOD_PKG], SCAN_STATUS_NA, "Package engine skipped");
    ASSERT_INT_EQ(r->verdict, SCAN_VERDICT_THREATS, "Findings give THREATS");
    ASSERT_INT_EQ(forensic_scan_module_threats(r, SCAN_MOD_WINBOOT), 3, "Threats counted");
    free(r);
    TEST_PASS("test_orchestrator");
}

static uint8_t g_hive[0x3000];

static void test_boot_start(void) {
    TEST_START("test_boot_start");
    mk("WINDOWS/system32/config");
    mk("WINDOWS/system32/Evil");
    uint8_t b[0x400];
    size_t len = build_pe(b, sizeof(b), true);
    put("WINDOWS/system32/Evil/hidden.sys", b, len);
    put("outside.sys", b, len);
    hv_t h;
    hv_init(&h, g_hive, sizeof(g_hive));
    uint32_t v1[] = { hv_dword(&h, "Start", 0), hv_string(&h, "ImagePath", "\\SystemRoot\\System32\\evil\\HIDDEN.sys") };
    uint32_t v2[] = { hv_dword(&h, "Start", 0), hv_string(&h, "ImagePath", "System32\\..\\..\\outside.sys") };
    uint32_t v3[] = { hv_dword(&h, "Start", 3), hv_string(&h, "ImagePath", "System32\\Evil\\hidden.sys") };
    uint32_t v4[] = { hv_dword(&h, "Start", 0) };
    uint32_t v5[] = { hv_dword(&h, "Start", 2), hv_string(&h, "ImagePath", "cmd.exe /c C:\\Users\\Public\\x.bat") };
    uint32_t svc[] = { hv_key(&h, "evil", NULL, 0, v1, 2), hv_key(&h, "escape", NULL, 0, v2, 2),
                       hv_key(&h, "demand", NULL, 0, v3, 2), hv_key(&h, "broken", NULL, 0, v4, 1),
                       hv_key(&h, "updater", NULL, 0, v5, 2) };
    uint32_t svcs = hv_key(&h, "Services", svc, 5, NULL, 0);
    uint32_t cur = hv_dword(&h, "Current", 1);
    uint32_t top[] = { hv_key(&h, "Select", NULL, 0, &cur, 1), hv_key(&h, "ControlSet001", &svcs, 1, NULL, 0) };
    put("WINDOWS/system32/config/SYSTEM", g_hive, hv_root(&h, hv_key(&h, "ROOT", top, 2, NULL, 0)));

    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
    ASSERT_INT_EQ(r->boot_start, 3, "Three boot-start services");
    ASSERT_TRUE(has_finding(r, "Evil/hidden.sys", "does not verify"), "Boot-start driver outside drivers checked");
    ASSERT_TRUE(!has_finding(r, "outside.sys", ""), "ImagePath with .. is not followed");
    ASSERT_INT_EQ(r->files_checked, 5, "Drivers dir file not checked twice");
    ASSERT_TRUE(has_rule(r, "WIN_SERVICE_COMMAND", "updater"), "Auto-start service running cmd /c flagged");
    ASSERT_TRUE(!has_rule(r, "WIN_SERVICE_COMMAND", "demand"), "Demand-start driver not flagged");
    free(r);
    TEST_PASS("test_boot_start");
}

static void test_bcd(void) {
    TEST_START("test_bcd");
    mk("esp");
    mk("esp/EFI");
    mk("esp/EFI/Microsoft");
    mk("esp/EFI/Microsoft/Boot");
    char esp[512];
    snprintf(esp, sizeof(esp), "%s/esp", g_root);
    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    ASSERT_INT_EQ(winboot_check_bcd(esp, r), BOOTO_ERR_NOT_FOUND, "No BCD store");

    for (int bad = 0; bad < 2; bad++) {
        hv_t h;
        hv_init(&h, g_hive, sizeof(g_hive));
        uint8_t on = (uint8_t)bad;
        uint32_t ts = hv_value(&h, "Element", 3, &on, 1);
        uint32_t ap = hv_string(&h, "Element", bad ? "\\Windows\\system32\\evil.efi" : "\\WINDOWS\\system32\\winload.efi");
        uint32_t els[] = { hv_key(&h, "16000049", NULL, 0, &ts, 1), hv_key(&h, "12000002", NULL, 0, &ap, 1) };
        uint32_t ty = hv_dword(&h, "Type", 0x10200003u);
        uint32_t parts[] = { hv_key(&h, "Description", NULL, 0, &ty, 1), hv_key(&h, "Elements", els, 2, NULL, 0) };
        uint32_t obj = hv_key(&h, "{a}", parts, 2, NULL, 0);
        uint32_t objs = hv_key(&h, "Objects", &obj, 1, NULL, 0);
        put("esp/EFI/Microsoft/Boot/BCD", g_hive, hv_root(&h, hv_key(&h, "NewStoreRoot", &objs, 1, NULL, 0)));
        memset(r, 0, sizeof(*r));
        ASSERT_INT_EQ(winboot_check_bcd(esp, r), BOOTO_OK, "BCD read");
        ASSERT_INT_EQ(r->threats_detected, bad ? 2 : 0, "Findings only when tampered");
    }
    ASSERT_TRUE(has_finding(r, "BCD", "testsigning"), "testsigning flagged");
    ASSERT_TRUE(has_finding(r, "BCD", "evil.efi"), "Changed loader path flagged");
    put("esp/EFI/Microsoft/Boot/BCD", (const uint8_t *)"junk", 4);
    memset(r, 0, sizeof(*r));
    ASSERT_INT_EQ(winboot_check_bcd(esp, r), BOOTO_OK, "Junk BCD read");
    ASSERT_TRUE(has_finding(r, "BCD", "not a valid"), "Junk BCD flagged");
    free(r);
    TEST_PASS("test_bcd");
}

/* SOFTWARE hive: Winlogon, one IFEO debugger, AppInit_DLLs and a Run value, tampered or as Windows ships them. */
static size_t software_hive(bool bad) {
    hv_t h;
    hv_init(&h, g_hive, sizeof(g_hive));
    uint32_t wl[] = { hv_string(&h, "Shell", bad ? "explorer.exe, C:\\ProgramData\\svc.exe" : "explorer.exe"),
                      hv_string(&h, "Userinit", bad ? "C:\\Windows\\system32\\userinit.exe,evil.exe"
                                                    : "C:\\Windows\\system32\\userinit.exe,") };
    uint32_t dbg = hv_string(&h, "Debugger", "C:\\Windows\\System32\\cmd.exe");
    uint32_t ifeo_sub = hv_key(&h, bad ? "sethc.exe" : "notepad.exe", NULL, 0, bad ? &dbg : NULL, bad ? 1 : 0);
    uint32_t ai[] = { hv_dword(&h, "LoadAppInit_DLLs", bad ? 1 : 0), hv_string(&h, "AppInit_DLLs", "C:\\x\\hook.dll") };
    uint32_t cv[] = { hv_key(&h, "Winlogon", NULL, 0, wl, 2), hv_key(&h, "Image File Execution Options", &ifeo_sub, 1, NULL, 0),
                      hv_key(&h, "Windows", NULL, 0, ai, 2) };
    uint32_t nt_cv = hv_key(&h, "CurrentVersion", cv, 3, NULL, 0);
    uint32_t run_v = hv_string(&h, "Updater", bad ? "powershell -w hidden -enc AAAA" : "\"C:\\Program Files\\Vendor\\tray.exe\"");
    uint32_t run = hv_key(&h, "Run", NULL, 0, &run_v, 1);
    uint32_t w_cv = hv_key(&h, "CurrentVersion", &run, 1, NULL, 0);
    uint32_t ms_sub[] = { hv_key(&h, "Windows NT", &nt_cv, 1, NULL, 0), hv_key(&h, "Windows", &w_cv, 1, NULL, 0) };
    uint32_t ms = hv_key(&h, "Microsoft", ms_sub, 2, NULL, 0);
    return hv_root(&h, hv_key(&h, "ROOT", &ms, 1, NULL, 0));
}

static void test_persistence(void) {
    TEST_START("test_persistence");
    static const char *const rules[] = { "WIN_WINLOGON_SHELL", "WIN_WINLOGON_USERINIT", "WIN_IFEO_ACCESSIBILITY",
                                         "WIN_APPINIT_DLLS", "WIN_RUN_KEY", "WIN_ACCESSIBILITY_SWAP", "WIN_STARTUP_FILE" };
    mk("ProgramData");
    mk("ProgramData/Microsoft");
    mk("ProgramData/Microsoft/Windows");
    mk("ProgramData/Microsoft/Windows/Start Menu");
    mk("ProgramData/Microsoft/Windows/Start Menu/Programs");
    mk("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp");
    put("WINDOWS/system32/cmd.exe", (const uint8_t *)"MZ cmd", 6);
    put("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/Vendor.lnk", (const uint8_t *)"L", 1);
    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    for (int bad = 0; bad < 2; bad++) {
        put("WINDOWS/system32/config/SOFTWARE", g_hive, software_hive(bad));
        put("WINDOWS/system32/sethc.exe", (const uint8_t *)(bad ? "MZ cmd" : "MZ sethc"), bad ? 6 : 8);
        if (bad) put("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/svc.vbs", (const uint8_t *)"x", 1);
        ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
        for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
            ASSERT_TRUE(has_rule(r, rules[i], "") == (bad == 1), rules[i]);
    }
    ASSERT_TRUE(has_rule(r, "WIN_IFEO_ACCESSIBILITY", "sethc.exe"), "IFEO names the hijacked program");
    ASSERT_TRUE(!has_rule(r, "WIN_STARTUP_FILE", "Vendor.lnk"), "Startup shortcut is normal");
    free(r);
    TEST_PASS("test_persistence");
}

static void test_ransomware(void) {
    TEST_START("test_ransomware");
    mk("Users");
    mk("Users/alice");
    mk("Users/alice/Documents");
    char rel[128];
    winboot_scan_result_t *r = calloc(1, sizeof(*r));
    for (int n = 9; n <= 10; n++) {
        snprintf(rel, sizeof(rel), "Users/alice/Documents/report%d.docx.lockbit", n);
        put(rel, (const uint8_t *)"x", 1);
        if (n == 9)
            for (int i = 0; i < 8; i++) {
                snprintf(rel, sizeof(rel), "Users/alice/Documents/report%d.docx.lockbit", i);
                put(rel, (const uint8_t *)"x", 1);
                snprintf(rel, sizeof(rel), "Users/alice/Documents/photo%d.jpg.bak", i);  // a backup tool's copies
                put(rel, (const uint8_t *)"x", 1);
            }
        ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
        ASSERT_TRUE(has_rule(r, "WIN_RANSOM_ENCRYPTED", "lockbit") == (n == 10), "Ten renamed documents, not nine");
    }
    ASSERT_TRUE(!has_rule(r, "WIN_RANSOM_ENCRYPTED", ".bak"), "Backup copies are not ransomware");
    static const char note[] = "Your files are encrypted. Visit http://abc.onion to restore them.";
    mk("Users/alice/Desktop");
    put("Users/alice/Desktop/HOW_TO_DECRYPT.txt", (const uint8_t *)note, sizeof(note));
    put("Users/alice/Desktop/readme.txt", (const uint8_t *)"Install notes", 13);
    ASSERT_INT_EQ(winboot_scan_rootfs(g_root, r), BOOTO_OK, "Scan runs");
    ASSERT_TRUE(has_rule(r, "WIN_RANSOM_NOTE", "HOW_TO_DECRYPT"), "Note naming an .onion site flagged");
    ASSERT_TRUE(!has_rule(r, "WIN_RANSOM_NOTE", "readme"), "Plain readme not flagged");
    free(r);
    TEST_PASS("test_ransomware");
}

int main(void) {
    printf("\n--- Running Windows Boot Engine Tests ---\n");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        return 1;
    }
    test_windows_root();
    test_scan();
    test_orchestrator();
    test_measured_boot();
    test_boot_start();
    test_bcd();
    test_persistence();
    test_ransomware();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) fprintf(stderr, "warning: cleanup of %s failed\n", g_root);
    TEST_SUMMARY();
    return 0;
}
