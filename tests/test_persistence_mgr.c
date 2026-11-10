/**
 * @file test_persistence_mgr.c
 * @brief Unit tests for Tails-style LUKS persistence manager.
 */
#include "test_framework.h"
#include "persistence_mgr.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void put_file(const char *dir, const char *name, const char *text) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(text, f); fclose(f); }
}

/* The partition must come from the disk live-boot booted from, never a same-named one on a suspect disk. */
static void test_find_data_partition_on_boot_disk_only(void) {
    TEST_START("test_find_data_partition_on_boot_disk_only");
    char root[] = "/tmp/booto_persist_XXXXXX";
    ASSERT_TRUE(mkdtemp(root) != NULL, "mkdtemp");
    char cmd[2048], sys[64], dev[128], sdb[128], nvme[128];
    snprintf(sys, sizeof(sys), "%.32s/sys", root);
    snprintf(sdb, sizeof(sdb), "%.40s/devices/pci0/block/sdb", sys);
    snprintf(nvme, sizeof(nvme), "%.40s/devices/pci1/block/nvme0n1", sys);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/sdb1 %s/sdb2 %s/nvme0n1p3 %s/dev/block && "
             "ln -s ../../devices/pci0/block/sdb/sdb1 %s/dev/block/8:17 && touch %s/sdb1/partition %s/sdb2/partition",
             sdb, sdb, nvme, sys, sys, sdb, sdb);
    ASSERT_TRUE(system(cmd) == 0, "fixture tree");
    put_file(sdb, "sdb1/uevent", "MAJOR=8\nMINOR=17\nDEVNAME=sdb1\nPARTNAME=BOOTO_LIVE\n");
    put_file(sdb, "sdb2/uevent", "MAJOR=8\nMINOR=18\nDEVNAME=sdb2\nPARTNAME=BOOTO_DATA\n");
    put_file(nvme, "nvme0n1p3/uevent", "DEVNAME=nvme0n1p3\nPARTNAME=BOOTO_DATA\n");
    put_file(root, "live", "22 1 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n"
                           "31 22 8:17 / /run/live/medium ro,noatime - vfat /dev/sdb1 ro\n");
    put_file(root, "nolive", "22 1 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n");
    char live[300], nolive[300];
    snprintf(live, sizeof(live), "%s/live", root);
    snprintf(nolive, sizeof(nolive), "%s/nolive", root);

    booto_error_t found = persistence_find_data_partition(live, sys, dev, sizeof(dev));
    char disk[PATH_MAX] = "", dev_nl[128];
    booto_error_t boot_disk = persistence_find_boot_disk(live, sys, disk, sizeof(disk));
    size_t dl = strlen(disk);
    booto_error_t not_live = persistence_find_data_partition(nolive, sys, dev_nl, sizeof(dev_nl));
    put_file(sdb, "sdb2/uevent", "DEVNAME=sdb2\nPARTNAME=OTHER\n");
    char dev2[128] = "";
    booto_error_t decoy_only = persistence_find_data_partition(live, sys, dev2, sizeof(dev2));
    snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
    if (system(cmd) != 0) perror("rm");

    ASSERT_INT_EQ(found, BOOTO_OK, "BOOTO_DATA found on the boot disk");
    ASSERT_INT_EQ(boot_disk, BOOTO_OK, "boot disk found from the live medium mount");
    ASSERT_TRUE(dl > 10 && strcmp(disk + dl - 10, "/block/sdb") == 0, "boot disk is the medium's whole disk, not its partition");
    ASSERT_STR_EQ(dev, "/dev/sdb2", "partition is the boot disk's, not the suspect disk's");
    ASSERT_INT_EQ(not_live, BOOTO_ERR_NOT_FOUND, "no live medium mounted -> not found");
    ASSERT_INT_EQ(decoy_only, BOOTO_ERR_NOT_FOUND, "same-named partition on another disk is ignored");
    TEST_PASS("test_find_data_partition_on_boot_disk_only");
}

static void test_persistence_init_rejects_non_dev(void) {
    TEST_START("test_persistence_init_rejects_non_dev");
    persistence_mgr_t mgr;
    ASSERT_INT_EQ(persistence_init(&mgr, "sdb2"), BOOTO_ERR_INVALID_ARG, "Relative device rejected");
    ASSERT_INT_EQ(persistence_init(&mgr, "../x"), BOOTO_ERR_INVALID_ARG, "Traversal path rejected");
    TEST_PASS("test_persistence_init_rejects_non_dev");
}

static void test_persistence_nonroot(void) {
    TEST_START("test_persistence_nonroot");
    persistence_mgr_t mgr;
    ASSERT_INT_EQ(persistence_init(&mgr, "/dev/sdb2"), BOOTO_OK, "Init on /dev path succeeds");
    ASSERT_TRUE(!persistence_is_unlocked(&mgr), "Initial state must not be UNLOCKED");

    if (geteuid() == 0) {
        printf("  (skipping non-root unlock/lock checks: running as root)\n");
        TEST_PASS("test_persistence_nonroot");
        return;
    }

    persistence_state_t before = mgr.state;
    ASSERT_INT_EQ(persistence_unlock(&mgr, "test_passphrase"), BOOTO_ERR_PERMISSION_DENIED,
                  "Non-root unlock must be denied");
    ASSERT_INT_EQ(mgr.state, before, "State unchanged after denied unlock");
    ASSERT_INT_EQ(persistence_lock(&mgr), BOOTO_OK, "Lock when not unlocked is a no-op");
    TEST_PASS("test_persistence_nonroot");
}

int main(void) {
    printf("\n--- Running LUKS Persistence Manager Tests ---\n");
    test_persistence_init_rejects_non_dev();
    test_persistence_nonroot();
    test_find_data_partition_on_boot_disk_only();
    TEST_SUMMARY();
    return 0;
}
