/**
 * @file test_persistence_mgr.c
 * @brief Unit tests for Tails-style LUKS persistence manager.
 */
#include "test_framework.h"
#include "persistence_mgr.h"

#include <string.h>
#include <unistd.h>

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
    TEST_SUMMARY();
    return 0;
}
