/**
 * @file test_persistence_mgr.c
 * @brief Unit tests for Tails-style LUKS persistence manager.
 */
#include "test_framework.h"
#include "persistence_mgr.h"

#include <string.h>

static void test_persistence_lifecycle(void) {
    TEST_START("test_persistence_lifecycle");

    persistence_mgr_t mgr;
    booto_error_t err = persistence_init(&mgr, "/dev/sdb2");
    ASSERT_INT_EQ(err, BOOTO_OK, "Persistence init must return BOOTO_OK");
    ASSERT_INT_EQ(mgr.state, PERSISTENCE_STATE_LOCKED, "Initial state must be LOCKED (Amnesic)");

    // Unlock mock container
    booto_error_t u_err = persistence_unlock(&mgr, "test_passphrase");
    ASSERT_INT_EQ(u_err, BOOTO_OK, "Unlock must succeed");
    ASSERT_TRUE(persistence_is_unlocked(&mgr), "Persistence must be in UNLOCKED state");

    // Lock container
    booto_error_t l_err = persistence_lock(&mgr);
    ASSERT_INT_EQ(l_err, BOOTO_OK, "Lock must succeed");
    ASSERT_INT_EQ(mgr.state, PERSISTENCE_STATE_LOCKED, "Restored to LOCKED state");

    TEST_PASS("test_persistence_lifecycle");
}

int main(void) {
    printf("\n--- Running LUKS Persistence Manager Tests ---\n");
    test_persistence_lifecycle();
    TEST_SUMMARY();
    return 0;
}
