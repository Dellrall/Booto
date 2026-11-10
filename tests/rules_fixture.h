/**
 * @file rules_fixture.h
 * @brief Tests: sign rule files with a throwaway Ed25519 key that the loader is told to trust.
 */
#ifndef BOOTO_TEST_RULES_FIXTURE_H
#define BOOTO_TEST_RULES_FIXTURE_H

#include "rules_loader.h"

#include <openssl/evp.h>
#include <stdio.h>

static EVP_PKEY *g_fixture_key;
static int g_fixture_key_trusted;

/* Trust a fresh key until rules_fixture_done. */
static void rules_fixture_init(void) {
    if (g_fixture_key_trusted) return;
    g_fixture_key_trusted = 1;
    if (!g_fixture_key) g_fixture_key = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    uint8_t pub[32];
    size_t n = sizeof(pub);
    if (g_fixture_key && EVP_PKEY_get_raw_public_key(g_fixture_key, pub, &n) == 1) rules_set_signing_key(pub);
}

/* Back to the release key, so later tests load the committed rules/. */
static void rules_fixture_done(void) { rules_set_signing_key(NULL); g_fixture_key_trusted = 0; }

/* Write "<path>.sig" over data, as scripts/update_rules.sh does with the release key. */
static void rules_fixture_sign(const char *path, const void *data, size_t len) {
    rules_fixture_init();
    unsigned char sig[64];
    size_t sig_len = sizeof(sig);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, g_fixture_key) == 1 &&
             EVP_DigestSign(ctx, sig, &sig_len, data, len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) return;
    char sig_path[600];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", path);
    FILE *f = fopen(sig_path, "wb");
    if (!f) return;
    fwrite(sig, 1, sig_len, f);
    fclose(f);
}

#endif /* BOOTO_TEST_RULES_FIXTURE_H */
