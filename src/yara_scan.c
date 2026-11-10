/**
 * @file yara_scan.c
 * @brief Signed YARA rules, compiled once with libyara and matched against in-memory file images.
 */
#include "yara_scan.h"
#include "logger.h"
#include "rules_loader.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#define YARA_SCAN_TIMEOUT_S 10

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_loaded;
static booto_error_t g_err;
static YR_RULES *g_rules; /* NULL with g_err OK: no rules file */

static const char *meta_string(const YR_RULE *rule, const char *name) {
    const YR_META *meta;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type == META_TYPE_STRING && strcmp(meta->identifier, name) == 0) return meta->string;
    }
    return NULL;
}

static void compile_error(int level, const char *file, int line, const YR_RULE *rule, const char *msg, void *user) {
    (void)file;
    (void)rule;
    LOG_ERROR("%s:%d: YARA %s: %s", (const char *)user, line, level == YARA_ERROR_LEVEL_ERROR ? "error" : "warning",
              msg);
}

static booto_error_t load(void) {
    char *src = NULL;
    size_t len = 0;
    char path[512];
    booto_error_t err = rules_read_signed(YARA_RULES_FILE, &src, &len, path, sizeof(path));
    if (err == BOOTO_ERR_NOT_FOUND) return BOOTO_OK;
    if (err != BOOTO_OK) return err;

    YR_COMPILER *c = NULL;
    err = BOOTO_ERR_CORRUPT_DATA;
    if (yr_initialize() != ERROR_SUCCESS || yr_compiler_create(&c) != ERROR_SUCCESS) {
        err = BOOTO_ERR_OUT_OF_MEMORY;
    } else {
        yr_compiler_set_callback(c, compile_error, path);
        if (yr_compiler_add_string(c, src, NULL) == 0 && yr_compiler_get_rules(c, &g_rules) == ERROR_SUCCESS) {
            err = BOOTO_OK;
        }
        yr_compiler_destroy(c);
    }
    free(src);

    int n = 0;
    const YR_RULE *rule;
    if (err == BOOTO_OK) yr_rules_foreach(g_rules, rule) {
        const char *sev = meta_string(rule, "severity");
        if (!sev || rules_severity_level(sev) < 0 || !meta_string(rule, "description")) {
            LOG_ERROR("YARA rule '%s' in %s needs string metas severity (INFO..CRITICAL) and description",
                      rule->identifier, path);
            err = BOOTO_ERR_CORRUPT_DATA;
        }
        n++;
    }
    if (err != BOOTO_OK) {
        if (g_rules) yr_rules_destroy(g_rules);
        g_rules = NULL;
        LOG_ERROR("Refusing YARA rules '%s'", path);
        return err;
    }
    LOG_INFO("Loaded %d signed YARA rules from %s", n, path);
    return BOOTO_OK;
}

typedef struct {
    yara_match_t *out;
    int max;
    int count;
} scan_ctx_t;

static int on_match(YR_SCAN_CONTEXT *context, int message, void *data, void *user) {
    (void)context;
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    scan_ctx_t *ctx = user;
    if (ctx->count >= ctx->max) return CALLBACK_ABORT;
    const YR_RULE *rule = data;
    yara_match_t *m = &ctx->out[ctx->count++];
    snprintf(m->rule, sizeof(m->rule), "%s", rule->identifier);
    snprintf(m->description, sizeof(m->description), "%s", meta_string(rule, "description")); // validated at load
    m->severity = (booto_severity_t)rules_severity_level(meta_string(rule, "severity"));
    return CALLBACK_CONTINUE;
}

static booto_error_t get_rules(YR_RULES **rules) {
    pthread_mutex_lock(&g_lock);
    if (!g_loaded) {
        g_err = load();
        g_loaded = true;
    }
    booto_error_t err = g_err;
    *rules = g_rules;
    pthread_mutex_unlock(&g_lock);
    return err;
}

booto_error_t yara_rules_status(void) {
    YR_RULES *rules;
    return get_rules(&rules);
}

booto_error_t yara_scan_buffer(const uint8_t *buf, size_t len, yara_match_t *out, int max, int *count) {
    if (!buf || !out || max <= 0 || !count) return BOOTO_ERR_INVALID_ARG;
    *count = 0;
    YR_RULES *rules;
    booto_error_t err = get_rules(&rules);
    if (err != BOOTO_OK || !rules) return err;

    scan_ctx_t ctx = { out, max, 0 };
    int rc = yr_rules_scan_mem(rules, buf, len, SCAN_FLAGS_FAST_MODE, on_match, &ctx, YARA_SCAN_TIMEOUT_S);
    *count = ctx.count;
    if (rc != ERROR_SUCCESS && rc != ERROR_CALLBACK_ERROR) {
        LOG_WARN("YARA scan stopped early (libyara error %d)", rc);
        return BOOTO_ERR_GENERIC;
    }
    return BOOTO_OK;
}

void yara_scan_reset(void) {
    pthread_mutex_lock(&g_lock);
    if (g_rules) yr_rules_destroy(g_rules);
    g_rules = NULL;
    g_loaded = false;
    pthread_mutex_unlock(&g_lock);
}
