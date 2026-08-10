/* OpenSSL 3 HMAC adapter for BELT-HASH and the BASH digest family. */

#include "bee2_backend.h"
#include "bee2_oids.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/crypto.h>

#define BELT_HMAC_SIZE 32u
#define BELT_HMAC_BLOCK_SIZE 32u
#define BEE2_HMAC_MAX_BLOCK_SIZE 160u
#define BEE2_HMAC_MAX_DIGEST_SIZE 64u

typedef void (*bee2_hash_init_fn)(bee2_backend_state_t *state);
typedef void (*bee2_hash_update_fn)(bee2_backend_state_t *state,
                                    const unsigned char *input,
                                    size_t input_len);
typedef void (*bee2_hash_final_fn)(bee2_backend_state_t *state, unsigned char *output);
typedef void (*bee2_hash_cleanup_fn)(bee2_backend_state_t *state);

typedef struct {
    const char *name;
    const char *oid;
    size_t digest_size;
    size_t block_size;
    bee2_hash_init_fn init;
    bee2_hash_update_fn update;
    bee2_hash_final_fn final;
    bee2_hash_cleanup_fn cleanup;
} bee2_hmac_digest_t;

static void bash256_init(bee2_backend_state_t *state) {
    bash_hash128_init((bash_hash_ctx_t *)state);
}

static void
bash256_update(bee2_backend_state_t *state, const unsigned char *input, size_t input_len) {
    bash_hash128_update((bash_hash_ctx_t *)state, input, input_len);
}

static void bash256_final(bee2_backend_state_t *state, unsigned char *output) {
    bash_hash128_get((bash_hash_ctx_t *)state, output);
}

static void bash256_cleanup(bee2_backend_state_t *state) {
    bash_hash128_cleanup((bash_hash_ctx_t *)state);
}

static void bash384_init(bee2_backend_state_t *state) {
    bash_hash192_init((bash_hash_ctx_t *)state);
}

static void
bash384_update(bee2_backend_state_t *state, const unsigned char *input, size_t input_len) {
    bash_hash192_update((bash_hash_ctx_t *)state, input, input_len);
}

static void bash384_final(bee2_backend_state_t *state, unsigned char *output) {
    bash_hash192_get((bash_hash_ctx_t *)state, output);
}

static void bash384_cleanup(bee2_backend_state_t *state) {
    bash_hash192_cleanup((bash_hash_ctx_t *)state);
}

static void bash512_init(bee2_backend_state_t *state) {
    bash_hash256_init((bash_hash_ctx_t *)state);
}

static void
bash512_update(bee2_backend_state_t *state, const unsigned char *input, size_t input_len) {
    bash_hash256_update((bash_hash_ctx_t *)state, input, input_len);
}

static void bash512_final(bee2_backend_state_t *state, unsigned char *output) {
    bash_hash256_get((bash_hash_ctx_t *)state, output);
}

static void bash512_cleanup(bee2_backend_state_t *state) {
    bash_hash256_cleanup((bash_hash_ctx_t *)state);
}

static const bee2_hmac_digest_t bee2_bash_hmac_digests[] = {{"bash256",
                                                             BEE2_OID_BASH256,
                                                             32u,
                                                             160u,
                                                             bash256_init,
                                                             bash256_update,
                                                             bash256_final,
                                                             bash256_cleanup},
                                                            {"bash384",
                                                             BEE2_OID_BASH384,
                                                             48u,
                                                             144u,
                                                             bash384_init,
                                                             bash384_update,
                                                             bash384_final,
                                                             bash384_cleanup},
                                                            {"bash512",
                                                             BEE2_OID_BASH512,
                                                             64u,
                                                             128u,
                                                             bash512_init,
                                                             bash512_update,
                                                             bash512_final,
                                                             bash512_cleanup}};

static const bee2_hmac_digest_t *bash_hmac_find_digest(const char *name) {
    size_t i;

    if (!name)
        return NULL;
    for (i = 0; i < sizeof(bee2_bash_hmac_digests) / sizeof(bee2_bash_hmac_digests[0]); ++i) {
        if (OPENSSL_strcasecmp(name, bee2_bash_hmac_digests[i].name) == 0 ||
            OPENSSL_strcasecmp(name, bee2_bash_hmac_digests[i].oid) == 0)
            return &bee2_bash_hmac_digests[i];
    }
    return NULL;
}

typedef struct {
    belt_hmac_ctx_t backend_state;
    bee2_backend_state_t outer_state;
    const bee2_hmac_digest_t *bash_digest;
    unsigned char *key;
    size_t key_len;
    size_t output_size;
    int output_size_set;
    int key_set;
    int initialized;
} bee2_hmac_ctx_t;

static void *hmac_newctx(void *provctx) {
    bee2_hmac_ctx_t *ctx;

    (void)provctx;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->output_size = BELT_HMAC_SIZE;
    return ctx;
}

static void hmac_freectx(void *vctx) {
    bee2_hmac_ctx_t *ctx = vctx;

    if (!ctx)
        return;
    belt_hmac_cleanup(&ctx->backend_state);
    bee2_backend_cleanup(&ctx->outer_state, sizeof(ctx->outer_state));
    OPENSSL_clear_free(ctx->key, ctx->key_len);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *hmac_dupctx(void *vctx) {
    const bee2_hmac_ctx_t *src = vctx;
    bee2_hmac_ctx_t *dst;

    if (!src)
        return NULL;
    dst = OPENSSL_memdup(src, sizeof(*src));
    if (!dst)
        return NULL;
    dst->key = NULL;
    dst->key_len = 0;
    if (src->key_set && !bee2_secret_replace(&dst->key, &dst->key_len, src->key, src->key_len)) {
        OPENSSL_clear_free(dst, sizeof(*dst));
        return NULL;
    }
    return dst;
}

static const OSSL_PARAM bee2_hmac_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *hmac_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_hmac_gettable_params;
}

static int hmac_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *param;

    param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (param && !OSSL_PARAM_set_size_t(param, BELT_HMAC_SIZE))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (param && !OSSL_PARAM_set_size_t(param, BELT_HMAC_BLOCK_SIZE))
        return 0;
    return 1;
}

static const OSSL_PARAM bee2_hmac_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *hmac_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_hmac_gettable_ctx_params;
}

static int hmac_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    const bee2_hmac_ctx_t *ctx = vctx;
    OSSL_PARAM *param;
    size_t digest_size = ctx->bash_digest ? ctx->bash_digest->digest_size : BELT_HMAC_SIZE;
    size_t block_size = ctx->bash_digest ? ctx->bash_digest->block_size : BELT_HMAC_BLOCK_SIZE;

    param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (param && !OSSL_PARAM_set_size_t(param, ctx->output_size))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
    if (param && !OSSL_PARAM_set_size_t(param, block_size))
        return 0;
    return ctx->output_size <= digest_size;
}

static const OSSL_PARAM bee2_hmac_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *hmac_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_hmac_settable_ctx_params;
}

static int hmac_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_hmac_ctx_t *ctx = vctx;
    const OSSL_PARAM *param;
    const char *digest = NULL;
    const void *key = NULL;
    size_t key_len = 0;
    size_t output_size = 0;

    if (!params)
        return 1;

    param = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_DIGEST);
    if (param) {
        const bee2_hmac_digest_t *bash_digest;

        if (!OSSL_PARAM_get_utf8_string_ptr(param, &digest))
            return 0;
        if (OPENSSL_strcasecmp(digest, "belt-hash") == 0 ||
            OPENSSL_strcasecmp(digest, BEE2_OID_BELT_HASH) == 0) {
            ctx->bash_digest = NULL;
        } else {
            bash_digest = bash_hmac_find_digest(digest);
            if (!bash_digest)
                return 0;
            ctx->bash_digest = bash_digest;
        }
        if (!ctx->output_size_set)
            ctx->output_size = ctx->bash_digest ? ctx->bash_digest->digest_size : BELT_HMAC_SIZE;
        else if (ctx->output_size >
                 (ctx->bash_digest ? ctx->bash_digest->digest_size : BELT_HMAC_SIZE))
            return 0;
        ctx->initialized = 0;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE);
    if (param) {
        size_t digest_size = ctx->bash_digest ? ctx->bash_digest->digest_size : BELT_HMAC_SIZE;
        if (!OSSL_PARAM_get_size_t(param, &output_size) || output_size == 0u ||
            output_size > digest_size)
            return 0;
        ctx->output_size = output_size;
        ctx->output_size_set = 1;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (param) {
        if (!OSSL_PARAM_get_octet_string_ptr(param, &key, &key_len) || key_len == 0u)
            return 0;
        if (!bee2_secret_replace(&ctx->key, &ctx->key_len, key, key_len))
            return 0;
        ctx->key_set = 1;
        ctx->initialized = 0;
    }
    return 1;
}

static int hmac_start(bee2_hmac_ctx_t *ctx) {
    unsigned char key_block[BEE2_HMAC_MAX_BLOCK_SIZE];
    unsigned char digest[BEE2_HMAC_MAX_DIGEST_SIZE];
    unsigned char pad[BEE2_HMAC_MAX_BLOCK_SIZE];
    bee2_backend_state_t temporary_state;
    size_t i;

    if (!ctx || !ctx->key_set)
        return 0;
    if (!ctx->bash_digest) {
        belt_hmac_init(&ctx->backend_state, ctx->key, ctx->key_len);
        ctx->initialized = 1;
        return 1;
    }

    OPENSSL_cleanse(key_block, sizeof(key_block));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(pad, sizeof(pad));
    OPENSSL_cleanse(&temporary_state, sizeof(temporary_state));

    if (ctx->key_len > ctx->bash_digest->block_size) {
        ctx->bash_digest->init(&temporary_state);
        ctx->bash_digest->update(&temporary_state, ctx->key, ctx->key_len);
        ctx->bash_digest->final(&temporary_state, digest);
        ctx->bash_digest->cleanup(&temporary_state);
        memcpy(key_block, digest, ctx->bash_digest->digest_size);
    } else {
        memcpy(key_block, ctx->key, ctx->key_len);
    }

    for (i = 0; i < ctx->bash_digest->block_size; ++i)
        pad[i] = key_block[i] ^ 0x36u;
    ctx->bash_digest->init(&ctx->backend_state);
    ctx->bash_digest->update(&ctx->backend_state, pad, ctx->bash_digest->block_size);

    for (i = 0; i < ctx->bash_digest->block_size; ++i)
        pad[i] = key_block[i] ^ 0x5cu;
    ctx->bash_digest->init(&ctx->outer_state);
    ctx->bash_digest->update(&ctx->outer_state, pad, ctx->bash_digest->block_size);

    OPENSSL_cleanse(&temporary_state, sizeof(temporary_state));
    OPENSSL_cleanse(pad, sizeof(pad));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(key_block, sizeof(key_block));
    ctx->initialized = 1;
    return 1;
}

static int
hmac_init(void *vctx, const unsigned char *key, size_t key_len, const OSSL_PARAM params[]) {
    bee2_hmac_ctx_t *ctx = vctx;

    if (!ctx || !hmac_set_ctx_params(ctx, params))
        return 0;
    if (key) {
        if (key_len == 0u || !bee2_secret_replace(&ctx->key, &ctx->key_len, key, key_len))
            return 0;
        ctx->key_set = 1;
    }
    if (!ctx->key_set)
        return 0;
    return hmac_start(ctx);
}

static int hmac_update(void *vctx, const unsigned char *input, size_t input_len) {
    bee2_hmac_ctx_t *ctx = vctx;

    if (!ctx || !ctx->initialized)
        return 0;
    if (input_len > 0u) {
        if (ctx->bash_digest)
            ctx->bash_digest->update(&ctx->backend_state, input, input_len);
        else
            belt_hmac_update(&ctx->backend_state, input, input_len);
    }
    return 1;
}

static int hmac_final(void *vctx, unsigned char *output, size_t *output_len, size_t output_size) {
    bee2_hmac_ctx_t *ctx = vctx;
    unsigned char inner_digest[BEE2_HMAC_MAX_DIGEST_SIZE];
    unsigned char full_mac[BEE2_HMAC_MAX_DIGEST_SIZE];
    bee2_backend_state_t outer_state;
    size_t digest_size;

    if (!ctx || !ctx->initialized || !output_len)
        return 0;
    digest_size = ctx->bash_digest ? ctx->bash_digest->digest_size : BELT_HMAC_SIZE;
    if (!output) {
        *output_len = ctx->output_size;
        return 1;
    }
    if (output_size < ctx->output_size || ctx->output_size > digest_size)
        return 0;

    OPENSSL_cleanse(inner_digest, sizeof(inner_digest));
    OPENSSL_cleanse(full_mac, sizeof(full_mac));
    OPENSSL_cleanse(&outer_state, sizeof(outer_state));
    if (ctx->bash_digest) {
        ctx->bash_digest->final(&ctx->backend_state, inner_digest);
        memcpy(&outer_state, &ctx->outer_state, sizeof(outer_state));
        ctx->bash_digest->update(&outer_state, inner_digest, digest_size);
        ctx->bash_digest->final(&outer_state, full_mac);
        ctx->bash_digest->cleanup(&outer_state);
    } else {
        belt_hmac_get(&ctx->backend_state, full_mac);
    }
    memcpy(output, full_mac, ctx->output_size);
    *output_len = ctx->output_size;
    OPENSSL_cleanse(&outer_state, sizeof(outer_state));
    OPENSSL_cleanse(full_mac, sizeof(full_mac));
    OPENSSL_cleanse(inner_digest, sizeof(inner_digest));
    ctx->initialized = 0;
    return 1;
}

const OSSL_DISPATCH bee2_hmac_functions[] = {
    {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))hmac_newctx},
    {OSSL_FUNC_MAC_FREECTX, (void (*)(void))hmac_freectx},
    {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))hmac_dupctx},
    {OSSL_FUNC_MAC_INIT, (void (*)(void))hmac_init},
    {OSSL_FUNC_MAC_UPDATE, (void (*)(void))hmac_update},
    {OSSL_FUNC_MAC_FINAL, (void (*)(void))hmac_final},
    {OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))hmac_get_params},
    {OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))hmac_gettable_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))hmac_get_ctx_params},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (void (*)(void))hmac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))hmac_set_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (void (*)(void))hmac_settable_ctx_params},
    {0, NULL}};
