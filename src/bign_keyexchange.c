/* OpenSSL 3 provider adapter for BIGN Diffie--Hellman key agreement. */

#include "bign_common.h"
#include "provider_util.h"

#include <bee2/crypto/bake.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <stdint.h>

#define BEE2_EXCHANGE_PARAM_KDF_NUM "kdf-num"
#define BEE2_BAKE_KDF_NAME "bake-kdf"
#define BEE2_BAKE_KDF_SIZE 32u

typedef struct {
    bee2_bign_key_t *local_key;
    bee2_bign_key_t *peer_key;
    unsigned char *ukm;
    size_t ukm_len;
    size_t kdf_output_len;
    uint64_t kdf_num;
    int use_bake_kdf;
} bee2_bign_keyexchange_ctx_t;

static void *bign_keyexchange_newctx(void *provctx) {
    bee2_bign_keyexchange_ctx_t *ctx;

    (void)provctx;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->kdf_output_len = BEE2_BAKE_KDF_SIZE;
    return ctx;
}

static void bign_keyexchange_freectx(void *vctx) {
    bee2_bign_keyexchange_ctx_t *ctx = vctx;

    if (!ctx)
        return;
    OPENSSL_clear_free(ctx->ukm, ctx->ukm_len);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *bign_keyexchange_dupctx(void *vctx) {
    const bee2_bign_keyexchange_ctx_t *src = vctx;
    bee2_bign_keyexchange_ctx_t *dst;

    if (!src)
        return NULL;
    dst = OPENSSL_memdup(src, sizeof(*src));
    if (!dst)
        return NULL;
    dst->ukm = NULL;
    dst->ukm_len = 0;
    if (src->ukm_len > 0u &&
        !bee2_secret_replace(&dst->ukm, &dst->ukm_len, src->ukm, src->ukm_len)) {
        OPENSSL_clear_free(dst, sizeof(*dst));
        return NULL;
    }
    return dst;
}

static int bign_keyexchange_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int bign_keyexchange_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_keyexchange_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = vkey;

    if (!ctx || !key || !key->variant || !key->has_priv)
        return 0;
    ctx->local_key = key;
    ctx->peer_key = NULL;
    return bign_keyexchange_set_ctx_params(ctx, params);
}

static int bign_keyexchange_set_peer(void *vctx, void *vkey) {
    bee2_bign_keyexchange_ctx_t *ctx = vctx;
    bee2_bign_key_t *peer = vkey;

    if (!ctx || !ctx->local_key || !peer || !peer->variant || !peer->has_pub ||
        peer->variant != ctx->local_key->variant)
        return 0;
    ctx->peer_key = peer;
    return 1;
}

static int bign_keyexchange_derive_raw(const bee2_bign_keyexchange_ctx_t *ctx,
                                       unsigned char *secret,
                                       size_t secret_len) {
    bign_params curve;
    int ok;

    OPENSSL_cleanse(&curve, sizeof(curve));
    if (!bee2_bign_curve_init_std(ctx->local_key->variant, &curve))
        return 0;
    ok = bignDH(secret, &curve, ctx->local_key->priv, ctx->peer_key->pub, secret_len) == ERR_OK;
    bee2_bign_cleanse(&curve, sizeof(curve));
    return ok;
}

static int
bign_keyexchange_derive(void *vctx, unsigned char *secret, size_t *secret_len, size_t output_size) {
    bee2_bign_keyexchange_ctx_t *ctx = vctx;
    size_t raw_max_len;
    size_t result_len;

    if (!ctx || !ctx->local_key || !ctx->peer_key || !secret_len)
        return 0;
    raw_max_len = bee2_bign_pub_len(ctx->local_key->variant);
    result_len = ctx->use_bake_kdf ? ctx->kdf_output_len : raw_max_len;
    if (!secret) {
        *secret_len = result_len;
        return 1;
    }
    if (output_size < result_len)
        return 0;

    if (ctx->use_bake_kdf) {
        unsigned char raw_secret[BEE2_BIGN_MAX_WORDS * 8];
        unsigned char derived[BEE2_BAKE_KDF_SIZE];
        size_t raw_len = bee2_bign_priv_len(ctx->local_key->variant);
        int ok = 0;

        OPENSSL_cleanse(raw_secret, sizeof(raw_secret));
        OPENSSL_cleanse(derived, sizeof(derived));
        if (!bign_keyexchange_derive_raw(ctx, raw_secret, raw_len))
            goto cleanup;
        if (bakeKDF(derived, raw_secret, raw_len, ctx->ukm, ctx->ukm_len, (size_t)ctx->kdf_num) !=
            ERR_OK)
            goto cleanup;
        memcpy(secret, derived, result_len);
        *secret_len = result_len;
        ok = 1;

    cleanup:
        bee2_bign_cleanse(derived, sizeof(derived));
        bee2_bign_cleanse(raw_secret, sizeof(raw_secret));
        return ok;
    }

    if (!bign_keyexchange_derive_raw(ctx, secret, result_len)) {
        bee2_bign_cleanse(secret, result_len);
        return 0;
    }
    *secret_len = result_len;
    return 1;
}

static const OSSL_PARAM bee2_bign_keyexchange_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
    OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
    OSSL_PARAM_uint64(BEE2_EXCHANGE_PARAM_KDF_NUM, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bign_keyexchange_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_bign_keyexchange_ctx_params;
}

static const OSSL_PARAM *bign_keyexchange_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_bign_keyexchange_ctx_params;
}

static int bign_keyexchange_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bign_keyexchange_ctx_t *ctx = vctx;
    const OSSL_PARAM *param;

    if (!ctx || !params)
        return ctx != NULL;

    param = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (param) {
        const char *name = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(param, &name))
            return 0;
        if (!name || name[0] == '\0' || OPENSSL_strcasecmp(name, "none") == 0)
            ctx->use_bake_kdf = 0;
        else if (OPENSSL_strcasecmp(name, BEE2_BAKE_KDF_NAME) == 0)
            ctx->use_bake_kdf = 1;
        else
            return 0;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (param) {
        const void *ukm = NULL;
        size_t ukm_len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(param, &ukm, &ukm_len) ||
            !bee2_secret_replace(&ctx->ukm, &ctx->ukm_len, ukm, ukm_len))
            return 0;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (param && (!OSSL_PARAM_get_size_t(param, &ctx->kdf_output_len) ||
                  ctx->kdf_output_len == 0u || ctx->kdf_output_len > BEE2_BAKE_KDF_SIZE))
        return 0;

    param = OSSL_PARAM_locate_const(params, BEE2_EXCHANGE_PARAM_KDF_NUM);
    if (param) {
        if (!OSSL_PARAM_get_uint64(param, &ctx->kdf_num) || ctx->kdf_num > SIZE_MAX)
            return 0;
    }
    return 1;
}

static int bign_keyexchange_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    const bee2_bign_keyexchange_ctx_t *ctx = vctx;
    OSSL_PARAM *param;
    const char *kdf_name;

    if (!ctx)
        return 0;
    kdf_name = ctx->use_bake_kdf ? BEE2_BAKE_KDF_NAME : "";
    param = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
    if (param && !OSSL_PARAM_set_utf8_string(param, kdf_name))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
    if (param && !OSSL_PARAM_set_octet_string(param, ctx->ukm, ctx->ukm_len))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
    if (param && !OSSL_PARAM_set_size_t(param, ctx->kdf_output_len))
        return 0;
    param = OSSL_PARAM_locate(params, BEE2_EXCHANGE_PARAM_KDF_NUM);
    if (param && !OSSL_PARAM_set_uint64(param, ctx->kdf_num))
        return 0;
    return 1;
}

const OSSL_DISPATCH bee2_bign_keyexchange_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))bign_keyexchange_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))bign_keyexchange_init},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))bign_keyexchange_derive},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))bign_keyexchange_set_peer},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))bign_keyexchange_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))bign_keyexchange_dupctx},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))bign_keyexchange_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))bign_keyexchange_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))bign_keyexchange_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))bign_keyexchange_gettable_ctx_params},
    {0, NULL}};
