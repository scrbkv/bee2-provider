#include "bign_common.h"

#include <limits.h>

#define BEE2_BIGN_KEYTRANSPORT_HEADER_SIZE 16u
#define BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER "header"

typedef struct {
    OSSL_LIB_CTX *libctx;
    bee2_bign_key_t *key;
    unsigned char header[BEE2_BIGN_KEYTRANSPORT_HEADER_SIZE];
    int encrypt;
} bee2_bign_keytransport_ctx_t;

static void *bign_keytransport_newctx(void *provctx) {
    bee2_bign_keytransport_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->libctx = bee2_provider_libctx(provctx);
    return ctx;
}

static void bign_keytransport_freectx(void *vctx) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    if (!ctx)
        return;
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *bign_keytransport_dupctx(void *vctx) {
    if (!vctx)
        return NULL;
    bee2_bign_keytransport_ctx_t *copy = OPENSSL_malloc(sizeof(*copy));
    if (copy)
        memcpy(copy, vctx, sizeof(*copy));
    return copy;
}

static const OSSL_PARAM bign_keytransport_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bign_keytransport_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *
bign_keytransport_gettable_ctx_params_fn(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bign_keytransport_gettable_ctx_params;
}

static const OSSL_PARAM *
bign_keytransport_settable_ctx_params_fn(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bign_keytransport_settable_ctx_params;
}

static int bign_keytransport_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    OSSL_PARAM *param;

    if (ctx == NULL)
        return 0;
    param = OSSL_PARAM_locate(params, BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER);
    if (param != NULL &&
        !OSSL_PARAM_set_octet_string(param, ctx->header, sizeof(ctx->header)))
        return 0;
    return 1;
}

static int bign_keytransport_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    const OSSL_PARAM *param;
    const void *header;
    size_t header_len;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    param = OSSL_PARAM_locate_const(params, BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER);
    if (param == NULL)
        return 1;
    if (!OSSL_PARAM_get_octet_string_ptr(param, &header, &header_len) ||
        header == NULL || header_len != sizeof(ctx->header))
        return 0;

    memmove(ctx->header, header, sizeof(ctx->header));
    return 1;
}

static int bign_keytransport_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = vkey;
    if (!ctx)
        return 0;
    ctx->key = NULL;
    ctx->encrypt = 0;
    if (!key || !key->variant || !key->has_pub ||
        !bign_keytransport_set_ctx_params(ctx, params))
        return 0;
    ctx->key = key;
    ctx->encrypt = 1;
    return 1;
}

static int bign_keytransport_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = vkey;
    if (!ctx)
        return 0;
    ctx->key = NULL;
    ctx->encrypt = 0;
    if (!key || !key->variant || !key->has_priv ||
        !bign_keytransport_set_ctx_params(ctx, params))
        return 0;
    ctx->key = key;
    ctx->encrypt = 0;
    return 1;
}

static int bign_keytransport_encrypt(void *vctx,
                                     unsigned char *out,
                                     size_t *outlen,
                                     size_t outsize,
                                     const unsigned char *in,
                                     size_t inlen) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bign_params curve;
    bee2_bign_rng_t rng = {0};
    size_t need;
    int ok = 0;
    if (!ctx || !ctx->encrypt || !ctx->key || !outlen || !in || inlen < 16)
        return 0;
    need = bee2_bign_priv_len(ctx->key->variant) + 16u;
    if (inlen > SIZE_MAX - need)
        return 0;
    need += inlen;
    if (!out) {
        *outlen = need;
        return 1;
    }
    if (outsize < need)
        return 0;
    rng.libctx = ctx->libctx;
    if (!bee2_bign_curve_init_std(ctx->key->variant, &curve))
        goto cleanup;
    if (bignKeyWrap(out, &curve, in, inlen, ctx->header, ctx->key->pub,
                    bee2_bign_openssl_rng, &rng) !=
            ERR_OK ||
        rng.failed)
        goto cleanup;
    *outlen = need;
    ok = 1;

cleanup:
    if (!ok)
        bee2_bign_cleanse(out, need);
    bee2_bign_cleanse(&curve, sizeof(curve));
    return ok;
}

static int bign_keytransport_decrypt(void *vctx,
                                     unsigned char *out,
                                     size_t *outlen,
                                     size_t outsize,
                                     const unsigned char *in,
                                     size_t inlen) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bign_params curve;
    size_t overhead;
    size_t need;
    int ok = 0;
    if (!ctx || ctx->encrypt || !ctx->key || !outlen || !in)
        return 0;
    overhead = bee2_bign_priv_len(ctx->key->variant) + 16u;
    if (inlen < overhead + 16u)
        return 0;
    need = inlen - overhead;
    if (!out) {
        *outlen = need;
        return 1;
    }
    if (outsize < need)
        return 0;
    if (!bee2_bign_curve_init_std(ctx->key->variant, &curve))
        goto cleanup;
    if (bignKeyUnwrap(out, &curve, in, inlen, ctx->header, ctx->key->priv) != ERR_OK)
        goto cleanup;
    *outlen = need;
    ok = 1;

cleanup:
    if (!ok)
        bee2_bign_cleanse(out, need);
    bee2_bign_cleanse(&curve, sizeof(curve));
    return ok;
}

const OSSL_DISPATCH bee2_bign_keytransport_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))bign_keytransport_newctx},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))bign_keytransport_freectx},
    {OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))bign_keytransport_dupctx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))bign_keytransport_encrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))bign_keytransport_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))bign_keytransport_decrypt_init},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))bign_keytransport_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, (void (*)(void))bign_keytransport_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
     (void (*)(void))bign_keytransport_gettable_ctx_params_fn},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))bign_keytransport_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))bign_keytransport_settable_ctx_params_fn},
    {0, NULL}};
