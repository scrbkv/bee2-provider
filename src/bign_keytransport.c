#include "bign_common.h"

#include <limits.h>
#include <openssl/rand.h>

typedef struct {
    bee2_bign_key_t *key;
    int encrypt;
} bee2_bign_keytransport_ctx_t;

typedef struct {
    int failed;
} bee2_bign_keytransport_rng_t;

static void bign_keytransport_rng(void *buf, size_t count, void *state) {
    bee2_bign_keytransport_rng_t *rng = state;

    if (rng == NULL || count > (size_t)INT_MAX || RAND_priv_bytes(buf, (int)count) != 1) {
        if (buf != NULL)
            bee2_bign_cleanse(buf, count);
        if (rng != NULL)
            rng->failed = 1;
    }
}

static void *bign_keytransport_newctx(void *provctx) {
    (void)provctx;
    return OPENSSL_zalloc(sizeof(bee2_bign_keytransport_ctx_t));
}

static void bign_keytransport_freectx(void *vctx) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    if (!ctx)
        return;
    bee2_bign_cleanse(ctx, sizeof(*ctx));
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

static int bign_keytransport_encrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = vkey;
    (void)params;
    if (!ctx || !key || !key->variant || !key->has_pub)
        return 0;
    ctx->key = key;
    ctx->encrypt = 1;
    return 1;
}

static int bign_keytransport_decrypt_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_keytransport_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = vkey;
    (void)params;
    if (!ctx || !key || !key->variant || !key->has_priv)
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
    bee2_bign_keytransport_rng_t rng = {0};
    size_t need;
    int ok = 0;
    static const unsigned char header[16];
    if (!ctx || !ctx->encrypt || !ctx->key || !outlen || !in || inlen < 16)
        return 0;
    need = inlen + bee2_bign_priv_len(ctx->key->variant) + 16u;
    if (!out) {
        *outlen = need;
        return 1;
    }
    if (outsize < need)
        return 0;
    OPENSSL_cleanse(&curve, sizeof(curve));
    if (!bee2_bign_curve_init_std(ctx->key->variant, &curve))
        goto cleanup;
    if (bignKeyWrap(out, &curve, in, inlen, header, ctx->key->pub, bign_keytransport_rng, &rng) !=
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
    static const unsigned char header[16];
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
    OPENSSL_cleanse(&curve, sizeof(curve));
    if (!bee2_bign_curve_init_std(ctx->key->variant, &curve))
        goto cleanup;
    if (bignKeyUnwrap(out, &curve, in, inlen, header, ctx->key->priv) != ERR_OK)
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
    {0, NULL}};
