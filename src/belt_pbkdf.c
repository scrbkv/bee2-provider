#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>

typedef struct {
    unsigned char *password;
    size_t password_len;
    unsigned char *salt;
    size_t salt_len;
    size_t iter;
} bee2_belt_pbkdf_ctx_t;

static void belt_pbkdf_clear(bee2_belt_pbkdf_ctx_t *ctx) {
    if (!ctx)
        return;
    OPENSSL_clear_free(ctx->password, ctx->password_len);
    OPENSSL_clear_free(ctx->salt, ctx->salt_len);
    ctx->password = ctx->salt = NULL;
    ctx->password_len = ctx->salt_len = 0;
    ctx->iter = 0;
}

static void *belt_pbkdf_newctx(void *provctx) {
    (void)provctx;
    return OPENSSL_zalloc(sizeof(bee2_belt_pbkdf_ctx_t));
}

static void belt_pbkdf_freectx(void *vctx) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    belt_pbkdf_clear(ctx);
    OPENSSL_free(ctx);
}

static void belt_pbkdf_reset(void *vctx) {
    belt_pbkdf_clear(vctx);
}

static int belt_pbkdf_set_octets(unsigned char **dst, size_t *dst_len, const OSSL_PARAM *p) {
    return bee2_secret_replace(dst, dst_len, p->data, p->data_size);
}

static int belt_pbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;
    uint64_t iter;
    if (!params)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD);
    if (p && !belt_pbkdf_set_octets(&ctx->password, &ctx->password_len, p))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p && !belt_pbkdf_set_octets(&ctx->salt, &ctx->salt_len, p))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);
    if (p) {
        if (!OSSL_PARAM_get_uint64(p, &iter) || iter == 0 || iter > SIZE_MAX)
            return 0;
        ctx->iter = (size_t)iter;
    }
    return 1;
}

static int
belt_pbkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    if (!belt_pbkdf_set_ctx_params(ctx, params))
        return 0;
    if (keylen != 32 || !ctx->password || !ctx->salt || ctx->iter == 0)
        return 0;
    return beltPBKDF2(key, ctx->password, ctx->password_len, ctx->iter, ctx->salt, ctx->salt_len) ==
           ERR_OK;
}

static const OSSL_PARAM belt_pbkdf_settable[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
    OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_pbkdf_settable_ctx_params(void *ctx, void *provctx) {
    (void)ctx;
    (void)provctx;
    return belt_pbkdf_settable;
}

const OSSL_DISPATCH bee2_belt_pbkdf_functions[] = {
    {OSSL_FUNC_KDF_NEWCTX, (void (*)(void))belt_pbkdf_newctx},
    {OSSL_FUNC_KDF_FREECTX, (void (*)(void))belt_pbkdf_freectx},
    {OSSL_FUNC_KDF_RESET, (void (*)(void))belt_pbkdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (void (*)(void))belt_pbkdf_derive},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (void (*)(void))belt_pbkdf_set_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void (*)(void))belt_pbkdf_settable_ctx_params},
    {0, NULL}};
