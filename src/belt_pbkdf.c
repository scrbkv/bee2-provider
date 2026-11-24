#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>

typedef struct {
    OSSL_LIB_CTX *libctx;
    unsigned char *password;
    size_t password_len;
    unsigned char *salt;
    size_t salt_len;
    size_t iter;
    int password_set;
    int salt_set;
} bee2_belt_pbkdf_ctx_t;

static void belt_pbkdf_clear(bee2_belt_pbkdf_ctx_t *ctx) {
    if (!ctx)
        return;
    OPENSSL_clear_free(ctx->password, ctx->password_len);
    OPENSSL_clear_free(ctx->salt, ctx->salt_len);
    ctx->password = ctx->salt = NULL;
    ctx->password_len = ctx->salt_len = 0;
    ctx->iter = 0;
    ctx->password_set = 0;
    ctx->salt_set = 0;
}

static void *belt_pbkdf_newctx(void *provctx) {
    bee2_belt_pbkdf_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->libctx = bee2_provider_libctx(provctx);
    return ctx;
}

static void belt_pbkdf_freectx(void *vctx) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    belt_pbkdf_clear(ctx);
    OPENSSL_free(ctx);
}

static void belt_pbkdf_reset(void *vctx) {
    belt_pbkdf_clear(vctx);
}

static int belt_pbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    const OSSL_PARAM *pwd, *salt, *iter_param;
    unsigned char *new_pwd = NULL, *new_salt = NULL;
    uint64_t iter;

    if (!params)
        return 1;
    pwd = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PASSWORD);
    salt = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    iter_param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_ITER);
    iter = ctx->iter;
    if (iter_param && (!OSSL_PARAM_get_uint64(iter_param, &iter) ||
                       iter == 0 || iter > SIZE_MAX))
        return 0;
    if ((pwd && (pwd->data_type != OSSL_PARAM_OCTET_STRING ||
                 (pwd->data == NULL && pwd->data_size != 0))) ||
        (salt && (salt->data_type != OSSL_PARAM_OCTET_STRING ||
                  (salt->data == NULL && salt->data_size != 0))))
        return 0;
    if (pwd && pwd->data_size != 0 &&
        (new_pwd = OPENSSL_memdup(pwd->data, pwd->data_size)) == NULL)
        return 0;
    if (salt && salt->data_size != 0 &&
        (new_salt = OPENSSL_memdup(salt->data, salt->data_size)) == NULL) {
        OPENSSL_clear_free(new_pwd, pwd ? pwd->data_size : 0);
        return 0;
    }
    if (pwd) {
        OPENSSL_clear_free(ctx->password, ctx->password_len);
        ctx->password = new_pwd;
        ctx->password_len = pwd->data_size;
        ctx->password_set = 1;
    }
    if (salt) {
        OPENSSL_clear_free(ctx->salt, ctx->salt_len);
        ctx->salt = new_salt;
        ctx->salt_len = salt->data_size;
        ctx->salt_set = 1;
    }
    ctx->iter = (size_t)iter;
    return 1;
}

static int
belt_pbkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]) {
    bee2_belt_pbkdf_ctx_t *ctx = vctx;
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    uint64_t iterations;
    int pkcs5 = 1;
    int ok;

    if (!belt_pbkdf_set_ctx_params(ctx, params))
        return 0;
    if (key == NULL || keylen != 32 ||
        !ctx->password_set || !ctx->salt_set || ctx->iter == 0)
        return 0;
    iterations = (uint64_t)ctx->iter;
    OSSL_PARAM kdf_params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, ctx->password, ctx->password_len),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, ctx->salt, ctx->salt_len),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "belt-hash", 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS5, &pkcs5),
        OSSL_PARAM_END
    };
    kdf = EVP_KDF_fetch(ctx->libctx, "PBKDF2", "provider=default");
    kctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
    ok = kctx != NULL && EVP_KDF_derive(kctx, key, keylen, kdf_params) > 0;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
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
