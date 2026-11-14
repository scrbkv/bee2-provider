/*
 * OpenSSL EVP_RAND adapters for the BRNG mechanisms of STB 34.101.47.
 * The cryptographic state transitions are implemented by Bee2.
 */

#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <bee2/crypto/brng.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define BRNG_BLOCK_SIZE 32u
#define BRNG_STRENGTH_BITS 256u
#define BRNG_IV_PARAM "iv"

typedef enum {
    BRNG_MODE_CTR_HBELT,
    BRNG_MODE_HMAC_HBELT
} brng_mode_t;

typedef struct {
    brng_mode_t mode;
    int state;
    unsigned int strength;
    size_t max_request;
    int instantiated;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
    int have_key;
    int have_iv;
    bee2_backend_state_t backend;
} bee2_brng_ctx_t;

static void brng_clear_backend(bee2_brng_ctx_t *c) {
    OPENSSL_cleanse(&c->backend, sizeof(c->backend));
    c->instantiated = 0;
    c->state = EVP_RAND_STATE_UNINITIALISED;
}

static void *brng_newctx_common(brng_mode_t mode) {
    bee2_brng_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->mode = mode;
    c->state = EVP_RAND_STATE_UNINITIALISED;
    c->strength = BRNG_STRENGTH_BITS;
    c->max_request = SIZE_MAX;
    return c;
}

static void *brng_ctr_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) {
    (void)provctx;
    (void)parent;
    (void)parent_calls;
    return brng_newctx_common(BRNG_MODE_CTR_HBELT);
}

static void *brng_hmac_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) {
    (void)provctx;
    (void)parent;
    (void)parent_calls;
    return brng_newctx_common(BRNG_MODE_HMAC_HBELT);
}

static void brng_freectx(void *vctx) {
    bee2_brng_ctx_t *c = vctx;
    if (!c)
        return;
    OPENSSL_clear_free(c->key, c->key_len);
    OPENSSL_clear_free(c->iv, c->iv_len);
    OPENSSL_clear_free(c, sizeof(*c));
}

static const OSSL_PARAM brng_gettable_params[] = {
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *brng_gettable_params_callback(void *provctx) {
    (void)provctx;
    return brng_gettable_params;
}

static int brng_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p && !OSSL_PARAM_set_int(p, EVP_RAND_STATE_UNINITIALISED))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p && !OSSL_PARAM_set_uint(p, BRNG_STRENGTH_BITS))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p && !OSSL_PARAM_set_size_t(p, SIZE_MAX))
        return 0;
    return 1;
}

static const OSSL_PARAM brng_gettable_ctx_params[] = {
    OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
    OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
    OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
    OSSL_PARAM_octet_string(BRNG_IV_PARAM, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *brng_gettable_ctx_params_callback(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return brng_gettable_ctx_params;
}

static int brng_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    static const unsigned char zero_iv[BRNG_BLOCK_SIZE] = {0};
    static const unsigned char empty_octet = 0;
    bee2_brng_ctx_t *c = vctx;
    OSSL_PARAM *p;
    const unsigned char *iv_data;
    size_t iv_len;
    unsigned char live_iv[BRNG_BLOCK_SIZE];

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p && !OSSL_PARAM_set_int(p, c->state))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p && !OSSL_PARAM_set_uint(p, c->strength))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p && !OSSL_PARAM_set_size_t(p, c->max_request))
        return 0;
    p = OSSL_PARAM_locate(params, BRNG_IV_PARAM);
    if (!p)
        return 1;

    if (c->mode == BRNG_MODE_CTR_HBELT) {
        if (c->instantiated) {
            brngCTRStepG(live_iv, &c->backend);
            iv_data = live_iv;
        } else {
            iv_data = c->have_iv ? c->iv : zero_iv;
        }
        iv_len = BRNG_BLOCK_SIZE;
    } else {
        iv_data = c->have_iv ? c->iv : &empty_octet;
        iv_len = c->have_iv ? c->iv_len : 0;
    }
    return OSSL_PARAM_set_octet_string(p, iv_data, iv_len);
}

static const OSSL_PARAM brng_settable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(BRNG_IV_PARAM, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *brng_settable_ctx_params_callback(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return brng_settable_ctx_params;
}

static int brng_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_brng_ctx_t *c = vctx;
    const OSSL_PARAM *key_param, *iv_param;
    const void *key_data = NULL, *iv_data = NULL;
    unsigned char *new_key = NULL, *new_iv = NULL;
    size_t key_len = 0, iv_len = 0;

    if (!c)
        return 0;
    if (!params)
        return 1;
    key_param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    iv_param = OSSL_PARAM_locate_const(params, BRNG_IV_PARAM);
    if (key_param &&
        (!OSSL_PARAM_get_octet_string_ptr(key_param, &key_data, &key_len) ||
         (key_data == NULL && key_len != 0) ||
         (c->mode == BRNG_MODE_CTR_HBELT && key_len != BRNG_BLOCK_SIZE) ||
         (c->mode == BRNG_MODE_HMAC_HBELT && key_len == 0)))
        return 0;
    if (iv_param &&
        (!OSSL_PARAM_get_octet_string_ptr(iv_param, &iv_data, &iv_len) ||
         (iv_data == NULL && iv_len != 0) ||
         (c->mode == BRNG_MODE_CTR_HBELT && iv_len != BRNG_BLOCK_SIZE)))
        return 0;

    if (key_param && key_len != 0 &&
        (new_key = OPENSSL_memdup(key_data, key_len)) == NULL)
        return 0;
    if (iv_param && iv_len != 0 &&
        (new_iv = OPENSSL_memdup(iv_data, iv_len)) == NULL) {
        OPENSSL_clear_free(new_key, key_len);
        return 0;
    }
    if (key_param || iv_param)
        brng_clear_backend(c);
    if (key_param) {
        OPENSSL_clear_free(c->key, c->key_len);
        c->key = new_key;
        c->key_len = key_len;
        c->have_key = 1;
    }
    if (iv_param) {
        OPENSSL_clear_free(c->iv, c->iv_len);
        c->iv = new_iv;
        c->iv_len = iv_len;
        c->have_iv = 1;
    }
    return 1;
}

static int brng_instantiate(void *vctx,
                            unsigned int strength,
                            int prediction_resistance,
                            const unsigned char *pstr,
                            size_t pstr_len,
                            const OSSL_PARAM params[]) {
    static const unsigned char zero_iv[BRNG_BLOCK_SIZE] = {0};
    static const unsigned char empty_octet = 0;
    bee2_brng_ctx_t *c = vctx;
    unsigned int max_strength;

    (void)pstr;
    /* These deterministic generators cannot source fresh entropy by themselves.
     * Never silently claim prediction resistance or personalization support. */
    if (prediction_resistance || pstr_len != 0 || !brng_set_ctx_params(vctx, params))
        return 0;
    if (!c->have_key || c->key_len == 0)
        return 0;
    if (c->mode == BRNG_MODE_CTR_HBELT && c->key_len != BRNG_BLOCK_SIZE)
        return 0;

    max_strength = c->key_len >= BRNG_BLOCK_SIZE ? BRNG_STRENGTH_BITS
                                                : (unsigned int)(c->key_len * 8u);
    if (strength > max_strength)
        return 0;
    brng_clear_backend(c);
    if (c->mode == BRNG_MODE_CTR_HBELT) {
        brngCTRStart(&c->backend, c->key, c->have_iv ? c->iv : zero_iv);
    } else {
        brngHMACStart(&c->backend,
                      c->key,
                      c->key_len,
                      c->have_iv ? c->iv : &empty_octet,
                      c->have_iv ? c->iv_len : 0);
    }
    c->instantiated = 1;
    c->strength = max_strength;
    c->state = EVP_RAND_STATE_READY;
    return 1;
}

static int brng_uninstantiate(void *vctx) {
    bee2_brng_ctx_t *c = vctx;
    brng_clear_backend(c);
    OPENSSL_clear_free(c->key, c->key_len);
    OPENSSL_clear_free(c->iv, c->iv_len);
    c->key = NULL;
    c->iv = NULL;
    c->key_len = c->iv_len = 0;
    c->have_key = c->have_iv = 0;
    c->strength = BRNG_STRENGTH_BITS;
    return 1;
}

static int brng_generate_ctr(bee2_brng_ctx_t *c,
                             unsigned char *out,
                             size_t outlen,
                             const unsigned char *addin,
                             size_t addin_len) {
    unsigned char block[BRNG_BLOCK_SIZE];
    unsigned char *additional = NULL;
    size_t pos = 0;

    /* Copy additional input because it may overlap with the output. The
     * initialized bytes become Bee2's X, and absent bytes are zero-padded. */
    if (addin_len) {
        additional = OPENSSL_memdup(addin, addin_len);
        if (!additional)
            return 0;
    }
    while (pos < outlen) {
        size_t chunk = outlen - pos;
        size_t input = pos < addin_len ? addin_len - pos : 0;
        if (chunk > sizeof(block))
            chunk = sizeof(block);
        if (input > chunk)
            input = chunk;
        memset(block, 0, sizeof(block));
        if (input)
            memcpy(block, additional + pos, input);
        brngCTRStepR(block, chunk, &c->backend);
        memcpy(out + pos, block, chunk);
        pos += chunk;
    }
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_clear_free(additional, addin_len);
    return 1;
}

static int brng_generate(void *vctx,
                         unsigned char *out,
                         size_t outlen,
                         unsigned int strength,
                         int prediction_resistance,
                         const unsigned char *addin,
                         size_t addin_len) {
    bee2_brng_ctx_t *c = vctx;

    if (!c->instantiated || c->state != EVP_RAND_STATE_READY ||
        strength > c->strength || outlen > c->max_request ||
        (outlen && !out) || (addin_len && !addin) || prediction_resistance)
        return 0;
    if (c->mode == BRNG_MODE_HMAC_HBELT) {
        /* Bee2 BRNG-HMAC has no additional-input parameter. */
        if (addin_len)
            return 0;
        if (outlen)
            brngHMACStepR(out, outlen, &c->backend);
        return 1;
    }
    /* Bee2 BRNG-CTR consumes X from the output buffer. If X is longer
     * than the requested output, it would otherwise be silently ignored. */
    if (addin_len > outlen)
        return 0;
    return brng_generate_ctr(c, out, outlen, addin, addin_len);
}

static int brng_reseed(void *vctx,
                       int prediction_resistance,
                       const unsigned char *ent,
                       size_t ent_len,
                       const unsigned char *addin,
                       size_t addin_len) {
    bee2_brng_ctx_t *c = vctx;
    (void)addin;
    /* Reseed means explicitly replacing the key, not reusing the old state.
     * The Bee2 algorithms have no prediction-resistance / reseed-mix API. */
    if (prediction_resistance || addin_len || !ent || !ent_len ||
        !c->instantiated ||
        (c->mode == BRNG_MODE_CTR_HBELT && ent_len != BRNG_BLOCK_SIZE))
        return 0;
    if (!bee2_secret_replace(&c->key, &c->key_len, ent, ent_len))
        return 0;
    c->have_key = 1;
    return brng_instantiate(c, 0, 0, NULL, 0, NULL);
}

static int brng_verify_zeroization(void *vctx) {
    const bee2_brng_ctx_t *c = vctx;
    const unsigned char *p = (const unsigned char *)&c->backend;
    size_t i;
    if (c->instantiated || c->have_key || c->have_iv)
        return 0;
    for (i = 0; i < sizeof(c->backend); ++i) {
        if (p[i])
            return 0;
    }
    return 1;
}

const OSSL_DISPATCH bee2_brng_ctr_hbelt_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))brng_ctr_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))brng_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))brng_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))brng_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))brng_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))brng_reseed},
    {OSSL_FUNC_RAND_GET_PARAMS, (void (*)(void))brng_get_params},
    {OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void))brng_gettable_params_callback},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))brng_get_ctx_params},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))brng_gettable_ctx_params_callback},
    {OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))brng_set_ctx_params},
    {OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void))brng_settable_ctx_params_callback},
    {OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void))brng_verify_zeroization},
    {0, NULL}};

const OSSL_DISPATCH bee2_brng_hmac_hbelt_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))brng_hmac_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))brng_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))brng_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))brng_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))brng_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))brng_reseed},
    {OSSL_FUNC_RAND_GET_PARAMS, (void (*)(void))brng_get_params},
    {OSSL_FUNC_RAND_GETTABLE_PARAMS, (void (*)(void))brng_gettable_params_callback},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))brng_get_ctx_params},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))brng_gettable_ctx_params_callback},
    {OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))brng_set_ctx_params},
    {OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void))brng_settable_ctx_params_callback},
    {OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void))brng_verify_zeroization},
    {0, NULL}};
