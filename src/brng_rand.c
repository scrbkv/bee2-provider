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
    unsigned int strength;
    size_t ctr_unused;
    int instantiated;
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
    int have_key;
    bee2_backend_state_t backend;
    unsigned char ctr_block[BRNG_BLOCK_SIZE];
} bee2_brng_ctx_t;

static void brng_clear_backend(bee2_brng_ctx_t *c) {
    OPENSSL_cleanse(&c->backend, sizeof(c->backend));
    OPENSSL_cleanse(c->ctr_block, sizeof(c->ctr_block));
    c->ctr_unused = 0;
    c->instantiated = 0;
}

static void *brng_newctx_common(brng_mode_t mode) {
    bee2_brng_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->mode = mode;
    c->strength = BRNG_STRENGTH_BITS;
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
    if (p && !OSSL_PARAM_set_int(p, c->instantiated ? EVP_RAND_STATE_READY
                                                      : EVP_RAND_STATE_UNINITIALISED))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p && !OSSL_PARAM_set_uint(p, c->strength))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p && !OSSL_PARAM_set_size_t(p, SIZE_MAX))
        return 0;
    p = OSSL_PARAM_locate(params, BRNG_IV_PARAM);
    if (!p)
        return 1;

    if (c->mode == BRNG_MODE_CTR_HBELT) {
        if (c->instantiated) {
            brngCTRStepG(live_iv, &c->backend);
            iv_data = live_iv;
        } else {
            iv_data = c->iv ? c->iv : zero_iv;
        }
        iv_len = BRNG_BLOCK_SIZE;
    } else {
        iv_data = c->iv ? c->iv : &empty_octet;
        iv_len = c->iv_len;
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

    if (!params)
        return 1;
    key_param = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    iv_param = OSSL_PARAM_locate_const(params, BRNG_IV_PARAM);
    if (key_param &&
        (!OSSL_PARAM_get_octet_string_ptr(key_param, &key_data, &key_len) ||
         (key_data == NULL && key_len != 0) ||
         (c->mode == BRNG_MODE_CTR_HBELT && key_len != BRNG_BLOCK_SIZE)))
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
    }
    return 1;
}

static int brng_instantiate(void *vctx,
                            unsigned int strength,
                            int prediction_resistance,
                            const unsigned char *pstr,
                            size_t pstr_len,
                            const OSSL_PARAM params[]) {
    static const unsigned char empty_octet = 0;
    bee2_brng_ctx_t *c = vctx;
    unsigned int max_strength;

    (void)pstr;
    /* These deterministic generators cannot source fresh entropy by themselves.
     * Never silently claim prediction resistance or personalization support. */
    /* A failed Instantiate must invalidate the previous generator. */
    brng_clear_backend(c);
    if (prediction_resistance || pstr_len != 0 || !brng_set_ctx_params(vctx, params))
        return 0;
    if (!c->have_key)
        return 0;

    max_strength = c->key_len >= BRNG_BLOCK_SIZE ? BRNG_STRENGTH_BITS
                                                : (unsigned int)(c->key_len * 8u);
    if (strength > max_strength)
        return 0;
    if (c->mode == BRNG_MODE_CTR_HBELT) {
        brngCTRStart(&c->backend, c->key, c->iv);
    } else {
        brngHMACStart(&c->backend,
                      c->key ? c->key : &empty_octet,
                      c->key_len,
                      c->iv ? c->iv : &empty_octet,
                      c->iv_len);
    }
    c->instantiated = 1;
    c->strength = max_strength;
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
    c->have_key = 0;
    c->strength = BRNG_STRENGTH_BITS;
    return 1;
}

static int brng_generate_ctr(bee2_brng_ctx_t *c,
                             unsigned char *out,
                             size_t outlen,
                             const unsigned char *addin,
                             size_t addin_len) {
    unsigned char *additional = NULL;
    size_t input_pos = 0;

    /* Copy additional input before changing BRNG state. It may overlap
     * the output, and an allocation failure must leave the state intact. */
    if (addin_len) {
        additional = OPENSSL_memdup(addin, addin_len);
        if (!additional)
            return 0;
    }

    /* A new X must apply to a new BRNG block. Bee2 otherwise returns
     * previously reserved bytes without reading the caller's X. */
    if (addin_len != 0)
        c->ctr_unused = 0;
    while (outlen != 0) {
        size_t chunk;

        if (c->ctr_unused == 0) {
            size_t input = addin_len - input_pos;

            if (input > BRNG_BLOCK_SIZE)
                input = BRNG_BLOCK_SIZE;
            memset(c->ctr_block, 0, BRNG_BLOCK_SIZE);
            if (input != 0)
                memcpy(c->ctr_block, additional + input_pos, input);
            input_pos += input;
            brngCTRStepR(c->ctr_block, BRNG_BLOCK_SIZE, &c->backend);
            c->ctr_unused = BRNG_BLOCK_SIZE;
        }
        chunk = outlen < c->ctr_unused ? outlen : c->ctr_unused;
        memcpy(out, c->ctr_block + BRNG_BLOCK_SIZE - c->ctr_unused, chunk);
        c->ctr_unused -= chunk;
        out += chunk;
        outlen -= chunk;
    }
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

    if (!c->instantiated || strength > c->strength ||
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
    /* STB 34.101.47 assigns a complete X block to each new Y block. */
    if (addin_len != 0 && (outlen == 0 ||
        (addin_len - 1) / BRNG_BLOCK_SIZE > (outlen - 1) / BRNG_BLOCK_SIZE))
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
    return !c->instantiated && !c->have_key && !c->key && !c->iv &&
           memIsZero(&c->backend, sizeof(c->backend)) &&
           memIsZero(c->ctr_block, sizeof(c->ctr_block));
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
