/*
 * brng_rand.c -- OpenSSL 3.x provider: Bee2 BRNG generators
 *
 * Implemented algorithms:
 *   - BRNG-CTR-HBELT  (section 6.2, based on belt-hash)
 *   - BRNG-HMAC-HBELT (section 6.3, based on HMAC[belt-hash])
 */

#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define BRNG_BLOCK_SIZE 32
#define BRNG_STRENGTH_BITS 256U
#define BRNG_IV_PARAM "iv"

typedef enum {
    BRNG_MODE_CTR_HBELT = 1,
    BRNG_MODE_HMAC_HBELT = 2
} brng_mode_t;

typedef struct {
    brng_mode_t mode;
    int state;
    unsigned int strength;
    size_t max_request;
    int instantiated;

    unsigned char *key;
    size_t key_len;
    int have_key;

    unsigned char *iv;
    size_t iv_len;
    int have_iv;

    /* BRNG-CTR-HBELT base: belt-hash(key || ...) */
    belt_hash_ctx_t ctr_key_base;

    /* BRNG-HMAC-HBELT bases: hash((key^ipad) || ...), hash((key^opad) || ...) */
    belt_hash_ctx_t hmac_inner_base;
    belt_hash_ctx_t hmac_outer_base;

    unsigned char s[BRNG_BLOCK_SIZE];
    unsigned char r[BRNG_BLOCK_SIZE];
    unsigned char block[BRNG_BLOCK_SIZE];
    size_t reserved;
} bee2_brng_ctx_t;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void brng_hash_update(belt_hash_ctx ctx, const unsigned char *in, size_t inl) {
    belt_hash_update(ctx, in, inl);
}

static void
brng_hbelt_digest(const unsigned char *in, size_t inl, unsigned char out[BRNG_BLOCK_SIZE]) {
    belt_hash_ctx_t h;
    belt_hash_init(&h);
    if (inl > 0)
        brng_hash_update(&h, in, inl);
    belt_hash_get(&h, out);
    belt_hash_cleanup(&h);
}

static void ctr_block_inc(unsigned char block[BRNG_BLOCK_SIZE]) {
    unsigned int carry = 1;
    size_t i;
    for (i = 0; i < BRNG_BLOCK_SIZE - 1; ++i) {
        unsigned int v = (unsigned int)block[i] + carry;
        block[i] = (unsigned char)v;
        carry = (v >> 8) & 1U;
    }
    block[BRNG_BLOCK_SIZE - 1] = (unsigned char)(block[BRNG_BLOCK_SIZE - 1] + carry);
}

static void brng_hbelt_hmac_bases_init(bee2_brng_ctx_t *c) {
    unsigned char key_block[BRNG_BLOCK_SIZE];
    unsigned char pad[BRNG_BLOCK_SIZE];
    size_t i;

    if (c->key_len <= BRNG_BLOCK_SIZE) {
        OPENSSL_cleanse(key_block, sizeof(key_block));
        if (c->key_len > 0)
            memcpy(key_block, c->key, c->key_len);
    } else {
        brng_hbelt_digest(c->key, c->key_len, key_block);
    }

    for (i = 0; i < BRNG_BLOCK_SIZE; ++i)
        pad[i] = key_block[i] ^ 0x36U;
    belt_hash_init(&c->hmac_inner_base);
    brng_hash_update(&c->hmac_inner_base, pad, BRNG_BLOCK_SIZE);

    for (i = 0; i < BRNG_BLOCK_SIZE; ++i)
        pad[i] = key_block[i] ^ 0x5CU;
    belt_hash_init(&c->hmac_outer_base);
    brng_hash_update(&c->hmac_outer_base, pad, BRNG_BLOCK_SIZE);

    OPENSSL_cleanse(pad, sizeof(pad));
    OPENSSL_cleanse(key_block, sizeof(key_block));
}

static void brng_hbelt_hmac_compute(const bee2_brng_ctx_t *c,
                                    const unsigned char *part1,
                                    size_t part1_len,
                                    const unsigned char *part2,
                                    size_t part2_len,
                                    unsigned char out[BRNG_BLOCK_SIZE]) {
    belt_hash_ctx_t inner = c->hmac_inner_base;
    belt_hash_ctx_t outer = c->hmac_outer_base;
    unsigned char inner_hash[BRNG_BLOCK_SIZE];

    if (part1_len > 0)
        brng_hash_update(&inner, part1, part1_len);
    if (part2_len > 0)
        brng_hash_update(&inner, part2, part2_len);
    belt_hash_get(&inner, inner_hash);
    brng_hash_update(&outer, inner_hash, BRNG_BLOCK_SIZE);
    belt_hash_get(&outer, out);

    belt_hash_cleanup(&inner);
    belt_hash_cleanup(&outer);
    OPENSSL_cleanse(inner_hash, sizeof(inner_hash));
}

static int brng_prepare_ctr(bee2_brng_ctx_t *c) {
    size_t i;

    if (!c->have_key || c->key_len != BRNG_BLOCK_SIZE)
        return 0;

    belt_hash_init(&c->ctr_key_base);
    brng_hash_update(&c->ctr_key_base, c->key, BRNG_BLOCK_SIZE);

    if (c->have_iv && c->iv_len == BRNG_BLOCK_SIZE) {
        memcpy(c->s, c->iv, BRNG_BLOCK_SIZE);
    } else {
        memset(c->s, 0, BRNG_BLOCK_SIZE);
    }

    for (i = 0; i < BRNG_BLOCK_SIZE; ++i)
        c->r[i] = (unsigned char)~c->s[i];
    memset(c->block, 0, sizeof(c->block));
    c->reserved = 0;
    return 1;
}

static int brng_prepare_hmac(bee2_brng_ctx_t *c) {
    static const unsigned char empty_octet = 0;

    if (!c->have_key)
        return 0;

    brng_hbelt_hmac_bases_init(c);
    brng_hbelt_hmac_compute(
        c, c->have_iv ? c->iv : &empty_octet, c->have_iv ? c->iv_len : 0, NULL, 0, c->r);
    memset(c->block, 0, sizeof(c->block));
    c->reserved = 0;
    return 1;
}

static void brng_ctr_make_block(bee2_brng_ctx_t *c,
                                const unsigned char x[BRNG_BLOCK_SIZE],
                                unsigned char y[BRNG_BLOCK_SIZE]) {
    size_t i;
    belt_hash_ctx_t h = c->ctr_key_base;

    brng_hash_update(&h, c->s, BRNG_BLOCK_SIZE);
    brng_hash_update(&h, x, BRNG_BLOCK_SIZE);
    brng_hash_update(&h, c->r, BRNG_BLOCK_SIZE);
    belt_hash_get(&h, y);
    belt_hash_cleanup(&h);

    ctr_block_inc(c->s);
    for (i = 0; i < BRNG_BLOCK_SIZE; ++i)
        c->r[i] ^= y[i];
}

static void brng_generate_ctr(bee2_brng_ctx_t *c,
                              unsigned char *out,
                              size_t outlen,
                              const unsigned char *addin,
                              size_t addin_len) {
    size_t addin_off = 0;

    if (c->reserved > 0) {
        if (c->reserved >= outlen) {
            memcpy(out, c->block + BRNG_BLOCK_SIZE - c->reserved, outlen);
            c->reserved -= outlen;
            return;
        }
        memcpy(out, c->block + BRNG_BLOCK_SIZE - c->reserved, c->reserved);
        out += c->reserved;
        outlen -= c->reserved;
        c->reserved = 0;
    }

    while (outlen >= BRNG_BLOCK_SIZE) {
        unsigned char x[BRNG_BLOCK_SIZE];
        size_t take = 0;

        if (addin && addin_off < addin_len) {
            take = addin_len - addin_off;
            if (take > BRNG_BLOCK_SIZE)
                take = BRNG_BLOCK_SIZE;
            memcpy(x, addin + addin_off, take);
        }
        if (take < BRNG_BLOCK_SIZE)
            memset(x + take, 0, BRNG_BLOCK_SIZE - take);
        addin_off += take;

        brng_ctr_make_block(c, x, out);
        OPENSSL_cleanse(x, sizeof(x));

        out += BRNG_BLOCK_SIZE;
        outlen -= BRNG_BLOCK_SIZE;
    }

    if (outlen > 0) {
        unsigned char x[BRNG_BLOCK_SIZE];
        size_t take = 0;

        if (addin && addin_off < addin_len) {
            take = addin_len - addin_off;
            if (take > outlen)
                take = outlen;
            memcpy(x, addin + addin_off, take);
        }
        if (take < BRNG_BLOCK_SIZE)
            memset(x + take, 0, BRNG_BLOCK_SIZE - take);

        brng_ctr_make_block(c, x, c->block);
        OPENSSL_cleanse(x, sizeof(x));

        memcpy(out, c->block, outlen);
        c->reserved = BRNG_BLOCK_SIZE - outlen;
    }
}

static void brng_generate_hmac(bee2_brng_ctx_t *c, unsigned char *out, size_t outlen) {
    static const unsigned char empty_octet = 0;
    const unsigned char *iv = c->have_iv ? c->iv : &empty_octet;
    const size_t iv_len = c->have_iv ? c->iv_len : 0;

    if (c->reserved > 0) {
        if (c->reserved >= outlen) {
            memcpy(out, c->block + BRNG_BLOCK_SIZE - c->reserved, outlen);
            c->reserved -= outlen;
            return;
        }
        memcpy(out, c->block + BRNG_BLOCK_SIZE - c->reserved, c->reserved);
        out += c->reserved;
        outlen -= c->reserved;
        c->reserved = 0;
    }

    while (outlen >= BRNG_BLOCK_SIZE) {
        unsigned char r_old[BRNG_BLOCK_SIZE];
        unsigned char r_new[BRNG_BLOCK_SIZE];
        memcpy(r_old, c->r, BRNG_BLOCK_SIZE);
        brng_hbelt_hmac_compute(c, r_old, BRNG_BLOCK_SIZE, NULL, 0, r_new);
        brng_hbelt_hmac_compute(c, r_old, BRNG_BLOCK_SIZE, iv, iv_len, out);
        memcpy(c->r, r_new, BRNG_BLOCK_SIZE);
        OPENSSL_cleanse(r_new, sizeof(r_new));
        OPENSSL_cleanse(r_old, sizeof(r_old));
        out += BRNG_BLOCK_SIZE;
        outlen -= BRNG_BLOCK_SIZE;
    }

    if (outlen > 0) {
        unsigned char r_old[BRNG_BLOCK_SIZE];
        unsigned char r_new[BRNG_BLOCK_SIZE];
        memcpy(r_old, c->r, BRNG_BLOCK_SIZE);
        brng_hbelt_hmac_compute(c, r_old, BRNG_BLOCK_SIZE, NULL, 0, r_new);
        brng_hbelt_hmac_compute(c, r_old, BRNG_BLOCK_SIZE, iv, iv_len, c->block);
        memcpy(c->r, r_new, BRNG_BLOCK_SIZE);
        OPENSSL_cleanse(r_new, sizeof(r_new));
        OPENSSL_cleanse(r_old, sizeof(r_old));
        memcpy(out, c->block, outlen);
        c->reserved = BRNG_BLOCK_SIZE - outlen;
    }
}

/* ------------------------------------------------------------------ */
/*  RAND lifecycle                                                     */
/* ------------------------------------------------------------------ */

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
    OPENSSL_cleanse(c, sizeof(*c));
    OPENSSL_clear_free(c, sizeof(*c));
}

/* ------------------------------------------------------------------ */
/*  RAND params                                                        */
/* ------------------------------------------------------------------ */

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
    const unsigned char *iv_ptr;
    size_t iv_len;

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
    if (p) {
        if (c->mode == BRNG_MODE_CTR_HBELT) {
            if (c->instantiated) {
                iv_ptr = c->s;
            } else if (c->have_iv && c->iv_len == BRNG_BLOCK_SIZE) {
                iv_ptr = c->iv;
            } else {
                iv_ptr = zero_iv;
            }
            iv_len = BRNG_BLOCK_SIZE;
        } else {
            iv_ptr = c->have_iv ? c->iv : &empty_octet;
            iv_len = c->have_iv ? c->iv_len : 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, iv_ptr, iv_len))
            return 0;
    }

    return 1;
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
    const OSSL_PARAM *p;
    const void *ptr = NULL;
    size_t len = 0;

    if (!params)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &len))
            return 0;
        if (c->mode == BRNG_MODE_CTR_HBELT && len != BRNG_BLOCK_SIZE)
            return 0;
        if (!bee2_secret_replace(&c->key, &c->key_len, ptr, len))
            return 0;
        c->have_key = 1;
        c->instantiated = 0;
        c->state = EVP_RAND_STATE_UNINITIALISED;
    }

    p = OSSL_PARAM_locate_const(params, BRNG_IV_PARAM);
    if (p) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &ptr, &len))
            return 0;
        if (c->mode == BRNG_MODE_CTR_HBELT && len != BRNG_BLOCK_SIZE)
            return 0;
        if (!bee2_secret_replace(&c->iv, &c->iv_len, ptr, len))
            return 0;
        c->have_iv = 1;
        c->instantiated = 0;
        c->state = EVP_RAND_STATE_UNINITIALISED;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/*  RAND operations                                                    */
/* ------------------------------------------------------------------ */

static int brng_instantiate(void *vctx,
                            unsigned int strength,
                            int prediction_resistance,
                            const unsigned char *pstr,
                            size_t pstr_len,
                            const OSSL_PARAM params[]) {
    static const unsigned char zero_iv[BRNG_BLOCK_SIZE] = {0};
    bee2_brng_ctx_t *c = vctx;

    (void)prediction_resistance;
    (void)pstr;
    (void)pstr_len;

    if (strength > BRNG_STRENGTH_BITS)
        return 0;
    if (!brng_set_ctx_params(vctx, params))
        return 0;

    c->reserved = 0;
    OPENSSL_cleanse(c->block, sizeof(c->block));
    OPENSSL_cleanse(c->s, sizeof(c->s));
    OPENSSL_cleanse(c->r, sizeof(c->r));

    if (c->mode == BRNG_MODE_CTR_HBELT) {
        if (!c->have_key || c->key_len != BRNG_BLOCK_SIZE) {
            c->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
        if (!c->have_iv) {
            if (!bee2_secret_replace(&c->iv, &c->iv_len, zero_iv, BRNG_BLOCK_SIZE)) {
                c->state = EVP_RAND_STATE_ERROR;
                return 0;
            }
            c->have_iv = 1;
        }
        if (!brng_prepare_ctr(c)) {
            c->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
    } else {
        if (!c->have_key) {
            c->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
        if (!brng_prepare_hmac(c)) {
            c->state = EVP_RAND_STATE_ERROR;
            return 0;
        }
    }

    c->instantiated = 1;
    c->state = EVP_RAND_STATE_READY;
    return 1;
}

static int brng_uninstantiate(void *vctx) {
    bee2_brng_ctx_t *c = vctx;

    c->instantiated = 0;
    c->state = EVP_RAND_STATE_UNINITIALISED;
    c->reserved = 0;
    OPENSSL_cleanse(c->block, sizeof(c->block));
    OPENSSL_cleanse(c->s, sizeof(c->s));
    OPENSSL_cleanse(c->r, sizeof(c->r));
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

    (void)prediction_resistance;

    if (!c->instantiated || c->state != EVP_RAND_STATE_READY)
        return 0;
    if (strength > c->strength)
        return 0;
    if (outlen > c->max_request)
        return 0;

    if (c->mode == BRNG_MODE_CTR_HBELT)
        brng_generate_ctr(c, out, outlen, addin, addin_len);
    else
        brng_generate_hmac(c, out, outlen);

    return 1;
}

static int brng_reseed(void *vctx,
                       int prediction_resistance,
                       const unsigned char *ent,
                       size_t ent_len,
                       const unsigned char *addin,
                       size_t addin_len) {
    bee2_brng_ctx_t *c = vctx;

    (void)prediction_resistance;

    if (ent && ent_len > 0) {
        if (c->mode == BRNG_MODE_CTR_HBELT && ent_len != BRNG_BLOCK_SIZE)
            return 0;
        if (!bee2_secret_replace(&c->key, &c->key_len, ent, ent_len))
            return 0;
        c->have_key = 1;
    }
    if (addin && addin_len > 0) {
        if (c->mode == BRNG_MODE_CTR_HBELT && addin_len != BRNG_BLOCK_SIZE)
            return 0;
        if (!bee2_secret_replace(&c->iv, &c->iv_len, addin, addin_len))
            return 0;
        c->have_iv = 1;
    }

    return brng_instantiate(vctx, c->strength, 0, NULL, 0, NULL);
}

static int brng_verify_zeroization(void *vctx) {
    bee2_brng_ctx_t *c = vctx;
    return c->instantiated == 0 && c->reserved == 0;
}

/* ------------------------------------------------------------------ */
/*  Dispatch                                                           */
/* ------------------------------------------------------------------ */

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
