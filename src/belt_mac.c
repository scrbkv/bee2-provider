/*
 * belt_mac.c — OpenSSL 3.x provider: BELT-MAC (STB 34.101.31)
 *
 * BELT-MAC is a CBC-MAC variant built on the BELT block cipher.
 *   Key   : 32 bytes (256-bit)
 *   Output:  8 bytes (64-bit)
 *
 * OID: 1.2.112.0.2.0.34.101.31.53
 *
 * NOTE: All provider-side functions are prefixed with provider_belt_mac_ to
 * avoid name collisions with the provider-local Bee2 adapter functions
 * (belt_mac_init, belt_mac_update, etc.).
 */

#include "bee2_backend.h"
#include "provider.h"

#define BELT_MAC_OUTPUT_SIZE BELT_MAC_SIZE /* 8 bytes */

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/*                                                                      */
/*  The Bee2 adapter retains the expanded key needed for reset.        */
/* ------------------------------------------------------------------ */

typedef struct {
    belt_mac_ctx_t backend_state;
    size_t fixed_key_len;
} bee2_belt_mac_ctx_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *provider_belt_mac_newctx_with_key_length(void *provctx, size_t key_len) {
    (void)provctx;
    bee2_belt_mac_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->fixed_key_len = key_len;
    belt_mac_init(&c->backend_state);
    return c;
}

static void *provider_belt_mac128_newctx(void *p) {
    return provider_belt_mac_newctx_with_key_length(p, 16);
}
static void *provider_belt_mac192_newctx(void *p) {
    return provider_belt_mac_newctx_with_key_length(p, 24);
}
static void *provider_belt_mac256_newctx(void *p) {
    return provider_belt_mac_newctx_with_key_length(p, 32);
}

static void provider_belt_mac_freectx(void *vctx) {
    bee2_belt_mac_ctx_t *c = vctx;
    if (!c)
        return;
    belt_mac_cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *provider_belt_mac_dupctx(void *vctx) {
    bee2_belt_mac_ctx_t *src = vctx;
    bee2_belt_mac_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  MAC operations                                                      */
/* ------------------------------------------------------------------ */

static int provider_belt_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/*
 * provider_belt_mac_init — resets the MAC and optionally installs a new key.
 * If no key is supplied, the previously stored key is reused.
 */
static int provider_belt_mac_init(void *vctx,
                                  const unsigned char *key,
                                  size_t keylen,
                                  const OSSL_PARAM params[]) {
    bee2_belt_mac_ctx_t *c = vctx;

    if (key != NULL) {
        if (keylen != c->fixed_key_len)
            return 0;
        belt_mac_set_key(&c->backend_state, key, keylen);
    }

    if (params && !provider_belt_mac_set_ctx_params(c, params))
        return 0;

    if (!c->backend_state.key_set) {
        return 0; /* no key available yet */
    }

    belt_mac_restart(&c->backend_state);
    return 1;
}

static int provider_belt_mac_update(void *vctx, const unsigned char *in, size_t inl) {
    bee2_belt_mac_ctx_t *c = vctx;
    if (inl == 0)
        return 1;
    belt_mac_update(&c->backend_state, in, inl);
    return 1;
}

static int provider_belt_mac_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    bee2_belt_mac_ctx_t *c = vctx;
    if (outsize < BELT_MAC_OUTPUT_SIZE)
        return 0;
    belt_mac_get(&c->backend_state, out);
    *outl = BELT_MAC_OUTPUT_SIZE;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters                                                */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_bmac_gettable_params[] = {OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
                                                       OSSL_PARAM_END};

static const OSSL_PARAM *provider_belt_mac_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_bmac_gettable_params;
}

static int provider_belt_mac_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_MAC_OUTPUT_SIZE))
        return 0;
    return 1;
}

static const OSSL_PARAM bee2_bmac_ctx_gettable[] = {OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
                                                    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bmac_ctx_settable[] = {
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0), OSSL_PARAM_END};

static const OSSL_PARAM *provider_belt_mac_gettable_ctx_params(void *mctx, void *pctx) {
    (void)mctx;
    (void)pctx;
    return bee2_bmac_ctx_gettable;
}

static const OSSL_PARAM *provider_belt_mac_settable_ctx_params(void *mctx, void *pctx) {
    (void)mctx;
    (void)pctx;
    return bee2_bmac_ctx_settable;
}

static int provider_belt_mac_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    (void)vctx;
    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_MAC_OUTPUT_SIZE))
        return 0;
    return 1;
}

static int provider_belt_mac_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_mac_ctx_t *c = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
    if (p != NULL) {
        const void *key = NULL;
        size_t key_len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &key, &key_len))
            return 0;
        if (key_len != c->fixed_key_len)
            return 0;
        belt_mac_set_key(&c->backend_state, key, key_len);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dispatch table                                                      */
/* ------------------------------------------------------------------ */

#define BELT_MAC_DISPATCH(NAME, NEWCTX)                                                            \
    const OSSL_DISPATCH NAME[] = {                                                                 \
        {OSSL_FUNC_MAC_NEWCTX, (void (*)(void))NEWCTX},                                            \
        {OSSL_FUNC_MAC_FREECTX, (void (*)(void))provider_belt_mac_freectx},                        \
        {OSSL_FUNC_MAC_DUPCTX, (void (*)(void))provider_belt_mac_dupctx},                          \
        {OSSL_FUNC_MAC_INIT, (void (*)(void))provider_belt_mac_init},                              \
        {OSSL_FUNC_MAC_UPDATE, (void (*)(void))provider_belt_mac_update},                          \
        {OSSL_FUNC_MAC_FINAL, (void (*)(void))provider_belt_mac_final},                            \
        {OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))provider_belt_mac_get_params},                  \
        {OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))provider_belt_mac_gettable_params},        \
        {OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))provider_belt_mac_get_ctx_params},          \
        {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,                                                        \
         (void (*)(void))provider_belt_mac_gettable_ctx_params},                                   \
        {OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))provider_belt_mac_set_ctx_params},          \
        {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,                                                        \
         (void (*)(void))provider_belt_mac_settable_ctx_params},                                   \
        {0, NULL}}

BELT_MAC_DISPATCH(bee2_belt_mac128_functions, provider_belt_mac128_newctx);
BELT_MAC_DISPATCH(bee2_belt_mac192_functions, provider_belt_mac192_newctx);
BELT_MAC_DISPATCH(bee2_belt_mac256_functions, provider_belt_mac256_newctx);
