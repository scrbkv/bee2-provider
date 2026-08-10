/*
 * belt_digest.c — OpenSSL 3.x provider: BELT-Hash digest (STB 34.101.31)
 *
 * BELT-Hash is a compression-function–based hash built on the BELT block
 * cipher. It produces a 256-bit (32-byte) digest.
 *
 * OID: 1.2.112.0.2.0.34.101.31.81
 */

#include "bee2_backend.h"
#include "provider.h"

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *provider_belt_hash_newctx(void *provctx) {
    (void)provctx;
    belt_hash_ctx_t *state = OPENSSL_malloc(sizeof(*state));
    if (!state)
        return NULL;
    belt_hash_init(state);
    return state;
}

static void provider_belt_hash_freectx(void *vctx) {
    belt_hash_ctx_t *state = vctx;
    if (!state)
        return;
    belt_hash_cleanup(state);
    OPENSSL_clear_free(state, sizeof(*state));
}

static void *provider_belt_hash_dupctx(void *vctx) {
    const belt_hash_ctx_t *src = vctx;
    belt_hash_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Hash operations                                                     */
/* ------------------------------------------------------------------ */

static int provider_belt_hash_init(void *vctx, const OSSL_PARAM params[]) {
    belt_hash_ctx_t *state = vctx;
    (void)params;
    belt_hash_init(state);
    return 1;
}

static int provider_belt_hash_update(void *vctx, const unsigned char *in, size_t inl) {
    belt_hash_ctx_t *state = vctx;
    if (inl == 0)
        return 1;
    belt_hash_update(state, in, inl);
    return 1;
}

static int provider_belt_hash_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz) {
    belt_hash_ctx_t *state = vctx;
    if (outsz < BELT_HASH_DIGEST_SIZE)
        return 0;
    belt_hash_get(state, out);
    *outl = BELT_HASH_DIGEST_SIZE;
    return 1;
}

/* One-shot: init + update + final. */
static int provider_belt_hash_digest(void *provctx,
                                     const unsigned char *in,
                                     size_t inl,
                                     unsigned char *out,
                                     size_t *outl,
                                     size_t outsz) {
    (void)provctx;
    if (outsz < BELT_HASH_DIGEST_SIZE)
        return 0;
    if (beltHash(out, in, inl) != ERR_OK)
        return 0;
    *outl = BELT_HASH_DIGEST_SIZE;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters                                                */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_belt_hash_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *provider_belt_hash_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_belt_hash_gettable_params;
}

static int provider_belt_hash_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_HASH_DIGEST_SIZE))
        return 0;

    /* BELT-Hash processes data in 32-byte (256-bit) blocks internally. */
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, 32))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p && !OSSL_PARAM_set_int(p, 0))
        return 0;

    return 1;
}

static const OSSL_PARAM bee2_belt_hash_ctx_gettable[] = {OSSL_PARAM_END};

static const OSSL_PARAM *provider_belt_hash_gettable_ctx_params(void *dctx, void *pctx) {
    (void)dctx;
    (void)pctx;
    return bee2_belt_hash_ctx_gettable;
}

static int provider_belt_hash_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    (void)vctx;
    (void)params;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dispatch table                                                      */
/* ------------------------------------------------------------------ */

const OSSL_DISPATCH bee2_belt_hash_functions[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))provider_belt_hash_newctx},
    {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))provider_belt_hash_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))provider_belt_hash_dupctx},
    {OSSL_FUNC_DIGEST_INIT, (void (*)(void))provider_belt_hash_init},
    {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))provider_belt_hash_update},
    {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))provider_belt_hash_final},
    {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))provider_belt_hash_digest},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))provider_belt_hash_get_params},
    {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))provider_belt_hash_gettable_params},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))provider_belt_hash_get_ctx_params},
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))provider_belt_hash_gettable_ctx_params},
    {0, NULL}};
