/*
 * belt_sde.c — OpenSSL 3.x provider: BELT-SDE sector encryption (STB 34.101.31)
 *
 * BELT-SDE (Sector Disk Encryption) is a wide-block sector cipher built on
 * belt-wblock.  The construction is:
 *
 *   Encrypt: C = T ⊕ belt-wblock(T ⊕ P)   where T = belt(K, IV) ⊕ first block
 *   (XOR with T applies to the first 16 bytes only; wblock covers all n blocks)
 *
 * Parameters:
 *   Key    : 16/24/32 bytes (128/192/256-bit)
 *   IV     : 16 bytes (sector tweak)
 *   Input  : n × 16 bytes  (n ≥ 1, no upper limit)
 *   Output : n × 16 bytes  (same size as input)
 *
 * Because belt-wblock is a one-shot wide-block cipher, one non-empty update
 * represents one complete sector. A second update is rejected. The output
 * length always equals the input length.
 *
 * OID (STB 34.101.31): 1.2.112.0.2.0.34.101.31.26
 */

#include "bee2_backend.h"
#include "provider.h"

#include <openssl/crypto.h>

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    belt_sde_ctx_t backend_state;

    int enc;
    int processed;
    size_t fixed_key_len; /* wrapper-fixed key length (16/24/32) */
} bee2_belt_sde_ctx_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *belt_sde_newctx(void *provctx, size_t fixed_key_len) {
    (void)provctx;
    bee2_belt_sde_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->fixed_key_len = fixed_key_len;
    belt_sde_init(&c->backend_state);
    return c;
}

#define BELT_SDE_NEWCTX(KEYBITS) \
    static void *belt_##KEYBITS##_sde_newctx(void *p) { \
        return belt_sde_newctx(p, (KEYBITS) / 8); \
    }

BELT_SDE_NEWCTX(128)
BELT_SDE_NEWCTX(192)
BELT_SDE_NEWCTX(256)

static void belt_sde_freectx(void *vctx) {
    bee2_belt_sde_ctx_t *c = vctx;
    if (!c)
        return;
    belt_sde_cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *belt_sde_dupctx(void *vctx) {
    bee2_belt_sde_ctx_t *src = vctx;
    bee2_belt_sde_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Init                                                                */
/* ------------------------------------------------------------------ */

static int belt_sde_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int belt_sde_init_operation(void *vctx,
                                   const unsigned char *key,
                                   size_t keylen,
                                   const unsigned char *iv,
                                   size_t ivlen,
                                   int enc,
                                   const OSSL_PARAM params[]) {
    bee2_belt_sde_ctx_t *c = vctx;
    c->enc = enc;
    c->processed = 0;

    if (params && !belt_sde_set_ctx_params(c, params))
        return 0;

    if (key != NULL) {
        if (keylen != c->fixed_key_len)
            return 0;
        belt_sde_set_key(&c->backend_state, key, keylen);
    }

    if (iv != NULL) {
        if (ivlen != BELT_IV_SIZE)
            return 0;
        belt_sde_set_iv(&c->backend_state, iv, ivlen);
    }

    belt_sde_restart(&c->backend_state);
    return 1;
}

static int belt_sde_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keylen,
                                 const unsigned char *iv,
                                 size_t ivlen,
                                 const OSSL_PARAM params[]) {
    return belt_sde_init_operation(vctx, key, keylen, iv, ivlen, 1, params);
}

static int belt_sde_decrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keylen,
                                 const unsigned char *iv,
                                 size_t ivlen,
                                 const OSSL_PARAM params[]) {
    return belt_sde_init_operation(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ------------------------------------------------------------------ */
/*  Update — process one complete sector                              */
/* ------------------------------------------------------------------ */

static int belt_sde_update(void *vctx,
                           unsigned char *out,
                           size_t *outl,
                           size_t outsize,
                           const unsigned char *in,
                           size_t inl) {
    bee2_belt_sde_ctx_t *c = vctx;
    *outl = 0;
    if (inl == 0)
        return 1;
    if (!c->backend_state.key_set || !c->backend_state.iv_set || c->processed || !out ||
        inl % BELT_BLOCK_SIZE != 0 || outsize < inl)
        return 0;

    if (c->enc)
        belt_sde_encrypt(&c->backend_state, in, inl / BELT_BLOCK_SIZE, out);
    else
        belt_sde_decrypt(&c->backend_state, in, inl / BELT_BLOCK_SIZE, out);

    c->processed = 1;
    *outl = inl;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Final — validate that a sector was processed                       */
/* ------------------------------------------------------------------ */

static int belt_sde_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    const bee2_belt_sde_ctx_t *c = vctx;
    (void)out;
    (void)outsize;
    *outl = 0;
    return c->backend_state.key_set && c->backend_state.iv_set && c->processed;
}

/* ------------------------------------------------------------------ */
/*  One-shot cipher                                                     */
/* ------------------------------------------------------------------ */

static int belt_sde_cipher(void *vctx,
                           unsigned char *out,
                           size_t *outl,
                           size_t outsize,
                           const unsigned char *in,
                           size_t inl) {
    size_t upd = 0, fin = 0;
    if (!belt_sde_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!belt_sde_final(vctx, out + upd, &fin, outsize - upd))
        return 0;
    *outl = upd + fin;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters (static)                                       */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_sde_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_sde_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_sde_gettable_params;
}

static int belt_sde_get_params_impl(OSSL_PARAM params[], size_t keylen) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_IV_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_BLOCK_SIZE))
        return 0;
    return 1;
}

#define BELT_SDE_GET_PARAMS(KEYBITS) \
    static int belt_##KEYBITS##_sde_get_params(OSSL_PARAM p[]) { \
        return belt_sde_get_params_impl(p, (KEYBITS) / 8); \
    }

BELT_SDE_GET_PARAMS(128)
BELT_SDE_GET_PARAMS(192)
BELT_SDE_GET_PARAMS(256)

/* ------------------------------------------------------------------ */
/*  Context parameters                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_sde_ctx_gettable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_sde_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL), OSSL_PARAM_END};

static const OSSL_PARAM *belt_sde_gettable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_sde_ctx_gettable;
}

static const OSSL_PARAM *belt_sde_settable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_sde_ctx_settable;
}

static int belt_sde_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_belt_sde_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->fixed_key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && c->backend_state.iv_set &&
        !OSSL_PARAM_set_octet_string(p, c->backend_state.iv, BELT_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p && c->backend_state.iv_set &&
        !OSSL_PARAM_set_octet_string(p, c->backend_state.iv, BELT_IV_SIZE))
        return 0;

    return 1;
}

static int belt_sde_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_sde_ctx_t *c = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t klen;
        if (!OSSL_PARAM_get_size_t(p, &klen))
            return 0;
        if (klen != c->fixed_key_len)
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dispatch tables                                                     */
/* ------------------------------------------------------------------ */

#define BELT_SDE_DISPATCH(KEYBITS) \
    const OSSL_DISPATCH bee2_belt_##KEYBITS##_sde_functions[] = { \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))belt_##KEYBITS##_sde_newctx}, \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))belt_sde_freectx}, \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))belt_sde_dupctx}, \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))belt_sde_encrypt_init}, \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))belt_sde_decrypt_init}, \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))belt_sde_update}, \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))belt_sde_final}, \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))belt_sde_cipher}, \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))belt_##KEYBITS##_sde_get_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))belt_sde_gettable_params}, \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))belt_sde_get_ctx_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))belt_sde_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))belt_sde_set_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))belt_sde_settable_ctx_params}, \
        {0, NULL}}

BELT_SDE_DISPATCH(128);
BELT_SDE_DISPATCH(192);
BELT_SDE_DISPATCH(256);
