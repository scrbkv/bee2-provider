/*
 * belt_kwp.c — OpenSSL 3.x provider: BELT-KWP key wrapping (STB 34.101.31)
 *
 * BELT-KWP wraps (encrypts + authenticates) key material using the BELT
 * wide-block cipher.  The algorithm appends a 16-byte authentication header
 * to the plaintext before encrypting the combined block with belt-wblock.
 *
 *   Key     : 16/24/32 bytes (128/192/256-bit)
 *   Header  : 16 bytes — initial authentication vector, passed as the IV
 *             parameter; defaults to all-zeros when not supplied
 *
 * Lengths:
 *   Plaintext  (encrypt input)  : n × 16 bytes  (n ≥ 1, n ≤ 32)
 *   Ciphertext (encrypt output) : (n + 1) × 16 bytes
 *   Ciphertext (decrypt input)  : (n + 1) × 16 bytes
 *   Plaintext  (decrypt output) : n × 16 bytes
 *
 * Decryption verifies the recovered header against the initial header (IV).
 * A mismatch is treated as an authentication failure and returns 0.
 *
 * Because belt-wblock requires all data at once, one non-empty update is one
 * complete wrap or unwrap operation. A second update is rejected.
 *
 * OID (STB 34.101.31): 1.2.112.0.2.0.34.101.31.73
 */

#include "bee2_backend.h"
#include "provider.h"

#include <openssl/crypto.h>

/* KWP header size equals one BELT block (16 bytes). */
#define BELT_KWP_HDR_SIZE BELT_IV_SIZE

/* Maximum plaintext blocks (library tmp buffer = 33 blocks). */
#define BELT_KWP_MAX_BLOCKS 32u

/* Default initial authentication header (H₀) — all-zeros. */
static const octet belt_kwp_default_header[BELT_KWP_HDR_SIZE];

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    int enc;
    int key_set;
    int processed;
    size_t fixed_key_len; /* key length selected by algorithm name */

    octet key[BELT_KEY_SIZE];     /* expanded 256-bit key                 */
    octet hdr[BELT_KWP_HDR_SIZE]; /* initial authentication header (H₀)   */

} bee2_belt_kwp_ctx_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *belt_kwp_newctx_with_key_length(void *provctx, size_t key_len) {
    (void)provctx;
    bee2_belt_kwp_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->fixed_key_len = key_len;
    memcpy(c->hdr, belt_kwp_default_header, BELT_KWP_HDR_SIZE);
    return c;
}

static void *belt_kwp128_newctx(void *p) {
    return belt_kwp_newctx_with_key_length(p, 16);
}
static void *belt_kwp192_newctx(void *p) {
    return belt_kwp_newctx_with_key_length(p, 24);
}
static void *belt_kwp256_newctx(void *p) {
    return belt_kwp_newctx_with_key_length(p, 32);
}

static void belt_kwp_freectx(void *vctx) {
    bee2_belt_kwp_ctx_t *c = vctx;
    if (!c)
        return;
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *belt_kwp_dupctx(void *vctx) {
    bee2_belt_kwp_ctx_t *src = vctx;
    bee2_belt_kwp_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Init                                                                */
/* ------------------------------------------------------------------ */

static int belt_kwp_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int belt_kwp_init_operation(void *vctx,
                                   const unsigned char *key,
                                   size_t keylen,
                                   const unsigned char *iv,
                                   size_t ivlen,
                                   int enc,
                                   const OSSL_PARAM params[]) {
    bee2_belt_kwp_ctx_t *c = vctx;
    c->enc = enc;
    c->processed = 0;

    if (params && !belt_kwp_set_ctx_params(c, params))
        return 0;

    if (key != NULL) {
        if (keylen != c->fixed_key_len)
            return 0;
        bee2_belt_expand_key(key, keylen, c->key);
        c->key_set = 1;
    }

    if (iv != NULL) {
        if (ivlen != BELT_KWP_HDR_SIZE)
            return 0;
        memcpy(c->hdr, iv, BELT_KWP_HDR_SIZE);
    }

    return 1;
}

static int belt_kwp_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keylen,
                                 const unsigned char *iv,
                                 size_t ivlen,
                                 const OSSL_PARAM params[]) {
    return belt_kwp_init_operation(vctx, key, keylen, iv, ivlen, 1, params);
}

static int belt_kwp_decrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keylen,
                                 const unsigned char *iv,
                                 size_t ivlen,
                                 const OSSL_PARAM params[]) {
    return belt_kwp_init_operation(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ------------------------------------------------------------------ */
/*  Update — process one complete wrap / unwrap operation             */
/* ------------------------------------------------------------------ */

static int belt_kwp_update(void *vctx,
                           unsigned char *out,
                           size_t *outl,
                           size_t outsize,
                           const unsigned char *in,
                           size_t inl) {
    bee2_belt_kwp_ctx_t *c = vctx;
    size_t blocks;
    size_t result_len;

    *outl = 0;
    if (inl == 0)
        return 1;
    if (!c->key_set || c->processed || !out || inl % BELT_BLOCK_SIZE != 0)
        return 0;

    blocks = inl / BELT_BLOCK_SIZE;
    if (c->enc) {
        result_len = inl + BELT_KWP_HDR_SIZE;
        if (blocks > BELT_KWP_MAX_BLOCKS || outsize < result_len)
            return 0;
        if (beltKWPWrap(out, in, inl, c->hdr, c->key, BELT_KEY_SIZE) != ERR_OK)
            return 0;
    } else {
        if (blocks < 2 || blocks > BELT_KWP_MAX_BLOCKS + 1)
            return 0;
        result_len = inl - BELT_KWP_HDR_SIZE;
        if (outsize < result_len)
            return 0;
        if (beltKWPUnwrap(out, in, inl, c->hdr, c->key, BELT_KEY_SIZE) != ERR_OK) {
            OPENSSL_cleanse(out, result_len);
            return 0;
        }
    }

    c->processed = 1;
    *outl = result_len;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Final — validate that an operation was processed                   */
/* ------------------------------------------------------------------ */

static int belt_kwp_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    const bee2_belt_kwp_ctx_t *c = vctx;
    (void)out;
    (void)outsize;
    *outl = 0;
    return c->key_set && c->processed;
}

/* ------------------------------------------------------------------ */
/*  One-shot cipher                                                     */
/* ------------------------------------------------------------------ */

static int belt_kwp_cipher(void *vctx,
                           unsigned char *out,
                           size_t *outl,
                           size_t outsize,
                           const unsigned char *in,
                           size_t inl) {
    size_t upd = 0, fin = 0;
    if (!belt_kwp_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!belt_kwp_final(vctx, out + upd, &fin, outsize - upd))
        return 0;
    *outl = upd + fin;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters (static)                                       */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_kwp_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_kwp_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_kwp_gettable_params;
}

static int belt_kwp_get_params_len(OSSL_PARAM params[], size_t key_len) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, key_len))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_KWP_HDR_SIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_BLOCK_SIZE))
        return 0;
    return 1;
}

static int belt_kwp128_get_params(OSSL_PARAM p[]) {
    return belt_kwp_get_params_len(p, 16);
}
static int belt_kwp192_get_params(OSSL_PARAM p[]) {
    return belt_kwp_get_params_len(p, 24);
}
static int belt_kwp256_get_params(OSSL_PARAM p[]) {
    return belt_kwp_get_params_len(p, 32);
}

/* ------------------------------------------------------------------ */
/*  Context parameters                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_kwp_ctx_gettable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_kwp_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL), OSSL_PARAM_END};

static const OSSL_PARAM *belt_kwp_gettable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_kwp_ctx_gettable;
}

static const OSSL_PARAM *belt_kwp_settable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_kwp_ctx_settable;
}

static int belt_kwp_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_belt_kwp_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->fixed_key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_KWP_HDR_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && !OSSL_PARAM_set_octet_string(p, c->hdr, BELT_KWP_HDR_SIZE))
        return 0;

    return 1;
}

static int belt_kwp_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_kwp_ctx_t *c = vctx;
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
/*  Dispatch table                                                      */
/* ------------------------------------------------------------------ */

#define BELT_KWP_DISPATCH(NAME, NEWCTX, GET_PARAMS)                                                \
    const OSSL_DISPATCH NAME[] = {                                                                 \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))NEWCTX},                                         \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))belt_kwp_freectx},                              \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))belt_kwp_dupctx},                                \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))belt_kwp_encrypt_init},                    \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))belt_kwp_decrypt_init},                    \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))belt_kwp_update},                                \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))belt_kwp_final},                                  \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))belt_kwp_cipher},                                \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))GET_PARAMS},                                 \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))belt_kwp_gettable_params},              \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))belt_kwp_get_ctx_params},                \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))belt_kwp_gettable_ctx_params},      \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))belt_kwp_set_ctx_params},                \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))belt_kwp_settable_ctx_params},      \
        {0, NULL}}

BELT_KWP_DISPATCH(bee2_belt_kwp128_functions, belt_kwp128_newctx, belt_kwp128_get_params);
BELT_KWP_DISPATCH(bee2_belt_kwp192_functions, belt_kwp192_newctx, belt_kwp192_get_params);
BELT_KWP_DISPATCH(bee2_belt_kwp256_functions, belt_kwp256_newctx, belt_kwp256_get_params);
