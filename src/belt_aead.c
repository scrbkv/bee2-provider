/*
 * belt_aead.c — OpenSSL 3.x provider: BELT AEAD modes (STB 34.101.31)
 *
 * Two authenticated-encryption-with-associated-data (AEAD) modes,
 * both built on the BELT block cipher:
 *
 *   BELT-CHE — Confidentiality + Hashing Extension (CTR + GMAC)
 *   BELT-DWP — Duplex Working Procedure (CTR + GMAC, extended construction)
 *
 * Parameters (identical for both modes):
 *   Key  : 16/24/32 bytes (128/192/256-bit)
 *   IV   : 16 bytes (128-bit)
 *   Tag  :  8 bytes (64-bit)  — BELT-GMAC output
 *
 * OpenSSL AEAD usage:
 *   Encrypt: init → update(NULL,aad) → update(out,pt) → final
 *            → get_ctx_params(AEAD_TAG) to retrieve tag
 *   Decrypt: init → update(NULL,aad) → update(out,ct)
 *            → set_ctx_params(AEAD_TAG) → final (verifies tag)
 *
 * OIDs (STB 34.101.31):
 *   CHE  1.2.112.0.2.0.34.101.31.66
 *   DWP  1.2.112.0.2.0.34.101.31.63
 */

#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/crypto.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define BELT_AEAD_TAG_SIZE BELT_MAC_SIZE /* 8 bytes */

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef void (*belt_aead_init_fn)(bee2_belt_mode_ctx_t *context);
typedef void (*belt_aead_restart_fn)(bee2_belt_mode_ctx_t *context);
typedef void (*belt_aead_set_key_fn)(bee2_belt_mode_ctx_t *context,
                                     const void *key,
                                     size_t key_length);
typedef void (*belt_aead_set_iv_fn)(bee2_belt_mode_ctx_t *context,
                                    const void *iv,
                                    size_t iv_length);
typedef void (*belt_aead_update_ad_fn)(bee2_belt_mode_ctx_t *context,
                                       const void *input,
                                       size_t length);
typedef void (*belt_aead_crypt_fn)(bee2_belt_mode_ctx_t *context,
                                   const void *input,
                                   size_t length,
                                   void *output);
typedef void (*belt_aead_get_tag_fn)(bee2_belt_mode_ctx_t *context, void *tag);
typedef void (*belt_aead_cleanup_fn)(bee2_belt_mode_ctx_t *context);

typedef struct {
    belt_aead_init_fn init;
    belt_aead_restart_fn restart;
    belt_aead_set_key_fn set_key;
    belt_aead_set_iv_fn set_iv;
    belt_aead_update_ad_fn update_ad;
    belt_aead_crypt_fn encrypt;
    belt_aead_crypt_fn decrypt;
    belt_aead_get_tag_fn get_tag;
    belt_aead_cleanup_fn cleanup;
} belt_aead_descriptor_t;

#define BELT_AEAD_DESCRIPTOR(NAME, PREFIX)                                                         \
    static const belt_aead_descriptor_t NAME = {PREFIX##_init,                                     \
                                                PREFIX##_restart,                                  \
                                                PREFIX##_set_key,                                  \
                                                PREFIX##_set_iv,                                   \
                                                PREFIX##_update_ad,                                \
                                                PREFIX##_encrypt,                                  \
                                                PREFIX##_decrypt,                                  \
                                                PREFIX##_get_mac,                                  \
                                                PREFIX##_cleanup}

BELT_AEAD_DESCRIPTOR(belt_che_descriptor, belt_che);
BELT_AEAD_DESCRIPTOR(belt_dwp_descriptor, belt_dwp);

typedef struct {
    bee2_belt_mode_ctx_t backend_state;
    const belt_aead_descriptor_t *algorithm;
    int enc;              /* 1 = encrypt, 0 = decrypt */
    int data_started;     /* set when first non-AAD update is processed  */
    size_t fixed_key_len; /* wrapper-fixed key length (16/24/32 bytes) */

    octet tag[BELT_AEAD_TAG_SIZE]; /* computed (enc) or expected (dec) */
    int tag_set;                   /* tag ready for get / compare      */
} bee2_belt_aead_ctx_t;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void belt_aead_reinitialize(bee2_belt_aead_ctx_t *c) {
    c->data_started = 0;
    c->tag_set = 0;
    memset(c->tag, 0, BELT_AEAD_TAG_SIZE);

    c->algorithm->restart(&c->backend_state);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *belt_aead_newctx_for_algorithm(void *provctx,
                                            const belt_aead_descriptor_t *algorithm,
                                            size_t fixed_key_len) {
    (void)provctx;
    bee2_belt_aead_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->algorithm = algorithm;
    c->fixed_key_len = fixed_key_len;
    c->algorithm->init(&c->backend_state);
    return c;
}

#define BELT_AEAD_NEWCTX(KEYBITS, MODE_LC, DESCRIPTOR)                                             \
    static void *belt_##KEYBITS##_##MODE_LC##_newctx(void *p) {                                    \
        return belt_aead_newctx_for_algorithm(p, &(DESCRIPTOR), (KEYBITS) / 8u);                   \
    }

BELT_AEAD_NEWCTX(128, che, belt_che_descriptor)
BELT_AEAD_NEWCTX(192, che, belt_che_descriptor)
BELT_AEAD_NEWCTX(256, che, belt_che_descriptor)
BELT_AEAD_NEWCTX(128, dwp, belt_dwp_descriptor)
BELT_AEAD_NEWCTX(192, dwp, belt_dwp_descriptor)
BELT_AEAD_NEWCTX(256, dwp, belt_dwp_descriptor)

static void belt_aead_freectx(void *vctx) {
    bee2_belt_aead_ctx_t *c = vctx;
    if (!c)
        return;
    c->algorithm->cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *belt_aead_dupctx(void *vctx) {
    bee2_belt_aead_ctx_t *src = vctx;
    bee2_belt_aead_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Init                                                                */
/* ------------------------------------------------------------------ */

static int belt_aead_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int belt_aead_init(void *vctx,
                          const unsigned char *key,
                          size_t keylen,
                          const unsigned char *iv,
                          size_t ivlen,
                          int enc,
                          const OSSL_PARAM params[]) {
    bee2_belt_aead_ctx_t *c = vctx;
    c->enc = enc;

    if (key != NULL) {
        if (keylen != c->fixed_key_len)
            return 0;
        c->algorithm->set_key(&c->backend_state, key, keylen);
    }

    if (iv != NULL) {
        if (ivlen != BELT_IV_SIZE)
            return 0;
        c->algorithm->set_iv(&c->backend_state, iv, ivlen);
    }

    if (c->backend_state.key_set)
        belt_aead_reinitialize(c);

    return !params || belt_aead_set_ctx_params(c, params);
}

static int belt_aead_encrypt_init(void *vctx,
                                  const unsigned char *key,
                                  size_t keylen,
                                  const unsigned char *iv,
                                  size_t ivlen,
                                  const OSSL_PARAM params[]) {
    return belt_aead_init(vctx, key, keylen, iv, ivlen, 1, params);
}

static int belt_aead_decrypt_init(void *vctx,
                                  const unsigned char *key,
                                  size_t keylen,
                                  const unsigned char *iv,
                                  size_t ivlen,
                                  const OSSL_PARAM params[]) {
    return belt_aead_init(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ------------------------------------------------------------------ */
/*  Update                                                              */
/*                                                                      */
/*  out == NULL  →  process as AAD (additional authenticated data)      */
/*  out != NULL  →  encrypt or decrypt the plaintext/ciphertext         */
/* ------------------------------------------------------------------ */

static int belt_aead_update(void *vctx,
                            unsigned char *out,
                            size_t *outl,
                            size_t outsize,
                            const unsigned char *in,
                            size_t inl) {
    bee2_belt_aead_ctx_t *c = vctx;
    *outl = 0;

    if (!c->backend_state.key_set || !c->backend_state.iv_set)
        return 0;

    if (inl == 0)
        return 1;

    if (out == NULL) {
        /* ---- AAD ------------------------------------------------- */
        if (c->data_started)
            return 0; /* cannot add AAD after data  */
        c->algorithm->update_ad(&c->backend_state, in, inl);
    } else {
        /* ---- plaintext / ciphertext ------------------------------ */
        if (outsize < inl)
            return 0;
        c->data_started = 1;
        if (c->enc)
            c->algorithm->encrypt(&c->backend_state, in, inl, out);
        else
            c->algorithm->decrypt(&c->backend_state, in, inl, out);
        *outl = inl;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Final                                                               */
/* ------------------------------------------------------------------ */

static int belt_aead_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    bee2_belt_aead_ctx_t *c = vctx;
    (void)out;
    (void)outsize;
    *outl = 0;

    if (c->enc) {
        /* Compute and store tag — caller retrieves via get_ctx_params. */
        c->algorithm->get_tag(&c->backend_state, c->tag);
        c->tag_set = 1;
    } else {
        /* Compute tag and verify against the expected value. */
        octet computed[BELT_AEAD_TAG_SIZE];
        int valid;

        if (!c->tag_set)
            return 0; /* caller must set expected tag first */

        c->algorithm->get_tag(&c->backend_state, computed);

        valid = bee2_constant_time_equal(computed, c->tag, BELT_AEAD_TAG_SIZE);
        OPENSSL_cleanse(computed, sizeof(computed));
        if (!valid)
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  One-shot cipher                                                     */
/* ------------------------------------------------------------------ */

static int belt_aead_cipher(void *vctx,
                            unsigned char *out,
                            size_t *outl,
                            size_t outsize,
                            const unsigned char *in,
                            size_t inl) {
    size_t upd = 0, fin = 0;
    if (!belt_aead_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!belt_aead_final(vctx, out + upd, &fin, outsize - upd))
        return 0;
    *outl = upd + fin;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Context parameters                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_aead_ctx_gettable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_aead_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_aead_gettable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_aead_ctx_gettable;
}

static const OSSL_PARAM *belt_aead_settable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_aead_ctx_settable;
}

static int belt_aead_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_belt_aead_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->fixed_key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_AEAD_TAG_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (!c->tag_set)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, c->tag, BELT_AEAD_TAG_SIZE))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && c->backend_state.iv_set &&
        !OSSL_PARAM_set_octet_string(p, c->backend_state.iv, BELT_IV_SIZE))
        return 0;

    return 1;
}

static int belt_aead_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_aead_ctx_t *c = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t klen;
        if (!OSSL_PARAM_get_size_t(p, &klen))
            return 0;
        if (klen != c->fixed_key_len)
            return 0;
    }

    /* Expected authentication tag for decryption. */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        const void *tag = NULL;
        size_t tag_len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &tag, &tag_len))
            return 0;
        if (tag_len != BELT_AEAD_TAG_SIZE)
            return 0;
        memcpy(c->tag, tag, BELT_AEAD_TAG_SIZE);
        c->tag_set = 1;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters (static)                                       */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_aead_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_aead_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_aead_gettable_params;
}

static int belt_aead_get_params_impl(OSSL_PARAM params[], size_t keylen) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, 1))
        return 0; /* stream-like AEAD */

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p && !OSSL_PARAM_set_size_t(p, BELT_AEAD_TAG_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p && !OSSL_PARAM_set_int(p, 1))
        return 0; /* is an AEAD cipher */

    return 1;
}

#define BELT_AEAD_GET_PARAMS(KEYBITS, MODE_LC)                                                     \
    static int belt_##KEYBITS##_##MODE_LC##_get_params(OSSL_PARAM p[]) {                           \
        return belt_aead_get_params_impl(p, (KEYBITS) / 8);                                        \
    }

BELT_AEAD_GET_PARAMS(128, che)
BELT_AEAD_GET_PARAMS(192, che)
BELT_AEAD_GET_PARAMS(256, che)
BELT_AEAD_GET_PARAMS(128, dwp)
BELT_AEAD_GET_PARAMS(192, dwp)
BELT_AEAD_GET_PARAMS(256, dwp)

/* ------------------------------------------------------------------ */
/*  Dispatch tables                                                      */
/* ------------------------------------------------------------------ */

#define BELT_AEAD_DISPATCH(KEYBITS, MODE_LC)                                                       \
    const OSSL_DISPATCH bee2_belt_##KEYBITS##_##MODE_LC##_functions[] = {                          \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))belt_##KEYBITS##_##MODE_LC##_newctx},            \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))belt_aead_freectx},                             \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))belt_aead_dupctx},                               \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))belt_aead_encrypt_init},                   \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))belt_aead_decrypt_init},                   \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))belt_aead_update},                               \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))belt_aead_final},                                 \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))belt_aead_cipher},                               \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))belt_##KEYBITS##_##MODE_LC##_get_params},    \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))belt_aead_gettable_params},             \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))belt_aead_get_ctx_params},               \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))belt_aead_gettable_ctx_params},     \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))belt_aead_set_ctx_params},               \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))belt_aead_settable_ctx_params},     \
        {0, NULL}}

BELT_AEAD_DISPATCH(128, che);
BELT_AEAD_DISPATCH(192, che);
BELT_AEAD_DISPATCH(256, che);
BELT_AEAD_DISPATCH(128, dwp);
BELT_AEAD_DISPATCH(192, dwp);
BELT_AEAD_DISPATCH(256, dwp);
