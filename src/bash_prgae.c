/*
 * bash_prgae.c — OpenSSL 3.x provider: BASH-PRGAE AEAD (STB 34.101.77)
 *
 * BASH-PRG-AE is a family of authenticated-encryption schemes built on
 * the BASH sponge PRG.  Six parameter sets are defined:
 *
 *   Variant   l    d   key  iv  tag   Description
 *   -------  ---  ---  ---  --  ---   -----------
 *   1281     128   1   16   16   16   128-bit security, capacity mode 1
 *   1282     128   2   16   16   16   128-bit security, capacity mode 2
 *   1921     192   1   24   24   24   192-bit security, capacity mode 1
 *   1922     192   2   24   24   24   192-bit security, capacity mode 2
 *   2561     256   1   32   32   32   256-bit security, capacity mode 1
 *   2562     256   2   32   32   32   256-bit security, capacity mode 2
 *
 * All sizes are in bytes.
 * Key and IV are passed as-is to the underlying bash_prg_start(); the
 * Bee2 adapter accepts sizes up to BASH_PRGAE_MAX_{KEY,IV}_SIZE.
 *
 * OpenSSL AEAD usage (identical to BELT-CHE / BELT-DWP):
 *   Encrypt: init → update(NULL,aad) → update(out,pt) → final
 *            → get_ctx_params(AEAD_TAG)
 *   Decrypt: init → update(NULL,aad) → update(out,ct)
 *            → set_ctx_params(AEAD_TAG) → final
 */

#include "bee2_backend.h"
#include "provider.h"
#include "provider_util.h"

#include <openssl/crypto.h>

/* ------------------------------------------------------------------ */
/*  Variant descriptor                                                  */
/* ------------------------------------------------------------------ */

typedef void (*bash_prgae_init_fn)(bash_prgae_ctx);
typedef void (*bash_prgae_restart_fn)(bash_prgae_ctx);
typedef void (*bash_prgae_set_key_fn)(bash_prgae_ctx, const void *, size_t);
typedef void (*bash_prgae_set_iv_fn)(bash_prgae_ctx, const void *, size_t);
typedef void (*bash_prgae_update_ad_fn)(bash_prgae_ctx, const void *, size_t);
typedef void (*bash_prgae_encrypt_fn)(bash_prgae_ctx, const void *, size_t, void *);
typedef void (*bash_prgae_decrypt_fn)(bash_prgae_ctx, const void *, size_t, void *);
typedef void (*bash_prgae_get_mac_fn)(bash_prgae_ctx, void *, size_t);
typedef void (*bash_prgae_cleanup_fn)(bash_prgae_ctx);

typedef struct {
    bash_prgae_init_fn backend_init;
    bash_prgae_restart_fn backend_restart;
    bash_prgae_set_key_fn backend_set_key;
    bash_prgae_set_iv_fn backend_set_iv;
    bash_prgae_update_ad_fn backend_update_ad;
    bash_prgae_encrypt_fn backend_encrypt;
    bash_prgae_decrypt_fn backend_decrypt;
    bash_prgae_get_mac_fn backend_get_mac;
    bash_prgae_cleanup_fn backend_cleanup;
    size_t min_key_size; /* minimum key length (bytes), equal to l/8 */
    size_t iv_size;      /* default IV length (bytes)                */
    size_t mac_size;     /* authentication tag (bytes)               */
} bash_prgae_variant_t;

static const bash_prgae_variant_t bash_prgae_variant_1281 = {
    .backend_init = bash_prgae_1281_init,
    .backend_restart = bash_prgae_1281_restart,
    .backend_set_key = bash_prgae_1281_set_key,
    .backend_set_iv = bash_prgae_1281_set_iv,
    .backend_update_ad = bash_prgae_1281_update_ad,
    .backend_encrypt = bash_prgae_1281_encrypt,
    .backend_decrypt = bash_prgae_1281_decrypt,
    .backend_get_mac = bash_prgae_1281_get_mac,
    .backend_cleanup = bash_prgae_1281_cleanup,
    .min_key_size = 16,
    .iv_size = 16,
    .mac_size = 16,
};

static const bash_prgae_variant_t bash_prgae_variant_1282 = {
    .backend_init = bash_prgae_1282_init,
    .backend_restart = bash_prgae_1282_restart,
    .backend_set_key = bash_prgae_1282_set_key,
    .backend_set_iv = bash_prgae_1282_set_iv,
    .backend_update_ad = bash_prgae_1282_update_ad,
    .backend_encrypt = bash_prgae_1282_encrypt,
    .backend_decrypt = bash_prgae_1282_decrypt,
    .backend_get_mac = bash_prgae_1282_get_mac,
    .backend_cleanup = bash_prgae_1282_cleanup,
    .min_key_size = 16,
    .iv_size = 16,
    .mac_size = 16,
};

static const bash_prgae_variant_t bash_prgae_variant_1921 = {
    .backend_init = bash_prgae_1921_init,
    .backend_restart = bash_prgae_1921_restart,
    .backend_set_key = bash_prgae_1921_set_key,
    .backend_set_iv = bash_prgae_1921_set_iv,
    .backend_update_ad = bash_prgae_1921_update_ad,
    .backend_encrypt = bash_prgae_1921_encrypt,
    .backend_decrypt = bash_prgae_1921_decrypt,
    .backend_get_mac = bash_prgae_1921_get_mac,
    .backend_cleanup = bash_prgae_1921_cleanup,
    .min_key_size = 24,
    .iv_size = 24,
    .mac_size = 24,
};

static const bash_prgae_variant_t bash_prgae_variant_1922 = {
    .backend_init = bash_prgae_1922_init,
    .backend_restart = bash_prgae_1922_restart,
    .backend_set_key = bash_prgae_1922_set_key,
    .backend_set_iv = bash_prgae_1922_set_iv,
    .backend_update_ad = bash_prgae_1922_update_ad,
    .backend_encrypt = bash_prgae_1922_encrypt,
    .backend_decrypt = bash_prgae_1922_decrypt,
    .backend_get_mac = bash_prgae_1922_get_mac,
    .backend_cleanup = bash_prgae_1922_cleanup,
    .min_key_size = 24,
    .iv_size = 24,
    .mac_size = 24,
};

static const bash_prgae_variant_t bash_prgae_variant_2561 = {
    .backend_init = bash_prgae_2561_init,
    .backend_restart = bash_prgae_2561_restart,
    .backend_set_key = bash_prgae_2561_set_key,
    .backend_set_iv = bash_prgae_2561_set_iv,
    .backend_update_ad = bash_prgae_2561_update_ad,
    .backend_encrypt = bash_prgae_2561_encrypt,
    .backend_decrypt = bash_prgae_2561_decrypt,
    .backend_get_mac = bash_prgae_2561_get_mac,
    .backend_cleanup = bash_prgae_2561_cleanup,
    .min_key_size = 32,
    .iv_size = 32,
    .mac_size = 32,
};

static const bash_prgae_variant_t bash_prgae_variant_2562 = {
    .backend_init = bash_prgae_2562_init,
    .backend_restart = bash_prgae_2562_restart,
    .backend_set_key = bash_prgae_2562_set_key,
    .backend_set_iv = bash_prgae_2562_set_iv,
    .backend_update_ad = bash_prgae_2562_update_ad,
    .backend_encrypt = bash_prgae_2562_encrypt,
    .backend_decrypt = bash_prgae_2562_decrypt,
    .backend_get_mac = bash_prgae_2562_get_mac,
    .backend_cleanup = bash_prgae_2562_cleanup,
    .min_key_size = 32,
    .iv_size = 32,
    .mac_size = 32,
};

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    bash_prgae_ctx_t backend_state;
    const bash_prgae_variant_t *variant;

    int enc; /* 1 = encrypt, 0 = decrypt */
    int data_started;

    size_t key_len;

    octet tag[32]; /* max mac_size across all variants = 32 bytes */
    int tag_set;
} bee2_bash_prgae_ctx_t;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void bash_prgae_reinit(bee2_bash_prgae_ctx_t *c) {
    c->data_started = 0;
    c->tag_set = 0;
    memset(c->tag, 0, sizeof(c->tag));

    c->variant->backend_restart(&c->backend_state);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *bash_prgae_newctx_for_variant(void *provctx, const bash_prgae_variant_t *variant) {
    (void)provctx;
    bee2_bash_prgae_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->variant = variant;
    c->key_len = variant->min_key_size;
    c->variant->backend_init(&c->backend_state);
    return c;
}

static void bash_prgae_freectx(void *vctx) {
    bee2_bash_prgae_ctx_t *c = vctx;
    if (!c)
        return;
    c->variant->backend_cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *bash_prgae_dupctx(void *vctx) {
    bee2_bash_prgae_ctx_t *src = vctx;
    bee2_bash_prgae_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* variant-specific newctx wrappers */
#define BASH_PRGAE_NEWCTX(SFX) \
    static void *bash_prgae_##SFX##_newctx(void *p) { \
        return bash_prgae_newctx_for_variant(p, &bash_prgae_variant_##SFX); \
    }

BASH_PRGAE_NEWCTX(1281)

BASH_PRGAE_NEWCTX(1282)

BASH_PRGAE_NEWCTX(1921)

BASH_PRGAE_NEWCTX(1922)

BASH_PRGAE_NEWCTX(2561)

BASH_PRGAE_NEWCTX(2562)

/* ------------------------------------------------------------------ */
/*  Init                                                              */
/* ------------------------------------------------------------------ */

static int bash_prgae_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int bash_prgae_init(void *vctx,
                           const unsigned char *key,
                           size_t keylen,
                           const unsigned char *iv,
                           size_t ivlen,
                           int enc,
                           const OSSL_PARAM params[]) {
    bee2_bash_prgae_ctx_t *c = vctx;
    c->enc = enc;

    if (key != NULL) {
        if (keylen < c->variant->min_key_size || keylen > BASH_PRGAE_MAX_KEY_SIZE)
            return 0;
        c->variant->backend_set_key(&c->backend_state, key, keylen);
        c->key_len = keylen;
    }

    if (iv != NULL) {
        if (ivlen > BASH_PRGAE_MAX_IV_SIZE)
            return 0;
        c->variant->backend_set_iv(&c->backend_state, iv, ivlen);
    }

    if (c->backend_state.key_set && c->backend_state.iv_set)
        bash_prgae_reinit(c);

    return !params || bash_prgae_set_ctx_params(c, params);
}

static int bash_prgae_encrypt_init(void *vctx,
                                   const unsigned char *key,
                                   size_t keylen,
                                   const unsigned char *iv,
                                   size_t ivlen,
                                   const OSSL_PARAM params[]) {
    return bash_prgae_init(vctx, key, keylen, iv, ivlen, 1, params);
}

static int bash_prgae_decrypt_init(void *vctx,
                                   const unsigned char *key,
                                   size_t keylen,
                                   const unsigned char *iv,
                                   size_t ivlen,
                                   const OSSL_PARAM params[]) {
    return bash_prgae_init(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ------------------------------------------------------------------ */
/*  Update                                                              */
/* ------------------------------------------------------------------ */

static int bash_prgae_update(void *vctx,
                             unsigned char *out,
                             size_t *outl,
                             size_t outsize,
                             const unsigned char *in,
                             size_t inl) {
    bee2_bash_prgae_ctx_t *c = vctx;
    *outl = 0;

    if (!c->backend_state.key_set || !c->backend_state.iv_set)
        return 0;

    if (inl == 0)
        return 1;

    if (out == NULL) {
        /* AAD */
        if (c->data_started)
            return 0;
        c->variant->backend_update_ad(&c->backend_state, in, inl);
    } else {
        /* plaintext / ciphertext */
        if (outsize < inl)
            return 0;
        c->data_started = 1;
        if (c->enc)
            c->variant->backend_encrypt(&c->backend_state, in, inl, out);
        else
            c->variant->backend_decrypt(&c->backend_state, in, inl, out);
        *outl = inl;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Final                                                               */
/* ------------------------------------------------------------------ */

static int bash_prgae_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    bee2_bash_prgae_ctx_t *c = vctx;
    (void)out;
    (void)outsize;
    *outl = 0;

    if (c->enc) {
        c->variant->backend_get_mac(&c->backend_state, c->tag, c->variant->mac_size);
        c->tag_set = 1;
    } else {
        octet computed[32]; /* big enough for any variant */
        int valid;

        if (!c->tag_set)
            return 0;
        c->variant->backend_get_mac(&c->backend_state, computed, c->variant->mac_size);

        valid = bee2_constant_time_equal(computed, c->tag, c->variant->mac_size);
        OPENSSL_cleanse(computed, sizeof(computed));
        if (!valid)
            return 0;
    }
    return 1;
}

/* One-shot */
static int bash_prgae_cipher(void *vctx,
                             unsigned char *out,
                             size_t *outl,
                             size_t outsize,
                             const unsigned char *in,
                             size_t inl) {
    size_t upd = 0, fin = 0;
    if (!bash_prgae_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!bash_prgae_final(vctx, out + upd, &fin, outsize - upd))
        return 0;
    *outl = upd + fin;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Parameters                                                          */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_bash_prgae_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bash_prgae_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_bash_prgae_gettable_params;
}

static int bash_prgae_get_params_impl(OSSL_PARAM params[], const bash_prgae_variant_t *variant) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, variant->min_key_size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, variant->iv_size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p && !OSSL_PARAM_set_size_t(p, variant->mac_size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

#define BASH_PRGAE_GET_PARAMS_FN(SFX) \
    static int bash_prgae_##SFX##_get_params(OSSL_PARAM p[]) { \
        return bash_prgae_get_params_impl(p, &bash_prgae_variant_##SFX); \
    }

BASH_PRGAE_GET_PARAMS_FN(1281)

BASH_PRGAE_GET_PARAMS_FN(1282)

BASH_PRGAE_GET_PARAMS_FN(1921)

BASH_PRGAE_GET_PARAMS_FN(1922)

BASH_PRGAE_GET_PARAMS_FN(2561)

BASH_PRGAE_GET_PARAMS_FN(2562)

static const OSSL_PARAM bee2_bash_prgae_ctx_gettable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bash_prgae_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *bash_prgae_gettable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_bash_prgae_ctx_gettable;
}

static const OSSL_PARAM *bash_prgae_settable_ctx_params(void *cctx, void *pctx) {
    (void)cctx;
    (void)pctx;
    return bee2_bash_prgae_ctx_settable;
}

static int bash_prgae_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_bash_prgae_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->variant->iv_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->variant->mac_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (!c->tag_set)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, c->tag, c->variant->mac_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && c->backend_state.iv_set &&
        !OSSL_PARAM_set_octet_string(p, c->backend_state.iv, c->backend_state.iv_len))
        return 0;

    return 1;
}

static int bash_prgae_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bash_prgae_ctx_t *c = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t klen;
        if (!OSSL_PARAM_get_size_t(p, &klen))
            return 0;
        if (klen < c->variant->min_key_size || klen > BASH_PRGAE_MAX_KEY_SIZE)
            return 0;
        if (c->backend_state.key_set && klen != c->backend_state.key_len)
            return 0;
        c->key_len = klen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        const void *tag = NULL;
        size_t tag_len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &tag, &tag_len))
            return 0;
        if (tag_len != c->variant->mac_size)
            return 0;
        memcpy(c->tag, tag, tag_len);
        c->tag_set = 1;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dispatch tables                                                     */
/* ------------------------------------------------------------------ */

#define BASH_PRGAE_DISPATCH(SFX) \
    const OSSL_DISPATCH bee2_bash_prgae_##SFX##_functions[] = { \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))bash_prgae_##SFX##_newctx}, \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))bash_prgae_freectx}, \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))bash_prgae_dupctx}, \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))bash_prgae_encrypt_init}, \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))bash_prgae_decrypt_init}, \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))bash_prgae_update}, \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))bash_prgae_final}, \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))bash_prgae_cipher}, \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))bash_prgae_##SFX##_get_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))bash_prgae_gettable_params}, \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))bash_prgae_get_ctx_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))bash_prgae_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))bash_prgae_set_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))bash_prgae_settable_ctx_params}, \
        {0, NULL}}

BASH_PRGAE_DISPATCH(1281);
BASH_PRGAE_DISPATCH(1282);
BASH_PRGAE_DISPATCH(1921);
BASH_PRGAE_DISPATCH(1922);
BASH_PRGAE_DISPATCH(2561);
BASH_PRGAE_DISPATCH(2562);
