/*
 * belt_cipher.c — OpenSSL 3.x provider: BELT block cipher (STB 34.101.31)
 *
 * Implements five modes backed by Bee2:
 *   BELT-ECB  — Electronic Codebook (no IV)
 *   BELT-CBC  — Cipher Block Chaining
 *   BELT-CFB  — Cipher Feedback (streaming; supports partial last block)
 *   BELT-CTR  — Counter mode (streaming; supports partial last block)
 *   BELT-BDE  — Block Disk Encryption (XEX-based tweakable block cipher)
 *
 * Key  : 16/24/32 bytes (128/192/256-bit)
 * Block: 16 bytes (128-bit)
 * IV   : 16 bytes (ECB has no IV)
 */

#include "bee2_backend.h"
#include "provider.h"

/* ------------------------------------------------------------------ */
/*  EVP cipher mode numbers (from <openssl/evp.h>)                     */
/* ------------------------------------------------------------------ */
#define BEE2_EVP_CIPH_ECB_MODE 1
#define BEE2_EVP_CIPH_CBC_MODE 2
#define BEE2_EVP_CIPH_CFB_MODE 3
#define BEE2_EVP_CIPH_CTR_MODE 5
#define BEE2_EVP_CIPH_BDE_MODE 8 /* XTS (8) is closest standard analogue */

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef void (*belt_mode_init_fn)(bee2_belt_mode_ctx_t *context);
typedef void (*belt_mode_restart_fn)(bee2_belt_mode_ctx_t *context);
typedef void (*belt_mode_set_key_fn)(bee2_belt_mode_ctx_t *context,
                                     const void *key,
                                     size_t key_length);
typedef void (*belt_mode_set_iv_fn)(bee2_belt_mode_ctx_t *context,
                                    const void *iv,
                                    size_t iv_length);
typedef void (*belt_mode_crypt_fn)(bee2_belt_mode_ctx_t *context,
                                   const void *input,
                                   size_t blocks,
                                   void *output);
typedef void (*belt_mode_cleanup_fn)(bee2_belt_mode_ctx_t *context);

typedef struct {
    belt_mode_init_fn init;
    belt_mode_restart_fn restart;
    belt_mode_set_key_fn set_key;
    belt_mode_set_iv_fn set_iv;
    belt_mode_crypt_fn encrypt;
    belt_mode_crypt_fn decrypt;
    belt_mode_cleanup_fn cleanup;
    size_t iv_size;
    int accepts_partial_block;
} belt_mode_descriptor_t;

#define BELT_MODE_DESCRIPTOR(NAME, PREFIX, IV_SIZE, PARTIAL) \
    static const belt_mode_descriptor_t NAME = {PREFIX##_init, \
                                                PREFIX##_restart, \
                                                PREFIX##_set_key, \
                                                PREFIX##_set_iv, \
                                                PREFIX##_encrypt, \
                                                PREFIX##_decrypt, \
                                                PREFIX##_cleanup, \
                                                (IV_SIZE), \
                                                (PARTIAL)}

static const belt_mode_descriptor_t belt_ecb_mode = {belt_ecb_init,
                                                     belt_ecb_restart,
                                                     belt_ecb_set_key,
                                                     belt_ecb_set_iv,
                                                     belt_ecb_encrypt,
                                                     belt_ecb_decrypt,
                                                     belt_ecb_cleanup,
                                                     0,
                                                     0};
BELT_MODE_DESCRIPTOR(belt_cbc_mode, belt_cbc, BELT_IV_SIZE, 0);
BELT_MODE_DESCRIPTOR(belt_cfb_mode, belt_cfb, BELT_IV_SIZE, 1);
BELT_MODE_DESCRIPTOR(belt_ctr_mode, belt_ctr, BELT_IV_SIZE, 1);
BELT_MODE_DESCRIPTOR(belt_bde_mode, belt_bde, BELT_IV_SIZE, 0);

typedef struct {
    bee2_belt_mode_ctx_t backend_state;
    const belt_mode_descriptor_t *mode;
    int enc;              /* 1 = encrypt, 0 = decrypt                  */
    size_t fixed_key_len; /* wrapper-fixed key length (16/24/32 bytes) */

    octet buf[BELT_BLOCK_SIZE]; /* partial-block input buffer               */
    size_t buf_len;             /* bytes currently in buf                   */
} bee2_belt_ctx_t;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Re-initialise the Bee2 context from saved key/IV. */
static void belt_reinit(bee2_belt_ctx_t *c) {
    c->mode->restart(&c->backend_state);
}

/* Process exactly one 16-byte block through the active cipher mode. */
static void belt_process_block(bee2_belt_ctx_t *c, const octet *in, octet *out) {
    belt_mode_crypt_fn crypt = c->enc ? c->mode->encrypt : c->mode->decrypt;
    crypt(&c->backend_state, in, 1, out);
}

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *
belt_newctx_mode(void *provctx, const belt_mode_descriptor_t *mode, size_t fixed_key_len) {
    (void)provctx;
    bee2_belt_ctx_t *c = OPENSSL_zalloc(sizeof(*c));
    if (!c)
        return NULL;
    c->mode = mode;
    c->fixed_key_len = fixed_key_len;
    c->mode->init(&c->backend_state);
    return c;
}

#define BELT_NEWCTX(KEYBITS, MODE_LC, MODE_DESCRIPTOR) \
    static void *belt_##KEYBITS##_##MODE_LC##_newctx(void *pctx) { \
        return belt_newctx_mode(pctx, &(MODE_DESCRIPTOR), (KEYBITS) / 8u); \
    }

BELT_NEWCTX(128, ecb, belt_ecb_mode)
BELT_NEWCTX(192, ecb, belt_ecb_mode)
BELT_NEWCTX(256, ecb, belt_ecb_mode)
BELT_NEWCTX(128, cbc, belt_cbc_mode)
BELT_NEWCTX(192, cbc, belt_cbc_mode)
BELT_NEWCTX(256, cbc, belt_cbc_mode)
BELT_NEWCTX(128, cfb, belt_cfb_mode)
BELT_NEWCTX(192, cfb, belt_cfb_mode)
BELT_NEWCTX(256, cfb, belt_cfb_mode)
BELT_NEWCTX(128, ctr, belt_ctr_mode)
BELT_NEWCTX(192, ctr, belt_ctr_mode)
BELT_NEWCTX(256, ctr, belt_ctr_mode)
BELT_NEWCTX(128, bde, belt_bde_mode)
BELT_NEWCTX(192, bde, belt_bde_mode)
BELT_NEWCTX(256, bde, belt_bde_mode)

static void belt_freectx(void *vctx) {
    bee2_belt_ctx_t *c = vctx;
    if (!c)
        return;
    c->mode->cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *belt_dupctx(void *vctx) {
    bee2_belt_ctx_t *src = vctx;
    bee2_belt_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* ------------------------------------------------------------------ */
/*  Init (encrypt / decrypt)                                            */
/* ------------------------------------------------------------------ */

static int belt_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int belt_init(void *vctx,
                     const unsigned char *key,
                     size_t keylen,
                     const unsigned char *iv,
                     size_t ivlen,
                     int enc,
                     const OSSL_PARAM params[]) {
    bee2_belt_ctx_t *c = vctx;
    c->enc = enc;
    c->buf_len = 0;

    if (params && !belt_set_ctx_params(c, params))
        return 0;

    if (key != NULL) {
        if (keylen != c->fixed_key_len)
            return 0;
        c->mode->set_key(&c->backend_state, key, keylen);
    }

    if (iv != NULL) {
        if (c->mode->iv_size == 0) {
            /* Some EVP callers pass a non-NULL IV pointer for ECB. Ignore it. */
            if (ivlen != 0)
                return 0;
        } else {
            if (ivlen != c->mode->iv_size)
                return 0;
            c->mode->set_iv(&c->backend_state, iv, ivlen);
        }
    }

    if (c->backend_state.key_set)
        belt_reinit(c);

    return 1;
}

static int belt_encrypt_init(void *vctx,
                             const unsigned char *key,
                             size_t keylen,
                             const unsigned char *iv,
                             size_t ivlen,
                             const OSSL_PARAM params[]) {
    return belt_init(vctx, key, keylen, iv, ivlen, 1, params);
}

static int belt_decrypt_init(void *vctx,
                             const unsigned char *key,
                             size_t keylen,
                             const unsigned char *iv,
                             size_t ivlen,
                             const OSSL_PARAM params[]) {
    return belt_init(vctx, key, keylen, iv, ivlen, 0, params);
}

/* ------------------------------------------------------------------ */
/*  Update — processes data, buffering any partial last block           */
/* ------------------------------------------------------------------ */

static int belt_update(void *vctx,
                       unsigned char *out,
                       size_t *outl,
                       size_t outsize,
                       const unsigned char *in,
                       size_t inl) {
    bee2_belt_ctx_t *c = vctx;
    size_t written = 0;

    *outl = 0;

    if (!c->backend_state.key_set || (c->mode->iv_size != 0 && !c->backend_state.iv_set))
        return 0;

    while (inl > 0) {
        if (c->buf_len == 0 && inl >= BELT_BLOCK_SIZE) {
            /* Fast path: consume whole blocks straight from the input. */
            if (outsize < written + BELT_BLOCK_SIZE)
                return 0;
            belt_process_block(c, in, out + written);
            written += BELT_BLOCK_SIZE;
            in += BELT_BLOCK_SIZE;
            inl -= BELT_BLOCK_SIZE;
        } else {
            /* Accumulate into the partial-block buffer. */
            size_t space = BELT_BLOCK_SIZE - c->buf_len;
            size_t copy = (inl < space) ? inl : space;
            memcpy(c->buf + c->buf_len, in, copy);
            c->buf_len += copy;
            in += copy;
            inl -= copy;

            if (c->buf_len == BELT_BLOCK_SIZE) {
                if (outsize < written + BELT_BLOCK_SIZE)
                    return 0;
                belt_process_block(c, c->buf, out + written);
                written += BELT_BLOCK_SIZE;
                c->buf_len = 0;
            }
        }
    }

    *outl = written;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Final — flushes the last (possibly partial) block                  */
/* ------------------------------------------------------------------ */

static int belt_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    bee2_belt_ctx_t *c = vctx;
    *outl = 0;

    if (c->buf_len == 0)
        return 1; /* nothing to flush */

    if (c->mode->accepts_partial_block) {
        /*
         * CFB and CTR are streaming modes: pad the partial input with zeros to
         * form a full block, encrypt it, then copy only the live bytes.
         * The zero-padded bytes XOR with keystream produce unused output.
         */
        octet tmp_in[BELT_BLOCK_SIZE] = {0};
        octet tmp_out[BELT_BLOCK_SIZE];

        if (outsize < c->buf_len)
            return 0;
        memcpy(tmp_in, c->buf, c->buf_len);
        belt_process_block(c, tmp_in, tmp_out);
        memcpy(out, tmp_out, c->buf_len);
        *outl = c->buf_len;
        c->buf_len = 0;
        return 1;
    }

    /*
     * ECB / CBC / BDE: partial blocks are illegal without padding.
     * Padding is handled by the EVP layer above us; if we reach here
     * with a partial block, the caller made an error.
     */
    return 0;
}

/* ------------------------------------------------------------------ */
/*  One-shot cipher                                                     */
/* ------------------------------------------------------------------ */

static int belt_cipher(void *vctx,
                       unsigned char *out,
                       size_t *outl,
                       size_t outsize,
                       const unsigned char *in,
                       size_t inl) {
    size_t upd = 0, fin = 0;
    if (!belt_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!belt_final(vctx, out + upd, &fin, outsize - upd))
        return 0;
    *outl = upd + fin;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Algorithm parameters (static / per-algorithm, no context)          */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_cipher_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_cipher_gettable_params;
}

static int belt_get_params_impl(
    OSSL_PARAM params[], size_t keylen, size_t ivlen, size_t block_size, unsigned int mode_val) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p && !OSSL_PARAM_set_size_t(p, ivlen))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, block_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p && !OSSL_PARAM_set_uint(p, mode_val))
        return 0;

    return 1;
}

#define BELT_GET_PARAMS(KEYBITS, MODE_LC, IVLEN, BSIZE, MODE_VAL) \
    static int belt_##KEYBITS##_##MODE_LC##_get_params(OSSL_PARAM p[]) { \
        return belt_get_params_impl(p, (KEYBITS) / 8, (IVLEN), (BSIZE), (MODE_VAL)); \
    }

BELT_GET_PARAMS(128, ecb, 0, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_ECB_MODE)
BELT_GET_PARAMS(192, ecb, 0, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_ECB_MODE)
BELT_GET_PARAMS(256, ecb, 0, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_ECB_MODE)
BELT_GET_PARAMS(128, cbc, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CBC_MODE)
BELT_GET_PARAMS(192, cbc, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CBC_MODE)
BELT_GET_PARAMS(256, cbc, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CBC_MODE)
BELT_GET_PARAMS(128, cfb, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(192, cfb, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(256, cfb, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(128, ctr, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(192, ctr, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(256, ctr, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(128, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)
BELT_GET_PARAMS(192, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)
BELT_GET_PARAMS(256, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)

/* ------------------------------------------------------------------ */
/*  Context parameters                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_cipher_ctx_gettable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_cipher_ctx_settable[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL), OSSL_PARAM_END};

static const OSSL_PARAM *belt_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_ctx_gettable;
}

static const OSSL_PARAM *belt_settable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_ctx_settable;
}

static int belt_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_belt_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_set_size_t(p, c->fixed_key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p) {
        if (!OSSL_PARAM_set_size_t(p, c->mode->iv_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p && c->mode->iv_size != 0) {
        if (!OSSL_PARAM_set_octet_string(p, c->backend_state.iv, c->mode->iv_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p && c->mode->iv_size != 0) {
        if (!OSSL_PARAM_set_octet_string(p, c->backend_state.iv, c->mode->iv_size))
            return 0;
    }

    return 1;
}

static int belt_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_ctx_t *c = vctx;
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

#define BELT_DISPATCH(KEYBITS, MODE_LC) \
    const OSSL_DISPATCH bee2_belt_##KEYBITS##_##MODE_LC##_functions[] = { \
        {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))belt_##KEYBITS##_##MODE_LC##_newctx}, \
        {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))belt_freectx}, \
        {OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))belt_dupctx}, \
        {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))belt_encrypt_init}, \
        {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))belt_decrypt_init}, \
        {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))belt_update}, \
        {OSSL_FUNC_CIPHER_FINAL, (void (*)(void))belt_final}, \
        {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))belt_cipher}, \
        {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))belt_##KEYBITS##_##MODE_LC##_get_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))belt_gettable_params}, \
        {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))belt_get_ctx_params}, \
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))belt_gettable_ctx_params}, \
        {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))belt_set_ctx_params}, \
        {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))belt_settable_ctx_params}, \
        {0, NULL}}

BELT_DISPATCH(128, ecb);
BELT_DISPATCH(192, ecb);
BELT_DISPATCH(256, ecb);
BELT_DISPATCH(128, cbc);
BELT_DISPATCH(192, cbc);
BELT_DISPATCH(256, cbc);
BELT_DISPATCH(128, cfb);
BELT_DISPATCH(192, cfb);
BELT_DISPATCH(256, cfb);
BELT_DISPATCH(128, ctr);
BELT_DISPATCH(192, ctr);
BELT_DISPATCH(256, ctr);
BELT_DISPATCH(128, bde);
BELT_DISPATCH(192, bde);
BELT_DISPATCH(256, bde);
