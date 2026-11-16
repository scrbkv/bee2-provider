/*
 * belt_cipher.c — OpenSSL 3.x provider: BELT block cipher (STB 34.101.31)
 *
 * Implements five modes backed by Bee2:
 *   BELT-ECB  — Electronic Codebook (no IV)
 *   BELT-CBC  — Cipher Block Chaining
 *   BELT-CFB  — Cipher Feedback (streaming; supports partial last block)
 *   BELT-CTR  — Counter mode (streaming; supports partial last block)
 *   ECB/CBC without padding use Bee2 ciphertext stealing for final partial blocks.
 *   BELT-BDE  — Block Disk Encryption (XEX-based tweakable block cipher)
 *
 * Key  : 16/24/32 bytes (128/192/256-bit)
 * Block: 16 bytes (128-bit)
 * IV   : 16 bytes (ECB has no IV)
 */

#include "bee2_backend.h"
#include "provider.h"

#include <openssl/evp.h>

/* ------------------------------------------------------------------ */
/* EVP has no named mode for BELT-BDE. OpenSSL represents a zero mode
 * as STREAM_CIPHER; this is a compatibility fallback, NOT a statement
 * that BELT-BDE has stream-cipher or XTS semantics. Applications must
 * identify BELT-BDE by its algorithm name or bee2-mode parameter. */
#define BEE2_EVP_CIPH_ECB_MODE EVP_CIPH_ECB_MODE
#define BEE2_EVP_CIPH_CBC_MODE EVP_CIPH_CBC_MODE
#define BEE2_EVP_CIPH_CFB_MODE EVP_CIPH_CFB_MODE
#define BEE2_EVP_CIPH_CTR_MODE EVP_CIPH_CTR_MODE
#define BEE2_EVP_CIPH_BDE_MODE 0u
#define BEE2_CIPHER_PARAM_BEE2_MODE "bee2-mode"

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

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

typedef struct {
    belt_mode_restart_fn restart;
    belt_mode_set_key_fn set_key;
    belt_mode_set_iv_fn set_iv;
    belt_mode_crypt_fn encrypt;
    belt_mode_crypt_fn decrypt;
    belt_mode_crypt_fn encrypt_bytes;
    belt_mode_crypt_fn decrypt_bytes;
    size_t iv_size;
} belt_mode_descriptor_t;

#define BELT_MODE_DESCRIPTOR(NAME, PREFIX, IV_SIZE, ENCRYPT_BYTES, DECRYPT_BYTES) \
    static const belt_mode_descriptor_t NAME = {PREFIX##_restart, \
                                                PREFIX##_set_key, \
                                                PREFIX##_set_iv, \
                                                PREFIX##_encrypt, \
                                                PREFIX##_decrypt, \
                                                (ENCRYPT_BYTES), \
                                                (DECRYPT_BYTES), \
                                                (IV_SIZE)}

static const belt_mode_descriptor_t belt_ecb_mode = {belt_ecb_restart,
                                                     belt_ecb_set_key,
                                                     NULL,
                                                     belt_ecb_encrypt,
                                                     belt_ecb_decrypt,
                                                     NULL,
                                                     NULL,
                                                     0};
BELT_MODE_DESCRIPTOR(belt_cbc_mode, belt_cbc, BELT_IV_SIZE, NULL, NULL);
BELT_MODE_DESCRIPTOR(belt_cfb_mode, belt_cfb, BELT_IV_SIZE,
                     belt_cfb_encrypt_bytes, belt_cfb_decrypt_bytes);
BELT_MODE_DESCRIPTOR(belt_ctr_mode, belt_ctr, BELT_IV_SIZE,
                     belt_ctr_crypt_bytes, belt_ctr_crypt_bytes);
BELT_MODE_DESCRIPTOR(belt_bde_mode, belt_bde, BELT_IV_SIZE, NULL, NULL);

typedef struct {
    bee2_belt_mode_ctx_t backend_state;
    const belt_mode_descriptor_t *mode;
    int enc;              /* 1 = encrypt, 0 = decrypt                  */
    size_t fixed_key_len; /* wrapper-fixed key length (16/24/32 bytes) */

    octet updated_iv[BELT_IV_SIZE];
    u32 key_words[8];
    unsigned int num;
    octet cfb_partial[BELT_BLOCK_SIZE];

    octet buf[BELT_BLOCK_SIZE]; /* partial-block input buffer               */
    size_t buf_len;             /* bytes currently in buf                   */
    octet last[BELT_BLOCK_SIZE]; /* final ciphertext block for padded decryption */
    int have_last;
    int padding;
    int started;
    int cts_done;
    int finalized;
} bee2_belt_ctx_t;

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Re-initialise the Bee2 context from saved key/IV. */
static void belt_reinit(bee2_belt_ctx_t *c) {
    c->mode->restart(&c->backend_state);
}

/* Keep the OpenSSL-facing IV state in step with Bee2's stream modes. */
static void belt_reset_iv_state(bee2_belt_ctx_t *c) {
    u32 block[4];

    memset(c->updated_iv, 0, sizeof(c->updated_iv));
    c->num = 0;
    if (c->mode->iv_size == 0 || !c->backend_state.iv_set)
        return;

    memcpy(c->updated_iv, c->backend_state.iv, sizeof(c->updated_iv));
    if (c->mode == &belt_ctr_mode) {
        u32From(block, c->updated_iv, sizeof(c->updated_iv));
        beltBlockEncr2(block, c->key_words);
        u32To(c->updated_iv, sizeof(c->updated_iv), block);
        OPENSSL_cleanse(block, sizeof(block));
    }
}

static void belt_update_cfb_state(bee2_belt_ctx_t *c,
                                  const unsigned char *ciphertext,
                                  size_t length) {
    size_t count;

    if (c->num != 0 && length != 0) {
        count = BELT_BLOCK_SIZE - c->num;
        if (count > length)
            count = length;
        memcpy(c->cfb_partial + c->num, ciphertext, count);
        c->num += (unsigned int)count;
        ciphertext += count;
        length -= count;
        if (c->num == BELT_BLOCK_SIZE) {
            memcpy(c->updated_iv, c->cfb_partial, BELT_BLOCK_SIZE);
            c->num = 0;
        }
    }
    if (length >= BELT_BLOCK_SIZE) {
        count = length / BELT_BLOCK_SIZE * BELT_BLOCK_SIZE;
        memcpy(c->updated_iv, ciphertext + count - BELT_BLOCK_SIZE, BELT_BLOCK_SIZE);
        ciphertext += count;
        length -= count;
    }
    if (length != 0) {
        memcpy(c->cfb_partial, ciphertext, length);
        c->num = (unsigned int)length;
    }
}

static void belt_update_ctr_state(bee2_belt_ctx_t *c, size_t length) {
    size_t blocks = length / BELT_BLOCK_SIZE;
    unsigned int remainder = (unsigned int)(length % BELT_BLOCK_SIZE);
    size_t i;

    if (remainder != 0 &&
        (c->num == 0 || c->num + remainder > BELT_BLOCK_SIZE))
        ++blocks;
    c->num = (c->num + remainder) % BELT_BLOCK_SIZE;

    for (i = 0; i < sizeof(c->updated_iv) && blocks != 0; ++i) {
        unsigned int sum = c->updated_iv[i] + (unsigned int)(blocks & 0xffu);
        c->updated_iv[i] = (octet)sum;
        blocks = (blocks >> 8) + (sum >> 8);
    }
}

/* Process exactly one 16-byte block through the active cipher mode. */
static void belt_process_block(bee2_belt_ctx_t *c, const octet *in, octet *out) {
    belt_mode_crypt_fn crypt = c->enc ? c->mode->encrypt : c->mode->decrypt;

    if (c->mode == &belt_cbc_mode && !c->enc)
        memcpy(c->updated_iv, in, sizeof(c->updated_iv));
    crypt(&c->backend_state, in, 1, out);
    if (c->mode == &belt_cbc_mode && c->enc)
        memcpy(c->updated_iv, out, sizeof(c->updated_iv));
}

/* Bee2 processes the final partial ECB/CBC fragment in one Step call.
 * The EVP Final callback cannot emit more than one declared block, so CTS
 * must be completed in Update, as in OpenSSL's built-in CTS ciphers. */
static void belt_process_tail(bee2_belt_ctx_t *c, const octet *input,
                              size_t count, octet *output) {
    size_t last_block = (count / BELT_BLOCK_SIZE - 1u) * BELT_BLOCK_SIZE;

    if (c->mode == &belt_cbc_mode && !c->enc)
        memcpy(c->updated_iv, input + last_block, BELT_BLOCK_SIZE);

    memmove(output, input, count);
    if (c->mode == &belt_ecb_mode) {
        if (c->enc)
            beltECBStepE(output, count, &c->backend_state.state);
        else
            beltECBStepD(output, count, &c->backend_state.state);
    } else {
        if (c->enc)
            beltCBCStepE(output, count, &c->backend_state.state);
        else
            beltCBCStepD(output, count, &c->backend_state.state);
        if (c->enc)
            memcpy(c->updated_iv, output + last_block, BELT_BLOCK_SIZE);
    }
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
    c->padding = mode == &belt_ecb_mode || mode == &belt_cbc_mode;
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

    if (c == NULL)
        return 0;
    /* Failed reinitialization must not leave the previous operation usable. */
    c->finalized = 1;
    if ((key != NULL && keylen != c->fixed_key_len) ||
        (iv != NULL && ivlen != c->mode->iv_size))
        return 0;
    /* Init starts a new operation. The padding restriction applies only
     * between Init and Final, not to a previously completed operation. */
    c->started = 0;
    if (params != NULL && !belt_set_ctx_params(c, params))
        return 0;
    c->enc = enc;
    c->buf_len = 0;
    c->have_last = 0;
    c->cts_done = 0;
    c->finalized = 0;
    if (key != NULL) {
        c->mode->set_key(&c->backend_state, key, keylen);
        u32From(c->key_words, c->backend_state.key, sizeof(c->key_words));
    }
    if (iv != NULL && c->mode->iv_size != 0)
        c->mode->set_iv(&c->backend_state, iv, ivlen);
    if (c->backend_state.key_set) {
        belt_reinit(c);
        belt_reset_iv_state(c);
    }
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
/*  Update and final                                                 */
/* ------------------------------------------------------------------ */

static int belt_update(void *vctx,
                       unsigned char *out,
                       size_t *outl,
                       size_t outsize,
                       const unsigned char *in,
                       size_t inl) {
    bee2_belt_ctx_t *c = vctx;
    size_t written = 0, original_inl = inl, full_blocks;
    unsigned char *copy = NULL;
    int hold_last = !c->enc && c->padding;

    *outl = 0;
    if (c->finalized || !c->backend_state.key_set ||
        (c->mode->iv_size != 0 && !c->backend_state.iv_set) ||
        (inl != 0 && (!in || !out)))
        return 0;

    if (c->mode->encrypt_bytes != NULL) {
        belt_mode_crypt_fn crypt = c->enc ? c->mode->encrypt_bytes : c->mode->decrypt_bytes;

        if (outsize < inl)
            return 0;
        if (inl != 0) {
            c->started = 1;
            if (c->mode == &belt_cfb_mode && !c->enc)
                belt_update_cfb_state(c, in, inl);
            crypt(&c->backend_state, in, inl, out);
            if (c->mode == &belt_cfb_mode) {
                if (c->enc)
                    belt_update_cfb_state(c, out, inl);
            } else {
                belt_update_ctr_state(c, inl);
            }
        }
        *outl = inl;
        return 1;
    }

    if (c->cts_done && inl != 0)
        return 0;

    /* A final nonaligned ECB/CBC fragment must contain a complete block.
     * Once processed, accepting more input would change its CTS result. */
    if (!c->padding && (c->mode == &belt_ecb_mode || c->mode == &belt_cbc_mode) &&
        c->buf_len == 0 && inl >= BELT_BLOCK_SIZE && inl % BELT_BLOCK_SIZE != 0) {
        if (outsize < inl)
            return 0;
        belt_process_tail(c, in, inl, out);
        c->started = 1;
        c->cts_done = 1;
        *outl = inl;
        return 1;
    }

    if (inl > SIZE_MAX - c->buf_len)
        return 0;
    full_blocks = (inl + c->buf_len) / BELT_BLOCK_SIZE;
    if (hold_last && !c->have_last && full_blocks != 0)
        --full_blocks;
    if (outsize < full_blocks * BELT_BLOCK_SIZE)
        return 0;

    /* A pending partial block may make the first output longer than the
     * bytes consumed from this call. Preserve unread input in-place. */
    if (in == out && inl >= BELT_BLOCK_SIZE - c->buf_len &&
        (c->buf_len != 0 || (hold_last && c->have_last))) {
        copy = OPENSSL_memdup(in, inl);
        if (!copy)
            return 0;
        in = copy;
    }
    if (inl != 0)
        c->started = 1;

    while (inl != 0) {
        const octet *block;

        if (c->buf_len == 0 && inl >= BELT_BLOCK_SIZE) {
            block = in;
            in += BELT_BLOCK_SIZE;
            inl -= BELT_BLOCK_SIZE;
        } else {
            size_t count = BELT_BLOCK_SIZE - c->buf_len;

            if (count > inl)
                count = inl;
            memcpy(c->buf + c->buf_len, in, count);
            c->buf_len += count;
            in += count;
            inl -= count;
            if (c->buf_len != BELT_BLOCK_SIZE)
                break;
            block = c->buf;
        }

        if (hold_last) {
            /* Keep the last block until Final can validate its padding. */
            if (c->have_last) {
                belt_process_block(c, c->last, out + written);
                written += BELT_BLOCK_SIZE;
            }
            memcpy(c->last, block, BELT_BLOCK_SIZE);
            c->have_last = 1;
        } else {
            belt_process_block(c, block, out + written);
            written += BELT_BLOCK_SIZE;
        }
        c->buf_len = 0;
    }

    OPENSSL_clear_free(copy, original_inl);
    *outl = written;
    return 1;
}

static int belt_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize) {
    bee2_belt_ctx_t *c = vctx;
    unsigned char block[BELT_BLOCK_SIZE];
    size_t pad_len, length;
    unsigned int mismatch = 0;
    size_t i;

    *outl = 0;
    if (c->finalized || !c->backend_state.key_set ||
        (c->mode->iv_size != 0 && !c->backend_state.iv_set))
        return 0;

    if (c->mode->encrypt_bytes != NULL) {
        c->finalized = 1;
        return 1;
    }
    if (!c->padding) {
        if (c->buf_len != 0)
            return 0;
        c->finalized = 1;
        return 1;
    }

    if (c->enc) {
        if (!out || outsize < BELT_BLOCK_SIZE)
            return 0;
        pad_len = BELT_BLOCK_SIZE - c->buf_len;
        memset(c->buf + c->buf_len, (int)pad_len, pad_len);
        belt_process_block(c, c->buf, out);
        c->buf_len = 0;
        c->finalized = 1;
        *outl = BELT_BLOCK_SIZE;
        return 1;
    }

    if (c->buf_len != 0 || !c->have_last)
        return 0;
    belt_process_block(c, c->last, block);
    pad_len = block[BELT_BLOCK_SIZE - 1];
    mismatch = (unsigned int)(pad_len == 0 || pad_len > BELT_BLOCK_SIZE);
    for (i = 0; i < BELT_BLOCK_SIZE; ++i) {
        unsigned int mask = 0u - (unsigned int)(i < pad_len);
        mismatch |= (block[BELT_BLOCK_SIZE - 1 - i] ^ (unsigned int)pad_len) & mask;
    }
    length = BELT_BLOCK_SIZE - (pad_len <= BELT_BLOCK_SIZE ? pad_len : BELT_BLOCK_SIZE);
    if (mismatch != 0 || outsize < length || (length != 0 && !out)) {
        OPENSSL_cleanse(block, sizeof(block));
        c->finalized = 1;
        return 0;
    }
    if (length != 0)
        memcpy(out, block, length);
    OPENSSL_cleanse(block, sizeof(block));
    c->have_last = 0;
    c->finalized = 1;
    *outl = length;
    return 1;
}

static int belt_cipher(void *vctx,
                       unsigned char *out,
                       size_t *outl,
                       size_t outsize,
                       const unsigned char *in,
                       size_t inl) {
    size_t upd = 0, fin = 0;

    *outl = 0;
    if (!belt_update(vctx, out, &upd, outsize, in, inl))
        return 0;
    if (!belt_final(vctx, out != NULL ? out + upd : NULL, &fin, outsize - upd))
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
    OSSL_PARAM_utf8_string(BEE2_CIPHER_PARAM_BEE2_MODE, NULL, 0),
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

    p = OSSL_PARAM_locate(params, BEE2_CIPHER_PARAM_BEE2_MODE);
    if (p && mode_val == BEE2_EVP_CIPH_BDE_MODE &&
        !OSSL_PARAM_set_utf8_string(p, "belt-bde"))
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
BELT_GET_PARAMS(128, cfb, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(192, cfb, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(256, cfb, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CFB_MODE)
BELT_GET_PARAMS(128, ctr, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(192, ctr, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(256, ctr, BELT_IV_SIZE, 1, BEE2_EVP_CIPH_CTR_MODE)
BELT_GET_PARAMS(128, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)
BELT_GET_PARAMS(192, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)
BELT_GET_PARAMS(256, bde, BELT_IV_SIZE, BELT_BLOCK_SIZE, BEE2_EVP_CIPH_BDE_MODE)

/* ------------------------------------------------------------------ */
/*  Context parameters                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_cipher_ctx_gettable[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_cipher_iv_ctx_gettable[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_cipher_stream_ctx_gettable[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_cipher_ctx_settable[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *belt_ecb_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_ctx_gettable;
}

static const OSSL_PARAM *belt_bde_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_ctx_gettable;
}

static const OSSL_PARAM *belt_cbc_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_iv_ctx_gettable;
}

static const OSSL_PARAM *belt_cfb_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_stream_ctx_gettable;
}

static const OSSL_PARAM *belt_ctr_gettable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_stream_ctx_gettable;
}

static const OSSL_PARAM *belt_settable_ctx_params(void *cctx, void *provctx) {
    (void)cctx;
    (void)provctx;
    return bee2_cipher_ctx_settable;
}

static int belt_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_belt_ctx_t *c = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p && !OSSL_PARAM_set_uint(p, (unsigned int)c->padding))
        return 0;

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
    if (p) {
        if ((c->mode != &belt_cbc_mode && c->mode != &belt_cfb_mode &&
             c->mode != &belt_ctr_mode) || !c->backend_state.iv_set)
            return 0;
        if (c->mode == &belt_cfb_mode && c->num != 0) {
            u32 block[4];
            octet iv[BELT_IV_SIZE];
            int ok;

            u32From(block, c->updated_iv, sizeof(c->updated_iv));
            beltBlockEncr2(block, c->key_words);
            u32To(iv, sizeof(iv), block);
            memcpy(iv, c->cfb_partial, c->num);
            ok = OSSL_PARAM_set_octet_string(p, iv, sizeof(iv));
            OPENSSL_cleanse(block, sizeof(block));
            OPENSSL_cleanse(iv, sizeof(iv));
            if (!ok)
                return 0;
        } else if (!OSSL_PARAM_set_octet_string(p, c->updated_iv, sizeof(c->updated_iv))) {
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p) {
        if ((c->mode != &belt_cfb_mode && c->mode != &belt_ctr_mode) ||
            !c->backend_state.iv_set ||
            !OSSL_PARAM_set_uint(p, c->num))
            return 0;
    }

    return 1;
}

static int belt_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_belt_ctx_t *c = vctx;
    const OSSL_PARAM *p;
    int new_padding = c->padding;

    if (!params)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int padding;

        if (!OSSL_PARAM_get_uint(p, &padding) || padding > 1 ||
            (padding != 0 && c->mode != &belt_ecb_mode && c->mode != &belt_cbc_mode) ||
            (c->started && (int)padding != c->padding))
            return 0;
        new_padding = (int)padding;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t klen;
        if (!OSSL_PARAM_get_size_t(p, &klen))
            return 0;
        if (klen != c->fixed_key_len)
            return 0;
    }
    c->padding = new_padding;
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
        {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))belt_##MODE_LC##_gettable_ctx_params}, \
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
