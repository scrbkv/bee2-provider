#include "bign_asn1.h"
#include "bign_der_frame.h"
#include "bign_stb_pbes2.h"

#include <limits.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

typedef enum {
    BIGN_ENCODE_PLAIN, BIGN_ENCODE_STB, BIGN_ENCODE_PBES2, BIGN_ENCODE_INVALID
} bign_encryption;

typedef struct {
    OSSL_LIB_CTX *libctx;
    EVP_CIPHER *cipher;
    const bee2_bign_variant_t *variant;
    bign_encryption encryption;
    int pem;
    int private_key;
    unsigned int iterations;
    size_t salt_len;
} bign_encoder_ctx;

static void *encoder_new(void *provctx, const bee2_bign_variant_t *variant,
                          int pem, int private_key)
{
    bign_encoder_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->libctx = bee2_provider_libctx(provctx);
        ctx->variant = variant;
        ctx->pem = pem;
        ctx->private_key = private_key;
        ctx->iterations = BEE2_STB_PBKDF2_DEFAULT_ITER;
        ctx->salt_len = BEE2_STB_PBKDF2_DEFAULT_SALT;
    }
    return ctx;
}

static void encoder_free(void *vctx)
{
    bign_encoder_ctx *ctx = vctx;

    if (ctx != NULL) {
        EVP_CIPHER_free(ctx->cipher);
        OPENSSL_free(ctx);
    }
}

static const OSSL_PARAM *encoder_settable(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_uint(BEE2_STB_PBKDF2_PARAM_ITER, NULL),
        OSSL_PARAM_size_t(BEE2_STB_PBKDF2_PARAM_SALTLEN, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return params;
}

static int encoder_set_params(void *vctx, const OSSL_PARAM params[])
{
    bign_encoder_ctx *ctx = vctx;
    const OSSL_PARAM *p, *cipher_param;
    const char *name = NULL, *properties = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned int iterations = ctx->iterations;
    size_t salt_len = ctx->salt_len;

    cipher_param = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    if (cipher_param != NULL)
        ctx->encryption = BIGN_ENCODE_INVALID;
    p = OSSL_PARAM_locate_const(params, BEE2_STB_PBKDF2_PARAM_ITER);
    if (p != NULL && (!OSSL_PARAM_get_uint(p, &iterations) || iterations == 0 || iterations > INT_MAX))
        return 0;
    p = OSSL_PARAM_locate_const(params, BEE2_STB_PBKDF2_PARAM_SALTLEN);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &salt_len) || salt_len >= BIGN_MAX_KEY_INPUT))
        return 0;
    if (cipher_param != NULL) {
        if (!OSSL_PARAM_get_utf8_string_ptr(cipher_param, &name))
            return 0;
        p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
        if (p != NULL && !OSSL_PARAM_get_utf8_string_ptr(p, &properties))
            return 0;
        if (name != NULL && OPENSSL_strcasecmp(name, "default") == 0)
            name = "belt-kwp256";
        if (name != NULL && (cipher = EVP_CIPHER_fetch(ctx->libctx, name, properties)) == NULL)
            return 0;
        if (cipher == NULL) {
            ctx->encryption = BIGN_ENCODE_PLAIN;
        } else if (EVP_CIPHER_is_a(cipher, "belt-kwp256")) {
            ctx->encryption = BIGN_ENCODE_STB;
            EVP_CIPHER_free(cipher);
            cipher = NULL;
        } else if (EVP_CIPHER_get_mode(cipher) == EVP_CIPH_CBC_MODE &&
                   EVP_CIPHER_get_nid(cipher) != NID_undef && EVP_CIPHER_get_iv_length(cipher) > 0) {
            ctx->encryption = BIGN_ENCODE_PBES2;
        } else {
            EVP_CIPHER_free(cipher);
            return 0;
        }
        EVP_CIPHER_free(ctx->cipher);
        ctx->cipher = cipher;
    }
    ctx->iterations = iterations;
    ctx->salt_len = salt_len;
    return 1;
}

static int select_private(void *provctx, int selection)
{
    (void)provctx;
    return selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int select_public(void *provctx, int selection)
{
    (void)provctx;
    return selection == 0 ||
        ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0 &&
         (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0);
}

static int write_protected(bign_encoder_ctx *ctx, BIO *out, const bee2_bign_key_t *key,
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    char pass[PEM_BUFSIZE];
    size_t pass_len = 0;
    X509_SIG *encrypted = NULL;
    int ok = 0;

    if (cb != NULL && cb(pass, sizeof(pass), &pass_len, NULL, cbarg) && pass_len <= sizeof(pass)) {
        if (ctx->encryption == BIGN_ENCODE_STB) {
            encrypted = bee2_stb_pbes2_protect(key->priv, bee2_bign_priv_len(key->variant),
                                               (const unsigned char *)pass, pass_len,
                                               ctx->iterations, ctx->salt_len, ctx->libctx);
        } else {
            PKCS8_PRIV_KEY_INFO *p8 = bee2_bign_asn1_pkcs8(key);

            if (p8 != NULL)
                encrypted = PKCS8_encrypt_ex(-1, ctx->cipher, pass, (int)pass_len, NULL,
                                              (int)ctx->salt_len, (int)ctx->iterations,
                                              p8, ctx->libctx, NULL);
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
    }
    OPENSSL_cleanse(pass, sizeof(pass));
    if (encrypted != NULL) {
        int length = i2d_X509_SIG(encrypted, NULL);

        if (length > 0 && (size_t)length <= BIGN_MAX_KEY_INPUT)
            ok = ctx->pem ? PEM_write_bio_PKCS8(out, encrypted) : i2d_PKCS8_bio(out, encrypted);
        X509_SIG_free(encrypted);
    }
    return ok;
}

static int encoder_encode(void *vctx, OSSL_CORE_BIO *out, const void *obj,
                          const OSSL_PARAM abstract[], int selection,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    bign_encoder_ctx *ctx = vctx;
    const bee2_bign_key_t *key = obj;
    BIO *bio;
    int ok = 0;

    (void)abstract;
    if (key == NULL || key->variant == NULL || (ctx->variant && ctx->variant != key->variant) ||
        ctx->encryption == BIGN_ENCODE_INVALID ||
        !(ctx->private_key ? select_private(NULL, selection) : select_public(NULL, selection)))
        return 0;
    bio = BIO_new_from_core_bio(ctx->libctx, out);
    if (bio == NULL)
        return 0;
    if (!ctx->private_key) {
        X509_PUBKEY *spki = bee2_bign_asn1_spki(key);

        if (spki != NULL)
            ok = ctx->pem ? PEM_write_bio_X509_PUBKEY(bio, spki) : i2d_X509_PUBKEY_bio(bio, spki);
        X509_PUBKEY_free(spki);
    } else if (key->has_priv && ctx->encryption == BIGN_ENCODE_PLAIN) {
        PKCS8_PRIV_KEY_INFO *p8 = bee2_bign_asn1_pkcs8(key);

        if (p8 != NULL)
            ok = ctx->pem ? PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, p8) : i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8);
        PKCS8_PRIV_KEY_INFO_free(p8);
    } else if (key->has_priv) {
        ok = write_protected(ctx, bio, key, cb, cbarg);
    }
    BIO_free(bio);
    return ok;
}

static void *encoder_import(void *vctx, int selection, const OSSL_PARAM params[])
{
    bign_encoder_ctx *ctx = vctx;
    bee2_bign_key_t *key = bee2_bign_key_new(ctx->variant);

    if (key == NULL || !bee2_bign_import_params(key, selection, params)) {
        bee2_bign_key_free(key);
        return NULL;
    }
    return key;
}

static void encoder_free_object(void *obj)
{
    bee2_bign_key_free(obj);
}

#define PRIVATE_ENCODER_PARAMS \
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))encoder_set_params}, \
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))encoder_settable},
#define PUBLIC_ENCODER_PARAMS

#define BIGN_ENCODER(NAME, VARIANT, PEM, PRIV, SELECT, PARAMS) \
    static void *encoder_##NAME##_new(void *provctx) \
    { \
        return encoder_new(provctx, VARIANT, PEM, PRIV); \
    } \
    const OSSL_DISPATCH bee2_bign_##NAME##_encoder_functions[] = { \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))encoder_##NAME##_new}, \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))encoder_free}, \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))SELECT}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))encoder_encode}, \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))encoder_import}, \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))encoder_free_object}, \
        PARAMS \
        {0, NULL} \
    }

#define BIGN_ENCODER_FORMATS(GROUP, VARIANT) \
    BIGN_ENCODER(GROUP##_private_pem, VARIANT, 1, 1, select_private, PRIVATE_ENCODER_PARAMS); \
    BIGN_ENCODER(GROUP##_private_der, VARIANT, 0, 1, select_private, PRIVATE_ENCODER_PARAMS); \
    BIGN_ENCODER(GROUP##_public_pem, VARIANT, 1, 0, select_public, PUBLIC_ENCODER_PARAMS); \
    BIGN_ENCODER(GROUP##_public_der, VARIANT, 0, 0, select_public, PUBLIC_ENCODER_PARAMS)

BIGN_ENCODER_FORMATS(any, NULL);
BIGN_ENCODER_FORMATS(256, bee2_bign_variant_256());
BIGN_ENCODER_FORMATS(384, bee2_bign_variant_384());
BIGN_ENCODER_FORMATS(512, bee2_bign_variant_512());

static void *decoder_new(void *provctx, bign_decode_kind kind) {
    bee2_bign_decoder_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (!ctx)
        return NULL;
    ctx->kind = kind;
    ctx->libctx = bee2_provider_libctx(provctx);
    ctx->max_pbkdf2_iterations = BEE2_STB_PBKDF2_DEFAULT_MAX_DECODE_ITER;
    return ctx;
}

static void bign_decoder_freectx(void *vctx) {
    OPENSSL_free(vctx);
}

static const OSSL_PARAM bign_decoder_settable[] = {
    OSSL_PARAM_uint(BEE2_STB_PBKDF2_PARAM_MAX_DECODE_ITER, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bign_decoder_settable_ctx_params(void *provctx) {
    (void)provctx;
    return bign_decoder_settable;
}

static int bign_decoder_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bign_decoder_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;
    unsigned int max_iterations;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, BEE2_STB_PBKDF2_PARAM_MAX_DECODE_ITER);
    if (p == NULL)
        return 1;
    if (!OSSL_PARAM_get_uint(p, &max_iterations) ||
        max_iterations == 0 || max_iterations > INT_MAX)
        return 0;
    ctx->max_pbkdf2_iterations = max_iterations;
    return 1;
}


static int bign_decoder_export_object(void *vctx,
                                      const void *objref,
                                      size_t objref_sz,
                                      OSSL_CALLBACK *export_cb,
                                      void *export_cbarg) {
    bee2_bign_key_t *key = NULL;

    (void)vctx;
    if (!objref || !export_cb || objref_sz != sizeof(key))
        return 0;
    memcpy(&key, objref, sizeof(key));
    if (!key)
        return 0;

    return bee2_bign_export_params(
        key, (key->has_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY : 0) |
             (key->has_pub ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY : 0),
        export_cb, export_cbarg);
}


static int decode_private_selection(void *provctx, int selection)
{
    (void)provctx;
    return selection == 0 || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
}

#define BIGN_DECODER(NAME, KIND, SELECT) \
    static void *NAME##_new(void *provctx) \
    { \
        return decoder_new(provctx, KIND); \
    } \
    const OSSL_DISPATCH NAME##_functions[] = { \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))NAME##_new}, \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_decoder_freectx}, \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))SELECT}, \
        {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))bign_decoder_set_ctx_params}, \
        {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))bign_decoder_settable_ctx_params}, \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))bee2_bign_asn1_decoder_decode}, \
        {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))bign_decoder_export_object}, \
        {0, NULL} \
    }

BIGN_DECODER(bee2_bign_pkcs8_decoder, BIGN_DECODE_PRIVATE, decode_private_selection);
BIGN_DECODER(bee2_bign_spki_decoder, BIGN_DECODE_PUBLIC, select_public);
static int decode_any_selection(void *provctx, int selection)
{
    (void)provctx;
    (void)selection;
    return 1;
}

BIGN_DECODER(bee2_stb_epki_decoder, BIGN_DECODE_DER, decode_any_selection);
BIGN_DECODER(bee2_stb_pem_decoder, BIGN_DECODE_PEM, decode_any_selection);
