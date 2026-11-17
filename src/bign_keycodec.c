#include "bee2_oids.h"
#include "bign_common.h"
#include "bign_asn1.h"
#include "bign_stb_pbes2.h"

#include <limits.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <string.h>

#define BIGN_PEM_LABEL "PRIVATE KEY"
#define BIGN_ENCRYPTED_PEM_LABEL "ENCRYPTED PRIVATE KEY"
#define BIGN_PUB_PEM_LABEL "PUBLIC KEY"

/* ASN.1 and PKCS#8 serialization live in bign_asn1.c. The STB
 * decoder enforces an application-adjustable PBKDF2 work limit. */

typedef struct {
    const bee2_bign_variant_t *variant;
    OSSL_LIB_CTX *libctx;
    int output_pem;
    EVP_CIPHER *cipher; /* Only used for OpenSSL PBES2 ciphers. */
    size_t kwp_key_len;
    int encrypt;
    unsigned int pbkdf2_iterations;
    size_t pbkdf2_salt_len;
} bee2_bign_encoder_ctx_t;

static int write_all(BIO *bio, const void *data, size_t len) {
    const unsigned char *p = data;

    while (len > 0) {
        size_t chunk = len > INT_MAX ? (size_t)INT_MAX : len;
        size_t written = 0;

        if (!BIO_write_ex(bio, p, chunk, &written) || written == 0)
            return 0;
        p += written;
        len -= written;
    }
    return 1;
}

static unsigned char *encrypt_pkcs8_der(const unsigned char *der, size_t der_len,
                                         const bee2_bign_encoder_ctx_t *ctx,
                                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg,
                                        size_t *out_len) {
    unsigned char *out = NULL;
    char password[PEM_BUFSIZE];
    size_t password_len = 0;
    size_t key_len;

    if (!ctx || !ctx->encrypt || !cb || !out_len)
        return NULL;
    *out_len = 0;
    key_len = ctx->kwp_key_len;
    OPENSSL_cleanse(password, sizeof(password));
    if (cb(password, sizeof(password), &password_len, NULL, cbarg) &&
        password_len <= sizeof(password)) {
        if (key_len != 0)
            out = bee2_stb_pbes2_encrypt(der, der_len, (const unsigned char *)password,
                                         password_len, key_len, ctx->pbkdf2_iterations,
                                         ctx->pbkdf2_salt_len, ctx->libctx, out_len);
        else
            out = bee2_bign_asn1_encrypt_standard_pkcs8(
                der, der_len, (const unsigned char *)password, password_len,
                ctx->cipher, ctx->pbkdf2_iterations, ctx->pbkdf2_salt_len,
                ctx->libctx, out_len);
    }
    OPENSSL_cleanse(password, sizeof(password));
    return out;
}

static void *bign_encoder_newctx_common(const bee2_bign_variant_t *variant,
                                        int output_pem,
                                        void *provctx) {
    bee2_bign_encoder_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->variant = variant;
    ctx->libctx = bee2_provider_libctx(provctx);
    ctx->output_pem = output_pem;
    ctx->kwp_key_len = 32; /* Default when encryption is explicitly requested. */
    ctx->pbkdf2_iterations = BEE2_STB_PBKDF2_MIN_ITER;
    ctx->pbkdf2_salt_len = BEE2_STB_PBKDF2_DEFAULT_SALT;
    return ctx;
}

static void bign_encoder_freectx(void *vctx) {
    bee2_bign_encoder_ctx_t *ctx = vctx;

    if (ctx) {
        EVP_CIPHER_free(ctx->cipher);
        OPENSSL_free(ctx);
    }
}

static const OSSL_PARAM bee2_bign_encoder_settable[] = {
    OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint(BEE2_STB_PBKDF2_PARAM_ITER, NULL),
    OSSL_PARAM_size_t(BEE2_STB_PBKDF2_PARAM_SALTLEN, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bign_encoder_settable_ctx_params(void *provctx) {
    (void)provctx;
    return bee2_bign_encoder_settable;
}

static int bign_encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bign_encoder_ctx_t *ctx = vctx;
    const OSSL_PARAM *param, *properties, *iter_param, *salt_param;
    const char *cipher_name = NULL;
    const char *propq = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned int iterations;
    size_t salt_len;

    if (!params)
        return 1;
    iterations = ctx->pbkdf2_iterations;
    salt_len = ctx->pbkdf2_salt_len;
    iter_param = OSSL_PARAM_locate_const(params, BEE2_STB_PBKDF2_PARAM_ITER);
    salt_param = OSSL_PARAM_locate_const(params, BEE2_STB_PBKDF2_PARAM_SALTLEN);
    if ((iter_param && (!OSSL_PARAM_get_uint(iter_param, &iterations) ||
                        iterations < BEE2_STB_PBKDF2_MIN_ITER || iterations > INT_MAX)) ||
        (salt_param && (!OSSL_PARAM_get_size_t(salt_param, &salt_len) ||
                        salt_len < BEE2_STB_PBKDF2_MIN_SALT || salt_len > INT_MAX)))
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    if (param != NULL) {
        if (!OSSL_PARAM_get_utf8_string_ptr(param, &cipher_name))
            return 0;
        properties = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);
        if (properties && !OSSL_PARAM_get_utf8_string_ptr(properties, &propq))
            return 0;
        size_t kwp_len = 0;

        /* "default" requests the STB profile without choosing a key size. */
        if (cipher_name && OPENSSL_strcasecmp(cipher_name, "default") == 0)
            cipher_name = "belt-kwp256";
        if (cipher_name && (cipher = EVP_CIPHER_fetch(ctx->libctx, cipher_name, propq)) == NULL)
            return 0;
        if (cipher) {
            if (EVP_CIPHER_is_a(cipher, "belt-kwp128") ||
                EVP_CIPHER_is_a(cipher, "belt-kwp192") ||
                EVP_CIPHER_is_a(cipher, "belt-kwp256")) {
                kwp_len = (size_t)EVP_CIPHER_get_key_length(cipher);
            } else if (EVP_CIPHER_get_mode(cipher) != EVP_CIPH_CBC_MODE ||
                       EVP_CIPHER_get_nid(cipher) == NID_undef ||
                       EVP_CIPHER_get_iv_length(cipher) <= 0) {
                EVP_CIPHER_free(cipher);
                return 0;
            }
        }
        EVP_CIPHER_free(ctx->cipher);
        ctx->encrypt = cipher != NULL;
        ctx->kwp_key_len = kwp_len;
        ctx->cipher = kwp_len == 0 ? cipher : NULL;
        if (kwp_len != 0)
            EVP_CIPHER_free(cipher);
    }
    ctx->pbkdf2_iterations = iterations;
    ctx->pbkdf2_salt_len = salt_len;
    return 1;
}

static int bign_encoder_does_selection(void *provctx, int selection) {
    (void)provctx;
    if (selection == 0)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return 1;
    return 0;
}

static int bign_encoder_encode(void *vctx,
                               OSSL_CORE_BIO *out,
                               const void *obj_raw,
                               const OSSL_PARAM obj_abstract[],
                               int selection,
                               OSSL_PASSPHRASE_CALLBACK *cb,
                               void *cbarg) {
    (void)obj_abstract;

    if (!(selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY))) {
        ERR_raise_data(ERR_LIB_PROV,
                       ERR_R_PASSED_INVALID_ARGUMENT,
                       "bign_encoder_encode: selection=%d",
                       selection);
        return 0;
    }
    if (!obj_raw) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "bign_encoder_encode: obj_raw is null");
        return 0;
    }

    const bee2_bign_key_t *key = obj_raw;
    bee2_bign_encoder_ctx_t *ctx = vctx;
    if (!ctx || !key->variant) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "bign_encoder_encode: missing ctx/variant");
        return 0;
    }
    if (ctx->variant && ctx->variant != key->variant) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "bign_encoder_encode: variant mismatch");
        return 0;
    }
    size_t der_len = 0;
    unsigned char *der = NULL;
    const char *label = BIGN_PEM_LABEL;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!key->has_priv) {
            ERR_raise_data(
                ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "bign_encoder_encode: no private key");
            return 0;
        }
        der = bee2_bign_asn1_encode_pkcs8_der(key, &der_len);
        label = BIGN_PEM_LABEL;
        if (der && ctx->encrypt) {
            unsigned char *encrypted;
            size_t encrypted_len = 0;

            encrypted = encrypt_pkcs8_der(der, der_len, ctx,
                                          cb, cbarg, &encrypted_len);
            OPENSSL_clear_free(der, der_len);
            der = encrypted;
            der_len = encrypted_len;
            label = BIGN_ENCRYPTED_PEM_LABEL;
        }
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        der = bee2_bign_asn1_encode_spki_der(key, &der_len);
        label = BIGN_PUB_PEM_LABEL;
    }
    if (!der) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "bign_encoder_encode: key encoding failed");
        return 0;
    }

    int ok = 0;
    BIO *bio = BIO_new_from_core_bio(ctx->libctx, out);

    if (bio != NULL) {
        if (ctx->output_pem) {
            if (der_len <= LONG_MAX)
                ok = PEM_write_bio(bio, label, NULL, der, (long)der_len);
        } else {
            ok = write_all(bio, der, der_len);
        }
        BIO_free(bio);
    }
    if (!ok) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "bign_encoder_encode: write failed");
    }

    OPENSSL_cleanse(der, der_len);
    OPENSSL_free(der);
    return ok;
}

static void *bign_encoder_import_object(void *vctx, int selection, const OSSL_PARAM params[]) {
    const bee2_bign_encoder_ctx_t *ctx = vctx;
    bee2_bign_key_t *key;

    if (ctx == NULL || params == NULL ||
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME) == NULL)
        return NULL;
    key = bee2_bign_key_new(ctx->variant);
    if (key == NULL)
        return NULL;
    if (!bee2_bign_import_params(key, selection, params)) {
        bee2_bign_key_free(key);
        return NULL;
    }
    return key;
}

static void bign_encoder_free_object(void *obj) {
    bee2_bign_key_free(obj);
}

static void *bign_decoder_newctx_common(const bee2_bign_variant_t *variant, void *provctx) {
    bee2_bign_decoder_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (!ctx)
        return NULL;
    ctx->variant = variant;
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
        max_iterations < BEE2_STB_PBKDF2_MIN_ITER || max_iterations > INT_MAX)
        return 0;
    ctx->max_pbkdf2_iterations = max_iterations;
    return 1;
}

static int bign_decoder_does_selection(void *provctx, int selection) {
    (void)provctx;
    if (selection == 0)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 1;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return 1;
    return 0;
}

static int bign_decoder_export_object(void *vctx,
                                      const void *objref,
                                      size_t objref_sz,
                                      OSSL_CALLBACK *export_cb,
                                      void *export_cbarg) {
    bee2_bign_decoder_ctx_t *ctx = vctx;
    bee2_bign_key_t *key = NULL;

    if (!ctx || !objref || !export_cb || objref_sz != sizeof(key))
        return 0;
    memcpy(&key, objref, sizeof(key));
    if (!key || (ctx->variant && key->variant != ctx->variant))
        return 0;

    return bee2_bign_export_params(
        key, (key->has_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY : 0) |
             (key->has_pub ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY : 0),
        export_cb, export_cbarg);
}


#define BIGN_CODEC_NEWCTX(BITS) \
    static void *bign##BITS##_pem_encoder_newctx(void *provctx) { \
        return bign_encoder_newctx_common(bee2_bign_variant_##BITS(), 1, provctx); \
    } \
    static void *bign##BITS##_der_encoder_newctx(void *provctx) { \
        return bign_encoder_newctx_common(bee2_bign_variant_##BITS(), 0, provctx); \
    }

BIGN_CODEC_NEWCTX(256)
BIGN_CODEC_NEWCTX(384)
BIGN_CODEC_NEWCTX(512)

static void *bign_decoder_newctx(void *provctx) {
    return bign_decoder_newctx_common(NULL, provctx);
}

static void *bign_stb_pem_newctx(void *provctx) {
    bee2_bign_decoder_ctx_t *ctx = bign_decoder_newctx_common(NULL, provctx);

    if (ctx)
        ctx->input_pem = 1;
    return ctx;
}

static void *bign_pem_encoder_newctx(void *provctx) {
    return bign_encoder_newctx_common(NULL, 1, provctx);
}

static void *bign_der_encoder_newctx(void *provctx) {
    return bign_encoder_newctx_common(NULL, 0, provctx);
}

#define BIGN_ENCODER_DISPATCH(BITS, FORMAT) \
    const OSSL_DISPATCH bee2_bign_##BITS##_##FORMAT##_encoder_functions[] = { \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign##BITS##_##FORMAT##_encoder_newctx}, \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_encoder_freectx}, \
        {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))bign_encoder_set_ctx_params}, \
        {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, \
         (void (*)(void))bign_encoder_settable_ctx_params}, \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_encoder_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_encoder_encode}, \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))bign_encoder_import_object}, \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))bign_encoder_free_object}, \
        {0, NULL}};

BIGN_ENCODER_DISPATCH(256, pem)
BIGN_ENCODER_DISPATCH(256, der)
BIGN_ENCODER_DISPATCH(384, pem)
BIGN_ENCODER_DISPATCH(384, der)
BIGN_ENCODER_DISPATCH(512, pem)
BIGN_ENCODER_DISPATCH(512, der)

const OSSL_DISPATCH bee2_bign_pem_encoder_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign_pem_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))bign_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))bign_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_encoder_encode},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))bign_encoder_import_object},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))bign_encoder_free_object},
    {0, NULL}};

const OSSL_DISPATCH bee2_bign_der_encoder_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign_der_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))bign_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))bign_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_encoder_encode},
    {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))bign_encoder_import_object},
    {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))bign_encoder_free_object},
    {0, NULL}};

const OSSL_DISPATCH bee2_stb_epki_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))bign_decoder_newctx},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))bign_decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
     (void (*)(void))bign_decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_decoder_freectx},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))bee2_bign_asn1_stb_epki_decode},
    {0, NULL}};

const OSSL_DISPATCH bee2_stb_pem_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))bign_stb_pem_newctx},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))bign_decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
     (void (*)(void))bign_decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_decoder_freectx},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))bee2_bign_asn1_stb_epki_decode},
    {0, NULL}};

const OSSL_DISPATCH bee2_bign_decoder_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))bign_decoder_newctx},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))bign_decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
     (void (*)(void))bign_decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))bign_decoder_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))bee2_bign_asn1_decoder_decode},
    {OSSL_FUNC_DECODER_EXPORT_OBJECT, (void (*)(void))bign_decoder_export_object},
    {0, NULL}};
