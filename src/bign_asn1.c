/* BIGN ASN.1 key payloads and PBES2 serialization. */
#include "bign_asn1.h"
#include "bign_der_frame.h"
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"
#include "provider_util.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

int bign_der_sequence_body(const unsigned char *data, size_t length,
                                  const unsigned char **body)
{
    const unsigned char *p = data;
    long body_length = 0;
    int tag = 0;
    int xclass = 0;
    int status;

    if (data == NULL || body == NULL || length == 0 ||
        length > BIGN_MAX_KEY_INPUT || length > LONG_MAX)
        return 0;

    status = ASN1_get_object(&p, &body_length, &tag, &xclass, (long)length);
    if ((status & 0x81) != 0 || (status & V_ASN1_CONSTRUCTED) == 0 ||
        tag != V_ASN1_SEQUENCE || xclass != V_ASN1_UNIVERSAL ||
        body_length < 0 || (size_t)body_length != (size_t)(data + length - p))
        return 0;

    *body = p;
    return 1;
}


/* Identify DER key envelopes before invoking ASN.1 decoders. In particular,
 * SPKI must not be speculatively decoded as PKCS#8: failed d2i calls leave
 * errors on the application's OpenSSL error queue. */
typedef enum {
    BIGN_DER_UNKNOWN,
    BIGN_DER_PRIVATE,
    BIGN_DER_ENCRYPTED,
    BIGN_DER_PUBLIC
} BIGN_DER_KIND;

static BIGN_DER_KIND bign_der_kind(const unsigned char *der, size_t len)
{
    const unsigned char *p, *end;
    long alg_len;
    int tag, xclass, status;

    if (!bign_der_sequence_body(der, len, &p))
        return BIGN_DER_UNKNOWN;
    end = der + len;
    if (p == end)
        return BIGN_DER_UNKNOWN;
    if (*p == V_ASN1_INTEGER)
        return BIGN_DER_PRIVATE;
    if (*p != (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE))
        return BIGN_DER_UNKNOWN;

    status = ASN1_get_object(&p, &alg_len, &tag, &xclass, (long)(end - p));
    if ((status & 0x81) != 0 || tag != V_ASN1_SEQUENCE ||
        xclass != V_ASN1_UNIVERSAL || alg_len < 0 ||
        (size_t)alg_len >= (size_t)(end - p))
        return BIGN_DER_UNKNOWN;
    p += alg_len;
    if (*p == V_ASN1_OCTET_STRING)
        return BIGN_DER_ENCRYPTED;
    if (*p == V_ASN1_BIT_STRING)
        return BIGN_DER_PUBLIC;
    return BIGN_DER_UNKNOWN;
}


static size_t asn_length(const ASN1_STRING *value)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(value);
#else
    int n = ASN1_STRING_length(value);
    return n >= 0 ? (size_t)n : SIZE_MAX;
#endif
}

static int bign_asn1_string_set(ASN1_STRING *str, const unsigned char *data, int len) {
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    if (len < 0)
        return 0;
    return ASN1_STRING_set1_data(str, data, (size_t)len);
#else
    return ASN1_STRING_set(str, data, len);
#endif
}

/* OpenSSL describes the optional STB fields; Bee2 encodes, decodes and
 * validates the ECParameters payload itself. */
typedef struct {
    ASN1_OBJECT *fieldType;
    ASN1_INTEGER *prime;
} BIGN_FIELDID;

typedef struct {
    ASN1_OCTET_STRING *a;
    ASN1_OCTET_STRING *b;
    ASN1_BIT_STRING *seed;
} BIGN_CURVE;

typedef struct {
    long version;
    BIGN_FIELDID *fieldID;
    BIGN_CURVE *curve;
    ASN1_OCTET_STRING *base;
    ASN1_INTEGER *order;
    ASN1_INTEGER *cofactor;
} BIGN_ECPARAMS;

DECLARE_ASN1_ITEM(BIGN_FIELDID)
DECLARE_ASN1_ITEM(BIGN_CURVE)
DECLARE_ASN1_ITEM(BIGN_ECPARAMS)

ASN1_SEQUENCE(BIGN_FIELDID) = {
    ASN1_SIMPLE(BIGN_FIELDID, fieldType, ASN1_OBJECT),
    ASN1_SIMPLE(BIGN_FIELDID, prime, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_FIELDID)

ASN1_SEQUENCE(BIGN_CURVE) = {
    ASN1_SIMPLE(BIGN_CURVE, a, ASN1_OCTET_STRING),
    ASN1_SIMPLE(BIGN_CURVE, b, ASN1_OCTET_STRING),
    ASN1_SIMPLE(BIGN_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(BIGN_CURVE)

ASN1_SEQUENCE(BIGN_ECPARAMS) = {
    ASN1_SIMPLE(BIGN_ECPARAMS, version, LONG),
    ASN1_SIMPLE(BIGN_ECPARAMS, fieldID, BIGN_FIELDID),
    ASN1_SIMPLE(BIGN_ECPARAMS, curve, BIGN_CURVE),
    ASN1_SIMPLE(BIGN_ECPARAMS, base, ASN1_OCTET_STRING),
    ASN1_SIMPLE(BIGN_ECPARAMS, order, ASN1_INTEGER),
    ASN1_OPT(BIGN_ECPARAMS, cofactor, ASN1_INTEGER)
} ASN1_SEQUENCE_END(BIGN_ECPARAMS)

DECLARE_ASN1_FUNCTIONS(BIGN_ECPARAMS)
IMPLEMENT_ASN1_FUNCTIONS(BIGN_ECPARAMS)

static int oid_equals(const ASN1_OBJECT *obj, const char *oid)
{
    char buf[80];
    int n;

    if (!obj)
        return 0;
    n = OBJ_obj2txt(buf, sizeof(buf), obj, 1);
    return n > 0 && n < (int)sizeof(buf) && strcmp(buf, oid) == 0;
}

static const bee2_bign_variant_t *variant_from_curve_obj(const ASN1_OBJECT *obj)
{
    const bee2_bign_variant_t *variants[] = {
        bee2_bign_variant_256(), bee2_bign_variant_384(),
        bee2_bign_variant_512()
    };
    size_t i;

    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i)
        if (oid_equals(obj, variants[i]->curve_oid))
            return variants[i];
    return NULL;
}


static const bee2_bign_variant_t *variant_from_domain_params(
    const ASN1_STRING *params, int *cofactor_encoding)
{
    const bee2_bign_variant_t *variant = NULL;
    const unsigned char *data, *p;
    BIGN_ECPARAMS *ecp = NULL;
    const unsigned char *body;
    bign_params parsed, standard;
    size_t length, bytes;

    data = ASN1_STRING_get0_data(params);
    length = asn_length(params);
    if (data == NULL || length == 0 || length > INT_MAX ||
        !bign_der_sequence_body(data, length, &body))
        return NULL;
    p = data;
    ecp = d2i_BIGN_ECPARAMS(NULL, &p, (long)length);
    /* Validate the OID with OpenSSL before using Bee2's fixed-OID DER
     * decoder. Malformed OIDs must not reach its string comparator. */
    if (ecp == NULL || p != data + length || ecp->fieldID == NULL ||
        !oid_equals(ecp->fieldID->fieldType, BEE2_OID_BIGN_PRIMEFIELD) ||
        ecp->curve == NULL)
        goto end;
    if (ecp->cofactor != NULL && ASN1_INTEGER_get(ecp->cofactor) != 1)
        goto end;
    if (bignParamsDec(&parsed, data, length) != ERR_OK)
        goto end;
    switch (parsed.l) {
    case 128: variant = bee2_bign_variant_256(); break;
    case 192: variant = bee2_bign_variant_384(); break;
    case 256: variant = bee2_bign_variant_512(); break;
    default: goto end;
    }
    if (!bee2_bign_curve_init_std(variant, &standard)) {
        variant = NULL;
        goto end;
    }
    bytes = bee2_bign_priv_len(variant);
    if (memcmp(parsed.p, standard.p, bytes) != 0 ||
        memcmp(parsed.a, standard.a, bytes) != 0 ||
        memcmp(parsed.b, standard.b, bytes) != 0 ||
        memcmp(parsed.yG, standard.yG, bytes) != 0 ||
        memcmp(parsed.q, standard.q, bytes) != 0 ||
        memcmp(parsed.seed, standard.seed, sizeof(parsed.seed)) != 0)
        variant = NULL;
    if (variant != NULL && cofactor_encoding != NULL)
        *cofactor_encoding = ecp->cofactor != NULL;
end:
    BIGN_ECPARAMS_free(ecp);
    bee2_bign_cleanse(&parsed, sizeof(parsed));
    bee2_bign_cleanse(&standard, sizeof(standard));
    return variant;
}

static const bee2_bign_variant_t *variant_from_alg_params(
    int ptype, const void *pval, int *explicit_encoding,
    int *cofactor_encoding)
{
    const bee2_bign_variant_t *variant = NULL;

    if (explicit_encoding != NULL)
        *explicit_encoding = 0;
    if (cofactor_encoding != NULL)
        *cofactor_encoding = 0;
    if (ptype == V_ASN1_OBJECT && pval != NULL)
        return variant_from_curve_obj((const ASN1_OBJECT *)pval);
    if (ptype == V_ASN1_SEQUENCE && pval != NULL) {
        variant = variant_from_domain_params((const ASN1_STRING *)pval,
                                             cofactor_encoding);
        if (variant != NULL && explicit_encoding != NULL)
            *explicit_encoding = 1;
    }
    return variant;
}

static ASN1_STRING *encode_explicit_domain_params(const bee2_bign_key_t *key)
{
    bign_params curve;
    unsigned char *der = NULL, *with_cofactor = NULL;
    const unsigned char *p;
    BIGN_ECPARAMS *ecp = NULL;
    ASN1_STRING *sequence = NULL;
    size_t n = 0;
    int length;

    if (!key || !key->variant || !bee2_bign_curve_init_std(key->variant, &curve) ||
        bignParamsEnc(NULL, &n, &curve) != ERR_OK || n > INT_MAX)
        goto end;
    der = OPENSSL_malloc(n);
    if (der == NULL || bignParamsEnc(der, &n, &curve) != ERR_OK)
        goto end;
    if (key->encode_cofactor) {
        p = der;
        ecp = d2i_BIGN_ECPARAMS(NULL, &p, (long)n);
        if (ecp == NULL || p != der + n || ecp->cofactor != NULL)
            goto end;
        ecp->cofactor = ASN1_INTEGER_new();
        if (ecp->cofactor == NULL || !ASN1_INTEGER_set(ecp->cofactor, 1))
            goto end;
        length = i2d_BIGN_ECPARAMS(ecp, &with_cofactor);
        if (length <= 0)
            goto end;
        n = (size_t)length;
    }
    sequence = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (sequence == NULL ||
        !bign_asn1_string_set(sequence, with_cofactor ? with_cofactor : der, (int)n)) {
        ASN1_STRING_free(sequence);
        sequence = NULL;
    }
end:
    BIGN_ECPARAMS_free(ecp);
    OPENSSL_free(with_cofactor);
    OPENSSL_free(der);
    bee2_bign_cleanse(&curve, sizeof(curve));
    return sequence;
}

static int bign_encode_algorithm_params(const bee2_bign_key_t *key,
                                        int *parameter_type, void **parameter_value)
{
    if (!key || !key->variant || !parameter_type || !parameter_value)
        return 0;
    if (key->encode_explicit) {
        *parameter_type = V_ASN1_SEQUENCE;
        *parameter_value = encode_explicit_domain_params(key);
    } else {
        *parameter_type = V_ASN1_OBJECT;
        *parameter_value = OBJ_txt2obj(key->variant->curve_oid, 1);
    }
    return *parameter_value != NULL;
}

static void bign_free_algorithm_params(int parameter_type, void *parameter_value)
{
    if (parameter_type == V_ASN1_OBJECT)
        ASN1_OBJECT_free(parameter_value);
    else if (parameter_type == V_ASN1_SEQUENCE)
        ASN1_STRING_free(parameter_value);
}

/* PKCS#8 construction is shared by key encoding and STB scalar unwrap. */
static PKCS8_PRIV_KEY_INFO *bign_make_pkcs8(const unsigned char *scalar,
                                            const bee2_bign_variant_t *variant,
                                            int explicit_params, int cofactor)
{
    bee2_bign_key_t encoding = {0};
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *alg = NULL;
    void *parameters = NULL;
    unsigned char *priv = NULL;
    size_t priv_len;
    int parameter_type = V_ASN1_UNDEF;

    encoding.variant = variant;
    encoding.encode_explicit = explicit_params;
    encoding.encode_cofactor = cofactor;
    priv_len = bee2_bign_priv_len(variant);
    priv = OPENSSL_memdup(scalar, priv_len);
    p8 = PKCS8_PRIV_KEY_INFO_new();
    alg = OBJ_txt2obj(BEE2_OID_BIGN_PUBKEY, 1);
    if (priv == NULL || p8 == NULL || alg == NULL ||
        !bign_encode_algorithm_params(&encoding, &parameter_type, &parameters) ||
        !PKCS8_pkey_set0(p8, alg, 0, parameter_type, parameters,
                         priv, (int)priv_len)) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        p8 = NULL;
    } else {
        alg = NULL;
        parameters = NULL;
        priv = NULL;
    }
    ASN1_OBJECT_free(alg);
    bign_free_algorithm_params(parameter_type, parameters);
    OPENSSL_clear_free(priv, priv_len);
    return p8;
}

unsigned char *bee2_bign_asn1_encode_pkcs8_der(const bee2_bign_key_t *key,
                                                size_t *out_len)
{
    PKCS8_PRIV_KEY_INFO *p8;
    unsigned char *der = NULL;
    int len;

    if (key == NULL || key->variant == NULL || !key->has_priv || out_len == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "encode_pkcs8_der: invalid key");
        return NULL;
    }
    *out_len = 0;
    p8 = bign_make_pkcs8(key->priv, key->variant,
                          key->encode_explicit, key->encode_cofactor);
    if (p8 == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "encode_pkcs8_der: PKCS#8 construction failed");
        return NULL;
    }
    len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (len <= 0) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                       "encode_pkcs8_der: DER encoding failed");
        OPENSSL_free(der);
        return NULL;
    }
    *out_len = (size_t)len;
    return der;
}



static int decode_pkcs8_info(PKCS8_PRIV_KEY_INFO *p8,
                             const bee2_bign_variant_t *expected, bee2_bign_key_t *key) {
    const ASN1_OBJECT *alg = NULL;
    const unsigned char *priv = NULL;
    const X509_ALGOR *palg = NULL;
    const void *pval = NULL;
    const bee2_bign_variant_t *variant;
    int priv_len = 0, ptype = 0;
    size_t need;

    if (!p8 || !key || !PKCS8_pkey_get0(&alg, &priv, &priv_len, &palg, p8) ||
        !oid_equals(alg, BEE2_OID_BIGN_PUBKEY))
        return 0;
    X509_ALGOR_get0(NULL, &ptype, &pval, palg);
    variant = variant_from_alg_params(ptype, pval, &key->encode_explicit, &key->encode_cofactor);
    if (!variant || (expected && variant != expected))
        return 0;
    need = bee2_bign_priv_len(variant);
    if (priv == NULL || priv_len != (int)need)
        return 0;

    key->variant = variant;
    memcpy(key->priv, priv, need);
    key->has_priv = 1;
    if (!bee2_bign_derive_pubkey(variant, key->pub, key->priv))
        return 0;
    key->has_pub = 1;
    return 1;
}

int bee2_bign_asn1_decode_pkcs8_der(const unsigned char *buf, size_t len,
                            const bee2_bign_variant_t *expected, bee2_bign_key_t *key) {
    const unsigned char *p = buf;
    PKCS8_PRIV_KEY_INFO *p8;
    ASN1_INTEGER *version;
    int ok = 0;

    if (!key || !bign_der_sequence_body(buf, len, &p))
        return 0;
    /* The STB BIGN key format uses PrivateKeyInfo version zero. Reject
     * OneAsymmetricKey v1 rather than silently ignoring its public key. */
    version = d2i_ASN1_INTEGER(NULL, &p, (long)(buf + len - p));
    if (version == NULL)
        return 0;
    ok = ASN1_INTEGER_get(version) == 0;
    ASN1_INTEGER_free(version);
    if (!ok)
        return 0;
    ok = 0;
    p = buf;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)len);
    if (!p8)
        return 0;
    if (p == buf + len)
        ok = decode_pkcs8_info(p8, expected, key);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return ok;
}

/* Read exactly one bounded DER object from a nonseekable core BIO. */
static int read_exact(BIO *bio, unsigned char *out, size_t len)
{
    while (len > 0) {
        size_t n = 0;

        if (!BIO_read_ex(bio, out, len, &n) || n == 0)
            return 0;
        out += n;
        len -= n;
    }
    return 1;
}

static int read_der_object(BIO *bio, unsigned char **out, size_t *len)
{
    unsigned char header[5];
    unsigned char *der = NULL;
    size_t headlen = 2, bodylen = 0, n = 0, i;
    unsigned int count;

    if (!BIO_read_ex(bio, header, 1, &n) || n == 0)
        return !BIO_should_retry(bio) && BIO_eof(bio) > 0;
    if (header[0] != 0x30 || !read_exact(bio, header + 1, 1))
        return 0;
    if (header[1] < 128) {
        bodylen = header[1];
    } else {
        count = header[1] & 127u;
        if (count == 0 || count > 3 ||
            !read_exact(bio, header + 2, count) || header[2] == 0)
            return 0;
        headlen += count;
        for (i = 0; i < count; ++i)
            bodylen = (bodylen << 8) | header[i + 2];
        if (bodylen < 128)
            return 0;
    }
    if (bodylen > BIGN_MAX_KEY_INPUT - headlen)
        return 0;
    der = OPENSSL_malloc(headlen + bodylen);
    if (der == NULL)
        return 0;
    memcpy(der, header, headlen);
    if (!read_exact(bio, der + headlen, bodylen)) {
        OPENSSL_clear_free(der, headlen + bodylen);
        return 0;
    }
    *out = der;
    *len = headlen + bodylen;
    return 1;
}

/* PEM decoding uses OpenSSL, but bound its raw input before the library
 * allocates the entire Base64-decoded object. The bound includes PEM text. */
#define BIGN_MAX_PEM_TEXT (BIGN_MAX_KEY_INPUT * 2u)

typedef struct {
    size_t bytes;
    int too_large;
} BIGN_PEM_LIMIT;

static long bign_pem_limit_callback(BIO *bio, int operation,
                                    const char *argp, size_t len,
                                    int argi, long argl, int ret,
                                    size_t *processed)
{
    BIGN_PEM_LIMIT *limit = (BIGN_PEM_LIMIT *)BIO_get_callback_arg(bio);

    (void)argp;
    (void)len;
    (void)argi;
    (void)argl;
    if ((operation & ~BIO_CB_RETURN) != BIO_CB_GETS)
        return ret;
    if (!(operation & BIO_CB_RETURN)) {
        if (limit->bytes >= BIGN_MAX_PEM_TEXT) {
            limit->too_large = 1;
            return 0;
        }
    } else if (ret > 0) {
        size_t bytes = processed != NULL ? *processed : (size_t)ret;

        if (bytes > BIGN_MAX_PEM_TEXT - limit->bytes) {
            limit->too_large = 1;
            return 0;
        }
        limit->bytes += bytes;
    }
    return ret;
}

typedef struct {
    unsigned char *der;
    size_t der_len;
    size_t der_alloc_len;
    char *pem_name;
} BIGN_INPUT;

typedef struct {
    OSSL_PASSPHRASE_CALLBACK *callback;
    void *callback_arg;
} BIGN_PEM_PASSWORD;

static int bign_pem_password(char *buf, int size, int rwflag, void *arg)
{
    BIGN_PEM_PASSWORD *password = arg;
    size_t len = 0;

    (void)rwflag;
    if (size <= 0 || password->callback == NULL ||
        !password->callback(buf, (size_t)size, &len, NULL,
                            password->callback_arg) ||
        len > (size_t)size || len > INT_MAX)
        return -1;
    return (int)len;
}

static int bign_read_input(bee2_bign_decoder_ctx_t *ctx,
                           OSSL_CORE_BIO *in, BIGN_INPUT *input,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    BIO *bio = BIO_new_from_core_bio(ctx->libctx, in);
    char *header = NULL;
    long len = 0;
    BIGN_PEM_LIMIT limit = {0};
    BIGN_PEM_PASSWORD password = {pw_cb, pw_cbarg};
    int ok = 0;

    if (bio == NULL)
        return 0;
    if (ctx->input_pem) {
        BIO_set_callback_arg(bio, (char *)&limit);
        BIO_set_callback_ex(bio, bign_pem_limit_callback);
        /* Keep the standard OpenSSL PEM parser, not a custom Base64 parser. */
        if (PEM_read_bio(bio, &input->pem_name, &header, &input->der, &len) > 0) {
            if (len > 0)
                input->der_len = input->der_alloc_len = (size_t)len;
            ok = len > 0 && (size_t)len <= BIGN_MAX_KEY_INPUT;
            if (ok && header != NULL && strlen(header) > 10) {
                EVP_CIPHER_INFO cipher_info;

                if (!PEM_get_EVP_CIPHER_INFO(header, &cipher_info) ||
                    !PEM_do_header(&cipher_info, input->der, &len,
                                   bign_pem_password, &password)) {
                    ok = 0;
                } else if (len < 0 || (size_t)len > input->der_alloc_len) {
                    ok = 0;
                } else {
                    input->der_len = (size_t)len;
                }
            }
        } else {
            ok = !BIO_should_retry(bio) && BIO_eof(bio) > 0;
        }
        BIO_set_callback_ex(bio, NULL);
        if (limit.too_large)
            ok = 0;
    } else {
        ok = read_der_object(bio, &input->der, &input->der_len);
        input->der_alloc_len = input->der_len;
    }
    OPENSSL_free(header);
    BIO_free(bio);
    return ok;
}

static void bign_free_input(BIGN_INPUT *input)
{
    /* Traditional encrypted PEM is decrypted in place. Padding removal
     * reduces der_len but must not reduce the region cleansed on free. */
    OPENSSL_clear_free(input->der, input->der_alloc_len);
    OPENSSL_free(input->pem_name);
}


unsigned char *bee2_bign_asn1_encode_spki_der(const bee2_bign_key_t *key, size_t *out_len) {
    X509_PUBKEY *xpk = NULL;
    ASN1_OBJECT *alg = NULL;
    void *parameters = NULL;
    int parameter_type = V_ASN1_UNDEF;
    unsigned char *pub = NULL;
    unsigned char *der = NULL;
    size_t pub_len = 0;

    if (!key || !key->variant || !out_len) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "encode_spki_der: invalid key");
        return NULL;
    }
    *out_len = 0;

    pub_len = bee2_bign_pub_len(key->variant);
    pub = OPENSSL_malloc(pub_len);
    if (!pub) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE, "encode_spki_der: alloc pub");
        return NULL;
    }
    if (key->has_pub) {
        memcpy(pub, key->pub, pub_len);
    } else if (key->has_priv) {
        if (!bee2_bign_derive_pubkey(key->variant, pub, key->priv)) {
            ERR_raise_data(
                ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_spki_der: derive pub failed");
            OPENSSL_free(pub);
            return NULL;
        }
    } else {
        OPENSSL_free(pub);
        return NULL;
    }

    xpk = X509_PUBKEY_new();
    if (!xpk) {
        OPENSSL_free(pub);
        return NULL;
    }

    alg = OBJ_txt2obj(BEE2_OID_BIGN_PUBKEY, 1);
    if (!alg || !bign_encode_algorithm_params(key, &parameter_type, &parameters)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_spki_der: OBJ_txt2obj failed");
        goto err;
    }

    if (!X509_PUBKEY_set0_param(xpk, alg, parameter_type, parameters, pub, (int)pub_len)) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_spki_der: X509_PUBKEY_set0_param failed");
        goto err;
    }
    alg = NULL;
    parameters = NULL;
    pub = NULL;

    int der_len = i2d_X509_PUBKEY(xpk, &der);
    if (der_len <= 0) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_spki_der: i2d_X509_PUBKEY failed");
        goto err;
    }
    *out_len = (size_t)der_len;

    X509_PUBKEY_free(xpk);
    return der;

err:
    if (alg)
        ASN1_OBJECT_free(alg);
    bign_free_algorithm_params(parameter_type, parameters);
    if (pub)
        OPENSSL_free(pub);
    X509_PUBKEY_free(xpk);
    return NULL;
}

int bee2_bign_asn1_decode_spki_der(const unsigned char *buf,
                           size_t len,
                           const bee2_bign_variant_t *expected,
                           bee2_bign_key_t *key) {
    const unsigned char *p = buf;

    X509_ALGOR *alg = NULL;
    ASN1_BIT_STRING *bit = NULL;
    const ASN1_OBJECT *aobj = NULL;
    int ptype = 0;
    const void *pval = NULL;
    const bee2_bign_variant_t *variant = NULL;
    const unsigned char *pub = NULL;
    size_t pub_len;
    int ok = 0;

    if (!key || !bign_der_sequence_body(buf, len, &p))
        return 0;

    const unsigned char *seq_end = buf + len;

    alg = d2i_X509_ALGOR(NULL, &p, (long)(seq_end - p));
    if (!alg)
        goto cleanup;

    bit = d2i_ASN1_BIT_STRING(NULL, &p, (long)(seq_end - p));
    if (!bit || p != seq_end)
        goto cleanup;
#if OPENSSL_VERSION_MAJOR >= 4
    size_t bit_bytes = 0;
    int unused_bits = 0;
    if (!ASN1_BIT_STRING_get_length(bit, &bit_bytes, &unused_bits) ||
        unused_bits != 0 || bit_bytes > INT_MAX)
        goto cleanup;
#else
    if ((bit->flags & ASN1_STRING_FLAG_BITS_LEFT) != 0 &&
        (bit->flags & 7) != 0)
        goto cleanup;
#endif

    X509_ALGOR_get0(&aobj, &ptype, &pval, alg);
    if (!oid_equals(aobj, BEE2_OID_BIGN_PUBKEY))
        goto cleanup;

    variant = variant_from_alg_params(ptype, pval, &key->encode_explicit, &key->encode_cofactor);
    if (!variant)
        goto cleanup;
    if (expected && expected != variant)
        goto cleanup;

    pub = ASN1_STRING_get0_data((const ASN1_STRING *)bit);
    pub_len = asn_length((const ASN1_STRING *)bit);
    if (!pub || pub_len != bee2_bign_pub_len(variant))
        goto cleanup;

    key->variant = variant;
    memcpy(key->pub, pub, pub_len);
    key->has_pub = 1;
    ok = bee2_bign_key_validate_public(key);

cleanup:
    ASN1_BIT_STRING_free(bit);
    X509_ALGOR_free(alg);
    return ok;
}


/* Recognise the BIGN algorithm without decoding the key payload. */
static int bign_der_has_bign_oid(const unsigned char *der, size_t len)
{
    const unsigned char *p, *end;
    ASN1_INTEGER *version = NULL;
    X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *oid = NULL;
    int match = 0;

    if (!bign_der_sequence_body(der, len, &p) || p == der + len)
        return 0;
    end = der + len;
    if (*p != V_ASN1_INTEGER &&
        *p != (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE))
        return 0;

    ERR_set_mark();
    if (*p == V_ASN1_INTEGER) {
        version = d2i_ASN1_INTEGER(NULL, &p, (long)(end - p));
        if (version == NULL)
            goto end;
    }
    alg = d2i_X509_ALGOR(NULL, &p, (long)(end - p));
    if (alg != NULL) {
        X509_ALGOR_get0(&oid, NULL, NULL, alg);
        match = oid_equals(oid, BEE2_OID_BIGN_PUBKEY);
    }
end:
    ASN1_INTEGER_free(version);
    X509_ALGOR_free(alg);
    ERR_pop_to_mark();
    return match;
}

int bee2_bign_asn1_decoder_decode(void *vctx,
                                  OSSL_CORE_BIO *in, int selection,
                                  OSSL_CALLBACK *data_cb, void *data_cbarg,
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    bee2_bign_decoder_ctx_t *ctx = vctx;
    BIGN_INPUT input = {0};
    bee2_bign_key_t *key = NULL;
    BIGN_DER_KIND kind;
    int decoded = 0, ok = 0;

    (void)pw_cb;
    (void)pw_cbarg;
    if (ctx == NULL || data_cb == NULL)
        return 0;
    if (!bign_read_input(ctx, in, &input, pw_cb, pw_cbarg))
        goto end;
    if (input.der == NULL || input.der_len == 0) {
        ok = 1;
        goto end;
    }
    /* Skip foreign key types without allocating a key or attempting
     * full BIGN parsing. Invalid data with the BIGN OID is fatal. */
    if (!bign_der_has_bign_oid(input.der, input.der_len)) {
        ok = 1;
        goto end;
    }
    key = bee2_bign_key_new(NULL);
    if (key == NULL)
        goto end;

    kind = bign_der_kind(input.der, input.der_len);
    switch (kind) {
    case BIGN_DER_PRIVATE:
        decoded = bee2_bign_asn1_decode_pkcs8_der(input.der, input.der_len,
                                                   ctx->variant, key);
        break;
    case BIGN_DER_PUBLIC:
        decoded = bee2_bign_asn1_decode_spki_der(input.der, input.der_len,
                                                  ctx->variant, key);
        break;
    default:
        break;
    }
    if (!decoded)
        goto end;
    if (selection != 0) {
        if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_priv) ||
            ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !key->has_pub)) {
            ok = 1;
            goto end;
        }
        if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->has_priv) {
            OPENSSL_cleanse(key->priv, sizeof(key->priv));
            key->has_priv = 0;
        }
    }

    {
        int obj_type = OSSL_OBJECT_PKEY;
        char data_type[] = "bign";
        void *objref = key;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, data_type, 0),
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &objref, sizeof(objref)),
            OSSL_PARAM_construct_end()
        };

        ok = data_cb(params, data_cbarg);
    }
end:
    bee2_bign_key_free(key);
    bign_free_input(&input);
    return ok;
}


static int bign_emit_object(OSSL_CALLBACK *data_cb, void *data_cbarg,
                            int object_type, const char *name,
                            const char *structure,
                            const unsigned char *der, size_t der_len)
{
    OSSL_PARAM params[5], *param = params;

    if (name != NULL)
        *param++ = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)name, 0);
    if (structure != NULL)
        *param++ = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)structure, 0);
    *param++ = OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_DATA, (void *)der, der_len);
    *param++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    *param = OSSL_PARAM_construct_end();
    return data_cb(params, data_cbarg);
}

static int bign_emit_der(OSSL_CALLBACK *data_cb, void *data_cbarg,
                         const char *name, const char *structure,
                         const unsigned char *der, size_t der_len)
{
    return bign_emit_object(data_cb, data_cbarg, OSSL_OBJECT_PKEY,
                            name, structure, der, der_len);
}

/* Preserve PEM type information when forwarding to OpenSSL. Traditional
 * RSA/EC keys are not PKCS#8 PrivateKeyInfo structures. */
static int bign_forward_pem(OSSL_CALLBACK *cb, void *arg,
                            const BIGN_INPUT *input)
{
    static const struct {
        const char *label;
        const char *type;
        const char *structure;
        int object_type;
    } labels[] = {
        {"PRIVATE KEY", NULL, "PrivateKeyInfo", OSSL_OBJECT_PKEY},
        {"PUBLIC KEY", NULL, "SubjectPublicKeyInfo", OSSL_OBJECT_PKEY},
        {"RSA PRIVATE KEY", "RSA", "type-specific", OSSL_OBJECT_PKEY},
        {"RSA PUBLIC KEY", "RSA", "type-specific", OSSL_OBJECT_PKEY},
        {"EC PRIVATE KEY", "EC", "type-specific", OSSL_OBJECT_PKEY},
        {"EC PARAMETERS", "EC", "type-specific", OSSL_OBJECT_PKEY},
        {"DSA PRIVATE KEY", "DSA", "type-specific", OSSL_OBJECT_PKEY},
        {"DSA PUBLIC KEY", "DSA", "type-specific", OSSL_OBJECT_PKEY},
        {"DSA PARAMETERS", "DSA", "type-specific", OSSL_OBJECT_PKEY},
        {"DH PARAMETERS", "DH", "type-specific", OSSL_OBJECT_PKEY},
        {"X9.42 DH PARAMETERS", "X9.42 DH", "type-specific", OSSL_OBJECT_PKEY},
        {"SM2 PRIVATE KEY", "SM2", "type-specific", OSSL_OBJECT_PKEY},
        {"SM2 PARAMETERS", "SM2", "type-specific", OSSL_OBJECT_PKEY},
        {"CERTIFICATE", NULL, "Certificate", OSSL_OBJECT_CERT},
        {"TRUSTED CERTIFICATE", NULL, "Certificate", OSSL_OBJECT_CERT},
        {"X509 CERTIFICATE", NULL, "Certificate", OSSL_OBJECT_CERT},
        {"X509 CRL", NULL, "CertificateList", OSSL_OBJECT_CRL}
    };
    size_t i;

    for (i = 0; i < sizeof(labels) / sizeof(labels[0]); ++i) {
        if (strcmp(input->pem_name, labels[i].label) == 0)
            return bign_emit_object(cb, arg, labels[i].object_type,
                                    labels[i].type, labels[i].structure,
                                    input->der, input->der_len);
    }
    return 1;
}

/* The incoming BIO has been consumed. Pass plain keys to the native DER
 * chain even when they belong to another algorithm. */
static int bign_forward_plain(OSSL_CALLBACK *data_cb, void *data_cbarg,
                              const unsigned char *der, size_t len,
                              BIGN_DER_KIND kind)
{
    const char *structure = kind == BIGN_DER_PRIVATE
                            ? "PrivateKeyInfo" : "SubjectPublicKeyInfo";

    return bign_emit_der(data_cb, data_cbarg, NULL, structure, der, len);
}

/* The OpenSSL DER decoder chain first unwraps EncryptedPrivateKeyInfo and
 * then passes an ordinary PrivateKeyInfo to the key-type decoder. The default
 * unwrap decoder cannot handle HMAC-HBELT, so provide a DER -> DER step for
 * STB PBES2 without changing the standard decoder or intercepting other keys. */
int bee2_bign_asn1_stb_epki_decode(void *vctx, OSSL_CORE_BIO *in, int selection,
                                   OSSL_CALLBACK *data_cb, void *data_cbarg,
                                   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    bee2_bign_decoder_ctx_t *ctx = vctx;
    BIGN_INPUT input = {0};
    const unsigned char *p;
    X509_SIG *encrypted = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *plain_der = NULL;
    char password[PEM_BUFSIZE] = {0};
    size_t password_len = 0;
    int plain_len = 0, recognised = 0, ok = 0;

    (void)selection;
    if (ctx == NULL || in == NULL || data_cb == NULL)
        return 0;
    if (!bign_read_input(ctx, in, &input, pw_cb, pw_cbarg))
        goto end;
    if (input.der_len == 0) {
        ok = 1;
        goto end;
    }
    if (input.der == NULL)
        goto end;

    /* The PEM label specifies the DER structure. An RSA/EC private key
     * must never be forwarded as PrivateKeyInfo solely because it starts
     * with an ASN.1 INTEGER. */
    if (ctx->input_pem) {
        if (input.pem_name == NULL)
            goto end;
        if (strcmp(input.pem_name, "ENCRYPTED PRIVATE KEY") != 0) {
            ok = bign_forward_pem(data_cb, data_cbarg, &input);
            goto end;
        }
    } else {
        BIGN_DER_KIND kind = bign_der_kind(input.der, input.der_len);

        if (kind == BIGN_DER_PRIVATE || kind == BIGN_DER_PUBLIC) {
            ok = bign_forward_plain(data_cb, data_cbarg, input.der,
                                    input.der_len, kind);
            goto end;
        }
        if (kind != BIGN_DER_ENCRYPTED) {
            ok = 1;
            goto end;
        }
    }

    p = input.der;
    encrypted = d2i_X509_SIG(NULL, &p, (long)input.der_len);
    if (encrypted == NULL || p != input.der + input.der_len ||
        !bee2_stb_pbes2_is_stb(encrypted)) {
        /* Delegate other PBES2 schemes to OpenSSL without requiring the
         * original BIO to support seeking or rewinding. */
        ok = bign_emit_der(data_cb, data_cbarg, NULL,
                           "EncryptedPrivateKeyInfo",
                           input.der, input.der_len);
        goto end;
    }

    if (pw_cb == NULL || !pw_cb(password, sizeof(password), &password_len,
                               NULL, pw_cbarg) ||
        password_len > sizeof(password))
        goto end;
    p8 = bee2_stb_pbes2_decrypt(encrypted, (const unsigned char *)password,
                                password_len, ctx->max_pbkdf2_iterations,
                                ctx->libctx, &recognised);
    if (!recognised || p8 == NULL)
        goto end;
    plain_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &plain_der);
    if (plain_len <= 0 || plain_der == NULL)
        goto end;
    ok = bign_emit_der(data_cb, data_cbarg, "bign", "PrivateKeyInfo",
                       plain_der, (size_t)plain_len);

end:
    OPENSSL_cleanse(password, sizeof(password));
    if (plain_der != NULL)
        OPENSSL_clear_free(plain_der, plain_len > 0 ? (size_t)plain_len : 0);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(encrypted);
    bign_free_input(&input);
    return ok;
}


int bee2_bign_asn1_resolve_hash_oid(const EVP_MD *md, const char *mdname,
                                    const char *known, char *oid, size_t size) {
    const ASN1_OBJECT *obj;
    ASN1_OBJECT *parsed = NULL;
    int nid, length;

    if (known) {
        size_t n = strlen(known);
        if (n >= size)
            return 0;
        memcpy(oid, known, n + 1);
        return 1;
    }
    nid = EVP_MD_get_type(md);
    obj = nid == NID_undef ? NULL : OBJ_nid2obj(nid);
    if (!obj)
        obj = parsed = OBJ_txt2obj(mdname, 1);
    if (!obj)
        return 0;
    length = OBJ_obj2txt(oid, (int)size, obj, 1);
    ASN1_OBJECT_free(parsed);
    return length > 0 && (size_t)length < size;
}


int bee2_bign_asn1_build_algid(const char *oid, const char *hash_oid,
                     unsigned char *buf, size_t buf_len, size_t *out_len) {
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_OBJECT *hash_obj = NULL;
    unsigned char *p = NULL;
    int len;
    int ok = 0;

    if (!oid || !buf || !out_len)
        return 0;

    obj = OBJ_txt2obj(oid, 1);
    if (!obj)
        goto cleanup;

    alg = X509_ALGOR_new();
    if (!alg)
        goto cleanup;

    if (hash_oid && (hash_obj = OBJ_txt2obj(hash_oid, 1)) == NULL)
        goto cleanup;
    if (!X509_ALGOR_set0(alg, obj, hash_obj ? V_ASN1_OBJECT : V_ASN1_NULL, hash_obj))
        goto cleanup;
    obj = NULL;
    hash_obj = NULL;

    len = i2d_X509_ALGOR(alg, NULL);
    if (len <= 0 || (size_t)len > buf_len)
        goto cleanup;

    p = buf;
    len = i2d_X509_ALGOR(alg, &p);
    if (len <= 0)
        goto cleanup;

    *out_len = (size_t)len;
    ok = 1;

cleanup:
    ASN1_OBJECT_free(obj);
    ASN1_OBJECT_free(hash_obj);
    X509_ALGOR_free(alg);
    return ok;
}


#define BEE2_OID_PBES2 "1.2.840.113549.1.5.13"
#define BEE2_OID_PBKDF2 "1.2.840.113549.1.5.12"


/* Transfers value to alg only on success. */
static int set_alg(X509_ALGOR *alg, const char *oid, int type, void *value)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);

    if (obj == NULL)
        return 0;
    if (!X509_ALGOR_set0(alg, obj, type, value)) {
        ASN1_OBJECT_free(obj);
        return 0;
    }
    return 1;
}

/* Derive the STB's 256-bit protection key with the provider KDF. */
static int stb_pbkdf2_derive(OSSL_LIB_CTX *libctx,
                             const unsigned char *password, size_t password_len,
                             const unsigned char *salt, size_t salt_len,
                             unsigned int iterations,
                             unsigned char key[32])
{
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *kctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
    uint64_t iter = iterations;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)password, password_len),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_END
    };
    int ok = kctx != NULL && EVP_KDF_derive(kctx, key, 32, params) > 0;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ok;
}


/* The provider cipher already checks the KWP length constraints and the
 * authentication header. No KWP primitive is implemented in the codec. */
static int stb_kwp_crypt(OSSL_LIB_CTX *libctx, int encrypt,
                         const unsigned char key[32],
                         const unsigned char *in, size_t in_len,
                         unsigned char *out, size_t *out_len)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(libctx, "belt-kwp256", "provider=bee2");
    EVP_CIPHER_CTX *ctx = cipher != NULL ? EVP_CIPHER_CTX_new() : NULL;
    int processed = 0, final = 0;
    int ok = 0;

    *out_len = 0;
    if (ctx != NULL)
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (ctx != NULL && in_len <= INT_MAX &&
        EVP_CipherInit_ex2(ctx, cipher, key, NULL, encrypt, NULL) > 0 &&
        EVP_CipherUpdate(ctx, out, &processed, in, (int)in_len) > 0 &&
        EVP_CipherFinal_ex(ctx, out + processed, &final) > 0) {
        *out_len = (size_t)processed + (size_t)final;
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

/* Pack standard EncryptedPrivateKeyInfo and PBES2 parameters with OpenSSL. */
static X509_SIG *stb_pbes2_pack(const unsigned char *salt, size_t salt_len,
                               unsigned int iterations,
                               const unsigned char *wrapped, size_t wrapped_len,
                               OSSL_LIB_CTX *libctx)
{
    PBE2PARAM *pbe = PBE2PARAM_new();
    X509_ALGOR *keyfunc = NULL, *outer = NULL;
    ASN1_OCTET_STRING *ciphertext = NULL;
    ASN1_STRING *params = NULL;
    X509_SIG *sig = NULL;
    int prf_nid = OBJ_txt2nid(BEE2_OID_HMAC_HBELT);

    if (pbe == NULL || prf_nid == NID_undef)
        goto end;
    keyfunc = PKCS5_pbkdf2_set_ex((int)iterations, (unsigned char *)salt,
                                    (int)salt_len, prf_nid, 32, libctx);
    if (keyfunc == NULL)
        goto end;
    X509_ALGOR_free(pbe->keyfunc);
    pbe->keyfunc = keyfunc;
    keyfunc = NULL;
    if (!set_alg(pbe->encryption, BEE2_OID_BELT_KWP, V_ASN1_NULL, NULL))
        goto end;
    params = ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBE2PARAM), NULL);
    sig = X509_SIG_new();
    if (params == NULL || sig == NULL)
        goto end;
    X509_SIG_getm(sig, &outer, &ciphertext);
    if (!set_alg(outer, BEE2_OID_PBES2, V_ASN1_SEQUENCE, params))
        goto end;
    params = NULL;
    if (!ASN1_OCTET_STRING_set(ciphertext, wrapped, (int)wrapped_len))
        goto end;

    X509_ALGOR_free(keyfunc);
    PBE2PARAM_free(pbe);
    return sig;
end:
    ASN1_STRING_free(params);
    X509_ALGOR_free(keyfunc);
    PBE2PARAM_free(pbe);
    X509_SIG_free(sig);
    return NULL;
}

unsigned char *bee2_stb_pbes2_encrypt(const unsigned char *scalar, size_t scalar_len,
                                      const unsigned char *password, size_t password_len,
                                      unsigned int iterations,
                                      size_t salt_len, OSSL_LIB_CTX *libctx, size_t *out_len)
{
    X509_SIG *sig = NULL;
    unsigned char *salt = NULL, *wrapped = NULL, *result = NULL;
    unsigned char key[32] = {0};
    size_t wrapped_len = 0;
    int n;

    if (out_len == NULL)
        return NULL;
    *out_len = 0;
    if (scalar == NULL || password == NULL || password_len > INT_MAX ||
        (scalar_len != 32 && scalar_len != 48 && scalar_len != 64) ||
        iterations == 0 || iterations > INT_MAX ||
        salt_len == 0 || salt_len >= BIGN_MAX_KEY_INPUT)
        return NULL;
    /* Reject a salt that cannot fit the whole permitted key envelope. */
    salt = OPENSSL_malloc(salt_len);
    wrapped = OPENSSL_malloc(scalar_len + 16);
    if (salt == NULL || wrapped == NULL ||
        RAND_bytes_ex(libctx, salt, salt_len, 0) <= 0 ||
        !stb_pbkdf2_derive(libctx, password, password_len, salt, salt_len,
                           iterations, key) ||
        !stb_kwp_crypt(libctx, 1, key, scalar, scalar_len,
                       wrapped, &wrapped_len))
        goto end;
    sig = stb_pbes2_pack(salt, salt_len, iterations,
                         wrapped, wrapped_len, libctx);
    if (sig == NULL)
        goto end;
    n = i2d_X509_SIG(sig, &result);
    if (n <= 0 || (size_t)n > BIGN_MAX_KEY_INPUT) {
        OPENSSL_clear_free(result, n > 0 ? (size_t)n : 0);
        result = NULL;
    } else {
        *out_len = (size_t)n;
    }
end:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_clear_free(wrapped, scalar_len + 16);
    OPENSSL_clear_free(salt, salt_len);
    X509_SIG_free(sig);
    return result;
}

/* ASN1_item_unpack() does not reject bytes after the first DER object.
 * For password-protection parameters accept only one complete sequence. */
static void *unpack_sequence_exact(const ASN1_STRING *encoded,
                                   const ASN1_ITEM *item)
{
    const unsigned char *p, *start;
    size_t len;
    ASN1_VALUE *value;

    if (encoded == NULL)
        return NULL;
    len = asn_length(encoded);
    start = ASN1_STRING_get0_data(encoded);
    if (start == NULL || len == 0 || len > LONG_MAX)
        return NULL;
    p = start;
    value = ASN1_item_d2i(NULL, &p, (long)len, item);
    if (value != NULL && p != start + len) {
        ASN1_item_free(value, item);
        value = NULL;
    }
    return value;
}

/* PBES2 itself is an OpenSSL ASN.1 structure. */
static PBE2PARAM *unpack_pbes2(const X509_SIG *encrypted)
{
    const X509_ALGOR *algorithm = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    int type;

    if (encrypted == NULL)
        return NULL;
    X509_SIG_get0(encrypted, &algorithm, &ciphertext);
    X509_ALGOR_get0(&oid, &type, &value, algorithm);
    if (!oid_equals(oid, BEE2_OID_PBES2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        return NULL;
    return unpack_sequence_exact((const ASN1_STRING *)value,
                                  ASN1_ITEM_rptr(PBE2PARAM));
}

/* Identify the encryptionScheme before validating nested PBKDF2 and
 * PBES2 parameters. A malformed STB envelope must not be offered to the
 * default PBES2 decoder just because strict ASN.1 decoding failed. */
int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted)
{
    const X509_ALGOR *outer = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    const unsigned char *p, *end;
    X509_ALGOR *scheme = NULL;
    size_t size;
    long n;
    int type, tag, xclass, status, recognised = 0;

    if (encrypted == NULL)
        return 0;
    X509_SIG_get0(encrypted, &outer, &ciphertext);
    if (outer == NULL)
        return 0;
    X509_ALGOR_get0(&oid, &type, &value, outer);
    if (!oid_equals(oid, BEE2_OID_PBES2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        return 0;
    size = asn_length((const ASN1_STRING *)value);
    p = ASN1_STRING_get0_data((const ASN1_STRING *)value);
    if (p == NULL || size == 0 || size > BIGN_MAX_KEY_INPUT)
        return 0;
    end = p + size;
    ERR_set_mark();
    status = ASN1_get_object(&p, &n, &tag, &xclass, (long)size);
    if ((status & 0x81) != 0 || tag != V_ASN1_SEQUENCE ||
        xclass != V_ASN1_UNIVERSAL || n <= 0 || n > (long)(end - p))
        goto done;
    end = p + n;
    /* Skip the complete KDF AlgorithmIdentifier, including its opaque
     * parameters, which may themselves contain malformed DER. */
    status = ASN1_get_object(&p, &n, &tag, &xclass, (long)(end - p));
    if ((status & 0x81) != 0 || tag != V_ASN1_SEQUENCE ||
        xclass != V_ASN1_UNIVERSAL || n <= 0 || n > (long)(end - p))
        goto done;
    p += n;
    scheme = d2i_X509_ALGOR(NULL, &p, (long)(end - p));
    if (scheme != NULL) {
        X509_ALGOR_get0(&oid, NULL, NULL, scheme);
        recognised = oid_equals(oid, BEE2_OID_BELT_KWP);
    }
done:
    X509_ALGOR_free(scheme);
    ERR_pop_to_mark();
    return recognised;
}

/* STB Annex E carries only the scalar, so the curve is determined by its size. */
static PKCS8_PRIV_KEY_INFO *stb_scalar_to_pkcs8(const unsigned char *scalar, size_t len)
{
    const bee2_bign_variant_t *variant;

    switch (len) {
    case 32: variant = bee2_bign_variant_256(); break;
    case 48: variant = bee2_bign_variant_384(); break;
    case 64: variant = bee2_bign_variant_512(); break;
    default: return NULL;
    }
    return bign_make_pkcs8(scalar, variant, 0, 0);
}

PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len,
                                            unsigned int max_iterations,
                                            OSSL_LIB_CTX *libctx, int *recognised)
{
    const X509_ALGOR *algorithm = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *obj = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char key[32] = {0}, *plaintext = NULL;
    size_t salt_len = 0, wrapped_len = 0, plaintext_len = 0;
    long iter;
    int type;

    if (recognised == NULL)
        return NULL;
    *recognised = bee2_stb_pbes2_is_stb(encrypted);
    if (!*recognised || password == NULL || password_len > INT_MAX)
        return NULL;
    X509_SIG_get0(encrypted, &algorithm, &ciphertext);
    pbe = unpack_pbes2(encrypted);
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
    if (!oid_equals(obj, BEE2_OID_BELT_KWP) || type != V_ASN1_NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->keyfunc);
    if (!oid_equals(obj, BEE2_OID_PBKDF2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = unpack_sequence_exact((const ASN1_STRING *)value,
                                ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL || kdf->prf == NULL ||
        kdf->salt == NULL || kdf->salt->type != V_ASN1_OCTET_STRING)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, kdf->prf);
    if (!oid_equals(obj, BEE2_OID_HMAC_HBELT) || type != V_ASN1_NULL)
        goto end;
    if (kdf->keylength != NULL &&
        ASN1_INTEGER_get(kdf->keylength) != 32)
        goto end;
    iter = ASN1_INTEGER_get(kdf->iter);
    salt_len = asn_length(kdf->salt->value.octet_string);
    wrapped_len = asn_length(ciphertext);
    if (iter <= 0 || iter > INT_MAX || iter > (long)max_iterations ||
        salt_len == 0 || salt_len > INT_MAX ||
        (wrapped_len != 48 && wrapped_len != 64 && wrapped_len != 80))
        goto end;
    plaintext = OPENSSL_malloc(wrapped_len);
    if (plaintext == NULL ||
        !stb_pbkdf2_derive(libctx, password, password_len,
                           ASN1_STRING_get0_data(kdf->salt->value.octet_string),
                           salt_len, (unsigned int)iter, key) ||
        !stb_kwp_crypt(libctx, 0, key,
                       ASN1_STRING_get0_data(ciphertext), wrapped_len,
                       plaintext, &plaintext_len))
        goto end;
    p8 = stb_scalar_to_pkcs8(plaintext, plaintext_len);
end:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_clear_free(plaintext, wrapped_len <= INT_MAX ? wrapped_len : 0);
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    return p8;
}

/* OpenSSL-managed PBES2 for non-STB ciphers (e.g. AES-CBC). */
unsigned char *bee2_bign_asn1_encrypt_standard_pkcs8(const unsigned char *der, size_t der_len,
                                                      const unsigned char *pass, size_t pass_len,
                                                      const EVP_CIPHER *cipher,
                                                      unsigned int iterations, size_t salt_len,
                                                      OSSL_LIB_CTX *libctx, size_t *out_len)
{
    const unsigned char *p = der;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    X509_SIG *encrypted = NULL;
    unsigned char *out = NULL;
    int n;

    if (out_len == NULL)
        return NULL;
    *out_len = 0;
    if (!der || !pass || !cipher || der_len > LONG_MAX || pass_len > INT_MAX ||
        salt_len >= BIGN_MAX_KEY_INPUT || iterations > INT_MAX ||
        !bign_der_sequence_body(der, der_len, &p))
        return NULL;
    p = der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)der_len);
    if (!p8 || p != der + der_len)
        goto end;
    encrypted = PKCS8_encrypt_ex(-1, cipher, (const char *)pass, (int)pass_len,
                                  NULL, (int)salt_len, (int)iterations, p8, libctx, NULL);
    if (!encrypted)
        goto end;
    n = i2d_X509_SIG(encrypted, &out);
    if (n <= 0 || (size_t)n > BIGN_MAX_KEY_INPUT) {
        OPENSSL_clear_free(out, n > 0 ? (size_t)n : 0);
        out = NULL;
    } else {
        *out_len = (size_t)n;
    }

end:
    X509_SIG_free(encrypted);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return out;
}
