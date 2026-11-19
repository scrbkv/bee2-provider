/* BIGN ASN.1, DER/PEM framing, PKCS#8 and PBES2 serialization. */
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

#define BIGN_PEM_LABEL "PRIVATE KEY"
#define BIGN_ENCRYPTED_PEM_LABEL "ENCRYPTED PRIVATE KEY"
#define BIGN_PUB_PEM_LABEL "PUBLIC KEY"

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


static int bign_asn1_string_length(const ASN1_STRING *str) {
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    size_t len = ASN1_STRING_get_length(str);
    return len > INT_MAX ? -1 : (int)len;
#else
    return ASN1_STRING_length(str);
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
    int n;

    data = ASN1_STRING_get0_data(params);
    n = bign_asn1_string_length(params);
    if (data == NULL || n <= 0 ||
        !bign_der_sequence_body(data, (size_t)n, &body))
        return NULL;
    length = (size_t)n;
    p = data;
    ecp = d2i_BIGN_ECPARAMS(NULL, &p, n);
    /* Validate the OID with OpenSSL before using Bee2's fixed-OID DER
     * decoder. Malformed OIDs must not reach its string comparator. */
    if (ecp == NULL || p != data + n || ecp->fieldID == NULL ||
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

unsigned char *bee2_bign_asn1_encode_pkcs8_der(const bee2_bign_key_t *key, size_t *out_len) {
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *alg = NULL;
    void *parameters = NULL;
    int parameter_type = V_ASN1_UNDEF;
    unsigned char *priv = NULL;
    unsigned char *der = NULL;
    size_t priv_len = 0;

    if (!key || !key->variant || !key->has_priv || !out_len) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER, "encode_pkcs8_der: invalid key");
        return NULL;
    }
    *out_len = 0;

    priv_len = bee2_bign_priv_len(key->variant);
    priv = OPENSSL_malloc(priv_len);
    if (!priv) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE, "encode_pkcs8_der: alloc priv");
        return NULL;
    }
    memcpy(priv, key->priv, priv_len);

    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (!p8) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_MALLOC_FAILURE, "encode_pkcs8_der: PKCS8_PRIV_KEY_INFO_new");
        goto err;
    }

    alg = OBJ_txt2obj(BEE2_OID_BIGN_PUBKEY, 1);
    if (!alg || !bign_encode_algorithm_params(key, &parameter_type, &parameters)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_pkcs8_der: OBJ_txt2obj failed");
        goto err;
    }

    if (!PKCS8_pkey_set0(p8, alg, 0, parameter_type, parameters, priv, (int)priv_len)) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_pkcs8_der: PKCS8_pkey_set0 failed");
        goto err;
    }
    alg = NULL;
    parameters = NULL;
    priv = NULL;

    int der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    if (der_len <= 0) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "encode_pkcs8_der: i2d_PKCS8_PRIV_KEY_INFO failed");
        goto err;
    }
    *out_len = (size_t)der_len;

    PKCS8_PRIV_KEY_INFO_free(p8);
    return der;

err:
    if (alg)
        ASN1_OBJECT_free(alg);
    bign_free_algorithm_params(parameter_type, parameters);
    if (priv) {
        OPENSSL_cleanse(priv, priv_len);
        OPENSSL_free(priv);
    }
    if (p8)
        PKCS8_PRIV_KEY_INFO_free(p8);
    if (der)
        OPENSSL_free(der);
    return NULL;
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
    int ok = 0;

    if (!key || !bign_der_sequence_body(buf, len, &p))
        return 0;
    p = buf;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)len);
    if (!p8)
        return 0;
    if (p == buf + len)
        ok = decode_pkcs8_info(p8, expected, key);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return ok;
}

int bee2_bign_asn1_decode_encrypted_pkcs8_der(const unsigned char *buf, size_t len,
                                      const bee2_bign_variant_t *expected,
                                      bee2_bign_key_t *key, OSSL_LIB_CTX *libctx,
                                      unsigned int max_pbkdf2_iterations,
                                      OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg) {
    const unsigned char *p = buf;
    X509_SIG *encrypted = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    char password[PEM_BUFSIZE];
    size_t password_len = 0;
    int recognised = 0;
    int ok = 0;

    if (!bign_der_sequence_body(buf, len, &p))
        return 0;
    p = buf;
    ERR_set_mark();
    encrypted = d2i_X509_SIG(NULL, &p, (long)len);
    ERR_pop_to_mark();
    if (!encrypted || p != buf + len)
        goto cleanup;
    if (!cb)
        goto cleanup;

    OPENSSL_cleanse(password, sizeof(password));
    if (!cb(password, sizeof(password), &password_len, NULL, cbarg) ||
        password_len > sizeof(password) || password_len > INT_MAX)
        goto clear_password;
    p8 = bee2_stb_pbes2_decrypt(encrypted, (const unsigned char *)password,
                                password_len, max_pbkdf2_iterations, libctx, &recognised);
    if (!recognised && p8 == NULL &&
        bee2_pkcs8_standard_pbkdf2_allowed(encrypted, max_pbkdf2_iterations))
        p8 = PKCS8_decrypt_ex(encrypted, password, (int)password_len, libctx, NULL);
    if (p8)
        ok = decode_pkcs8_info(p8, expected, key);

clear_password:
    OPENSSL_cleanse(password, sizeof(password));
cleanup:
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(encrypted);
    return ok;
}


/* A decoder consumes one record, not the entire underlying stream. */
static int read_exact(BIO *bio, unsigned char *out, size_t len) {
    while (len != 0) {
        size_t n = 0;
        if (!BIO_read_ex(bio, out, len, &n) || n == 0)
            return 0;
        out += n;
        len -= n;
    }
    return 1;
}

static int read_der_object(BIO *bio, unsigned char **out, size_t *len) {
    unsigned char header[5] = {0x30}, *der;
    size_t headlen = 2, bodylen = 0, i;
    unsigned int count;

    if (!read_exact(bio, header + 1, 1))
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
    if (!der)
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

static int append_bytes(unsigned char **buffer,
                        size_t *length,
                        size_t *capacity,
                        const unsigned char *data,
                        size_t data_length) {
    size_t required;
    size_t new_capacity;
    unsigned char *expanded;

    if (!buffer || !length || !capacity || (!data && data_length != 0) ||
        data_length > SIZE_MAX - *length)
        return 0;

    required = *length + data_length;
    if (required > *capacity) {
        new_capacity = *capacity ? *capacity : 4096u;
        while (new_capacity < required) {
            if (new_capacity > SIZE_MAX / 2u) {
                new_capacity = required;
                break;
            }
            new_capacity *= 2u;
        }
        expanded = OPENSSL_realloc(*buffer, new_capacity);
        if (!expanded)
            return 0;
        *buffer = expanded;
        *capacity = new_capacity;
    }

    if (data_length != 0)
        memcpy(*buffer + *length, data, data_length);
    *length = required;
    return 1;
}

static int read_pem_object(BIO *bio, unsigned char first,
                           unsigned char **out, size_t *len) {
    static const char begin[] = "-----BEGIN ";
    static const char end[] = "-----END ";
    unsigned char *buf = NULL, ch = first;
    size_t used = 0, capacity = 0;
    int begun = 0, ending = 0, closed = 0;

    /* Read one PEM record, including its line terminator, without read-ahead. */
    for (;;) {
        if (used == BIGN_MAX_KEY_INPUT ||
            !append_bytes(&buf, &used, &capacity, &ch, 1))
            break;
        if (closed) {
            if (ch == '\n') {
                *out = buf;
                *len = used;
                return 1;
            }
            if (ch != '\r' && ch != ' ' && ch != '\t')
                break;
        }
        if (!begun && used >= sizeof(begin) - 1 &&
            memcmp(buf + used - (sizeof(begin) - 1), begin, sizeof(begin) - 1) == 0)
            begun = 1;
        if (begun && !ending && used >= sizeof(end) - 1 &&
            memcmp(buf + used - (sizeof(end) - 1), end, sizeof(end) - 1) == 0)
            ending = 1;
        if (ending && used >= 5 && memcmp(buf + used - 5, "-----", 5) == 0)
            closed = 1;
        if (!read_exact(bio, &ch, 1)) {
            if (closed && !BIO_should_retry(bio) && BIO_eof(bio) > 0) {
                *out = buf;
                *len = used;
                return 1;
            }
            break;
        }
    }
    OPENSSL_clear_free(buf, capacity);
    return 0;
}

static int read_one_object(BIO *bio, unsigned char **out, size_t *len) {
    unsigned char first;
    size_t n = 0;

    if (!bio || !out || !len)
        return 0;
    *out = NULL;
    *len = 0;
    if (!BIO_read_ex(bio, &first, 1, &n) || n == 0)
        return !BIO_should_retry(bio) && BIO_eof(bio) > 0;
    if (first == 0x30)
        return read_der_object(bio, out, len);
    if (first == '\t' || first == '\r' || first == '\n' ||
        (first >= 0x20 && first <= 0x7e))
        return read_pem_object(bio, first, out, len);
    return 0;
}

static unsigned char *
pem_to_der_buf(const unsigned char *buf, size_t len, size_t *out_len, char **out_name) {
    BIO *bio = NULL;
    char *name = NULL;
    char *header = NULL;
    unsigned char *data = NULL;
    long dlen = 0;
    unsigned char *der = NULL;

    if (!out_len)
        return NULL;
    *out_len = 0;
    if (out_name)
        *out_name = NULL;

    if (!buf || len > INT_MAX)
        return NULL;
    bio = BIO_new_mem_buf(buf, (int)len);
    if (!bio)
        return NULL;

    if (!PEM_read_bio(bio, &name, &header, &data, &dlen)) {
        BIO_free(bio);
        return NULL;
    }
    BIO_free(bio);

    if (out_name) {
        *out_name = name;
    } else if (name) {
        OPENSSL_free(name);
    }

    der = data;
    *out_len = (size_t)dlen;

    OPENSSL_free(header);
    return der;
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
    int pub_len = 0;
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
    pub_len = bign_asn1_string_length((const ASN1_STRING *)bit);
    if (!pub || pub_len != (int)bee2_bign_pub_len(variant))
        goto cleanup;

    key->variant = variant;
    memcpy(key->pub, pub, (size_t)pub_len);
    key->has_pub = 1;
    ok = bee2_bign_key_validate_public(key);

cleanup:
    ASN1_BIT_STRING_free(bit);
    X509_ALGOR_free(alg);
    return ok;
}


int bee2_bign_asn1_decoder_decode(void *vctx,
                               OSSL_CORE_BIO *in,
                               int selection,
                               OSSL_CALLBACK *data_cb,
                               void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb,
                               void *pw_cbarg) {
    bee2_bign_decoder_ctx_t *ctx = vctx;
    if (!ctx || !data_cb)
        return 0;

    BIO *bio = BIO_new_from_core_bio(ctx->libctx, in);
    size_t len = 0;
    unsigned char *buf;
    int read_ok;

    if (bio == NULL)
        return 0;
    read_ok = read_one_object(bio, &buf, &len);
    BIO_free(bio);
    if (!read_ok)
        return 0;
    if (len == 0) {
        OPENSSL_clear_free(buf, len);
        return 1;
    }

    unsigned char *der = buf;
    size_t der_len = len;
    int is_pem = buf[0] != 0x30;
    char *pem_name = NULL;
    if (is_pem) {
        der = pem_to_der_buf(buf, len, &der_len, &pem_name);
        if (!der || der_len == 0) {
            OPENSSL_clear_free(buf, len);
            OPENSSL_free(der);
            OPENSSL_free(pem_name);
            return 1;
        }
    }

    bee2_bign_key_t *key = bee2_bign_key_new(NULL);
    if (!key) {
        if (der != buf)
            OPENSSL_clear_free(der, der_len);
        OPENSSL_clear_free(buf, len);
        OPENSSL_free(pem_name);
        return 0;
    }

    int decoded = 0;
    if (pem_name) {
        if (strcmp(pem_name, BIGN_PEM_LABEL) == 0) {
            decoded = bee2_bign_asn1_decode_pkcs8_der(der, der_len, ctx->variant, key);
        } else if (strcmp(pem_name, BIGN_ENCRYPTED_PEM_LABEL) == 0) {
            decoded = bee2_bign_asn1_decode_encrypted_pkcs8_der(der, der_len, ctx->variant, key,
                                                 ctx->libctx, ctx->max_pbkdf2_iterations,
                                                 pw_cb, pw_cbarg);
        } else if (strcmp(pem_name, BIGN_PUB_PEM_LABEL) == 0) {
            decoded = bee2_bign_asn1_decode_spki_der(der, der_len, ctx->variant, key);
        }
    } else {
        decoded = bee2_bign_asn1_decode_pkcs8_der(der, der_len, ctx->variant, key);
        if (!decoded)
            decoded = bee2_bign_asn1_decode_encrypted_pkcs8_der(der, der_len, ctx->variant, key,
                                                 ctx->libctx, ctx->max_pbkdf2_iterations,
                                                 pw_cb, pw_cbarg);
        if (!decoded)
            decoded = bee2_bign_asn1_decode_spki_der(der, der_len, ctx->variant, key);
    }

    if (decoded && selection != 0) {
        if (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_priv) ||
            ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !key->has_pub)) {
            decoded = 0;
        } else if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->has_priv) {
            /* A public-only decoder must not export the private scalar. */
            OPENSSL_cleanse(key->priv, sizeof(key->priv));
            key->has_priv = 0;
        }
    }

    if (!decoded) {
        bee2_bign_key_free(key);
        if (der != buf)
            OPENSSL_clear_free(der, der_len);
        OPENSSL_clear_free(buf, len);
        OPENSSL_free(pem_name);
        /* EncryptedPrivateKeyInfo is shared by all key algorithms.
         * An unsuccessful BIGN decode must not abort other decoders. */
        return 1;
    }

    int obj_type = OSSL_OBJECT_PKEY;
    const char *data_type = "bign";
    void *objref = key;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0),
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &objref, sizeof(objref)),
        OSSL_PARAM_construct_end()};

    int ok = data_cb(params, data_cbarg);

    bee2_bign_key_free(key);
    if (der != buf)
        OPENSSL_clear_free(der, der_len);
    OPENSSL_clear_free(buf, len);
    OPENSSL_free(pem_name);
    return ok;
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
    BIO *bio = NULL;
    unsigned char *buf = NULL, *plain_der = NULL, *converted = NULL;
    const unsigned char *payload = NULL;
    char *pem_name = NULL;
    const unsigned char *p;
    X509_SIG *encrypted = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const ASN1_OBJECT *key_oid = NULL;
    char password[PEM_BUFSIZE] = {0};
    char key_type[128];
    size_t password_len = 0, len = 0, payload_len = 0;
    int plain_len = 0, obj_type = OSSL_OBJECT_PKEY, recognised = 0;
    int ok = 0;

    (void)selection;
    if (ctx == NULL || in == NULL || data_cb == NULL)
        return 0;
    bio = BIO_new_from_core_bio(ctx->libctx, in);
    if (bio == NULL)
        goto end;

    if (ctx->input_pem) {
        if (!read_one_object(bio, &buf, &len))
            goto end;
        if (len == 0) {
            ok = 1;
            goto end;
        }
        if (buf[0] == 0x30) {
            /* A generic loader may invoke this adapter on DER input. */
            payload = buf;
            payload_len = len;
        } else {
            converted = pem_to_der_buf(buf, len, &payload_len, &pem_name);
            if (converted == NULL || payload_len == 0 ||
                payload_len > BIGN_MAX_KEY_INPUT)
                goto end;
            payload = converted;
        }
    } else {
        if (!read_one_object(bio, &buf, &len))
            goto end;
        if (len == 0) {
            ok = 1;
            goto end;
        }
        payload = buf;
        payload_len = len;
    }

    p = payload;
    ERR_set_mark();
    encrypted = d2i_X509_SIG(NULL, &p, (long)payload_len);
    ERR_pop_to_mark();
    if (encrypted == NULL || p != payload + payload_len ||
        !bee2_stb_pbes2_is_stb(encrypted)) {
        PKCS8_PRIV_KEY_INFO *plain_p8 = NULL;
        X509_PUBKEY *pub = NULL;
        const ASN1_OBJECT *private_oid = NULL;
        ASN1_OBJECT *public_oid = NULL;
        const char *structure = NULL;
        char bign_name[] = "bign";

        /* The first DER-to-DER decoder may consume a nonseekable BIO.
         * Recognised plain BIGN keys must therefore pass through here as
         * well, without requiring another attempt to read the original BIO. */
        p = payload;
        ERR_set_mark();
        plain_p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)payload_len);
        ERR_pop_to_mark();
        if (plain_p8 != NULL && p == payload + payload_len &&
            PKCS8_pkey_get0(&private_oid, NULL, NULL, NULL, plain_p8) &&
            oid_equals(private_oid, BEE2_OID_BIGN_PUBKEY)) {
            structure = "PrivateKeyInfo";
        } else {
            p = payload;
            ERR_set_mark();
            pub = d2i_X509_PUBKEY(NULL, &p, (long)payload_len);
            ERR_pop_to_mark();
            if (pub != NULL && p == payload + payload_len &&
                X509_PUBKEY_get0_param(&public_oid, NULL, NULL, NULL, pub) &&
                oid_equals(public_oid, BEE2_OID_BIGN_PUBKEY))
                structure = "SubjectPublicKeyInfo";
        }
        if (structure != NULL) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, bign_name, 0),
                OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)structure, 0),
                OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA,
                                        (void *)payload, payload_len),
                OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
                OSSL_PARAM_END
            };

            ok = data_cb(params, data_cbarg);
        } else {
            /* Leave other key types and PBES2 schemes to OpenSSL. */
            ok = 1;
        }
        PKCS8_PRIV_KEY_INFO_free(plain_p8);
        X509_PUBKEY_free(pub);
        goto end;
    }
    if (pw_cb == NULL || !pw_cb(password, sizeof(password), &password_len,
                               NULL, pw_cbarg) ||
        password_len > sizeof(password))
        goto end;
    p8 = bee2_stb_pbes2_decrypt(encrypted,
                                (const unsigned char *)password,
                                password_len, ctx->max_pbkdf2_iterations,
                                ctx->libctx, &recognised);
    if (!recognised || p8 == NULL ||
        !PKCS8_pkey_get0(&key_oid, NULL, NULL, NULL, p8) ||
        key_oid == NULL ||
        OBJ_obj2txt(key_type, sizeof(key_type), key_oid, 1) <= 0)
        goto end;
    plain_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &plain_der);
    if (plain_len <= 0 || plain_der == NULL)
        goto end;

    {
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, key_type, 0),
            OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, "PrivateKeyInfo", 0),
            OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA, plain_der, (size_t)plain_len),
            OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
            OSSL_PARAM_END
        };

        ok = data_cb(params, data_cbarg);
    }

end:
    OPENSSL_cleanse(password, sizeof(password));
    if (plain_der != NULL)
        OPENSSL_clear_free(plain_der, plain_len > 0 ? (size_t)plain_len : 0);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_SIG_free(encrypted);
    OPENSSL_clear_free(converted, payload_len);
    OPENSSL_free(pem_name);
    OPENSSL_clear_free(buf, len);
    BIO_free(bio);
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
        iterations < BEE2_STB_PBKDF2_MIN_ITER || iterations > INT_MAX ||
        salt_len < BEE2_STB_PBKDF2_MIN_SALT || salt_len > INT_MAX)
        return NULL;
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
    if (n <= 0) {
        OPENSSL_free(result);
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

static size_t asn_length(const ASN1_STRING *value)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(value);
#else
    int n = ASN1_STRING_length(value);
    return n >= 0 ? (size_t)n : SIZE_MAX;
#endif
}


/* PBES2 itself is an OpenSSL ASN.1 structure.  Parse it in one place
 * instead of repeating its envelope checks in each STB policy helper. */
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
    return ASN1_item_unpack((const ASN1_STRING *)value,
                            ASN1_ITEM_rptr(PBE2PARAM));
}

int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted)
{
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe;
    int type, recognised = 0;

    pbe = unpack_pbes2(encrypted);
    if (pbe == NULL)
        return 0;
    X509_ALGOR_get0(&oid, &type, &value, pbe->encryption);
    recognised = oid_equals(oid, BEE2_OID_BELT_KWP);
    PBE2PARAM_free(pbe);
    return recognised;
}

/* Only bounded PBKDF2 is attempted by the standard PBES2 fallback.
 * Other KDFs are left to OpenSSL's normal decoder chain. */
int bee2_pkcs8_standard_pbkdf2_allowed(const X509_SIG *encrypted,
                                          unsigned int max_iterations)
{
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    long iterations;
    int type, allowed = 0;

    if (max_iterations == 0)
        return 0;
    pbe = unpack_pbes2(encrypted);
    if (pbe == NULL)
        return 0;
    X509_ALGOR_get0(&oid, &type, &value, pbe->keyfunc);
    if (!oid_equals(oid, BEE2_OID_PBKDF2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value,
                           ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL)
        goto end;
    iterations = ASN1_INTEGER_get(kdf->iter);
    allowed = iterations > 0 && (unsigned long)iterations <= max_iterations;
end:
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    return allowed;
}

/* STB 34.101.45, Annex E: authenticated plaintext is a BIGN scalar.
 * OpenSSL builds the ordinary PrivateKeyInfo around it for the decoder. */
static PKCS8_PRIV_KEY_INFO *stb_scalar_to_pkcs8(const unsigned char *scalar, size_t len)
{
    const bee2_bign_variant_t *variant;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *algorithm = NULL, *curve = NULL;
    unsigned char *copy = NULL;

    switch (len) {
    case 32: variant = bee2_bign_variant_256(); break;
    case 48: variant = bee2_bign_variant_384(); break;
    case 64: variant = bee2_bign_variant_512(); break;
    default: return NULL;
    }
    p8 = PKCS8_PRIV_KEY_INFO_new();
    algorithm = OBJ_txt2obj(BEE2_OID_BIGN_PUBKEY, 1);
    curve = OBJ_txt2obj(variant->curve_oid, 1);
    copy = OPENSSL_memdup(scalar, len);
    if (p8 == NULL || algorithm == NULL || curve == NULL || copy == NULL ||
        !PKCS8_pkey_set0(p8, algorithm, 0, V_ASN1_OBJECT, curve, copy, (int)len))
        goto err;
    return p8;

err:
    ASN1_OBJECT_free(algorithm);
    ASN1_OBJECT_free(curve);
    OPENSSL_clear_free(copy, len);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
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
    *recognised = 0;
    if (encrypted == NULL || password == NULL || password_len > INT_MAX)
        return NULL;
    X509_SIG_get0(encrypted, &algorithm, &ciphertext);
    pbe = unpack_pbes2(encrypted);
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
    *recognised = oid_equals(obj, BEE2_OID_BELT_KWP);
    if (!*recognised || type != V_ASN1_NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->keyfunc);
    if (!oid_equals(obj, BEE2_OID_PBKDF2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
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
    if (iter < BEE2_STB_PBKDF2_MIN_ITER || iter > INT_MAX ||
        iter > (long)max_iterations ||
        salt_len < BEE2_STB_PBKDF2_MIN_SALT || salt_len > INT_MAX ||
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
        salt_len > INT_MAX || iterations > INT_MAX ||
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
    if (n <= 0) {
        OPENSSL_free(out);
        out = NULL;
    } else {
        *out_len = (size_t)n;
    }

end:
    X509_SIG_free(encrypted);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return out;
}
