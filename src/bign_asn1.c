/* BIGN ASN.1, DER/PEM framing, PKCS#8 and PBES2 serialization. */
#include "bign_asn1.h"
#include "bign_der_frame.h"
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"
#include "provider_util.h"
#include <bee2/crypto/belt.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

typedef struct {
    int type;
    union {
        ASN1_OBJECT *named;
        BIGN_ECPARAMS *specified;
        ASN1_NULL *implicit;
    } value;
} BIGN_DOMAINPARAMS;

DECLARE_ASN1_ITEM(BIGN_FIELDID)
DECLARE_ASN1_ITEM(BIGN_CURVE)
DECLARE_ASN1_ITEM(BIGN_ECPARAMS)
DECLARE_ASN1_ITEM(BIGN_DOMAINPARAMS)

ASN1_SEQUENCE(BIGN_FIELDID) = {ASN1_SIMPLE(BIGN_FIELDID, fieldType, ASN1_OBJECT),
                               ASN1_SIMPLE(BIGN_FIELDID,
                                           prime,
                                           ASN1_INTEGER)} ASN1_SEQUENCE_END(BIGN_FIELDID)

    ASN1_SEQUENCE(BIGN_CURVE) = {ASN1_SIMPLE(BIGN_CURVE, a, ASN1_OCTET_STRING),
                                 ASN1_SIMPLE(BIGN_CURVE, b, ASN1_OCTET_STRING),
                                 ASN1_OPT(BIGN_CURVE,
                                          seed,
                                          ASN1_BIT_STRING)} ASN1_SEQUENCE_END(BIGN_CURVE)

        ASN1_SEQUENCE(BIGN_ECPARAMS) = {ASN1_SIMPLE(BIGN_ECPARAMS, version, LONG),
                                        ASN1_SIMPLE(BIGN_ECPARAMS, fieldID, BIGN_FIELDID),
                                        ASN1_SIMPLE(BIGN_ECPARAMS, curve, BIGN_CURVE),
                                        ASN1_SIMPLE(BIGN_ECPARAMS, base, ASN1_OCTET_STRING),
                                        ASN1_SIMPLE(BIGN_ECPARAMS, order, ASN1_INTEGER),
                                        ASN1_OPT(BIGN_ECPARAMS,
                                                 cofactor,
                                                 ASN1_INTEGER)} ASN1_SEQUENCE_END(BIGN_ECPARAMS)

            DECLARE_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)
                IMPLEMENT_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)

                    ASN1_CHOICE(BIGN_DOMAINPARAMS) =
                        {ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.named, ASN1_OBJECT),
                         ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.specified, BIGN_ECPARAMS),
                         ASN1_SIMPLE(BIGN_DOMAINPARAMS,
                                     value.implicit,
                                     ASN1_NULL)} ASN1_CHOICE_END(BIGN_DOMAINPARAMS)


                            DECLARE_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)
                                DECLARE_ASN1_ENCODE_FUNCTIONS_name(BIGN_DOMAINPARAMS,
                                                                   BIGN_DOMAINPARAMS)
                                    IMPLEMENT_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)


                                        
static int oid_equals(const ASN1_OBJECT *obj, const char *oid) {
    char buf[80];
    int n;

    if (!obj)
        return 0;
    n = OBJ_obj2txt(buf, sizeof(buf), obj, 1);
    if (n <= 0 || n >= (int)sizeof(buf))
        return 0;
    return strcmp(buf, oid) == 0;
}

static const bee2_bign_variant_t *variant_from_curve_obj(const ASN1_OBJECT *obj) {
    const bee2_bign_variant_t *v256 = bee2_bign_variant_256();
    const bee2_bign_variant_t *v384 = bee2_bign_variant_384();
    const bee2_bign_variant_t *v512 = bee2_bign_variant_512();

    if (oid_equals(obj, v256->curve_oid))
        return v256;
    if (oid_equals(obj, v384->curve_oid))
        return v384;
    if (oid_equals(obj, v512->curve_oid))
        return v512;
    return NULL;
}

static int bn_to_fixed_le(const BIGNUM *bn, unsigned char *out, size_t len) {
    return !BN_is_negative(bn) &&
           BN_bn2lebinpad(bn, out, (int)len) == (int)len;
}

static int variant_matches_params(const bee2_bign_variant_t *variant,
                                  const unsigned char *p_le,
                                  const unsigned char *a_le,
                                  const unsigned char *b_le,
                                  const unsigned char *q_le,
                                  const unsigned char *y_le,
                                  size_t bytes) {
    bign_params curve;
    if (!bee2_bign_curve_init_std(variant, &curve))
        return 0;

    if (memcmp(curve.p, p_le, bytes) != 0)
        return 0;
    if (memcmp(curve.a, a_le, bytes) != 0)
        return 0;
    if (memcmp(curve.b, b_le, bytes) != 0)
        return 0;
    if (memcmp(curve.q, q_le, bytes) != 0)
        return 0;
    if (memcmp(curve.yG, y_le, bytes) != 0)
        return 0;
    return 1;
}

static const bee2_bign_variant_t *variant_from_explicit_params(const BIGN_ECPARAMS *ecp) {
    unsigned char p_le[BEE2_BIGN_MAX_WORDS * 8];
    unsigned char a_le[BEE2_BIGN_MAX_WORDS * 8];
    unsigned char b_le[BEE2_BIGN_MAX_WORDS * 8];
    unsigned char q_le[BEE2_BIGN_MAX_WORDS * 8];
    unsigned char y_le[BEE2_BIGN_MAX_WORDS * 8];
    BIGNUM *p_bn = NULL;
    BIGNUM *q_bn = NULL;
    BIGNUM *cof_bn = NULL;
    const unsigned char *a_data = NULL;
    const unsigned char *b_data = NULL;
    const unsigned char *base_data = NULL;
    const bee2_bign_variant_t *variant = NULL;
    int bits = 0;
    size_t bytes = 0;

    if (ecp->version != 1)
        return NULL;
    if (!oid_equals(ecp->fieldID->fieldType, BEE2_OID_BIGN_PRIMEFIELD))
        return NULL;

    p_bn = ASN1_INTEGER_to_BN(ecp->fieldID->prime, NULL);
    if (!p_bn)
        goto cleanup;
    bits = BN_num_bits(p_bn);
    if (bits != 256 && bits != 384 && bits != 512)
        goto cleanup;
    bytes = (size_t)bits / 8u;

    if (!bn_to_fixed_le(p_bn, p_le, bytes))
        goto cleanup;
    a_data = ASN1_STRING_get0_data(ecp->curve->a);
    b_data = ASN1_STRING_get0_data(ecp->curve->b);
    if (!a_data || !b_data)
        goto cleanup;
    if (bign_asn1_string_length(ecp->curve->a) != (int)bytes ||
        bign_asn1_string_length(ecp->curve->b) != (int)bytes)
        goto cleanup;
    memcpy(a_le, a_data, bytes);
    memcpy(b_le, b_data, bytes);

    if (bign_asn1_string_length(ecp->base) != (int)bytes)
        goto cleanup;
    base_data = ASN1_STRING_get0_data(ecp->base);
    if (!base_data)
        goto cleanup;
    memcpy(y_le, base_data, bytes);

    q_bn = ASN1_INTEGER_to_BN(ecp->order, NULL);
    if (!q_bn)
        goto cleanup;
    if (BN_num_bits(q_bn) != bits)
        goto cleanup;
    if (!bn_to_fixed_le(q_bn, q_le, bytes))
        goto cleanup;

    if (ecp->cofactor) {
        cof_bn = ASN1_INTEGER_to_BN(ecp->cofactor, NULL);
        if (!cof_bn || !BN_is_one(cof_bn))
            goto cleanup;
    }

    switch (bits) {
    case 256:
        variant = bee2_bign_variant_256();
        break;
    case 384:
        variant = bee2_bign_variant_384();
        break;
    case 512:
        variant = bee2_bign_variant_512();
        break;
    }
    if (!variant_matches_params(variant, p_le, a_le, b_le, q_le, y_le, bytes)) {
        variant = NULL;
        goto cleanup;
    }
    if (ecp->curve->seed != NULL) {
        const ASN1_BIT_STRING *seed = ecp->curve->seed;
        bign_params standard;
        unsigned char *seed_der = NULL;
        int der_len, valid;

        if (bign_asn1_string_length((const ASN1_STRING *)seed) != 8 ||
            !bee2_bign_curve_init_std(variant, &standard)) {
            variant = NULL;
            goto cleanup;
        }
        der_len = i2d_ASN1_BIT_STRING(seed, &seed_der);
        valid = der_len == 11 && seed_der != NULL &&
                seed_der[0] == V_ASN1_BIT_STRING &&
                seed_der[1] == 9 && seed_der[2] == 0 &&
                memcmp(seed_der + 3, standard.seed, 8) == 0;
        OPENSSL_free(seed_der);
        if (!valid)
            variant = NULL;
    }

cleanup:
    BN_free(p_bn);
    BN_free(q_bn);
    BN_free(cof_bn);
    return variant;
}

static const bee2_bign_variant_t *variant_from_domain_params(const ASN1_STRING *params,
                                                             int *explicit_encoding,
                                                             int *cofactor_encoding) {
    const unsigned char *p = NULL;
    long len = 0;
    BIGN_DOMAINPARAMS *dp = NULL;
    const bee2_bign_variant_t *variant = NULL;

    if (!params)
        return NULL;
    p = ASN1_STRING_get0_data(params);
    len = bign_asn1_string_length(params);
    if (!p || len <= 0)
        return NULL;

    dp = d2i_BIGN_DOMAINPARAMS(NULL, &p, len);
    if (!dp)
        return NULL;
    if (p != ASN1_STRING_get0_data(params) + len) {
        BIGN_DOMAINPARAMS_free(dp);
        return NULL;
    }

    if (dp->type == 0) {
        variant = variant_from_curve_obj(dp->value.named);
    } else if (dp->type == 1) {
        variant = variant_from_explicit_params(dp->value.specified);
        if (variant && explicit_encoding)
            *explicit_encoding = 1;
        if (variant && cofactor_encoding)
            *cofactor_encoding = dp->value.specified->cofactor != NULL;
    }

    BIGN_DOMAINPARAMS_free(dp);
    return variant;
}

static const bee2_bign_variant_t *variant_from_alg_params(int ptype,
                                                          const void *pval,
                                                          int *explicit_encoding,
                                                          int *cofactor_encoding) {
    if (explicit_encoding)
        *explicit_encoding = 0;
    if (cofactor_encoding)
        *cofactor_encoding = 0;
    if (!pval)
        return NULL;
    if (ptype == V_ASN1_OBJECT)
        return variant_from_curve_obj((const ASN1_OBJECT *)pval);
    if (ptype == V_ASN1_SEQUENCE)
        return variant_from_domain_params(
            (const ASN1_STRING *)pval, explicit_encoding, cofactor_encoding);
    return NULL;
}

static ASN1_INTEGER *asn1_integer_from_le(const unsigned char *value, size_t len) {
    BIGNUM *bn = NULL;
    ASN1_INTEGER *integer = NULL;

    bn = BN_lebin2bn(value, (int)len, NULL);
    if (!bn)
        return NULL;
    integer = BN_to_ASN1_INTEGER(bn, NULL);
    BN_clear_free(bn);
    return integer;
}

static ASN1_STRING *encode_explicit_domain_params(const bee2_bign_key_t *key) {
    bign_params curve;
    BIGN_DOMAINPARAMS *domain = NULL;
    BIGN_ECPARAMS *params = NULL;
    ASN1_STRING *sequence = NULL;
    unsigned char *der = NULL;
    size_t bytes;
    int der_len;

    if (!key || !key->variant || !bee2_bign_curve_init_std(key->variant, &curve))
        return NULL;
    bytes = bee2_bign_priv_len(key->variant);

    params = BIGN_ECPARAMS_new();
    domain = BIGN_DOMAINPARAMS_new();
    if (!params || !domain)
        goto cleanup;

    params->version = 1;
    ASN1_OBJECT_free(params->fieldID->fieldType);
    params->fieldID->fieldType = OBJ_txt2obj(BEE2_OID_BIGN_PRIMEFIELD, 1);
    ASN1_INTEGER_free(params->fieldID->prime);
    params->fieldID->prime = asn1_integer_from_le(curve.p, bytes);
    if (!params->fieldID->fieldType || !params->fieldID->prime ||
        !ASN1_OCTET_STRING_set(params->curve->a, curve.a, (int)bytes) ||
        !ASN1_OCTET_STRING_set(params->curve->b, curve.b, (int)bytes) ||
        !ASN1_OCTET_STRING_set(params->base, curve.yG, (int)bytes))
        goto cleanup;

    if (!params->curve->seed)
        params->curve->seed = ASN1_BIT_STRING_new();
    if (!params->curve->seed)
        goto cleanup;
#if OPENSSL_VERSION_MAJOR >= 4
    if (!ASN1_BIT_STRING_set1(params->curve->seed, curve.seed, 8, 0))
        goto cleanup;
#else
    params->curve->seed->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 7);
    params->curve->seed->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    if (!ASN1_BIT_STRING_set(params->curve->seed, curve.seed, 8))
        goto cleanup;
#endif

    ASN1_INTEGER_free(params->order);
    params->order = asn1_integer_from_le(curve.q, bytes);
    if (!params->order)
        goto cleanup;
    if (key->encode_cofactor) {
        params->cofactor = ASN1_INTEGER_new();
        if (!params->cofactor || !ASN1_INTEGER_set(params->cofactor, 1))
            goto cleanup;
    }

    domain->type = 1;
    domain->value.specified = params;
    params = NULL;
    der_len = i2d_BIGN_DOMAINPARAMS(domain, &der);
    if (der_len <= 0)
        goto cleanup;
    sequence = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    if (!sequence || !bign_asn1_string_set(sequence, der, der_len)) {
        ASN1_STRING_free(sequence);
        sequence = NULL;
    }

cleanup:
    OPENSSL_free(der);
    BIGN_ECPARAMS_free(params);
    BIGN_DOMAINPARAMS_free(domain);
    bee2_bign_cleanse(&curve, sizeof(curve));
    return sequence;
}

static int bign_encode_algorithm_params(const bee2_bign_key_t *key,
                                        int *parameter_type,
                                        void **parameter_value) {
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

static void bign_free_algorithm_params(int parameter_type, void *parameter_value) {
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
                                password_len, max_pbkdf2_iterations, &recognised);
    if (!recognised && p8 == NULL &&
        bee2_stb_pbes2_legacy_pbkdf2_allowed(encrypted, max_pbkdf2_iterations))
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

/* Only used by read_pem_object(), whose input is capped at 1 MiB.
 * A byte-at-a-time append needs no generic size/overflow negotiation. */
static int append_pem_byte(unsigned char **buffer, size_t *used,
                           size_t *capacity, unsigned char byte)
{
    if (*used == *capacity) {
        size_t next = *capacity != 0 ? *capacity * 2u : 4096u;
        unsigned char *expanded = OPENSSL_realloc(*buffer, next);

        if (!expanded)
            return 0;
        *buffer = expanded;
        *capacity = next;
    }
    (*buffer)[(*used)++] = byte;
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
            !append_pem_byte(&buf, &used, &capacity, ch))
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
                                 void *pw_cbarg)
{
    bee2_bign_decoder_ctx_t *ctx = vctx;
    BIO *bio;
    bee2_bign_key_t *key;
    unsigned char *buf = NULL;
    size_t len = 0;
    int decoded, ok;

    if (!ctx || !data_cb)
        return 0;
    bio = BIO_new_from_core_bio(ctx->libctx, in);
    if (!bio)
        return 0;
    ok = read_one_object(bio, &buf, &len);
    BIO_free(bio);
    if (!ok)
        return 0;
    /* This implementation is advertised as input=der. PEM is handled by
     * the separate PEM-to-DER decoder, not parsed a second time here. */
    if (len == 0 || buf[0] != 0x30) {
        OPENSSL_clear_free(buf, len);
        return 1;
    }

    key = bee2_bign_key_new(NULL);
    if (!key) {
        OPENSSL_clear_free(buf, len);
        return 0;
    }
    decoded = bee2_bign_asn1_decode_pkcs8_der(buf, len, ctx->variant, key);
    if (!decoded)
        decoded = bee2_bign_asn1_decode_encrypted_pkcs8_der(
            buf, len, ctx->variant, key, ctx->libctx,
            ctx->max_pbkdf2_iterations, pw_cb, pw_cbarg);
    if (!decoded)
        decoded = bee2_bign_asn1_decode_spki_der(buf, len, ctx->variant, key);

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
        OPENSSL_clear_free(buf, len);
        /* EncryptedPrivateKeyInfo is shared by all key algorithms.
         * An unsuccessful BIGN decode must not abort other decoders. */
        return 1;
    }

    {
        int obj_type = OSSL_OBJECT_PKEY;
        const char *data_type = "bign";
        void *objref = key;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             (char *)data_type, 0),
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &objref, sizeof(objref)),
            OSSL_PARAM_construct_end()
        };

        ok = data_cb(params, data_cbarg);
    }
    bee2_bign_key_free(key);
    OPENSSL_clear_free(buf, len);
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

    if (!read_one_object(bio, &buf, &len))
        goto end;
    if (len == 0) {
        ok = 1;
        goto end;
    }
    if (ctx->input_pem && buf[0] != 0x30) {
        converted = pem_to_der_buf(buf, len, &payload_len, &pem_name);
        if (converted == NULL || payload_len == 0 ||
            payload_len > BIGN_MAX_KEY_INPUT)
            goto end;
        payload = converted;
    } else {
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
                                &recognised);
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

static const char *kwp_oid(size_t key_len)
{
    switch (key_len) {
    case 16: return BEE2_OID_BELT_128_KWP;
    case 24: return BEE2_OID_BELT_192_KWP;
    case 32: return BEE2_OID_BELT_KWP;
    default: return NULL;
    }
}

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

static ASN1_STRING *pack_param(const ASN1_VALUE *value, const ASN1_ITEM *item)
{
    return ASN1_item_pack((void *)value, item, NULL);
}

static X509_SIG *build_encrypted_info(const unsigned char *salt, size_t salt_len,
                                      unsigned int iterations, size_t key_len,
                                      const unsigned char *wrapped, size_t wrapped_len)
{
    PBKDF2PARAM *kdf = NULL;
    PBE2PARAM *pbe = NULL;
    X509_SIG *info = NULL;
    X509_ALGOR *outer = NULL;
    ASN1_OCTET_STRING *encrypted = NULL;
    ASN1_OCTET_STRING *asn_salt = NULL;
    ASN1_STRING *encoded = NULL;
    const char *oid = kwp_oid(key_len);
    int ok = 0;

    /* Sizes and the KWP key variant are checked by the only caller. */
    kdf = PBKDF2PARAM_new();
    pbe = PBE2PARAM_new();
    info = X509_SIG_new();
    if (kdf == NULL || pbe == NULL || info == NULL)
        goto end;

    asn_salt = ASN1_OCTET_STRING_new();
    if (asn_salt == NULL || !ASN1_OCTET_STRING_set(asn_salt, salt, (int)salt_len))
        goto end;
    ASN1_TYPE_set(kdf->salt, V_ASN1_OCTET_STRING, asn_salt);
    asn_salt = NULL;
    if (!ASN1_INTEGER_set(kdf->iter, (long)iterations))
        goto end;
    kdf->keylength = ASN1_INTEGER_new();
    if (kdf->keylength == NULL || !ASN1_INTEGER_set(kdf->keylength, (long)key_len))
        goto end;
    kdf->prf = X509_ALGOR_new();
    if (kdf->prf == NULL || !set_alg(kdf->prf, BEE2_OID_HMAC_HBELT, V_ASN1_NULL, NULL))
        goto end;

    encoded = pack_param((const ASN1_VALUE *)kdf, ASN1_ITEM_rptr(PBKDF2PARAM));
    if (encoded == NULL || !set_alg(pbe->keyfunc, BEE2_OID_PBKDF2, V_ASN1_SEQUENCE, encoded))
        goto end;
    encoded = NULL;
    /* KWP has no IV; the mandatory 16-byte header is all zeroes. */
    if (!set_alg(pbe->encryption, oid, V_ASN1_UNDEF, NULL))
        goto end;
    encoded = pack_param((const ASN1_VALUE *)pbe, ASN1_ITEM_rptr(PBE2PARAM));
    if (encoded == NULL)
        goto end;
    X509_SIG_getm(info, &outer, &encrypted);
    if (!set_alg(outer, BEE2_OID_PBES2, V_ASN1_SEQUENCE, encoded))
        goto end;
    encoded = NULL;
    if (!ASN1_OCTET_STRING_set(encrypted, wrapped, (int)wrapped_len))
        goto end;
    ok = 1;

end:
    ASN1_OCTET_STRING_free(asn_salt);
    ASN1_STRING_free(encoded);
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    if (!ok) {
        X509_SIG_free(info);
        info = NULL;
    }
    return info;
}

unsigned char *bee2_stb_pbes2_encrypt(const unsigned char *der, size_t der_len,
                                      const unsigned char *password, size_t password_len,
                                      size_t key_len, unsigned int iterations,
                                      size_t salt_len, OSSL_LIB_CTX *libctx, size_t *out_len)
{
    unsigned char derived[32] = {0};
    unsigned char *salt = NULL, *wrapped = NULL, *result = NULL;
    X509_SIG *info = NULL;
    int n;

    if (out_len == NULL)
        return NULL;
    *out_len = 0;
    if (der == NULL || password == NULL || kwp_oid(key_len) == NULL ||
        password_len > INT_MAX || der_len < 16 || der_len > INT_MAX - 16 ||
        iterations < BEE2_STB_PBKDF2_MIN_ITER || iterations > INT_MAX ||
        salt_len < BEE2_STB_PBKDF2_MIN_SALT || salt_len > INT_MAX)
        return NULL;

    salt = OPENSSL_malloc(salt_len);
    wrapped = OPENSSL_malloc(der_len + 16);
    if (salt == NULL || wrapped == NULL || RAND_priv_bytes_ex(libctx, salt, salt_len, 0) != 1 ||
        beltPBKDF2(derived, password, password_len, iterations, salt, salt_len) != ERR_OK ||
        beltKWPWrap(wrapped, der, der_len, NULL, derived, key_len) != ERR_OK)
        goto end;

    info = build_encrypted_info(salt, salt_len, iterations, key_len, wrapped, der_len + 16);
    if (info == NULL)
        goto end;
    n = i2d_X509_SIG(info, &result);
    if (n <= 0) {
        OPENSSL_free(result);
        result = NULL;
    } else {
        *out_len = (size_t)n;
    }

end:
    OPENSSL_cleanse(derived, sizeof(derived));
    OPENSSL_clear_free(salt, salt_len);
    OPENSSL_clear_free(wrapped, der_len + 16);
    X509_SIG_free(info);
    return result;
}

static size_t asn_length(const ASN1_STRING *value)
{
    int len = bign_asn1_string_length(value);
    return len < 0 ? SIZE_MAX : (size_t)len;
}


int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted)
{
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *obj = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    int type, recognised = 0;
    size_t key_len;

    if (encrypted == NULL)
        return 0;
    X509_SIG_get0(encrypted, &alg, &ciphertext);
    if (alg == NULL || ciphertext == NULL)
        return 0;
    X509_ALGOR_get0(&obj, &type, &value, alg);
    if (!oid_equals(obj, BEE2_OID_PBES2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        return 0;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe != NULL) {
        X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
        for (key_len = 16; key_len <= 32; key_len += 8) {
            if (oid_equals(obj, kwp_oid(key_len))) {
                recognised = 1;
                break;
            }
        }
    }
    PBE2PARAM_free(pbe);
    return recognised;
}


/* Only bounded PBKDF2 is attempted by the BIGN legacy PBES2 fallback.
 * Other KDFs are left to OpenSSL's normal decoder chain. */
int bee2_stb_pbes2_legacy_pbkdf2_allowed(const X509_SIG *encrypted,
                                          unsigned int max_iterations)
{
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    long iterations;
    int type, allowed = 0;

    if (!encrypted || max_iterations == 0)
        return 0;
    X509_SIG_get0(encrypted, &alg, &ciphertext);
    if (!alg || !ciphertext)
        return 0;
    X509_ALGOR_get0(&oid, &type, &value, alg);
    if (!oid_equals(oid, BEE2_OID_PBES2) ||
        type != V_ASN1_SEQUENCE || !value)
        return 0;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (!pbe)
        goto end;
    X509_ALGOR_get0(&oid, &type, &value, pbe->keyfunc);
    if (!oid_equals(oid, BEE2_OID_PBKDF2) ||
        type != V_ASN1_SEQUENCE || !value)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
    if (!kdf)
        goto end;
    iterations = ASN1_INTEGER_get(kdf->iter);
    allowed = iterations > 0 && (unsigned long)iterations <= max_iterations;

end:
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    return allowed;
}

PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len,
                                            unsigned int max_iterations, int *recognised)
{
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *obj = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char derived[32] = {0};
    unsigned char *plain = NULL;
    const unsigned char *salt, *wrapped, *p;
    size_t salt_len, wrapped_len, plain_len, key_len = 0, k;
    long iter;
    int type = V_ASN1_UNDEF;

    if (recognised == NULL)
        return NULL;
    *recognised = 0;
    if (encrypted == NULL || password == NULL || password_len > INT_MAX)
        return NULL;
    X509_SIG_get0(encrypted, &alg, &ciphertext);
    if (alg == NULL || ciphertext == NULL)
        return NULL;
    X509_ALGOR_get0(&obj, &type, &value, alg);
    if (!oid_equals(obj, BEE2_OID_PBES2) || type != V_ASN1_SEQUENCE || value == NULL)
        return NULL;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    /* PBE2PARAM decoding enforces both mandatory AlgorithmIdentifiers. */
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
    for (k = 16; k <= 32; k += 8) {
        if (oid_equals(obj, kwp_oid(k))) {
            *recognised = 1;
            key_len = k;
            break;
        }
    }
    if (!*recognised)
        goto end;
    if (type != V_ASN1_UNDEF && type != V_ASN1_NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->keyfunc);
    if (!oid_equals(obj, BEE2_OID_PBKDF2) || type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
    /* salt and iter are mandatory ASN.1 fields; the STB PRF is not. */
    if (kdf == NULL || kdf->prf == NULL ||
        kdf->salt->type != V_ASN1_OCTET_STRING)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, kdf->prf);
    if (!oid_equals(obj, BEE2_OID_HMAC_HBELT) ||
        (type != V_ASN1_UNDEF && type != V_ASN1_NULL))
        goto end;
    if (kdf->keylength != NULL && ASN1_INTEGER_get(kdf->keylength) != (long)key_len)
        goto end;
    iter = ASN1_INTEGER_get(kdf->iter);
    salt_len = asn_length(kdf->salt->value.octet_string);
    wrapped_len = asn_length(ciphertext);
    if (iter < BEE2_STB_PBKDF2_MIN_ITER || iter > INT_MAX ||
        iter > (long)max_iterations ||
        salt_len < BEE2_STB_PBKDF2_MIN_SALT || salt_len > INT_MAX ||
        wrapped_len < 32 || wrapped_len > INT_MAX)
        goto end;
    salt = ASN1_STRING_get0_data(kdf->salt->value.octet_string);
    wrapped = ASN1_STRING_get0_data(ciphertext);
    if (salt == NULL || wrapped == NULL)
        goto end;
    plain_len = wrapped_len - 16;
    plain = OPENSSL_malloc(plain_len);
    if (plain == NULL)
        goto end;
    if (beltPBKDF2(derived, password, password_len, (size_t)iter, salt, salt_len) != ERR_OK)
        goto end;
    if (beltKWPUnwrap(plain, wrapped, wrapped_len, NULL, derived, key_len) != ERR_OK)
        goto end;
    p = plain;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)plain_len);
    if (p8 != NULL && p != plain + plain_len) {
        PKCS8_PRIV_KEY_INFO_free(p8);
        p8 = NULL;
    }

end:
    OPENSSL_cleanse(derived, sizeof(derived));
    if (plain != NULL)
        OPENSSL_clear_free(plain, wrapped_len - 16);
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
    if (!der || !pass || !cipher || pass_len > INT_MAX ||
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
