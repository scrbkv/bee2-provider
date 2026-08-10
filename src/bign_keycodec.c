#include "bee2_oids.h"
#include "bign_common.h"

#include <limits.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIGN_PEM_LABEL "PRIVATE KEY"
#define BIGN_PUB_PEM_LABEL "PUBLIC KEY"

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

#if OPENSSL_VERSION_MAJOR >= 3
                            DECLARE_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)
                                DECLARE_ASN1_ENCODE_FUNCTIONS_name(BIGN_DOMAINPARAMS,
                                                                   BIGN_DOMAINPARAMS)
                                    IMPLEMENT_ASN1_FUNCTIONS(BIGN_DOMAINPARAMS)
#else
                            DECLARE_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
                                DECLARE_ASN1_ENCODE_FUNCTIONS_const(BIGN_DOMAINPARAMS,
                                                                    BIGN_DOMAINPARAMS)
                                    IMPLEMENT_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
#endif

                                        typedef struct {
    const bee2_bign_variant_t *variant;
    int output_pem;
} bee2_bign_encoder_ctx_t;

typedef struct {
    const bee2_bign_variant_t *variant;
} bee2_bign_decoder_ctx_t;

typedef struct {
    unsigned char *data;
    size_t len;
    int done;
} bee2_bign_store_ctx_t;

static int write_all_core(OSSL_CORE_BIO *bio, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len > 0) {
        size_t chunk = (len > INT_MAX) ? (size_t)INT_MAX : len;
        size_t written = 0;
        if (!bee2_core_bio_write(bio, p, chunk, &written) || written == 0)
            return 0;
        p += written;
        len -= written;
    }
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

static int
write_pem_payload(OSSL_CORE_BIO *bio, const unsigned char *data, size_t len, const char *label) {
    char header[64];
    char footer[64];
    int hdr_len = snprintf(header, sizeof(header), "-----BEGIN %s-----\n", label);
    int ftr_len = snprintf(footer, sizeof(footer), "-----END %s-----\n", label);
    unsigned char b64[80];

    if (hdr_len <= 0 || ftr_len <= 0)
        return 0;
    if (!write_all_core(bio, header, (size_t)hdr_len))
        return 0;

    for (size_t offset = 0; offset < len; offset += 48) {
        size_t chunk_len = len - offset;
        if (chunk_len > 48)
            chunk_len = 48;
        int outlen = EVP_EncodeBlock(b64, data + offset, (int)chunk_len);
        if (outlen <= 0)
            return 0;
        if (!write_all_core(bio, b64, (size_t)outlen))
            return 0;
        if (!write_all_core(bio, "\n", 1))
            return 0;
    }

    if (!write_all_core(bio, footer, (size_t)ftr_len))
        return 0;
    return 1;
}

static int oid_equals(const ASN1_OBJECT *obj, const char *oid) {
    char buf[80];
    int n;

    if (!obj || !oid)
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
    unsigned char tmp[BEE2_BIGN_MAX_WORDS * 8];
    size_t i;

    if (!bn || !out)
        return 0;
    if (BN_is_negative(bn))
        return 0;
    if (len > sizeof(tmp))
        return 0;
    if (BN_num_bytes(bn) > (int)len)
        return 0;
    if (BN_bn2binpad(bn, tmp, (int)len) != (int)len)
        return 0;

    for (i = 0; i < len; ++i)
        out[i] = tmp[len - 1 - i];
    return 1;
}

static int variant_matches_params(const bee2_bign_variant_t *variant,
                                  const unsigned char *p_le,
                                  const unsigned char *a_le,
                                  const unsigned char *b_le,
                                  const unsigned char *q_le,
                                  const unsigned char *y_le,
                                  size_t bytes) {
    bign_params curve;
    if (!variant)
        return 0;
    if (bee2_bign_priv_len(variant) != bytes)
        return 0;
    if (!bee2_bign_curve_init_std(variant, &curve))
        return 0;
    if (curve.l / 4u != bytes)
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
    const bee2_bign_variant_t *variants[] = {
        bee2_bign_variant_256(),
        bee2_bign_variant_384(),
        bee2_bign_variant_512(),
    };
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
    size_t i;

    if (!ecp || ecp->version != 1)
        return NULL;
    if (!ecp->fieldID || !ecp->fieldID->fieldType || !ecp->fieldID->prime)
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
    if (!ecp->curve || !ecp->curve->a || !ecp->curve->b)
        goto cleanup;
    a_data = ASN1_STRING_get0_data(ecp->curve->a);
    b_data = ASN1_STRING_get0_data(ecp->curve->b);
    if (!a_data || !b_data)
        goto cleanup;
    if (ASN1_STRING_length(ecp->curve->a) != (int)bytes ||
        ASN1_STRING_length(ecp->curve->b) != (int)bytes)
        goto cleanup;
    memcpy(a_le, a_data, bytes);
    memcpy(b_le, b_data, bytes);

    if (!ecp->base || ASN1_STRING_length(ecp->base) != (int)bytes)
        goto cleanup;
    base_data = ASN1_STRING_get0_data(ecp->base);
    if (!base_data)
        goto cleanup;
    memcpy(y_le, base_data, bytes);

    if (!ecp->order)
        goto cleanup;
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

    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        if (variant_matches_params(variants[i], p_le, a_le, b_le, q_le, y_le, bytes)) {
            variant = variants[i];
            break;
        }
    }

cleanup:
    if (p_bn)
        BN_free(p_bn);
    if (q_bn)
        BN_free(q_bn);
    if (cof_bn)
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
    len = ASN1_STRING_length(params);
    if (!p || len <= 0)
        return NULL;

    dp = d2i_BIGN_DOMAINPARAMS(NULL, &p, len);
    if (!dp)
        return NULL;

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

    if (!value || len > INT_MAX)
        return NULL;
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
    if (!params || !domain || !params->fieldID || !params->curve || !params->base)
        goto cleanup;

    params->version = 1;
    ASN1_OBJECT_free(params->fieldID->fieldType);
    params->fieldID->fieldType = OBJ_txt2obj(BEE2_OID_BIGN_PRIMEFIELD, 1);
    ASN1_INTEGER_free(params->fieldID->prime);
    params->fieldID->prime = asn1_integer_from_le(curve.p, bytes);
    if (!params->fieldID->fieldType || !params->fieldID->prime || !params->curve->a ||
        !params->curve->b || !ASN1_OCTET_STRING_set(params->curve->a, curve.a, (int)bytes) ||
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
    if (!sequence || !ASN1_STRING_set(sequence, der, der_len)) {
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

static unsigned char *encode_pkcs8_der(const bee2_bign_key_t *key, size_t *out_len) {
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

static int decode_pkcs8_der(const unsigned char *buf,
                            size_t len,
                            const bee2_bign_variant_t *expected,
                            bee2_bign_key_t *key) {
    const unsigned char *p = buf;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const ASN1_OBJECT *alg = NULL;
    const unsigned char *priv = NULL;
    int priv_len = 0;
    const X509_ALGOR *palg = NULL;
    int ptype = 0;
    const void *pval = NULL;
    const bee2_bign_variant_t *variant = NULL;
    size_t need = 0;

    if (!buf || len == 0 || !key)
        return 0;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)len);
    if (!p8)
        return 0;

    if (!PKCS8_pkey_get0(&alg, &priv, &priv_len, &palg, p8)) {
        goto err;
    }
    if (!oid_equals(alg, BEE2_OID_BIGN_PUBKEY))
        goto err;

    X509_ALGOR_get0(NULL, &ptype, &pval, palg);
    variant = variant_from_alg_params(ptype, pval, &key->encode_explicit, &key->encode_cofactor);
    if (!variant || (expected && variant != expected))
        goto err;

    need = bee2_bign_priv_len(variant);
    if (priv_len != (int)need)
        goto err;

    key->variant = variant;
    memcpy(key->priv, priv, need);
    key->has_priv = 1;
    if (!bee2_bign_derive_pubkey(key->variant, key->pub, key->priv))
        goto err;
    key->has_pub = 1;

    PKCS8_PRIV_KEY_INFO_free(p8);
    return 1;

err:
    PKCS8_PRIV_KEY_INFO_free(p8);
    return 0;
}

static unsigned char *read_all(OSSL_CORE_BIO *in, size_t *out_len) {
    unsigned char *buf = NULL;
    size_t cap = 0;
    size_t used = 0;
    unsigned char tmp[4096];

    if (!in) {
        return NULL;
    }

    for (;;) {
        size_t n = 0;
        int ok = bee2_core_bio_read(in, tmp, sizeof(tmp), &n);
        if (!ok) {
            if (n == 0)
                break;
            OPENSSL_clear_free(buf, cap);
            return NULL;
        }
        if (n == 0)
            break;
        if (!append_bytes(&buf, &used, &cap, tmp, n)) {
            OPENSSL_clear_free(buf, cap);
            return NULL;
        }
    }

    if (out_len)
        *out_len = used;
    return buf;
}

static int is_pem_data(const unsigned char *buf, size_t len) {
    static const unsigned char marker[] = "-----BEGIN";
    size_t offset;

    if (!buf || len < sizeof(marker) - 1)
        return 0;
    for (offset = 0; offset <= len - (sizeof(marker) - 1); ++offset) {
        if (memcmp(buf + offset, marker, sizeof(marker) - 1) == 0)
            return 1;
    }
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

static unsigned char *encode_spki_der(const bee2_bign_key_t *key, size_t *out_len) {
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

static int decode_spki_der(const unsigned char *buf,
                           size_t len,
                           const bee2_bign_variant_t *expected,
                           bee2_bign_key_t *key) {
    const unsigned char *p = buf;
    long seqlen = 0;
    int tag = 0;
    int xclass = 0;
    int ret;
    X509_ALGOR *alg = NULL;
    ASN1_BIT_STRING *bit = NULL;
    const ASN1_OBJECT *aobj = NULL;
    int ptype = 0;
    const void *pval = NULL;
    const bee2_bign_variant_t *variant = NULL;
    const unsigned char *pub = NULL;
    int pub_len = 0;
    int ok = 0;

    if (!buf || len == 0 || !key)
        return 0;

    ret = ASN1_get_object(&p, &seqlen, &tag, &xclass, (long)len);
    if ((ret & 0x80) != 0 || tag != V_ASN1_SEQUENCE || seqlen < 0)
        return 0;
    if ((size_t)seqlen > (size_t)(buf + len - p))
        return 0;

    const unsigned char *seq_end = p + seqlen;

    alg = d2i_X509_ALGOR(NULL, &p, (long)(seq_end - p));
    if (!alg)
        goto cleanup;

    bit = d2i_ASN1_BIT_STRING(NULL, &p, (long)(seq_end - p));
    if (!bit)
        goto cleanup;

    X509_ALGOR_get0(&aobj, &ptype, &pval, alg);
    if (!oid_equals(aobj, BEE2_OID_BIGN_PUBKEY))
        goto cleanup;

    variant = variant_from_alg_params(ptype, pval, &key->encode_explicit, &key->encode_cofactor);
    if (!variant)
        goto cleanup;
    if (expected && expected != variant)
        goto cleanup;

    pub = ASN1_STRING_get0_data((const ASN1_STRING *)bit);
    pub_len = ASN1_STRING_length((const ASN1_STRING *)bit);
    if (!pub || pub_len != (int)bee2_bign_pub_len(variant))
        goto cleanup;

    key->variant = variant;
    memcpy(key->pub, pub, (size_t)pub_len);
    key->has_pub = 1;
    ok = 1;

cleanup:
    ASN1_BIT_STRING_free(bit);
    X509_ALGOR_free(alg);
    return ok;
}

static void *bign_encoder_newctx_common(const bee2_bign_variant_t *variant, int output_pem) {
    bee2_bign_encoder_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->variant = variant;
    ctx->output_pem = output_pem;
    return ctx;
}

static void bign_encoder_freectx(void *vctx) {
    OPENSSL_free(vctx);
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
    (void)cb;
    (void)cbarg;

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
        der = encode_pkcs8_der(key, &der_len);
        label = BIGN_PEM_LABEL;
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        der = encode_spki_der(key, &der_len);
        label = BIGN_PUB_PEM_LABEL;
    }
    if (!der) {
        ERR_raise_data(
            ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "bign_encoder_encode: key encoding failed");
        return 0;
    }

    int ok = 0;
    if (ctx->output_pem) {
        ok = write_pem_payload(out, der, der_len, label);
    } else {
        ok = write_all_core(out, der, der_len);
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
    const OSSL_PARAM *p = NULL;
    char *group = NULL;
    const bee2_bign_variant_t *variant = NULL;
    bee2_bign_key_t *key = NULL;
    const void *buf = NULL;
    size_t len = 0;

    if (!ctx || !params)
        return NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p && !OSSL_PARAM_get_utf8_string(p, &group, 0))
        return NULL;
    variant = bee2_bign_variant_from_name(group);
    OPENSSL_free(group);
    if (!variant || variant != ctx->variant) {
        return NULL;
    }

    key = bee2_bign_key_new(variant);
    if (!key)
        return NULL;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (!p)
            goto err;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &buf, &len))
            goto err;
        if (len != bee2_bign_priv_len(variant))
            goto err;
        memcpy(key->priv, buf, len);
        key->has_priv = 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &buf, &len))
            goto err;
        if (len != bee2_bign_pub_len(variant))
            goto err;
        memcpy(key->pub, buf, len);
        key->has_pub = 1;
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && key->has_priv &&
               !bee2_bign_key_ensure_public(key))
        goto err;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_priv)
        goto err;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !key->has_pub)
        goto err;

    return key;

err:
    bee2_bign_key_free(key);
    return NULL;
}

static int
bign_export_key_params(const bee2_bign_key_t *key, OSSL_CALLBACK *export_cb, void *export_cbarg) {
    if (!key || !export_cb)
        return 0;

    size_t priv_len = bee2_bign_priv_len(key->variant);
    size_t pub_len = bee2_bign_pub_len(key->variant);

    OSSL_PARAM params[5];
    size_t n = 0;

    params[n++] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, (char *)key->variant->curve_oid, 0);
    if (key->has_priv) {
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, (void *)key->priv, priv_len);
    }
    if (key->has_pub) {
        params[n++] =
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)key->pub, pub_len);
    }
    params[n] = OSSL_PARAM_construct_end();

    return export_cb(params, export_cbarg);
}

static void bign_encoder_free_object(void *obj) {
    bee2_bign_key_free(obj);
}

static void *bign_decoder_newctx_common(const bee2_bign_variant_t *variant) {
    bee2_bign_decoder_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->variant = variant;
    return ctx;
}

static void bign_decoder_freectx(void *vctx) {
    OPENSSL_free(vctx);
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

static int bign_decoder_decode(void *vctx,
                               OSSL_CORE_BIO *in,
                               int selection,
                               OSSL_CALLBACK *data_cb,
                               void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb,
                               void *pw_cbarg) {
    (void)selection;
    (void)pw_cb;
    (void)pw_cbarg;

    bee2_bign_decoder_ctx_t *ctx = vctx;
    if (!ctx || !data_cb)
        return 0;

    size_t len = 0;
    unsigned char *buf = read_all(in, &len);
    if (!buf || len == 0) {
        OPENSSL_clear_free(buf, len);
        return 0;
    }

    unsigned char *der = buf;
    size_t der_len = len;
    int is_pem = is_pem_data(buf, len);
    char *pem_name = NULL;
    if (is_pem) {
        der = pem_to_der_buf(buf, len, &der_len, &pem_name);
        if (!der || der_len == 0) {
            OPENSSL_clear_free(buf, len);
            OPENSSL_free(der);
            OPENSSL_free(pem_name);
            return 0;
        }
    }

    bee2_bign_key_t *key = bee2_bign_key_new(NULL);
    if (!key) {
        OPENSSL_clear_free(buf, len);
        return 0;
    }

    int decoded = 0;
    if (pem_name) {
        if (strcmp(pem_name, BIGN_PEM_LABEL) == 0) {
            decoded = decode_pkcs8_der(der, der_len, ctx->variant, key);
        } else if (strcmp(pem_name, BIGN_PUB_PEM_LABEL) == 0) {
            decoded = decode_spki_der(der, der_len, ctx->variant, key);
        }
    } else {
        decoded = decode_pkcs8_der(der, der_len, ctx->variant, key);
        if (!decoded) {
            decoded = decode_spki_der(der, der_len, ctx->variant, key);
        }
    }

    if (!decoded) {
        bee2_bign_key_free(key);
        if (der != buf)
            OPENSSL_free(der);
        OPENSSL_clear_free(buf, len);
        OPENSSL_free(pem_name);
        return 0;
    }

    int obj_type = OSSL_OBJECT_PKEY;
    const char *data_type = key->variant->name;
    void *objref = key;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type),
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0),
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &objref, sizeof(objref)),
        OSSL_PARAM_construct_end()};

    int ok = data_cb(params, data_cbarg);

    bee2_bign_key_free(key);
    if (der != buf)
        OPENSSL_free(der);
    OPENSSL_clear_free(buf, len);
    OPENSSL_free(pem_name);
    return ok;
}

#define BIGN_CODEC_NEWCTX(BITS) \
    static void *bign##BITS##_pem_encoder_newctx(void *provctx) { \
        (void)provctx; \
        return bign_encoder_newctx_common(bee2_bign_variant_##BITS(), 1); \
    } \
    static void *bign##BITS##_der_encoder_newctx(void *provctx) { \
        (void)provctx; \
        return bign_encoder_newctx_common(bee2_bign_variant_##BITS(), 0); \
    } \
    static void *bign##BITS##_decoder_newctx(void *provctx) { \
        (void)provctx; \
        return bign_decoder_newctx_common(bee2_bign_variant_##BITS()); \
    }

BIGN_CODEC_NEWCTX(256)
BIGN_CODEC_NEWCTX(384)
BIGN_CODEC_NEWCTX(512)

static void *bign_store_open_ex(void *provctx,
                                const char *uri,
                                const OSSL_PARAM params[],
                                OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                void *pw_cbarg) {
    (void)provctx;
    (void)params;
    (void)pw_cb;
    (void)pw_cbarg;

    if (!uri)
        return NULL;

    const char *path = uri;
    if (strncmp(uri, "bign:", 5) == 0) {
        path = uri + 5;
    } else if (strncmp(uri, "file:", 5) == 0) {
        path = uri + 5;
        if (path[0] == '/' && path[1] == '/')
            path += 2;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    unsigned char *buf = NULL;
    size_t cap = 0;
    size_t len = 0;
    unsigned char tmp[4096];
    while (!feof(fp)) {
        size_t n = fread(tmp, 1, sizeof(tmp), fp);
        if (n == 0)
            break;
        if (!append_bytes(&buf, &len, &cap, tmp, n)) {
            OPENSSL_clear_free(buf, cap);
            fclose(fp);
            return NULL;
        }
    }
    if (ferror(fp)) {
        OPENSSL_clear_free(buf, cap);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    if (!buf || len == 0) {
        OPENSSL_clear_free(buf, cap);
        return NULL;
    }

    bee2_bign_store_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) {
        OPENSSL_clear_free(buf, cap);
        return NULL;
    }
    ctx->data = buf;
    ctx->len = len;
    ctx->done = 0;
    return ctx;
}

static void *bign_store_open(void *provctx, const char *uri) {
    return bign_store_open_ex(provctx, uri, NULL, NULL, NULL);
}

static int bign_store_load(void *vctx,
                           OSSL_CALLBACK *object_cb,
                           void *object_cbarg,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb,
                           void *pw_cbarg) {
    (void)pw_cb;
    (void)pw_cbarg;

    bee2_bign_store_ctx_t *ctx = vctx;
    if (!ctx || ctx->done || !object_cb)
        return 0;
    ctx->done = 1;

    unsigned char *der = NULL;
    size_t der_len = 0;
    char *name = NULL;
    char *header = NULL;
    unsigned char *pdata = NULL;
    long pdata_len = 0;

    BIO *bio = BIO_new_mem_buf(ctx->data, (int)ctx->len);
    if (bio && PEM_read_bio(bio, &name, &header, &pdata, &pdata_len)) {
        if (name && strcmp(name, BIGN_PEM_LABEL) == 0) {
            der = pdata;
            der_len = (size_t)pdata_len;
            pdata = NULL;
        }
    }
    BIO_free(bio);
    OPENSSL_free(name);
    OPENSSL_free(header);

    if (!der) {
        der = ctx->data;
        der_len = ctx->len;
    }

    bee2_bign_key_t *tmp_key = bee2_bign_key_new(NULL);
    if (!tmp_key) {
        OPENSSL_free(pdata);
        return 0;
    }
    if (!decode_pkcs8_der(der, der_len, NULL, tmp_key)) {
        bee2_bign_key_free(tmp_key);
        OPENSSL_free(pdata);
        return 0;
    }

    int obj_type = OSSL_OBJECT_PKEY;
    const char *data_type = tmp_key->variant->name;
    const char *data_structure = "PrivateKeyInfo";
    const char *input_type = "der";

    OSSL_PARAM params[6];
    size_t n = 0;
    params[n++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &obj_type);
    params[n++] =
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)data_type, 0);
    params[n++] = OSSL_PARAM_construct_utf8_string(
        OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)data_structure, 0);
#ifdef OSSL_OBJECT_PARAM_INPUT_TYPE
    params[n++] =
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_INPUT_TYPE, (char *)input_type, 0);
#else
    (void)input_type;
#endif
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, der_len);
    params[n] = OSSL_PARAM_construct_end();

    int ok = object_cb(params, object_cbarg);

    OPENSSL_free(pdata);
    OPENSSL_clear_free(ctx->data, ctx->len);
    ctx->data = NULL;
    ctx->len = 0;
    bee2_bign_key_free(tmp_key);
    return ok;
}

static int bign_store_eof(void *vctx) {
    bee2_bign_store_ctx_t *ctx = vctx;
    return ctx ? ctx->done : 1;
}

static int bign_store_close(void *vctx) {
    bee2_bign_store_ctx_t *ctx = vctx;
    if (!ctx)
        return 1;
    if (ctx->data)
        OPENSSL_clear_free(ctx->data, ctx->len);
    OPENSSL_free(ctx);
    return 1;
}

static int bign_store_export_object(void *vctx,
                                    const void *objref,
                                    size_t objref_sz,
                                    OSSL_CALLBACK *export_cb,
                                    void *export_cbarg) {
    (void)vctx;
    if (!export_cb)
        return 0;

    bee2_bign_key_t *key = NULL;
    if (objref_sz == sizeof(void *)) {
        memcpy(&key, objref, sizeof(key));
    } else {
        key = (bee2_bign_key_t *)objref;
    }
    if (!key || !key->variant || !key->has_priv)
        return 0;

    return bign_export_key_params(key, export_cb, export_cbarg);
}

#define BIGN_ENCODER_DISPATCH(BITS, FORMAT) \
    const OSSL_DISPATCH bee2_bign_##BITS##_##FORMAT##_encoder_functions[] = { \
        {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))bign##BITS##_##FORMAT##_encoder_newctx}, \
        {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))bign_encoder_freectx}, \
        {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))bign_encoder_does_selection}, \
        {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))bign_encoder_encode}, \
        {OSSL_FUNC_ENCODER_IMPORT_OBJECT, (void (*)(void))bign_encoder_import_object}, \
        {OSSL_FUNC_ENCODER_FREE_OBJECT, (void (*)(void))bign_encoder_free_object}, \
        {0, NULL}};

#define BIGN_DECODER_DISPATCH(BITS) \
    const OSSL_DISPATCH bee2_bign_##BITS##_decoder_functions[] = { \
        {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))bign##BITS##_decoder_newctx}, \
        {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))bign_decoder_freectx}, \
        {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))bign_decoder_does_selection}, \
        {OSSL_FUNC_DECODER_DECODE, (void (*)(void))bign_decoder_decode}, \
        {0, NULL}};

BIGN_ENCODER_DISPATCH(256, pem)
BIGN_ENCODER_DISPATCH(256, der)
BIGN_ENCODER_DISPATCH(384, pem)
BIGN_ENCODER_DISPATCH(384, der)
BIGN_ENCODER_DISPATCH(512, pem)
BIGN_ENCODER_DISPATCH(512, der)
BIGN_DECODER_DISPATCH(256)
BIGN_DECODER_DISPATCH(384)
BIGN_DECODER_DISPATCH(512)

const OSSL_DISPATCH bee2_bign_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))bign_store_open},
#ifdef OSSL_FUNC_STORE_OPEN_EX
    {OSSL_FUNC_STORE_OPEN_EX, (void (*)(void))bign_store_open_ex},
#endif
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))bign_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))bign_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))bign_store_close},
    {OSSL_FUNC_STORE_EXPORT_OBJECT, (void (*)(void))bign_store_export_object},
    {0, NULL}};
