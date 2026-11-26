/* BIGN ASN.1 key payloads and PBES2 serialization. */
#include "bign_asn1.h"
#include "bign_der_frame.h"
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
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
        body_length < 0 || (size_t)body_length != (size_t)(data + length - p) ||
        ASN1_object_size(1, (int)body_length, V_ASN1_SEQUENCE) != (int)length)
        return 0;

    *body = p;
    return 1;
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

/* Space for the explicit curve plus ASN.1 tags, lengths and cofactor. */
#define BIGN_EC_PARAMS_DER_MAX (sizeof(bign_params) + 96)

/* Bee2 encodes ECParameters. OpenSSL adds its optional cofactor. */
static size_t encode_curve(const bee2_bign_variant_t *variant, int cofactor,
                           unsigned char der[BIGN_EC_PARAMS_DER_MAX])
{
    bign_params params;
    const unsigned char *body;
    ASN1_INTEGER *one;
    size_t len = BIGN_EC_PARAMS_DER_MAX, body_len;
    int integer_len, total;
    unsigned char *p = der;

    if (!bee2_bign_curve_init_std(variant, &params) ||
        bignParamsEnc(der, &len, &params) != ERR_OK)
        return 0;
    if (!cofactor)
        return len;
    if (!bign_der_sequence_body(der, len, &body))
        return 0;
    body_len = (size_t)(der + len - body);
    one = ASN1_INTEGER_new();
    if (one == NULL || !ASN1_INTEGER_set(one, 1)) {
        ASN1_INTEGER_free(one);
        return 0;
    }
    integer_len = i2d_ASN1_INTEGER(one, NULL);
    total = integer_len > 0
        ? ASN1_object_size(1, (int)body_len + integer_len, V_ASN1_SEQUENCE) : 0;
    if (total <= 0 || (size_t)total > BIGN_EC_PARAMS_DER_MAX) {
        ASN1_INTEGER_free(one);
        return 0;
    }
    memmove(der + total - body_len - integer_len, body, body_len);
    ASN1_put_object(&p, 1, (int)body_len + integer_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    p += body_len;
    integer_len = i2d_ASN1_INTEGER(one, &p);
    ASN1_INTEGER_free(one);
    return integer_len > 0 ? (size_t)total : 0;
}

static int oid_equals(const ASN1_OBJECT *obj, const char *oid)
{
    char buf[80];
    int n = obj != NULL ? OBJ_obj2txt(buf, sizeof(buf), obj, 1) : 0;

    return n > 0 && n < (int)sizeof(buf) && strcmp(buf, oid) == 0;
}

/* The provider exposes the three standard curves. Match their canonical
 * explicit parameters in both legal forms, with and without cofactor. */
static const bee2_bign_variant_t *variant_from_alg_params(
    int type, const void *value, int *explicit_encoding, int *cofactor_encoding)
{
    const bee2_bign_variant_t *variants[] = {
        bee2_bign_variant_256(), bee2_bign_variant_384(), bee2_bign_variant_512()
    };
    size_t i;

    *explicit_encoding = 0;
    *cofactor_encoding = 0;
    if (value == NULL)
        return NULL;
    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        const bee2_bign_variant_t *variant = variants[i];

        if (type == V_ASN1_OBJECT && oid_equals(value, variant->curve_oid))
            return variant;
        if (type == V_ASN1_SEQUENCE) {
            const unsigned char *data = ASN1_STRING_get0_data(value);
            size_t length = asn_length(value);
            unsigned char der[BIGN_EC_PARAMS_DER_MAX];
            int cofactor;

            if (data == NULL || length > sizeof(der))
                return NULL;
            for (cofactor = 0; cofactor <= 1; ++cofactor) {
                size_t n = encode_curve(variant, cofactor, der);

                if (n != 0 && n == length && memcmp(data, der, length) == 0) {
                    *explicit_encoding = 1;
                    *cofactor_encoding = cofactor;
                    return variant;
                }
            }
        }
    }
    return NULL;
}

static ASN1_STRING *encode_explicit_domain_params(const bee2_bign_key_t *key)
{
    unsigned char der[BIGN_EC_PARAMS_DER_MAX];
    size_t length = encode_curve(key->variant, key->encode_cofactor, der);
    ASN1_STRING *sequence = length != 0 ? ASN1_STRING_type_new(V_ASN1_SEQUENCE) : NULL;

    if (sequence != NULL && !bign_asn1_string_set(sequence, der, (int)length)) {
        ASN1_STRING_free(sequence);
        sequence = NULL;
    }
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

PKCS8_PRIV_KEY_INFO *bee2_bign_asn1_pkcs8(const bee2_bign_key_t *key)
{
    if (key == NULL || key->variant == NULL || !key->has_priv)
        return NULL;
    return bign_make_pkcs8(key->priv, key->variant, key->encode_explicit, key->encode_cofactor);
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

X509_PUBKEY *bee2_bign_asn1_spki(const bee2_bign_key_t *key)
{
    X509_PUBKEY *spki;
    ASN1_OBJECT *algorithm;
    void *parameters = NULL;
    unsigned char *pub;
    size_t length;
    int type = V_ASN1_UNDEF;

    if (key == NULL || key->variant == NULL || (!key->has_pub && !key->has_priv))
        return NULL;
    length = bee2_bign_pub_len(key->variant);
    pub = OPENSSL_malloc(length);
    spki = X509_PUBKEY_new();
    algorithm = OBJ_txt2obj(BEE2_OID_BIGN_PUBKEY, 1);
    if (pub == NULL || spki == NULL || algorithm == NULL ||
        !bign_encode_algorithm_params(key, &type, &parameters))
        goto end;
    if (key->has_pub)
        memcpy(pub, key->pub, length);
    else if (!bee2_bign_derive_pubkey(key->variant, pub, key->priv))
        goto end;
    if (X509_PUBKEY_set0_param(spki, algorithm, type, parameters, pub, (int)length))
        return spki;
end:
    X509_PUBKEY_free(spki);
    ASN1_OBJECT_free(algorithm);
    bign_free_algorithm_params(type, parameters);
    OPENSSL_free(pub);
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


static int set_alg(X509_ALGOR *alg, const char *oid, int type, void *value)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);

    if (obj == NULL || !X509_ALGOR_set0(alg, obj, type, value)) {
        ASN1_OBJECT_free(obj);
        return 0;
    }
    return 1;
}

int bee2_bign_asn1_build_algid(const char *oid, const char *hash_oid,
                               unsigned char *buf, size_t buf_len, size_t *out_len)
{
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *parameter = NULL;
    int length, ok;

    if (oid == NULL || buf == NULL || out_len == NULL)
        return 0;
    alg = X509_ALGOR_new();
    if (alg == NULL || (hash_oid != NULL && (parameter = OBJ_txt2obj(hash_oid, 1)) == NULL) ||
        !set_alg(alg, oid, parameter != NULL ? V_ASN1_OBJECT : V_ASN1_NULL, parameter)) {
        ASN1_OBJECT_free(parameter);
        X509_ALGOR_free(alg);
        return 0;
    }
    length = i2d_X509_ALGOR(alg, NULL);
    ok = length > 0 && (size_t)length <= buf_len && i2d_X509_ALGOR(alg, &buf) == length;
    if (ok)
        *out_len = (size_t)length;
    X509_ALGOR_free(alg);
    return ok;
}

#define BEE2_OID_PBES2 "1.2.840.113549.1.5.13"
#define BEE2_OID_PBKDF2 "1.2.840.113549.1.5.12"

static int pack_algorithm(X509_ALGOR *alg, const char *oid,
                          const void *value, const ASN1_ITEM *item)
{
    ASN1_STRING *packed = ASN1_item_pack((void *)value, item, NULL);

    if (packed == NULL || !set_alg(alg, oid, V_ASN1_SEQUENCE, packed)) {
        ASN1_STRING_free(packed);
        return 0;
    }
    return 1;
}

X509_SIG *bee2_stb_pbes2_protect(const unsigned char *scalar, size_t scalar_len,
                               const unsigned char *password, size_t password_len,
                               unsigned int iterations, size_t salt_len, OSSL_LIB_CTX *libctx)
{
    PBKDF2PARAM *kdf = NULL;
    PBE2PARAM *pbe = NULL;
    X509_SIG *encrypted = NULL;
    X509_ALGOR *alg;
    ASN1_OCTET_STRING *ciphertext;
    unsigned char *salt = NULL;
    unsigned char key[32], wrapped[80];
    int length, ok = 0;

    if (scalar == NULL || (password == NULL && password_len != 0) ||
        (scalar_len != 32 && scalar_len != 48 && scalar_len != 64) ||
        iterations == 0 || iterations > INT_MAX || salt_len >= BIGN_MAX_KEY_INPUT)
        return NULL;
    if (salt_len != 0) {
        salt = OPENSSL_malloc(salt_len);
        if (salt == NULL || RAND_bytes_ex(libctx, salt, salt_len, 0) != 1)
            goto end;
    }
    kdf = PBKDF2PARAM_new();
    pbe = PBE2PARAM_new();
    encrypted = X509_SIG_new();
    if (kdf == NULL || pbe == NULL || encrypted == NULL)
        goto end;
    kdf->keylength = ASN1_INTEGER_new();
    kdf->prf = X509_ALGOR_new();
    if (kdf->keylength == NULL || kdf->prf == NULL ||
        !ASN1_TYPE_set_octetstring(kdf->salt, salt, (int)salt_len) ||
        !ASN1_INTEGER_set(kdf->iter, iterations) ||
        !ASN1_INTEGER_set(kdf->keylength, sizeof(key)) ||
        !set_alg(kdf->prf, BEE2_OID_HMAC_HBELT, V_ASN1_NULL, NULL) ||
        !pack_algorithm(pbe->keyfunc, BEE2_OID_PBKDF2, kdf, ASN1_ITEM_rptr(PBKDF2PARAM)) ||
        !set_alg(pbe->encryption, BEE2_OID_BELT_KWP, V_ASN1_NULL, NULL))
        goto end;
    X509_SIG_getm(encrypted, &alg, &ciphertext);
    memset(wrapped, 0, sizeof(wrapped));
    if (!pack_algorithm(alg, BEE2_OID_PBES2, pbe, ASN1_ITEM_rptr(PBE2PARAM)) ||
        !ASN1_OCTET_STRING_set(ciphertext, wrapped, (int)(scalar_len + 16)))
        goto end;
    length = i2d_X509_SIG(encrypted, NULL);
    if (length <= 0 || (size_t)length > BIGN_MAX_KEY_INPUT ||
        beltPBKDF2(key, password, password_len, iterations, salt, salt_len) != ERR_OK ||
        beltKWPWrap(wrapped, scalar, scalar_len, NULL, key, sizeof(key)) != ERR_OK ||
        !ASN1_OCTET_STRING_set(ciphertext, wrapped, (int)(scalar_len + 16)))
        goto end;
    ok = 1;
end:
    OPENSSL_clear_free(salt, salt_len);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(wrapped, sizeof(wrapped));
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    if (!ok) {
        X509_SIG_free(encrypted);
        encrypted = NULL;
    }
    return encrypted;
}

static const ASN1_STRING *algorithm_sequence(const X509_ALGOR *alg, const char *oid)
{
    const ASN1_OBJECT *object;
    const void *value;
    int type;

    X509_ALGOR_get0(&object, &type, &value, alg);
    return type == V_ASN1_SEQUENCE && oid_equals(object, oid) ? value : NULL;
}

static int algorithm_null(const X509_ALGOR *alg, const char *oid)
{
    const ASN1_OBJECT *object;
    int type;

    X509_ALGOR_get0(&object, &type, NULL, alg);
    return type == V_ASN1_NULL && oid_equals(object, oid);
}

static ASN1_VALUE *unpack_sequence_exact(const ASN1_STRING *encoded, const ASN1_ITEM *item)
{
    const unsigned char *start, *p;
    size_t length;
    ASN1_VALUE *value;

    if (encoded == NULL)
        return NULL;
    start = p = ASN1_STRING_get0_data(encoded);
    length = asn_length(encoded);
    if (!bign_der_sequence_body(start, length, &p))
        return NULL;
    p = start;
    value = ASN1_item_d2i(NULL, &p, (long)length, item);
    if (p != start + length) {
        ASN1_item_free(value, item);
        return NULL;
    }
    return value;
}

/* Identify the scheme before rejecting malformed parameters or prompting. */
static PBE2PARAM *parse_stb_pbes2(const X509_SIG *encrypted, int *recognised)
{
    const X509_ALGOR *alg;
    const ASN1_OBJECT *scheme;
    const ASN1_STRING *encoded;
    const unsigned char *start, *p;
    size_t length;
    PBE2PARAM *pbe;

    *recognised = 0;
    if (encrypted == NULL)
        return NULL;
    X509_SIG_get0(encrypted, &alg, NULL);
    encoded = algorithm_sequence(alg, BEE2_OID_PBES2);
    if (encoded == NULL)
        return NULL;
    start = p = ASN1_STRING_get0_data(encoded);
    length = asn_length(encoded);
    if (start == NULL || length == 0 || length > BIGN_MAX_KEY_INPUT)
        return NULL;
    pbe = (PBE2PARAM *)ASN1_item_d2i(NULL, &p, (long)length, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe != NULL) {
        X509_ALGOR_get0(&scheme, NULL, NULL, pbe->encryption);
        *recognised = oid_equals(scheme, BEE2_OID_BELT_KWP);
        if (!*recognised || p != start + length || !bign_der_sequence_body(start, length, &p)) {
            PBE2PARAM_free(pbe);
            pbe = NULL;
        }
    }
    return pbe;
}

int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted)
{
    int recognised;
    PBE2PARAM *pbe = parse_stb_pbes2(encrypted, &recognised);

    PBE2PARAM_free(pbe);
    return recognised;
}

static PKCS8_PRIV_KEY_INFO *unprotect(const X509_SIG *encrypted, const PBE2PARAM *pbe,
                                     const unsigned char *password, size_t password_len,
                                     unsigned int max_iterations)
{
    const ASN1_OCTET_STRING *ciphertext, *salt;
    PBKDF2PARAM *kdf;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const bee2_bign_variant_t *variant;
    unsigned char key[32], scalar[64];
    size_t wrapped_len, salt_len;
    uint64_t iterations;

    if (pbe == NULL || (password == NULL && password_len != 0) ||
        !algorithm_null(pbe->encryption, BEE2_OID_BELT_KWP))
        return NULL;
    X509_SIG_get0(encrypted, NULL, &ciphertext);
    wrapped_len = asn_length(ciphertext);
    switch (wrapped_len) {
    case 48: variant = bee2_bign_variant_256(); break;
    case 64: variant = bee2_bign_variant_384(); break;
    case 80: variant = bee2_bign_variant_512(); break;
    default: return NULL;
    }
    kdf = (PBKDF2PARAM *)unpack_sequence_exact(algorithm_sequence(pbe->keyfunc, BEE2_OID_PBKDF2),
                                               ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL)
        return NULL;
    if (!ASN1_INTEGER_get_uint64(&iterations, kdf->iter) ||
        iterations == 0 || iterations > max_iterations ||
        kdf->prf == NULL || !algorithm_null(kdf->prf, BEE2_OID_HMAC_HBELT) ||
        (kdf->keylength != NULL && ASN1_INTEGER_get(kdf->keylength) != sizeof(key)) ||
        ASN1_TYPE_get(kdf->salt) != V_ASN1_OCTET_STRING)
        goto end;
    salt = kdf->salt->value.octet_string;
    salt_len = asn_length(salt);
    if (salt_len <= BIGN_MAX_KEY_INPUT &&
        beltPBKDF2(key, password, password_len, (size_t)iterations,
                   ASN1_STRING_get0_data(salt), salt_len) == ERR_OK &&
        beltKWPUnwrap(scalar, ASN1_STRING_get0_data(ciphertext), wrapped_len,
                      NULL, key, sizeof(key)) == ERR_OK)
        p8 = bign_make_pkcs8(scalar, variant, 0, 0);
end:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(scalar, sizeof(scalar));
    PBKDF2PARAM_free(kdf);
    return p8;
}

PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len, unsigned int max_iterations,
                                            int *recognised)
{
    PBE2PARAM *pbe;
    PKCS8_PRIV_KEY_INFO *p8;

    if (recognised == NULL)
        return NULL;
    pbe = parse_stb_pbes2(encrypted, recognised);
    p8 = unprotect(encrypted, pbe, password, password_len, max_iterations);
    PBE2PARAM_free(pbe);
    return p8;
}


static PKCS8_PRIV_KEY_INFO *decode_encrypted(const bee2_bign_decoder_ctx_t *ctx,
                            const unsigned char *der, size_t length,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
                            int *recognised)
{
    const unsigned char *p = der;
    X509_SIG *encrypted;
    PBE2PARAM *pbe;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    char password[PEM_BUFSIZE];
    size_t password_len = 0;

    encrypted = d2i_X509_SIG(NULL, &p, (long)length);
    if (encrypted == NULL)
        return NULL;
    pbe = parse_stb_pbes2(encrypted, recognised);
    if (pbe != NULL && p == der + length && pw_cb != NULL &&
        pw_cb(password, sizeof(password), &password_len, NULL, pw_cbarg) &&
        password_len <= sizeof(password)) {
        p8 = unprotect(encrypted, pbe, (const unsigned char *)password,
                       password_len, ctx->max_pbkdf2_iterations);
    }
    OPENSSL_cleanse(password, sizeof(password));
    PBE2PARAM_free(pbe);
    X509_SIG_free(encrypted);
    return p8;
}

/* The generic OpenSSL decoder unwraps PBES2 before trying key decoders.
 * Intercept the Annex E scheme at that entry point, then resume the chain. */
typedef struct {
    OSSL_PASSPHRASE_CALLBACK *callback;
    void *argument;
} pem_password;

static int pem_pass(char *out, int size, int writing, void *argument)
{
    pem_password *password = argument;
    size_t n = 0;

    (void)writing;
    return size >= 0 && password->callback != NULL &&
        password->callback(out, (size_t)size, &n, NULL, password->argument) &&
        n <= (size_t)size ? (int)n : -1;
}

static int emit_der(OSSL_CALLBACK *cb, void *arg, int type, const char *structure,
                    const char *name, unsigned char *der, size_t length)
{
    OSSL_PARAM params[5], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &type);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der, length);
    if (structure != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)structure, 0);
    if (name != NULL)
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, (char *)name, 0);
    *p = OSSL_PARAM_construct_end();
    return cb(params, arg);
}

static const char *der_structure(const unsigned char *der, size_t length)
{
    const unsigned char *p;
    X509_ALGOR *alg;
    const char *structure = NULL;

    if (!bign_der_sequence_body(der, length, &p) || p == der + length)
        return NULL;
    if (*p == V_ASN1_INTEGER) {
        ASN1_INTEGER *version = d2i_ASN1_INTEGER(NULL, &p, (long)(der + length - p));

        if (version != NULL && p < der + length && *p == (V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE))
            structure = "PrivateKeyInfo";
        ASN1_INTEGER_free(version);
        return structure;
    }
    alg = d2i_X509_ALGOR(NULL, &p, (long)(der + length - p));
    if (alg != NULL && p < der + length) {
        if (*p == V_ASN1_BIT_STRING)
            structure = "SubjectPublicKeyInfo";
        else if (*p == V_ASN1_OCTET_STRING)
            structure = "EncryptedPrivateKeyInfo";
    }
    X509_ALGOR_free(alg);
    return structure;
}

#define BIGN_MAX_PEM_TEXT (2u * BIGN_MAX_KEY_INPUT)

typedef struct {
    size_t count;
    int overflow;
} pem_limit;

static long limit_pem(BIO *bio, int op, const char *data, size_t len, int argi,
                      long argl, int ret, size_t *processed)
{
    pem_limit *limit = (pem_limit *)BIO_get_callback_arg(bio);

    (void)data;
    (void)len;
    (void)argi;
    (void)argl;
    if (op == BIO_CB_GETS && limit->count >= BIGN_MAX_PEM_TEXT)
        limit->overflow = 1;
    if (op == (BIO_CB_GETS | BIO_CB_RETURN) && ret > 0 && processed != NULL) {
        if (*processed > BIGN_MAX_PEM_TEXT - limit->count)
            limit->overflow = 1;
        else
            limit->count += *processed;
    }
    return limit->overflow ? 0 : ret;
}

static int bridge_decode(const bee2_bign_decoder_ctx_t *ctx, BIO *bio, int selection,
                         OSSL_CALLBACK *cb, void *arg,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    PKCS8_PRIV_KEY_INFO *plain = NULL;
    unsigned char *der = NULL, *clear_der = NULL;
    char *label = NULL, *header = NULL;
    const char *structure = NULL, *name = NULL;
    size_t length = 0, allocated = 0;
    int type = OSSL_OBJECT_PKEY, recognised = 0, n = 0, ok = 1;
    int marked = ERR_set_mark();

    if (ctx->kind == BIGN_DECODE_PEM) {
        long len = 0;
        pem_limit limit = {0};
        int read;

        BIO_set_callback_arg(bio, (char *)&limit);
        BIO_set_callback_ex(bio, limit_pem);
        read = PEM_read_bio(bio, &label, &header, &der, &len);
        BIO_set_callback_ex(bio, NULL);
        BIO_set_callback_arg(bio, NULL);
        if (len > 0)
            allocated = (size_t)len;
        if (limit.overflow || allocated > BIGN_MAX_KEY_INPUT) {
            ok = 0;
            goto end;
        }
        if (read <= 0 || len <= 0)
            goto end;
        if (strcmp(label, PEM_STRING_PKCS8) == 0)
            structure = "EncryptedPrivateKeyInfo";
        else if (strcmp(label, PEM_STRING_PKCS8INF) == 0)
            structure = "PrivateKeyInfo";
        else if (strcmp(label, PEM_STRING_PUBLIC) == 0)
            structure = "SubjectPublicKeyInfo";
        else if (strcmp(label, PEM_STRING_X509) == 0 ||
                 strcmp(label, PEM_STRING_X509_TRUSTED) == 0 ||
                 strcmp(label, PEM_STRING_X509_OLD) == 0)
            type = OSSL_OBJECT_CERT;
        else if (strcmp(label, PEM_STRING_X509_CRL) == 0)
            type = OSSL_OBJECT_CRL;
        else {
            char *suffix = strrchr(label, ' ');

            if (suffix != NULL && strcmp(suffix, " KEY") == 0) {
                *suffix = '\0';
                suffix = strrchr(label, ' ');
                if (suffix != NULL)
                    *suffix = '\0';
                name = label;
            } else if (suffix != NULL && strcmp(suffix, " PARAMETERS") == 0) {
                *suffix = '\0';
                name = label;
            }
            if (name == NULL)
                goto end;
            structure = "type-specific";
        }
        if (*header != '\0') {
            EVP_CIPHER_INFO cipher;
            pem_password password = {pw_cb, pw_cbarg};

            if (!PEM_get_EVP_CIPHER_INFO(header, &cipher) ||
                !PEM_do_header(&cipher, der, &len, pem_pass, &password) || len <= 0) {
                ok = 0;
                goto end;
            }
        }
        length = (size_t)len;
    } else {
        if (!read_der_object(bio, &der, &length) || length == 0)
            goto end;
        allocated = length;
        structure = der_structure(der, length);
        if (structure == NULL)
            type = OSSL_OBJECT_UNKNOWN;
    }
    if (structure != NULL && strcmp(structure, "EncryptedPrivateKeyInfo") == 0 &&
        (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
        plain = decode_encrypted(ctx, der, length, pw_cb, pw_cbarg, &recognised);
        if (recognised) {
            n = plain != NULL ? i2d_PKCS8_PRIV_KEY_INFO(plain, &clear_der) : 0;
            ok = n > 0;
            structure = "PrivateKeyInfo";
        }
    }
end:
    if (marked)
        ERR_pop_to_mark();
    else
        ERR_clear_error();
    if (ok && n > 0)
        ok = emit_der(cb, arg, type, structure, NULL, clear_der, (size_t)n);
    else if (ok && length != 0)
        ok = emit_der(cb, arg, type, structure, name, der, length);
    PKCS8_PRIV_KEY_INFO_free(plain);
    OPENSSL_clear_free(clear_der, n > 0 ? (size_t)n : 0);
    OPENSSL_clear_free(der, allocated);
    OPENSSL_free(header);
    OPENSSL_free(label);
    return ok;
}

int bee2_bign_asn1_decoder_decode(void *vctx, OSSL_CORE_BIO *in, int selection,
                                  OSSL_CALLBACK *data_cb, void *data_cbarg,
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    bee2_bign_decoder_ctx_t *ctx = vctx;
    unsigned char *der = NULL;
    size_t length = 0;
    BIO *bio;
    bee2_bign_key_t *key = NULL;
    int marked, decoded = 0, ok = 1;

    if (ctx == NULL || in == NULL || data_cb == NULL)
        return 0;
    bio = BIO_new_from_core_bio(ctx->libctx, in);
    if (bio == NULL)
        return 0;
    if (ctx->kind == BIGN_DECODE_PEM || ctx->kind == BIGN_DECODE_DER) {
        ok = bridge_decode(ctx, bio, selection, data_cb, data_cbarg, pw_cb, pw_cbarg);
        BIO_free(bio);
        return ok;
    }
    marked = ERR_set_mark();
    if (!read_der_object(bio, &der, &length) || length == 0)
        goto end;
    key = bee2_bign_key_new(NULL);
    if (key == NULL) {
        ok = 0;
        goto end;
    }
    decoded = ctx->kind == BIGN_DECODE_PRIVATE
                  ? bee2_bign_asn1_decode_pkcs8_der(der, length, NULL, key)
                  : bee2_bign_asn1_decode_spki_der(der, length, NULL, key);
end:
    if (marked)
        ERR_pop_to_mark();
    else
        ERR_clear_error();
    BIO_free(bio);
    OPENSSL_clear_free(der, length);

    if (decoded) {
        int object_type = OSSL_OBJECT_PKEY;
        char data_type[] = "bign";
        OSSL_PARAM params[] = {
            OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &object_type),
            OSSL_PARAM_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, data_type, sizeof(data_type)),
            OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key)),
            OSSL_PARAM_END
        };

        if (selection != 0 && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
            OPENSSL_cleanse(key->priv, sizeof(key->priv));
            key->has_priv = 0;
        }
        ok = data_cb(params, data_cbarg);
    }
    bee2_bign_key_free(key);
    return ok;
}
