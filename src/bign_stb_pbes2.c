/* STB 34.101.45, Annex E: PBKDF2-HMAC-HBELT and BELT-KWP in PBES2. */
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"

#include <bee2/crypto/belt.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

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

static int oid_is(const ASN1_OBJECT *obj, const char *text)
{
    ASN1_OBJECT *expected = OBJ_txt2obj(text, 1);
    int match = expected != NULL && obj != NULL && OBJ_cmp(obj, expected) == 0;

    ASN1_OBJECT_free(expected);
    return match;
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

    if (oid == NULL || salt_len > INT_MAX || wrapped_len > INT_MAX)
        return NULL;
    kdf = PBKDF2PARAM_new();
    pbe = PBE2PARAM_new();
    info = X509_SIG_new();
    if (kdf == NULL || pbe == NULL || info == NULL || kdf->salt == NULL ||
        kdf->iter == NULL || pbe->keyfunc == NULL || pbe->encryption == NULL)
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
    if (outer == NULL || encrypted == NULL ||
        !set_alg(outer, BEE2_OID_PBES2, V_ASN1_SEQUENCE, encoded))
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
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(value);
#else
    int n = ASN1_STRING_length(value);
    return n >= 0 ? (size_t)n : SIZE_MAX;
#endif
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
    if (!oid_is(obj, BEE2_OID_PBES2) ||
        type != V_ASN1_SEQUENCE || value == NULL)
        return 0;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe != NULL && pbe->encryption != NULL) {
        X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
        for (key_len = 16; key_len <= 32; key_len += 8) {
            if (oid_is(obj, kwp_oid(key_len))) {
                recognised = 1;
                break;
            }
        }
    }
    PBE2PARAM_free(pbe);
    return recognised;
}

PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len, int *recognised)
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
    if (!oid_is(obj, BEE2_OID_PBES2) || type != V_ASN1_SEQUENCE || value == NULL)
        return NULL;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe == NULL || pbe->encryption == NULL || pbe->keyfunc == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
    for (k = 16; k <= 32; k += 8) {
        if (oid_is(obj, kwp_oid(k))) {
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
    if (!oid_is(obj, BEE2_OID_PBKDF2) || type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL || kdf->salt == NULL || kdf->iter == NULL || kdf->prf == NULL ||
        kdf->salt->type != V_ASN1_OCTET_STRING ||
        kdf->salt->value.octet_string == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, kdf->prf);
    if (!oid_is(obj, BEE2_OID_HMAC_HBELT) ||
        (type != V_ASN1_UNDEF && type != V_ASN1_NULL))
        goto end;
    if (kdf->keylength != NULL && ASN1_INTEGER_get(kdf->keylength) != (long)key_len)
        goto end;
    iter = ASN1_INTEGER_get(kdf->iter);
    salt_len = asn_length(kdf->salt->value.octet_string);
    wrapped_len = asn_length(ciphertext);
    if (iter < BEE2_STB_PBKDF2_MIN_ITER || iter > INT_MAX ||
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
