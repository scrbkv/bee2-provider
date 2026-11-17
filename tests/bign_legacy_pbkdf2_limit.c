/* PBES2 iteration limits must be checked before starting password derivation. */
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"

#include <limits.h>
#include <string.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#define OID_PBES2 "1.2.840.113549.1.5.13"
#define OID_PBKDF2 "1.2.840.113549.1.5.12"
#define OID_SCRYPT "1.3.6.1.4.1.11591.4.11"

static int set_algorithm(X509_ALGOR *alg, const char *oid, int type, void *value)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);

    if (!obj)
        return 0;
    if (!X509_ALGOR_set0(alg, obj, type, value)) {
        ASN1_OBJECT_free(obj);
        return 0;
    }
    return 1;
}

static X509_SIG *make_pbes2(long iterations, const char *kdf_oid,
                             const char *cipher_oid)
{
    static const unsigned char salt_bytes[8] = {0};
    static const unsigned char aes_iv[16] = {0};
    static const unsigned char dummy_data[32] = {0};
    X509_SIG *info = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    ASN1_STRING *packed_kdf = NULL, *packed_pbe = NULL;
    ASN1_OCTET_STRING *salt = NULL, *iv = NULL;
    X509_ALGOR *algorithm = NULL;
    ASN1_OCTET_STRING *ciphertext = NULL;
    int ok = 0;

    info = X509_SIG_new();
    pbe = PBE2PARAM_new();
    kdf = PBKDF2PARAM_new();
    salt = ASN1_OCTET_STRING_new();
    iv = ASN1_OCTET_STRING_new();
    if (!info || !pbe || !kdf || !kdf->salt || !kdf->iter ||
        !pbe->keyfunc || !pbe->encryption || !salt || !iv ||
        !ASN1_INTEGER_set(kdf->iter, iterations) ||
        !ASN1_OCTET_STRING_set(salt, salt_bytes, sizeof(salt_bytes)) ||
        !ASN1_OCTET_STRING_set(iv, aes_iv, sizeof(aes_iv)))
        goto end;
    ASN1_TYPE_set(kdf->salt, V_ASN1_OCTET_STRING, salt);
    salt = NULL;
    packed_kdf = ASN1_item_pack(kdf, ASN1_ITEM_rptr(PBKDF2PARAM), NULL);
    if (!packed_kdf ||
        !set_algorithm(pbe->keyfunc, kdf_oid, V_ASN1_SEQUENCE, packed_kdf))
        goto end;
    packed_kdf = NULL;
    if (!set_algorithm(pbe->encryption, cipher_oid,
                       V_ASN1_OCTET_STRING, iv))
        goto end;
    iv = NULL;
    packed_pbe = ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBE2PARAM), NULL);
    if (!packed_pbe)
        goto end;
    X509_SIG_getm(info, &algorithm, &ciphertext);
    if (!algorithm || !ciphertext ||
        !set_algorithm(algorithm, OID_PBES2, V_ASN1_SEQUENCE, packed_pbe))
        goto end;
    packed_pbe = NULL;
    if (!ASN1_OCTET_STRING_set(ciphertext, dummy_data, sizeof(dummy_data)))
        goto end;
    ok = 1;
end:
    ASN1_OCTET_STRING_free(salt);
    ASN1_OCTET_STRING_free(iv);
    ASN1_STRING_free(packed_kdf);
    ASN1_STRING_free(packed_pbe);
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    if (!ok) {
        X509_SIG_free(info);
        info = NULL;
    }
    return info;
}


/* Classification of STB PBES2 depends on the KWP cipher OID.  A recognised
 * envelope with unexpected cipher parameters must not be decrypted or
 * silently treated as an ordinary AES PBES2 envelope. */
static int check_stb_pbes2_classification(void)
{
    static const char *const ciphers[] = {
        BEE2_OID_BELT_128_KWP, BEE2_OID_BELT_192_KWP, BEE2_OID_BELT_KWP
    };
    static const unsigned char password[] = "password";
    X509_SIG *info = NULL;
    PKCS8_PRIV_KEY_INFO *plain = NULL;
    size_t i;
    int recognised, ok = 0;

    if (bee2_stb_pbes2_is_stb(NULL) ||
        bee2_stb_pbes2_legacy_pbkdf2_allowed(NULL, 10000))
        return 0;
    for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); ++i) {
        info = make_pbes2(10000, OID_PBKDF2, ciphers[i]);
        if (info == NULL || !bee2_stb_pbes2_is_stb(info) ||
            bee2_stb_pbes2_legacy_pbkdf2_allowed(info, 0))
            goto end;

        /* The fixture deliberately carries an AES-style IV rather than
         * KWP's absent parameters.  Recognition precedes validation. */
        recognised = 0;
        plain = bee2_stb_pbes2_decrypt(info, password,
                                       sizeof(password) - 1, 10000,
                                       &recognised);
        if (plain != NULL || !recognised)
            goto end;
        X509_SIG_free(info);
        info = NULL;
    }
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "STB PBES2 KWP classification contract failed\n");
    PKCS8_PRIV_KEY_INFO_free(plain);
    X509_SIG_free(info);
    return ok;
}



/* Exercise PBKDF2 salt encodings omitted by the normal OpenSSL EVP tests.
 * The test starts from a genuine authenticated STB-encrypted PKCS#8 key. */
static int mutate_stb_salt(X509_SIG *info, int wrong_type)
{
    static const unsigned char short_salt[7] = {0};
    X509_ALGOR *outer = NULL;
    ASN1_OCTET_STRING *ciphertext = NULL;
    const ASN1_OBJECT *obj = NULL;
    const void *value = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    ASN1_STRING *packed = NULL;
    int type, ok = 0;

    X509_SIG_getm(info, &outer, &ciphertext);
    if (outer == NULL || ciphertext == NULL)
        return 0;
    X509_ALGOR_get0(&obj, &type, &value, outer);
    if (type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value,
                           ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->keyfunc);
    if (type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack((const ASN1_STRING *)value,
                           ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL)
        goto end;

    if (wrong_type) {
        ASN1_TYPE_set(kdf->salt, V_ASN1_NULL, NULL);
    } else if (!ASN1_OCTET_STRING_set(kdf->salt->value.octet_string,
                                       short_salt, sizeof(short_salt))) {
        goto end;
    }
    packed = ASN1_item_pack(kdf, ASN1_ITEM_rptr(PBKDF2PARAM), NULL);
    if (packed == NULL ||
        !set_algorithm(pbe->keyfunc, OID_PBKDF2, V_ASN1_SEQUENCE, packed))
        goto end;
    packed = NULL;
    packed = ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBE2PARAM), NULL);
    if (packed == NULL ||
        !set_algorithm(outer, OID_PBES2, V_ASN1_SEQUENCE, packed))
        goto end;
    packed = NULL;
    ok = 1;

end:
    ASN1_STRING_free(packed);
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    return ok;
}

static int check_stb_decrypt_parameters(void)
{
    static const unsigned char password[] = "stb-pbes2-parameter-test";
    static const unsigned char private_data[16] = {
        1, 3, 3, 7, 9, 2, 4, 6, 0, 5, 1, 8, 7, 3, 2, 1
    };
    PKCS8_PRIV_KEY_INFO *pkcs8 = NULL, *decoded = NULL;
    ASN1_OBJECT *algorithm = NULL;
    unsigned char *private_copy = NULL, *plain = NULL, *encrypted = NULL;
    unsigned char *roundtrip = NULL, *trailing = NULL, *extra_der = NULL;
    X509_SIG *info = NULL;
    size_t encrypted_len = 0, extra_len = 0;
    int plain_len = 0, roundtrip_len, recognised;
    size_t key_len;
    int wrong_type, ok = 0;

    pkcs8 = PKCS8_PRIV_KEY_INFO_new();
    algorithm = OBJ_txt2obj("1.2.3.4", 1);
    private_copy = OPENSSL_memdup(private_data, sizeof(private_data));
    if (pkcs8 == NULL || algorithm == NULL || private_copy == NULL ||
        !PKCS8_pkey_set0(pkcs8, algorithm, 0, V_ASN1_NULL, NULL,
                        private_copy, (int)sizeof(private_data)))
        goto end;
    algorithm = NULL;
    private_copy = NULL;
    plain_len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &plain);
    if (plain_len < 16 || plain == NULL)
        goto end;

    for (key_len = 16; key_len <= 32; key_len += 8) {
        const unsigned char *p;

        OPENSSL_clear_free(encrypted, encrypted_len);
        encrypted = bee2_stb_pbes2_encrypt(
            plain, (size_t)plain_len, password, sizeof(password) - 1,
            key_len, BEE2_STB_PBKDF2_MIN_ITER, BEE2_STB_PBKDF2_MIN_SALT,
            NULL, &encrypted_len);
        if (encrypted == NULL)
            goto end;
        p = encrypted;
        X509_SIG_free(info);
        info = d2i_X509_SIG(NULL, &p, (long)encrypted_len);
        if (info == NULL || p != encrypted + encrypted_len ||
            !bee2_stb_pbes2_is_stb(info))
            goto end;

        PKCS8_PRIV_KEY_INFO_free(decoded);
        recognised = 0;
        decoded = bee2_stb_pbes2_decrypt(info, password,
                                          sizeof(password) - 1, 10000,
                                          &recognised);
        if (decoded == NULL || !recognised)
            goto end;
        OPENSSL_free(roundtrip);
        roundtrip = NULL;
        roundtrip_len = i2d_PKCS8_PRIV_KEY_INFO(decoded, &roundtrip);
        if (roundtrip_len != plain_len || roundtrip == NULL ||
            memcmp(roundtrip, plain, (size_t)plain_len) != 0)
            goto end;
    }

    /* The recognised output parameter is required; a missing one must not
     * trigger a decryption attempt. */
    if (bee2_stb_pbes2_decrypt(info, password, sizeof(password) - 1,
                               10000, NULL) != NULL)
        goto end;

    for (wrong_type = 0; wrong_type < 2; ++wrong_type) {
        const unsigned char *p = encrypted;

        X509_SIG_free(info);
        info = d2i_X509_SIG(NULL, &p, (long)encrypted_len);
        if (info == NULL || !mutate_stb_salt(info, wrong_type))
            goto end;
        PKCS8_PRIV_KEY_INFO_free(decoded);
        decoded = NULL;
        recognised = 0;
        decoded = bee2_stb_pbes2_decrypt(info, password,
                                          sizeof(password) - 1, 10000,
                                          &recognised);
        if (decoded != NULL || !recognised)
            goto end;
    }

    /* A valid authenticated KWP envelope must not accept extra bytes after
     * the PKCS#8 DER object in its recovered plaintext. */
    trailing = OPENSSL_malloc((size_t)plain_len + 1);
    if (trailing == NULL)
        goto end;
    memcpy(trailing, plain, (size_t)plain_len);
    trailing[plain_len] = 0;
    extra_der = bee2_stb_pbes2_encrypt(
        trailing, (size_t)plain_len + 1, password, sizeof(password) - 1,
        32, BEE2_STB_PBKDF2_MIN_ITER, BEE2_STB_PBKDF2_MIN_SALT,
        NULL, &extra_len);
    if (extra_der == NULL)
        goto end;
    {
        const unsigned char *p = extra_der;

        X509_SIG_free(info);
        info = d2i_X509_SIG(NULL, &p, (long)extra_len);
    }
    if (info == NULL)
        goto end;
    PKCS8_PRIV_KEY_INFO_free(decoded);
    decoded = NULL;
    recognised = 0;
    decoded = bee2_stb_pbes2_decrypt(info, password,
                                      sizeof(password) - 1, 10000,
                                      &recognised);
    if (decoded != NULL || !recognised)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "STB PBES2 decryption parameter contract failed\n");
    X509_SIG_free(info);
    PKCS8_PRIV_KEY_INFO_free(decoded);
    PKCS8_PRIV_KEY_INFO_free(pkcs8);
    ASN1_OBJECT_free(algorithm);
    OPENSSL_clear_free(private_copy, sizeof(private_data));
    OPENSSL_clear_free(trailing, plain_len > 0 ? (size_t)plain_len + 1 : 0);
    OPENSSL_clear_free(extra_der, extra_len);
    OPENSSL_clear_free(encrypted, encrypted_len);
    OPENSSL_clear_free(plain, plain_len > 0 ? (size_t)plain_len : 0);
    OPENSSL_free(roundtrip);
    return ok;
}

int main(void)
{
    static const struct {
        long iterations;
        unsigned int maximum;
        int allowed;
    } cases[] = {
        {0, 10000u, 0},
        {1, 10000u, 1},
        {9999, 10000u, 1},
        {10000, 10000u, 1},
        {10001, 10000u, 0},
        {LONG_MAX, 10000u, 0},
    };
    size_t i;
    X509_SIG *unknown;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        X509_SIG *info = make_pbes2(cases[i].iterations, OID_PBKDF2,
                                    "2.16.840.1.101.3.4.1.42");
        int result;

        if (!info) {
            fprintf(stderr, "PBES2 test fixture construction failed at case %zu\n", i);
            return 1;
        }
        result = bee2_stb_pbes2_legacy_pbkdf2_allowed(info, cases[i].maximum);
        X509_SIG_free(info);
        if (result != cases[i].allowed) {
            fprintf(stderr, "PBES2 iteration limit mismatch at case %zu\n", i);
            return 1;
        }
    }
    unknown = make_pbes2(1, OID_SCRYPT, "2.16.840.1.101.3.4.1.42");
    if (!unknown || bee2_stb_pbes2_legacy_pbkdf2_allowed(unknown, 10000u)) {
        fprintf(stderr, "Unrecognised PBES2 KDF was accepted\n");
        X509_SIG_free(unknown);
        return 1;
    }
    X509_SIG_free(unknown);
    return check_stb_pbes2_classification() &&
           check_stb_decrypt_parameters() ? 0 : 1;
}
