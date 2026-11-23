/* STB PBES2 classification and password protection contracts. */
#include "bign_stb_pbes2.h"
#include "bee2_oids.h"

#include <string.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/provider.h>

#define OID_PBES2 "1.2.840.113549.1.5.13"
#define OID_PBKDF2 "1.2.840.113549.1.5.12"

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

    if (bee2_stb_pbes2_is_stb(NULL))
        return 0;
    for (i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); ++i) {
        info = make_pbes2(10000, OID_PBKDF2, ciphers[i]);
        if (info == NULL || bee2_stb_pbes2_is_stb(info) != (i == 2))
            goto end;

        /* The fixture deliberately carries an AES-style IV rather than
         * KWP's absent parameters.  Recognition precedes validation. */
        recognised = 0;
        plain = bee2_stb_pbes2_decrypt(info, password,
                                       sizeof(password) - 1, 10000, NULL, &recognised);
        if (plain != NULL || recognised != (i == 2))
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



static int append_trailing_byte(ASN1_STRING *encoded)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    size_t len = ASN1_STRING_get_length(encoded);
#else
    int legacy_len = ASN1_STRING_length(encoded);
    size_t len = legacy_len > 0 ? (size_t)legacy_len : 0;
#endif
    unsigned char *copy;
    int ok;

    if (len == 0 || len >= INT_MAX)
        return 0;
    copy = OPENSSL_malloc(len + 1);
    if (copy == NULL)
        return 0;
    memcpy(copy, ASN1_STRING_get0_data(encoded), len);
    copy[len] = 0;
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    ok = ASN1_STRING_set1_data(encoded, copy, len + 1);
#else
    ok = ASN1_STRING_set(encoded, copy, (int)len + 1);
#endif
    OPENSSL_free(copy);
    return ok;
}

/* Exercise invalid STB PBKDF2 parameters and trailing nested DER. */
static int mutate_stb_salt(X509_SIG *info, int mode)
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

    if (mode == 1) {
        ASN1_TYPE_set(kdf->salt, V_ASN1_NULL, NULL);
    } else if (mode == 0 &&
               !ASN1_OCTET_STRING_set(kdf->salt->value.octet_string,
                                      short_salt, sizeof(short_salt))) {
        goto end;
    }
    packed = ASN1_item_pack(kdf, ASN1_ITEM_rptr(PBKDF2PARAM), NULL);
    if (packed == NULL || (mode == 2 && !append_trailing_byte(packed)) ||
        !set_algorithm(pbe->keyfunc, OID_PBKDF2, V_ASN1_SEQUENCE, packed))
        goto end;
    packed = NULL;
    packed = ASN1_item_pack(pbe, ASN1_ITEM_rptr(PBE2PARAM), NULL);
    if (packed == NULL || (mode == 3 && !append_trailing_byte(packed)) ||
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
    static const unsigned char scalar[64] = {1};
    static const char *const curve_oids[] = {
        BEE2_OID_BIGN_CURVE256, BEE2_OID_BIGN_CURVE384,
        BEE2_OID_BIGN_CURVE512
    };
    X509_SIG *info = NULL;
    PKCS8_PRIV_KEY_INFO *decoded = NULL;
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0, i;
    int recognised, wrong_type, ok = 0;

    for (i = 0; i < sizeof(curve_oids) / sizeof(curve_oids[0]); ++i) {
        const unsigned int iterations = i == 0 ? 1u : BEE2_STB_PBKDF2_DEFAULT_ITER;
        const size_t salt_len = i == 0 ? 1u : BEE2_STB_PBKDF2_DEFAULT_SALT;
        const unsigned char *p, *private_bytes = NULL;
        const ASN1_OBJECT *algorithm = NULL;
        const X509_ALGOR *key_alg = NULL;
        const void *parameters = NULL;
        char oid[96];
        int private_len = 0, parameter_type = 0;
        size_t scalar_len = 32u + 16u * i;

        OPENSSL_clear_free(encrypted, encrypted_len);
        encrypted = NULL;
        encrypted_len = 0;
        encrypted = bee2_stb_pbes2_encrypt(
            scalar, scalar_len, password, sizeof(password) - 1,
            iterations, salt_len, NULL, &encrypted_len);
        if (encrypted == NULL)
            goto end;
        p = encrypted;
        X509_SIG_free(info);
        info = d2i_X509_SIG(NULL, &p, (long)encrypted_len);
        if (info == NULL || p != encrypted + encrypted_len ||
            !bee2_stb_pbes2_is_stb(info))
            goto end;

        PKCS8_PRIV_KEY_INFO_free(decoded);
        decoded = NULL;
        recognised = 0;
        decoded = bee2_stb_pbes2_decrypt(info, password,
                                          sizeof(password) - 1, 10000, NULL,
                                          &recognised);
        if (decoded == NULL || !recognised ||
            !PKCS8_pkey_get0(&algorithm, &private_bytes, &private_len,
                             &key_alg, decoded) ||
            private_len != (int)scalar_len ||
            CRYPTO_memcmp(private_bytes, scalar, scalar_len) != 0 ||
            OBJ_obj2txt(oid, sizeof(oid), algorithm, 1) <= 0 ||
            strcmp(oid, BEE2_OID_BIGN_PUBKEY) != 0)
            goto end;
        X509_ALGOR_get0(NULL, &parameter_type, &parameters, key_alg);
        if (parameter_type != V_ASN1_OBJECT || parameters == NULL ||
            OBJ_obj2txt(oid, sizeof(oid), parameters, 1) <= 0 ||
            strcmp(oid, curve_oids[i]) != 0)
            goto end;
    }

    if (bee2_stb_pbes2_decrypt(info, password, sizeof(password) - 1,
                                10000, NULL, NULL) != NULL)
        goto end;

    for (wrong_type = 0; wrong_type < 4; ++wrong_type) {
        const unsigned char *p = encrypted;

        X509_SIG_free(info);
        info = d2i_X509_SIG(NULL, &p, (long)encrypted_len);
        if (info == NULL || !mutate_stb_salt(info, wrong_type)) {
            fprintf(stderr, "STB PBES2 mutation failed: case %d\n", wrong_type);
            goto end;
        }
        if (!bee2_stb_pbes2_is_stb(info)) {
            fprintf(stderr, "STB PBES2 classification failed: case %d\n", wrong_type);
            goto end;
        }
        PKCS8_PRIV_KEY_INFO_free(decoded);
        decoded = NULL;
        recognised = 0;
        decoded = bee2_stb_pbes2_decrypt(info, password,
                                          sizeof(password) - 1, 10000, NULL,
                                          &recognised);
        if (decoded != NULL || !recognised) {
            fprintf(stderr,
                    "STB PBES2 nested DER validation failed: case %d, recognised %d\n",
                    wrong_type, recognised);
            goto end;
        }
    }
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "STB PBES2 decryption parameter contract failed\n");
    X509_SIG_free(info);
    PKCS8_PRIV_KEY_INFO_free(decoded);
    OPENSSL_clear_free(encrypted, encrypted_len);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *bee2 = NULL, *def = NULL;
    int ok;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    ok = def != NULL && bee2 != NULL &&
         check_stb_pbes2_classification() && check_stb_decrypt_parameters();
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
