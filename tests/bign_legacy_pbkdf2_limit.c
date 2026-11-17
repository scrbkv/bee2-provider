/* PBES2 iteration limits must be checked before starting password derivation. */
#include "bign_stb_pbes2.h"

#include <limits.h>
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

static X509_SIG *make_pbes2(long iterations, const char *kdf_oid)
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
    if (!set_algorithm(pbe->encryption, "2.16.840.1.101.3.4.1.42",
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
        X509_SIG *info = make_pbes2(cases[i].iterations, OID_PBKDF2);
        int result;

        if (!info) {
            fprintf(stderr, "PBES2 test fixture construction failed at case %zu\n", i);
            return 1;
        }
        result = bee2_pkcs8_standard_pbkdf2_allowed(info, cases[i].maximum);
        X509_SIG_free(info);
        if (result != cases[i].allowed) {
            fprintf(stderr, "PBES2 iteration limit mismatch at case %zu\n", i);
            return 1;
        }
    }
    unknown = make_pbes2(1, OID_SCRYPT);
    if (!unknown || bee2_pkcs8_standard_pbkdf2_allowed(unknown, 10000u)) {
        fprintf(stderr, "Unrecognised PBES2 KDF was accepted\n");
        X509_SIG_free(unknown);
        return 1;
    }
    X509_SIG_free(unknown);
    return 0;
}
