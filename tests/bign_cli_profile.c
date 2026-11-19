/* Inspect the exact Annex E envelope produced by the openssl CLI. */
#include "bee2_oids.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PBES2_OID "1.2.840.113549.1.5.13"
#define PBKDF2_OID "1.2.840.113549.1.5.12"

static int has_oid(const ASN1_OBJECT *obj, const char *oid)
{
    ASN1_OBJECT *expected = OBJ_txt2obj(oid, 1);
    int ok = obj != NULL && expected != NULL &&
             OBJ_cmp(obj, expected) == 0;

    ASN1_OBJECT_free(expected);
    return ok;
}

static size_t asn_length(const ASN1_STRING *str)
{
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    return ASN1_STRING_get_length(str);
#else
    int n = ASN1_STRING_length(str);
    return n < 0 ? SIZE_MAX : (size_t)n;
#endif
}

static int inspect(const char *file, long iterations, size_t salt_len,
                   size_t scalar_len)
{
    BIO *bio = BIO_new_file(file, "rb");
    X509_SIG *sig = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *kdf = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OCTET_STRING *encrypted = NULL;
    const ASN1_OBJECT *obj = NULL;
    const void *value = NULL;
    int type = V_ASN1_UNDEF, ok = 0;

    if (bio == NULL || (sig = PEM_read_bio_PKCS8(bio, NULL, NULL, NULL)) == NULL)
        goto end;
    X509_SIG_get0(sig, &alg, &encrypted);
    if (alg == NULL || encrypted == NULL ||
        asn_length(encrypted) != scalar_len + 16)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, alg);
    if (!has_oid(obj, PBES2_OID) || type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    pbe = ASN1_item_unpack(value, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->encryption);
    if (!has_oid(obj, BEE2_OID_BELT_KWP) || type != V_ASN1_NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, pbe->keyfunc);
    if (!has_oid(obj, PBKDF2_OID) || type != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    kdf = ASN1_item_unpack(value, ASN1_ITEM_rptr(PBKDF2PARAM));
    if (kdf == NULL || kdf->salt == NULL ||
        kdf->salt->type != V_ASN1_OCTET_STRING ||
        kdf->salt->value.octet_string == NULL ||
        asn_length(kdf->salt->value.octet_string) != salt_len ||
        kdf->iter == NULL || ASN1_INTEGER_get(kdf->iter) != iterations ||
        kdf->keylength == NULL || ASN1_INTEGER_get(kdf->keylength) != 32 ||
        kdf->prf == NULL)
        goto end;
    X509_ALGOR_get0(&obj, &type, &value, kdf->prf);
    ok = has_oid(obj, BEE2_OID_HMAC_HBELT) && type == V_ASN1_NULL;

end:
    if (!ok)
        fprintf(stderr, "Incorrect STB Annex E PBES2 envelope in %s\n", file);
    PBKDF2PARAM_free(kdf);
    PBE2PARAM_free(pbe);
    X509_SIG_free(sig);
    BIO_free(bio);
    return ok;
}

int main(int argc, char **argv)
{
    long iterations, salt_len, scalar_len;

    if (argc != 5)
        return 2;
    iterations = strtol(argv[2], NULL, 10);
    salt_len = strtol(argv[3], NULL, 10);
    scalar_len = strtol(argv[4], NULL, 10);
    if (iterations <= 0 || salt_len <= 0 ||
        (scalar_len != 32 && scalar_len != 48 && scalar_len != 64))
        return 2;
    return inspect(argv[1], iterations, (size_t)salt_len,
                   (size_t)scalar_len) ? 0 : 1;
}
