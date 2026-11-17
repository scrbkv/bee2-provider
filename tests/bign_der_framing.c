/* Test the exact DER framing helper used by the BIGN key decoder.
 * The openssl pkey CLI intentionally accepts one DER object followed by data. */
#include "../src/bign_der_frame.h"
#include "../src/bign_asn1.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(const char *label, const unsigned char *der, size_t size,
                 int should_accept)
{
    const unsigned char *body = NULL;
    int accepted = bign_der_sequence_body(der, size, &body);

    if (accepted != should_accept ||
        (accepted && (body == NULL || body < der || body > der + size))) {
        fprintf(stderr, "Unexpected DER framing result: %s\n", label);
        return 0;
    }
    return 1;
}



/* Deterministic mutation corpus over real PKCS#8/SPKI encodings.
 * Every truncation and appended byte must be rejected. A single-bit or
 * byte alteration may still encode a valid, *different* key, in which case
 * validate the returned key rather than incorrectly demanding rejection.
 */
static int check_der_mutations(const unsigned char *der, size_t length,
                               const bee2_bign_variant_t *expected,
                               int is_public)
{
    static const unsigned char changes[] = {1, 0x80, 0xff};
    unsigned char *altered = NULL;
    size_t i, j, rejects = 0;
    int ok = 0;

    altered = OPENSSL_malloc(length + 2);
    if (!altered)
        return 0;
    for (i = 0; i < length; ++i) {
        bee2_bign_key_t key = {0};
        int success = is_public
            ? bee2_bign_asn1_decode_spki_der(der, i, expected, &key)
            : bee2_bign_asn1_decode_pkcs8_der(der, i, expected, &key);
        if (success)
            goto done;
    }
    memcpy(altered, der, length);
    altered[length] = 0;
    {
        bee2_bign_key_t key = {0};
        int accepted = is_public
            ? bee2_bign_asn1_decode_spki_der(altered, length + 1, expected, &key)
            : bee2_bign_asn1_decode_pkcs8_der(altered, length + 1, expected, &key);
        if (accepted)
            goto done;
    }

    for (i = 0; i < length; ++i) {
        for (j = 0; j < sizeof(changes); ++j) {
            bee2_bign_key_t parsed = {0};
            int accepted;
            memcpy(altered, der, length);
            altered[i] ^= changes[j];
            accepted = is_public
                ? bee2_bign_asn1_decode_spki_der(altered, length, expected, &parsed)
                : bee2_bign_asn1_decode_pkcs8_der(altered, length, expected, &parsed);
            if (accepted) {
                if (parsed.variant != expected ||
                    !parsed.has_pub ||
                    parsed.has_priv != !is_public ||
                    !bee2_bign_key_validate_public(&parsed) ||
                    (!is_public && !bee2_bign_key_validate_pair(&parsed))) {
                    OPENSSL_cleanse(&parsed, sizeof(parsed));
                    goto done;
                }
            } else {
                ++rejects;
            }
            OPENSSL_cleanse(&parsed, sizeof(parsed));
        }
    }
    ok = rejects != 0;
done:
    if (!ok)
        fprintf(stderr, "BIGN %s DER mutation corpus failed\n",
                is_public ? "public" : "private");
    OPENSSL_clear_free(altered, length + 2);
    return ok;
}

/* Exercise the ASN.1 public interface directly: OpenSSL's pkey CLI can
 * consume just one object and is not a strict DER framing validator.
 * Keep these assertions in the existing ASN.1 test executable.
 */
static int check_bign_key_der(void)
{
    bee2_bign_key_t key = {0}, parsed = {0}, absent = {0};
    const bee2_bign_variant_t *curve = bee2_bign_variant_256();
    unsigned char *private_der = NULL, *public_der = NULL, *damaged = NULL;
    size_t private_len = 0, public_len = 0;
    unsigned int encoding_case;
    int ok = 0;

    key.variant = curve;
    key.has_priv = 1;
    key.priv[0] = 3;
    for (encoding_case = 0; encoding_case < 3; ++encoding_case) {
        key.encode_explicit = encoding_case != 0;
        key.encode_cofactor = encoding_case == 2;
        private_der = bee2_bign_asn1_encode_pkcs8_der(&key, &private_len);
        public_der = bee2_bign_asn1_encode_spki_der(&key, &public_len);
        if (!private_der || !public_der || private_len < 32 || public_len < 64 ||
            !check_der_mutations(private_der, private_len, curve, 0) ||
            !check_der_mutations(public_der, public_len, curve, 1))
            goto done;

        memset(&parsed, 0, sizeof(parsed));
        if (!bee2_bign_asn1_decode_pkcs8_der(private_der, private_len, curve, &parsed) ||
            !parsed.has_priv || !parsed.has_pub ||
            parsed.variant != curve ||
            parsed.encode_explicit != key.encode_explicit ||
            parsed.encode_cofactor != key.encode_cofactor ||
            CRYPTO_memcmp(key.priv, parsed.priv, 32) != 0)
            goto done;

        memset(&parsed, 0, sizeof(parsed));
        if (!bee2_bign_asn1_decode_spki_der(public_der, public_len, curve, &parsed) ||
            !parsed.has_pub || parsed.has_priv || parsed.variant != curve ||
            parsed.encode_explicit != key.encode_explicit ||
            parsed.encode_cofactor != key.encode_cofactor ||
            !bee2_bign_key_validate_public(&parsed))
            goto done;

        if (bee2_bign_asn1_decode_pkcs8_der(private_der, private_len,
                                            bee2_bign_variant_384(), &parsed) ||
            bee2_bign_asn1_decode_spki_der(public_der, public_len,
                                           bee2_bign_variant_384(), &parsed) ||
            bee2_bign_asn1_decode_pkcs8_der(private_der, private_len - 1, curve, &parsed) ||
            bee2_bign_asn1_decode_spki_der(public_der, public_len - 1, curve, &parsed) ||
            bee2_bign_asn1_decode_pkcs8_der(private_der, private_len, curve, NULL) ||
            bee2_bign_asn1_decode_spki_der(public_der, public_len, curve, NULL))
            goto done;

        damaged = OPENSSL_memdup(public_der, public_len);
        if (!damaged)
            goto done;
        memset(damaged + public_len - 64, 0, 64);
        if (bee2_bign_asn1_decode_spki_der(damaged, public_len, curve, &parsed))
            goto done;
        OPENSSL_free(damaged);
        damaged = OPENSSL_memdup(private_der, private_len);
        if (!damaged)
            goto done;
        memset(damaged + private_len - 32, 0, 32);
        if (bee2_bign_asn1_decode_pkcs8_der(damaged, private_len, curve, &parsed))
            goto done;

        OPENSSL_free(damaged);
        damaged = NULL;
        OPENSSL_free(private_der);
        private_der = NULL;
        OPENSSL_free(public_der);
        public_der = NULL;
    }

    absent.variant = curve;
    if (bee2_bign_asn1_encode_pkcs8_der(&absent, &private_len) != NULL ||
        bee2_bign_asn1_encode_spki_der(&absent, &public_len) != NULL ||
        bee2_bign_asn1_encode_pkcs8_der(&key, NULL) != NULL ||
        bee2_bign_asn1_encode_spki_der(&key, NULL) != NULL ||
        bee2_bign_asn1_encode_pkcs8_der(NULL, &private_len) != NULL ||
        bee2_bign_asn1_decode_pkcs8_der(NULL, 0, curve, &parsed) ||
        bee2_bign_asn1_decode_spki_der(NULL, 0, curve, &parsed))
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN ASN.1 key DER boundary test failed\n");
    OPENSSL_free(damaged);
    OPENSSL_free(private_der);
    OPENSSL_free(public_der);
    OPENSSL_cleanse(&key, sizeof(key));
    OPENSSL_cleanse(&parsed, sizeof(parsed));
    return ok;
}



/* The generic decoder normally unwraps encrypted PKCS#8 through an
 * intermediate decoder. Keep the BIGN direct decoding fallback tested too:
 * it must enforce password, iteration and curve-selection boundaries. */
static int test_passphrase(char *pass, size_t size, size_t *length,
                           const OSSL_PARAM params[], void *arg)
{
    const char *value = arg;
    size_t n = strlen(value);

    (void)params;
    if (n > size)
        return 0;
    memcpy(pass, value, n);
    *length = n;
    return 1;
}

static int check_encrypted_key_der(void)
{
    static const unsigned char secret[] = "bign-encrypted-key-test";
    static const unsigned char wrong[] = "incorrect-password";
    bee2_bign_key_t original = {0}, parsed = {0};
    unsigned char *plain = NULL, *encrypted = NULL;
    size_t plain_len = 0, encrypted_len = 0;
    int ok = 0;

    original.variant = bee2_bign_variant_256();
    original.has_priv = 1;
    original.priv[0] = 3;
    plain = bee2_bign_asn1_encode_pkcs8_der(&original, &plain_len);
    if (!plain)
        goto end;
    encrypted = bee2_bign_asn1_encrypt_standard_pkcs8(
        plain, plain_len, secret, sizeof(secret) - 1,
        EVP_aes_256_cbc(), 12000, 16, NULL, &encrypted_len);
    if (!encrypted)
        goto end;
    if (!bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len, original.variant, &parsed, NULL,
            12000, test_passphrase, (void *)secret) ||
        parsed.variant != original.variant || !parsed.has_priv ||
        !parsed.has_pub ||
        CRYPTO_memcmp(parsed.priv, original.priv, 32) != 0 ||
        !bee2_bign_key_validate_public(&parsed))
        goto end;

    OPENSSL_cleanse(&parsed, sizeof(parsed));
    if (bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len, original.variant, &parsed, NULL,
            12000, test_passphrase, (void *)wrong) ||
        bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len, original.variant, &parsed, NULL,
            11999, test_passphrase, (void *)secret) ||
        bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len, original.variant, &parsed, NULL,
            12000, NULL, NULL) ||
        bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len, bee2_bign_variant_384(), &parsed, NULL,
            12000, test_passphrase, (void *)secret) ||
        bee2_bign_asn1_decode_encrypted_pkcs8_der(
            encrypted, encrypted_len - 1, original.variant, &parsed, NULL,
            12000, test_passphrase, (void *)secret))
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN direct encrypted PKCS#8 DER contract failed\n");
    OPENSSL_clear_free(encrypted, encrypted_len);
    OPENSSL_clear_free(plain, plain_len);
    OPENSSL_cleanse(&original, sizeof(original));
    OPENSSL_cleanse(&parsed, sizeof(parsed));
    return ok;
}


/* Validate DER AlgorithmIdentifier construction, including its optional
 * digest OID, through the same helpers used for BIGN signatures. */
static int check_signature_algid(void)
{
    static const char signature_oid[] = "1.2.112.0.2.0.34.101.45.12";
    static const char digest_oid[] = "1.2.3.4";
    ASN1_OBJECT *expected_sig = NULL, *expected_md = NULL;
    const ASN1_OBJECT *actual = NULL;
    const void *parameter = NULL;
    X509_ALGOR *alg = NULL;
    unsigned char der[128];
    char resolved[80];
    const unsigned char *p;
    size_t length;
    int parameter_type = 0, with_digest, ok = 0;

    expected_sig = OBJ_txt2obj(signature_oid, 1);
    expected_md = OBJ_txt2obj(digest_oid, 1);
    if (expected_sig == NULL || expected_md == NULL)
        goto end;

    if (!bee2_bign_asn1_resolve_hash_oid(EVP_sha256(), "SHA256", NULL,
                                         resolved, sizeof(resolved)) ||
        strcmp(resolved, "2.16.840.1.101.3.4.2.1") != 0 ||
        bee2_bign_asn1_resolve_hash_oid(EVP_sha256(), "SHA256", NULL,
                                       resolved, 2) ||
        !bee2_bign_asn1_resolve_hash_oid(EVP_sha256(), "SHA256",
                                          digest_oid, resolved, sizeof(resolved)) ||
        strcmp(resolved, digest_oid) != 0 ||
        bee2_bign_asn1_resolve_hash_oid(EVP_sha256(), "SHA256",
                                       digest_oid, resolved, strlen(digest_oid)))
        goto end;

    for (with_digest = 0; with_digest < 2; ++with_digest) {
        length = 0;
        if (!bee2_bign_asn1_build_algid(signature_oid,
                                        with_digest ? digest_oid : NULL,
                                        der, sizeof(der), &length) ||
            length == 0 || length > sizeof(der))
            goto end;
        p = der;
        alg = d2i_X509_ALGOR(NULL, &p, (long)length);
        if (alg == NULL || p != der + length)
            goto end;
        X509_ALGOR_get0(&actual, &parameter_type, &parameter, alg);
        if (actual == NULL || OBJ_cmp(actual, expected_sig) != 0 ||
            (with_digest ? (parameter_type != V_ASN1_OBJECT ||
                            OBJ_cmp((const ASN1_OBJECT *)parameter, expected_md) != 0) :
                           parameter_type != V_ASN1_NULL))
            goto end;
        X509_ALGOR_free(alg);
        alg = NULL;
    }

    length = 1234;
    if (bee2_bign_asn1_build_algid(signature_oid, digest_oid, der, 1, &length) ||
        bee2_bign_asn1_build_algid("not-an-oid", NULL,
                                  der, sizeof(der), &length) ||
        bee2_bign_asn1_build_algid(signature_oid, "not-an-oid",
                                  der, sizeof(der), &length) ||
        bee2_bign_asn1_build_algid(NULL, NULL, der, sizeof(der), &length) ||
        bee2_bign_asn1_build_algid(signature_oid, NULL, NULL, 0, &length) ||
        bee2_bign_asn1_build_algid(signature_oid, NULL, der, sizeof(der), NULL) ||
        length != 1234)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN AlgorithmIdentifier ASN.1 contract failed\n");
    X509_ALGOR_free(alg);
    ASN1_OBJECT_free(expected_md);
    ASN1_OBJECT_free(expected_sig);
    return ok;
}

int main(void)
{
    static const unsigned char valid_empty[] = {0x30, 0x00};
    static const unsigned char valid_nested[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    static const unsigned char trailing[] = {0x30, 0x00, 0x00};
    static const unsigned char short_body[] = {0x30, 0x03, 0x02, 0x01};
    static const unsigned char indefinite[] = {0x30, 0x80, 0x00, 0x00};
    static const unsigned char wrong_tag[] = {0x04, 0x00};
    static const unsigned char primitive_seq[] = {0x10, 0x00};
    unsigned char *oversized;
    int ok = 1;

    ok &= check("empty", valid_empty, sizeof(valid_empty), 1);
    ok &= check("nested", valid_nested, sizeof(valid_nested), 1);
    ok &= check("trailing", trailing, sizeof(trailing), 0);
    ok &= check("truncated", short_body, sizeof(short_body), 0);
    ok &= check("indefinite", indefinite, sizeof(indefinite), 0);
    ok &= check("wrong tag", wrong_tag, sizeof(wrong_tag), 0);
    ok &= check("primitive sequence", primitive_seq, sizeof(primitive_seq), 0);
    ok &= check("no data", NULL, 0, 0);

    oversized = malloc(BIGN_MAX_KEY_INPUT + 1u);
    if (oversized == NULL) {
        fprintf(stderr, "Unable to allocate oversized DER test buffer\n");
        return 1;
    }
    memset(oversized, 0, BIGN_MAX_KEY_INPUT + 1u);
    oversized[0] = 0x30;
    oversized[1] = 0x00;
    ok &= check("oversized", oversized, BIGN_MAX_KEY_INPUT + 1u, 0);
    free(oversized);

    ok &= check_signature_algid();
    ok &= check_bign_key_der();
    ok &= check_encrypted_key_der();
    return ok ? 0 : 1;
}
