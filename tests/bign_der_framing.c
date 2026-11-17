/* Test the exact DER framing helper used by the BIGN key decoder.
 * The openssl pkey CLI intentionally accepts one DER object followed by data. */
#include "../src/bign_der_frame.h"
#include "../src/bign_asn1.h"
#include "../src/provider_util.h"

#include <openssl/crypto.h>

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
    unsigned int explicit_encoding;
    int ok = 0;

    key.variant = curve;
    key.has_priv = 1;
    key.priv[0] = 3;
    for (explicit_encoding = 0; explicit_encoding < 2; ++explicit_encoding) {
        key.encode_explicit = (int)explicit_encoding;
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
            parsed.encode_explicit != (int)explicit_encoding ||
            CRYPTO_memcmp(key.priv, parsed.priv, 32) != 0)
            goto done;

        memset(&parsed, 0, sizeof(parsed));
        if (!bee2_bign_asn1_decode_spki_der(public_der, public_len, curve, &parsed) ||
            !parsed.has_pub || parsed.has_priv || parsed.variant != curve ||
            parsed.encode_explicit != (int)explicit_encoding ||
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


/* Run the shared BIGN and secret-memory helpers through their public
 * contracts. These are genuine invalid-input and key-consistency cases,
 * rather than synthetic branches hidden behind compiler directives.
 */
static int check_common_contract(void)
{
    const bee2_bign_variant_t *variant = bee2_bign_variant_256();
    bee2_bign_key_t *key = NULL;
    unsigned char data[16], pub[64], secret_a[] = {3, 7, 9};
    unsigned char *secret = NULL;
    size_t secret_len = 0;
    bign_params params;
    size_t i;
    int ok = 0;

    memset(data, 0xa5, sizeof(data));
    bee2_bign_openssl_rng(data, sizeof(data), NULL);
    for (i = 0; i < sizeof(data); ++i)
        if (data[i] != 0)
            goto done;

    if (bee2_bign_variant_matches(NULL, "bign-256") ||
        bee2_bign_variant_matches(variant, NULL) ||
        !bee2_bign_variant_matches(variant, "bign-256") ||
        !bee2_bign_variant_matches(variant, variant->curve_oid) ||
        bee2_bign_variant_matches(variant, "bign-384") ||
        bee2_bign_variant_from_name(NULL) != NULL ||
        bee2_bign_variant_from_name("not-a-curve") != NULL ||
        bee2_bign_variant_from_name("bign-256") != variant ||
        bee2_bign_priv_len(NULL) != 0 ||
        bee2_bign_pub_len(NULL) != 0 ||
        bee2_bign_sig_len(NULL) != 0 ||
        bee2_bign_curve_init_std(NULL, &params) ||
        bee2_bign_curve_init_std(variant, NULL) ||
        bee2_bign_derive_pubkey(NULL, pub, secret_a) ||
        bee2_bign_derive_pubkey(variant, NULL, secret_a) ||
        bee2_bign_derive_pubkey(variant, pub, NULL))
        goto done;

    key = bee2_bign_key_new(variant);
    if (key == NULL ||
        bee2_bign_key_validate_public(NULL) ||
        bee2_bign_key_validate_public(key) ||
        bee2_bign_key_validate_pair(NULL) ||
        bee2_bign_key_validate_pair(key))
        goto done;

    key->has_priv = 1;
    key->priv[0] = 3;
    if (!bee2_bign_derive_pubkey(variant, key->pub, key->priv))
        goto done;
    key->has_pub = 1;
    if (!bee2_bign_key_validate_pair(key) ||
        !bee2_bign_key_validate_public(key))
        goto done;

    key->pub[0] ^= 1;
    if (bee2_bign_key_validate_pair(key))
        goto done;
    key->pub[0] ^= 1;
    key->has_pub = 0;
    if (bee2_bign_key_validate_pair(key))
        goto done;
    key->has_pub = 1;
    key->has_priv = 0;
    if (bee2_bign_key_validate_pair(key))
        goto done;
    key->has_priv = 1;
    memset(key->pub, 0, sizeof(key->pub));
    if (bee2_bign_key_validate_public(key))
        goto done;

    if (bee2_secret_replace(NULL, &secret_len, secret_a, sizeof(secret_a)) ||
        bee2_secret_replace(&secret, NULL, secret_a, sizeof(secret_a)) ||
        bee2_secret_replace(&secret, &secret_len, NULL, 1) ||
        !bee2_secret_replace(&secret, &secret_len, secret_a, sizeof(secret_a)) ||
        secret_len != sizeof(secret_a) ||
        !bee2_constant_time_equal(secret, secret_a, secret_len) ||
        bee2_constant_time_equal(secret, NULL, secret_len) ||
        bee2_constant_time_equal(NULL, secret_a, secret_len) ||
        bee2_constant_time_equal(secret_a, data, sizeof(secret_a)) ||
        !bee2_constant_time_equal(NULL, NULL, 0) ||
        !bee2_secret_replace(&secret, &secret_len, NULL, 0) ||
        secret != NULL || secret_len != 0)
        goto done;

    bee2_bign_cleanse(NULL, sizeof(data));
    bee2_bign_cleanse(data, 0);
    bee2_bign_key_free(NULL);
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN shared helper contract failed\n");
    OPENSSL_clear_free(secret, secret_len);
    bee2_bign_key_free(key);
    OPENSSL_cleanse(pub, sizeof(pub));
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

    ok &= check_bign_key_der();
    ok &= check_common_contract();
    return ok ? 0 : 1;
}
