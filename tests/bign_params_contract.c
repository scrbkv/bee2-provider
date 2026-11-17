/* Rejected BIGN parameters must not change the active key or KDF context. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static EVP_PKEY *generate_key(const char *name)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int get_encoding(EVP_PKEY *key, const char *expected)
{
    char value[32];
    size_t length = 0;

    return EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_EC_ENCODING,
                                          value, sizeof(value), &length) > 0 &&
           strcmp(value, expected) == 0;
}

static int check_key_params(EVP_PKEY *key)
{
    char explicit_name[] = OSSL_PKEY_EC_ENCODING_EXPLICIT;
    char group_name[] = OSSL_PKEY_EC_ENCODING_GROUP;
    char invalid_name[] = "invalid";
    unsigned char invalid_pub[1] = {0};
    unsigned int malformed_value = 7;
    OSSL_PARAM bad_encoding_type[] = {
        OSSL_PARAM_uint(OSSL_PKEY_PARAM_EC_ENCODING, &malformed_value),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_group_type[] = {
        OSSL_PARAM_uint(OSSL_PKEY_PARAM_GROUP_NAME, &malformed_value),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_encoding[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, explicit_name, sizeof(explicit_name)),
        OSSL_PARAM_utf8_string("enc_params", invalid_name, sizeof(invalid_name)),
        OSSL_PARAM_END
    };
    OSSL_PARAM good_encoding[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, explicit_name, sizeof(explicit_name)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_key[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, group_name, sizeof(group_name)),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, invalid_pub, sizeof(invalid_pub)),
        OSSL_PARAM_END
    };

    if (!get_encoding(key, OSSL_PKEY_EC_ENCODING_GROUP))
        return 0;
    if (EVP_PKEY_set_params(key, bad_encoding) > 0 ||
        !get_encoding(key, OSSL_PKEY_EC_ENCODING_GROUP))
        return 0;
    if (EVP_PKEY_set_params(key, good_encoding) <= 0 ||
        !get_encoding(key, OSSL_PKEY_EC_ENCODING_EXPLICIT))
        return 0;
    if (EVP_PKEY_set_params(key, bad_key) > 0 ||
        !get_encoding(key, OSSL_PKEY_EC_ENCODING_EXPLICIT))
        return 0;
    /* EVP passes these typed parameters to KEYMGMT; reject atomically. */
    if (EVP_PKEY_set_params(key, bad_encoding_type) > 0 ||
        EVP_PKEY_set_params(key, bad_group_type) > 0 ||
        !get_encoding(key, OSSL_PKEY_EC_ENCODING_EXPLICIT))
        return 0;
    return 1;
}

static int check_exchange_params(EVP_PKEY *local_key, EVP_PKEY *peer_key)
{
    EVP_PKEY_CTX *ctx = NULL;
    char bake[] = "bake-kdf";
    char none[] = "none";
    size_t valid_length = 16;
    size_t invalid_length = 64;
    size_t needed = 0;
    size_t actual = 0;
    size_t queried = 0;
    unsigned char secret[32];
    unsigned char ukm[] = {0x10, 0x20, 0x30, 0x40};
    unsigned char other_ukm[] = {0x50, 0x60, 0x70, 0x80};
    unsigned char queried_ukm[sizeof(ukm)] = {0};
    OSSL_PARAM initial[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, bake, sizeof(bake)),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &valid_length),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ukm, sizeof(ukm)),
        OSSL_PARAM_END
    };
    OSSL_PARAM invalid_size[] = {
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &invalid_length),
        OSSL_PARAM_END
    };
    OSSL_PARAM invalid_mixed[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, none, sizeof(none)),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                other_ukm, sizeof(other_ukm)),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &invalid_length),
        OSSL_PARAM_END
    };
    OSSL_PARAM query[] = {
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &queried),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                queried_ukm, sizeof(queried_ukm)),
        OSSL_PARAM_END
    };
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local_key, "provider=bee2");
    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0 ||
        EVP_PKEY_CTX_set_params(ctx, initial) <= 0)
        goto end;
    if (EVP_PKEY_CTX_set_params(ctx, invalid_size) > 0 ||
        EVP_PKEY_CTX_set_params(ctx, invalid_mixed) > 0)
        goto end;
    if (EVP_PKEY_CTX_get_params(ctx, query) <= 0 || queried != valid_length ||
        CRYPTO_memcmp(queried_ukm, ukm, sizeof(ukm)) != 0)
        goto end;
    if (EVP_PKEY_derive(ctx, NULL, &needed) <= 0 || needed != valid_length)
        goto end;
    actual = sizeof(secret);
    if (EVP_PKEY_derive(ctx, secret, &actual) <= 0 || actual != valid_length)
        goto end;
    ok = 1;

end:
    OPENSSL_cleanse(secret, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    return ok;
}


/* Import must reject a valid point that does not belong to the scalar.
 * A failed EVP_PKEY_set_params must also leave the existing key unchanged. */
static int check_mismatched_pair(EVP_PKEY *alice, EVP_PKEY *bob, const char *algorithm)
{
    unsigned char private_key[64], foreign_public[128], expected_public[128];
    unsigned char actual_public[128];
    size_t private_len = 0, foreign_len = 0, expected_len = 0, actual_len = 0;
    EVP_PKEY_CTX *import = NULL;
    EVP_PKEY *invalid = NULL;
    OSSL_PARAM params[3];
    int ok = 0;

    if (EVP_PKEY_get_octet_string_param(alice, OSSL_PKEY_PARAM_PRIV_KEY,
                                        private_key, sizeof(private_key),
                                        &private_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(alice, OSSL_PKEY_PARAM_PUB_KEY,
                                        expected_public, sizeof(expected_public),
                                        &expected_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(bob, OSSL_PKEY_PARAM_PUB_KEY,
                                        foreign_public, sizeof(foreign_public),
                                        &foreign_len) <= 0 ||
        expected_len != foreign_len ||
        CRYPTO_memcmp(expected_public, foreign_public, expected_len) == 0)
        goto end;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                   private_key, private_len);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   foreign_public, foreign_len);
    params[2] = OSSL_PARAM_construct_end();
    import = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    if (!import || EVP_PKEY_fromdata_init(import) <= 0 ||
        EVP_PKEY_fromdata(import, &invalid, EVP_PKEY_KEYPAIR, params) > 0 ||
        EVP_PKEY_set_params(alice, params) > 0 ||
        EVP_PKEY_get_octet_string_param(alice, OSSL_PKEY_PARAM_PUB_KEY,
                                        actual_public, sizeof(actual_public),
                                        &actual_len) <= 0 ||
        actual_len != expected_len ||
        CRYPTO_memcmp(actual_public, expected_public, expected_len) != 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN mismatched private/public import accepted: %s\n",
                algorithm);
    EVP_PKEY_free(invalid);
    EVP_PKEY_CTX_free(import);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(foreign_public, sizeof(foreign_public));
    OPENSSL_cleanse(expected_public, sizeof(expected_public));
    OPENSSL_cleanse(actual_public, sizeof(actual_public));
    return ok;
}

static int check_keygen_from_template(EVP_PKEY *template)
{
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_pkey(
        NULL, template, "provider=bee2");
    EVP_PKEY *generated = NULL;
    int ok = gen != NULL && EVP_PKEY_keygen_init(gen) > 0 &&
             EVP_PKEY_keygen(gen, &generated) > 0 &&
             EVP_PKEY_get_bits(generated) == EVP_PKEY_get_bits(template) &&
             EVP_PKEY_eq(generated, template) == 0;

    EVP_PKEY_free(generated);
    EVP_PKEY_CTX_free(gen);
    if (!ok)
        fprintf(stderr, "BIGN key generation from template failed\n");
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const names[] = {"bign-256", "bign-384", "bign-512"};
    OSSL_PROVIDER *def = NULL;
    OSSL_PROVIDER *bee2 = NULL;
    EVP_PKEY *alice = NULL;
    EVP_PKEY *bob = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        goto end;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        alice = generate_key(names[i]);
        bob = generate_key(names[i]);
        if (alice == NULL || bob == NULL || !check_key_params(alice) ||
            !check_exchange_params(alice, bob) ||
            !check_mismatched_pair(alice, bob, names[i]) ||
            !check_keygen_from_template(alice)) {
            fprintf(stderr, "BIGN parameter rollback failed for %s\n", names[i]);
            goto end;
        }
        EVP_PKEY_free(alice);
        EVP_PKEY_free(bob);
        alice = NULL;
        bob = NULL;
    }
    ok = 1;

end:
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
