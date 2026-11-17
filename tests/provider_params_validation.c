/* Check malformed and size-query parameters through public OpenSSL APIs. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

static int check_mac(const char *algorithm, size_t keylen)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, algorithm, "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    unsigned char key[32] = {0}, tag[8] = {0}, data[3] = {1, 2, 3};
    size_t size = 0;
    char invalid[] = "invalid";
    OSSL_PARAM bad_type[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_KEY, invalid, 0), OSSL_PARAM_END
    };
    OSSL_PARAM bad_length[] = {
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, key, 1), OSSL_PARAM_END
    };
    OSSL_PARAM good_key[] = {
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, key, 0), OSSL_PARAM_END
    };
    OSSL_PARAM get_size[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &size), OSSL_PARAM_END
    };
    OSSL_PARAM bad_get[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_SIZE, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    int ok = 0;

    good_key[0].data_size = keylen;
    if (mac == NULL || ctx == NULL ||
        EVP_MAC_init(ctx, NULL, 0, NULL) > 0 ||
        EVP_MAC_init(ctx, key, keylen - 1, NULL) > 0 ||
        EVP_MAC_get_params(mac, get_size) <= 0 || size != sizeof(tag) ||
        EVP_MAC_get_params(mac, bad_get) > 0 ||
        EVP_MAC_CTX_get_params(ctx, bad_get) > 0 ||
        EVP_MAC_CTX_set_params(ctx, bad_type) > 0 ||
        EVP_MAC_CTX_set_params(ctx, bad_length) > 0 ||
        EVP_MAC_init(ctx, key, keylen, bad_type) > 0 ||
        EVP_MAC_init(ctx, key, keylen, NULL) <= 0 ||
        EVP_MAC_final(ctx, NULL, &size, 0) <= 0 || size != sizeof(tag) ||
        EVP_MAC_final(ctx, tag, &size, sizeof(tag) - 1) > 0 ||
        EVP_MAC_update(ctx, data, sizeof(data)) <= 0 ||
        EVP_MAC_final(ctx, tag, &size, sizeof(tag)) <= 0 ||
        size != sizeof(tag) ||
        EVP_MAC_CTX_set_params(ctx, good_key) <= 0 ||
        EVP_MAC_update(ctx, data, sizeof(data)) > 0 ||
        EVP_MAC_init(ctx, NULL, 0, NULL) <= 0 ||
        EVP_MAC_update(ctx, data, sizeof(data)) <= 0 ||
        EVP_MAC_final(ctx, tag, &size, sizeof(tag)) <= 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BELT-MAC parameter contract failed: %s\n", algorithm);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int check_kwp(const char *algorithm, size_t keylen)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[16] = {0}, retrieved_iv[16] = {0};
    size_t param_len = keylen;
    char invalid[] = "invalid";
    OSSL_PARAM right_keylen[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &param_len), OSSL_PARAM_END
    };
    OSSL_PARAM bad_type[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_KEYLEN, invalid, 0), OSSL_PARAM_END
    };
    OSSL_PARAM bad_get_key[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_KEYLEN, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_get_ivlen[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_IVLEN, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_get_block[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_BLOCK_SIZE, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM get_iv[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, retrieved_iv, sizeof(retrieved_iv)),
        OSSL_PARAM_END
    };
    OSSL_PARAM short_iv[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, retrieved_iv, 1),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (cipher == NULL || ctx == NULL ||
        EVP_CIPHER_get_params(cipher, bad_get_key) > 0 ||
        EVP_CIPHER_get_params(cipher, bad_get_ivlen) > 0 ||
        EVP_CIPHER_get_params(cipher, bad_get_block) > 0 ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_get_params(ctx, bad_get_key) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, bad_get_ivlen) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, short_iv) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, get_iv) <= 0 ||
        memcmp(iv, retrieved_iv, sizeof(iv)) != 0 ||
        EVP_CIPHER_CTX_set_params(ctx, bad_type) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, right_keylen) <= 0)
        goto done;
    param_len = keylen - 1;
    if (EVP_CIPHER_CTX_set_params(ctx, right_keylen) > 0 ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, bad_type) > 0 ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BELT-KWP parameter contract failed: %s\n", algorithm);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int check_pbkdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    unsigned char output[32], password[] = "password", salt[] = "salt";
    uint64_t iterations = 2, zero = 0;
    char invalid[] = "invalid";
    OSSL_PARAM valid[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, password, sizeof(password) - 1),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt) - 1),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_password[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PASSWORD, invalid, 0), OSSL_PARAM_END
    };
    OSSL_PARAM bad_salt[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_SALT, invalid, 0), OSSL_PARAM_END
    };
    OSSL_PARAM bad_iterations[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_ITER, invalid, 0), OSSL_PARAM_END
    };
    OSSL_PARAM zero_iterations[] = {
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &zero), OSSL_PARAM_END
    };
    OSSL_PARAM null_password[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 1), OSSL_PARAM_END
    };
    OSSL_PARAM null_salt[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 1), OSSL_PARAM_END
    };
    int ok = 0;

    if (kdf == NULL || ctx == NULL ||
        EVP_KDF_CTX_set_params(ctx, bad_password) > 0 ||
        EVP_KDF_CTX_set_params(ctx, bad_salt) > 0 ||
        EVP_KDF_CTX_set_params(ctx, bad_iterations) > 0 ||
        EVP_KDF_CTX_set_params(ctx, zero_iterations) > 0 ||
        EVP_KDF_CTX_set_params(ctx, null_password) > 0 ||
        EVP_KDF_CTX_set_params(ctx, null_salt) > 0 ||
        EVP_KDF_derive(ctx, output, sizeof(output), NULL) > 0 ||
        EVP_KDF_derive(ctx, output, sizeof(output) - 1, valid) > 0 ||
        EVP_KDF_derive(ctx, output, sizeof(output), bad_password) > 0 ||
        EVP_KDF_derive(ctx, output, sizeof(output), valid) <= 0)
        goto done;
    EVP_KDF_CTX_reset(ctx);
    if (EVP_KDF_derive(ctx, output, sizeof(output), NULL) > 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BELT-PBKDF parameter contract failed\n");
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

static int check_bign_encoding(const char *algorithm)
{
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *key = NULL;
    char encoding[32];
    char bad[] = "unknown";
    unsigned char blob[2] = {1, 2};
    OSSL_PARAM invalid_type[] = {
        OSSL_PARAM_octet_string("enc_params", blob, sizeof(blob)), OSSL_PARAM_END
    };
    OSSL_PARAM invalid_value[] = {
        OSSL_PARAM_utf8_string("enc_params", bad, 0), OSSL_PARAM_END
    };
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0 ||
        EVP_PKEY_set_utf8_string_param(key, "enc_params", "specified") <= 0 ||
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_EC_ENCODING,
                                       encoding, sizeof(encoding), NULL) <= 0 ||
        strcmp(encoding, OSSL_PKEY_EC_ENCODING_EXPLICIT) != 0 ||
        EVP_PKEY_set_params(key, invalid_type) > 0 ||
        EVP_PKEY_set_params(key, invalid_value) > 0 ||
        EVP_PKEY_set_utf8_string_param(key, "enc_params", "cofactor") <= 0 ||
        EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_ENCODING,
                                       OSSL_PKEY_EC_ENCODING_GROUP) <= 0 ||
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_EC_ENCODING,
                                       encoding, sizeof(encoding), NULL) <= 0 ||
        strcmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN encoding params failed: %s\n", algorithm);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
    return ok;
}

static int check_provider_metadata(OSSL_PROVIDER *provider)
{
    static const char *names[] = {
        OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_VERSION,
        OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_STATUS
    };
    char *name = NULL, *version = NULL, *build = NULL;
    unsigned int wrong = 1;
    int status = 0;
    size_t i;
    OSSL_PARAM valid[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &build, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, &status),
        OSSL_PARAM_END
    };

    if (OSSL_PROVIDER_get_params(provider, valid) <= 0 ||
        name == NULL || strcmp(name, "Bee2 provider") != 0 ||
        version == NULL || version[0] == '\0' ||
        build == NULL || strcmp(build, "Bee2 backend") != 0 || status != 1)
        return 0;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        OSSL_PARAM wrong_type[] = {
            OSSL_PARAM_uint(names[i], &wrong), OSSL_PARAM_END
        };
        unsigned char blob[2] = {1, 2};
        OSSL_PARAM bad_status[] = {
            OSSL_PARAM_octet_string(OSSL_PROV_PARAM_STATUS, blob, sizeof(blob)),
            OSSL_PARAM_END
        };
        if (OSSL_PROVIDER_get_params(provider, i == 3 ? bad_status : wrong_type) > 0)
            return 0;
    }
    return 1;
}


/* An IV returned through EVP must match the initialized state.  Reject
 * undersized output buffers and parameters of the wrong data type. */
static int check_cipher_iv(const char *algorithm, size_t keylen, size_t ivlen,
                           int updated_iv)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[32], actual[32] = {0}, updated[32] = {0};
    char bad_type[] = "invalid";
    size_t got_keylen = 0, got_ivlen = 0;
    size_t i;
    int ok = 0;
    OSSL_PARAM valid[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, actual, sizeof(actual)),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &got_keylen),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &got_ivlen),
        OSSL_PARAM_END
    };
    OSSL_PARAM updated_param[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, updated, sizeof(updated)),
        OSSL_PARAM_END
    };
    OSSL_PARAM short_iv[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, actual, 1),
        OSSL_PARAM_END
    };
    OSSL_PARAM short_updated[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, updated, 1),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_keylen[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_KEYLEN, bad_type, sizeof(bad_type)),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_ivlen[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_IVLEN, bad_type, sizeof(bad_type)),
        OSSL_PARAM_END
    };

    for (i = 0; i < sizeof(iv); ++i)
        iv[i] = (unsigned char)(i * 17u + 1u);
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_get_params(ctx, short_iv) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, wrong_keylen) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, wrong_ivlen) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, valid) <= 0 ||
        got_keylen != keylen || got_ivlen != ivlen ||
        memcmp(iv, actual, ivlen) != 0)
        goto done;

    if (updated_iv &&
        (EVP_CIPHER_CTX_get_params(ctx, short_updated) > 0 ||
         EVP_CIPHER_CTX_get_params(ctx, updated_param) <= 0 ||
         memcmp(iv, updated, ivlen) != 0))
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "Cipher IV metadata contract failed: %s\n", algorithm);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL, *bee2_provider = NULL;
    int ok = 0;
    size_t i;
    static const size_t lengths[] = {16, 24, 32};
    static const char *const macs[] = {"belt-mac128", "belt-mac192", "belt-mac256"};
    static const char *const wraps[] = {"belt-kwp128", "belt-kwp192", "belt-kwp256"};

    if (argc != 2 ||
        !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    bee2_provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (default_provider == NULL || bee2_provider == NULL ||
        !check_provider_metadata(bee2_provider))
        goto done;
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        if (!check_mac(macs[i], lengths[i]) ||
            !check_kwp(wraps[i], lengths[i]))
            goto done;
    }
    ok = check_cipher_iv("belt-sde256", 32, 16, 1) &&
         check_cipher_iv("belt-cbc256", 32, 16, 0) &&
         check_cipher_iv("belt-cfb256", 32, 16, 0) &&
         check_cipher_iv("belt-ctr256", 32, 16, 0) &&
         check_cipher_iv("belt-dwp256", 32, 16, 0) &&
         check_cipher_iv("belt-che256", 32, 16, 0) &&
         check_cipher_iv("bash-prg-ae1281", 16, 16, 0) &&
         check_cipher_iv("bash-prg-ae1921", 24, 24, 0) &&
         check_cipher_iv("bash-prg-ae2561", 32, 32, 0) &&
         check_pbkdf() && check_bign_encoding("bign-256") &&
         check_bign_encoding("bign-384") &&
         check_bign_encoding("bign-512");
done:
    OSSL_PROVIDER_unload(bee2_provider);
    OSSL_PROVIDER_unload(default_provider);
    return ok ? 0 : 1;
}
