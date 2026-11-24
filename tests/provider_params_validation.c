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
        /* Named-curve keys must reject cofactor rather than ignore it. */
        EVP_PKEY_set_utf8_string_param(key, "enc_params", "cofactor") > 0 ||
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_EC_ENCODING,
                                       encoding, sizeof(encoding), NULL) <= 0 ||
        strcmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0 ||
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
        strcmp(encoding, OSSL_PKEY_EC_ENCODING_GROUP) != 0 ||
        /* Switching to named parameters clears cofactor state. */
        EVP_PKEY_set_utf8_string_param(key, "enc_params", "cofactor") > 0 ||
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


/* Digest metadata is part of the provider contract.  Each wrong output
 * parameter type must fail rather than silently reporting success. */
static int check_digest_metadata(const char *algorithm, size_t digest_size,
                                 size_t block_size)
{
    EVP_MD *md = EVP_MD_fetch(NULL, algorithm, "provider=bee2");
    size_t output_size = 0, rate = 0;
    int xof = -1;
    char invalid[] = "wrong";
    OSSL_PARAM good[] = {
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, &output_size),
        OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, &rate),
        OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, &xof),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_size[] = {
        OSSL_PARAM_utf8_string(OSSL_DIGEST_PARAM_SIZE, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_rate[] = {
        OSSL_PARAM_utf8_string(OSSL_DIGEST_PARAM_BLOCK_SIZE, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_xof[] = {
        OSSL_PARAM_utf8_string(OSSL_DIGEST_PARAM_XOF, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    int ok = md != NULL &&
             EVP_MD_get_params(md, good) > 0 &&
             output_size == digest_size && rate == block_size && xof == 0 &&
             EVP_MD_get_params(md, bad_size) <= 0 &&
             EVP_MD_get_params(md, bad_rate) <= 0 &&
             EVP_MD_get_params(md, bad_xof) <= 0;

    if (!ok)
        fprintf(stderr, "Digest metadata contract failed: %s\n", algorithm);
    EVP_MD_free(md);
    return ok;
}


/* BASH PRGAE advertises both algorithm metadata and context metadata.
 * Bad result types must be rejected by each callback independently. */
static int check_prgae_metadata(const char *algorithm, size_t expected_key,
                                size_t expected_iv)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[32] = {0};
    char invalid[] = "invalid";
    size_t key_len = 0, iv_len = 0, block_size = 0, tag_len = 0;
    int aead = -1, ok = 0;
    const char *const names[] = {
        OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_IVLEN,
        OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_CIPHER_PARAM_AEAD
    };
    OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_len),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, &block_size),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tag_len),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, &aead),
        OSSL_PARAM_END
    };
    OSSL_PARAM ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_len),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &tag_len),
        OSSL_PARAM_END
    };
    size_t i;

    if (cipher == NULL || ctx == NULL ||
        EVP_CIPHER_get_params(cipher, params) <= 0 ||
        key_len != expected_key || iv_len != expected_iv ||
        block_size != 1 || tag_len == 0 || aead != 1)
        goto end;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        OSSL_PARAM invalid_param[] = {
            OSSL_PARAM_utf8_string(names[i], invalid, sizeof(invalid)),
            OSSL_PARAM_END
        };
        if (EVP_CIPHER_get_params(cipher, invalid_param) > 0)
            goto end;
    }

    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_get_params(ctx, ctx_params) <= 0 ||
        key_len != expected_key || iv_len != expected_iv)
        goto end;

    for (i = 0; i < 3; ++i) {
        OSSL_PARAM invalid_param[] = {
            OSSL_PARAM_utf8_string(names[i == 2 ? 3 : i],
                                   invalid, sizeof(invalid)),
            OSSL_PARAM_END
        };
        if (EVP_CIPHER_CTX_get_params(ctx, invalid_param) > 0)
            goto end;
    }
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BASH PRGAE metadata contract failed: %s\n", algorithm);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}


/* Changing the PRGAE announcement length invalidates the old IV.
 * A caller must provide a new IV before processing more data. */
static int check_prgae_iv_reset(void)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "bash-prg-ae2561",
                                          "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[32] = {0}, aad[4] = {1, 2, 3, 4};
    unsigned char input[5] = {8}, output[16] = {0}, tag[32] = {0};
    char wrong[] = "wrong";
    size_t short_iv = 16, invalid_iv = 19, restored_iv = 32, invalid_key = 36;
    size_t keylen = sizeof(key);
    int written = 0, final_len = 0, ok = 0;
    OSSL_PARAM short_iv_param[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &short_iv),
        OSSL_PARAM_END
    };
    OSSL_PARAM invalid_iv_param[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &invalid_iv),
        OSSL_PARAM_END
    };
    OSSL_PARAM full_iv_param[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &restored_iv),
        OSSL_PARAM_END
    };
    OSSL_PARAM invalid_key_param[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &invalid_key),
        OSSL_PARAM_END
    };
    OSSL_PARAM current_key_param[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &keylen),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_type[] = {
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_KEYLEN, wrong, sizeof(wrong)),
        OSSL_PARAM_END
    };
    OSSL_PARAM full_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM short_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, 1),
        OSSL_PARAM_END
    };

    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_params(ctx, invalid_key_param) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, invalid_iv_param) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, wrong_type) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, current_key_param) <= 0 ||
        EVP_CIPHER_CTX_get_params(ctx, full_tag) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, full_tag) > 0 ||
        EVP_CIPHER_CTX_set_params(ctx, short_iv_param) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &written, input, sizeof(input)) > 0 ||
        EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &written, aad, sizeof(aad)) <= 0 ||
        EVP_CIPHER_CTX_set_params(ctx, full_iv_param) > 0 ||
        EVP_EncryptUpdate(ctx, output, &written, input, sizeof(input)) <= 0 ||
        written != (int)sizeof(input) ||
        EVP_EncryptFinal_ex(ctx, output + written, &final_len) <= 0 ||
        EVP_CIPHER_CTX_get_params(ctx, short_tag) > 0 ||
        EVP_CIPHER_CTX_get_params(ctx, full_tag) <= 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "BASH PRGAE IV reset contract failed\n");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(tag, sizeof(tag));
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
    ok = check_prgae_iv_reset() &&
         check_prgae_metadata("bash-prg-ae1281", 16, 16) &&
         check_prgae_metadata("bash-prg-ae1921", 24, 24) &&
         check_prgae_metadata("bash-prg-ae2561", 32, 32) &&
         check_digest_metadata("belt-hash", 32, 32) &&
         check_digest_metadata("bash256", 32, 160) &&
         check_digest_metadata("bash384", 48, 144) &&
         check_digest_metadata("bash512", 64, 128) &&
         check_cipher_iv("belt-sde256", 32, 16, 1) &&
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
