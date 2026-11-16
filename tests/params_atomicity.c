/* A rejected parameter batch must not change the working MAC/KDF context. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_hmac(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    char bash[] = "bash512", belt[] = "belt-hash";
    size_t wide = 64;
    OSSL_PARAM good[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, bash, sizeof(bash)),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &wide),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, belt, sizeof(belt)),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &wide),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_MAC_CTX_set_params(ctx, good) > 0 &&
             EVP_MAC_CTX_get_mac_size(ctx) == wide &&
             EVP_MAC_CTX_set_params(ctx, bad) <= 0 &&
             EVP_MAC_CTX_get_mac_size(ctx) == wide;

    if (!ok)
        fprintf(stderr, "HMAC rejected parameters corrupted context\n");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}


static int check_hmac_failed_reinit(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    unsigned char key[32] = {0}, output[32], data[] = {1, 2, 3};
    char invalid_digest[] = "SHA256";
    size_t output_len = 0, invalid_size = 33;
    OSSL_PARAM invalid_digest_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, invalid_digest, sizeof(invalid_digest)),
        OSSL_PARAM_END
    };
    OSSL_PARAM invalid_size_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, &invalid_size),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL &&
             EVP_MAC_init(ctx, key, sizeof(key), NULL) > 0 &&
             EVP_MAC_update(ctx, data, sizeof(data)) > 0 &&
             EVP_MAC_init(ctx, NULL, 0, invalid_digest_params) <= 0 &&
             EVP_MAC_update(ctx, data, sizeof(data)) <= 0 &&
             EVP_MAC_final(ctx, output, &output_len, sizeof(output)) <= 0 &&
             EVP_MAC_init(ctx, NULL, 0, NULL) > 0 &&
             EVP_MAC_update(ctx, data, sizeof(data)) > 0 &&
             EVP_MAC_init(ctx, NULL, 0, invalid_size_params) <= 0 &&
             EVP_MAC_update(ctx, data, sizeof(data)) <= 0 &&
             EVP_MAC_final(ctx, output, &output_len, sizeof(output)) <= 0 &&
             EVP_MAC_init(ctx, NULL, 0, NULL) > 0 &&
             EVP_MAC_update(ctx, data, sizeof(data)) > 0 &&
             EVP_MAC_final(ctx, output, &output_len, sizeof(output)) > 0 &&
             output_len == sizeof(output);

    if (!ok)
        fprintf(stderr, "Failed HMAC Init left the previous operation active\n");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(output, sizeof(output));
    return ok;
}

static int check_pbkdf(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    unsigned char original[32], again[32];
    char password[] = "stb-password", other[] = "changed-password";
    unsigned char salt[] = {0x0a, 0x11, 0x28, 0x37, 0x46, 0x55, 0x64, 0x73};
    uint64_t iterations = 10000, invalid = 0;
    OSSL_PARAM good[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, password, sizeof(password) - 1),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, other, sizeof(other) - 1),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &invalid),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_KDF_CTX_set_params(ctx, good) > 0 &&
             EVP_KDF_derive(ctx, original, sizeof(original), NULL) > 0 &&
             EVP_KDF_CTX_set_params(ctx, bad) <= 0 &&
             EVP_KDF_derive(ctx, again, sizeof(again), NULL) > 0 &&
             CRYPTO_memcmp(original, again, sizeof(original)) == 0;

    if (!ok)
        fprintf(stderr, "BELT PBKDF rejected parameters corrupted context\n");
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(original, sizeof(original));
    OPENSSL_cleanse(again, sizeof(again));
    return ok;
}

static int check_bign_digest(void)
{
    EVP_PKEY_CTX *gen = NULL, *sign = NULL;
    EVP_PKEY *key = NULL;
    char belt[] = "belt-hash", sha[] = "SHA1";
    char digest[64] = {0};
    OSSL_PARAM good[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, belt, sizeof(belt)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, sha, sizeof(sha)),
        OSSL_PARAM_END
    };
    OSSL_PARAM query[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_END
    };
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto end;
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (sign == NULL || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, good) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, bad) > 0 ||
        EVP_PKEY_CTX_get_params(sign, query) <= 0 ||
        strcmp(digest, belt) != 0)
        goto end;
    {
        unsigned char hash[32] = {0}, signature[48];
        size_t signature_len = sizeof(signature);

        /* An unsuccessful new SignInit must not leave the old operation live. */
        if (EVP_PKEY_sign_init_ex(sign, bad) > 0 ||
            EVP_PKEY_sign(sign, signature, &signature_len, hash, sizeof(hash)) > 0)
            goto end;
    }
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "BIGN rejected digest changed the signature context\n");
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_free(key);
    return ok;
}

static int check_belt_cipher(void)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "belt-cbc256", "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[16] = {0};
    unsigned int padding = 0, actual = 0;
    size_t wrong_key_len = 16;
    OSSL_PARAM bad[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &padding),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &wrong_key_len),
        OSSL_PARAM_END
    };
    OSSL_PARAM get[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &actual),
        OSSL_PARAM_END
    };
    int ok = cipher && ctx &&
             EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) > 0 &&
             EVP_CIPHER_CTX_set_params(ctx, bad) <= 0 &&
             EVP_CIPHER_CTX_get_params(ctx, get) > 0 && actual == 1;

    if (!ok)
        fprintf(stderr, "Rejected BELT padding batch changed the context\n");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int check_bash_prgae(void)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "bash-prg-ae1281", "provider=bee2");
    EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new(), *dec = EVP_CIPHER_CTX_new();
    unsigned char key[16] = {0}, iv[16] = {0}, plain[17] = {0};
    unsigned char ciphertext[17], recovered[17], tag[16], wrong_tag[16];
    size_t wrong_iv_len = 3;
    int len = 0, fin = 0, out = 0, ok = 0;
    OSSL_PARAM gettag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM good[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, wrong_tag, sizeof(wrong_tag)),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, &wrong_iv_len),
        OSSL_PARAM_END
    };

    if (!cipher || !enc || !dec ||
        EVP_EncryptInit_ex2(enc, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(enc, ciphertext, &len, plain, sizeof(plain)) <= 0 ||
        len != (int)sizeof(plain) ||
        EVP_EncryptFinal_ex(enc, ciphertext + len, &fin) <= 0 ||
        EVP_CIPHER_CTX_get_params(enc, gettag) <= 0)
        goto cleanup;

    memcpy(wrong_tag, tag, sizeof(tag));
    wrong_tag[0] ^= 1;
    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_params(dec, good) <= 0 ||
        EVP_CIPHER_CTX_set_params(dec, bad) > 0 ||
        EVP_DecryptUpdate(dec, recovered, &out, ciphertext, sizeof(ciphertext)) <= 0 ||
        out != (int)sizeof(recovered) ||
        EVP_DecryptFinal_ex(dec, recovered + out, &fin) <= 0 ||
        CRYPTO_memcmp(plain, recovered, sizeof(plain)) != 0)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "Rejected BASH-PRGAE tag/IV batch changed the context\n");
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_free(cipher);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    ok = check_hmac() && check_hmac_failed_reinit() && check_pbkdf() && check_bign_digest() &&
         check_belt_cipher() && check_bash_prgae();
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
