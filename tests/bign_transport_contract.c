/* BIGN key transport EVP coverage for fixed and random plaintext inputs. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static EVP_PKEY *generate_key(const char *algorithm)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    EVP_PKEY *key = NULL;

    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_keygen(ctx, &key) > 0) {
        EVP_PKEY_CTX_free(ctx);
        return key;
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static int roundtrip(EVP_PKEY_CTX *encrypt, EVP_PKEY_CTX *decrypt,
                     const unsigned char *plaintext, size_t length)
{
    unsigned char ciphertext[512], recovered[512];
    size_t ciphertext_len = 0;
    size_t recovered_len = sizeof(recovered);
    int ok = 0;

    if (EVP_PKEY_encrypt(encrypt, NULL, &ciphertext_len, plaintext, length) <= 0 ||
        ciphertext_len > sizeof(ciphertext) ||
        EVP_PKEY_encrypt(encrypt, ciphertext, &ciphertext_len, plaintext, length) <= 0 ||
        EVP_PKEY_decrypt(decrypt, recovered, &recovered_len,
                         ciphertext, ciphertext_len) <= 0 ||
        recovered_len != length ||
        CRYPTO_memcmp(recovered, plaintext, length) != 0)
        goto end;

    /* A modified key token must be rejected, not silently unwrapped. */
    ciphertext[ciphertext_len - 1] ^= 1u;
    recovered_len = sizeof(recovered);
    if (EVP_PKEY_decrypt(decrypt, recovered, &recovered_len,
                         ciphertext, ciphertext_len) > 0)
        goto end;
    ok = 1;

end:
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    return ok;
}

static int check_algorithm(const char *name)
{
    static const size_t lengths[] = {16, 32, 64, 257};
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *encrypt = NULL, *decrypt = NULL;
    unsigned char input[257];
    size_t i, j, k;
    int profile;
    int ok = 0;

    key = generate_key(name);
    if (key == NULL)
        goto end;
    encrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    decrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (encrypt == NULL || decrypt == NULL ||
        EVP_PKEY_encrypt_init(encrypt) <= 0 ||
        EVP_PKEY_decrypt_init(decrypt) <= 0)
        goto end;

    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        for (profile = 0; profile < 4; ++profile) {
            for (j = 0; j < lengths[i]; ++j) {
                if (profile == 0)
                    input[j] = 0;
                else if (profile == 1)
                    input[j] = 0xFF;
                else if (profile == 2)
                    input[j] = (unsigned char)(j * 37u + 11u);
            }
            if (profile == 3 && RAND_bytes(input, (int)lengths[i]) <= 0)
                goto end;
            k = lengths[i];
            if (!roundtrip(encrypt, decrypt, input, k))
                goto end;
        }
    }
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN key transport test failed: %s\n", name);
    EVP_PKEY_CTX_free(encrypt);
    EVP_PKEY_CTX_free(decrypt);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(input, sizeof(input));
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const names[] = {"bign-256", "bign-384", "bign-512"};
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (!check_algorithm(names[i]))
            goto end;
    ok = 1;

end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
