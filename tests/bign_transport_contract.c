/* BIGN key transport EVP coverage for fixed and random plaintext inputs. */
#include <openssl/crypto.h>
#include <openssl/err.h>
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
    size_t needed = 0;
    int ok = 0;

    /* libcrypto passes a null outlen to provider callbacks for size queries. */
    if (EVP_PKEY_encrypt(encrypt, NULL, NULL, plaintext, length) > 0 ||
        EVP_PKEY_encrypt(encrypt, NULL, &ciphertext_len, plaintext, length) <= 0 ||
        ciphertext_len > sizeof(ciphertext) ||
        EVP_PKEY_encrypt(encrypt, ciphertext, &ciphertext_len, plaintext, length) <= 0)
        goto end;
    if (EVP_PKEY_decrypt(decrypt, NULL, NULL, ciphertext, ciphertext_len) > 0 ||
        EVP_PKEY_decrypt(decrypt, NULL, &needed, ciphertext, ciphertext_len) <= 0 ||
        needed != length)
        goto end;
    recovered_len = length - 1;
    if (EVP_PKEY_decrypt(decrypt, recovered, &recovered_len,
                         ciphertext, ciphertext_len) > 0)
        goto end;
    recovered_len = sizeof(recovered);
    if (EVP_PKEY_decrypt(decrypt, recovered, &recovered_len,
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

#define BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER "header"

static int set_header(EVP_PKEY_CTX *ctx, const unsigned char *header, size_t length)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER,
                                (void *)header, length),
        OSSL_PARAM_END
    };

    return EVP_PKEY_CTX_set_params(ctx, params) > 0;
}

static int get_header(EVP_PKEY_CTX *ctx, unsigned char header[16])
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(BEE2_BIGN_KEYTRANSPORT_PARAM_HEADER,
                                header, 16),
        OSSL_PARAM_END
    };

    return EVP_PKEY_CTX_get_params(ctx, params) > 0;
}

static int check_header(EVP_PKEY *key)
{
    static const unsigned char header_a[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const unsigned char header_b[16] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    static const unsigned char plaintext[] = "BIGN key transport header";
    EVP_PKEY_CTX *encrypt = NULL, *wrong_decrypt = NULL, *decrypt = NULL;
    EVP_PKEY_CTX *copy = NULL;
    unsigned char ciphertext[512], recovered[sizeof(plaintext)];
    unsigned char returned_header[16];
    size_t ciphertext_len = 0, recovered_len;
    int ok = 0;

    encrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    wrong_decrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    decrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (encrypt == NULL || wrong_decrypt == NULL || decrypt == NULL ||
        EVP_PKEY_encrypt_init(encrypt) <= 0 ||
        EVP_PKEY_decrypt_init(wrong_decrypt) <= 0 ||
        EVP_PKEY_decrypt_init(decrypt) <= 0 ||
        !set_header(encrypt, header_a, sizeof(header_a)) ||
        !set_header(wrong_decrypt, header_b, sizeof(header_b)) ||
        !set_header(decrypt, header_a, sizeof(header_a)) ||
        !get_header(encrypt, returned_header) ||
        CRYPTO_memcmp(returned_header, header_a, sizeof(header_a)) != 0)
        goto end;

    /* Duplicating an initialized context must retain its header, but the
     * copy and original must be independently mutable. */
    copy = EVP_PKEY_CTX_dup(encrypt);
    if (copy == NULL || !get_header(copy, returned_header) ||
        CRYPTO_memcmp(returned_header, header_a, sizeof(header_a)) != 0 ||
        !set_header(copy, header_b, sizeof(header_b)) ||
        !get_header(encrypt, returned_header) ||
        CRYPTO_memcmp(returned_header, header_a, sizeof(header_a)) != 0)
        goto end;

    /* Invalid lengths must be rejected without changing the stored header. */
    if (set_header(encrypt, header_a, sizeof(header_a) - 1u) ||
        !get_header(encrypt, returned_header) ||
        CRYPTO_memcmp(returned_header, header_a, sizeof(header_a)) != 0)
        goto end;

    if (EVP_PKEY_encrypt(encrypt, NULL, &ciphertext_len,
                         plaintext, sizeof(plaintext)) <= 0 ||
        ciphertext_len > sizeof(ciphertext) ||
        EVP_PKEY_encrypt(encrypt, ciphertext, &ciphertext_len,
                         plaintext, sizeof(plaintext)) <= 0)
        goto end;

    recovered_len = sizeof(recovered);
    if (EVP_PKEY_decrypt(wrong_decrypt, recovered, &recovered_len,
                         ciphertext, ciphertext_len) > 0)
        goto end;
    ERR_clear_error();

    recovered_len = sizeof(recovered);
    if (EVP_PKEY_decrypt(decrypt, recovered, &recovered_len,
                         ciphertext, ciphertext_len) <= 0 ||
        recovered_len != sizeof(plaintext) ||
        CRYPTO_memcmp(recovered, plaintext, sizeof(plaintext)) != 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN key transport header test failed\n");
    EVP_PKEY_CTX_free(copy);
    EVP_PKEY_CTX_free(encrypt);
    EVP_PKEY_CTX_free(wrong_decrypt);
    EVP_PKEY_CTX_free(decrypt);
    OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    OPENSSL_cleanse(returned_header, sizeof(returned_header));
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
    if (!check_header(key))
        goto end;
    {
        OSSL_PARAM invalid[] = {
            OSSL_PARAM_octet_string("header", input, 15),
            OSSL_PARAM_END};
        size_t required = 0;

        if (EVP_PKEY_encrypt_init_ex(encrypt, invalid) > 0 ||
            EVP_PKEY_encrypt(encrypt, NULL, &required, input, 16) > 0)
            goto end;
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
