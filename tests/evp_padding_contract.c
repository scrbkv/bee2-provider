#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 16
#define MESSAGE_MAX 80

static int crypt(EVP_CIPHER *cipher, int encrypt, int padding, int split,
                 const unsigned char *key, const unsigned char *iv,
                 const unsigned char *input, size_t inlen,
                 unsigned char *output, size_t *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    size_t offset = 0, used = 0;
    int len = 0, ok = 0;

    if (!ctx)
        return 0;
    if (EVP_CipherInit_ex2(ctx, cipher, key, iv, encrypt, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, padding) != 1)
        goto done;
    while (offset != inlen) {
        size_t part = split ? 1 + ((offset * 7 + 3) % 19) : inlen - offset;

        if (part > inlen - offset)
            part = inlen - offset;
        if (EVP_CipherUpdate(ctx, output + used, &len, input + offset, (int)part) != 1)
            goto done;
        offset += part;
        used += (size_t)len;
    }
    if (EVP_CipherFinal_ex(ctx, output + used, &len) != 1)
        goto done;
    used += (size_t)len;
    *outlen = used;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int test_case(EVP_CIPHER *cipher, const unsigned char *key,
                     const unsigned char *iv, size_t msglen)
{
    unsigned char plain[MESSAGE_MAX] = {0};
    unsigned char whole[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    unsigned char split[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    unsigned char decoded[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    size_t len1 = 0, len2 = 0, len3 = 0, i;

    for (i = 0; i < msglen; i++)
        plain[i] = (unsigned char)(17 * i + 5);
    if (!crypt(cipher, 1, 1, 0, key, iv, plain, msglen, whole, &len1) ||
        len1 != (msglen / BLOCK_SIZE + 1) * BLOCK_SIZE ||
        !crypt(cipher, 1, 1, 1, key, iv, plain, msglen, split, &len2) ||
        len1 != len2 || CRYPTO_memcmp(whole, split, len1) != 0 ||
        !crypt(cipher, 0, 1, 1, key, iv, whole, len1, decoded, &len3) ||
        len3 != msglen || CRYPTO_memcmp(plain, decoded, msglen) != 0) {
        fprintf(stderr, "padded roundtrip failed at length %zu\n", msglen);
        return 0;
    }

    if (crypt(cipher, 0, 1, 0, key, iv, whole, len1 - 1, decoded, &len3)) {
        fprintf(stderr, "truncated ciphertext was accepted\n");
        return 0;
    }
    return 1;
}

static int test_invalid_padding(EVP_CIPHER *cipher, const unsigned char *key,
                                const unsigned char *iv)
{
    unsigned char plain[BLOCK_SIZE] = {0};
    unsigned char encrypted[2 * BLOCK_SIZE] = {0};
    unsigned char result[2 * BLOCK_SIZE] = {0};
    size_t ciphertext_len = 0, result_len = 0;

    /* Generate invalid trailing plaintext deliberately. Arbitrary ciphertext
     * corruption could accidentally produce valid padding. */
    if (!crypt(cipher, 1, 0, 0, key, iv, plain, sizeof(plain),
               encrypted, &ciphertext_len) ||
        crypt(cipher, 0, 1, 0, key, iv, encrypted, ciphertext_len,
              result, &result_len)) {
        fprintf(stderr, "zero-length PKCS#7 padding was accepted\n");
        return 0;
    }
    plain[BLOCK_SIZE - 2] = 3;
    plain[BLOCK_SIZE - 1] = 2;
    if (!crypt(cipher, 1, 0, 0, key, iv, plain, sizeof(plain),
               encrypted, &ciphertext_len) ||
        crypt(cipher, 0, 1, 0, key, iv, encrypted, ciphertext_len,
              result, &result_len)) {
        fprintf(stderr, "inconsistent PKCS#7 padding was accepted\n");
        return 0;
    }
    return 1;
}

static int test_no_padding(EVP_CIPHER *cipher, const unsigned char *key,
                           const unsigned char *iv)
{
    static const size_t lengths[] = {16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65};
    unsigned char input[MESSAGE_MAX] = {0};
    unsigned char whole[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    unsigned char split[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    unsigned char decoded[MESSAGE_MAX + 2 * BLOCK_SIZE] = {0};
    size_t clen = 0, slen = 0, plen = 0;
    size_t i;

    for (i = 0; i < sizeof(input); i++)
        input[i] = (unsigned char)(i * 13 + 19);
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t n = lengths[i];
        if (!crypt(cipher, 1, 0, 0, key, iv, input, n, whole, &clen) ||
            !crypt(cipher, 1, 0, 1, key, iv, input, n, split, &slen) ||
            clen != n || slen != n || CRYPTO_memcmp(whole, split, n) != 0 ||
            !crypt(cipher, 0, 0, 1, key, iv, whole, clen, decoded, &plen) ||
            plen != n || CRYPTO_memcmp(input, decoded, n) != 0) {
            fprintf(stderr, "unpadded ciphertext-stealing failure at length %zu\n", n);
            return 0;
        }
    }
    for (i = 0; i < BLOCK_SIZE; i++) {
        if (crypt(cipher, 1, 0, 1, key, iv, input, i, whole, &clen) ||
            crypt(cipher, 0, 0, 1, key, iv, input, i, decoded, &plen)) {
            fprintf(stderr, "short unpadded ECB/CBC input accepted at length %zu\n", i);
            return 0;
        }
    }
    return 1;
}

static int test_inplace(EVP_CIPHER *cipher, const unsigned char *key,
                        const unsigned char *iv)
{
    unsigned char plain[45];
    unsigned char expected[96] = {0};
    unsigned char output[96] = {0};
    unsigned char chunk[64] = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    size_t expected_len = 0, offset = 0;
    size_t used = 0, i;
    int len = 0, ok = 0;
    const size_t parts[] = {5, 27, 13};

    for (i = 0; i < sizeof(plain); i++)
        plain[i] = (unsigned char)(i * 9 + 1);
    if (!crypt(cipher, 1, 1, 0, key, iv, plain, sizeof(plain),
               expected, &expected_len))
        return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1)
        goto done;
    for (i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        memcpy(chunk, plain + offset, parts[i]);
        if (EVP_EncryptUpdate(ctx, chunk, &len, chunk, (int)parts[i]) != 1)
            goto done;
        memcpy(output + used, chunk, (size_t)len);
        used += (size_t)len;
        offset += parts[i];
    }
    if (EVP_EncryptFinal_ex(ctx, output + used, &len) != 1)
        goto done;
    used += (size_t)len;
    if (used != expected_len || CRYPTO_memcmp(output, expected, used) != 0)
        goto done;

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL) != 1)
        goto done;
    offset = used = 0;
    for (i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        size_t part = parts[i];

        if (i == 2)
            part = expected_len - offset;
        memcpy(chunk, expected + offset, part);
        if (EVP_DecryptUpdate(ctx, chunk, &len, chunk, (int)part) != 1)
            goto done;
        memcpy(output + used, chunk, (size_t)len);
        used += (size_t)len;
        offset += part;
    }
    if (EVP_DecryptFinal_ex(ctx, output + used, &len) != 1)
        goto done;
    used += (size_t)len;
    if (used != sizeof(plain) || CRYPTO_memcmp(output, plain, used) != 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "buffered in-place encryption failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    static const size_t lengths[] = {0, 1, 7, 15, 16, 17, 31, 32, 33, 47, 48, 63};
    unsigned char key[32] = {0};
    unsigned char iv[BLOCK_SIZE] = {0};
    EVP_CIPHER *cipher = NULL;
    OSSL_PROVIDER *provider = NULL;
    OSSL_PROVIDER *def = NULL;
    size_t keylen, i;
    int ok = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: %s module-dir cipher-name\n", argv[0]);
        return 2;
    }
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    cipher = EVP_CIPHER_fetch(NULL, argv[2], "provider=bee2");
    if (!def || !provider || !cipher || EVP_CIPHER_get_block_size(cipher) != BLOCK_SIZE)
        goto done;
    {
        const OSSL_PARAM *gettable = EVP_CIPHER_gettable_ctx_params(cipher);
        int is_cbc = strncmp(argv[2], "belt-cbc", 8) == 0;

        if (gettable == NULL ||
            (OSSL_PARAM_locate_const(gettable, OSSL_CIPHER_PARAM_UPDATED_IV) != NULL) != is_cbc ||
            OSSL_PARAM_locate_const(gettable, OSSL_CIPHER_PARAM_NUM) != NULL)
            goto done;
    }
    keylen = (size_t)EVP_CIPHER_get_key_length(cipher);
    if (keylen > sizeof(key))
        goto done;
    for (i = 0; i < keylen; i++)
        key[i] = (unsigned char)(i * 11 + 1);
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(i * 5 + 9);
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        if (!test_case(cipher, key, strncmp(argv[2], "belt-ecb", 8) == 0 ? NULL : iv,
                       lengths[i]))
            goto done;
    }
    if (!test_no_padding(cipher, key, strncmp(argv[2], "belt-ecb", 8) == 0 ? NULL : iv) ||
        !test_invalid_padding(cipher, key, strncmp(argv[2], "belt-ecb", 8) == 0 ? NULL : iv) ||
        !test_inplace(cipher, key, strncmp(argv[2], "belt-ecb", 8) == 0 ? NULL : iv))
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "EVP padding contract failed: %s\n", argv[2]);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
