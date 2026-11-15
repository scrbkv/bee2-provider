/* Independently construct HMAC over the three BASH digests. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t size;
    size_t block_size;
} digest_case_t;

static const digest_case_t digests[] = {
    {"bash256", 32, 160},
    {"bash384", 48, 144},
    {"bash512", 64, 128}
};

static void fill_bytes(unsigned char *buf, size_t length, unsigned char seed)
{
    size_t i;
    for (i = 0; i < length; ++i)
        buf[i] = (unsigned char)(seed + 29u * i + (i >> 3));
}

static int reference_hmac(const EVP_MD *md, size_t block_size,
                          const unsigned char *key, size_t key_len,
                          const unsigned char *data, size_t data_len,
                          unsigned char *result, unsigned int *result_len)
{
    unsigned char key_block[160] = {0}, inner[64] = {0}, pad[160];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int inner_len = 0;
    size_t i;
    int ok = 0;

    if (ctx == NULL || block_size > sizeof(key_block))
        goto end;
    if (key_len > block_size) {
        if (EVP_Digest(key, key_len, key_block, &inner_len, md, NULL) <= 0)
            goto end;
    } else if (key_len != 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < block_size; ++i)
        pad[i] = (unsigned char)(key_block[i] ^ 0x36u);
    if (EVP_DigestInit_ex2(ctx, md, NULL) <= 0 ||
        EVP_DigestUpdate(ctx, pad, block_size) <= 0 ||
        EVP_DigestUpdate(ctx, data, data_len) <= 0 ||
        EVP_DigestFinal_ex(ctx, inner, &inner_len) <= 0)
        goto end;

    for (i = 0; i < block_size; ++i)
        pad[i] = (unsigned char)(key_block[i] ^ 0x5cu);
    if (EVP_DigestInit_ex2(ctx, md, NULL) <= 0 ||
        EVP_DigestUpdate(ctx, pad, block_size) <= 0 ||
        EVP_DigestUpdate(ctx, inner, inner_len) <= 0 ||
        EVP_DigestFinal_ex(ctx, result, result_len) <= 0)
        goto end;
    ok = 1;
end:
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(key_block, sizeof(key_block));
    OPENSSL_cleanse(inner, sizeof(inner));
    OPENSSL_cleanse(pad, sizeof(pad));
    return ok;
}

static int test_digest(const digest_case_t *test)
{
    static const size_t message_lengths[] = {0, 1, 31, 32, 63, 64, 127, 128,
                                              143, 144, 159, 160, 161, 257};
    unsigned char key[257], data[257], expected[64], actual[64];
    EVP_MD *md = EVP_MD_fetch(NULL, test->name, "provider=bee2");
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    char digest_name[16];
    OSSL_PARAM params[2];
    size_t key_lengths[] = {1, test->size, test->block_size - 1,
                            test->block_size, test->block_size + 1, 257};
    size_t i, j, actual_len;
    unsigned int expected_len;
    int ok = 0;

    if (md == NULL || mac == NULL || ctx == NULL)
        goto end;
    OPENSSL_strlcpy(digest_name, test->name, sizeof(digest_name));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    for (i = 0; i < sizeof(key_lengths) / sizeof(key_lengths[0]); ++i) {
        fill_bytes(key, key_lengths[i], (unsigned char)(37u + i));
        for (j = 0; j < sizeof(message_lengths) / sizeof(message_lengths[0]); ++j) {
            fill_bytes(data, message_lengths[j], (unsigned char)(47u + j));
            if (!reference_hmac(md, test->block_size, key, key_lengths[i],
                                data, message_lengths[j], expected, &expected_len) ||
                EVP_MAC_init(ctx, key, key_lengths[i], params) <= 0 ||
                EVP_MAC_update(ctx, data, message_lengths[j]) <= 0 ||
                EVP_MAC_final(ctx, actual, &actual_len, sizeof(actual)) <= 0 ||
                actual_len != expected_len || actual_len != test->size ||
                CRYPTO_memcmp(actual, expected, actual_len) != 0) {
                fprintf(stderr, "%s HMAC: key=%zu data=%zu mismatch\n",
                        test->name, key_lengths[i], message_lengths[j]);
                goto end;
            }
        }
    }
    ok = 1;
end:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(data, sizeof(data));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    EVP_MD_free(md);
    return ok;
}

int main(int argc, char **argv)
{
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
    for (i = 0; i < sizeof(digests) / sizeof(digests[0]); ++i)
        if (!test_digest(&digests[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
