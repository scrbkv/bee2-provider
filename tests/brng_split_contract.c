/* BRNG-CTR must preserve the same byte stream across EVP calls. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int check_split(const char *algorithm)
{
    static const size_t chunks[] = {1, 1, 15, 1, 13, 1, 32, 33};
    unsigned char key[32], iv[32], whole[97], split[97];
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *left = NULL, *right = NULL;
    size_t i, offset = 0;
    int ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
        OSSL_PARAM_octet_string("iv", iv, sizeof(iv)),
        OSSL_PARAM_END
    };

    for (i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)(i * 19u + 7u);
        iv[i] = (unsigned char)(i * 13u + 3u);
    }
    rand = EVP_RAND_fetch(NULL, algorithm, "provider=bee2");
    if (!rand || !(left = EVP_RAND_CTX_new(rand, NULL)) ||
        !(right = EVP_RAND_CTX_new(rand, NULL)) ||
        !EVP_RAND_CTX_set_params(left, params) ||
        !EVP_RAND_CTX_set_params(right, params) ||
        !EVP_RAND_instantiate(left, 256, 0, NULL, 0, NULL) ||
        !EVP_RAND_instantiate(right, 256, 0, NULL, 0, NULL) ||
        !EVP_RAND_generate(left, whole, sizeof(whole), 256, 0, NULL, 0))
        goto end;
    for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
        if (!EVP_RAND_generate(right, split + offset, chunks[i], 256, 0, NULL, 0))
            goto end;
        offset += chunks[i];
    }
    if (offset != sizeof(whole) ||
        CRYPTO_memcmp(whole, split, sizeof(whole)) != 0)
        goto end;

    /* Both contexts must continue at the same position after the boundary. */
    if (!EVP_RAND_generate(left, whole, sizeof(whole), 256, 0, NULL, 0) ||
        !EVP_RAND_generate(right, split, sizeof(split), 256, 0, NULL, 0) ||
        CRYPTO_memcmp(whole, split, sizeof(whole)) != 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "%s: split generation differs from a single request\n", algorithm);
    EVP_RAND_CTX_free(right);
    EVP_RAND_CTX_free(left);
    EVP_RAND_free(rand);
    OPENSSL_cleanse(whole, sizeof(whole));
    OPENSSL_cleanse(split, sizeof(split));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    ok = def && bee2 && check_split("brng-ctr-hbelt");
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
