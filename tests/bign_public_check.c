/* Invalid public points must not pass the provider's EVP validation. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static int test_invalid_public_key(const char *alg, size_t keylen)
{
    EVP_PKEY_CTX *ctx = NULL, *checkctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char pub[128] = {0};
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                          (char *)alg, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                           pub, 2 * keylen),
        OSSL_PARAM_construct_end()
    };
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=bee2");
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1)
        goto end;
    if (!EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params)) {
        /* Rejecting an invalid point on import is also acceptable. */
        ok = 1;
        goto end;
    }
    checkctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (checkctx == NULL)
        goto end;
    if (EVP_PKEY_public_check(checkctx) == 0 &&
        EVP_PKEY_public_check_quick(checkctx) == 0)
        ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "%s: invalid all-zero public point accepted\n", alg);
    EVP_PKEY_CTX_free(checkctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int test_generated_key(const char *alg)
{
    EVP_PKEY_CTX *genctx = NULL, *checkctx = NULL, *impctx = NULL;
    EVP_PKEY *key = NULL, *imported = NULL;
    unsigned char pub[128];
    size_t pub_len = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)alg, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub)),
        OSSL_PARAM_construct_end()
    };
    int ok = 0;

    genctx = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=bee2");
    if (genctx == NULL || EVP_PKEY_keygen_init(genctx) != 1 ||
        EVP_PKEY_generate(genctx, &key) != 1)
        goto end;
    checkctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (checkctx == NULL || EVP_PKEY_public_check(checkctx) != 1 ||
        EVP_PKEY_public_check_quick(checkctx) != 1 ||
        EVP_PKEY_pairwise_check(checkctx) != 1)
        goto end;

    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof(pub), &pub_len) != 1)
        goto end;
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   pub, pub_len);
    impctx = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=bee2");
    if (impctx == NULL || EVP_PKEY_fromdata_init(impctx) != 1 ||
        EVP_PKEY_fromdata(impctx, &imported, EVP_PKEY_PUBLIC_KEY, params) != 1)
        goto end;
    EVP_PKEY_CTX_free(checkctx);
    checkctx = EVP_PKEY_CTX_new_from_pkey(NULL, imported, "provider=bee2");
    if (checkctx == NULL || EVP_PKEY_public_check(checkctx) != 1)
        goto end;
    ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "%s: generated key did not pass validation\n", alg);
    EVP_PKEY_CTX_free(checkctx);
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_CTX_free(impctx);
    EVP_PKEY_free(imported);
    EVP_PKEY_free(key);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *defprov = NULL, *bee2prov = NULL;
    int ok = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <provider-module-directory>\n", argv[0]);
        return 2;
    }
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    defprov = OSSL_PROVIDER_load(NULL, "default");
    bee2prov = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (defprov == NULL || bee2prov == NULL) {
        ok = 0;
        goto end;
    }
    if (!test_invalid_public_key("bign-256", 32) ||
        !test_generated_key("bign-256"))
        ok = 0;
    if (!test_invalid_public_key("bign-384", 48) ||
        !test_generated_key("bign-384"))
        ok = 0;
    if (!test_invalid_public_key("bign-512", 64) ||
        !test_generated_key("bign-512"))
        ok = 0;

 end:
    OSSL_PROVIDER_unload(bee2prov);
    OSSL_PROVIDER_unload(defprov);
    return ok ? 0 : 1;
}
