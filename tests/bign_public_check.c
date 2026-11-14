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
    if (ctx == NULL || !EVP_PKEY_fromdata_init(ctx))
        goto end;
    if (!EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params)) {
        /* Rejecting an invalid point on import is also acceptable. */
        ok = 1;
        goto end;
    }
    checkctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (checkctx == NULL)
        goto end;
    if (EVP_PKEY_public_check(checkctx) == 0)
        ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "%s: invalid all-zero public point accepted\n", alg);
    EVP_PKEY_CTX_free(checkctx);
    EVP_PKEY_CTX_free(ctx);
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
    if (!test_invalid_public_key("bign-256", 32))
        ok = 0;
    if (!test_invalid_public_key("bign-384", 48))
        ok = 0;
    if (!test_invalid_public_key("bign-512", 64))
        ok = 0;

 end:
    OSSL_PROVIDER_unload(bee2prov);
    OSSL_PROVIDER_unload(defprov);
    return ok ? 0 : 1;
}
