/* Invalid public points must not pass the provider's EVP validation. */
#include <openssl/core_dispatch.h>
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

static int test_generated_key(const char *alg, const char *curve_name,
                              const char *curve_oid)
{
    const char *groups[] = {alg, curve_name, curve_oid};
    EVP_PKEY_CTX *genctx = NULL, *checkctx = NULL, *impctx = NULL;
    EVP_PKEY *key = NULL, *imported = NULL;
    unsigned char pub[128], priv[64], recovered[128], unexpected[64];
    size_t pub_len = 0, priv_len = 0, recovered_len = 0;
    size_t i;
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
    EVP_PKEY_CTX_free(checkctx);
    checkctx = NULL;

    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof(pub), &pub_len) != 1 ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv, sizeof(priv), &priv_len) != 1)
        goto end;

    impctx = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=bee2");
    if (impctx == NULL || EVP_PKEY_fromdata_init(impctx) != 1)
        goto end;
    for (i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                              (char *)groups[i], 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                               pub, pub_len),
            /* A public-only import must not retain this private component. */
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                               priv, priv_len),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY_free(imported);
        imported = NULL;
        if (EVP_PKEY_fromdata(impctx, &imported, EVP_PKEY_PUBLIC_KEY, params) != 1 ||
            EVP_PKEY_get_octet_string_param(imported, OSSL_PKEY_PARAM_PRIV_KEY,
                                            unexpected, sizeof(unexpected),
                                            &recovered_len) > 0 ||
            EVP_PKEY_get_octet_string_param(imported, OSSL_PKEY_PARAM_PUB_KEY,
                                            recovered, sizeof(recovered),
                                            &recovered_len) != 1 ||
            recovered_len != pub_len ||
            CRYPTO_memcmp(recovered, pub, pub_len) != 0)
            goto end;

        checkctx = EVP_PKEY_CTX_new_from_pkey(NULL, imported, "provider=bee2");
        if (checkctx == NULL || EVP_PKEY_public_check(checkctx) != 1)
            goto end;
        EVP_PKEY_CTX_free(checkctx);
        checkctx = NULL;
    }
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "%s: key import, group alias or selection failed\n", alg);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(unexpected, sizeof(unexpected));
    EVP_PKEY_CTX_free(checkctx);
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_CTX_free(impctx);
    EVP_PKEY_free(imported);
    EVP_PKEY_free(key);
    return ok;
}

/* Encoder imports must honor PRIVATE_KEY selection even when a caller
 * supplies an unrelated malformed public component. */
static int test_encoder_private_selection(OSSL_PROVIDER *provider)
{
    const OSSL_ALGORITHM *algs, *alg;
    const OSSL_DISPATCH *d;
    OSSL_FUNC_encoder_newctx_fn *newctx = NULL;
    OSSL_FUNC_encoder_freectx_fn *freectx = NULL;
    OSSL_FUNC_encoder_import_object_fn *import_object = NULL;
    OSSL_FUNC_encoder_free_object_fn *free_object = NULL;
    unsigned char priv[32] = {1}, invalid_pub[64] = {0};
    char group[] = "bign-curve256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, sizeof(priv)),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, invalid_pub,
                                           sizeof(invalid_pub)),
        OSSL_PARAM_construct_end()
    };
    void *ctx = NULL, *obj = NULL;
    int no_cache = 0, ok = 0;

    algs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_ENCODER, &no_cache);
    if (!algs)
        return 0;
    for (alg = algs; alg->algorithm_names != NULL; ++alg) {
        if (strstr(alg->algorithm_names, "bign-256") != NULL &&
            alg->property_definition != NULL &&
            strstr(alg->property_definition, "output=der,structure=PrivateKeyInfo"))
            break;
    }
    if (alg->algorithm_names == NULL)
        goto cleanup;
    for (d = alg->implementation; d && d->function_id != 0; ++d) {
        switch (d->function_id) {
        case OSSL_FUNC_ENCODER_NEWCTX:
            newctx = OSSL_FUNC_encoder_newctx(d);
            break;
        case OSSL_FUNC_ENCODER_FREECTX:
            freectx = OSSL_FUNC_encoder_freectx(d);
            break;
        case OSSL_FUNC_ENCODER_IMPORT_OBJECT:
            import_object = OSSL_FUNC_encoder_import_object(d);
            break;
        case OSSL_FUNC_ENCODER_FREE_OBJECT:
            free_object = OSSL_FUNC_encoder_free_object(d);
            break;
        }
    }
    if (!newctx || !freectx || !import_object || !free_object)
        goto cleanup;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider));
    if (!ctx)
        goto cleanup;
    obj = import_object(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params);
    ok = obj != NULL;

cleanup:
    if (obj && free_object)
        free_object(obj);
    if (ctx && freectx)
        freectx(ctx);
    OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_ENCODER, algs);
    OPENSSL_cleanse(priv, sizeof(priv));
    if (!ok)
        fprintf(stderr, "BIGN encoder ignored selection or rejected private key\n");
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
    if (!test_encoder_private_selection(bee2prov))
        ok = 0;
    if (!test_invalid_public_key("bign-256", 32) ||
        !test_generated_key("bign-256", "bign-curve256v1",
                            "1.2.112.0.2.0.34.101.45.3.1"))
        ok = 0;
    if (!test_invalid_public_key("bign-384", 48) ||
        !test_generated_key("bign-384", "bign-curve384v1",
                            "1.2.112.0.2.0.34.101.45.3.2"))
        ok = 0;
    if (!test_invalid_public_key("bign-512", 64) ||
        !test_generated_key("bign-512", "bign-curve512v1",
                            "1.2.112.0.2.0.34.101.45.3.3"))
        ok = 0;

 end:
    OSSL_PROVIDER_unload(bee2prov);
    OSSL_PROVIDER_unload(defprov);
    return ok ? 0 : 1;
}
