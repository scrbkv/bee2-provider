/* Private-only BIGN keys must validate, duplicate and derive public data. */
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int check_private_only(const char *alg, size_t priv_len)
{
    unsigned char priv[64] = {1}, public_a[128], public_b[128];
    size_t len_a = 0, len_b = 0;
    EVP_PKEY_CTX *ctx = NULL, *check = NULL, *copy_check = NULL;
    EVP_PKEY *key = NULL, *copy = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len),
        OSSL_PARAM_END
    };
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, "provider=bee2");
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PRIVATE_KEY, params) <= 0 ||
        !(check = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2")) ||
        EVP_PKEY_private_check(check) != 1 ||
        EVP_PKEY_public_check(check) == 1 ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        public_a, sizeof(public_a), &len_a) != 1 ||
        len_a != priv_len * 2)
        goto end;

    /* EVP_PKEY_dup asks the provider to copy KEYPAIR selection. The source
     * deliberately contains no cached public component. */
    copy = EVP_PKEY_dup(key);
    if (!copy || !(copy_check = EVP_PKEY_CTX_new_from_pkey(NULL, copy, "provider=bee2")) ||
        EVP_PKEY_public_check(copy_check) != 1)
        goto end;
    if (EVP_PKEY_get_octet_string_param(copy, OSSL_PKEY_PARAM_PUB_KEY,
                                        public_b, sizeof(public_b), &len_b) != 1 ||
        len_a != len_b || CRYPTO_memcmp(public_a, public_b, len_a) != 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "%s: BIGN private-only validation/duplication failed\n", alg);
    EVP_PKEY_CTX_free(copy_check);
    EVP_PKEY_CTX_free(check);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(copy);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(public_a, sizeof(public_a));
    OPENSSL_cleanse(public_b, sizeof(public_b));
    return ok;
}

/* Curve-specific encoders already know the key group. Requiring a second
 * group-name parameter here would duplicate the keymgmt import contract. */
static int check_encoder_import(OSSL_PROVIDER *provider, const char *name,
                                size_t priv_len)
{
    const OSSL_ALGORITHM *algs, *alg;
    const OSSL_DISPATCH *dispatch;
    OSSL_FUNC_encoder_newctx_fn *newctx = NULL;
    OSSL_FUNC_encoder_freectx_fn *freectx = NULL;
    OSSL_FUNC_encoder_import_object_fn *import_object = NULL;
    OSSL_FUNC_encoder_free_object_fn *free_object = NULL;
    unsigned char priv[64] = {1};
    char wrong_group[16], correct_group[16];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len),
        OSSL_PARAM_END
    };
    OSSL_PARAM with_group[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, correct_group, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len),
        OSSL_PARAM_END
    };
    void *ctx = NULL, *obj = NULL;
    int no_cache = 0, ok = 0;

    OPENSSL_strlcpy(correct_group, name, sizeof(correct_group));
    OPENSSL_strlcpy(wrong_group, strcmp(name, "bign-256") == 0 ? "bign-384" : "bign-256",
                    sizeof(wrong_group));
    algs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_ENCODER, &no_cache);
    if (algs == NULL)
        return 0;
    for (alg = algs; alg->algorithm_names != NULL; ++alg) {
        if (strstr(alg->algorithm_names, name) == NULL ||
            alg->property_definition == NULL ||
            strstr(alg->property_definition, "output=der,structure=PrivateKeyInfo") == NULL)
            continue;
        for (dispatch = alg->implementation;
             dispatch != NULL && dispatch->function_id != 0; ++dispatch) {
            switch (dispatch->function_id) {
            case OSSL_FUNC_ENCODER_NEWCTX:
                newctx = OSSL_FUNC_encoder_newctx(dispatch);
                break;
            case OSSL_FUNC_ENCODER_FREECTX:
                freectx = OSSL_FUNC_encoder_freectx(dispatch);
                break;
            case OSSL_FUNC_ENCODER_IMPORT_OBJECT:
                import_object = OSSL_FUNC_encoder_import_object(dispatch);
                break;
            case OSSL_FUNC_ENCODER_FREE_OBJECT:
                free_object = OSSL_FUNC_encoder_free_object(dispatch);
                break;
            }
        }
        break;
    }
    if (newctx != NULL && freectx != NULL && import_object != NULL &&
        free_object != NULL && alg->algorithm_names != NULL) {
        ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider));
        if (ctx != NULL)
            obj = import_object(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, params);
        if (obj != NULL) {
            free_object(obj);
            obj = NULL;
            ok = 1;
            with_group[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, wrong_group, 0);
            obj = import_object(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, with_group);
            if (obj != NULL)
                ok = 0;
            else {
                with_group[0] = OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME, correct_group, 0);
                obj = import_object(ctx, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, with_group);
                if (obj == NULL)
                    ok = 0;
            }
        }
    }
    if (obj != NULL && free_object != NULL)
        free_object(obj);
    if (ctx != NULL && freectx != NULL)
        freectx(ctx);
    OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_ENCODER, algs);
    OPENSSL_cleanse(priv, sizeof(priv));
    if (!ok)
        fprintf(stderr, "%s: encoder rejected private key without group-name\n", name);
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
    ok = def && bee2 && check_private_only("bign-256", 32) &&
         check_private_only("bign-384", 48) &&
         check_private_only("bign-512", 64) &&
         check_encoder_import(bee2, "bign-256", 32) &&
         check_encoder_import(bee2, "bign-384", 48) &&
         check_encoder_import(bee2, "bign-512", 64);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
