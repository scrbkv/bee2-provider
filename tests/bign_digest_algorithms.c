/* Verify advertised BIGN signature algorithm names select their digest. */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *algorithm;
    const char *digest;
    const char *wrong_digest;
} bign_signature_case_t;

static const bign_signature_case_t fixed_algorithms[] = {
    {"bign-with-hbelt", "belt-hash", "bash256"},
    {"bign-with-bash256", "bash256", "belt-hash"},
    {"bign-with-bash384", "bash384", "bash256"},
    {"bign-with-bash512", "bash512", "bash384"}
};

static int contains_name(const char *aliases, const char *name)
{
    const char *p = aliases;
    size_t len = strlen(name);
    while (*p != '\0') {
        const char *q = strchr(p, ':');
        size_t part_len = q == NULL ? strlen(p) : (size_t)(q - p);
        if (part_len == len && OPENSSL_strncasecmp(p, name, len) == 0)
            return 1;
        if (q == NULL)
            break;
        p = q + 1;
    }
    return 0;
}

static int check_named_signature(const OSSL_ALGORITHM *alg,
                                 OSSL_PROVIDER *provider,
                                 const bign_signature_case_t *test)
{
    OSSL_FUNC_signature_newctx_fn *newctx = NULL;
    OSSL_FUNC_signature_freectx_fn *freectx = NULL;
    OSSL_FUNC_signature_get_ctx_params_fn *get = NULL;
    OSSL_FUNC_signature_set_ctx_params_fn *set = NULL;
    const OSSL_DISPATCH *function;
    char reported[64] = {0};
    char wrong[64];
    char deterministic_mode[] = "deterministic";
    char invalid_mode[] = "randomized";
    unsigned int deterministic = 0;
    size_t digest_size = 0;
    OSSL_PARAM query_state[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &digest_size),
        OSSL_PARAM_END
    };
    OSSL_PARAM enable_mode[] = {
        OSSL_PARAM_utf8_string("sig", deterministic_mode, sizeof(deterministic_mode)),
        OSSL_PARAM_END
    };
    OSSL_PARAM reject_mode[] = {
        OSSL_PARAM_utf8_string("sig", invalid_mode, sizeof(invalid_mode)),
        OSSL_PARAM_END
    };
    char correct[64];
    OSSL_PARAM query[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, reported, sizeof(reported)),
        OSSL_PARAM_END
    };
    OSSL_PARAM value[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, wrong, sizeof(wrong)),
        OSSL_PARAM_END
    };
    void *ctx = NULL;
    int ok = 0;

    for (function = alg->implementation; function->function_id != 0; ++function) {
        switch (function->function_id) {
        case OSSL_FUNC_SIGNATURE_NEWCTX:
            newctx = OSSL_FUNC_signature_newctx(function);
            break;
        case OSSL_FUNC_SIGNATURE_FREECTX:
            freectx = OSSL_FUNC_signature_freectx(function);
            break;
        case OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS:
            get = OSSL_FUNC_signature_get_ctx_params(function);
            break;
        case OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS:
            set = OSSL_FUNC_signature_set_ctx_params(function);
            break;
        }
    }
    if (newctx == NULL || freectx == NULL || get == NULL || set == NULL)
        goto end;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), NULL);
    if (ctx == NULL || get(ctx, query) <= 0 ||
        OPENSSL_strcasecmp(reported, test->digest) != 0)
        goto end;
    OPENSSL_strlcpy(wrong, test->wrong_digest, sizeof(wrong));
    if (set(ctx, value) > 0)
        goto end;
    memset(reported, 0, sizeof(reported));
    if (get(ctx, query) <= 0 || OPENSSL_strcasecmp(reported, test->digest) != 0)
        goto end;
    OPENSSL_strlcpy(correct, test->digest, sizeof(correct));
    value[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, correct, 0);
    if (set(ctx, value) <= 0)
        goto end;
    memset(reported, 0, sizeof(reported));
    if (get(ctx, query) <= 0 || OPENSSL_strcasecmp(reported, test->digest) != 0 ||
        get(ctx, query_state) <= 0 || deterministic != 0 ||
        digest_size != (OPENSSL_strcasecmp(test->digest, "bash384") == 0 ? 48u :
                       OPENSSL_strcasecmp(test->digest, "bash512") == 0 ? 64u : 32u) ||
        set(ctx, reject_mode) > 0 ||
        get(ctx, query_state) <= 0 || deterministic != 0 ||
        set(ctx, enable_mode) <= 0 ||
        get(ctx, query_state) <= 0 || deterministic != 1)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "BIGN digest binding failed: %s\n", test->algorithm);
    if (ctx != NULL && freectx != NULL)
        freectx(ctx);
    return ok;
}

/* Explicit digest properties must be applied independently of the signature provider. */
static int check_digest_properties(OSSL_PROVIDER *provider, const OSSL_ALGORITHM *algs)
{
    const OSSL_ALGORITHM *alg;
    const OSSL_DISPATCH *fn;
    OSSL_FUNC_signature_newctx_fn *newctx = NULL;
    OSSL_FUNC_signature_freectx_fn *freectx = NULL;
    OSSL_FUNC_signature_set_ctx_params_fn *setctx = NULL;
    char digest[] = "belt-hash";
    char allowed[] = "provider=bee2", rejected[] = "provider=default";
    OSSL_PARAM negative[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, rejected, sizeof(rejected)),
        OSSL_PARAM_END};
    OSSL_PARAM positive[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, allowed, sizeof(allowed)),
        OSSL_PARAM_END};
    OSSL_PARAM implicit[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_END};
    void *ctx = NULL;
    int ok = 0;

    for (alg = algs; alg->algorithm_names != NULL; ++alg)
        if (contains_name(alg->algorithm_names, "bign-with-hbelt"))
            break;
    if (alg->algorithm_names == NULL)
        return 0;
    for (fn = alg->implementation; fn->function_id != 0; ++fn) {
        if (fn->function_id == OSSL_FUNC_SIGNATURE_NEWCTX)
            newctx = OSSL_FUNC_signature_newctx(fn);
        else if (fn->function_id == OSSL_FUNC_SIGNATURE_FREECTX)
            freectx = OSSL_FUNC_signature_freectx(fn);
        else if (fn->function_id == OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS)
            setctx = OSSL_FUNC_signature_set_ctx_params(fn);
    }
    if (!newctx || !freectx || !setctx)
        return 0;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), "provider=default");
    if (!ctx || setctx(ctx, implicit) > 0)
        goto cleanup;
    freectx(ctx);
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), "provider=bee2");
    if (!ctx || setctx(ctx, implicit) <= 0)
        goto cleanup;
    freectx(ctx);
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), "provider=bee2");
    if (!ctx || setctx(ctx, negative) > 0)
        goto cleanup;
    freectx(ctx);
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), "provider=bee2");
    if (ctx != NULL && setctx(ctx, positive) > 0)
        ok = 1;
cleanup:
    freectx(ctx);
    return ok;
}


/* This public EVP one-shot path is distinct from DigestSignUpdate/Final. */
static int check_oneshot_signature(const char *curve, const char *digest)
{
    unsigned char message[257], signature[128];
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sign = NULL, *verify = NULL;
    size_t siglen = sizeof(signature);
    size_t i;
    int ok = 0;

    for (i = 0; i < sizeof(message); ++i)
        message[i] = (unsigned char)(i * 37u + 9u);
    gen = EVP_PKEY_CTX_new_from_name(NULL, curve, "provider=bee2");
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto done;
    sign = EVP_MD_CTX_new();
    verify = EVP_MD_CTX_new();
    if (!sign || !verify ||
        EVP_DigestSignInit_ex(sign, NULL, digest, NULL, "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestSign(sign, signature, &siglen, message, sizeof(message)) <= 0 ||
        EVP_DigestVerifyInit_ex(verify, NULL, digest, NULL, "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestVerify(verify, signature, siglen, message, sizeof(message)) <= 0)
        goto done;
    message[0] ^= 0x80;
    if (EVP_DigestVerifyInit_ex(verify, NULL, digest, NULL, "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestVerify(verify, signature, siglen, message, sizeof(message)) > 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN one-shot signature failed: %s/%s\n", curve, digest);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(sign);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
    OPENSSL_cleanse(signature, sizeof(signature));
    return ok;
}

int main(int argc, char **argv)
{
    const OSSL_ALGORITHM *algs = NULL, *alg;
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int no_cache = 0, ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    algs = OSSL_PROVIDER_query_operation(bee2, OSSL_OP_SIGNATURE, &no_cache);
    if (algs == NULL)
        goto end;
    for (i = 0; i < sizeof(fixed_algorithms) / sizeof(fixed_algorithms[0]); ++i) {
        for (alg = algs; alg->algorithm_names != NULL; ++alg)
            if (contains_name(alg->algorithm_names, fixed_algorithms[i].algorithm))
                break;
        if (alg->algorithm_names == NULL ||
            !check_named_signature(alg, bee2, &fixed_algorithms[i]))
            goto end;
    }
    if (!check_digest_properties(bee2, algs) ||
        !check_oneshot_signature("bign-256", "belt-hash") ||
        !check_oneshot_signature("bign-256", "bash256") ||
        !check_oneshot_signature("bign-384", "bash384") ||
        !check_oneshot_signature("bign-512", "bash512"))
        goto end;
    ok = 1;
end:
    if (algs != NULL)
        OSSL_PROVIDER_unquery_operation(bee2, OSSL_OP_SIGNATURE, algs);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
