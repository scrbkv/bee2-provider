/* Exercise one-shot digest dispatch and the EVP interfaces. */
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t size;
    size_t rate;
} digest_variant_t;

static const digest_variant_t variants[] = {
    {"belt-hash", 32, 32},
    {"bash256", 32, 160},
    {"bash384", 48, 144},
    {"bash512", 64, 128},
};

static int matches_name(const char *names, const char *name)
{
    size_t length = strlen(name);

    while (*names != '\0') {
        const char *end = strchr(names, ':');
        size_t part_length = end != NULL ? (size_t)(end - names) : strlen(names);

        if (part_length == length && OPENSSL_strncasecmp(names, name, length) == 0)
            return 1;
        if (end == NULL)
            break;
        names = end + 1;
    }
    return 0;
}

static OSSL_FUNC_digest_digest_fn *find_oneshot(const OSSL_ALGORITHM *algs,
                                                const char *name)
{
    const OSSL_ALGORITHM *alg;
    const OSSL_DISPATCH *dispatch;

    for (alg = algs; alg != NULL && alg->algorithm_names != NULL; ++alg) {
        if (!matches_name(alg->algorithm_names, name))
            continue;
        for (dispatch = alg->implementation; dispatch->function_id != 0; ++dispatch) {
            if (dispatch->function_id == OSSL_FUNC_DIGEST_DIGEST)
                return OSSL_FUNC_digest_digest(dispatch);
        }
        break;
    }
    return NULL;
}

static int test_variant(OSSL_PROVIDER *provider, const OSSL_ALGORITHM *algs,
                        const digest_variant_t *variant)
{
    unsigned char data[4096];
    unsigned char direct[64], quick[64], streamed[64];
    size_t lengths[] = {0, 1, variant->rate - 1, variant->rate,
                        variant->rate + 1, 2 * variant->rate + 5, sizeof(data)};
    OSSL_FUNC_digest_digest_fn *oneshot = find_oneshot(algs, variant->name);
    EVP_MD *md = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t i, direct_len, quick_len;
    unsigned int streamed_len;
    int ok = 0;

    md = EVP_MD_fetch(NULL, variant->name, "provider=bee2");
    ctx = EVP_MD_CTX_new();
    if (oneshot == NULL || md == NULL || ctx == NULL)
        goto end;

    for (i = 0; i < sizeof(data); ++i)
        data[i] = (unsigned char)(i * 37u + 11u);

    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t length = lengths[i];
        size_t split = length / 3;

        direct_len = quick_len = 0;
        streamed_len = 0;
        if (!oneshot(OSSL_PROVIDER_get0_provider_ctx(provider), data, length,
                     direct, &direct_len, sizeof(direct)) ||
            !EVP_Q_digest(NULL, variant->name, "provider=bee2", data, length,
                          quick, &quick_len) ||
            !EVP_DigestInit_ex2(ctx, md, NULL) ||
            !EVP_DigestUpdate(ctx, data, split) ||
            !EVP_DigestUpdate(ctx, data + split, length - split) ||
            !EVP_DigestFinal_ex(ctx, streamed, &streamed_len) ||
            direct_len != variant->size || quick_len != variant->size ||
            streamed_len != variant->size ||
            CRYPTO_memcmp(direct, quick, variant->size) != 0 ||
            CRYPTO_memcmp(direct, streamed, variant->size) != 0)
            goto end;
    }

    if (!EVP_DigestInit_ex2(ctx, md, NULL) ||
        EVP_DigestUpdate(ctx, NULL, 1) > 0 ||
        !EVP_DigestUpdate(ctx, data, 1) ||
        EVP_DigestFinal_ex(ctx, NULL, &streamed_len) > 0 ||
        !EVP_DigestFinal_ex(ctx, streamed, &streamed_len) ||
        streamed_len != variant->size)
        goto end;

    direct_len = 0;
    if (oneshot(OSSL_PROVIDER_get0_provider_ctx(provider), data, 1,
                direct, &direct_len, variant->size - 1) ||
        oneshot(OSSL_PROVIDER_get0_provider_ctx(provider), data, 1,
                direct, NULL, sizeof(direct)) ||
        oneshot(OSSL_PROVIDER_get0_provider_ctx(provider), data, 1,
                NULL, &direct_len, sizeof(direct)) ||
        oneshot(OSSL_PROVIDER_get0_provider_ctx(provider), NULL, 1,
                direct, &direct_len, sizeof(direct)))
        goto end;
    ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "%s one-shot digest regression failed\n", variant->name);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    OPENSSL_cleanse(direct, sizeof(direct));
    OPENSSL_cleanse(quick, sizeof(quick));
    OPENSSL_cleanse(streamed, sizeof(streamed));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    const OSSL_ALGORITHM *algs = NULL;
    size_t i;
    int ok = 0;
    int no_cache = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        goto end;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    algs = OSSL_PROVIDER_query_operation(bee2, OSSL_OP_DIGEST, &no_cache);
    if (algs == NULL)
        goto end;
    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        if (!test_variant(bee2, algs, &variants[i]))
            goto end;
    }
    ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "digest one-shot regression failed\n");
    if (algs != NULL)
        OSSL_PROVIDER_unquery_operation(bee2, OSSL_OP_DIGEST, algs);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
