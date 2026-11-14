/* Regression checks for malformed provider input and invalid operation order. */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static const OSSL_ALGORITHM *find_cipher(const OSSL_ALGORITHM *algs,
                                          const char *name)
{
    const OSSL_ALGORITHM *alg;
    size_t len = strlen(name);

    for (alg = algs; alg != NULL && alg->algorithm_names != NULL; ++alg) {
        const char *s = alg->algorithm_names;
        while (s != NULL && *s != '\0') {
            const char *end = strchr(s, ':');
            size_t n = end != NULL ? (size_t)(end - s) : strlen(s);
            if (n == len && OPENSSL_strncasecmp(s, name, len) == 0)
                return alg;
            s = end != NULL ? end + 1 : NULL;
        }
    }
    return NULL;
}

static int check_cipher(OSSL_PROVIDER *provider, const OSSL_ALGORITHM *algs,
                        const char *name, size_t keylen, size_t ivlen,
                        int requires_aligned_key)
{
    const OSSL_ALGORITHM *alg = find_cipher(algs, name);
    const OSSL_DISPATCH *d;
    OSSL_FUNC_cipher_newctx_fn *newctx = NULL;
    OSSL_FUNC_cipher_freectx_fn *freectx = NULL;
    OSSL_FUNC_cipher_encrypt_init_fn *encrypt_init = NULL;
    OSSL_FUNC_cipher_update_fn *update = NULL;
    OSSL_FUNC_cipher_final_fn *final = NULL;
    unsigned char key[60] = {0}, iv[60] = {0}, output[16] = {0};
    size_t outlen = 0;
    void *ctx = NULL;
    int ok = 0;

    if (alg == NULL)
        goto end;
    for (d = alg->implementation; d->function_id != 0; ++d) {
        switch (d->function_id) {
        case OSSL_FUNC_CIPHER_NEWCTX:
            newctx = OSSL_FUNC_cipher_newctx(d); break;
        case OSSL_FUNC_CIPHER_FREECTX:
            freectx = OSSL_FUNC_cipher_freectx(d); break;
        case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
            encrypt_init = OSSL_FUNC_cipher_encrypt_init(d); break;
        case OSSL_FUNC_CIPHER_UPDATE:
            update = OSSL_FUNC_cipher_update(d); break;
        case OSSL_FUNC_CIPHER_FINAL:
            final = OSSL_FUNC_cipher_final(d); break;
        }
    }
    if (newctx == NULL || freectx == NULL || encrypt_init == NULL ||
        update == NULL || final == NULL)
        goto end;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider));
    if (ctx == NULL)
        goto end;
    if (requires_aligned_key) {
        if (encrypt_init(ctx, key, keylen + 1, iv, ivlen, NULL))
            goto end;
        if (encrypt_init(ctx, key, keylen, iv, ivlen + 1, NULL))
            goto end;
    }
    if (!encrypt_init(ctx, key, keylen, iv, ivlen, NULL) ||
        update(ctx, NULL, &outlen, 0, NULL, 1) ||
        !update(ctx, output, &outlen, sizeof(output), key, 1) ||
        outlen != 1 || !final(ctx, output, &outlen, sizeof(output)) ||
        final(ctx, output, &outlen, sizeof(output)) ||
        update(ctx, output, &outlen, sizeof(output), key, 1))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "invalid cipher input contract: %s\n", name);
    if (freectx != NULL && ctx != NULL)
        freectx(ctx);
    return ok;
}

static int check_mac(void)
{
    unsigned char key[32] = {0}, output[8];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-mac256", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    size_t outlen = 0;
    int ok = 0;

    if (ctx == NULL || EVP_MAC_update(ctx, key, 1) > 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) > 0 ||
        EVP_MAC_init(ctx, key, sizeof(key), NULL) <= 0 ||
        EVP_MAC_update(ctx, key, 1) <= 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) <= 0 ||
        outlen != sizeof(output) ||
        EVP_MAC_update(ctx, key, 1) > 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) > 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "invalid BELT MAC operation order accepted\n");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int check_bign_private_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    EVP_PKEY *pkey = NULL;
    unsigned char zero[32] = {0};
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, zero, sizeof(zero)),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0 &&
             EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) <= 0;
    if (!ok)
        fprintf(stderr, "zero BIGN private scalar was accepted\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    const OSSL_ALGORITHM *algs = NULL;
    int no_cache = 0, ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    algs = OSSL_PROVIDER_query_operation(bee2, OSSL_OP_CIPHER, &no_cache);
    if (algs == NULL ||
        !check_cipher(bee2, algs, "bash-prg-ae1281", 16, 16, 1) ||
        !check_cipher(bee2, algs, "bash-prg-ae1921", 24, 24, 1) ||
        !check_cipher(bee2, algs, "bash-prg-ae2561", 32, 32, 1) ||
        !check_cipher(bee2, algs, "belt-che256", 32, 16, 0) ||
        !check_cipher(bee2, algs, "belt-dwp256", 32, 16, 0) ||
        !check_mac() || !check_bign_private_key())
        goto end;
    ok = 1;
end:
    if (algs != NULL)
        OSSL_PROVIDER_unquery_operation(bee2, OSSL_OP_CIPHER, algs);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
