/* Exercise the provider's one-shot cipher dispatch and duplicated state
 * against the public EVP streaming path for every advertised cipher.
 */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    OSSL_FUNC_cipher_newctx_fn *newctx;
    OSSL_FUNC_cipher_freectx_fn *freectx;
    OSSL_FUNC_cipher_dupctx_fn *dupctx;
    OSSL_FUNC_cipher_encrypt_init_fn *init;
    OSSL_FUNC_cipher_cipher_fn *cipher;
    OSSL_FUNC_cipher_get_ctx_params_fn *getparams;
} methods_t;

static int inspect(const OSSL_ALGORITHM *alg, OSSL_PROVIDER *provider)
{
    methods_t m = {0};
    const OSSL_DISPATCH *fn;
    unsigned char key[32], iv[32], data[64], got[128], other[128], reference[128];
    unsigned char tag[32], reference_tag[32];
    size_t keylen, ivlen, taglen, gotlen = 0, otherlen = 0;
    size_t i;
    void *ctx = NULL, *clone = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *evp = NULL;
    int len = 0, final_len = 0, ok = 0;
    int is_aead, is_padded;
    unsigned int no_padding = 0;
    OSSL_PARAM padding_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &no_padding),
        OSSL_PARAM_END
    };
    char name[80];
    const char *end = strchr(alg->algorithm_names, ':');
    size_t name_len = end ? (size_t)(end - alg->algorithm_names) :
                           strlen(alg->algorithm_names);

    if (name_len >= sizeof(name))
        return 0;
    memcpy(name, alg->algorithm_names, name_len);
    name[name_len] = '\0';
    keylen = strstr(name, "128") ? 16 : (strstr(name, "192") ? 24 : 32);
    ivlen = strstr(name, "ecb") ? 0 : (strstr(name, "bash-prg-ae") ? keylen : 16);
    is_padded = strstr(name, "belt-ecb") != NULL ||
                strstr(name, "belt-cbc") != NULL;
    is_aead = strstr(name, "bash-prg-ae") != NULL ||
              strstr(name, "belt-che") != NULL ||
              strstr(name, "belt-dwp") != NULL;
    taglen = !is_aead ? 0 : (strstr(name, "bash-prg-ae") ? keylen : 8);
    for (i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)(i * 3 + 2);
        iv[i] = (unsigned char)(i * 7 + 11);
    }
    for (i = 0; i < sizeof(data); ++i)
        data[i] = (unsigned char)(i * 13 + 19);

    for (fn = alg->implementation; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_CIPHER_NEWCTX: m.newctx = OSSL_FUNC_cipher_newctx(fn); break;
        case OSSL_FUNC_CIPHER_FREECTX: m.freectx = OSSL_FUNC_cipher_freectx(fn); break;
        case OSSL_FUNC_CIPHER_DUPCTX: m.dupctx = OSSL_FUNC_cipher_dupctx(fn); break;
        case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
            m.init = OSSL_FUNC_cipher_encrypt_init(fn); break;
        case OSSL_FUNC_CIPHER_CIPHER: m.cipher = OSSL_FUNC_cipher_cipher(fn); break;
        case OSSL_FUNC_CIPHER_GET_CTX_PARAMS:
            m.getparams = OSSL_FUNC_cipher_get_ctx_params(fn); break;
        }
    }

    if (!m.newctx || !m.freectx || !m.dupctx || !m.init || !m.cipher ||
        (taglen && !m.getparams))
        goto done;
    ctx = m.newctx(OSSL_PROVIDER_get0_provider_ctx(provider));
    if (!ctx || !m.init(ctx, key, keylen, ivlen ? iv : NULL, ivlen,
                        is_padded ? padding_params : NULL))
        goto done;
    clone = m.dupctx(ctx);
    if (!clone ||
        !m.cipher(ctx, got, &gotlen, sizeof(got), data, sizeof(data)) ||
        !m.cipher(clone, other, &otherlen, sizeof(other), data, sizeof(data)) ||
        gotlen != otherlen || CRYPTO_memcmp(got, other, gotlen) != 0)
        goto done;

    cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    evp = EVP_CIPHER_CTX_new();
    if (!cipher || !evp ||
        EVP_EncryptInit_ex2(evp, cipher, key, ivlen ? iv : NULL, NULL) <= 0 ||
        (!is_aead && EVP_CIPHER_CTX_set_padding(evp, 0) <= 0) ||
        EVP_EncryptUpdate(evp, reference, &len, data, sizeof(data)) <= 0 ||
        EVP_EncryptFinal_ex(evp, reference + len, &final_len) <= 0 ||
        (size_t)(len + final_len) != gotlen ||
        CRYPTO_memcmp(got, reference, gotlen) != 0)
        goto done;

    if (taglen != 0) {
        OSSL_PARAM get_direct[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, taglen),
            OSSL_PARAM_END
        };
        OSSL_PARAM get_evp[] = {
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, reference_tag, taglen),
            OSSL_PARAM_END
        };
        if (!m.getparams(ctx, get_direct) ||
            !m.getparams(clone, get_direct) ||
            EVP_CIPHER_CTX_get_params(evp, get_evp) <= 0 ||
            CRYPTO_memcmp(tag, reference_tag, taglen) != 0)
            goto done;
    }
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "One-shot/duplicated cipher contract failed: %s\n", name);
    EVP_CIPHER_CTX_free(evp);
    EVP_CIPHER_free(cipher);
    if (clone && m.freectx) m.freectx(clone);
    if (ctx && m.freectx) m.freectx(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(data, sizeof(data));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    const OSSL_ALGORITHM *algs = NULL, *alg;
    int ok = 0, no_cache = 0;
    if (argc != 2) return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1])) return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!def || !bee2) goto done;
    algs = OSSL_PROVIDER_query_operation(bee2, OSSL_OP_CIPHER, &no_cache);
    if (!algs) goto done;
    for (alg = algs; alg->algorithm_names != NULL; ++alg)
        if (!inspect(alg, bee2))
            goto done;
    ok = 1;
done:
    if (algs)
        OSSL_PROVIDER_unquery_operation(bee2, OSSL_OP_CIPHER, algs);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
