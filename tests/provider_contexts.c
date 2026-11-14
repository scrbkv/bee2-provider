/* Check that the provider can be loaded in independent library contexts. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#define DIGEST_SIZE 32

static int belt_digest(OSSL_LIB_CTX *libctx, unsigned char out[DIGEST_SIZE])
{
    static const unsigned char message[] = "bee2 provider context test";
    EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int outlen = 0;
    int ok = 0;

    md = EVP_MD_fetch(libctx, "belt-hash", "provider=bee2");
    mdctx = EVP_MD_CTX_new();
    if (md == NULL || mdctx == NULL)
        goto end;
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)
            || !EVP_DigestUpdate(mdctx, message, sizeof(message) - 1)
            || !EVP_DigestFinal_ex(mdctx, out, &outlen)
            || outlen != DIGEST_SIZE)
        goto end;
    ok = 1;

 end:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    return ok;
}

static int load_provider(OSSL_LIB_CTX *libctx, const char *module_dir,
                         OSSL_PROVIDER **defprov, OSSL_PROVIDER **bee2prov)
{
    if (!OSSL_PROVIDER_set_default_search_path(libctx, module_dir))
        return 0;
    *defprov = OSSL_PROVIDER_load(libctx, "default");
    *bee2prov = OSSL_PROVIDER_load(libctx, "bee2_provider");
    return *defprov != NULL && *bee2prov != NULL;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *a = NULL, *b = NULL;
    OSSL_PROVIDER *a_def = NULL, *b_def = NULL;
    OSSL_PROVIDER *a_bee2 = NULL, *b_bee2 = NULL;
    unsigned char a_digest[DIGEST_SIZE], b_digest[DIGEST_SIZE];
    int ok = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <provider-module-directory>\n", argv[0]);
        return 2;
    }
    a = OSSL_LIB_CTX_new();
    b = OSSL_LIB_CTX_new();
    if (a == NULL || b == NULL
            || !load_provider(a, argv[1], &a_def, &a_bee2)
            || !load_provider(b, argv[1], &b_def, &b_bee2)
            || !belt_digest(a, a_digest)
            || !belt_digest(b, b_digest)
            || CRYPTO_memcmp(a_digest, b_digest, DIGEST_SIZE) != 0)
        goto end;

    OSSL_PROVIDER_unload(a_bee2);
    a_bee2 = NULL;
    OSSL_PROVIDER_unload(a_def);
    a_def = NULL;
    OSSL_LIB_CTX_free(a);
    a = NULL;

    if (!belt_digest(b, b_digest)
            || CRYPTO_memcmp(a_digest, b_digest, DIGEST_SIZE) != 0)
        goto end;
    ok = 1;

 end:
    if (!ok)
        fprintf(stderr, "independent OSSL_LIB_CTX provider test failed\n");
    OSSL_PROVIDER_unload(a_bee2);
    OSSL_PROVIDER_unload(b_bee2);
    OSSL_PROVIDER_unload(a_def);
    OSSL_PROVIDER_unload(b_def);
    OSSL_LIB_CTX_free(a);
    OSSL_LIB_CTX_free(b);
    OPENSSL_cleanse(a_digest, sizeof(a_digest));
    OPENSSL_cleanse(b_digest, sizeof(b_digest));
    return ok ? 0 : 1;
}
