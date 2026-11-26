/* BIGN must fetch digests and private randomness from its own library ctx. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <stdio.h>

static int check_standalone_pbkdf(OSSL_LIB_CTX *libctx)
{
    unsigned char derived[32], empty = 0;
    unsigned int iterations = 1;
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, &empty, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, &empty, 0),
        OSSL_PARAM_uint(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_END
    };
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, "belt-pbkdf", "provider=bee2");
    EVP_KDF_CTX *ctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
    int ok = ctx != NULL && EVP_KDF_CTX_get_kdf_size(ctx) == sizeof(derived) &&
             EVP_KDF_derive(ctx, derived, sizeof(derived), params) == 1;

    OPENSSL_cleanse(derived, sizeof(derived));
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return ok;
}

int main(int argc, char **argv) {
    static const unsigned char input[] = "library-context-isolation";
    unsigned char hash[32] = {0};
    unsigned char signature[128];
    size_t signature_len = sizeof(signature);
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *global_null = NULL, *def = NULL, *bee2 = NULL;
    EVP_PKEY_CTX *gen = NULL, *sign = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *digest_sign = NULL;
    int ok = 0;

    if (argc != 2)
        return 2;
    /* Disable automatic default-provider loading in the global context.
     * Any unqualified RAND_priv_bytes() / EVP_MD_fetch(NULL) now fails. */
    global_null = OSSL_PROVIDER_load(NULL, "null");
    libctx = OSSL_LIB_CTX_new();
    if (!global_null || !libctx ||
        !OSSL_PROVIDER_set_default_search_path(libctx, argv[1]))
        goto end;
    bee2 = OSSL_PROVIDER_load(libctx, "bee2_provider");
    if (!bee2 || !check_standalone_pbkdf(libctx))
        goto end;
    def = OSSL_PROVIDER_load(libctx, "default");
    if (!def)
        goto end;
    gen = EVP_PKEY_CTX_new_from_name(libctx, "bign-256", "provider=bee2");
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto end;

    sign = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=bee2");
    if (!sign || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_sign(sign, signature, &signature_len, hash, sizeof(hash)) <= 0)
        goto end;

    digest_sign = EVP_MD_CTX_new();
    if (!digest_sign ||
        EVP_DigestSignInit_ex(digest_sign, NULL, "belt-hash", libctx,
                              "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestSignUpdate(digest_sign, input, sizeof(input)) <= 0 ||
        EVP_DigestSignFinal(digest_sign, NULL, &signature_len) <= 0 ||
        signature_len > sizeof(signature) ||
        EVP_DigestSignFinal(digest_sign, signature, &signature_len) <= 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "provider escaped its OSSL_LIB_CTX\n");
    EVP_MD_CTX_free(digest_sign);
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(gen);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    OSSL_LIB_CTX_free(libctx);
    OSSL_PROVIDER_unload(global_null);
    return ok ? 0 : 1;
}
