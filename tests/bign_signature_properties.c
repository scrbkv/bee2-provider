/* The BIGN signature context must preserve its digest and message across
 * property changes and rejected mid-stream parameter updates. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif

static int check_variant(const char *name, const char *digest)
{
    static const unsigned char message[] = "BIGN digest properties test";
    EVP_PKEY_CTX *keygen = NULL, *sign_ctx = NULL, *reference_ctx = NULL;
    EVP_MD_CTX *sign = NULL, *reference = NULL, *verify = NULL;
    EVP_PKEY *key = NULL;
    unsigned char actual[96], expected[96];
    size_t actual_len = sizeof(actual), expected_len = sizeof(expected);
    unsigned int deterministic = 1;
    char properties[] = "provider=bee2";
    OSSL_PARAM det_params[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };
    OSSL_PARAM props[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, properties, 0),
        OSSL_PARAM_END
    };
    int ok = 0;

    keygen = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    sign = EVP_MD_CTX_new();
    reference = EVP_MD_CTX_new();
    verify = EVP_MD_CTX_new();
    if (keygen == NULL || sign == NULL || reference == NULL || verify == NULL ||
        EVP_PKEY_keygen_init(keygen) <= 0 || EVP_PKEY_keygen(keygen, &key) <= 0)
        goto end;
    if (EVP_DigestSignInit_ex(reference, &reference_ctx, digest, NULL,
                              "provider=bee2", key, NULL) <= 0 ||
        EVP_PKEY_CTX_set_params(reference_ctx, det_params) <= 0 ||
        EVP_DigestSignUpdate(reference, message, sizeof(message)) <= 0 ||
        EVP_DigestSignFinal(reference, expected, &expected_len) <= 0)
        goto end;

    if (EVP_DigestSignInit_ex(sign, &sign_ctx, digest, NULL,
                              "provider=bee2", key, NULL) <= 0 ||
        EVP_PKEY_CTX_set_params(sign_ctx, props) <= 0 ||
        EVP_PKEY_CTX_set_params(sign_ctx, det_params) <= 0 ||
        EVP_DigestSignUpdate(sign, NULL, 0) <= 0 ||
        EVP_DigestSignUpdate(sign, message, sizeof(message)) <= 0 ||
        EVP_PKEY_CTX_set_params(sign_ctx, props) > 0 ||
        EVP_DigestSignFinal(sign, actual, &actual_len) <= 0 ||
        actual_len != expected_len ||
        CRYPTO_memcmp(actual, expected, actual_len) != 0)
        goto end;

    if (EVP_DigestVerifyInit_ex(verify, NULL, digest, NULL,
                                "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestVerifyUpdate(verify, message, sizeof(message)) <= 0 ||
        EVP_DigestVerifyFinal(verify, actual, actual_len) <= 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "%s: BIGN digest property/state contract failed\n", name);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(reference);
    EVP_MD_CTX_free(sign);
    EVP_PKEY_CTX_free(keygen);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL, *bee2_provider = NULL;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    bee2_provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (default_provider && bee2_provider &&
        check_variant("bign-256", "belt-hash") &&
        check_variant("bign-384", "bash384") &&
        check_variant("bign-512", "bash512"))
        ok = 1;
    OSSL_PROVIDER_unload(bee2_provider);
    OSSL_PROVIDER_unload(default_provider);
    return ok ? 0 : 1;
}
