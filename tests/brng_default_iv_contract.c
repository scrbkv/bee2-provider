/* Verify documented implicit IV defaults and strict RAND parameter types. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

static int check_variant(const char *name, int is_hmac)
{
    EVP_RAND *algorithm = EVP_RAND_fetch(NULL, name, "provider=bee2");
    EVP_RAND_CTX *implicit = NULL, *explicit = NULL;
    unsigned char key[32] = {0}, iv[32] = {0};
    unsigned char got_iv[32] = {0xa5}, out1[64], out2[64];
    unsigned char garbage[1] = {0};
    OSSL_PARAM read_iv[] = {
        OSSL_PARAM_octet_string("iv", got_iv, sizeof(got_iv)), OSSL_PARAM_END
    };
    OSSL_PARAM key_only[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)), OSSL_PARAM_END
    };
    OSSL_PARAM key_and_iv[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
        OSSL_PARAM_octet_string("iv", iv, is_hmac ? 0 : sizeof(iv)),
        OSSL_PARAM_END
    };
    OSSL_PARAM incorrect_key_type[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_KEY, (char *)garbage, 1),
        OSSL_PARAM_END
    };
    OSSL_PARAM incorrect_iv_type[] = {
        OSSL_PARAM_utf8_string("iv", (char *)garbage, 1), OSSL_PARAM_END
    };
    OSSL_PARAM short_ctr_key[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, 16), OSSL_PARAM_END
    };
    OSSL_PARAM short_ctr_iv[] = {
        OSSL_PARAM_octet_string("iv", iv, 16), OSSL_PARAM_END
    };
    OSSL_PARAM empty_hmac_key[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, 0), OSSL_PARAM_END
    };
    OSSL_PARAM invalid_state[] = {
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_STATE, garbage, 1), OSSL_PARAM_END
    };
    OSSL_PARAM invalid_strength[] = {
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_STRENGTH, garbage, 1), OSSL_PARAM_END
    };
    OSSL_PARAM invalid_request[] = {
        OSSL_PARAM_octet_string(OSSL_RAND_PARAM_MAX_REQUEST, garbage, 1), OSSL_PARAM_END
    };
    int ok = 0;

    if (algorithm == NULL)
        goto done;
    implicit = EVP_RAND_CTX_new(algorithm, NULL);
    explicit = EVP_RAND_CTX_new(algorithm, NULL);
    if (implicit == NULL || explicit == NULL ||
        EVP_RAND_CTX_get_params(implicit, read_iv) <= 0 ||
        read_iv[0].return_size != (is_hmac ? 0u : sizeof(iv)) ||
        (!is_hmac && CRYPTO_memcmp(got_iv, iv, sizeof(iv)) != 0) ||
        EVP_RAND_get_params(algorithm, invalid_state) > 0 ||
        EVP_RAND_get_params(algorithm, invalid_strength) > 0 ||
        EVP_RAND_get_params(algorithm, invalid_request) > 0 ||
        EVP_RAND_CTX_get_params(implicit, invalid_state) > 0 ||
        EVP_RAND_CTX_get_params(implicit, invalid_strength) > 0 ||
        EVP_RAND_CTX_get_params(implicit, invalid_request) > 0 ||
        EVP_RAND_CTX_set_params(implicit, incorrect_key_type) > 0 ||
        EVP_RAND_CTX_set_params(implicit, incorrect_iv_type) > 0)
        goto done;
    if (is_hmac) {
        if (EVP_RAND_CTX_set_params(implicit, empty_hmac_key) > 0)
            goto done;
    } else if (EVP_RAND_CTX_set_params(implicit, short_ctr_key) > 0 ||
               EVP_RAND_CTX_set_params(implicit, short_ctr_iv) > 0)
        goto done;

    if (EVP_RAND_CTX_set_params(implicit, key_only) <= 0 ||
        EVP_RAND_CTX_set_params(explicit, key_and_iv) <= 0 ||
        EVP_RAND_instantiate(implicit, 256, 0, NULL, 0, NULL) <= 0 ||
        EVP_RAND_instantiate(explicit, 256, 0, NULL, 0, NULL) <= 0 ||
        EVP_RAND_generate(implicit, out1, sizeof(out1), 256, 0, NULL, 0) <= 0 ||
        EVP_RAND_generate(explicit, out2, sizeof(out2), 256, 0, NULL, 0) <= 0 ||
        CRYPTO_memcmp(out1, out2, sizeof(out1)) != 0 ||
        EVP_RAND_uninstantiate(implicit) <= 0 ||
        EVP_RAND_uninstantiate(explicit) <= 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "Implicit BRNG IV or RAND parameter contract failed: %s\n", name);
    EVP_RAND_CTX_free(explicit);
    EVP_RAND_CTX_free(implicit);
    EVP_RAND_free(algorithm);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def && bee2)
        ok = check_variant("brng-ctr-hbelt", 0) &&
             check_variant("brng-hmac-hbelt", 1);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
