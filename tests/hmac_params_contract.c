/* MAC key setting through OSSL_PARAM and size-only finalization. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

static int check_params(const char *digest)
{
    static const unsigned char message[] = "MAC parameters remain effective across init";
    unsigned char key_a[19] = {1}, key_b[43] = {2};
    unsigned char computed[64] = {0}, reference[64] = {0};
    char digest_name[16];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *via_params = NULL, *direct = NULL;
    size_t result_len = 0, reference_len = 0, expected_len = 0;
    OSSL_PARAM options[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, key_a, sizeof(key_a)),
        OSSL_PARAM_END
    };
    int ok = 0;

    OPENSSL_strlcpy(digest_name, digest, sizeof(digest_name));
    mac = EVP_MAC_fetch(NULL, "belt-hmac", "provider=bee2");
    if (!mac || !(via_params = EVP_MAC_CTX_new(mac)) ||
        !(direct = EVP_MAC_CTX_new(mac)))
        goto end;
    if (!EVP_MAC_CTX_set_params(via_params, options) ||
        !EVP_MAC_init(via_params, NULL, 0, NULL) ||
        !EVP_MAC_update(via_params, message, sizeof(message)) ||
        !EVP_MAC_final(via_params, NULL, &result_len, 0) ||
        result_len == 0 || result_len > sizeof(computed) ||
        !EVP_MAC_final(via_params, computed, &result_len, sizeof(computed)) ||
        !EVP_MAC_init(direct, key_a, sizeof(key_a), options) ||
        !EVP_MAC_update(direct, message, sizeof(message)) ||
        !EVP_MAC_final(direct, reference, &reference_len, sizeof(reference)) ||
        result_len != reference_len ||
        CRYPTO_memcmp(computed, reference, result_len) != 0)
        goto end;

    /* Change the key with OSSL_PARAM, then reinitialize without key arg. */
    options[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                    key_b, sizeof(key_b));
    if (!EVP_MAC_CTX_set_params(via_params, options) ||
        !EVP_MAC_init(via_params, NULL, 0, NULL) ||
        !EVP_MAC_update(via_params, message, sizeof(message)) ||
        !EVP_MAC_final(via_params, computed, &result_len, sizeof(computed)) ||
        !EVP_MAC_init(direct, key_b, sizeof(key_b), options) ||
        !EVP_MAC_update(direct, message, sizeof(message)) ||
        !EVP_MAC_final(direct, reference, &reference_len, sizeof(reference)) ||
        result_len != reference_len ||
        CRYPTO_memcmp(computed, reference, result_len) != 0)
        goto end;
    expected_len = EVP_MAC_CTX_get_mac_size(via_params);
    ok = expected_len == result_len;
end:
    if (!ok)
        fprintf(stderr, "MAC OSSL_PARAM key/size contract failed: %s\n", digest);
    OPENSSL_cleanse(key_a, sizeof(key_a));
    OPENSSL_cleanse(key_b, sizeof(key_b));
    OPENSSL_cleanse(computed, sizeof(computed));
    OPENSSL_cleanse(reference, sizeof(reference));
    EVP_MAC_CTX_free(direct);
    EVP_MAC_CTX_free(via_params);
    EVP_MAC_free(mac);
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
    ok = def && bee2 && check_params("belt-hash") && check_params("bash256");
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
