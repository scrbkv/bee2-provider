#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *algorithm;
    size_t private_key_length;
    size_t shared_secret_length;
} bign_exchange_case_t;

static EVP_PKEY *make_private_key(const bign_exchange_case_t *test_case, unsigned char seed) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char private_key[64] = {0};
    OSSL_PARAM params[2];
    size_t i;

    private_key[0] = (unsigned char)(seed | 1u);
    for (i = 1; i < test_case->private_key_length / 2u; ++i)
        private_key[i] = (unsigned char)(seed + (unsigned char)(3u * i));

    ctx = EVP_PKEY_CTX_new_from_name(NULL, test_case->algorithm, "provider=bee2");
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0)
        goto cleanup;
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PRIV_KEY, private_key, test_case->private_key_length);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0)
        key = NULL;

cleanup:
    OPENSSL_cleanse(private_key, sizeof(private_key));
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int derive_secret(EVP_PKEY *local_key,
                         EVP_PKEY *peer_key,
                         int use_bake_kdf,
                         unsigned char **secret,
                         size_t *secret_length) {
    static unsigned char ukm[] = {0x42, 0x49, 0x47, 0x4e, 0x2d, 0x44, 0x48};
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    char kdf_name[] = "bake-kdf";
    size_t kdf_length = 32u;
    uint64_t kdf_num = UINT64_C(0x1020304050607080);
    size_t required = 0;
    int ok = 0;

    *secret = NULL;
    *secret_length = 0;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local_key, "provider=bee2");
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
        goto cleanup;
    if (use_bake_kdf) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, kdf_name, 0);
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ukm, sizeof(ukm));
        params[2] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &kdf_length);
        params[3] = OSSL_PARAM_construct_uint64("kdf-num", &kdf_num);
        params[4] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
            goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, NULL, &required) <= 0 || required == 0u)
        goto cleanup;
    *secret = OPENSSL_malloc(required);
    if (!*secret)
        goto cleanup;
    *secret_length = required;
    if (EVP_PKEY_derive(ctx, *secret, secret_length) <= 0)
        goto cleanup;
    ok = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        OPENSSL_clear_free(*secret, required);
        *secret = NULL;
        *secret_length = 0;
    }
    return ok;
}

static int run_case(const bign_exchange_case_t *test_case) {
    EVP_PKEY *alice = NULL;
    EVP_PKEY *bob = NULL;
    unsigned char *alice_secret = NULL;
    unsigned char *bob_secret = NULL;
    size_t alice_length = 0;
    size_t bob_length = 0;
    int use_kdf;
    int ok = 0;

    alice = make_private_key(test_case, 0x21u);
    bob = make_private_key(test_case, 0x61u);
    if (!alice || !bob) {
        fprintf(stderr, "[FAIL] %s key construction\n", test_case->algorithm);
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    for (use_kdf = 0; use_kdf <= 1; ++use_kdf) {
        if (!derive_secret(alice, bob, use_kdf, &alice_secret, &alice_length) ||
            !derive_secret(bob, alice, use_kdf, &bob_secret, &bob_length)) {
            fprintf(stderr,
                    "[FAIL] %s %s derive\n",
                    test_case->algorithm,
                    use_kdf ? "BAKE-KDF" : "raw DH");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
        if (alice_length != bob_length ||
            alice_length != (use_kdf ? 32u : test_case->shared_secret_length) ||
            CRYPTO_memcmp(alice_secret, bob_secret, alice_length) != 0) {
            fprintf(stderr,
                    "[FAIL] %s %s agreement mismatch\n",
                    test_case->algorithm,
                    use_kdf ? "BAKE-KDF" : "raw DH");
            goto cleanup;
        }
        OPENSSL_clear_free(alice_secret, alice_length);
        OPENSSL_clear_free(bob_secret, bob_length);
        alice_secret = NULL;
        bob_secret = NULL;
    }
    printf("[OK] %s raw DH and BAKE-KDF\n", test_case->algorithm);
    ok = 1;

cleanup:
    OPENSSL_clear_free(alice_secret, alice_length);
    OPENSSL_clear_free(bob_secret, bob_length);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    return ok;
}

int main(int argc, char **argv) {
    static const bign_exchange_case_t cases[] = {
        {"bign-256", 32u, 64u},
        {"bign-384", 48u, 96u},
        {"bign-512", 64u, 128u},
    };
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *bee2_provider = NULL;
    size_t i;
    int result = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <provider-path> <algorithm>\n", argv[0]);
        return 2;
    }
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    bee2_provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!default_provider || !bee2_provider)
        goto cleanup;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (strcmp(argv[2], cases[i].algorithm) == 0) {
            result = run_case(&cases[i]) ? 0 : 1;
            goto cleanup;
        }
    }
    fprintf(stderr, "unknown algorithm: %s\n", argv[2]);

cleanup:
    OSSL_PROVIDER_unload(bee2_provider);
    OSSL_PROVIDER_unload(default_provider);
    return result;
}
