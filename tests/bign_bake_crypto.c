/* Compare EVP BIGN + BAKE-KDF with the Bee2 reference KDF. */
#include <bee2/crypto/bake.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t private_len;
} bign_case_t;

static const bign_case_t cases[] = {
    {"bign-256", 32}, {"bign-384", 48}, {"bign-512", 64}
};

static EVP_PKEY *make_key(const bign_case_t *test, unsigned char seed)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, test->name,
                                                    "provider=bee2");
    EVP_PKEY *key = NULL;
    unsigned char private_bytes[64] = {0};
    OSSL_PARAM params[2];
    size_t i;

    private_bytes[0] = seed | 1u;
    for (i = 1; i < test->private_len / 2; ++i)
        private_bytes[i] = (unsigned char)(seed + i * 3u);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  private_bytes, test->private_len);
    params[1] = OSSL_PARAM_construct_end();
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    return key;
}

static int test_curve(const bign_case_t *test)
{
    EVP_PKEY *local = NULL, *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char raw[128], expected[32], actual[32];
    unsigned char ukm[32];
    static const size_t output_lengths[] = {1, 16, 32};
    static const size_t ukm_lengths[] = {7, 32};
    uint64_t kdf_number;
    char kdf[] = "bake-kdf";
    size_t raw_len = sizeof(raw), derived_len, i, j;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, kdf, sizeof(kdf)),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, ukm, sizeof(ukm)),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, &derived_len),
        OSSL_PARAM_uint64("kdf-num", &kdf_number),
        OSSL_PARAM_END
    };
    int ok = 0;

    for (i = 0; i < sizeof(ukm); ++i)
        ukm[i] = (unsigned char)(i * 17u + 9u);
    local = make_key(test, 0x21u);
    peer = make_key(test, 0x61u);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local, "provider=bee2");
    if (local == NULL || peer == NULL || ctx == NULL ||
        EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, raw, &raw_len) <= 0 ||
        raw_len != test->private_len * 2)
        goto end;

    for (i = 0; i < sizeof(ukm_lengths) / sizeof(ukm_lengths[0]); ++i) {
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                                      ukm, ukm_lengths[i]);
        kdf_number = i == 0 ? UINT64_C(0) : UINT64_C(0x1234567);
        if (bakeKDF(expected, raw, test->private_len, ukm,
                    ukm_lengths[i], (size_t)kdf_number) != ERR_OK)
            goto end;
        for (j = 0; j < sizeof(output_lengths) / sizeof(output_lengths[0]); ++j) {
            derived_len = output_lengths[j];
            if (EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
                EVP_PKEY_derive(ctx, actual, &derived_len) <= 0 ||
                derived_len != output_lengths[j] ||
                CRYPTO_memcmp(actual, expected, derived_len) != 0) {
                fprintf(stderr, "%s BAKE-KDF mismatch: iv=%zu output=%zu\n",
                        test->name, ukm_lengths[i], output_lengths[j]);
                goto end;
            }
        }
    }
    ok = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(raw, sizeof(raw));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(ukm, sizeof(ukm));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (!test_curve(&cases[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
