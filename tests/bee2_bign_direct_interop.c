/* Check the EVP BIGN adapters against the Bee2 public cryptographic API.
 * This is NOT a published STB known-answer test. */
#include <bee2/core/err.h>
#include <bee2/crypto/bign.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    const char *curve_oid;
    const char *digest_oid;
    size_t priv_len;
} bign_case_t;

static const bign_case_t cases[] = {
    {"bign-256", "1.2.112.0.2.0.34.101.45.3.1", "1.2.112.0.2.0.34.101.31.81", 32},
    {"bign-384", "1.2.112.0.2.0.34.101.45.3.2", "1.2.112.0.2.0.34.101.77.12", 48},
    {"bign-512", "1.2.112.0.2.0.34.101.45.3.3", "1.2.112.0.2.0.34.101.77.13", 64},
};

typedef struct { int failed; } rng_ctx_t;

static void test_random_bytes(void *buf, size_t len, void *state)
{
    rng_ctx_t *rng = state;
    if (RAND_priv_bytes(buf, (int)len) != 1) {
        OPENSSL_cleanse(buf, len);
        rng->failed = 1;
    }
}

static EVP_PKEY *make_key(const char *name)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int check_signature(EVP_PKEY *key, const bign_params *curve,
                           const bign_case_t *test, const unsigned char *priv,
                           const unsigned char *pub)
{
    unsigned char digest[64], signature[96], native_sig[96], oid_der[32];
    size_t oid_len = sizeof(oid_der), sig_len = sizeof(signature), i;
    EVP_PKEY_CTX *sign = NULL, *verify = NULL;
    int ok = 0;

    for (i = 0; i < test->priv_len; ++i)
        digest[i] = (unsigned char)((i * 37u + test->priv_len) & 0xffu);
    if (bignOidToDER(oid_der, &oid_len, test->digest_oid) != ERR_OK)
        goto end;
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (sign == NULL || verify == NULL || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_verify_init(verify) <= 0 ||
        EVP_PKEY_sign(sign, signature, &sig_len, digest, test->priv_len) <= 0 ||
        bignVerify(curve, oid_der, oid_len, digest, signature, pub) != ERR_OK ||
        bignSign2(native_sig, curve, oid_der, oid_len, digest, priv, NULL, 0) != ERR_OK ||
        EVP_PKEY_verify(verify, native_sig, test->priv_len + test->priv_len / 2,
                        digest, test->priv_len) <= 0)
        goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(verify);
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(native_sig, sizeof(native_sig));
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok;
}

static int check_derive(EVP_PKEY *key, EVP_PKEY *peer,
                        const bign_params *curve, const unsigned char *priv,
                        const unsigned char *peer_pub, size_t n)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    unsigned char actual[128], expected[128];
    size_t outlen = sizeof(actual);
    int ok = 0;

    if (ctx == NULL || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, actual, &outlen) <= 0 || outlen != 2 * n ||
        bignDH(expected, curve, priv, peer_pub, outlen) != ERR_OK ||
        CRYPTO_memcmp(actual, expected, outlen) != 0)
        goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static int check_transport(EVP_PKEY *key, const bign_params *curve,
                           const unsigned char *priv, const unsigned char *pub,
                           size_t n)
{
    static const size_t lengths[] = {16, 17, 32, 64, 257};
    static const unsigned char zero_header[16] = {0};
    EVP_PKEY_CTX *encrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    EVP_PKEY_CTX *decrypt = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    rng_ctx_t rng = {0};
    unsigned char plaintext[257], wrapped[512], native_token[512];
    unsigned char recovered[512];
    size_t i, j, ct_len, native_len, recovered_len;
    int ok = 0;

    if (encrypt == NULL || decrypt == NULL ||
        EVP_PKEY_encrypt_init(encrypt) <= 0 || EVP_PKEY_decrypt_init(decrypt) <= 0)
        goto end;
    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        for (j = 0; j < lengths[i]; ++j)
            plaintext[j] = (unsigned char)(i * 19u + j * 31u);
        ct_len = sizeof(wrapped);
        native_len = lengths[i] + n + 16;
        if (EVP_PKEY_encrypt(encrypt, wrapped, &ct_len, plaintext, lengths[i]) <= 0 ||
            ct_len != native_len ||
            bignKeyUnwrap(recovered, curve, wrapped, ct_len, zero_header, priv) != ERR_OK ||
            CRYPTO_memcmp(recovered, plaintext, lengths[i]) != 0)
            goto end;
        if (bignKeyWrap(native_token, curve, plaintext, lengths[i], zero_header,
                        pub, test_random_bytes, &rng) != ERR_OK || rng.failed)
            goto end;
        recovered_len = sizeof(recovered);
        if (EVP_PKEY_decrypt(decrypt, recovered, &recovered_len, native_token,
                             native_len) <= 0 || recovered_len != lengths[i] ||
            CRYPTO_memcmp(recovered, plaintext, lengths[i]) != 0)
            goto end;
    }
    ok = 1;
end:
    EVP_PKEY_CTX_free(encrypt);
    EVP_PKEY_CTX_free(decrypt);
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    OPENSSL_cleanse(wrapped, sizeof(wrapped));
    OPENSSL_cleanse(native_token, sizeof(native_token));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    return ok;
}

static int check_case(const bign_case_t *test)
{
    bign_params curve;
    EVP_PKEY *local = NULL, *peer = NULL;
    unsigned char priv[64], pub[128], peer_pub[128], native_pub[128];
    size_t n = test->priv_len, actual_len = 0;
    int ok = 0;

    memset(&curve, 0, sizeof(curve));
    local = make_key(test->name);
    peer = make_key(test->name);
    if (local == NULL || peer == NULL ||
        bignParamsStd(&curve, test->curve_oid) != ERR_OK ||
        EVP_PKEY_get_octet_string_param(local, OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv, sizeof(priv), &actual_len) <= 0 ||
        actual_len != n ||
        EVP_PKEY_get_octet_string_param(local, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof(pub), &actual_len) <= 0 ||
        actual_len != 2 * n ||
        EVP_PKEY_get_octet_string_param(peer, OSSL_PKEY_PARAM_PUB_KEY,
                                        peer_pub, sizeof(peer_pub), &actual_len) <= 0 ||
        actual_len != 2 * n ||
        bignPubkeyCalc(native_pub, &curve, priv) != ERR_OK ||
        CRYPTO_memcmp(native_pub, pub, 2 * n) != 0 ||
        bignKeypairVal(&curve, priv, pub) != ERR_OK ||
        !check_signature(local, &curve, test, priv, pub) ||
        !check_derive(local, peer, &curve, priv, peer_pub, n) ||
        !check_transport(local, &curve, priv, pub, n))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "direct Bee2 BIGN comparison failed: %s\n", test->name);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(&curve, sizeof(curve));
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
        if (!check_case(&cases[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
