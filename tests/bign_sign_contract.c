#include <openssl/core_names.h>

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *alg;
    size_t priv_len;
    size_t sig_len;
    const char *digest;
} bign_case_t;

static void fill_priv(unsigned char *priv, size_t len, unsigned char seed) {
    size_t i;
    memset(priv, 0, len);
    priv[0] = (unsigned char)(seed | 1u);
    for (i = 1; i < len / 2u; ++i)
        priv[i] = (unsigned char)(seed + (unsigned char)i);
}

static EVP_PKEY *build_private_key(const bign_case_t *tc, const unsigned char *priv) {
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    kctx = EVP_PKEY_CTX_new_from_name(NULL, tc->alg, "provider=bee2");
    if (!kctx) {
        fprintf(stderr, "[FAIL] EVP_PKEY_CTX_new_from_name(%s)\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_fromdata_init(%s)\n", tc->alg);
        goto cleanup;
    }

    params[0] =
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv, tc->priv_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_fromdata(%s)\n", tc->alg);
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

static int run_sign_verify_case(const bign_case_t *tc, unsigned char seed) {
    int ok = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    EVP_PKEY_CTX *vctx = NULL;
    unsigned char priv[64];
    unsigned char hash[64];
    unsigned char hash_bad[64];
    unsigned char *sig = NULL;
    unsigned char *sig_again = NULL;
    size_t hash_len = tc->priv_len;
    size_t sig_len = 0;
    size_t sig_again_len = 0;
    unsigned int deterministic = 1;
    OSSL_PARAM sign_params[2];
    size_t i;

    if (tc->priv_len > sizeof(priv) || hash_len > sizeof(hash))
        return 0;

    fill_priv(priv, tc->priv_len, seed);
    memset(hash, 0, sizeof(hash));
    for (i = 0; i < hash_len; ++i)
        hash[i] = (unsigned char)(seed ^ (unsigned char)(i * 3u + 1u));
    memcpy(hash_bad, hash, sizeof(hash_bad));
    hash_bad[0] ^= 0x80u;

    pkey = build_private_key(tc, priv);
    if (!pkey)
        goto cleanup;

    sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=bee2");
    if (!sctx) {
        fprintf(stderr, "[FAIL] EVP_PKEY_CTX_new_from_pkey(sign, %s)\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_sign_init(sctx) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_sign_init(%s)\n", tc->alg);
        goto cleanup;
    }
    sign_params[0] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    sign_params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(sctx, sign_params) <= 0) {
        fprintf(stderr, "[FAIL] enabling deterministic signature for %s\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_sign(sctx, NULL, &sig_len, hash, hash_len) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_sign(size, %s)\n", tc->alg);
        goto cleanup;
    }
    if (sig_len != tc->sig_len) {
        fprintf(stderr,
                "[FAIL] signature size mismatch for %s (got %zu, want %zu)\n",
                tc->alg,
                sig_len,
                tc->sig_len);
        goto cleanup;
    }
    sig = malloc(sig_len);
    if (!sig)
        goto cleanup;
    if (EVP_PKEY_sign(sctx, sig, &sig_len, hash, hash_len) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_sign(%s)\n", tc->alg);
        goto cleanup;
    }
    sig_again_len = sig_len;
    sig_again = malloc(sig_again_len);
    if (!sig_again || EVP_PKEY_sign(sctx, sig_again, &sig_again_len, hash, hash_len) <= 0 ||
        sig_again_len != sig_len || CRYPTO_memcmp(sig, sig_again, sig_len) != 0) {
        fprintf(
            stderr, "[FAIL] non-deterministic signature in deterministic mode for %s\n", tc->alg);
        goto cleanup;
    }

    vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=bee2");
    if (!vctx) {
        fprintf(stderr, "[FAIL] EVP_PKEY_CTX_new_from_pkey(verify, %s)\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_verify_init(vctx) <= 0) {
        fprintf(stderr, "[FAIL] EVP_PKEY_verify_init(%s)\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_verify(vctx, sig, sig_len, hash, hash_len) != 1) {
        fprintf(stderr, "[FAIL] EVP_PKEY_verify(valid, %s)\n", tc->alg);
        goto cleanup;
    }
    if (EVP_PKEY_verify(vctx, sig, sig_len, hash_bad, hash_len) == 1) {
        fprintf(stderr, "[FAIL] EVP_PKEY_verify(invalid, %s) unexpectedly passed\n", tc->alg);
        goto cleanup;
    }

    printf("[OK] %s sign/verify\n", tc->alg);
    ok = 1;

cleanup:
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_free(pkey);
    if (sig)
        free(sig);
    if (sig_again)
        free(sig_again);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(hash, sizeof(hash));
    OPENSSL_cleanse(hash_bad, sizeof(hash_bad));
    return ok;
}

static int run_digest_streaming_case(const bign_case_t *tc, unsigned char seed) {
    static const unsigned char first[] = "BIGN streaming: first part";
    static const unsigned char second[] = " and second part";
    unsigned char priv[64];
    unsigned char reference_sig[96];
    unsigned char streaming_sig[96];
    unsigned int deterministic = 1;
    char other_digest[] = "belt-hash";
    OSSL_PARAM deterministic_param[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };
    OSSL_PARAM digest_param[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, other_digest, 0),
        OSSL_PARAM_END
    };
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *reference = NULL, *streaming = NULL, *verify = NULL;
    EVP_PKEY_CTX *reference_pctx = NULL, *streaming_pctx = NULL;
    size_t reference_len = sizeof(reference_sig);
    size_t streaming_len = sizeof(streaming_sig);
    int ok = 0;

    fill_priv(priv, tc->priv_len, seed);
    if (tc->priv_len == 32u)
        OPENSSL_strlcpy(other_digest, "bash256", sizeof(other_digest));
    key = build_private_key(tc, priv);
    reference = EVP_MD_CTX_new();
    streaming = EVP_MD_CTX_new();
    verify = EVP_MD_CTX_new();
    if (!key || !reference || !streaming || !verify)
        goto cleanup;

    /* Reference: set deterministic mode before any message bytes. */
    if (EVP_DigestSignInit_ex(reference, &reference_pctx, tc->digest, NULL,
                              "provider=bee2", key, NULL) <= 0 ||
        EVP_PKEY_CTX_set_params(reference_pctx, deterministic_param) <= 0 ||
        EVP_DigestSignUpdate(reference, first, sizeof(first) - 1u) <= 0 ||
        EVP_DigestSignUpdate(reference, second, sizeof(second) - 1u) <= 0 ||
        EVP_DigestSignFinal(reference, reference_sig, &reference_len) <= 0)
        goto cleanup;

    /* Changing the signature mode must preserve the in-progress digest. */
    if (EVP_DigestSignInit_ex(streaming, &streaming_pctx, tc->digest, NULL,
                              "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestSignUpdate(streaming, first, sizeof(first) - 1u) <= 0 ||
        EVP_PKEY_CTX_set_params(streaming_pctx, digest_param) > 0 ||
        EVP_PKEY_CTX_set_params(streaming_pctx, deterministic_param) <= 0 ||
        EVP_DigestSignUpdate(streaming, second, sizeof(second) - 1u) <= 0 ||
        EVP_DigestSignFinal(streaming, streaming_sig, &streaming_len) <= 0 ||
        streaming_len != reference_len ||
        CRYPTO_memcmp(streaming_sig, reference_sig, reference_len) != 0)
        goto cleanup;

    if (EVP_DigestVerifyInit_ex(verify, NULL, tc->digest, NULL,
                                "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestVerifyUpdate(verify, first, sizeof(first) - 1u) <= 0 ||
        EVP_DigestVerifyUpdate(verify, second, sizeof(second) - 1u) <= 0 ||
        EVP_DigestVerifyFinal(verify, streaming_sig, streaming_len) <= 0)
        goto cleanup;

    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "[FAIL] BIGN digest streaming parameters for %s\n", tc->alg);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(streaming);
    EVP_MD_CTX_free(reference);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(reference_sig, sizeof(reference_sig));
    OPENSSL_cleanse(streaming_sig, sizeof(streaming_sig));
    return ok;
}

static int should_run_alg(const char *selected_alg, const char *alg_name) {
    return selected_alg == NULL || strcmp(selected_alg, alg_name) == 0;
}

int main(int argc, char **argv) {
    int ret = 1;
    int ran = 0;
    const char *selected_alg = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *bee2_prov = NULL;
    static const bign_case_t cases[] = {
        {"bign-256", 32u, 48u, "belt-hash"},
        {"bign-384", 48u, 72u, "bash384"},
        {"bign-512", 64u, 96u, "bash512"}};
    size_t i;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <provider-path> [bign-256|bign-384|bign-512]\n", argv[0]);
        return 2;
    }
    if (argc == 3)
        selected_alg = argv[2];

    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1])) {
        fprintf(stderr, "[FAIL] OSSL_PROVIDER_set_default_search_path(%s)\n", argv[1]);
        return 1;
    }
    default_prov = OSSL_PROVIDER_load(NULL, "default");
    bee2_prov = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!default_prov || !bee2_prov) {
        fprintf(stderr, "[FAIL] loading providers (default + bee2_provider)\n");
        goto cleanup;
    }

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (!should_run_alg(selected_alg, cases[i].alg))
            continue;
        ran = 1;
        if (!run_sign_verify_case(&cases[i], (unsigned char)(0x21u + i * 0x11u)) ||
            !run_digest_streaming_case(&cases[i], (unsigned char)(0x21u + i * 0x11u)))
            goto cleanup;
    }
    if (!ran) {
        fprintf(stderr, "[FAIL] unknown algorithm selector: %s\n", selected_alg);
        goto cleanup;
    }

    if (selected_alg)
        printf("[OK] BIGN sign/verify passed for %s\n", selected_alg);
    else
        printf("[OK] BIGN sign/verify tests passed\n");
    ret = 0;

cleanup:
    OSSL_PROVIDER_unload(bee2_prov);
    OSSL_PROVIDER_unload(default_prov);
    return ret;
}
