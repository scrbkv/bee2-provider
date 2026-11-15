#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t key_len;
    size_t iv_len;
    size_t msg_len;
} cipher_case_t;

typedef struct {
    const char *name;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
} aead_case_t;

static void fill_bytes(unsigned char *buf, size_t len, unsigned char seed) {
    size_t i;
    for (i = 0; i < len; ++i)
        buf[i] = (unsigned char)(seed + (unsigned char)(i * 13u + 7u));
}

static int run_block_cipher_roundtrip(const cipher_case_t *tc, unsigned char seed) {
    int ok = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc = NULL;
    EVP_CIPHER_CTX *dec = NULL;
    unsigned char key[32];
    unsigned char iv[32];
    unsigned char *pt = NULL;
    unsigned char *ct = NULL;
    unsigned char *rt = NULL;
    int outl = 0;
    int tmplen = 0;
    int ct_len = 0;
    int rt_len = 0;
    size_t alloc_len;
    size_t key_len = tc->key_len;
    int block_size;
    OSSL_PARAM init_params[2];

    if (tc->key_len > sizeof(key) || tc->iv_len > sizeof(iv)) {
        fprintf(stderr, "[FAIL] internal key/iv size error for %s\n", tc->name);
        return 0;
    }

    cipher = EVP_CIPHER_fetch(NULL, tc->name, "provider=bee2");
    if (!cipher) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_fetch(%s)\n", tc->name);
        goto cleanup;
    }
    block_size = EVP_CIPHER_get_block_size(cipher);
    alloc_len = tc->msg_len + (size_t)((block_size > 0) ? block_size : 32) + 32u;

    pt = malloc(tc->msg_len);
    ct = malloc(alloc_len);
    rt = malloc(alloc_len);
    if (!pt || !ct || !rt)
        goto cleanup;

    fill_bytes(key, tc->key_len, (unsigned char)(seed ^ 0x11u));
    fill_bytes(iv, tc->iv_len, (unsigned char)(seed ^ 0x22u));
    fill_bytes(pt, tc->msg_len, (unsigned char)(seed ^ 0x33u));

    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();
    if (!enc || !dec)
        goto cleanup;

    init_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_len);
    init_params[1] = OSSL_PARAM_construct_end();
    if (EVP_EncryptInit_ex2(enc, cipher, key, tc->iv_len ? iv : NULL, init_params) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptInit_ex2(%s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_set_padding(enc, 0) != 1) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_CTX_set_padding(enc, %s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_EncryptUpdate(enc, ct, &outl, pt, (int)tc->msg_len) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptUpdate(%s)\n", tc->name);
        goto cleanup;
    }
    ct_len = outl;
    if (EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptFinal_ex(%s)\n", tc->name);
        goto cleanup;
    }
    ct_len += tmplen;

    if (EVP_DecryptInit_ex2(dec, cipher, key, tc->iv_len ? iv : NULL, init_params) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptInit_ex2(%s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_set_padding(dec, 0) != 1) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_CTX_set_padding(dec, %s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_DecryptUpdate(dec, rt, &outl, ct, ct_len) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptUpdate(%s)\n", tc->name);
        goto cleanup;
    }
    rt_len = outl;
    if (EVP_DecryptFinal_ex(dec, rt + rt_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptFinal_ex(%s)\n", tc->name);
        goto cleanup;
    }
    rt_len += tmplen;

    if ((size_t)rt_len != tc->msg_len || CRYPTO_memcmp(rt, pt, tc->msg_len) != 0) {
        fprintf(stderr, "[FAIL] roundtrip mismatch for %s\n", tc->name);
        goto cleanup;
    }

    if (EVP_EncryptInit_ex2(enc, NULL, NULL, NULL, init_params) != 1 ||
        EVP_CIPHER_CTX_set_padding(enc, 0) != 1 ||
        EVP_EncryptUpdate(enc, rt, &outl, pt, (int)tc->msg_len) != 1) {
        fprintf(stderr, "[FAIL] saved-key reinit for %s\n", tc->name);
        goto cleanup;
    }
    rt_len = outl;
    if (EVP_EncryptFinal_ex(enc, rt + rt_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] saved-key reinit final for %s\n", tc->name);
        goto cleanup;
    }
    rt_len += tmplen;
    if (rt_len != ct_len || CRYPTO_memcmp(rt, ct, (size_t)ct_len) != 0) {
        fprintf(stderr, "[FAIL] saved-key reinit mismatch for %s\n", tc->name);
        goto cleanup;
    }

    printf("[OK] %s roundtrip\n", tc->name);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_free(cipher);
    if (pt) {
        OPENSSL_cleanse(pt, tc->msg_len);
        free(pt);
    }
    if (ct) {
        OPENSSL_cleanse(ct, alloc_len);
        free(ct);
    }
    if (rt) {
        OPENSSL_cleanse(rt, alloc_len);
        free(rt);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    return ok;
}

static int run_block_cipher_partial_rejection(const cipher_case_t *tc, unsigned char seed) {
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32];
    unsigned char iv[32];
    unsigned char input[65];
    unsigned char output[96];
    int outl = 0;
    int finl = 0;
    int rejected = 0;

    cipher = EVP_CIPHER_fetch(NULL, tc->name, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx)
        goto cleanup;
    fill_bytes(key, tc->key_len, (unsigned char)(seed ^ 0x51u));
    fill_bytes(iv, tc->iv_len, (unsigned char)(seed ^ 0x52u));
    fill_bytes(input, sizeof(input), (unsigned char)(seed ^ 0x53u));

    if (EVP_EncryptInit_ex2(ctx, cipher, key, tc->iv_len ? iv : NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto cleanup;
    if (EVP_EncryptUpdate(ctx, output, &outl, input, (int)sizeof(input)) != 1)
        rejected = 1;
    else if (EVP_EncryptFinal_ex(ctx, output + outl, &finl) != 1)
        rejected = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(output, sizeof(output));
    if (!rejected)
        fprintf(stderr, "[FAIL] partial block accepted by %s\n", tc->name);
    return rejected;
}

static int run_kwp_roundtrip(const cipher_case_t *tc, unsigned char seed) {
    int ok = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc = NULL;
    EVP_CIPHER_CTX *dec = NULL;
    unsigned char key[32];
    unsigned char iv[32];
    unsigned char pt[32];
    unsigned char ct[64];
    unsigned char rt[48];
    int outl = 0;
    int tmplen = 0;
    int ct_len = 0;
    int rt_len = 0;

    if (tc->key_len > sizeof(key) || tc->iv_len > sizeof(iv)) {
        fprintf(stderr, "[FAIL] internal key/iv size error for %s\n", tc->name);
        return 0;
    }

    cipher = EVP_CIPHER_fetch(NULL, tc->name, "provider=bee2");
    if (!cipher) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_fetch(%s)\n", tc->name);
        goto cleanup;
    }
    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();
    if (!enc || !dec)
        goto cleanup;

    fill_bytes(key, tc->key_len, (unsigned char)(seed ^ 0x41u));
    fill_bytes(iv, tc->iv_len, (unsigned char)(seed ^ 0x42u));
    fill_bytes(pt, sizeof(pt), (unsigned char)(seed ^ 0x43u));

    if (EVP_EncryptInit_ex2(enc, cipher, key, iv, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(enc, 0) != 1 ||
        EVP_EncryptUpdate(enc, ct, &outl, pt, (int)sizeof(pt)) != 1) {
        fprintf(stderr, "[FAIL] wrapping with %s\n", tc->name);
        goto cleanup;
    }
    ct_len = outl;
    if (EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] wrapping final with %s\n", tc->name);
        goto cleanup;
    }
    ct_len += tmplen;

    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(dec, 0) != 1 ||
        EVP_DecryptUpdate(dec, rt, &outl, ct, ct_len) != 1) {
        fprintf(stderr, "[FAIL] unwrapping with %s\n", tc->name);
        goto cleanup;
    }
    rt_len = outl;
    if (EVP_DecryptFinal_ex(dec, rt + rt_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] unwrapping final with %s\n", tc->name);
        goto cleanup;
    }
    rt_len += tmplen;
    if (rt_len != (int)sizeof(pt) || CRYPTO_memcmp(rt, pt, sizeof(pt)) != 0) {
        fprintf(stderr, "[FAIL] wrap roundtrip mismatch for %s\n", tc->name);
        goto cleanup;
    }

    EVP_CIPHER_CTX_free(dec);
    dec = EVP_CIPHER_CTX_new();
    if (!dec)
        goto cleanup;
    ct[0] ^= 1u;
    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(dec, 0) != 1) {
        fprintf(stderr, "[FAIL] tampered unwrap setup for %s\n", tc->name);
        goto cleanup;
    }
    if (EVP_DecryptUpdate(dec, rt, &outl, ct, ct_len) == 1) {
        fprintf(stderr, "[FAIL] tampered wrapped key accepted for %s\n", tc->name);
        goto cleanup;
    }

    printf("[OK] %s roundtrip/authentication\n", tc->name);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(pt, sizeof(pt));
    OPENSSL_cleanse(ct, sizeof(ct));
    OPENSSL_cleanse(rt, sizeof(rt));
    return ok;
}

static int run_aead_roundtrip(const aead_case_t *tc, unsigned char seed) {
    int ok = 0;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc = NULL;
    EVP_CIPHER_CTX *dec = NULL;
    unsigned char key[32];
    unsigned char iv[32];
    unsigned char aad[29];
    unsigned char pt[73];
    unsigned char ct[96];
    unsigned char rt[96];
    unsigned char tag[32];
    unsigned char repeat_tag[32];
    OSSL_PARAM get_tag[2];
    OSSL_PARAM enc_params[2];
    OSSL_PARAM dec_params[3];
    OSSL_PARAM set_tag[2];
    size_t key_len = tc->key_len;
    int outl = 0;
    int tmplen = 0;
    int ct_len = 0;
    int rt_len = 0;

    if (tc->key_len > sizeof(key) || tc->iv_len > sizeof(iv) || tc->tag_len > sizeof(tag)) {
        fprintf(stderr, "[FAIL] internal size error for %s\n", tc->name);
        return 0;
    }

    cipher = EVP_CIPHER_fetch(NULL, tc->name, "provider=bee2");
    if (!cipher) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_fetch(%s)\n", tc->name);
        goto cleanup;
    }
    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();
    if (!enc || !dec)
        goto cleanup;

    fill_bytes(key, tc->key_len, (unsigned char)(seed ^ 0x61u));
    fill_bytes(iv, tc->iv_len, (unsigned char)(seed ^ 0x62u));
    fill_bytes(aad, sizeof(aad), (unsigned char)(seed ^ 0x63u));
    fill_bytes(pt, sizeof(pt), (unsigned char)(seed ^ 0x64u));
    memset(tag, 0, sizeof(tag));
    memset(repeat_tag, 0, sizeof(repeat_tag));

    enc_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_len);
    enc_params[1] = OSSL_PARAM_construct_end();
    if (EVP_EncryptInit_ex2(enc, cipher, key, iv, enc_params) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptInit_ex2(%s)\n", tc->name);
        goto cleanup;
    }
    set_tag[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, tc->tag_len);
    set_tag[1] = OSSL_PARAM_construct_end();
    if (EVP_CIPHER_CTX_set_params(enc, set_tag) > 0) {
        fprintf(stderr, "[FAIL] encryption accepted an expected tag for %s\n", tc->name);
        goto cleanup;
    }
    if (EVP_EncryptUpdate(enc, NULL, &outl, aad, (int)sizeof(aad)) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptUpdate(AAD, %s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_EncryptUpdate(enc, ct, &outl, pt, (int)sizeof(pt)) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptUpdate(data, %s)\n", tc->name);
        goto cleanup;
    }
    ct_len = outl;
    if (EVP_EncryptFinal_ex(enc, ct + ct_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] EVP_EncryptFinal_ex(%s)\n", tc->name);
        goto cleanup;
    }
    ct_len += tmplen;

    get_tag[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, tc->tag_len);
    get_tag[1] = OSSL_PARAM_construct_end();
    if (EVP_CIPHER_CTX_get_params(enc, get_tag) != 1) {
        fprintf(stderr, "[FAIL] EVP_CIPHER_CTX_get_params(tag, %s)\n", tc->name);
        goto cleanup;
    }

    dec_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &key_len);
    dec_params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, tc->tag_len);
    dec_params[2] = OSSL_PARAM_construct_end();
    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, dec_params) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptInit_ex2(%s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_get_params(dec, get_tag) > 0) {
        fprintf(stderr, "[FAIL] decryption exposed its expected tag for %s\n", tc->name);
        goto cleanup;
    }
    if (EVP_DecryptUpdate(dec, NULL, &outl, aad, (int)sizeof(aad)) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptUpdate(AAD, %s)\n", tc->name);
        goto cleanup;
    }
    if (EVP_DecryptUpdate(dec, rt, &outl, ct, ct_len) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptUpdate(data, %s)\n", tc->name);
        goto cleanup;
    }
    rt_len = outl;

    if (EVP_DecryptFinal_ex(dec, rt + rt_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] EVP_DecryptFinal_ex(%s)\n", tc->name);
        goto cleanup;
    }
    rt_len += tmplen;

    if (rt_len != (int)sizeof(pt) || CRYPTO_memcmp(rt, pt, sizeof(pt)) != 0) {
        fprintf(stderr, "[FAIL] roundtrip mismatch for %s\n", tc->name);
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_set_params(dec, set_tag) > 0) {
        fprintf(stderr, "[FAIL] decryption accepted a tag after final for %s\n", tc->name);
        goto cleanup;
    }

    if (EVP_EncryptInit_ex2(enc, NULL, NULL, NULL, enc_params) != 1 ||
        EVP_EncryptUpdate(enc, NULL, &outl, aad, (int)sizeof(aad)) != 1 ||
        EVP_EncryptUpdate(enc, rt, &outl, pt, (int)sizeof(pt)) != 1) {
        fprintf(stderr, "[FAIL] saved-key AEAD reinit for %s\n", tc->name);
        goto cleanup;
    }
    rt_len = outl;
    if (EVP_EncryptFinal_ex(enc, rt + rt_len, &tmplen) != 1) {
        fprintf(stderr, "[FAIL] saved-key AEAD reinit final for %s\n", tc->name);
        goto cleanup;
    }
    rt_len += tmplen;
    get_tag[0] =
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, repeat_tag, tc->tag_len);
    if (EVP_CIPHER_CTX_get_params(enc, get_tag) != 1 || rt_len != ct_len ||
        CRYPTO_memcmp(rt, ct, (size_t)ct_len) != 0 ||
        CRYPTO_memcmp(repeat_tag, tag, tc->tag_len) != 0) {
        fprintf(stderr, "[FAIL] saved-key AEAD reinit mismatch for %s\n", tc->name);
        goto cleanup;
    }

    EVP_CIPHER_CTX_free(dec);
    dec = EVP_CIPHER_CTX_new();
    if (!dec)
        goto cleanup;

    tag[0] ^= 1u;
    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, NULL) != 1 ||
        EVP_DecryptUpdate(dec, NULL, &outl, aad, (int)sizeof(aad)) != 1 ||
        EVP_DecryptUpdate(dec, rt, &outl, ct, ct_len) != 1) {
        fprintf(stderr, "[FAIL] tampered-tag decrypt setup for %s\n", tc->name);
        goto cleanup;
    }
    set_tag[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, tc->tag_len);
    set_tag[1] = OSSL_PARAM_construct_end();
    if (EVP_CIPHER_CTX_set_params(dec, set_tag) != 1) {
        fprintf(stderr, "[FAIL] setting tampered tag for %s\n", tc->name);
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(dec, rt + outl, &tmplen) == 1) {
        fprintf(stderr, "[FAIL] tampered tag accepted for %s\n", tc->name);
        goto cleanup;
    }

    printf("[OK] %s roundtrip/authentication\n", tc->name);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(aad, sizeof(aad));
    OPENSSL_cleanse(pt, sizeof(pt));
    OPENSSL_cleanse(ct, sizeof(ct));
    OPENSSL_cleanse(rt, sizeof(rt));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(repeat_tag, sizeof(repeat_tag));
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
    size_t i;

    static const cipher_case_t block_cases[] = {{"belt-ecb128", 16u, 0u, 64u},
                                                {"belt-ecb192", 24u, 0u, 64u},
                                                {"belt-ecb256", 32u, 0u, 64u},
                                                {"belt-cbc128", 16u, 16u, 64u},
                                                {"belt-cbc192", 24u, 16u, 64u},
                                                {"belt-cbc256", 32u, 16u, 64u},
                                                {"belt-cfb128", 16u, 16u, 73u},
                                                {"belt-cfb192", 24u, 16u, 73u},
                                                {"belt-cfb256", 32u, 16u, 73u},
                                                {"belt-ctr128", 16u, 16u, 73u},
                                                {"belt-ctr192", 24u, 16u, 73u},
                                                {"belt-ctr256", 32u, 16u, 73u},
                                                {"belt-bde128", 16u, 16u, 64u},
                                                {"belt-bde192", 24u, 16u, 64u},
                                                {"belt-bde256", 32u, 16u, 64u},
                                                {"belt-sde128", 16u, 16u, 64u},
                                                {"belt-sde192", 24u, 16u, 64u},
                                                {"belt-sde256", 32u, 16u, 64u}};

    static const aead_case_t aead_cases[] = {{"belt-che128", 16u, 16u, 8u},
                                             {"belt-che192", 24u, 16u, 8u},
                                             {"belt-che256", 32u, 16u, 8u},
                                             {"belt-dwp128", 16u, 16u, 8u},
                                             {"belt-dwp192", 24u, 16u, 8u},
                                             {"belt-dwp256", 32u, 16u, 8u},
                                             {"bash-prg-ae1281", 16u, 16u, 16u},
                                             {"bash-prg-ae1282", 16u, 16u, 16u},
                                             {"bash-prg-ae1921", 24u, 24u, 24u},
                                             {"bash-prg-ae1922", 24u, 24u, 24u},
                                             {"bash-prg-ae2561", 32u, 32u, 32u},
                                             {"bash-prg-ae2562", 32u, 32u, 32u}};

    static const cipher_case_t kwp_cases[] = {{"belt-kwp128", 16u, 16u, 32u},
                                              {"belt-kwp192", 24u, 16u, 32u},
                                              {"belt-kwp256", 32u, 16u, 32u}};

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <provider-path> [algorithm-name]\n", argv[0]);
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

    for (i = 0; i < sizeof(block_cases) / sizeof(block_cases[0]); ++i) {
        if (!should_run_alg(selected_alg, block_cases[i].name))
            continue;
        ran = 1;
        if (!run_block_cipher_roundtrip(&block_cases[i], (unsigned char)(0x10u + i)))
            goto cleanup;
        if ((strstr(block_cases[i].name, "-bde") != NULL ||
             strstr(block_cases[i].name, "-sde") != NULL) &&
            !run_block_cipher_partial_rejection(&block_cases[i], (unsigned char)(0x50u + i)))
            goto cleanup;
    }

    for (i = 0; i < sizeof(aead_cases) / sizeof(aead_cases[0]); ++i) {
        if (!should_run_alg(selected_alg, aead_cases[i].name))
            continue;
        ran = 1;
        if (!run_aead_roundtrip(&aead_cases[i], (unsigned char)(0x80u + i)))
            goto cleanup;
    }

    for (i = 0; i < sizeof(kwp_cases) / sizeof(kwp_cases[0]); ++i) {
        if (!should_run_alg(selected_alg, kwp_cases[i].name))
            continue;
        ran = 1;
        if (!run_kwp_roundtrip(&kwp_cases[i], (unsigned char)(0xC0u + i)))
            goto cleanup;
    }
    if (!ran) {
        fprintf(stderr, "[FAIL] unknown algorithm selector: %s\n", selected_alg);
        goto cleanup;
    }

    if (selected_alg)
        printf("[OK] Cipher coverage passed for %s\n", selected_alg);
    else
        printf("[OK] Cipher coverage tests passed\n");
    ret = 0;

cleanup:
    OSSL_PROVIDER_unload(bee2_prov);
    OSSL_PROVIDER_unload(default_prov);
    return ret;
}
