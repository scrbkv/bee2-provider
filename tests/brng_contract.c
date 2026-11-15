/* Reject unsupported EVP_RAND semantics instead of reporting success. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int check_ctr_additional_input(void)
{
    unsigned char key[32] = {0}, iv[32] = {0};
    unsigned char first_left, first_right, first_overlap;
    unsigned char x[16] = {1}, y[16] = {2};
    unsigned char left_output[16], right_output[16], overlap_output[16];
    EVP_RAND *alg = NULL;
    EVP_RAND_CTX *left = NULL, *right = NULL, *overlap = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
        OSSL_PARAM_octet_string("iv", iv, sizeof(iv)),
        OSSL_PARAM_END
    };
    int ok = 0;

    alg = EVP_RAND_fetch(NULL, "brng-ctr-hbelt", "provider=bee2");
    if (!alg || !(left = EVP_RAND_CTX_new(alg, NULL)) ||
        !(right = EVP_RAND_CTX_new(alg, NULL)) ||
        !(overlap = EVP_RAND_CTX_new(alg, NULL)) ||
        !EVP_RAND_CTX_set_params(left, params) ||
        !EVP_RAND_CTX_set_params(right, params) ||
        !EVP_RAND_CTX_set_params(overlap, params) ||
        !EVP_RAND_instantiate(left, 256, 0, NULL, 0, NULL) ||
        !EVP_RAND_instantiate(right, 256, 0, NULL, 0, NULL) ||
        !EVP_RAND_instantiate(overlap, 256, 0, NULL, 0, NULL) ||
        !EVP_RAND_generate(left, &first_left, 1, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(right, &first_right, 1, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(overlap, &first_overlap, 1, 256, 0, NULL, 0) ||
        first_left != first_right || first_left != first_overlap)
        goto cleanup;
    memcpy(overlap_output, x, sizeof(x));
    if (!EVP_RAND_generate(left, left_output, sizeof(left_output), 256, 0, x, sizeof(x)) ||
        !EVP_RAND_generate(right, right_output, sizeof(right_output), 256, 0, y, sizeof(y)) ||
        !EVP_RAND_generate(overlap, overlap_output, sizeof(overlap_output), 256, 0,
                           overlap_output, sizeof(overlap_output)) ||
        CRYPTO_memcmp(left_output, right_output, sizeof(left_output)) == 0 ||
        CRYPTO_memcmp(left_output, overlap_output, sizeof(left_output)) != 0)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "BRNG-CTR ignored additional input after a partial block\n");
    EVP_RAND_CTX_free(overlap);
    EVP_RAND_CTX_free(right);
    EVP_RAND_CTX_free(left);
    EVP_RAND_free(alg);
    return ok;
}

static int check_rand(const char *name, int is_hmac) {
    unsigned char key[32] = {0}, iv[32] = {0}, out[64] = {0};
    unsigned char entropy[32] = {1};
    const unsigned char extra[] = {0x01, 0x02, 0x03};
    EVP_RAND *alg = NULL;
    EVP_RAND_CTX *ctx = NULL;
    OSSL_PARAM p[] = {OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
                      OSSL_PARAM_construct_octet_string("iv", iv, sizeof(iv)),
                      OSSL_PARAM_construct_end()};
    int ok = 0;

    alg = EVP_RAND_fetch(NULL, name, "provider=bee2");
    if (!alg || !(ctx = EVP_RAND_CTX_new(alg, NULL)) ||
        !EVP_RAND_CTX_set_params(ctx, p) ||
        EVP_RAND_instantiate(ctx, 256, 1, NULL, 0, NULL) ||
        EVP_RAND_instantiate(ctx, 256, 0, extra, sizeof(extra), NULL) ||
        !EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, NULL) ||
        EVP_RAND_generate(ctx, out, sizeof(out), 256, 1, NULL, 0) ||
        EVP_RAND_reseed(ctx, 1, entropy, sizeof(entropy), NULL, 0) ||
        EVP_RAND_reseed(ctx, 0, NULL, 0, NULL, 0) ||
        EVP_RAND_reseed(ctx, 0, entropy, sizeof(entropy), extra, sizeof(extra)))
        goto end;
    if (is_hmac) {
        if (EVP_RAND_generate(ctx, out, sizeof(out), 256, 0, extra, sizeof(extra)))
            goto end;
    } else {
        if (EVP_RAND_generate(ctx, out, 1, 256, 0, extra, sizeof(extra)))
            goto end; /* X must fit within the output provided to Bee2. */
    }
    if (!EVP_RAND_generate(ctx, out, sizeof(out), 256, 0, NULL, 0) ||
        !EVP_RAND_reseed(ctx, 0, entropy, sizeof(entropy), NULL, 0) ||
        !EVP_RAND_generate(ctx, out, sizeof(out), 256, 0, NULL, 0) ||
        !EVP_RAND_uninstantiate(ctx) || !EVP_RAND_verify_zeroization(ctx) ||
        EVP_RAND_generate(ctx, out, sizeof(out), 256, 0, NULL, 0))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "EVP_RAND contract failure for %s\n", name);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(alg);
    return ok;
}

int main(int argc, char **argv) {
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;
    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def && bee2 && check_rand("brng-ctr-hbelt", 0) &&
        check_rand("brng-hmac-hbelt", 1) && check_ctr_additional_input())
        ok = 1;
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
