#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BRNG_IV_PARAM "iv"

static const char BELT_H_256_HEX[] = "B194BAC80A08F53B366D008E584A5DE4"
                                     "8504FA9D1BB6C7AC252E72C202FDCE0D"
                                     "5BE3D61217B96181FE6786AD716B890B"
                                     "5CB0C0FF33C356B835C405AED8E07F99"
                                     "E12BDC1AE28257EC703FCCF095EE8DF1"
                                     "C1AB76389FE678CAF7C6F860D5BB9C4F"
                                     "F33C657B637C306ADD4EA7799EB23D31"
                                     "3E98B56E27D3BCCF591E181F4C5AB793"
                                     "E9DEE72C8F0C0FA62DDB49F46F739647"
                                     "06075316ED247A3739CBA38303A98BF6"
                                     "92BD9B1CE5D141015445FBC95E4D0EF2"
                                     "682080AA227D642F2687F93490405511"
                                     "BE32971343FC9A48A02A885F194B09A1"
                                     "7ECDA4D01544AF8CA58450BF66D2E88A"
                                     "A2D7465242A8DFB36974C551EB232921"
                                     "D4EFD9B43A622875911410EA776CDA1D";

/* STB 34.101.47, Appendix B.2 */
static const char BRNG_CTR_B2_OUT_HEX[] = "1F66B5B84B7339674533F0329C74F218"
                                          "34281FED0732429E0C79235FC273E269"
                                          "4C0E74B2CD5811AD21F23DE7E0FA742C"
                                          "3ED6EC483C461CE15C33A77AA308B7D2"
                                          "0F51D91347617C20BD4AB07AEF4F26A1"
                                          "AD1362A8F9A3D42FBE1B8E6F1C88AAD5"
                                          "0A4E8298BE0839E46F19409F637F4415"
                                          "572251DD0D39284F0F0390D93BBCE9EC"
                                          "F81B29D571F6452FF8B2B97F57E18A58"
                                          "BC946FEE45EAB32B06FCAC23A33F422B"
                                          "C431B41BBE8E802288737ACF45A29251"
                                          "FC736A3C6F478F77A7ED271D5EEDAA58"
                                          "E98309303623AFD33017C42BC6D43C15"
                                          "438446EE57D46E412EFC0B61B5FBA39E"
                                          "D37BABE50BFEEB8ED162BB1393D46FB4"
                                          "3534A201EB3B1A5C085DC5068ED6F89A";

static const char BRNG_CTR_B2_IV_HEX[] = "C132971343FC9A48A02A885F194B09A1"
                                         "7ECDA4D01544AF8CA58450BF66D2E88A";

/* STB 34.101.47, Appendix B.4 */
static const char BRNG_HMAC_B4_OUT_HEX[] = "AF907A0E470A3A1B268ECCCCC0B90F23"
                                           "9FE94A2DC6E014179FC789CB3C3887E4"
                                           "695C6B96B84948F8D76924E22260859D"
                                           "B9B5FE757BEDA2E17103EE44655A9FEF"
                                           "648077CCC5002E0561C6EF512C513B8C"
                                           "24B4F3A157221CFBC1597E969778C1E4";

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;
    if (strlen(hex) != out_len * 2)
        return 0;
    for (i = 0; i < out_len; ++i) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static int assert_hex_eq(const char *label,
                         const unsigned char *actual,
                         size_t actual_len,
                         const char *expected_hex) {
    size_t i;
    const char *hex = "0123456789ABCDEF";
    char *actual_hex = malloc(actual_len * 2 + 1);
    if (!actual_hex)
        return 0;

    for (i = 0; i < actual_len; ++i) {
        actual_hex[2 * i] = hex[actual[i] >> 4];
        actual_hex[2 * i + 1] = hex[actual[i] & 0x0F];
    }
    actual_hex[actual_len * 2] = '\0';

    if (strcmp(actual_hex, expected_hex) != 0) {
        fprintf(stderr,
                "[FAIL] %s mismatch\nexpected: %s\nactual:   %s\n",
                label,
                expected_hex,
                actual_hex);
        free(actual_hex);
        return 0;
    }
    printf("[OK] %s\n", label);
    free(actual_hex);
    return 1;
}

static int run_brng_ctr_vector(const unsigned char belt_h[256]) {
    int ok = 0;
    EVP_RAND *alg = NULL;
    EVP_RAND_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM gparams[2];
    unsigned char out[256];
    unsigned char iv[32];

    alg = EVP_RAND_fetch(NULL, "brng-ctr-hbelt", "provider=bee2");
    if (!alg) {
        fprintf(stderr, "[FAIL] EVP_RAND_fetch(brng-ctr-hbelt)\n");
        goto cleanup;
    }
    ctx = EVP_RAND_CTX_new(alg, NULL);
    if (!ctx) {
        fprintf(stderr, "[FAIL] EVP_RAND_CTX_new(brng-ctr-hbelt)\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)(belt_h + 128), 32);
    params[1] = OSSL_PARAM_construct_octet_string(BRNG_IV_PARAM, (void *)(belt_h + 192), 32);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_CTX_set_params(ctx, params)) {
        fprintf(stderr, "[FAIL] EVP_RAND_CTX_set_params(brng-ctr-hbelt)\n");
        goto cleanup;
    }
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, NULL)) {
        fprintf(stderr, "[FAIL] EVP_RAND_instantiate(brng-ctr-hbelt)\n");
        goto cleanup;
    }

    if (!EVP_RAND_generate(ctx, out, 96, 256, 0, belt_h, 96)) {
        fprintf(stderr, "[FAIL] EVP_RAND_generate(brng-ctr-hbelt, first 96)\n");
        goto cleanup;
    }

    gparams[0] = OSSL_PARAM_construct_octet_string(BRNG_IV_PARAM, iv, sizeof(iv));
    gparams[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_get_params(ctx, gparams)) {
        fprintf(stderr, "[FAIL] EVP_RAND_CTX_get_params(brng-ctr-hbelt)\n");
        goto cleanup;
    }

    if (!EVP_RAND_generate(ctx, out + 96, 160, 256, 0, belt_h + 96, 160)) {
        fprintf(stderr, "[FAIL] EVP_RAND_generate(brng-ctr-hbelt, rest)\n");
        goto cleanup;
    }

    if (!assert_hex_eq(
            "STB 34.101.47 B.2 brng-ctr-hbelt output", out, sizeof(out), BRNG_CTR_B2_OUT_HEX))
        goto cleanup;
    if (!assert_hex_eq("STB 34.101.47 B.2 brng-ctr-hbelt IV", iv, sizeof(iv), BRNG_CTR_B2_IV_HEX))
        goto cleanup;

    ok = 1;

cleanup:
    if (ctx)
        EVP_RAND_uninstantiate(ctx);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(alg);
    return ok;
}

static int run_brng_hmac_vector(const unsigned char belt_h[256]) {
    int ok = 0;
    EVP_RAND *alg = NULL;
    EVP_RAND_CTX *ctx = NULL;
    OSSL_PARAM params[3];
    unsigned char out[96];

    alg = EVP_RAND_fetch(NULL, "brng-hmac-hbelt", "provider=bee2");
    if (!alg) {
        fprintf(stderr, "[FAIL] EVP_RAND_fetch(brng-hmac-hbelt)\n");
        goto cleanup;
    }
    ctx = EVP_RAND_CTX_new(alg, NULL);
    if (!ctx) {
        fprintf(stderr, "[FAIL] EVP_RAND_CTX_new(brng-hmac-hbelt)\n");
        goto cleanup;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)(belt_h + 128), 32);
    params[1] = OSSL_PARAM_construct_octet_string(BRNG_IV_PARAM, (void *)(belt_h + 192), 32);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_CTX_set_params(ctx, params)) {
        fprintf(stderr, "[FAIL] EVP_RAND_CTX_set_params(brng-hmac-hbelt)\n");
        goto cleanup;
    }
    if (!EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, NULL)) {
        fprintf(stderr, "[FAIL] EVP_RAND_instantiate(brng-hmac-hbelt)\n");
        goto cleanup;
    }

    if (!EVP_RAND_generate(ctx, out, 32, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(ctx, out + 32, 11, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(ctx, out + 43, 19, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(ctx, out + 62, 2, 256, 0, NULL, 0) ||
        !EVP_RAND_generate(ctx, out + 64, 32, 256, 0, NULL, 0)) {
        fprintf(stderr, "[FAIL] EVP_RAND_generate(brng-hmac-hbelt)\n");
        goto cleanup;
    }

    if (!assert_hex_eq(
            "STB 34.101.47 B.4 brng-hmac-hbelt output", out, sizeof(out), BRNG_HMAC_B4_OUT_HEX))
        goto cleanup;

    ok = 1;

cleanup:
    if (ctx)
        EVP_RAND_uninstantiate(ctx);
    EVP_RAND_CTX_free(ctx);
    EVP_RAND_free(alg);
    return ok;
}

static int should_run_alg(const char *selected_alg, const char *alg_name) {
    return selected_alg == NULL || strcmp(selected_alg, alg_name) == 0;
}

int main(int argc, char **argv) {
    int ret = 1;
    int ran = 0;
    unsigned char belt_h[256];
    const char *selected_alg = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *bee2_prov = NULL;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <provider-path> [brng-ctr-hbelt|brng-hmac-hbelt]\n", argv[0]);
        return 2;
    }
    if (argc == 3)
        selected_alg = argv[2];
    if (!hex_to_bytes(BELT_H_256_HEX, belt_h, sizeof(belt_h))) {
        fprintf(stderr, "[FAIL] internal vector parse error\n");
        return 1;
    }

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

    if (should_run_alg(selected_alg, "brng-ctr-hbelt")) {
        ran = 1;
        if (!run_brng_ctr_vector(belt_h))
            goto cleanup;
    }
    if (should_run_alg(selected_alg, "brng-hmac-hbelt")) {
        ran = 1;
        if (!run_brng_hmac_vector(belt_h))
            goto cleanup;
    }
    if (!ran) {
        fprintf(stderr, "[FAIL] unknown algorithm selector: %s\n", selected_alg);
        goto cleanup;
    }

    if (selected_alg)
        printf("[OK] BRNG KAT passed for %s\n", selected_alg);
    else
        printf("[OK] BRNG KAT tests passed\n");
    ret = 0;

cleanup:
    OSSL_PROVIDER_unload(bee2_prov);
    OSSL_PROVIDER_unload(default_prov);
    OPENSSL_cleanse(belt_h, sizeof(belt_h));
    return ret;
}
