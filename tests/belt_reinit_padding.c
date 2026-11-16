/* Reinitialising an EVP cipher resets the active operation before parameters. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#define BLOCK 16

static int check_cipher(const char *name)
{
    unsigned char key[32] = {0}, iv[BLOCK] = {0};
    unsigned char input[2 * BLOCK] = {0};
    unsigned char encrypted[3 * BLOCK] = {0};
    unsigned int padding_off = 0, padding_on = 1, bad_padding = 2;
    OSSL_PARAM off[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &padding_off), OSSL_PARAM_END
    };
    OSSL_PARAM on[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &padding_on), OSSL_PARAM_END
    };
    OSSL_PARAM bad[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, &bad_padding), OSSL_PARAM_END
    };
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    size_t i;
    int n = 0, final_len = 0, ok = 0, stage = 0;

    for (i = 0; i < sizeof(key); ++i)
        key[i] = (unsigned char)(i * 7 + 1);
    for (i = 0; i < sizeof(iv); ++i)
        iv[i] = (unsigned char)(i * 3 + 5);
    for (i = 0; i < sizeof(input); ++i)
        input[i] = (unsigned char)(i * 11 + 9);

    /* Start a padded operation to set the provider's "started" flag. */
    stage = 1;
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, BLOCK) != 1 ||
        EVP_CIPHER_CTX_set_params(ctx, off) != 0)
        goto end;

    /* A fresh Init may change padding even after the previous Update.
     * Use direct provider parameters above: EVP_CIPHER_CTX_set_padding()
     * changes EVP's NO_PADDING flag even if the provider rejects it. */
    stage = 2;
    if (EVP_EncryptInit_ex2(ctx, NULL, key, iv, off) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, sizeof(input)) != 1 ||
        n != (int)sizeof(input) ||
        EVP_EncryptFinal_ex(ctx, encrypted + n, &final_len) != 1 || final_len != 0)
        goto end;

    stage = 3;
    if (EVP_EncryptInit_ex2(ctx, NULL, key, iv, on) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, sizeof(input)) != 1 ||
        n != (int)sizeof(input) ||
        EVP_EncryptFinal_ex(ctx, encrypted + n, &final_len) != 1 || final_len != BLOCK)
        goto end;

    /* Reject invalid parameters and prevent use of the preceding operation. */
    stage = 4;
    if (EVP_EncryptInit_ex2(ctx, NULL, key, iv, on) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, BLOCK) != 1 ||
        EVP_EncryptInit_ex2(ctx, NULL, key, iv, bad) == 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, BLOCK) == 1 ||
        EVP_EncryptInit_ex2(ctx, NULL, key, iv, off) != 1 ||
        EVP_EncryptUpdate(ctx, encrypted, &n, input, sizeof(input)) != 1 ||
        n != (int)sizeof(input) ||
        EVP_EncryptFinal_ex(ctx, encrypted + n, &final_len) != 1 || final_len != 0)
        goto end;

    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "%s: padding reinitialisation contract failed (stage %d)\n",
                name, stage);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const names[] = {
        "belt-ecb128", "belt-ecb192", "belt-ecb256",
        "belt-cbc128", "belt-cbc192", "belt-cbc256"
    };
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
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!check_cipher(names[i]))
            goto end;
    }
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
