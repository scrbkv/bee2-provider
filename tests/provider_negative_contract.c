/* Check invalid operation sequences through the public EVP interface. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int check_cipher(const char *name, size_t keylen, size_t ivlen, int aead)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[32] = {0}, data[32] = {0};
    unsigned char output[64];
    size_t wrong_keylen = 1;
    int written = 0, tail = 0, ok = 0;
    OSSL_PARAM invalid[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &wrong_keylen),
        OSSL_PARAM_END
    };

    if (!cipher || !ctx ||
        EVP_EncryptInit_ex2(ctx, cipher, key, ivlen ? iv : NULL, NULL) <= 0 ||
        EVP_CIPHER_CTX_set_params(ctx, invalid) > 0)
        goto done;

    if (aead && EVP_EncryptUpdate(ctx, NULL, &written, data, 3) <= 0)
        goto done;
    if (EVP_EncryptUpdate(ctx, output, &written, data, 1) <= 0 ||
        written != 1 ||
        EVP_EncryptFinal_ex(ctx, output + written, &tail) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &written, data, 1) > 0 ||
        EVP_EncryptInit_ex2(ctx, NULL, key, ivlen ? iv : NULL, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &written, data, 1) <= 0 ||
        written != 1)
        goto done;

    ok = EVP_CIPHER_CTX_get_key_length(ctx) == (int)keylen;
done:
    if (!ok)
        fprintf(stderr, "Invalid EVP cipher state contract: %s\n", name);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

static int check_sde_failed_init(void)
{
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "belt-sde256", "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}, iv[16] = {0};
    unsigned char input[32] = {0}, output[32];
    size_t wrong_keylen = 16;
    int written = 0, ok = 0;
    OSSL_PARAM invalid[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, &wrong_keylen),
        OSSL_PARAM_END
    };

    if (!cipher || !ctx ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptInit_ex2(ctx, NULL, NULL, NULL, invalid) > 0 ||
        EVP_EncryptInit_ex2(ctx, NULL, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, output, &written, input, sizeof(input)) <= 0 ||
        written != (int)sizeof(input))
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BELT-SDE EVP reinitialization contract failed\n");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}


static int check_mac(void)
{
    unsigned char key[32] = {0}, output[8];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "belt-mac256", "provider=bee2");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    size_t outlen = 0;
    int ok = 0;

    if (ctx == NULL || EVP_MAC_update(ctx, key, 1) > 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) > 0 ||
        EVP_MAC_init(ctx, key, sizeof(key), NULL) <= 0 ||
        EVP_MAC_update(ctx, key, 1) <= 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) <= 0 ||
        outlen != sizeof(output) ||
        EVP_MAC_update(ctx, key, 1) > 0 ||
        EVP_MAC_final(ctx, output, &outlen, sizeof(output)) > 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "invalid BELT MAC operation order accepted\n");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ok;
}

static int check_bign_private_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "bign-256", "provider=bee2");
    EVP_PKEY *pkey = NULL;
    unsigned char zero[32] = {0};
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, zero, sizeof(zero)),
        OSSL_PARAM_END
    };
    int ok = ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0 &&
             EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) <= 0;
    if (!ok)
        fprintf(stderr, "zero BIGN private scalar was accepted\n");
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!def || !bee2)
        goto end;

    ok = check_cipher("bash-prg-ae1281", 16, 16, 1) &&
         check_cipher("bash-prg-ae1921", 24, 24, 1) &&
         check_cipher("bash-prg-ae2561", 32, 32, 1) &&
         check_cipher("belt-che256", 32, 16, 1) &&
         check_cipher("belt-dwp256", 32, 16, 1) &&
         check_cipher("belt-cfb256", 32, 16, 0) &&
         check_sde_failed_init() &&
         check_mac() && check_bign_private_key();
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
