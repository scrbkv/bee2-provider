/* BELT-SDE requires at least two 16-byte blocks per sector. */
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL, *bee2_provider = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32] = {0}, iv[16] = {0};
    unsigned char input[32] = {0}, output[48] = {0};
    int outlen = 0, finlen = 0;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        goto done;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    bee2_provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (default_provider == NULL || bee2_provider == NULL)
        goto done;

    cipher = EVP_CIPHER_fetch(NULL, "belt-sde256", "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL)
        goto done;
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        goto done;
    if (EVP_EncryptUpdate(ctx, output, &outlen, input, 16) > 0) {
        fputs("BELT-SDE accepted an invalid 16-byte sector\n", stderr);
        goto done;
    }

    /* Reinitialize after a rejected operation and check the valid boundary. */
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) ||
        !EVP_EncryptUpdate(ctx, output, &outlen, input, 32) || outlen != 32 ||
        !EVP_EncryptFinal_ex(ctx, output + outlen, &finlen) || finlen != 0)
        goto done;
    ok = 1;

done:
    if (!ok)
        fputs("BELT-SDE minimum-sector contract failed\n", stderr);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(bee2_provider);
    OSSL_PROVIDER_unload(default_provider);
    return ok ? 0 : 1;
}
