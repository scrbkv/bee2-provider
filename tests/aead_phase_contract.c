/* AAD must precede data in the provider's AEAD streaming contracts. */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

static int check_phase(const char *algorithm, size_t key_len, size_t iv_len)
{
    unsigned char key[32], iv[32], in[32] = {7}, out[48], aad[7] = {1};
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t i;
    int written = 0, final_len = 0, ok = 0;

    for (i = 0; i < key_len; ++i)
        key[i] = (unsigned char)(13u * i + 5u);
    for (i = 0; i < iv_len; ++i)
        iv[i] = (unsigned char)(11u * i + 3u);
    cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (!cipher || !ctx ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &written, aad, sizeof(aad)) <= 0 ||
        EVP_EncryptUpdate(ctx, out, &written, in, sizeof(in)) <= 0 ||
        written != (int)sizeof(in))
        goto end;
    /* This is not a new AAD segment: data encryption already started. */
    if (EVP_EncryptUpdate(ctx, NULL, &written, aad, sizeof(aad)) > 0)
        goto end;

    /* A new init must permit fresh AAD followed by data and finalization. */
    if (EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &written, aad, sizeof(aad)) <= 0 ||
        EVP_EncryptUpdate(ctx, out, &written, in, sizeof(in)) <= 0 ||
        EVP_EncryptFinal_ex(ctx, out + written, &final_len) <= 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "%s: AEAD phase-order test failed\n", algorithm);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(out, sizeof(out));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    ok = def && bee2 && check_phase("belt-dwp256", 32, 16) &&
         check_phase("belt-che256", 32, 16) &&
         check_phase("bash-prg-ae1281", 16, 16) &&
         check_phase("bash-prg-ae1922", 24, 24) &&
         check_phase("bash-prg-ae2561", 32, 32);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
