/* STB 34.101.77 Appendix A.4: BASH-PRG-AE1281 encryption segment.
 * Appendix A.6 is independently checked via the public EVP API in
 * bash_prgae_evp_stb.c.  Do not duplicate the A.6 vector or call provider
 * internals just to exercise the same result twice.
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int hex_bytes(unsigned char *out, size_t size, const char *hex)
{
    size_t i;
    unsigned int value;

    if (strlen(hex) != size * 2)
        return 0;
    for (i = 0; i < size; ++i) {
        if (sscanf(hex + 2 * i, "%2x", &value) != 1)
            return 0;
        out[i] = (unsigned char)value;
    }
    return 1;
}

static int check_bash_1281(void)
{
    /* STB 34.101.77 A.4.beta: PRG encryption segment (23 bytes). */
    static const char *const key_hex = "71CC358A0D5082173DE04803F7E905CB";
    static const char *const iv_hex = "E9DEE72C8F0C0FA62DDB49F46F739647";
    static const char *const data_hex =
        "92BD9B1CE5D141015445FBC95E4D0EF2"
        "682080AA227D64";
    static const char *const ciphertext_hex =
        "51ED3B28D345FFD1AD22815B86ECC17C"
        "278C8FE8920214";
    unsigned char key[16], iv[16], plaintext[23], expected[23], ciphertext[23];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int output_len = 0, final_len = 0, ok = 0;

    if (!hex_bytes(key, sizeof(key), key_hex) ||
        !hex_bytes(iv, sizeof(iv), iv_hex) ||
        !hex_bytes(plaintext, sizeof(plaintext), data_hex) ||
        !hex_bytes(expected, sizeof(expected), ciphertext_hex))
        goto end;
    cipher = EVP_CIPHER_fetch(NULL, "bash-prg-ae1281", "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, ciphertext, &output_len, plaintext,
                          sizeof(plaintext)) <= 0 ||
        output_len != (int)sizeof(plaintext) ||
        EVP_EncryptFinal_ex(ctx, ciphertext + output_len, &final_len) <= 0 ||
        final_len != 0 ||
        CRYPTO_memcmp(ciphertext, expected, sizeof(ciphertext)) != 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "STB 34.101.77 A.4 BASH-PRG-AE1281 KAT failed\n");
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def != NULL && bee2 != NULL)
        ok = check_bash_1281();
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
