/* STB 34.101.77 Appendix A.6: BASH-PRG-AE l=256, d=1.

   The standard's example uses a 16-byte IV, rather than the provider's
   default 32-byte EVP IV length. Call the provider dispatch directly to
   exercise the specified length without modifying the reference vector. */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
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
    static const char *const h_hex =
        "B194BAC80A08F53B366D008E584A5DE4"
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
        "682080AA227D642F2687F93490405511";
    static const char *const ciphertext_hex =
        "690673766C3E848CAC7C05169FFB7B77"
        "51E52A011040E5602573FAF991044A00"
        "4329EEF7BED8E6875830A91854D1BD2E"
        "DC6FC2FF37851DBAC249DF400A0549EA"
        "2E0C811D499E1FF1E5E32FAE7F0532FA"
        "4051D0F9E300D9B1DBF119AC8CFFC48D"
        "D3CBF1CA0DBA5DD97481C88DF0BE4127"
        "85E40988B31585537948B80F5A9C49E0"
        "8DD684A7DCA871C380DFDC4C4DFBE61F"
        "50D2D0FBD24D8B9D32974A347247D001"
        "BAD5B168440025693967E77394DC088B"
        "0ECCFA8D291BA13D44F60B06E2EDB351";
    static const char *const tag_hex =
        "CDE5AF6EF9A14B7D0C191B869A6343ED"
        "6A4E9AAB4EE00A579E9E682D0EC051E3";
    unsigned char h[192], expected_ct[192], expected_tag[32];
    unsigned char zeros[192] = {0}, ciphertext[192], tag[32];
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    const OSSL_ALGORITHM *algs = NULL;
    const OSSL_ALGORITHM *alg;
    const OSSL_DISPATCH *entry;
    OSSL_FUNC_cipher_newctx_fn *newctx = NULL;
    OSSL_FUNC_cipher_freectx_fn *freectx = NULL;
    OSSL_FUNC_cipher_encrypt_init_fn *encrypt_init = NULL;
    OSSL_FUNC_cipher_update_fn *update = NULL;
    OSSL_FUNC_cipher_final_fn *final = NULL;
    OSSL_FUNC_cipher_get_ctx_params_fn *get_ctx_params = NULL;
    void *ctx = NULL;
    size_t outlen = 0, finlen = 0;
    int no_cache = 0, ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };

    if (argc != 2)
        return 2;
    if (!hex_bytes(h, sizeof(h), h_hex) ||
        !hex_bytes(expected_ct, sizeof(expected_ct), ciphertext_hex) ||
        !hex_bytes(expected_tag, sizeof(expected_tag), tag_hex))
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        goto end;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL || !check_bash_1281())
        goto end;
    algs = OSSL_PROVIDER_query_operation(bee2, OSSL_OP_CIPHER, &no_cache);
    if (algs == NULL)
        goto end;
    for (alg = algs; alg->algorithm_names != NULL; ++alg)
        if (strstr(alg->algorithm_names, "bash-prg-ae2561") != NULL)
            break;
    if (alg->algorithm_names == NULL)
        goto end;
    for (entry = alg->implementation; entry->function_id != 0; ++entry) {
        switch (entry->function_id) {
        case OSSL_FUNC_CIPHER_NEWCTX:
            newctx = OSSL_FUNC_cipher_newctx(entry);
            break;
        case OSSL_FUNC_CIPHER_FREECTX:
            freectx = OSSL_FUNC_cipher_freectx(entry);
            break;
        case OSSL_FUNC_CIPHER_ENCRYPT_INIT:
            encrypt_init = OSSL_FUNC_cipher_encrypt_init(entry);
            break;
        case OSSL_FUNC_CIPHER_UPDATE:
            update = OSSL_FUNC_cipher_update(entry);
            break;
        case OSSL_FUNC_CIPHER_FINAL:
            final = OSSL_FUNC_cipher_final(entry);
            break;
        case OSSL_FUNC_CIPHER_GET_CTX_PARAMS:
            get_ctx_params = OSSL_FUNC_cipher_get_ctx_params(entry);
            break;
        }
    }
    if (newctx == NULL || freectx == NULL || encrypt_init == NULL ||
        update == NULL || final == NULL || get_ctx_params == NULL)
        goto end;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(bee2));
    if (ctx == NULL || !encrypt_init(ctx, h + 32, 32, h, 16, NULL) ||
        !update(ctx, NULL, &outlen, 0, h + 64, 49) ||
        !update(ctx, ciphertext, &outlen, sizeof(ciphertext),
                zeros, sizeof(zeros)) ||
        outlen != sizeof(ciphertext) ||
        !final(ctx, NULL, &finlen, 0) || finlen != 0 ||
        !get_ctx_params(ctx, params) ||
        CRYPTO_memcmp(ciphertext, expected_ct, sizeof(ciphertext)) != 0 ||
        CRYPTO_memcmp(tag, expected_tag, sizeof(tag)) != 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "STB 34.101.77 A.6 BASH-PRG-AE2561 KAT failed\n");
    if (ctx != NULL && freectx != NULL)
        freectx(ctx);
    if (algs != NULL)
        OSSL_PROVIDER_unquery_operation(bee2, OSSL_OP_CIPHER, algs);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    OPENSSL_cleanse(h, sizeof(h));
    return ok ? 0 : 1;
}
