/* STB 34.101.77 Appendix A.6 through the public OpenSSL EVP API. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int from_hex(unsigned char *data, size_t len, const char *hex)
{
    size_t i;
    unsigned int b;

    if (strlen(hex) != len * 2)
        return 0;
    for (i = 0; i < len; ++i) {
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
            return 0;
        data[i] = (unsigned char)b;
    }
    return 1;
}

static int check_prgae2561(void)
{
    static const char h_hex[] =
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
    static const char ciphertext_hex[] =
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
    static const char tag_hex[] =
        "CDE5AF6EF9A14B7D0C191B869A6343ED"
        "6A4E9AAB4EE00A579E9E682D0EC051E3";
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "bash-prg-ae2561", "provider=bee2");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char h[192], zeros[192] = {0}, output[192], expected[192];
    unsigned char tag[32], expected_tag[32];
    size_t got_ivlen;
    OSSL_PARAM get_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    int outlen = 0, final_len = 0, ok = 0, stage = 0;

    stage = 1;
    if (!from_hex(h, sizeof(h), h_hex) ||
        !from_hex(expected, sizeof(expected), ciphertext_hex) ||
        !from_hex(expected_tag, sizeof(expected_tag), tag_hex) ||
        cipher == NULL || ctx == NULL)
        goto end;
    stage = 2;
    if (EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL) <= 0)
        goto end;
    stage = 3;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL) <= 0)
        goto end;
    stage = 4;
    got_ivlen = (size_t)EVP_CIPHER_CTX_get_iv_length(ctx);
    if (got_ivlen != 16)
        goto end;
    stage = 5;
    if (EVP_EncryptInit_ex2(ctx, NULL, h + 32, h, NULL) <= 0)
        goto end;
    stage = 6;
    if (EVP_EncryptUpdate(ctx, NULL, &outlen, h + 64, 49) <= 0)
        goto end;
    stage = 7;
    if (EVP_EncryptUpdate(ctx, output, &outlen, zeros, sizeof(zeros)) <= 0 ||
        outlen != (int)sizeof(output))
        goto end;
    stage = 8;
    if (EVP_EncryptFinal_ex(ctx, output + outlen, &final_len) <= 0 ||
        final_len != 0)
        goto end;
    stage = 9;
    if (EVP_CIPHER_CTX_get_params(ctx, get_tag) <= 0)
        goto end;
    stage = 10;
    if (CRYPTO_memcmp(output, expected, sizeof(output)) != 0 ||
        CRYPTO_memcmp(tag, expected_tag, sizeof(tag)) != 0)
        goto end;
    ok = 1;
end:
    if (!ok) {
        fprintf(stderr, "STB 34.101.77 A.6 EVP BASH-PRGAE2561 KAT failed at stage %d\n", stage);
        if (stage == 10) {
            size_t i;
            fprintf(stderr, "ciphertext first 16: ");
            for (i = 0; i < 16; ++i)
                fprintf(stderr, "%02X", output[i]);
            fprintf(stderr, "\nexpected first 16: ");
            for (i = 0; i < 16; ++i)
                fprintf(stderr, "%02X", expected[i]);
            fprintf(stderr, "\n");
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(h, sizeof(h));
    OPENSSL_cleanse(output, sizeof(output));
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
    if (def != NULL && bee2 != NULL && check_prgae2561())
        ok = 1;
    if (!ok)
        fprintf(stderr, "STB 34.101.77 A.6 EVP KAT failed\n");
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
