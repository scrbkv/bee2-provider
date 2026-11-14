/* Appendix A.19-1/2 of STB 34.101.31: BELT-DWP and BELT-CHE. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    size_t length;
    const char *ciphertext;
    const char *tag;
} vector_t;

static const vector_t vectors[] = {
    {"belt-dwp256", 16, "52C9AF96FF50F64435FC43DEF56BD797",
     "3B2E0AEB2B91854B"},
    {"belt-che256", 15, "BF3DAEAF5D18D2BCC30EA62D2E70A4",
     "548622B844123FF7"}
};

static int hex_byte(const char *s)
{
    unsigned int value = 0;
    if (sscanf(s, "%2x", &value) != 1)
        return -1;
    return (int)value;
}

static int from_hex(unsigned char *dst, size_t n, const char *hex)
{
    size_t i;

    if (strlen(hex) != 2 * n)
        return 0;
    for (i = 0; i < n; ++i) {
        int byte = hex_byte(hex + 2 * i);
        if (byte < 0)
            return 0;
        dst[i] = (unsigned char)byte;
    }
    return 1;
}

static int check_vector(const vector_t *vector)
{
    static const char *const input_hex =
        "B194BAC80A08F53B366D008E584A5DE4"
        "8504FA9D1BB6C7AC252E72C202FDCE0D"
        "5BE3D61217B96181FE6786AD716B890B";
    static const char *const key_hex =
        "E9DEE72C8F0C0FA62DDB49F46F739647"
        "06075316ED247A3739CBA38303A98BF6";
    static const char *const iv_hex = "BE32971343FC9A48A02A885F194B09A1";
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc = NULL, *dec = NULL;
    unsigned char input[48], key[32], iv[16];
    unsigned char ciphertext[48], expected[16], tag[8], expected_tag[8], recovered[48];
    OSSL_PARAM get_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    OSSL_PARAM set_tag[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, expected_tag,
                                sizeof(expected_tag)),
        OSSL_PARAM_END
    };
    int len = 0, final_len = 0, ok = 0;

    if (!from_hex(input, sizeof(input), input_hex) ||
        !from_hex(key, sizeof(key), key_hex) ||
        !from_hex(iv, sizeof(iv), iv_hex) ||
        !from_hex(expected, vector->length, vector->ciphertext) ||
        !from_hex(expected_tag, sizeof(expected_tag), vector->tag))
        goto end;
    cipher = EVP_CIPHER_fetch(NULL, vector->name, "provider=bee2");
    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();
    if (cipher == NULL || enc == NULL || dec == NULL ||
        EVP_EncryptInit_ex2(enc, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(enc, NULL, &len, input + 16, 32) <= 0 ||
        EVP_EncryptUpdate(enc, ciphertext, &len, input, (int)vector->length) <= 0 ||
        len != (int)vector->length ||
        EVP_EncryptFinal_ex(enc, ciphertext + len, &final_len) <= 0 ||
        final_len != 0 ||
        EVP_CIPHER_CTX_get_params(enc, get_tag) <= 0 ||
        CRYPTO_memcmp(ciphertext, expected, vector->length) != 0 ||
        CRYPTO_memcmp(tag, expected_tag, sizeof(tag)) != 0)
        goto end;

    if (EVP_DecryptInit_ex2(dec, cipher, key, iv, set_tag) <= 0 ||
        EVP_DecryptUpdate(dec, NULL, &len, input + 16, 32) <= 0 ||
        EVP_DecryptUpdate(dec, recovered, &len, expected, (int)vector->length) <= 0 ||
        len != (int)vector->length ||
        EVP_DecryptFinal_ex(dec, recovered + len, &final_len) <= 0 ||
        CRYPTO_memcmp(recovered, input, vector->length) != 0)
        goto end;

    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "STB AEAD KAT failed: %s\n", vector->name);
    EVP_CIPHER_CTX_free(dec);
    EVP_CIPHER_CTX_free(enc);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    return ok;
}

int main(int argc, char **argv)
{
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
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i)
        if (!check_vector(&vectors[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
