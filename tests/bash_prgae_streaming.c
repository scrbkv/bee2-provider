/* BASH-PRG-AE output must not depend on EVP Update boundaries. */
#include <bee2/crypto/bash.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#define AAD_SIZE 257
#define TEXT_SIZE 401
#define MAX_TAG_SIZE 32

static size_t next_chunk(size_t remaining, unsigned int plan, size_t index)
{
    static const size_t pieces[] = {1, 2, 15, 16, 17, 31, 32, 63, 64, 127, 128, 3, 7};
    size_t chunk;

    if (plan == 0)
        chunk = remaining;
    else if (plan == 1)
        chunk = 1;
    else
        chunk = pieces[index % (sizeof(pieces) / sizeof(pieces[0]))];
    return chunk < remaining ? chunk : remaining;
}

static int crypt(EVP_CIPHER *cipher, int enc,
                 const unsigned char *key, const unsigned char *iv,
                 const unsigned char *aad, size_t aad_len,
                 const unsigned char *input, size_t input_len,
                 unsigned char *output, unsigned char *tag, size_t tag_len,
                 unsigned int aad_plan, unsigned int text_plan)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    OSSL_PARAM tag_params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, tag_len),
        OSSL_PARAM_END
    };
    size_t pos, part, index;
    int written, final_len, ok = 0;

    if (ctx == NULL ||
        EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, NULL) != 1)
        goto end;

    for (pos = 0, index = 0; pos < aad_len; pos += part, ++index) {
        part = next_chunk(aad_len - pos, aad_plan, index);
        if (EVP_CipherUpdate(ctx, NULL, &written, aad + pos, (int)part) != 1 ||
            written != 0)
            goto end;
    }
    for (pos = 0, index = 0; pos < input_len; pos += part, ++index) {
        part = next_chunk(input_len - pos, text_plan, index);
        if (EVP_CipherUpdate(ctx, output + pos, &written,
                             input + pos, (int)part) != 1 ||
            written != (int)part)
            goto end;
    }
    if (!enc && EVP_CIPHER_CTX_set_params(ctx, tag_params) != 1)
        goto end;
    if (EVP_CipherFinal_ex(ctx, output + input_len, &final_len) != 1 || final_len != 0)
        goto end;
    if (enc && EVP_CIPHER_CTX_get_params(ctx, tag_params) != 1)
        goto end;
    ok = 1;

end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Check an empty message against the STB command sequence, not just against
 * a second EVP operation using the same provider. */
static int check_empty_reference(EVP_CIPHER *cipher, size_t key_len, size_t d)
{
    unsigned char key[32], iv[32], aad[17], expected[32], tag[32], data[1] = {0};
    void *state = OPENSSL_malloc(bashPrg_keep());
    size_t i, aad_len;
    int ok = 0;

    if (state == NULL)
        return 0;
    for (i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)(i * 7 + 3);
        iv[i] = (unsigned char)(i * 11 + 5);
    }
    for (i = 0; i < sizeof(aad); ++i)
        aad[i] = (unsigned char)(i * 13 + 17);

    for (aad_len = 0; aad_len <= sizeof(aad); aad_len += sizeof(aad)) {
        bashPrgStart(state, key_len * 8, d, iv, key_len, key, key_len);
        if (aad_len != 0)
            bashPrgAbsorb(aad, aad_len, state);
        bashPrgEncr(data, 0, state);
        bashPrgSqueeze(expected, key_len, state);

        if (!crypt(cipher, 1, key, iv, aad, aad_len, data, 0,
                   data, tag, key_len, 0, 0) ||
            CRYPTO_memcmp(tag, expected, key_len) != 0 ||
            !crypt(cipher, 0, key, iv, aad, aad_len, data, 0,
                   data, tag, key_len, 0, 0))
            goto end;
        tag[0] ^= 1;
        if (crypt(cipher, 0, key, iv, aad, aad_len, data, 0,
                  data, tag, key_len, 0, 0))
            goto end;
    }
    ok = 1;
end:
    OPENSSL_clear_free(state, bashPrg_keep());
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(tag, sizeof(tag));
    return ok;
}

static int check_variant(const char *name, size_t key_len, size_t iv_len, size_t d)
{
    unsigned char key[MAX_TAG_SIZE], iv[MAX_TAG_SIZE];
    unsigned char aad[AAD_SIZE], plain[TEXT_SIZE];
    unsigned char expected[TEXT_SIZE + 1], output[TEXT_SIZE + 1];
    unsigned char recovered[TEXT_SIZE + 1];
    unsigned char tag[MAX_TAG_SIZE], other_tag[MAX_TAG_SIZE];
    unsigned int aad_plan, text_plan;
    EVP_CIPHER *cipher = NULL;
    size_t i;
    int ok = 0;

    for (i = 0; i < sizeof(key); ++i)
        key[i] = (unsigned char)(i * 7 + 3);
    for (i = 0; i < sizeof(iv); ++i)
        iv[i] = (unsigned char)(i * 11 + 5);
    for (i = 0; i < sizeof(aad); ++i)
        aad[i] = (unsigned char)(i * 13 + 17);
    for (i = 0; i < sizeof(plain); ++i)
        plain[i] = (unsigned char)(i * 19 + 23);

    cipher = EVP_CIPHER_fetch(NULL, name, "provider=bee2");
    if (cipher == NULL || EVP_CIPHER_get_key_length(cipher) != (int)key_len ||
        EVP_CIPHER_get_iv_length(cipher) != (int)iv_len ||
        !crypt(cipher, 1, key, iv, aad, sizeof(aad), plain, sizeof(plain),
               expected, tag, key_len, 0, 0))
        goto end;

    for (aad_plan = 0; aad_plan < 3; ++aad_plan) {
        for (text_plan = 0; text_plan < 3; ++text_plan) {
            if (!crypt(cipher, 1, key, iv, aad, sizeof(aad), plain, sizeof(plain),
                       output, other_tag, key_len, aad_plan, text_plan) ||
                CRYPTO_memcmp(output, expected, sizeof(plain)) != 0 ||
                CRYPTO_memcmp(other_tag, tag, key_len) != 0 ||
                !crypt(cipher, 0, key, iv, aad, sizeof(aad), expected, sizeof(plain),
                       recovered, other_tag, key_len, text_plan, aad_plan) ||
                CRYPTO_memcmp(recovered, plain, sizeof(plain)) != 0)
                goto end;
        }
    }

    /* In-place processing and a different AAD/text boundary on decryption. */
    memcpy(output, plain, sizeof(plain));
    if (!crypt(cipher, 1, key, iv, aad, sizeof(aad), output, sizeof(plain),
               output, other_tag, key_len, 2, 1) ||
        CRYPTO_memcmp(output, expected, sizeof(plain)) != 0 ||
        CRYPTO_memcmp(other_tag, tag, key_len) != 0)
        goto end;
    memcpy(recovered, expected, sizeof(plain));
    if (!crypt(cipher, 0, key, iv, aad, sizeof(aad), recovered, sizeof(plain),
               recovered, other_tag, key_len, 1, 2) ||
        CRYPTO_memcmp(recovered, plain, sizeof(plain)) != 0)
        goto end;

    /* A wrong tag must be rejected regardless of the Update split. */
    memcpy(other_tag, tag, key_len);
    other_tag[0] ^= 1;
    if (crypt(cipher, 0, key, iv, aad, sizeof(aad), expected, sizeof(plain),
              recovered, other_tag, key_len, 1, 2))
        goto end;

    /* Empty AAD and empty plaintext must match the Bee2 STB commands. */
    if (!check_empty_reference(cipher, key_len, d))
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "%s: BASH-PRG-AE streaming contract failed\n", name);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plain, sizeof(plain));
    OPENSSL_cleanse(output, sizeof(output));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(other_tag, sizeof(other_tag));
    return ok;
}

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        size_t key_len;
        size_t iv_len;
        size_t d;
    } variants[] = {
        {"bash-prg-ae1281", 16, 16, 1}, {"bash-prg-ae1282", 16, 16, 2},
        {"bash-prg-ae1921", 24, 24, 1}, {"bash-prg-ae1922", 24, 24, 2},
        {"bash-prg-ae2561", 32, 32, 1}, {"bash-prg-ae2562", 32, 32, 2}
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
    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        if (!check_variant(variants[i].name, variants[i].key_len,
                           variants[i].iv_len, variants[i].d))
            goto end;
    }
    ok = 1;

end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
