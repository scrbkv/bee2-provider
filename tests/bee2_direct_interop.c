/* Compare the OpenSSL provider with Bee2, not with another provider call.
 * Test-only pseudo-randomness is deterministic and is not used for keys in
 * production.  There are no locally generated "expected KAT" constants. */
#include <bee2/core/err.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static uint32_t prng_state = 0xA516B927u;

static void test_bytes(unsigned char *buf, size_t len, int profile)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 17;
        prng_state ^= prng_state << 5;
        switch (profile) {
        case 0: buf[i] = 0; break;
        case 1: buf[i] = 0xff; break;
        case 2: buf[i] = (unsigned char)i; break;
        case 3: buf[i] = (unsigned char)(1u << (i & 7)); break;
        default: buf[i] = (unsigned char)prng_state; break;
        }
    }
}

static int same(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

typedef enum {
    MODE_ECB, MODE_CBC, MODE_CFB, MODE_CTR,
    MODE_BDE, MODE_SDE, MODE_KWP
} belt_test_mode_t;

static const struct {
    const char *name;
    belt_test_mode_t mode;
} belt_modes[] = {
    {"ecb", MODE_ECB}, {"cbc", MODE_CBC}, {"cfb", MODE_CFB},
    {"ctr", MODE_CTR}, {"bde", MODE_BDE}, {"sde", MODE_SDE},
    {"kwp", MODE_KWP}
};

static int reference_belt(belt_test_mode_t mode, unsigned char *out,
                          const unsigned char *in, size_t len,
                          const unsigned char *key, size_t keylen,
                          const unsigned char *iv)
{
    err_t err;
    switch (mode) {
    case MODE_ECB: err = beltECBEncr(out, in, len, key, keylen); break;
    case MODE_CBC: err = beltCBCEncr(out, in, len, key, keylen, iv); break;
    case MODE_CFB: err = beltCFBEncr(out, in, len, key, keylen, iv); break;
    case MODE_CTR: err = beltCTR(out, in, len, key, keylen, iv); break;
    case MODE_BDE: err = beltBDEEncr(out, in, len, key, keylen, iv); break;
    case MODE_SDE: err = beltSDEEncr(out, in, len, key, keylen, iv); break;
    case MODE_KWP: err = beltKWPWrap(out, in, len, iv, key, keylen); break;
    default: return 0;
    }
    return err == ERR_OK;
}

static int test_belt_mode(const char *name, belt_test_mode_t mode, size_t keylen,
                          size_t length, int profile)
{
    char algorithm[32];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32], iv[16], input[1024], actual[1040], expected[1040];
    size_t wanted = length + (mode == MODE_KWP ? 16u : 0u);
    int got = 0, fin = 0, ok = 0;

    (void)snprintf(algorithm, sizeof(algorithm), "belt-%s%u", name,
                   (unsigned)(keylen * 8));
    test_bytes(key, keylen, profile);
    test_bytes(iv, sizeof(iv), profile + 1);
    test_bytes(input, length, profile);
    if (!reference_belt(mode, expected, input, length, key, keylen, iv))
        goto end;

    cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key,
                            mode == MODE_ECB ? NULL : iv, NULL) <= 0)
        goto end;
    if ((mode == MODE_ECB || mode == MODE_CBC) &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) <= 0)
        goto end;
    if (EVP_EncryptUpdate(ctx, actual, &got, input, (int)length) <= 0 ||
        EVP_EncryptFinal_ex(ctx, actual + got, &fin) <= 0 ||
        (size_t)(got + fin) != wanted || !same(actual, expected, wanted))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "Bee2 mismatch: %s length=%zu profile=%d\n",
                algorithm, length, profile);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int test_belt_aead(const char *name, size_t keylen,
                          size_t length, int profile)
{
    char algorithm[32];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32], iv[16], aad[41], input[257], actual[257];
    unsigned char expected[257], tag[8], expected_tag[8];
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    int got = 0, fin = 0, ok = 0;
    err_t err;

    (void)snprintf(algorithm, sizeof(algorithm), "belt-%s%u", name,
                   (unsigned)(keylen * 8));
    test_bytes(key, keylen, profile);
    test_bytes(iv, sizeof(iv), profile + 1);
    test_bytes(aad, sizeof(aad), profile + 2);
    test_bytes(input, length, profile + 3);
    if (strcmp(name, "che") == 0)
        err = beltCHEWrap(expected, expected_tag, input, length, aad,
                          sizeof(aad), key, keylen, iv);
    else
        err = beltDWPWrap(expected, expected_tag, input, length, aad,
                          sizeof(aad), key, keylen, iv);
    if (err != ERR_OK)
        goto end;
    cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &got, aad, sizeof(aad)) <= 0 ||
        EVP_EncryptUpdate(ctx, actual, &got, input, (int)length) <= 0 ||
        got != (int)length ||
        EVP_EncryptFinal_ex(ctx, actual + got, &fin) <= 0 || fin != 0 ||
        EVP_CIPHER_CTX_get_params(ctx, params) <= 0 ||
        !same(actual, expected, length) || !same(tag, expected_tag, sizeof(tag)))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "Bee2 mismatch: %s length=%zu profile=%d\n",
                algorithm, length, profile);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int test_bash_aead(unsigned int level, unsigned int d,
                          size_t length, int profile)
{
    char algorithm[32];
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32], iv[32], aad[41], input[257];
    unsigned char actual[257], expected[257], tag[32], expected_tag[32];
    void *state = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_END
    };
    size_t n = level / 8;
    int got = 0, fin = 0, ok = 0;

    (void)snprintf(algorithm, sizeof(algorithm), "bash-prg-ae%u%u", level, d);
    test_bytes(key, n, profile);
    test_bytes(iv, n, profile + 1);
    test_bytes(aad, sizeof(aad), profile + 2);
    test_bytes(input, length, profile + 3);
    state = OPENSSL_zalloc(bashPrg_keep());
    if (state == NULL)
        goto end;
    memcpy(expected, input, length);
    bashPrgStart(state, level, d, iv, n, key, n);
    bashPrgAbsorb(aad, sizeof(aad), state);
    bashPrgEncr(expected, length, state);
    bashPrgSqueeze(expected_tag, n, state);

    cipher = EVP_CIPHER_fetch(NULL, algorithm, "provider=bee2");
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL ||
        EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &got, aad, sizeof(aad)) <= 0 ||
        EVP_EncryptUpdate(ctx, actual, &got, input, (int)length) <= 0 ||
        got != (int)length ||
        EVP_EncryptFinal_ex(ctx, actual + got, &fin) <= 0 || fin != 0)
        goto end;
    params[0].data_size = n;
    if (EVP_CIPHER_CTX_get_params(ctx, params) <= 0 ||
        !same(actual, expected, length) || !same(tag, expected_tag, n))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "Bee2 mismatch: %s length=%zu profile=%d\n",
                algorithm, length, profile);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    OPENSSL_clear_free(state, bashPrg_keep());
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int test_hash(const char *name, size_t level, size_t length, int profile)
{
    unsigned char input[1024], actual[64], expected[64];
    size_t outlen = 0, wanted = level == 0 ? 32 : level / 4;
    err_t rc;

    test_bytes(input, length, profile);
    rc = level == 0 ? beltHash(expected, input, length) :
                      bashHash(expected, level, input, length);
    return rc == ERR_OK &&
           EVP_Q_digest(NULL, name, "provider=bee2", input, length,
                        actual, &outlen) == 1 &&
           outlen == wanted && same(actual, expected, wanted);
}

static int test_mac(size_t keylen, size_t length, int profile)
{
    char name[32];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    unsigned char key[32], input[1024], actual[8], expected[8];
    size_t outlen = 0;
    int ok = 0;

    (void)snprintf(name, sizeof(name), "belt-mac%u", (unsigned)(keylen * 8));
    test_bytes(key, keylen, profile);
    test_bytes(input, length, profile + 1);
    if (beltMAC(expected, input, length, key, keylen) != ERR_OK)
        goto end;
    mac = EVP_MAC_fetch(NULL, name, "provider=bee2");
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL || EVP_MAC_init(ctx, key, keylen, NULL) <= 0 ||
        EVP_MAC_update(ctx, input, length) <= 0 ||
        EVP_MAC_final(ctx, actual, &outlen, sizeof(actual)) <= 0 ||
        outlen != sizeof(actual) || !same(actual, expected, sizeof(actual)))
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "Bee2 MAC mismatch: %s length=%zu profile=%d\n",
                name, length, profile);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    OPENSSL_cleanse(key, sizeof(key));
    return ok;
}

static int test_pbkdf_empty_inputs(const unsigned char *password,
                                    size_t password_len,
                                    const unsigned char *salt,
                                    size_t salt_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    unsigned char actual[32], expected[32];
    uint64_t iterations = 3;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                (void *)password, password_len),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,
                                (void *)salt, salt_len),
        OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (beltPBKDF2(expected, password, password_len, (size_t)iterations,
                   salt, salt_len) != ERR_OK)
        goto end;
    kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL || EVP_KDF_CTX_set_params(ctx, params) <= 0 ||
        EVP_KDF_derive(ctx, actual, sizeof(actual), NULL) <= 0 ||
        !same(actual, expected, sizeof(expected)))
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BELT-PBKDF empty-input interoperability failed\n");
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static int test_pbkdf_empty_boundaries(void)
{
    static const unsigned char password[] = "provider test password";
    static const unsigned char salt[] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
    };

    return test_pbkdf_empty_inputs(NULL, 0, NULL, 0) &&
           test_pbkdf_empty_inputs(NULL, 0, salt, sizeof(salt)) &&
           test_pbkdf_empty_inputs(password, sizeof(password) - 1, NULL, 0) &&
           test_pbkdf_empty_inputs(password, sizeof(password) - 1,
                                   salt, sizeof(salt));
}

int main(int argc, char **argv)
{
    static const size_t block_lengths[] = {16, 32, 48, 64, 256, 1024};
    static const size_t stream_lengths[] = {1, 15, 16, 17, 31, 32, 33, 65, 257, 1024};
    static const size_t kwp_lengths[] = {16, 17, 31, 32, 33, 257, 512, 513, 1024};
    static const size_t message_lengths[] = {1, 15, 16, 17, 31, 32, 33, 65, 257};
    static const size_t hash_lengths[] = {0, 1, 31, 32, 63, 64, 127, 128,
                                          143, 144, 159, 160, 257, 1024};
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i, j, k;
    int profile, ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;

    for (i = 0; i < ARRAY_SIZE(belt_modes); ++i) {
        const belt_test_mode_t mode = belt_modes[i].mode;
        const size_t *lengths = block_lengths;
        size_t count = ARRAY_SIZE(block_lengths);
        if (mode == MODE_CFB || mode == MODE_CTR) {
            lengths = stream_lengths;
            count = ARRAY_SIZE(stream_lengths);
        } else if (mode == MODE_KWP) {
            lengths = kwp_lengths;
            count = ARRAY_SIZE(kwp_lengths);
        }
        for (j = 0; j < 3; ++j) {
            for (k = 0; k < count; ++k) {
                if (mode == MODE_SDE && lengths[k] < 32)
                    continue;
                for (profile = 0; profile < 5; ++profile)
                    if (!test_belt_mode(belt_modes[i].name, mode, 16 + 8 * j,
                                        lengths[k], profile))
                        goto end;
            }
        }
    }
    for (i = 0; i < 2; ++i) {
        const char *name = i == 0 ? "che" : "dwp";
        for (j = 0; j < 3; ++j)
            for (k = 0; k < ARRAY_SIZE(message_lengths); ++k)
                for (profile = 0; profile < 5; ++profile)
                    if (!test_belt_aead(name, 16 + 8 * j, message_lengths[k], profile))
                        goto end;
    }
    for (i = 0; i < 3; ++i)
        for (j = 1; j <= 2; ++j)
            for (k = 0; k < ARRAY_SIZE(message_lengths); ++k)
                for (profile = 0; profile < 5; ++profile)
                    if (!test_bash_aead((unsigned)(128 + 64 * i), (unsigned)j,
                                        message_lengths[k], profile))
                        goto end;

    for (profile = 0; profile < 5; ++profile)
        for (k = 0; k < ARRAY_SIZE(hash_lengths); ++k) {
            const size_t n = hash_lengths[k];
            if (!test_hash("belt-hash", 0, n, profile) ||
                !test_hash("bash256", 128, n, profile) ||
                !test_hash("bash384", 192, n, profile) ||
                !test_hash("bash512", 256, n, profile))
                goto end;
            for (i = 0; i < 3; ++i)
                if (!test_mac(16 + 8 * i, n, profile))
                    goto end;
        }
    if (!test_pbkdf_empty_boundaries())
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "Bee2 direct interoperability failed\n");
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
