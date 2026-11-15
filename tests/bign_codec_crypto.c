/* BIGN key serialization, including encrypted PKCS#8 PEM and DER. */
#include <limits.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static const unsigned char password[] = "bee2-key-roundtrip";
static const unsigned char wrong_password[] = "incorrect-password";

static EVP_PKEY *generate_key(const char *name)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    EVP_PKEY *key = NULL;

    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int decode_key(EVP_PKEY **key, const char *format, const BUF_MEM *data,
                      const unsigned char *pass, size_t passlen)
{
    OSSL_DECODER_CTX *ctx = NULL;
    BIO *input = NULL;
    int ok = 0;

    if (data->length > INT_MAX)
        return 0;
    ctx = OSSL_DECODER_CTX_new_for_pkey(key, format, NULL, "bign",
                                        OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
    input = BIO_new_mem_buf(data->data, (int)data->length);
    if (ctx == NULL || input == NULL ||
        !OSSL_DECODER_CTX_set_passphrase(ctx, pass, passlen))
        goto cleanup;
    ok = OSSL_DECODER_from_bio(ctx, input) > 0;

cleanup:
    BIO_free(input);
    OSSL_DECODER_CTX_free(ctx);
    return ok;
}

static int same_private_key(EVP_PKEY *left, EVP_PKEY *right)
{
    unsigned char first[64], second[64];
    size_t first_len = 0, second_len = 0;
    int ok;

    ok = EVP_PKEY_get_octet_string_param(left, OSSL_PKEY_PARAM_PRIV_KEY,
                                         first, sizeof(first), &first_len) > 0 &&
         EVP_PKEY_get_octet_string_param(right, OSSL_PKEY_PARAM_PRIV_KEY,
                                         second, sizeof(second), &second_len) > 0 &&
         first_len == second_len && CRYPTO_memcmp(first, second, first_len) == 0 &&
         EVP_PKEY_eq(left, right) == 1;
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return ok;
}

static int check_serialization(EVP_PKEY *key, const char *format, int encrypted)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    EVP_PKEY *decoded = NULL, *invalid = NULL;
    BIO *output = NULL;
    BUF_MEM *data = NULL;
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
                                             format, "PrivateKeyInfo", "provider=bee2");
    output = BIO_new(BIO_s_mem());
    if (encoder == NULL || output == NULL)
        goto cleanup;
    if (encrypted &&
        (!OSSL_ENCODER_CTX_set_cipher(encoder, "AES-256-CBC", NULL) ||
         !OSSL_ENCODER_CTX_set_passphrase(encoder, password, sizeof(password) - 1)))
        goto cleanup;
    if (!OSSL_ENCODER_to_bio(encoder, output) || !BIO_get_mem_ptr(output, &data) ||
        data == NULL || data->length == 0)
        goto cleanup;
    if (!decode_key(&decoded, format, data, password, sizeof(password) - 1) ||
        decoded == NULL || !same_private_key(key, decoded))
        goto cleanup;

    if (encrypted) {
        if (decode_key(&invalid, format, data, wrong_password,
                       sizeof(wrong_password) - 1) || invalid != NULL)
            goto cleanup;
        ERR_clear_error();
    }
    ok = 1;

cleanup:
    if (!ok) {
        fprintf(stderr, "BIGN %s PKCS#8 %s roundtrip failed\n",
                encrypted ? "encrypted" : "plain", format);
        ERR_print_errors_fp(stderr);
    }
    EVP_PKEY_free(invalid);
    EVP_PKEY_free(decoded);
    BIO_free(output);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

int main(int argc, char **argv)
{
    static const char *const names[] = {"bign-256", "bign-384", "bign-512"};
    static const char *const formats[] = {"DER", "PEM"};
    OSSL_PROVIDER *default_prov = NULL, *bee2_prov = NULL;
    EVP_PKEY *key = NULL;
    size_t i, j;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    default_prov = OSSL_PROVIDER_load(NULL, "default");
    bee2_prov = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!default_prov || !bee2_prov)
        goto cleanup;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        key = generate_key(names[i]);
        if (!key)
            goto cleanup;
        for (j = 0; j < sizeof(formats) / sizeof(formats[0]); ++j) {
            if (!check_serialization(key, formats[j], 0) ||
                !check_serialization(key, formats[j], 1))
                goto cleanup;
        }
        EVP_PKEY_free(key);
        key = NULL;
    }
    ok = 1;

cleanup:
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(key);
    OSSL_PROVIDER_unload(bee2_prov);
    OSSL_PROVIDER_unload(default_prov);
    return ok ? 0 : 1;
}
