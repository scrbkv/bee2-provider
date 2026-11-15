/* BIGN key serialization, including encrypted PKCS#8 PEM and DER. */
#include <limits.h>
#include <openssl/asn1t.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
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

static int check_public_only_decoding(EVP_PKEY *key)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    EVP_PKEY *public_key = NULL;
    BIO *output = NULL, *input = NULL;
    BUF_MEM *data = NULL;
    unsigned char original[128], decoded[128];
    size_t original_len = 0, decoded_len = 0;
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_KEYPAIR, "DER", "PrivateKeyInfo", "provider=bee2");
    output = BIO_new(BIO_s_mem());
    if (!encoder || !output || !OSSL_ENCODER_to_bio(encoder, output) ||
        !BIO_get_mem_ptr(output, &data) || !data || data->length > INT_MAX)
        goto cleanup;

    decoder = OSSL_DECODER_CTX_new_for_pkey(
        &public_key, "DER", NULL, "bign", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
    input = BIO_new_mem_buf(data->data, (int)data->length);
    if (!decoder || !input || OSSL_DECODER_from_bio(decoder, input) <= 0 ||
        !public_key || EVP_PKEY_get_octet_string_param(public_key, OSSL_PKEY_PARAM_PRIV_KEY,
                                         decoded, sizeof(decoded), &decoded_len) > 0 ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                         original, sizeof(original), &original_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(public_key, OSSL_PKEY_PARAM_PUB_KEY,
                                         decoded, sizeof(decoded), &decoded_len) <= 0 ||
        original_len != decoded_len ||
        CRYPTO_memcmp(original, decoded, original_len) != 0)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "BIGN public-only decoder exposed private key or failed\n");
    OPENSSL_cleanse(original, sizeof(original));
    OPENSSL_cleanse(decoded, sizeof(decoded));
    EVP_PKEY_free(public_key);
    BIO_free(input);
    BIO_free(output);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

static int same_private_key(EVP_PKEY *left, EVP_PKEY *right)
{
    unsigned char first[128], second[128];
    char group_left[80], group_right[80];
    size_t first_len = 0, second_len = 0;
    int ok = 0;

    if (EVP_PKEY_get_octet_string_param(left, OSSL_PKEY_PARAM_PRIV_KEY,
                                        first, sizeof(first), &first_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(right, OSSL_PKEY_PARAM_PRIV_KEY,
                                        second, sizeof(second), &second_len) <= 0 ||
        first_len != second_len || CRYPTO_memcmp(first, second, first_len) != 0)
        goto cleanup;

    if (EVP_PKEY_get_octet_string_param(left, OSSL_PKEY_PARAM_PUB_KEY,
                                        first, sizeof(first), &first_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(right, OSSL_PKEY_PARAM_PUB_KEY,
                                        second, sizeof(second), &second_len) <= 0 ||
        first_len != second_len || CRYPTO_memcmp(first, second, first_len) != 0)
        goto cleanup;

    if (EVP_PKEY_get_utf8_string_param(left, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group_left, sizeof(group_left), NULL) <= 0 ||
        EVP_PKEY_get_utf8_string_param(right, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group_right, sizeof(group_right), NULL) <= 0 ||
        strcmp(group_left, group_right) != 0)
        goto cleanup;
    ok = 1;

cleanup:
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return ok;
}

/* Verify the DER PBES2 parameters, independently of successful decryption. */
static int check_pbkdf2_params(const BUF_MEM *data)
{
    const unsigned char *p = (const unsigned char *)data->data;
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    const X509_ALGOR *algorithm = NULL;
    X509_SIG *encrypted = NULL;
    PBE2PARAM *pbes2 = NULL;
    PBKDF2PARAM *pbkdf2 = NULL;
    int type = 0, ok = 0;

    if (data->length > LONG_MAX)
        return 0;
    encrypted = d2i_X509_SIG(NULL, &p, (long)data->length);
    if (!encrypted || p != (const unsigned char *)data->data + data->length)
        goto cleanup;
    X509_SIG_get0(encrypted, &algorithm, NULL);
    X509_ALGOR_get0(&oid, &type, &value, algorithm);
    if (OBJ_obj2nid(oid) != NID_pbes2 || type != V_ASN1_SEQUENCE || !value)
        goto cleanup;
    pbes2 = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (!pbes2)
        goto cleanup;
    X509_ALGOR_get0(&oid, &type, &value, pbes2->keyfunc);
    if (OBJ_obj2nid(oid) != NID_id_pbkdf2 || type != V_ASN1_SEQUENCE || !value)
        goto cleanup;
    pbkdf2 = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
    if (!pbkdf2 || !pbkdf2->salt || !pbkdf2->iter ||
        pbkdf2->salt->type != V_ASN1_OCTET_STRING ||
        ASN1_INTEGER_get(pbkdf2->iter) != 10000 ||
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
        ASN1_STRING_get_length(pbkdf2->salt->value.octet_string) != 16u)
#else
        ASN1_STRING_length(pbkdf2->salt->value.octet_string) != 16)
#endif
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "BIGN encrypted PKCS#8 PBKDF2 parameters are incorrect\n");
    PBKDF2PARAM_free(pbkdf2);
    PBE2PARAM_free(pbes2);
    X509_SIG_free(encrypted);
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
    if ((encrypted && strcmp(format, "DER") == 0 && !check_pbkdf2_params(data)) ||
        !decode_key(&decoded, format, data, password, sizeof(password) - 1) ||
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

/* Foreign encrypted PKCS#8 objects must remain decodable when the BIGN
 * decoder is loaded alongside OpenSSL's default provider. */
static int check_foreign_key(const char *algorithm, const char *format, int encrypted)
{
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *original = NULL, *decoded = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    BIO *output = NULL, *input = NULL;
    BUF_MEM *data = NULL;
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=default");
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0)
        goto cleanup;
    if (strcmp(algorithm, "RSA") == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gen, 2048) <= 0)
            goto cleanup;
    } else if (EVP_PKEY_CTX_set_group_name(gen, "prime256v1") <= 0) {
        goto cleanup;
    }
    if (EVP_PKEY_generate(gen, &original) <= 0)
        goto cleanup;
    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        original, OSSL_KEYMGMT_SELECT_KEYPAIR, format, "PrivateKeyInfo", "provider=default");
    output = BIO_new(BIO_s_mem());
    if (!encoder || !output)
        goto cleanup;
    if (encrypted &&
        (!OSSL_ENCODER_CTX_set_cipher(encoder, "AES-256-CBC", NULL) ||
         !OSSL_ENCODER_CTX_set_passphrase(encoder, password, sizeof(password) - 1)))
        goto cleanup;
    if (!OSSL_ENCODER_to_bio(encoder, output) ||
        !BIO_get_mem_ptr(output, &data) || !data || data->length > INT_MAX)
        goto cleanup;
    decoder = OSSL_DECODER_CTX_new_for_pkey(
        &decoded, format, NULL, NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
    input = BIO_new_mem_buf(data->data, (int)data->length);
    if (!decoder || !input ||
        (encrypted && !OSSL_DECODER_CTX_set_passphrase(
                           decoder, password, sizeof(password) - 1)) ||
        OSSL_DECODER_from_bio(decoder, input) <= 0 ||
        !decoded || !EVP_PKEY_is_a(decoded, algorithm) ||
        EVP_PKEY_eq(original, decoded) != 1)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok) {
        fprintf(stderr, "%s %s %s key loading with BIGN provider failed\n",
                algorithm, format, encrypted ? "encrypted" : "plain");
        ERR_print_errors_fp(stderr);
    }
    BIO_free(input);
    BIO_free(output);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(original);
    EVP_PKEY_free(decoded);
    EVP_PKEY_CTX_free(gen);
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
        if (!check_public_only_decoding(key))
            goto cleanup;
        for (j = 0; j < sizeof(formats) / sizeof(formats[0]); ++j) {
            if (!check_serialization(key, formats[j], 0) ||
                !check_serialization(key, formats[j], 1))
                goto cleanup;
        }
        EVP_PKEY_free(key);
        key = NULL;
    }
    for (i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        if (!check_foreign_key("RSA", formats[i], 1) ||
            !check_foreign_key("EC", formats[i], 1))
            goto cleanup;
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
