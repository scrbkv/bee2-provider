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
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <stdint.h>
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

static int decode_key_limited(EVP_PKEY **key, const char *format, const BUF_MEM *data,
                              const unsigned char *pass, size_t passlen,
                              unsigned int max_iterations)
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
    if (max_iterations != 0) {
        OSSL_PARAM limit[] = {
            OSSL_PARAM_uint("stb-pbkdf2-max-decode-iterations", &max_iterations),
            OSSL_PARAM_END};

        if (!OSSL_DECODER_CTX_set_params(ctx, limit))
            goto cleanup;
    }
    ok = OSSL_DECODER_from_bio(ctx, input) > 0;

cleanup:
    BIO_free(input);
    OSSL_DECODER_CTX_free(ctx);
    return ok;
}

static int decode_key(EVP_PKEY **key, const char *format, const BUF_MEM *data,
                      const unsigned char *pass, size_t passlen)
{
    return decode_key_limited(key, format, data, pass, passlen, 0);
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

/* Check record boundaries for DER and PEM, and open-stream DER decoding. */
static int check_key_stream(EVP_PKEY *key, const char *format)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    EVP_PKEY *decoded = NULL;
    BIO *encoded = NULL, *input = NULL, *reader = NULL, *writer = NULL;
    BUF_MEM *data = NULL;
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_KEYPAIR, format, "PrivateKeyInfo", "provider=bee2");
    encoded = BIO_new(BIO_s_mem());
    if (!encoder || !encoded || !OSSL_ENCODER_to_bio(encoder, encoded) ||
        !BIO_get_mem_ptr(encoded, &data) || !data || data->length == 0 ||
        data->length > INT_MAX)
        goto cleanup;

    input = BIO_new(BIO_s_mem());
    if (!input ||
        BIO_write(input, data->data, (int)data->length) != (int)data->length ||
        BIO_write(input, data->data, (int)data->length) != (int)data->length)
        goto cleanup;

    decoder = OSSL_DECODER_CTX_new_for_pkey(
        &decoded, format, NULL, "bign", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
    if (!decoder || OSSL_DECODER_from_bio(decoder, input) <= 0 ||
        !decoded || !same_private_key(key, decoded) ||
        BIO_ctrl_pending(input) != data->length)
        goto cleanup;
    OSSL_DECODER_CTX_free(decoder);
    decoder = NULL;
    EVP_PKEY_free(decoded);
    decoded = NULL;

    decoder = OSSL_DECODER_CTX_new_for_pkey(
        &decoded, format, NULL, "bign", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
    if (!decoder || OSSL_DECODER_from_bio(decoder, input) <= 0 ||
        !decoded || !same_private_key(key, decoded) || BIO_ctrl_pending(input) != 0)
        goto cleanup;
    OSSL_DECODER_CTX_free(decoder);
    decoder = NULL;
    EVP_PKEY_free(decoded);
    decoded = NULL;

    /* OpenSSL's generic PEM decoder requires EOF on BIO pairs; the
     * provider's DER reader can finish as soon as the DER body arrives. */
    if (strcmp(format, "DER") == 0) {
        if (!BIO_new_bio_pair(&reader, 0, &writer, 0) ||
            BIO_write(writer, data->data, (int)data->length) != (int)data->length)
            goto cleanup;
        decoder = OSSL_DECODER_CTX_new_for_pkey(
            &decoded, format, NULL, "bign", OSSL_KEYMGMT_SELECT_KEYPAIR, NULL, NULL);
        if (!decoder || OSSL_DECODER_from_bio(decoder, reader) <= 0 ||
            !decoded || !same_private_key(key, decoded))
            goto cleanup;
    }
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "BIGN %s stream framing failed\n", format);
    EVP_PKEY_free(decoded);
    OSSL_DECODER_CTX_free(decoder);
    BIO_free(writer);
    BIO_free(reader);
    BIO_free(input);
    BIO_free(encoded);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

/* Verify the DER PBES2 parameters, independently of successful decryption. */
static int check_pbkdf2_params(const BUF_MEM *data, const char *kwp_oid,
                               size_t key_len)
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
        ASN1_INTEGER_get(pbkdf2->iter) != 12000 ||
        !pbkdf2->keylength || ASN1_INTEGER_get(pbkdf2->keylength) != (long)key_len ||
        !pbkdf2->prf ||
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
        ASN1_STRING_get_length(pbkdf2->salt->value.octet_string) != 24u)
#else
        ASN1_STRING_length(pbkdf2->salt->value.octet_string) != 24)
#endif
        goto cleanup;
    {
        char oid_text[80];

        X509_ALGOR_get0(&oid, &type, &value, pbkdf2->prf);
        if (OBJ_obj2txt(oid_text, sizeof(oid_text), oid, 1) <= 0 ||
            strcmp(oid_text, "1.2.112.0.2.0.34.101.47.12") != 0)
            goto cleanup;
        X509_ALGOR_get0(&oid, &type, &value, pbes2->encryption);
        if (OBJ_obj2txt(oid_text, sizeof(oid_text), oid, 1) <= 0 ||
            strcmp(oid_text, kwp_oid) != 0 || type != V_ASN1_UNDEF)
            goto cleanup;
    }
    ok = 1;

cleanup:
    if (!ok)
        fprintf(stderr, "BIGN encrypted PKCS#8 PBKDF2 parameters are incorrect\n");
    PBKDF2PARAM_free(pbkdf2);
    PBE2PARAM_free(pbes2);
    X509_SIG_free(encrypted);
    return ok;
}


/* Exercise structurally valid PBES2 mutations through the public decoder.
 * keyLength is optional; KWP parameters may be absent or ASN.1 NULL. */
static int set_test_alg(X509_ALGOR *algorithm, const char *oid, int type, void *value)
{
    ASN1_OBJECT *object = OBJ_txt2obj(oid, 1);

    if (object == NULL)
        return 0;
    if (!X509_ALGOR_set0(algorithm, object, type, value)) {
        ASN1_OBJECT_free(object);
        return 0;
    }
    return 1;
}

static int check_pbes2_variants(const BUF_MEM *data, EVP_PKEY *key)
{
    enum { BAD_ITER, BAD_SALT, BAD_KEYLEN, BAD_PRF, BAD_KDF, NO_PRF,
           NO_KEYLEN, NULL_KWP, BAD_KWP, COUNT };
    static const char *const cases[] = {
        "iterations", "salt", "keyLength", "PRF", "KDF", "missing PRF",
        "missing keyLength", "NULL KWP parameters", "bad KWP parameters"
    };
    int variation;

    if (data->length > LONG_MAX)
        return 0;
    for (variation = 0; variation < COUNT; ++variation) {
        const unsigned char *p = (const unsigned char *)data->data;
        const ASN1_OBJECT *oid = NULL;
        const void *value = NULL;
        X509_SIG *encrypted = NULL;
        X509_ALGOR *outer = NULL;
        ASN1_OCTET_STRING *ciphertext = NULL;
        PBE2PARAM *pbes2 = NULL;
        PBKDF2PARAM *pbkdf2 = NULL;
        ASN1_STRING *kdf_der = NULL, *pbe_der = NULL;
        EVP_PKEY *decoded = NULL;
        BUF_MEM candidate = {0};
        unsigned char *der = NULL;
        char cipher_oid[96];
        int type = 0, der_len = 0, ok = 0;
        int expected = variation == NO_KEYLEN || variation == NULL_KWP;

        encrypted = d2i_X509_SIG(NULL, &p, (long)data->length);
        if (encrypted == NULL || p != (const unsigned char *)data->data + data->length)
            goto next;
        X509_SIG_getm(encrypted, &outer, &ciphertext);
        X509_ALGOR_get0(&oid, &type, &value, outer);
        if (type != V_ASN1_SEQUENCE || value == NULL)
            goto next;
        pbes2 = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
        if (pbes2 == NULL)
            goto next;
        X509_ALGOR_get0(&oid, &type, &value, pbes2->encryption);
        if (OBJ_obj2txt(cipher_oid, sizeof(cipher_oid), oid, 1) <= 0)
            goto next;
        X509_ALGOR_get0(&oid, &type, &value, pbes2->keyfunc);
        if (type != V_ASN1_SEQUENCE || value == NULL)
            goto next;
        pbkdf2 = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBKDF2PARAM));
        if (pbkdf2 == NULL)
            goto next;
        switch (variation) {
        case BAD_ITER:
            if (!ASN1_INTEGER_set(pbkdf2->iter, 1))
                goto next;
            break;
        case BAD_SALT:
            if (!ASN1_OCTET_STRING_set(pbkdf2->salt->value.octet_string,
                                       (const unsigned char *)"bad", 3))
                goto next;
            break;
        case BAD_KEYLEN:
            if (pbkdf2->keylength == NULL ||
                !ASN1_INTEGER_set(pbkdf2->keylength, 15))
                goto next;
            break;
        case BAD_PRF:
            if (!set_test_alg(pbkdf2->prf, "1.2.840.113549.2.9", V_ASN1_NULL, NULL))
                goto next;
            break;
        case NO_PRF:
            X509_ALGOR_free(pbkdf2->prf);
            pbkdf2->prf = NULL;
            break;
        case NO_KEYLEN:
            ASN1_INTEGER_free(pbkdf2->keylength);
            pbkdf2->keylength = NULL;
            break;
        case NULL_KWP:
            if (!set_test_alg(pbes2->encryption, cipher_oid, V_ASN1_NULL, NULL))
                goto next;
            break;
        case BAD_KWP: {
            ASN1_OCTET_STRING *invalid = ASN1_OCTET_STRING_new();

            if (invalid == NULL)
                goto next;
            if (!ASN1_OCTET_STRING_set(invalid, (const unsigned char *)"bad", 3) ||
                !set_test_alg(pbes2->encryption, cipher_oid,
                              V_ASN1_OCTET_STRING, invalid)) {
                ASN1_OCTET_STRING_free(invalid);
                goto next;
            }
            break;
        }
        default:
            break;
        }
        kdf_der = ASN1_item_pack(pbkdf2, ASN1_ITEM_rptr(PBKDF2PARAM), NULL);
        if (kdf_der == NULL ||
            !set_test_alg(pbes2->keyfunc,
                          variation == BAD_KDF ? "1.2.840.113549.2.9" :
                                                 "1.2.840.113549.1.5.12",
                          V_ASN1_SEQUENCE, kdf_der))
            goto next;
        kdf_der = NULL;
        pbe_der = ASN1_item_pack(pbes2, ASN1_ITEM_rptr(PBE2PARAM), NULL);
        if (pbe_der == NULL ||
            !set_test_alg(outer, "1.2.840.113549.1.5.13", V_ASN1_SEQUENCE, pbe_der))
            goto next;
        pbe_der = NULL;
        der_len = i2d_X509_SIG(encrypted, &der);
        if (der_len <= 0 || der == NULL)
            goto next;
        candidate.data = (char *)der;
        candidate.length = (size_t)der_len;
        {
            int accepted = decode_key(&decoded, "DER", &candidate,
                                      password, sizeof(password) - 1) && decoded != NULL;

            if (accepted != expected || (accepted && !same_private_key(key, decoded)))
                goto next;
        }
        ok = 1;
next:
        if (!ok)
            fprintf(stderr, "BIGN PBES2 mutated DER: %s\n", cases[variation]);
        EVP_PKEY_free(decoded);
        OPENSSL_free(der);
        ASN1_STRING_free(pbe_der);
        ASN1_STRING_free(kdf_der);
        PBKDF2PARAM_free(pbkdf2);
        PBE2PARAM_free(pbes2);
        X509_SIG_free(encrypted);
        ERR_clear_error();
        if (!ok)
            return 0;
    }
    return 1;
}


/* A valid KWP authentication tag must not make trailing plaintext bytes
 * acceptable after the PKCS#8 DER object. PKCS8_decrypt_ex() alone does
 * not guarantee that its ASN.1 decoder consumed the entire plaintext. */
static int check_pbes2_plaintext_trailing_der(const BUF_MEM *encoded, EVP_PKEY *key)
{
    const unsigned char *p = (const unsigned char *)encoded->data;
    const ASN1_OBJECT *oid = NULL;
    const void *value = NULL;
    X509_SIG *sig = NULL;
    PBE2PARAM *pbe = NULL;
    PBKDF2PARAM *pbkdf2 = NULL;
    X509_ALGOR *outer = NULL;
    ASN1_OCTET_STRING *ciphertext = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    EVP_PKEY *unexpected = NULL;
    BIO *plain_bio = NULL;
    BUF_MEM *plain = NULL;
    unsigned char derived[32] = {0};
    unsigned char *invalid_plain = NULL, *wrapped = NULL, *mutated = NULL;
    const unsigned char *salt = NULL;
    const char *cipher_name;
    size_t salt_len, key_len;
    uint64_t iterations;
    int bits = EVP_PKEY_get_bits(key);
    int typ, part = 0, last = 0, mutated_len = 0, ok = 0;
    BUF_MEM candidate = {0};

    key_len = bits == 256 ? 16u : bits == 384 ? 24u : bits == 512 ? 32u : 0;
    cipher_name = bits == 256 ? "belt-kwp128" :
                  bits == 384 ? "belt-kwp192" : "belt-kwp256";
    if (key_len == 0 || encoded->length > LONG_MAX)
        goto end;
    sig = d2i_X509_SIG(NULL, &p, (long)encoded->length);
    if (sig == NULL || p != (const unsigned char *)encoded->data + encoded->length)
        goto end;
    X509_SIG_getm(sig, &outer, &ciphertext);
    if (outer == NULL || ciphertext == NULL)
        goto end;
    X509_ALGOR_get0(&oid, &typ, &value, outer);
    if (OBJ_obj2nid(oid) != NID_pbes2 ||
        typ != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    pbe = ASN1_item_unpack((const ASN1_STRING *)value, ASN1_ITEM_rptr(PBE2PARAM));
    if (pbe == NULL)
        goto end;
    X509_ALGOR_get0(&oid, &typ, &value, pbe->keyfunc);
    if (OBJ_obj2nid(oid) != NID_id_pbkdf2 ||
        typ != V_ASN1_SEQUENCE || value == NULL)
        goto end;
    pbkdf2 = ASN1_item_unpack((const ASN1_STRING *)value,
                              ASN1_ITEM_rptr(PBKDF2PARAM));
    if (pbkdf2 == NULL || pbkdf2->salt == NULL ||
        pbkdf2->salt->type != V_ASN1_OCTET_STRING ||
        pbkdf2->salt->value.octet_string == NULL ||
        pbkdf2->iter == NULL)
        goto end;
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    salt_len = ASN1_STRING_get_length(pbkdf2->salt->value.octet_string);
#else
    typ = ASN1_STRING_length(pbkdf2->salt->value.octet_string);
    if (typ <= 0)
        goto end;
    salt_len = (size_t)typ;
#endif
    if (salt_len == 0 || salt_len > INT_MAX ||
        ASN1_INTEGER_get(pbkdf2->iter) <= 0)
        goto end;
    salt = ASN1_STRING_get0_data(pbkdf2->salt->value.octet_string);
    iterations = (uint64_t)ASN1_INTEGER_get(pbkdf2->iter);

    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_KEYPAIR, "DER", "PrivateKeyInfo", "provider=bee2");
    plain_bio = BIO_new(BIO_s_mem());
    if (encoder == NULL || plain_bio == NULL ||
        OSSL_ENCODER_to_bio(encoder, plain_bio) <= 0 ||
        BIO_get_mem_ptr(plain_bio, &plain) <= 0 || plain == NULL ||
        plain->length > INT_MAX - 32)
        goto end;
    invalid_plain = OPENSSL_malloc(plain->length + 1);
    wrapped = OPENSSL_malloc(plain->length + 33);
    if (invalid_plain == NULL || wrapped == NULL)
        goto end;
    memcpy(invalid_plain, plain->data, plain->length);
    invalid_plain[plain->length] = 0;

    kdf = EVP_KDF_fetch(NULL, "belt-pbkdf", "provider=bee2");
    kdf_ctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
    cipher = EVP_CIPHER_fetch(NULL, cipher_name, "provider=bee2");
    cipher_ctx = cipher != NULL ? EVP_CIPHER_CTX_new() : NULL;
    if (kdf_ctx == NULL || cipher_ctx == NULL)
        goto end;
    {
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD, (void *)password, sizeof(password) - 1),
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
            OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iterations),
            OSSL_PARAM_construct_end()
        };

        if (EVP_KDF_derive(kdf_ctx, derived, sizeof(derived), params) <= 0)
            goto end;
    }
    if (EVP_CipherInit_ex2(cipher_ctx, cipher, derived, NULL, 1, NULL) <= 0 ||
        EVP_CipherUpdate(cipher_ctx, wrapped, &part,
                         invalid_plain, (int)(plain->length + 1)) <= 0 ||
        EVP_CipherFinal_ex(cipher_ctx, wrapped + part, &last) <= 0 ||
        !ASN1_OCTET_STRING_set(ciphertext, wrapped, part + last))
        goto end;
    mutated_len = i2d_X509_SIG(sig, &mutated);
    if (mutated_len <= 0 || mutated == NULL)
        goto end;
    candidate.data = (char *)mutated;
    candidate.length = (size_t)mutated_len;
    if (decode_key(&unexpected, "DER", &candidate,
                   password, sizeof(password) - 1) || unexpected != NULL)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN PBES2 accepted authenticated trailing DER data\n");
    ERR_clear_error();
    EVP_PKEY_free(unexpected);
    OPENSSL_free(mutated);
    OPENSSL_clear_free(wrapped, plain != NULL ? plain->length + 33 : 0);
    OPENSSL_clear_free(invalid_plain, plain != NULL ? plain->length + 1 : 0);
    OPENSSL_cleanse(derived, sizeof(derived));
    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_CIPHER_free(cipher);
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    BIO_free(plain_bio);
    OSSL_ENCODER_CTX_free(encoder);
    PBKDF2PARAM_free(pbkdf2);
    PBE2PARAM_free(pbe);
    X509_SIG_free(sig);
    return ok;
}

static int check_serialization(EVP_PKEY *key, const char *format, int encrypted)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    EVP_PKEY *decoded = NULL, *invalid = NULL, *limited = NULL;
    BIO *output = NULL;
    BUF_MEM *data = NULL;
    int bits = EVP_PKEY_get_bits(key);
    const char *cipher = bits == 256 ? "belt-kwp128" :
                         bits == 384 ? "belt-kwp192" : "belt-kwp256";
    const char *oid = bits == 256 ? "1.2.112.0.2.0.34.101.31.71" :
                      bits == 384 ? "1.2.112.0.2.0.34.101.31.72" :
                                    "1.2.112.0.2.0.34.101.31.73";
    size_t key_len = bits == 256 ? 16u : bits == 384 ? 24u : 32u;
    unsigned int iterations = 12000, too_few_iterations = 9999;
    size_t salt_length = 24, too_short_salt = 7;
    OSSL_PARAM settings[] = {
        OSSL_PARAM_uint("stb-pbkdf2-iterations", &iterations),
        OSSL_PARAM_size_t("stb-pbkdf2-saltlen", &salt_length),
        OSSL_PARAM_END};
    OSSL_PARAM invalid_iter[] = {
        OSSL_PARAM_uint("stb-pbkdf2-iterations", &too_few_iterations),
        OSSL_PARAM_END};
    OSSL_PARAM invalid_salt[] = {
        OSSL_PARAM_size_t("stb-pbkdf2-saltlen", &too_short_salt),
        OSSL_PARAM_END};
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR,
                                             format, "PrivateKeyInfo", "provider=bee2");
    output = BIO_new(BIO_s_mem());
    if (encoder == NULL || output == NULL)
        goto cleanup;
    if (encrypted &&
        (OSSL_ENCODER_CTX_set_params(encoder, invalid_iter) > 0 ||
         OSSL_ENCODER_CTX_set_params(encoder, invalid_salt) > 0 ||
         !OSSL_ENCODER_CTX_set_params(encoder, settings) ||
         !OSSL_ENCODER_CTX_set_cipher(encoder, cipher, NULL) ||
         !OSSL_ENCODER_CTX_set_passphrase(encoder, password, sizeof(password) - 1)))
        goto cleanup;
    if (!OSSL_ENCODER_to_bio(encoder, output) || !BIO_get_mem_ptr(output, &data) ||
        data == NULL || data->length == 0)
        goto cleanup;
    if ((encrypted && strcmp(format, "DER") == 0 &&
         (!check_pbkdf2_params(data, oid, key_len) ||
           !check_pbes2_variants(data, key) ||
           !check_pbes2_plaintext_trailing_der(data, key))) ||
        !decode_key(&decoded, format, data, password, sizeof(password) - 1) ||
        decoded == NULL || !same_private_key(key, decoded))
        goto cleanup;

    if (encrypted) {
        if (decode_key(&invalid, format, data, wrong_password,
                       sizeof(wrong_password) - 1) || invalid != NULL)
            goto cleanup;
        ERR_clear_error();
        if (decode_key_limited(&limited, format, data, password,
                               sizeof(password) - 1, iterations - 1) || limited != NULL)
            goto cleanup;
        ERR_clear_error();
        if (!decode_key_limited(&limited, format, data, password,
                                sizeof(password) - 1, iterations) ||
            limited == NULL || !same_private_key(key, limited))
            goto cleanup;
    }
    ok = 1;

cleanup:
    if (!ok) {
        fprintf(stderr, "BIGN %s PKCS#8 %s roundtrip failed\n",
                encrypted ? "encrypted" : "plain", format);
        ERR_print_errors_fp(stderr);
    }
    EVP_PKEY_free(limited);
    EVP_PKEY_free(invalid);
    EVP_PKEY_free(decoded);
    BIO_free(output);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

/* Optional OpenSSL-managed PBES2 encryption must round-trip BIGN keys. */
static int check_selected_cipher(EVP_PKEY *key, const char *format, const char *cipher_name)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    EVP_PKEY *decoded = NULL, *wrong = NULL;
    BIO *output = NULL;
    BUF_MEM *data = NULL;
    unsigned int iterations = 12000;
    size_t salt_length = 24;
    OSSL_PARAM settings[] = {
        OSSL_PARAM_uint("stb-pbkdf2-iterations", &iterations),
        OSSL_PARAM_size_t("stb-pbkdf2-saltlen", &salt_length),
        OSSL_PARAM_END
    };
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_KEYPAIR, format, "PrivateKeyInfo", "provider=bee2");
    output = BIO_new(BIO_s_mem());
    if (!encoder || !output || !OSSL_ENCODER_CTX_set_params(encoder, settings) ||
        !OSSL_ENCODER_CTX_set_cipher(encoder, cipher_name, NULL) ||
        !OSSL_ENCODER_CTX_set_passphrase(encoder, password, sizeof(password) - 1) ||
        !OSSL_ENCODER_to_bio(encoder, output) ||
        !BIO_get_mem_ptr(output, &data) || !data || data->length == 0)
        goto cleanup;

    if (!decode_key(&decoded, format, data, password, sizeof(password) - 1) ||
        !decoded || !same_private_key(key, decoded) ||
        decode_key(&wrong, format, data, wrong_password, sizeof(wrong_password) - 1) ||
        wrong != NULL)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok) {
        fprintf(stderr, "BIGN %s PBES2 with %s failed\n", format, cipher_name);
        ERR_print_errors_fp(stderr);
    }
    EVP_PKEY_free(wrong);
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


/* Failed cipher selection must not poison the encoder.  Writable output must
 * still succeed; read-only BIO output must fail rather than losing the key. */
static int check_encoder_failures(EVP_PKEY *key, const char *format)
{
    OSSL_ENCODER_CTX *encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, OSSL_KEYMGMT_SELECT_KEYPAIR, format, "PrivateKeyInfo",
        "provider=bee2");
    BIO *writable = BIO_new(BIO_s_mem());
    BIO *read_only = BIO_new_mem_buf("", 0);
    int ok = 0;

    if (encoder == NULL || writable == NULL || read_only == NULL ||
        OSSL_ENCODER_CTX_set_cipher(encoder, "AES-256-GCM", NULL) > 0 ||
        OSSL_ENCODER_CTX_set_cipher(encoder, "belt-ctr256", NULL) > 0 ||
        OSSL_ENCODER_CTX_set_cipher(encoder, "no-such-cipher", NULL) > 0 ||
        OSSL_ENCODER_to_bio(encoder, writable) <= 0 ||
        OSSL_ENCODER_to_bio(encoder, read_only) > 0)
        goto end;
    ok = 1;

end:
    if (!ok)
        fprintf(stderr, "BIGN %s encoder error handling failed\n", format);
    ERR_clear_error();
    BIO_free(read_only);
    BIO_free(writable);
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
        if ((i == 0 && (!check_encoder_failures(key, "DER") ||
                        !check_encoder_failures(key, "PEM"))) ||
            !check_public_only_decoding(key) ||
            !check_key_stream(key, "DER") || !check_key_stream(key, "PEM"))
            goto cleanup;
        for (j = 0; j < sizeof(formats) / sizeof(formats[0]); ++j) {
            if (!check_serialization(key, formats[j], 0) ||
                !check_serialization(key, formats[j], 1) ||
                !check_selected_cipher(key, formats[j], "AES-256-CBC") ||
                !check_selected_cipher(key, formats[j], "AES-192-CBC") ||
                !check_selected_cipher(key, formats[j], "AES-128-CBC") ||
                !check_selected_cipher(key, formats[j], "default"))
                goto cleanup;
        }
        EVP_PKEY_free(key);
        key = NULL;
    }
    for (i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        if (!check_foreign_key("RSA", formats[i], 0) ||
            !check_foreign_key("EC", formats[i], 0) ||
            !check_foreign_key("RSA", formats[i], 1) ||
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
