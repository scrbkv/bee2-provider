/* Rejected BIGN private scalars and public points through OSSL_DECODER. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int decode(const unsigned char *der, size_t len, int public_only)
{
    EVP_PKEY *decoded = NULL;
    OSSL_DECODER_CTX *ctx = NULL;
    const unsigned char *p = der;
    size_t remaining = len;
    int result;

    ctx = OSSL_DECODER_CTX_new_for_pkey(
        &decoded, "DER", NULL, NULL,
        public_only ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY :
                      OSSL_KEYMGMT_SELECT_KEYPAIR,
        NULL, NULL);
    result = ctx != NULL &&
             OSSL_DECODER_from_data(ctx, &p, &remaining) > 0 &&
             decoded != NULL;
    OSSL_DECODER_CTX_free(ctx);
    EVP_PKEY_free(decoded);
    ERR_clear_error();
    return result;
}

static int check_encoding(EVP_PKEY *key, int public_only, size_t bits)
{
    OSSL_ENCODER_CTX *encoder = NULL;
    unsigned char *der = NULL, *damaged = NULL;
    size_t len = 0, payload = public_only ? bits / 4u : bits / 8u;
    int selection = public_only ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY :
                                  OSSL_KEYMGMT_SELECT_KEYPAIR;
    const char *structure = public_only ? "SubjectPublicKeyInfo" :
                                         "PrivateKeyInfo";
    int ok = 0;

    encoder = OSSL_ENCODER_CTX_new_for_pkey(
        key, selection, "DER", structure, "provider=bee2");
    if (encoder == NULL || !OSSL_ENCODER_to_data(encoder, &der, &len) ||
        der == NULL || len <= payload + 1u || !decode(der, len, public_only))
        goto end;
    damaged = OPENSSL_memdup(der, len);
    if (damaged == NULL)
        goto end;
    if (decode(damaged, len - 1u, public_only))
        goto end;
    memcpy(damaged, der, len);
    memset(damaged + len - payload, 0, payload);
    if (decode(damaged, len, public_only))
        goto end;
    if (public_only) {
        memcpy(damaged, der, len);
        damaged[len - payload - 1u] = 1; /* nonzero BIT STRING unused bits */
        if (decode(damaged, len, public_only))
            goto end;
    }
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "BIGN-%zu %s ASN.1 negative test failed\n",
                bits, public_only ? "SPKI" : "PKCS#8");
    OPENSSL_clear_free(damaged, len);
    OPENSSL_clear_free(der, len);
    OSSL_ENCODER_CTX_free(encoder);
    return ok;
}

static int check_curve(const char *algorithm, size_t bits)
{
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *key = NULL;
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    if (gen != NULL && EVP_PKEY_keygen_init(gen) > 0 &&
        EVP_PKEY_generate(gen, &key) > 0 &&
        check_encoding(key, 0, bits) && check_encoding(key, 1, bits))
        ok = 1;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gen);
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
    if (def != NULL && bee2 != NULL &&
        check_curve("bign-256", 256) &&
        check_curve("bign-384", 384) &&
        check_curve("bign-512", 512))
        ok = 1;
    if (!ok)
        ERR_print_errors_fp(stderr);
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
