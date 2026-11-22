/* A successful BIGN DER decode must not leave failed ASN.1 probes in ERR. */
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

static int check_spki(const char *algorithm)
{
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *key = NULL, *decoded = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    unsigned char *der = NULL;
    unsigned char pub[128], restored[128];
    const unsigned char *p;
    size_t len = 0, remaining, pub_len = 0, restored_len = 0;
    int ok = 0;

    gen = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto end;
    encoder = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PUBLIC_KEY,
                                            "DER", "SubjectPublicKeyInfo", NULL);
    if (encoder == NULL || OSSL_ENCODER_to_data(encoder, &der, &len) <= 0)
        goto end;
    decoder = OSSL_DECODER_CTX_new_for_pkey(&decoded, "DER", NULL, NULL,
                                            EVP_PKEY_PUBLIC_KEY, NULL, NULL);
    if (decoder == NULL)
        goto end;

    p = der;
    remaining = len;
    ERR_clear_error();
    if (OSSL_DECODER_from_data(decoder, &p, &remaining) <= 0 ||
        decoded == NULL || ERR_peek_error() != 0 ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, sizeof(pub), &pub_len) <= 0 ||
        EVP_PKEY_get_octet_string_param(decoded, OSSL_PKEY_PARAM_PUB_KEY,
                                        restored, sizeof(restored), &restored_len) <= 0 ||
        pub_len != restored_len || CRYPTO_memcmp(pub, restored, pub_len) != 0)
        goto end;
    ok = 1;
end:
    if (!ok) {
        fprintf(stderr, "%s: SPKI decode failed or left OpenSSL errors\n", algorithm);
        ERR_print_errors_fp(stderr);
    }
    OPENSSL_clear_free(der, len);
    OSSL_DECODER_CTX_free(decoder);
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(decoded);
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
        check_spki("bign-256") && check_spki("bign-384") &&
        check_spki("bign-512"))
        ok = 1;
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
