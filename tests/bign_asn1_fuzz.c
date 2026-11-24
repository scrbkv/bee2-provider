/* Fuzz public BIGN DER/PEM decoders with bounded PBKDF2 work.
 * Byte zero selects envelope; remaining bytes are unmodified DER/PEM. */
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include "bign_asn1.h"
#include <stdint.h>
#include <stdlib.h>

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *def, *bee2;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *dir = getenv("BEE2_FUZZ_MODULES");
    (void)argc;
    (void)argv;
    libctx = OSSL_LIB_CTX_new();
    if (!libctx || !dir || !*dir ||
        !OSSL_PROVIDER_set_default_search_path(libctx, dir))
        return -1;
    def = OSSL_PROVIDER_load(libctx, "default");
    bee2 = OSSL_PROVIDER_load(libctx, "bee2_provider");
    return def && bee2 ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const unsigned char password[] = "fuzz-password";
    unsigned int limit_value = 16;
    OSSL_PARAM limit[] = {
        OSSL_PARAM_uint("stb-pbkdf2-max-decode-iterations", &limit_value),
        OSSL_PARAM_END
    };
    OSSL_DECODER_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    bee2_bign_key_t parsed = {0};
    const char *format, *structure;
    unsigned int kind;
    int selection = OSSL_KEYMGMT_SELECT_KEYPAIR;

    if (!libctx || size < 2 || size > 4097)
        return 0;
    kind = data[0] & 3u;
    ++data;
    --size;
    format = kind == 3 ? "PEM" : "DER";
    structure = kind == 0 ? "PrivateKeyInfo" :
                kind == 1 ? "SubjectPublicKeyInfo" :
                kind == 2 ? "EncryptedPrivateKeyInfo" : NULL;
    if (kind == 1)
        selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    /* Compile the existing DER helpers into this target: libFuzzer now
     * observes actual ASN.1 parser edges, not just harness dispatch. */
    if (kind == 0)
        (void)bee2_bign_asn1_decode_pkcs8_der(data, size,
                                                bee2_bign_variant_256(), &parsed);
    else if (kind == 1)
        (void)bee2_bign_asn1_decode_spki_der(data, size,
                                               bee2_bign_variant_256(), &parsed);
    bee2_bign_cleanse(&parsed, sizeof(parsed));
    ctx = OSSL_DECODER_CTX_new_for_pkey(&key, format, structure, "bign",
                                        selection, libctx, "provider=bee2");
    if (ctx && OSSL_DECODER_CTX_set_passphrase(ctx, password,
                                              sizeof(password) - 1) &&
        OSSL_DECODER_CTX_set_params(ctx, limit)) {
        bio = BIO_new_mem_buf(data, (int)size);
        if (bio)
            (void)OSSL_DECODER_from_bio(ctx, bio);
    }
    BIO_free(bio);
    EVP_PKEY_free(key);
    OSSL_DECODER_CTX_free(ctx);
    ERR_clear_error();
    return 0;
}
