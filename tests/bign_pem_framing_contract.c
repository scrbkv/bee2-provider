/* PEM boundaries through the OpenSSL decoder chain and the Bee2 bridge. */
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

static EVP_PKEY *load_key(const unsigned char *data, size_t length, int selection)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &key, "PEM", NULL, "BIGN", selection, NULL, NULL);
    const unsigned char *p = data;
    size_t remaining = length;

    if (!ctx || OSSL_DECODER_from_data(ctx, &p, &remaining) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(ctx);
    return key;
}

static int same_public(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char first[128], second[128];
    size_t a_len = 0, b_len = 0;

    return a && b &&
           EVP_PKEY_get_octet_string_param(a, OSSL_PKEY_PARAM_PUB_KEY,
                                            first, sizeof(first), &a_len) > 0 &&
           EVP_PKEY_get_octet_string_param(b, OSSL_PKEY_PARAM_PUB_KEY,
                                            second, sizeof(second), &b_len) > 0 &&
           a_len == b_len && CRYPTO_memcmp(first, second, a_len) == 0;
}

static int test_case(const char *algorithm, int public_key)
{
    EVP_PKEY_CTX *gen = NULL;
    EVP_PKEY *original = NULL, *reloaded = NULL;
    OSSL_ENCODER_CTX *enc = NULL;
    unsigned char *pem = NULL, *normalized = NULL;
    size_t len = 0, i, n = 0;
    int ok = 0;
    const int selection = public_key ? OSSL_KEYMGMT_SELECT_PUBLIC_KEY :
                                       OSSL_KEYMGMT_SELECT_KEYPAIR;
    const char *where = "keygen";

    gen = EVP_PKEY_CTX_new_from_name(NULL, algorithm, "provider=bee2");
    if (!gen || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &original) <= 0)
        goto done;
    where = "encode";
    enc = OSSL_ENCODER_CTX_new_for_pkey(original, selection, "PEM",
                                       public_key ? "SubjectPublicKeyInfo" :
                                                    "PrivateKeyInfo",
                                       "provider=bee2");
    if (!enc || OSSL_ENCODER_to_data(enc, &pem, &len) <= 0 || len < 32)
        goto done;
    normalized = OPENSSL_malloc(len * 2 + 24);
    if (!normalized)
        goto done;

    where = "original";
    reloaded = load_key(pem, len, selection);
    if (!same_public(original, reloaded))
        goto done;
    EVP_PKEY_free(reloaded);
    reloaded = NULL;

    /* CRLF line endings and no final newline. */
    where = "crlf";
    for (i = 0; i < len; ++i) {
        if (pem[i] == '\n')
            normalized[n++] = '\r';
        normalized[n++] = pem[i];
    }
    reloaded = load_key(normalized, n, selection);
    if (!same_public(original, reloaded))
        goto done;
    EVP_PKEY_free(reloaded);
    reloaded = NULL;

    where = "without final newline";
    if (n > 1 && normalized[n - 1] == '\n')
        --n;
    if (n > 1 && normalized[n - 1] == '\r')
        --n;
    reloaded = load_key(normalized, n, selection);
    if (!same_public(original, reloaded))
        goto done;
    EVP_PKEY_free(reloaded);
    reloaded = NULL;

    where = "malformed footer";
    if (n > 8) {
        /* One missing footer hyphen must not be accepted as a PEM key. */
        normalized[n - 1] = 'X';
        reloaded = load_key(normalized, n, selection);
        if (reloaded != NULL)
            goto done;
    }
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN PEM boundary failure %s/%s at %s\n",
                algorithm, public_key ? "public" : "private", where);
    EVP_PKEY_free(reloaded);
    OPENSSL_clear_free(normalized, len * 2 + 24);
    OPENSSL_clear_free(pem, len);
    OSSL_ENCODER_CTX_free(enc);
    EVP_PKEY_free(original);
    EVP_PKEY_CTX_free(gen);
    return ok;
}

typedef struct {
    size_t bytes;
} read_counter_t;

static long count_pem_reads(BIO *bio, int operation, const char *argp,
                            size_t len, int argi, long argl,
                            int ret, size_t *processed)
{
    read_counter_t *counter = (read_counter_t *)BIO_get_callback_arg(bio);

    (void)argp;
    (void)len;
    (void)argi;
    (void)argl;
    if (operation == (BIO_CB_GETS | BIO_CB_RETURN) &&
        ret > 0 && processed != NULL)
        counter->bytes += *processed;
    return ret;
}

/* Verify the provider's read cap, not merely rejection of invalid DER. */
static int test_oversized_pem(void)
{
    static const char header[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
    static const char footer[] = "-----END ENCRYPTED PRIVATE KEY-----\n";
    const size_t max_text = 2u * 1024u * 1024u;
    const size_t base64_chars = max_text + 4096u;
    char *pem = NULL;
    size_t i, length = 0;
    BIO *input = NULL;
    OSSL_DECODER_CTX *decoder = NULL;
    EVP_PKEY *key = NULL;
    read_counter_t counter = {0};
    int decoded = 0, ok = 0;

    pem = OPENSSL_malloc(base64_chars + base64_chars / 64 + 128);
    if (pem == NULL)
        goto done;
    memcpy(pem, header, sizeof(header) - 1);
    length = sizeof(header) - 1;
    for (i = 0; i < base64_chars; ++i) {
        pem[length++] = 'A';
        if (i % 64 == 63)
            pem[length++] = '\n';
    }
    memcpy(pem + length, footer, sizeof(footer) - 1);
    length += sizeof(footer) - 1;
    input = BIO_new_mem_buf(pem, (int)length);
    decoder = OSSL_DECODER_CTX_new_for_pkey(
        &key, "PEM", NULL, "bign", OSSL_KEYMGMT_SELECT_KEYPAIR,
        NULL, "provider=bee2");
    if (input == NULL || decoder == NULL)
        goto done;
    BIO_set_callback_arg(input, (char *)&counter);
    BIO_set_callback_ex(input, count_pem_reads);
    decoded = OSSL_DECODER_from_bio(decoder, input);
    ok = decoded <= 0 && key == NULL &&
         counter.bytes >= max_text && counter.bytes <= max_text + 255;
done:
    if (!ok)
        fprintf(stderr, "BIGN PEM read limit failed (read %zu bytes)\n",
                counter.bytes);
    OSSL_DECODER_CTX_free(decoder);
    EVP_PKEY_free(key);
    BIO_free(input);
    OPENSSL_clear_free(pem, base64_chars + base64_chars / 64 + 128);
    return ok;
}

int main(int argc, char **argv)
{
    static const char *names[] = {"bign-256", "bign-384", "bign-512"};
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!def || !bee2)
        goto done;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!test_case(names[i], 0) || !test_case(names[i], 1))
            goto done;
    }
    OSSL_PROVIDER_unload(def);
    def = NULL;
    if (!test_oversized_pem())
        goto done;
    ok = 1;
done:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
