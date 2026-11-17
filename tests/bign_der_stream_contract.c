/* DER stream reader: reject truncated and noncanonical ASN.1 length fields
 * before attempting to interpret an object as a BIGN key. */
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

static int rejected(const char *label, const unsigned char *data, size_t length)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &key, "DER", NULL, "BIGN", OSSL_KEYMGMT_SELECT_KEYPAIR,
        NULL, "provider=bee2");
    const unsigned char *cursor = data;
    size_t remaining = length;
    int ok;

    if (ctx == NULL)
        return 0;
    (void)OSSL_DECODER_from_data(ctx, &cursor, &remaining);
    ok = key == NULL;
    if (!ok)
        fprintf(stderr, "BIGN accepted malformed DER stream: %s\n", label);
    EVP_PKEY_free(key);
    OSSL_DECODER_CTX_free(ctx);
    ERR_clear_error();
    return ok;
}

int main(int argc, char **argv)
{
    static const unsigned char truncated_header[] = {0x30};
    static const unsigned char indefinite[] = {0x30, 0x80};
    static const unsigned char excessive_length_bytes[] = {0x30, 0x84, 1, 2, 3, 4};
    static const unsigned char truncated_length[] = {0x30, 0x81};
    static const unsigned char leading_zero[] = {0x30, 0x82, 0, 0x80};
    static const unsigned char short_long_form[] = {0x30, 0x81, 0x7f};
    static const unsigned char truncated_two_byte_length[] = {0x30, 0x82, 1};
    static const unsigned char oversized[] = {0x30, 0x83, 0x11, 0, 0};
    static const unsigned char truncated_body[] = {0x30, 0x81, 0x80};
    static const unsigned char empty_sequence[] = {0x30, 0};
    static const unsigned char wrong_tag[] = {0x04, 0};
    static const struct {
        const char *label;
        const unsigned char *data;
        size_t length;
    } cases[] = {
        {"missing length", truncated_header, sizeof(truncated_header)},
        {"indefinite", indefinite, sizeof(indefinite)},
        {"long length count", excessive_length_bytes, sizeof(excessive_length_bytes)},
        {"truncated length", truncated_length, sizeof(truncated_length)},
        {"leading zero", leading_zero, sizeof(leading_zero)},
        {"nonminimal length", short_long_form, sizeof(short_long_form)},
        {"truncated two-byte length", truncated_two_byte_length,
         sizeof(truncated_two_byte_length)},
        {"oversized", oversized, sizeof(oversized)},
        {"truncated body", truncated_body, sizeof(truncated_body)},
        {"empty sequence", empty_sequence, sizeof(empty_sequence)},
        {"wrong tag", wrong_tag, sizeof(wrong_tag)}
    };
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2 ||
        !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (!rejected(cases[i].label, cases[i].data, cases[i].length))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
