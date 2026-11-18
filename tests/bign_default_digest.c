/* A null digest name must select the BIGN curve's default hash. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

static int check_default_digest(const char *name, size_t expected_siglen)
{
    static const unsigned char message[] = "Default BIGN digest selection";
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sign = NULL, *verify = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    char empty_digest[] = "";
    OSSL_PARAM clear_digest[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, empty_digest, 0),
        OSSL_PARAM_END
    };
    unsigned char signature[96];
    size_t signature_len;
    size_t n;
    int ok = 0;

    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0)
        goto done;
    sign = EVP_MD_CTX_new();
    verify = EVP_MD_CTX_new();
    if (sign == NULL || verify == NULL)
        goto done;

    /* Exercise both the empty-message and nonempty one-shot paths. */
    for (n = 0; n < 2; ++n) {
        size_t message_len = n == 0 ? 0 : sizeof(message) - 1;

        signature_len = sizeof(signature);
        if (EVP_DigestSignInit_ex(sign, NULL, NULL, NULL, "provider=bee2", key, NULL) <= 0 ||
            EVP_DigestSign(sign, signature, &signature_len, message, message_len) <= 0 ||
            signature_len != expected_siglen ||
            EVP_DigestVerifyInit_ex(verify, NULL, NULL, NULL, "provider=bee2", key, NULL) <= 0 ||
            EVP_DigestVerify(verify, signature, signature_len, message, message_len) != 1)
            goto done;
        if (n != 0 &&
            EVP_DigestVerify(verify, signature, signature_len, message, message_len - 1) > 0)
            goto done;
    }
    /* Clearing the selected hash before a one-shot operation must restore
     * the curve's default digest, both for signing and verification.  This
     * exercises a reset that cannot be reached through ordinary KATs. */
    signature_len = sizeof(signature);
    if (EVP_DigestSignInit_ex(sign, &sctx, NULL, NULL, "provider=bee2", key, NULL) <= 0 ||
        EVP_PKEY_CTX_set_params(sctx, clear_digest) <= 0 ||
        EVP_DigestSign(sign, signature, &signature_len,
                       message, sizeof(message) - 1) <= 0 ||
        signature_len != expected_siglen ||
        EVP_DigestVerifyInit_ex(verify, &vctx, NULL, NULL,
                                "provider=bee2", key, NULL) <= 0 ||
        EVP_PKEY_CTX_set_params(vctx, clear_digest) <= 0 ||
        EVP_DigestVerify(verify, signature, signature_len,
                         message, sizeof(message) - 1) != 1)
        goto done;

    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN default digest failed: %s\n", name);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(sign);
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
    if (def == NULL || bee2 == NULL)
        goto done;
    ok = check_default_digest("bign-256", 48) &&
         check_default_digest("bign-384", 72) &&
         check_default_digest("bign-512", 96);
done:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
