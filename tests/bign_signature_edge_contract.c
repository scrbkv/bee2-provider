/* Probe BIGN signature parameters through EVP without bypassing libcrypto. */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif

static EVP_PKEY *generate_key(const char *name)
{
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(NULL, name, "provider=bee2");
    EVP_PKEY *key = NULL;

    if (gen == NULL || EVP_PKEY_keygen_init(gen) <= 0 ||
        EVP_PKEY_keygen(gen, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(gen);
    return key;
}

static int check_variant(const char *name, const char *digest,
                         const char *wrong_digest, size_t digest_size)
{
    static const unsigned char message[] = "BIGN signature parameter contract";
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sign = NULL, *verify = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    unsigned char signature[96], aid[64], tiny[1];
    char mdname[32];
    size_t sig_len, md_size = 0;
    unsigned int deterministic = 1, reported = 0;
    char illegal[96];
    char overlong[256] = "provider=bee2";
    size_t i;
    OSSL_PARAM bad_algid[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, tiny, sizeof(tiny)),
        OSSL_PARAM_END
    };
    OSSL_PARAM query_algid[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM query_details[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, mdname, sizeof(mdname)),
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, &md_size),
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &reported),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_digest_out[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_DIGEST, tiny, sizeof(tiny)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_size_out[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, tiny, sizeof(tiny)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_mode_out[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_DETERMINISTIC, tiny, sizeof(tiny)),
        OSSL_PARAM_END
    };
    OSSL_PARAM deterministic_param[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };
    OSSL_PARAM too_long_properties[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, illegal, sizeof(illegal)),
        OSSL_PARAM_END
    };
    OSSL_PARAM overlong_properties[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, overlong, 0),
        OSSL_PARAM_END
    };
    OSSL_PARAM wrong_md[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char *)wrong_digest, 0),
        OSSL_PARAM_END
    };
    int ok = 0;
    const char *phase = "initialize";

    key = generate_key(name);
    sign = EVP_MD_CTX_new();
    verify = EVP_MD_CTX_new();
    if (key == NULL || sign == NULL || verify == NULL ||
        EVP_DigestSignInit_ex(sign, &sctx, digest, NULL, "provider=bee2", key, NULL) <= 0)
        goto done;

    phase = "read invalid output parameters";
    /* Reject malformed output targets while preserving the live signature context. */
    if (EVP_PKEY_CTX_get_params(sctx, bad_algid) > 0 ||
        EVP_PKEY_CTX_get_params(sctx, bad_digest_out) > 0 ||
        EVP_PKEY_CTX_get_params(sctx, bad_size_out) > 0 ||
        EVP_PKEY_CTX_get_params(sctx, bad_mode_out) > 0 ||
        EVP_PKEY_CTX_get_params(sctx, query_algid) <= 0 ||
        query_algid[0].return_size == 0 ||
        query_algid[0].return_size > sizeof(aid) ||
        EVP_PKEY_CTX_get_params(sctx, query_details) <= 0 ||
        strcmp(mdname, digest) != 0 || md_size != digest_size || reported != 0)
        goto done;

    phase = "reject digest and property updates";
    /* A digest of the wrong size must be rejected, and failed property
     * updates must not corrupt an already selected digest. */
    phase = "reject mismatched digest";
    wrong_md[0].data_size = strlen(wrong_digest) + 1;
    if (EVP_PKEY_CTX_set_params(sctx, wrong_md) > 0)
        goto done;
    phase = "reject invalid or overlong properties";
    memset(illegal, 'x', sizeof(illegal) - 1);
    illegal[sizeof(illegal) - 1] = '\0';
    for (i = 0; i < 12; ++i)
        OPENSSL_strlcat(overlong, ",provider=bee2", sizeof(overlong));
    overlong_properties[0].data_size = strlen(overlong) + 1;
    if (EVP_PKEY_CTX_set_params(sctx, too_long_properties) > 0 ||
        EVP_PKEY_CTX_set_params(sctx, overlong_properties) > 0 ||
        EVP_PKEY_CTX_get_params(sctx, query_details) <= 0 ||
        strcmp(mdname, digest) != 0 || md_size != digest_size ||
        EVP_PKEY_CTX_set_params(sctx, deterministic_param) <= 0)
        goto done;
    phase = "query deterministic mode";
    reported = 0;
    if (EVP_PKEY_CTX_get_params(sctx, query_details) <= 0 || reported != 1)
        goto done;

    phase = "sign and verify";
    sig_len = sizeof(signature);
    if (EVP_DigestSign(sign, signature, &sig_len, message, sizeof(message)) <= 0 ||
        EVP_DigestVerifyInit_ex(verify, NULL, digest, NULL, "provider=bee2", key, NULL) <= 0 ||
        EVP_DigestVerify(verify, signature, sig_len, message, sizeof(message)) != 1)
        goto done;
    ok = 1;

done:
    if (!ok)
        fprintf(stderr, "BIGN signature parameters failed: %s (%s)\n", name, phase);
    EVP_MD_CTX_free(verify);
    EVP_MD_CTX_free(sign);
    EVP_PKEY_free(key);
    return ok;
}

/* A generic BIGN raw-signature context may clear an explicitly selected
 * digest and fall back to the standard digest OID for the selected curve. */
static int check_digest_reset(const char *algorithm, const char *digest, size_t bits)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sign = NULL, *verify = NULL;
    unsigned char hash[64] = {3, 1, 4, 1};
    unsigned char signature[96];
    size_t signature_len = sizeof(signature);
    char empty[] = "";
    OSSL_PARAM select_digest[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, (char *)digest, 0),
        OSSL_PARAM_END
    };
    OSSL_PARAM clear_digest[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, empty, sizeof(empty)),
        OSSL_PARAM_END
    };
    int ok = 0;

    key = generate_key(algorithm);
    if (!key)
        goto done;
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (!sign || !verify || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, select_digest) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, clear_digest) <= 0 ||
        EVP_PKEY_sign(sign, signature, &signature_len, hash, bits / 8u) <= 0 ||
        EVP_PKEY_verify_init(verify) <= 0 ||
        EVP_PKEY_verify(verify, signature, signature_len, hash, bits / 8u) <= 0)
        goto done;
    ok = 1;
done:
    if (!ok)
        fprintf(stderr, "BIGN raw digest reset failed: %s\n", algorithm);
    EVP_PKEY_CTX_free(verify);
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(signature, sizeof(signature));
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
    ok = check_variant("bign-256", "belt-hash", "bash384", 32) &&
         check_variant("bign-384", "bash384", "bash256", 48) &&
         check_variant("bign-512", "bash512", "bash384", 64) &&
         check_digest_reset("bign-256", "belt-hash", 256) &&
         check_digest_reset("bign-384", "bash384", 384) &&
         check_digest_reset("bign-512", "bash512", 512);
done:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
