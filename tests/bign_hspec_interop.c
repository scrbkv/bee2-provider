/* bign-with-hspec: the selected hash OID must be passed unchanged to Bee2. */
#include <limits.h>
#include <bee2/core/err.h>
#include <bee2/crypto/bign.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

#define HSPEC_OID "1.2.112.0.2.0.34.101.45.11"

typedef struct {
    const char *name;
    const char *curve_oid;
    const char *mdname;
    const char *md_oid;
    size_t n;
} hspec_case_t;

static const hspec_case_t cases[] = {
    {"bign-256", "1.2.112.0.2.0.34.101.45.3.1", "SHA256",
     "2.16.840.1.101.3.4.2.1", 32},
    {"bign-256", "1.2.112.0.2.0.34.101.45.3.1", "SHA3-256",
     "2.16.840.1.101.3.4.2.8", 32},
    {"bign-384", "1.2.112.0.2.0.34.101.45.3.2", "SHA384",
     "2.16.840.1.101.3.4.2.2", 48},
    {"bign-512", "1.2.112.0.2.0.34.101.45.3.3", "SHA512",
     "2.16.840.1.101.3.4.2.3", 64}
};

static int is_hspec_id(const unsigned char *der, size_t len,
                       const char *expected_hash_oid)
{
    const unsigned char *p = der;
    const ASN1_OBJECT *obj;
    const void *param = NULL;
    X509_ALGOR *alg = NULL;
    char oid[96], hash_oid[96];
    int ptype = V_ASN1_UNDEF;
    int ok = 0;

    if (len > LONG_MAX)
        return 0;
    alg = d2i_X509_ALGOR(NULL, &p, (long)len);
    if (alg == NULL || p != der + len)
        goto end;
    X509_ALGOR_get0(&obj, &ptype, &param, alg);
    if (ptype == V_ASN1_OBJECT && param != NULL &&
        OBJ_obj2txt(oid, sizeof(oid), obj, 1) > 0 &&
        OBJ_obj2txt(hash_oid, sizeof(hash_oid),
                    (const ASN1_OBJECT *)param, 1) > 0 &&
        strcmp(oid, HSPEC_OID) == 0 &&
        strcmp(hash_oid, expected_hash_oid) == 0)
        ok = 1;
end:
    X509_ALGOR_free(alg);
    return ok;
}

static int check_named_operation(OSSL_PROVIDER *provider)
{
    const OSSL_ALGORITHM *algs, *alg;
    const OSSL_DISPATCH *fn;
    OSSL_FUNC_signature_newctx_fn *newctx = NULL;
    OSSL_FUNC_signature_freectx_fn *freectx = NULL;
    OSSL_FUNC_signature_get_ctx_params_fn *getctx = NULL;
    OSSL_FUNC_signature_set_ctx_params_fn *setctx = NULL;
    OSSL_FUNC_signature_sign_init_fn *signinit = NULL;
    OSSL_FUNC_signature_verify_init_fn *verifyinit = NULL;
    OSSL_FUNC_signature_sign_fn *signfn = NULL;
    OSSL_FUNC_signature_verify_fn *verifyfn = NULL;
    OSSL_FUNC_keymgmt_new_fn *newkey = NULL;
    OSSL_FUNC_keymgmt_import_fn *importkey = NULL;
    OSSL_FUNC_keymgmt_free_fn *freekey = NULL;
    const OSSL_ALGORITHM *keyalgs = NULL, *keyalg;
    unsigned char priv[32] = {3}, digest_data[32], sig[48], native[48];
    unsigned char oid_der[32];
    size_t oid_len = sizeof(oid_der), sig_len = sizeof(sig), i;
    bign_params curve;
    unsigned int deterministic = 1;
    OSSL_PARAM key_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, sizeof(priv)),
        OSSL_PARAM_END
    };
    OSSL_PARAM det[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };
    char digest[] = "SHA256";
    unsigned char aid[96];
    OSSL_PARAM get[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM set[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest, sizeof(digest)),
        OSSL_PARAM_END
    };
    void *ctx = NULL, *key = NULL;
    int no_cache = 0, no_key_cache = 0, ok = 0;

    memset(&curve, 0, sizeof(curve));
    algs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_SIGNATURE, &no_cache);
    if (algs == NULL)
        return 0;
    for (alg = algs; alg->algorithm_names != NULL; ++alg)
        if (strncmp(alg->algorithm_names, "bign-with-hspec:", 16) == 0)
            break;
    if (alg->algorithm_names == NULL)
        goto end;
    for (fn = alg->implementation; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_SIGNATURE_NEWCTX:
            newctx = OSSL_FUNC_signature_newctx(fn);
            break;
        case OSSL_FUNC_SIGNATURE_FREECTX:
            freectx = OSSL_FUNC_signature_freectx(fn);
            break;
        case OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS:
            getctx = OSSL_FUNC_signature_get_ctx_params(fn);
            break;
        case OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS:
            setctx = OSSL_FUNC_signature_set_ctx_params(fn);
            break;
        case OSSL_FUNC_SIGNATURE_SIGN_INIT:
            signinit = OSSL_FUNC_signature_sign_init(fn);
            break;
        case OSSL_FUNC_SIGNATURE_VERIFY_INIT:
            verifyinit = OSSL_FUNC_signature_verify_init(fn);
            break;
        case OSSL_FUNC_SIGNATURE_SIGN:
            signfn = OSSL_FUNC_signature_sign(fn);
            break;
        case OSSL_FUNC_SIGNATURE_VERIFY:
            verifyfn = OSSL_FUNC_signature_verify(fn);
            break;
        }
    }
    if (!newctx || !freectx || !getctx || !setctx || !signinit || !verifyinit ||
        !signfn || !verifyfn)
        goto end;
    ctx = newctx(OSSL_PROVIDER_get0_provider_ctx(provider), NULL);
    if (ctx == NULL || getctx(ctx, get) ||
        !setctx(ctx, set) || !getctx(ctx, get) ||
        !is_hspec_id(aid, get[0].return_size, cases[0].md_oid))
        goto end;

    keyalgs = OSSL_PROVIDER_query_operation(provider, OSSL_OP_KEYMGMT, &no_key_cache);
    if (!keyalgs)
        goto end;
    for (keyalg = keyalgs; keyalg->algorithm_names != NULL; ++keyalg)
        if (strncmp(keyalg->algorithm_names, "bign-256:", 9) == 0)
            break;
    if (keyalg->algorithm_names == NULL)
        goto end;
    for (fn = keyalg->implementation; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_KEYMGMT_NEW:
            newkey = OSSL_FUNC_keymgmt_new(fn);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORT:
            importkey = OSSL_FUNC_keymgmt_import(fn);
            break;
        case OSSL_FUNC_KEYMGMT_FREE:
            freekey = OSSL_FUNC_keymgmt_free(fn);
            break;
        }
    }
    if (!newkey || !importkey || !freekey)
        goto end;
    key = newkey(OSSL_PROVIDER_get0_provider_ctx(provider));
    if (!key || !importkey(key, OSSL_KEYMGMT_SELECT_KEYPAIR, key_params))
        goto end;
    for (i = 0; i < sizeof(digest_data); ++i)
        digest_data[i] = (unsigned char)(7u + i * 11u);
    if (bignParamsStd(&curve, cases[0].curve_oid) != ERR_OK ||
        bignOidToDER(oid_der, &oid_len, cases[0].md_oid) != ERR_OK ||
        !setctx(ctx, det) || !signinit(ctx, key, NULL) ||
        !signfn(ctx, sig, &sig_len, sizeof(sig), digest_data, sizeof(digest_data)) ||
        sig_len != sizeof(sig) ||
        bignSign2(native, &curve, oid_der, oid_len, digest_data, priv, NULL, 0) != ERR_OK ||
        CRYPTO_memcmp(sig, native, sizeof(sig)) != 0 ||
        !verifyinit(ctx, key, NULL) ||
        !verifyfn(ctx, sig, sig_len, digest_data, sizeof(digest_data)))
        goto end;
    ok = 1;
end:
    if (key && freekey)
        freekey(key);
    if (ctx && freectx)
        freectx(ctx);
    if (algs)
        OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_SIGNATURE, algs);
    if (keyalgs)
        OSSL_PROVIDER_unquery_operation(provider, OSSL_OP_KEYMGMT, keyalgs);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(sig, sizeof(sig));
    OPENSSL_cleanse(native, sizeof(native));
    OPENSSL_cleanse(digest_data, sizeof(digest_data));
    OPENSSL_cleanse(&curve, sizeof(curve));
    return ok;
}

static EVP_PKEY *new_private_key(const hspec_case_t *tc, unsigned char priv[64])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, tc->name, "provider=bee2");
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    size_t i;

    memset(priv, 0, 64);
    priv[0] = 3;
    for (i = 1; i < tc->n / 2; ++i)
        priv[i] = (unsigned char)(i * 3u + 1u);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, tc->n);
    params[1] = OSSL_PARAM_construct_end();
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int check_signature(const hspec_case_t *tc)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sign = NULL, *verify = NULL;
    unsigned char priv[64], pub[128];
    unsigned char digest[64], actual[96], native[96], oid_der[32], aid[96];
    size_t oid_len = sizeof(oid_der), actual_len = sizeof(actual), pub_len = 0;
    unsigned int deterministic = 1;
    char digest_name[16];
    OSSL_PARAM params[3];
    OSSL_PARAM get[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid)),
        OSSL_PARAM_END
    };
    bign_params curve;
    size_t i;
    int ok = 0;

    memset(&curve, 0, sizeof(curve));
    key = new_private_key(tc, priv);
    if (!key || EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                                  pub, sizeof(pub), &pub_len) <= 0 ||
        pub_len != tc->n * 2 || bignParamsStd(&curve, tc->curve_oid) != ERR_OK ||
        bignOidToDER(oid_der, &oid_len, tc->md_oid) != ERR_OK)
        goto end;
    for (i = 0; i < tc->n; ++i)
        digest[i] = (unsigned char)(0x51u + i * 13u);
    OPENSSL_strlcpy(digest_name, tc->mdname, sizeof(digest_name));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest_name, 0);
    params[1] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    params[2] = OSSL_PARAM_construct_end();
    sign = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    verify = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=bee2");
    if (!sign || !verify || EVP_PKEY_sign_init(sign) <= 0 ||
        EVP_PKEY_CTX_set_params(sign, params) <= 0 ||
        EVP_PKEY_CTX_get_params(sign, get) <= 0 ||
        !is_hspec_id(aid, get[0].return_size, tc->md_oid) ||
        EVP_PKEY_sign(sign, actual, &actual_len, digest, tc->n) <= 0 ||
        actual_len != tc->n + tc->n / 2 ||
        bignSign2(native, &curve, oid_der, oid_len, digest, priv, NULL, 0) != ERR_OK ||
        CRYPTO_memcmp(actual, native, actual_len) != 0 ||
        EVP_PKEY_verify_init(verify) <= 0 ||
        EVP_PKEY_CTX_set_params(verify, params) <= 0 ||
        EVP_PKEY_verify(verify, native, actual_len, digest, tc->n) <= 0 ||
        bignVerify(&curve, oid_der, oid_len, digest, actual, pub) != ERR_OK)
        goto end;

    /* Bee2 binds the digest OID into the signature, not just its bytes. */
    if (tc->n == 32) {
        unsigned char wrong_oid[32];
        size_t wrong_len = sizeof(wrong_oid);
        char sha1[] = "SHA1";
        OSSL_PARAM wrong_digest[] = {
            OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, sha1, sizeof(sha1)),
            OSSL_PARAM_END
        };

        const char *other_oid = strcmp(tc->mdname, "SHA3-256") == 0 ?
            "2.16.840.1.101.3.4.2.1" : "2.16.840.1.101.3.4.2.8";

        if (bignOidToDER(wrong_oid, &wrong_len, other_oid) != ERR_OK ||
            bignVerify(&curve, wrong_oid, wrong_len, digest, actual, pub) == ERR_OK ||
            EVP_PKEY_CTX_set_params(verify, wrong_digest) > 0)
            goto end;
    }
    digest[0] ^= 1u;
    if (EVP_PKEY_verify(verify, actual, actual_len, digest, tc->n) > 0)
        goto end;
    ok = 1;
end:
    if (!ok)
        fprintf(stderr, "bign-with-hspec interoperability failed: %s\n", tc->name);
    EVP_PKEY_CTX_free(sign);
    EVP_PKEY_CTX_free(verify);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(pub, sizeof(pub));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(actual, sizeof(actual));
    OPENSSL_cleanse(native, sizeof(native));
    OPENSSL_cleanse(&curve, sizeof(curve));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL, *provider = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (!default_provider || !provider || !check_named_operation(provider))
        goto end;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        if (!check_signature(&cases[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(default_provider);
    return ok ? 0 : 1;
}
