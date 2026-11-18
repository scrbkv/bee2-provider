/* Every documented provider algorithm must be visible through OSSL_PROVIDER. */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int operation;
    const char *names;
} operation_case_t;

static const operation_case_t operations[] = {
    {OSSL_OP_CIPHER,
     "belt-ecb128 belt-ecb192 belt-ecb256 belt-cbc128 belt-cbc192 belt-cbc256 "
     "belt-cfb128 belt-cfb192 belt-cfb256 belt-ctr128 belt-ctr192 belt-ctr256 "
     "belt-bde128 belt-bde192 belt-bde256 belt-sde128 belt-sde192 belt-sde256 "
     "belt-che128 belt-che192 belt-che256 belt-dwp128 belt-dwp192 belt-dwp256 "
     "belt-kwp128 belt-kwp192 belt-kwp256 "
     "bash-prg-ae1281 bash-prg-ae1282 bash-prg-ae1921 bash-prg-ae1922 "
     "bash-prg-ae2561 bash-prg-ae2562"},
    {OSSL_OP_DIGEST, "belt-hash bash256 bash384 bash512"},
    {OSSL_OP_MAC, "belt-mac128 belt-mac192 belt-mac256 belt-hmac"},
    {OSSL_OP_KDF, "belt-pbkdf"},
    {OSSL_OP_ASYM_CIPHER, "bign-keytransport"},
    {OSSL_OP_RAND, "brng-ctr-hbelt brng-hmac-hbelt"},
    {OSSL_OP_KEYMGMT, "bign bign-pubkey bign-256 bign-384 bign-512"},
    {OSSL_OP_KEYEXCH, "bign bign-256 bign-384 bign-512"},
    {OSSL_OP_SIGNATURE,
     "bign bign-256 bign-384 bign-512 bign-with-hspec bign-with-hbelt "
     "bign-with-bash256 bign-with-bash384 bign-with-bash512"},
    {OSSL_OP_ENCODER, "bign bign-pubkey bign-256 bign-384 bign-512"},
    {OSSL_OP_DECODER, "bign bign-pubkey"}
};

static int names_include(const char *aliases, const char *name, size_t length)
{
    const char *p = aliases;

    while (*p != '\0') {
        const char *end = strchr(p, ':');
        size_t n = end == NULL ? strlen(p) : (size_t)(end - p);
        if (n == length && OPENSSL_strncasecmp(p, name, n) == 0)
            return 1;
        if (end == NULL)
            break;
        p = end + 1;
    }
    return 0;
}

static int test_operation(OSSL_PROVIDER *provider, const operation_case_t *test)
{
    const OSSL_ALGORITHM *algs, *algorithm;
    const char *p = test->names;
    int no_cache = 0, ok = 0;

    algs = OSSL_PROVIDER_query_operation(provider, test->operation, &no_cache);
    if (algs == NULL)
        return 0;
    while (*p != '\0') {
        const char *end = strchr(p, ' ');
        size_t length = end == NULL ? strlen(p) : (size_t)(end - p);

        for (algorithm = algs; algorithm->algorithm_names != NULL; ++algorithm)
            if (names_include(algorithm->algorithm_names, p, length))
                break;
        if (algorithm->algorithm_names == NULL) {
            fprintf(stderr, "Missing provider algorithm: %.*s\n",
                    (int)length, p);
            goto end;
        }
        if (end == NULL)
            break;
        p = end + 1;
    }
    ok = 1;
end:
    OSSL_PROVIDER_unquery_operation(provider, test->operation, algs);
    return ok;
}


/* These callbacks describe the public provider contract. Query all declared
 * algorithms, not just the methods fetched by a particular OpenSSL release. */
static int test_provider_params(OSSL_PROVIDER *provider)
{
    const OSSL_PARAM *gettable = OSSL_PROVIDER_gettable_params(provider);
    const char *name = NULL, *version = NULL, *build = NULL;
    int status = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, sizeof(name)),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, &version, sizeof(version)),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &build, sizeof(build)),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, &status),
        OSSL_PARAM_END
    };

    return gettable != NULL &&
           OSSL_PARAM_locate_const(gettable, OSSL_PROV_PARAM_NAME) != NULL &&
           OSSL_PROVIDER_get_params(provider, params) > 0 &&
           name != NULL && version != NULL && build != NULL && status == 1;
}

#define GETTABLE(ID, FN, ...) \
    case ID: params = FN(d)(__VA_ARGS__); break

static int test_dispatch_metadata(OSSL_PROVIDER *provider, int operation)
{
    const OSSL_ALGORITHM *algs, *alg;
    const OSSL_DISPATCH *d;
    void *pc = OSSL_PROVIDER_get0_provider_ctx(provider);
    OSSL_PARAM empty[] = {OSSL_PARAM_END};
    int no_cache = 0, count = 0;

    algs = OSSL_PROVIDER_query_operation(provider, operation, &no_cache);
    if (algs == NULL)
        return 0;
    for (alg = algs; alg->algorithm_names != NULL; ++alg) {
        for (d = alg->implementation; d->function_id != 0; ++d) {
            const OSSL_PARAM *params = NULL;
            int queried = 1;

            switch (operation) {
            case OSSL_OP_CIPHER:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_cipher_gettable_params, pc);
                GETTABLE(OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_cipher_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_cipher_settable_ctx_params, NULL, pc);
                default: queried = 0;
                }
                break;
            case OSSL_OP_DIGEST:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_digest_gettable_params, pc);
                GETTABLE(OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FUNC_digest_gettable_ctx_params, NULL, pc);
                default: queried = 0;
                }
                break;
            case OSSL_OP_MAC:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_MAC_GETTABLE_PARAMS, OSSL_FUNC_mac_gettable_params, pc);
                GETTABLE(OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, OSSL_FUNC_mac_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, OSSL_FUNC_mac_settable_ctx_params, NULL, pc);
                case OSSL_FUNC_MAC_GET_PARAMS:
                    if (OSSL_FUNC_mac_get_params(d)(empty) <= 0)
                        goto error;
                    queried = 0;
                    break;
                default: queried = 0;
                }
                break;
            case OSSL_OP_KDF:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_KDF_GETTABLE_PARAMS, OSSL_FUNC_kdf_gettable_params, pc);
                GETTABLE(OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_kdf_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, OSSL_FUNC_kdf_settable_ctx_params, NULL, pc);
                default: queried = 0;
                }
                break;
            case OSSL_OP_RAND:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_RAND_GETTABLE_PARAMS, OSSL_FUNC_rand_gettable_params, pc);
                GETTABLE(OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, OSSL_FUNC_rand_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, OSSL_FUNC_rand_settable_ctx_params, NULL, pc);
                case OSSL_FUNC_RAND_GET_PARAMS:
                    if (OSSL_FUNC_rand_get_params(d)(empty) <= 0)
                        goto error;
                    queried = 0;
                    break;
                default: queried = 0;
                }
                break;
            case OSSL_OP_KEYMGMT:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_keymgmt_gettable_params, pc);
                GETTABLE(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_keymgmt_settable_params, pc);
                GETTABLE(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_keymgmt_import_types, OSSL_KEYMGMT_SELECT_KEYPAIR);
                GETTABLE(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_keymgmt_export_types, OSSL_KEYMGMT_SELECT_KEYPAIR);
#ifdef OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX
                GETTABLE(OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX, OSSL_FUNC_keymgmt_import_types_ex, pc, OSSL_KEYMGMT_SELECT_KEYPAIR);
#endif
#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
                GETTABLE(OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX, OSSL_FUNC_keymgmt_export_types_ex, pc, OSSL_KEYMGMT_SELECT_KEYPAIR);
#endif
                case OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME:
                    if (OSSL_FUNC_keymgmt_query_operation_name(d)(OSSL_OP_KEYEXCH) == NULL)
                        goto error;
                    queried = 0;
                    break;
                default: queried = 0;
                }
                break;
            case OSSL_OP_KEYEXCH:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_keyexch_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_FUNC_keyexch_settable_ctx_params, NULL, pc);
                default: queried = 0;
                }
                break;
            case OSSL_OP_SIGNATURE:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_signature_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_signature_settable_ctx_params, NULL, pc);
#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
                case OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES:
                    if (OSSL_FUNC_signature_query_key_types(d)() == NULL)
                        goto error;
                    queried = 0;
                    break;
#endif
                default: queried = 0;
                }
                break;
            case OSSL_OP_ASYM_CIPHER:
                switch (d->function_id) {
                GETTABLE(OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_asym_cipher_gettable_ctx_params, NULL, pc);
                GETTABLE(OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_asym_cipher_settable_ctx_params, NULL, pc);
                default: queried = 0;
                }
                break;
            case OSSL_OP_ENCODER:
                if (d->function_id == OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS)
                    params = OSSL_FUNC_encoder_settable_ctx_params(d)(pc);
                else
                    queried = 0;
                break;
            case OSSL_OP_DECODER:
                if (d->function_id == OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS)
                    params = OSSL_FUNC_decoder_settable_ctx_params(d)(pc);
                else
                    queried = 0;
                break;
            default:
                queried = 0;
            }
            if (queried) {
                if (params == NULL) {
                    fprintf(stderr, "Missing metadata: operation %d, algorithm %s, function %d\n",
                            operation, alg->algorithm_names, d->function_id);
                    goto error;
                }
                ++count;
            }
        }
    }
    OSSL_PROVIDER_unquery_operation(provider, operation, algs);
    return count > 0;
error:
    OSSL_PROVIDER_unquery_operation(provider, operation, algs);
    return 0;
}

#undef GETTABLE

int main(int argc, char **argv)
{
    OSSL_PROVIDER *def = NULL, *bee2 = NULL;
    size_t i;
    int ok = 0;

    if (argc != 2)
        return 2;
    if (!OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 1;
    def = OSSL_PROVIDER_load(NULL, "default");
    bee2 = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (def == NULL || bee2 == NULL)
        goto end;
    if (!test_provider_params(bee2))
        goto end;
    for (i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        if (!test_operation(bee2, &operations[i]) ||
            !test_dispatch_metadata(bee2, operations[i].operation))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
