/* Every documented provider algorithm must be visible through OSSL_PROVIDER. */
#include <openssl/core_dispatch.h>
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
    for (i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        if (!test_operation(bee2, &operations[i]))
            goto end;
    ok = 1;
end:
    OSSL_PROVIDER_unload(bee2);
    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
