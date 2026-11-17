/* Key-generation ownership and failure paths, isolated from OpenSSL's
 * internal allocator.  Link-time wrappers affect provider source only. */
#include "bign_common.h"

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

extern const OSSL_DISPATCH bee2_bign_256_keymgmt_functions[];

enum failure_site {
    FAILURE_NONE,
    FAILURE_ALLOCATION,
    FAILURE_ENTROPY
};

static enum failure_site failure;
static int calls;

void *__real_CRYPTO_zalloc(size_t size, const char *file, int line);
int __real_RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf,
                             size_t len, unsigned int strength);

void *__wrap_CRYPTO_zalloc(size_t size, const char *file, int line)
{
    if (failure == FAILURE_ALLOCATION && ++calls == 1)
        return NULL;
    return __real_CRYPTO_zalloc(size, file, line);
}

int __wrap_RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf,
                             size_t len, unsigned int strength)
{
    /* Fail only once: a Bee2 sampler may retry when it draws zero. */
    if (failure == FAILURE_ENTROPY && ++calls == 1)
        return 0;
    return __real_RAND_priv_bytes_ex(ctx, buf, len, strength);
}

static int test_faults(void)
{
    OSSL_FUNC_keymgmt_new_fn *new_key = NULL;
    OSSL_FUNC_keymgmt_free_fn *free_key = NULL;
    OSSL_FUNC_keymgmt_dup_fn *duplicate = NULL;
    OSSL_FUNC_keymgmt_gen_init_fn *new_generator = NULL;
    OSSL_FUNC_keymgmt_gen_fn *generate = NULL;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *free_generator = NULL;
    const OSSL_DISPATCH *fn;
    void *ctx = NULL, *key = NULL, *copy = NULL, *temp_generator = NULL;
    int ok = 0;

    for (fn = bee2_bign_256_keymgmt_functions; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_KEYMGMT_NEW:
            new_key = OSSL_FUNC_keymgmt_new(fn);
            break;
        case OSSL_FUNC_KEYMGMT_FREE:
            free_key = OSSL_FUNC_keymgmt_free(fn);
            break;
        case OSSL_FUNC_KEYMGMT_DUP:
            duplicate = OSSL_FUNC_keymgmt_dup(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_INIT:
            new_generator = OSSL_FUNC_keymgmt_gen_init(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN:
            generate = OSSL_FUNC_keymgmt_gen(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_CLEANUP:
            free_generator = OSSL_FUNC_keymgmt_gen_cleanup(fn);
            break;
        }
    }
    if (new_key == NULL || free_key == NULL || duplicate == NULL ||
        new_generator == NULL || generate == NULL || free_generator == NULL)
        goto end;

    ctx = new_generator(NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL);
    key = new_key(NULL);
    if (ctx == NULL || key == NULL)
        goto end;
    free_key(key);
    key = NULL;

    key = generate(ctx, NULL, NULL);
    if (key == NULL)
        goto end;
    copy = duplicate(key, OSSL_KEYMGMT_SELECT_KEYPAIR);
    if (copy == NULL)
        goto end;
    free_key(copy);
    copy = NULL;

    failure = FAILURE_ALLOCATION;
    calls = 0;
    copy = new_key(NULL);
    failure = FAILURE_NONE;
    if (copy != NULL || calls != 1)
        goto end;

    failure = FAILURE_ALLOCATION;
    calls = 0;
    temp_generator = new_generator(NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL);
    failure = FAILURE_NONE;
    if (temp_generator != NULL || calls != 1)
        goto end;

    failure = FAILURE_ALLOCATION;
    calls = 0;
    copy = generate(ctx, NULL, NULL);
    failure = FAILURE_NONE;
    if (copy != NULL || calls != 1)
        goto end;

    failure = FAILURE_ALLOCATION;
    calls = 0;
    copy = duplicate(key, OSSL_KEYMGMT_SELECT_KEYPAIR);
    failure = FAILURE_NONE;
    if (copy != NULL || calls != 1)
        goto end;

    failure = FAILURE_ENTROPY;
    calls = 0;
    copy = generate(ctx, NULL, NULL);
    failure = FAILURE_NONE;
    if (copy != NULL || calls == 0)
        goto end;

    /* Recover from an entropy failure without creating a new generator. */
    copy = generate(ctx, NULL, NULL);
    if (copy == NULL)
        goto end;
    ok = 1;

end:
    failure = FAILURE_NONE;
    if (!ok)
        fputs("BIGN KEYMGMT allocation or entropy fault contract failed\n", stderr);
    if (free_key != NULL) {
        free_key(copy);
        free_key(key);
    }
    if (free_generator != NULL) {
        if (temp_generator != NULL)
            free_generator(temp_generator);
        if (ctx != NULL)
            free_generator(ctx);
    }
    return ok;
}


/* Dispatch callbacks can receive combinations of selections and parameters
 * that EVP_PKEY_fromdata() filters before reaching the provider.  Check that
 * a rejected import is transactional, and a private-only key can still
 * export its derived public component without changing its stored state. */
static int check_import_and_template(void)
{
    unsigned char scalar[32] = {3}, other_scalar[32] = {4};
    unsigned char expected[64], foreign[64], actual[64] = {0};
    char invalid[] = "invalid";
    char wrong_group[] = "bign-384";
    char explicit_encoding[] = OSSL_PKEY_EC_ENCODING_EXPLICIT;
    const OSSL_DISPATCH *fn;
    OSSL_FUNC_keymgmt_new_fn *new_key = NULL;
    OSSL_FUNC_keymgmt_free_fn *free_key = NULL;
    OSSL_FUNC_keymgmt_import_fn *import = NULL;
    OSSL_FUNC_keymgmt_get_params_fn *get_params = NULL;
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init = NULL;
    OSSL_FUNC_keymgmt_gen_set_template_fn *set_template = NULL;
    OSSL_FUNC_keymgmt_gen_set_params_fn *set_gen_params = NULL;
    OSSL_FUNC_keymgmt_gen_fn *generate = NULL;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup = NULL;
    bee2_bign_key_t *key = NULL, *empty = NULL, *different = NULL, *generated = NULL;
    void *gen = NULL;
    OSSL_PARAM private_input[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, scalar, sizeof(scalar)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_private_type[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PRIV_KEY, invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_private_length[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, scalar, 31),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_public_length[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, foreign, 1),
        OSSL_PARAM_END
    };
    OSSL_PARAM mismatched_pair[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, scalar, sizeof(scalar)),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, foreign, sizeof(foreign)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_group[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                               wrong_group, sizeof(wrong_group)),
        OSSL_PARAM_END
    };
    OSSL_PARAM empty_params[] = {OSSL_PARAM_END};
    OSSL_PARAM output[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, actual, sizeof(actual)),
        OSSL_PARAM_END
    };
    OSSL_PARAM bad_encoding[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
                               invalid, sizeof(invalid)),
        OSSL_PARAM_END
    };
    OSSL_PARAM good_encoding[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
                               explicit_encoding, sizeof(explicit_encoding)),
        OSSL_PARAM_END
    };
    int ok = 0;

    for (fn = bee2_bign_256_keymgmt_functions; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_KEYMGMT_NEW:
            new_key = OSSL_FUNC_keymgmt_new(fn);
            break;
        case OSSL_FUNC_KEYMGMT_FREE:
            free_key = OSSL_FUNC_keymgmt_free(fn);
            break;
        case OSSL_FUNC_KEYMGMT_IMPORT:
            import = OSSL_FUNC_keymgmt_import(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GET_PARAMS:
            get_params = OSSL_FUNC_keymgmt_get_params(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_INIT:
            gen_init = OSSL_FUNC_keymgmt_gen_init(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE:
            set_template = OSSL_FUNC_keymgmt_gen_set_template(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS:
            set_gen_params = OSSL_FUNC_keymgmt_gen_set_params(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN:
            generate = OSSL_FUNC_keymgmt_gen(fn);
            break;
        case OSSL_FUNC_KEYMGMT_GEN_CLEANUP:
            gen_cleanup = OSSL_FUNC_keymgmt_gen_cleanup(fn);
            break;
        }
    }
    if (new_key == NULL || free_key == NULL || import == NULL ||
        get_params == NULL || gen_init == NULL || set_template == NULL ||
        set_gen_params == NULL || generate == NULL || gen_cleanup == NULL ||
        !bee2_bign_derive_pubkey(bee2_bign_variant_256(), expected, scalar) ||
        !bee2_bign_derive_pubkey(bee2_bign_variant_256(), foreign, other_scalar))
        goto end;

    key = new_key(NULL);
    empty = new_key(NULL);
    different = bee2_bign_key_new(bee2_bign_variant_384());
    if (key == NULL || empty == NULL || different == NULL ||
        !import(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, private_input) ||
        key->has_pub || !key->has_priv ||
        !get_params(key, output) ||
        CRYPTO_memcmp(actual, expected, sizeof(expected)) != 0 ||
        key->has_pub)
        goto end;

    /* Provider-side parsing and pair validation must not alter the key on
     * failure, even when called outside the usual EVP parameter conversion. */
    if (import(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, bad_private_type) ||
        import(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, bad_private_length) ||
        import(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, bad_public_length) ||
        import(key, OSSL_KEYMGMT_SELECT_KEYPAIR, mismatched_pair) ||
        import(key, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, bad_group) ||
        import(empty, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, empty_params) ||
        import(empty, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, empty_params) ||
        key->has_pub || !key->has_priv ||
        CRYPTO_memcmp(key->priv, scalar, sizeof(scalar)) != 0 ||
        !get_params(key, output) ||
        CRYPTO_memcmp(actual, expected, sizeof(expected)) != 0)
        goto end;

    gen = gen_init(NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL);
    if (gen == NULL ||
        set_template(gen, different) ||
        !set_template(gen, key) ||
        set_gen_params(gen, bad_encoding) ||
        !set_gen_params(gen, good_encoding))
        goto end;
    generated = generate(gen, NULL, NULL);
    if (generated == NULL || !generated->has_priv || !generated->has_pub ||
        !generated->encode_explicit)
        goto end;
    ok = 1;
end:
    if (!ok)
        fputs("BIGN KEYMGMT import/template contract failed\n", stderr);
    if (free_key != NULL) {
        free_key(key);
        free_key(empty);
        free_key(generated);
    }
    bee2_bign_key_free(different);
    if (gen_cleanup != NULL && gen != NULL)
        gen_cleanup(gen);
    OPENSSL_cleanse(scalar, sizeof(scalar));
    OPENSSL_cleanse(other_scalar, sizeof(other_scalar));
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(foreign, sizeof(foreign));
    OPENSSL_cleanse(actual, sizeof(actual));
    return ok;
}

int main(void)
{
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    int ok = def != NULL && test_faults() && check_import_and_template();

    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
