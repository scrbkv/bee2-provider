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
    void *ctx = NULL, *key = NULL, *copy = NULL;
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
    copy = new_generator(NULL, OSSL_KEYMGMT_SELECT_KEYPAIR, NULL);
    failure = FAILURE_NONE;
    if (copy != NULL || calls != 1)
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
    if (free_generator != NULL)
        free_generator(ctx);
    return ok;
}

int main(void)
{
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    int ok = def != NULL && test_faults();

    OSSL_PROVIDER_unload(def);
    return ok ? 0 : 1;
}
