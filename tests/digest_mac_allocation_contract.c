/* Exercise allocation failure in the provider's real digest and MAC callbacks.
 * The linker wraps only calls made by the source compiled into this test,
 * not libcrypto's own allocations.  No duplicate digest KATs are needed. */
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

extern const OSSL_DISPATCH bee2_belt_hash_functions[];
extern const OSSL_DISPATCH bee2_belt_mac256_functions[];
extern const OSSL_DISPATCH bee2_bash256_functions[];
extern const OSSL_DISPATCH bee2_bash384_functions[];
extern const OSSL_DISPATCH bee2_bash512_functions[];

static int fail_allocation;
static int allocation_calls;

void *__real_CRYPTO_malloc(size_t size, const char *file, int line);
void *__real_CRYPTO_zalloc(size_t size, const char *file, int line);
void *__wrap_CRYPTO_malloc(size_t size, const char *file, int line)
{
    if (fail_allocation && ++allocation_calls == 1)
        return NULL;
    return __real_CRYPTO_malloc(size, file, line);
}

static int check_digest(const OSSL_DISPATCH *functions,
                        const char *name, size_t expected_size)
{
    static const unsigned char message[] = "digest allocation rollback";
    OSSL_FUNC_digest_newctx_fn *newctx = NULL;
    OSSL_FUNC_digest_freectx_fn *freectx = NULL;
    OSSL_FUNC_digest_dupctx_fn *dupctx = NULL;
    OSSL_FUNC_digest_init_fn *init = NULL;
    OSSL_FUNC_digest_update_fn *update = NULL;
    OSSL_FUNC_digest_final_fn *final = NULL;
    const OSSL_DISPATCH *fn;
    unsigned char first[64] = {0}, second[64] = {0};
    size_t first_len = 0, second_len = 0;
    void *ctx = NULL, *clone = NULL;
    int ok = 0;

    for (fn = functions; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_DIGEST_NEWCTX:
            newctx = OSSL_FUNC_digest_newctx(fn);
            break;
        case OSSL_FUNC_DIGEST_FREECTX:
            freectx = OSSL_FUNC_digest_freectx(fn);
            break;
        case OSSL_FUNC_DIGEST_DUPCTX:
            dupctx = OSSL_FUNC_digest_dupctx(fn);
            break;
        case OSSL_FUNC_DIGEST_INIT:
            init = OSSL_FUNC_digest_init(fn);
            break;
        case OSSL_FUNC_DIGEST_UPDATE:
            update = OSSL_FUNC_digest_update(fn);
            break;
        case OSSL_FUNC_DIGEST_FINAL:
            final = OSSL_FUNC_digest_final(fn);
            break;
        }
    }
    if (newctx == NULL || freectx == NULL || dupctx == NULL ||
        init == NULL || update == NULL || final == NULL)
        goto done;

    fail_allocation = 1;
    allocation_calls = 0;
    ctx = newctx(NULL);
    fail_allocation = 0;
    if (ctx != NULL || allocation_calls != 1)
        goto done;

    ctx = newctx(NULL);
    if (ctx == NULL || !init(ctx, NULL) ||
        !update(ctx, message, sizeof(message) - 1))
        goto done;

    fail_allocation = 1;
    allocation_calls = 0;
    clone = dupctx(ctx);
    fail_allocation = 0;
    if (clone != NULL || allocation_calls != 1)
        goto done;

    clone = dupctx(ctx);
    if (clone == NULL ||
        !final(ctx, first, &first_len, sizeof(first)) ||
        !final(clone, second, &second_len, sizeof(second)) ||
        first_len != expected_size || second_len != expected_size ||
        CRYPTO_memcmp(first, second, expected_size) != 0)
        goto done;
    ok = 1;

done:
    fail_allocation = 0;
    if (!ok)
        fprintf(stderr, "%s: digest allocation rollback failed\n", name);
    if (freectx != NULL) {
        freectx(clone);
        freectx(ctx);
    }
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return ok;
}


void *__wrap_CRYPTO_zalloc(size_t size, const char *file, int line)
{
    if (fail_allocation && ++allocation_calls == 1)
        return NULL;
    return __real_CRYPTO_zalloc(size, file, line);
}

/* BELT-MAC also owns expanded key state, so a failed duplication must
 * preserve the original context's ability to finalize. */
static int check_mac(void)
{
    static const unsigned char data[] = "BELT-MAC allocation rollback";
    const OSSL_DISPATCH *fn;
    OSSL_FUNC_mac_newctx_fn *newctx = NULL;
    OSSL_FUNC_mac_freectx_fn *freectx = NULL;
    OSSL_FUNC_mac_dupctx_fn *dupctx = NULL;
    OSSL_FUNC_mac_init_fn *init = NULL;
    OSSL_FUNC_mac_update_fn *update = NULL;
    OSSL_FUNC_mac_final_fn *final = NULL;
    unsigned char key[32] = {0}, first[8], second[8];
    size_t first_len = 0, second_len = 0;
    void *ctx = NULL, *clone = NULL;
    int ok = 0;

    for (fn = bee2_belt_mac256_functions; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_MAC_NEWCTX:
            newctx = OSSL_FUNC_mac_newctx(fn);
            break;
        case OSSL_FUNC_MAC_FREECTX:
            freectx = OSSL_FUNC_mac_freectx(fn);
            break;
        case OSSL_FUNC_MAC_DUPCTX:
            dupctx = OSSL_FUNC_mac_dupctx(fn);
            break;
        case OSSL_FUNC_MAC_INIT:
            init = OSSL_FUNC_mac_init(fn);
            break;
        case OSSL_FUNC_MAC_UPDATE:
            update = OSSL_FUNC_mac_update(fn);
            break;
        case OSSL_FUNC_MAC_FINAL:
            final = OSSL_FUNC_mac_final(fn);
            break;
        }
    }
    if (newctx == NULL || freectx == NULL || dupctx == NULL ||
        init == NULL || update == NULL || final == NULL)
        goto end;

    fail_allocation = 1;
    allocation_calls = 0;
    ctx = newctx(NULL);
    fail_allocation = 0;
    if (ctx != NULL || allocation_calls != 1)
        goto end;
    ctx = newctx(NULL);
    if (ctx == NULL || !init(ctx, key, sizeof(key), NULL) ||
        !update(ctx, data, sizeof(data) - 1))
        goto end;

    fail_allocation = 1;
    allocation_calls = 0;
    clone = dupctx(ctx);
    fail_allocation = 0;
    if (clone != NULL || allocation_calls != 1)
        goto end;
    clone = dupctx(ctx);
    if (clone == NULL ||
        !final(ctx, first, &first_len, sizeof(first)) ||
        !final(clone, second, &second_len, sizeof(second)) ||
        first_len != sizeof(first) || second_len != sizeof(second) ||
        CRYPTO_memcmp(first, second, sizeof(first)) != 0)
        goto end;
    ok = 1;
end:
    fail_allocation = 0;
    if (!ok)
        fprintf(stderr, "BELT-MAC allocation rollback failed\n");
    if (freectx != NULL) {
        freectx(clone);
        freectx(ctx);
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return ok;
}

int main(void)
{
    return check_digest(bee2_belt_hash_functions, "belt-hash", 32) &&
           check_digest(bee2_bash256_functions, "bash256", 32) &&
           check_digest(bee2_bash384_functions, "bash384", 48) &&
           check_digest(bee2_bash512_functions, "bash512", 64) &&
           check_mac() ? 0 : 1;
}
