/* Provider-native BIGN signature context duplication and failure rollback.
 * Wrap only calls linked from the provider source built into this executable,
 * leaving OpenSSL's own allocator and digest objects unaffected. */
#include "bign_common.h"
#include "provider.h"

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

extern const OSSL_DISPATCH bee2_bign_256_signature_functions[];

enum fault_site {
    FAULT_NONE,
    FAULT_MEMDUP,
    FAULT_MD_UP_REF,
    FAULT_MD_CTX_NEW,
    FAULT_MD_CTX_COPY,
    FAULT_MD_FETCH
};

static enum fault_site fault;
static int injected;

static int should_fail(enum fault_site site)
{
    if (fault != site)
        return 0;
    injected++;
    return 1;
}

void *__real_CRYPTO_memdup(const void *data, size_t size,
                          const char *file, int line);
int __real_EVP_MD_up_ref(EVP_MD *md);
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
int __real_EVP_MD_CTX_copy_ex(EVP_MD_CTX *dst, const EVP_MD_CTX *src);
EVP_MD *__real_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *name,
                            const char *properties);

void *__wrap_CRYPTO_memdup(const void *data, size_t size,
                          const char *file, int line)
{
    return should_fail(FAULT_MEMDUP) ? NULL :
           __real_CRYPTO_memdup(data, size, file, line);
}

int __wrap_EVP_MD_up_ref(EVP_MD *md)
{
    return should_fail(FAULT_MD_UP_REF) ? 0 : __real_EVP_MD_up_ref(md);
}

EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void)
{
    return should_fail(FAULT_MD_CTX_NEW) ? NULL : __real_EVP_MD_CTX_new();
}

int __wrap_EVP_MD_CTX_copy_ex(EVP_MD_CTX *dst, const EVP_MD_CTX *src)
{
    return should_fail(FAULT_MD_CTX_COPY) ? 0 :
           __real_EVP_MD_CTX_copy_ex(dst, src);
}

EVP_MD *__wrap_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *name,
                            const char *properties)
{
    return should_fail(FAULT_MD_FETCH) ? NULL :
           __real_EVP_MD_fetch(ctx, name, properties);
}

static int check_signature_faults(void)
{
    static const unsigned char data[] = "signature context duplication";
    OSSL_FUNC_signature_newctx_fn *newctx = NULL;
    OSSL_FUNC_signature_freectx_fn *freectx = NULL;
    OSSL_FUNC_signature_dupctx_fn *dupctx = NULL;
    OSSL_FUNC_signature_digest_sign_init_fn *init = NULL;
    OSSL_FUNC_signature_digest_sign_update_fn *update = NULL;
    const OSSL_DISPATCH *fn;
    bee2_bign_key_t key = {0};
    void *ctx = NULL, *copy = NULL;
    enum fault_site site;
    int ok = 0;

    for (fn = bee2_bign_256_signature_functions; fn->function_id != 0; ++fn) {
        switch (fn->function_id) {
        case OSSL_FUNC_SIGNATURE_NEWCTX:
            newctx = OSSL_FUNC_signature_newctx(fn);
            break;
        case OSSL_FUNC_SIGNATURE_FREECTX:
            freectx = OSSL_FUNC_signature_freectx(fn);
            break;
        case OSSL_FUNC_SIGNATURE_DUPCTX:
            dupctx = OSSL_FUNC_signature_dupctx(fn);
            break;
        case OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT:
            init = OSSL_FUNC_signature_digest_sign_init(fn);
            break;
        case OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE:
            update = OSSL_FUNC_signature_digest_sign_update(fn);
            break;
        }
    }
    if (newctx == NULL || freectx == NULL || dupctx == NULL ||
        init == NULL || update == NULL)
        goto end;

    key.variant = bee2_bign_variant_256();
    key.has_priv = 1;
    key.priv[0] = 3;
    if (!bee2_bign_derive_pubkey(key.variant, key.pub, key.priv))
        goto end;
    key.has_pub = 1;

    ctx = newctx(NULL, NULL);
    if (ctx == NULL || init(ctx, "belt-hash", &key, NULL) <= 0 ||
        update(ctx, data, sizeof(data)) <= 0)
        goto end;

    copy = dupctx(ctx);
    if (copy == NULL)
        goto end;
    freectx(copy);
    copy = NULL;

    /* Each failure must be observed, rejected and safely released. */
    for (site = FAULT_MEMDUP; site <= FAULT_MD_CTX_COPY; ++site) {
        fault = site;
        injected = 0;
        copy = dupctx(ctx);
        fault = FAULT_NONE;
        if (copy != NULL || injected == 0)
            goto end;
    }

    /* A failed DigestSignInit is recoverable through another init. */
    fault = FAULT_MD_FETCH;
    injected = 0;
    if (init(ctx, "belt-hash", &key, NULL) > 0) {
        fault = FAULT_NONE;
        goto end;
    }
    fault = FAULT_NONE;
    if (injected == 0 || init(ctx, "belt-hash", &key, NULL) <= 0 ||
        update(ctx, data, sizeof(data)) <= 0)
        goto end;

    copy = dupctx(ctx);
    if (copy == NULL)
        goto end;
    ok = 1;

end:
    fault = FAULT_NONE;
    if (!ok)
        fputs("BIGN signature allocation fault contract failed\n", stderr);
    if (freectx != NULL) {
        freectx(copy);
        freectx(ctx);
    }
    OPENSSL_cleanse(&key, sizeof(key));
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *default_provider = NULL, *bee2_provider = NULL;
    int ok = 0;

    if (argc != 2 || !OSSL_PROVIDER_set_default_search_path(NULL, argv[1]))
        return 2;
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    bee2_provider = OSSL_PROVIDER_load(NULL, "bee2_provider");
    if (default_provider != NULL && bee2_provider != NULL)
        ok = check_signature_faults();
    OSSL_PROVIDER_unload(bee2_provider);
    OSSL_PROVIDER_unload(default_provider);
    return ok ? 0 : 1;
}
