/* Exercise secret replacement and constant-time comparison edge cases. */
#include "provider_util.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

static int reject_memdup;

void *__real_CRYPTO_memdup(const void *source, size_t length,
                          const char *file, int line);

void *__wrap_CRYPTO_memdup(const void *source, size_t length,
                          const char *file, int line)
{
    if (reject_memdup)
        return NULL;
    return __real_CRYPTO_memdup(source, length, file, line);
}

static int check_comparison(void)
{
    static const unsigned char a[] = {0, 1, 2, 3};
    static const unsigned char b[] = {0, 1, 2, 4};

    return bee2_constant_time_equal(NULL, NULL, 0) &&
           !bee2_constant_time_equal(NULL, a, sizeof(a)) &&
           !bee2_constant_time_equal(a, NULL, sizeof(a)) &&
           bee2_constant_time_equal(a, a, sizeof(a)) &&
           !bee2_constant_time_equal(a, b, sizeof(a));
}

static int check_replacement(void)
{
    static const unsigned char first[] = {1, 2, 3, 4};
    static const unsigned char second[] = {5, 6, 7};
    unsigned char *secret = NULL;
    unsigned char *before;
    size_t length = 0;
    int ok = 0;

    if (bee2_secret_replace(NULL, &length, first, sizeof(first)) ||
        bee2_secret_replace(&secret, NULL, first, sizeof(first)) ||
        bee2_secret_replace(&secret, &length, NULL, 1) ||
        !bee2_secret_replace(&secret, &length, first, sizeof(first)) ||
        length != sizeof(first) || secret == NULL ||
        memcmp(secret, first, sizeof(first)) != 0)
        goto end;

    /* The source may refer to the buffer being replaced. */
    if (!bee2_secret_replace(&secret, &length, secret, length) ||
        length != sizeof(first) ||
        memcmp(secret, first, sizeof(first)) != 0)
        goto end;

    before = secret;
    reject_memdup = 1;
    if (bee2_secret_replace(&secret, &length, second, sizeof(second)))
        goto end;
    reject_memdup = 0;
    if (secret != before || length != sizeof(first) ||
        memcmp(secret, first, sizeof(first)) != 0)
        goto end;

    if (!bee2_secret_replace(&secret, &length, NULL, 0) ||
        secret != NULL || length != 0 ||
        !bee2_secret_replace(&secret, &length, second, sizeof(second)) ||
        length != sizeof(second) ||
        memcmp(secret, second, sizeof(second)) != 0 ||
        !bee2_secret_replace(&secret, &length, second, 0) ||
        secret != NULL || length != 0)
        goto end;

    ok = 1;
end:
    reject_memdup = 0;
    OPENSSL_clear_free(secret, length);
    return ok;
}

int main(void)
{
    if (!check_comparison() || !check_replacement()) {
        fprintf(stderr, "Provider utility contract failed\n");
        return 1;
    }
    return 0;
}
