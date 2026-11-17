/* Verify secret replacement semantics, including aliasing and clearing. */
#include "provider_util.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

static int check_replacement(void)
{
    static const unsigned char first[] = {1, 2, 3, 4};
    static const unsigned char second[] = {5, 6, 7};
    unsigned char *secret = NULL;
    size_t length = 0;
    int ok = 0;

    if (bee2_secret_replace(&secret, &length, NULL, 1) ||
        !bee2_secret_replace(&secret, &length, first, sizeof(first)) ||
        length != sizeof(first) || secret == NULL ||
        memcmp(secret, first, sizeof(first)) != 0)
        goto end;

    /* The source may refer to the buffer being replaced. */
    if (!bee2_secret_replace(&secret, &length, secret, length) ||
        length != sizeof(first) ||
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
    OPENSSL_clear_free(secret, length);
    return ok;
}

int main(void)
{
    if (!check_replacement()) {
        fprintf(stderr, "Provider utility contract failed\n");
        return 1;
    }
    return 0;
}
