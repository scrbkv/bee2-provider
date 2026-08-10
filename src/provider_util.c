#include "provider_util.h"

#include <openssl/crypto.h>

int bee2_secret_replace(unsigned char **destination,
                        size_t *destination_length,
                        const void *source,
                        size_t source_length) {
    unsigned char *replacement = NULL;

    if (destination == NULL || destination_length == NULL || (source == NULL && source_length != 0))
        return 0;

    if (source_length != 0) {
        replacement = OPENSSL_memdup(source, source_length);
        if (replacement == NULL)
            return 0;
    }

    OPENSSL_clear_free(*destination, *destination_length);
    *destination = replacement;
    *destination_length = source_length;
    return 1;
}

int bee2_constant_time_equal(const void *left, const void *right, size_t length) {
    if (length == 0)
        return 1;
    if (left == NULL || right == NULL)
        return 0;
    return CRYPTO_memcmp(left, right, length) == 0;
}
