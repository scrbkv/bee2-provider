#ifndef BEE2_PROVIDER_UTIL_H
#define BEE2_PROVIDER_UTIL_H

#include <stddef.h>

int bee2_secret_replace(unsigned char **destination,
                        size_t *destination_length,
                        const void *source,
                        size_t source_length);
int bee2_constant_time_equal(const void *left, const void *right, size_t length);

#endif
