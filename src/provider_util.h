#ifndef BEE2_PROVIDER_UTIL_H
#define BEE2_PROVIDER_UTIL_H

#include <stddef.h>

int bee2_secret_replace(unsigned char **destination,
                        size_t *destination_length,
                        const void *source,
                        size_t source_length);

#endif
