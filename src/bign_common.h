#ifndef BEE2_BIGN_COMMON_H
#define BEE2_BIGN_COMMON_H

#include "bee2_backend.h"
#include "provider.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *name;
    const char *curve_oid;
    uint32_t bits;
    uint32_t security_bits;
    const char *default_digest;
} bee2_bign_variant_t;

typedef struct {
    const bee2_bign_variant_t *variant;
    int has_pub;
    int has_priv;
    int encode_explicit;
    int encode_cofactor;
    octet pub[BEE2_BIGN_MAX_WORDS * 16];
    octet priv[BEE2_BIGN_MAX_WORDS * 8];
} bee2_bign_key_t;

const bee2_bign_variant_t *bee2_bign_variant_256(void);
const bee2_bign_variant_t *bee2_bign_variant_384(void);
const bee2_bign_variant_t *bee2_bign_variant_512(void);
const bee2_bign_variant_t *bee2_bign_variant_from_name(const char *name);
int bee2_bign_variant_matches(const bee2_bign_variant_t *variant, const char *name);

size_t bee2_bign_priv_len(const bee2_bign_variant_t *variant);
size_t bee2_bign_pub_len(const bee2_bign_variant_t *variant);
size_t bee2_bign_sig_len(const bee2_bign_variant_t *variant);

int bee2_bign_curve_init_std(const bee2_bign_variant_t *variant, bign_params *curve);
int bee2_bign_derive_pubkey(const bee2_bign_variant_t *variant,
                            unsigned char *pub,
                            const unsigned char *priv);

bee2_bign_key_t *bee2_bign_key_new(const bee2_bign_variant_t *variant);
void bee2_bign_key_free(bee2_bign_key_t *key);
int bee2_bign_key_ensure_public(bee2_bign_key_t *key);
int bee2_bign_key_validate_pair(const bee2_bign_key_t *key);

void bee2_bign_cleanse(void *ptr, size_t len);

#endif /* BEE2_BIGN_COMMON_H */
