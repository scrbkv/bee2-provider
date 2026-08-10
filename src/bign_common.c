#include "bign_common.h"

#include "bee2_oids.h"
#include "provider_util.h"

#include <openssl/crypto.h>
#include <string.h>

static const bee2_bign_variant_t bee2_bign_var_256 = {
    "bign-256", BEE2_OID_BIGN_CURVE256, 256u, 128u, "belt-hash"};

static const bee2_bign_variant_t bee2_bign_var_384 = {
    "bign-384", BEE2_OID_BIGN_CURVE384, 384u, 192u, "bash384"};

static const bee2_bign_variant_t bee2_bign_var_512 = {
    "bign-512", BEE2_OID_BIGN_CURVE512, 512u, 256u, "bash512"};

const bee2_bign_variant_t *bee2_bign_variant_256(void) {
    return &bee2_bign_var_256;
}

const bee2_bign_variant_t *bee2_bign_variant_384(void) {
    return &bee2_bign_var_384;
}

const bee2_bign_variant_t *bee2_bign_variant_512(void) {
    return &bee2_bign_var_512;
}

int bee2_bign_variant_matches(const bee2_bign_variant_t *variant, const char *name) {
    return variant != NULL && name != NULL &&
           (strcmp(name, variant->name) == 0 || strcmp(name, variant->curve_oid) == 0);
}

const bee2_bign_variant_t *bee2_bign_variant_from_name(const char *name) {
    const bee2_bign_variant_t *variants[] = {
        &bee2_bign_var_256, &bee2_bign_var_384, &bee2_bign_var_512};
    size_t i;

    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        if (bee2_bign_variant_matches(variants[i], name))
            return variants[i];
    }
    return NULL;
}

size_t bee2_bign_priv_len(const bee2_bign_variant_t *variant) {
    return variant ? ((size_t)variant->bits / 8u) : 0u;
}

size_t bee2_bign_pub_len(const bee2_bign_variant_t *variant) {
    return bee2_bign_priv_len(variant) * 2u;
}

size_t bee2_bign_sig_len(const bee2_bign_variant_t *variant) {
    size_t b = bee2_bign_priv_len(variant);
    return b + (b / 2u);
}

int bee2_bign_curve_init_std(const bee2_bign_variant_t *variant, bign_params *curve) {
    if (!variant || !curve)
        return 0;
    OPENSSL_cleanse(curve, sizeof(*curve));
    return bignParamsStd(curve, variant->curve_oid) == ERR_OK;
}

int bee2_bign_derive_pubkey(const bee2_bign_variant_t *variant,
                            unsigned char *pub,
                            const unsigned char *priv) {
    int ok = 0;
    bign_params curve;

    if (!variant || !pub || !priv)
        return 0;
    OPENSSL_cleanse(&curve, sizeof(curve));
    if (!bee2_bign_curve_init_std(variant, &curve))
        goto cleanup;
    ok = (bignPubkeyCalc(pub, &curve, priv) == ERR_OK);

cleanup:
    bee2_bign_cleanse(&curve, sizeof(curve));
    return ok;
}

bee2_bign_key_t *bee2_bign_key_new(const bee2_bign_variant_t *variant) {
    bee2_bign_key_t *key = OPENSSL_zalloc(sizeof(*key));

    if (key != NULL)
        key->variant = variant;
    return key;
}

void bee2_bign_key_free(bee2_bign_key_t *key) {
    if (key == NULL)
        return;
    OPENSSL_clear_free(key, sizeof(*key));
}

int bee2_bign_key_ensure_public(bee2_bign_key_t *key) {
    if (key == NULL || key->variant == NULL)
        return 0;
    if (key->has_pub)
        return 1;
    if (!key->has_priv || !bee2_bign_derive_pubkey(key->variant, key->pub, key->priv))
        return 0;
    key->has_pub = 1;
    return 1;
}

int bee2_bign_key_validate_pair(const bee2_bign_key_t *key) {
    unsigned char derived[BEE2_BIGN_MAX_WORDS * 16];
    size_t public_length;
    int valid;

    if (key == NULL || key->variant == NULL || !key->has_priv || !key->has_pub)
        return 0;

    OPENSSL_cleanse(derived, sizeof(derived));
    valid = bee2_bign_derive_pubkey(key->variant, derived, key->priv);
    public_length = bee2_bign_pub_len(key->variant);
    if (valid)
        valid = bee2_constant_time_equal(derived, key->pub, public_length);
    bee2_bign_cleanse(derived, sizeof(derived));
    return valid;
}

void bee2_bign_cleanse(void *ptr, size_t len) {
    if (!ptr || len == 0u)
        return;
    OPENSSL_cleanse(ptr, len);
}
