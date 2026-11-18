#include "bign_common.h"

#include "bee2_oids.h"
#include "provider_util.h"

#include <bee2/crypto/bign128.h>
#include <bee2/crypto/bign192.h>
#include <bee2/crypto/bign256.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string.h>

static const bee2_bign_variant_t bee2_bign_var_256 = {
    "bign-256", BEE2_OID_BIGN_CURVE256, 256u, 128u, "belt-hash"};

static const bee2_bign_variant_t bee2_bign_var_384 = {
    "bign-384", BEE2_OID_BIGN_CURVE384, 384u, 192u, "bash384"};

static const bee2_bign_variant_t bee2_bign_var_512 = {
    "bign-512", BEE2_OID_BIGN_CURVE512, 512u, 256u, "bash512"};

void bee2_bign_openssl_rng(void *buf, size_t count, void *state) {
    bee2_bign_rng_t *rng = state;

    if (rng == NULL || RAND_priv_bytes_ex(rng->libctx, buf, count, 0) != 1) {
        if (buf != NULL)
            OPENSSL_cleanse(buf, count);
        if (rng != NULL)
            rng->failed = 1;
    }
}

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
    const char *curve_names[] = {
        BEE2_NAME_BIGN_CURVE256, BEE2_NAME_BIGN_CURVE384, BEE2_NAME_BIGN_CURVE512};
    size_t i;

    for (i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        if (bee2_bign_variant_matches(variants[i], name) ||
            (name && strcmp(name, curve_names[i]) == 0))
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

/* Fixed-curve Bee2 APIs reuse precomputed curve state. The provider only
 * exposes these three standard curves, so a generic EC setup is unnecessary. */
int bee2_bign_derive_pubkey(const bee2_bign_variant_t *variant,
                            unsigned char *pub, const unsigned char *priv) {
    if (variant == &bee2_bign_var_256)
        return bign128PubkeyCalc(pub, priv) == ERR_OK;
    if (variant == &bee2_bign_var_384)
        return bign192PubkeyCalc(pub, priv) == ERR_OK;
    if (variant == &bee2_bign_var_512)
        return bign256PubkeyCalc(pub, priv) == ERR_OK;
    return 0;
}

int bee2_bign_keypair_generate(const bee2_bign_variant_t *variant,
                               unsigned char *priv, unsigned char *pub,
                               bee2_bign_rng_t *rng) {
    if (variant == &bee2_bign_var_256)
        return bign128KeypairGen(priv, pub, bee2_bign_openssl_rng, rng) == ERR_OK;
    if (variant == &bee2_bign_var_384)
        return bign192KeypairGen(priv, pub, bee2_bign_openssl_rng, rng) == ERR_OK;
    if (variant == &bee2_bign_var_512)
        return bign256KeypairGen(priv, pub, bee2_bign_openssl_rng, rng) == ERR_OK;
    return 0;
}

int bee2_bign_key_wrap(const bee2_bign_variant_t *variant, unsigned char *token,
                       const unsigned char *key, size_t len,
                       const unsigned char header[16], const unsigned char *pub,
                       bee2_bign_rng_t *rng) {
    if (variant == &bee2_bign_var_256)
        return bign128KeyWrap(token, key, len, header, pub,
                              bee2_bign_openssl_rng, rng) == ERR_OK;
    if (variant == &bee2_bign_var_384)
        return bign192KeyWrap(token, key, len, header, pub,
                              bee2_bign_openssl_rng, rng) == ERR_OK;
    if (variant == &bee2_bign_var_512)
        return bign256KeyWrap(token, key, len, header, pub,
                              bee2_bign_openssl_rng, rng) == ERR_OK;
    return 0;
}

int bee2_bign_key_unwrap(const bee2_bign_variant_t *variant, unsigned char *key,
                         const unsigned char *token, size_t len,
                         const unsigned char header[16], const unsigned char *priv) {
    if (variant == &bee2_bign_var_256)
        return bign128KeyUnwrap(key, token, len, header, priv) == ERR_OK;
    if (variant == &bee2_bign_var_384)
        return bign192KeyUnwrap(key, token, len, header, priv) == ERR_OK;
    if (variant == &bee2_bign_var_512)
        return bign256KeyUnwrap(key, token, len, header, priv) == ERR_OK;
    return 0;
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

int bee2_bign_key_validate_public(const bee2_bign_key_t *key) {
    if (!key || !key->variant || !key->has_pub)
        return 0;
    if (key->variant == &bee2_bign_var_256)
        return bign128PubkeyVal(key->pub) == ERR_OK;
    if (key->variant == &bee2_bign_var_384)
        return bign192PubkeyVal(key->pub) == ERR_OK;
    if (key->variant == &bee2_bign_var_512)
        return bign256PubkeyVal(key->pub) == ERR_OK;
    return 0;
}

int bee2_bign_key_validate_pair(const bee2_bign_key_t *key) {
    if (!key || !key->variant || !key->has_priv || !key->has_pub)
        return 0;
    if (key->variant == &bee2_bign_var_256)
        return bign128KeypairVal(key->priv, key->pub) == ERR_OK;
    if (key->variant == &bee2_bign_var_384)
        return bign192KeypairVal(key->priv, key->pub) == ERR_OK;
    if (key->variant == &bee2_bign_var_512)
        return bign256KeypairVal(key->priv, key->pub) == ERR_OK;
    return 0;
}

void bee2_bign_cleanse(void *ptr, size_t len) {
    if (!ptr || len == 0u)
        return;
    OPENSSL_cleanse(ptr, len);
}
