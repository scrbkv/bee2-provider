#include "bign_common.h"
#include "provider_util.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <string.h>

#define BEE2_PKEY_PARAM_ENC_PARAMS "enc_params"

typedef struct {
    OSSL_LIB_CTX *libctx;
    const bee2_bign_variant_t *variant;
    int selection;
    int encode_explicit;
    int encode_cofactor;
} bee2_bign_gen_ctx_t;

static const OSSL_PARAM bee2_bign_keymgmt_impexp_types[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bign_keymgmt_gettable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bign_keymgmt_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(BEE2_PKEY_PARAM_ENC_PARAMS, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bign_gen_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
    OSSL_PARAM_utf8_string(BEE2_PKEY_PARAM_ENC_PARAMS, NULL, 0),
    OSSL_PARAM_END};

static int
bign_apply_encoding_params(int *encode_explicit, int *encode_cofactor, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;
    char *value = NULL;
    int explicit_encoding, cofactor_encoding;
    int ok = 0;

    if (params == NULL)
        return 1;

    explicit_encoding = *encode_explicit;
    cofactor_encoding = *encode_cofactor;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
    if (p) {
        if (!OSSL_PARAM_get_utf8_string(p, &value, 0))
            goto cleanup;
        if (OPENSSL_strcasecmp(value, OSSL_PKEY_EC_ENCODING_EXPLICIT) == 0)
            explicit_encoding = 1;
        else if (OPENSSL_strcasecmp(value, OSSL_PKEY_EC_ENCODING_GROUP) == 0)
            explicit_encoding = 0;
        else
            goto cleanup;
        OPENSSL_free(value);
        value = NULL;
    }

    p = OSSL_PARAM_locate_const(params, BEE2_PKEY_PARAM_ENC_PARAMS);
    if (p) {
        if (!OSSL_PARAM_get_utf8_string(p, &value, 0))
            goto cleanup;
        if (OPENSSL_strcasecmp(value, "specified") == 0)
            explicit_encoding = 1;
        else if (OPENSSL_strcasecmp(value, "cofactor") == 0)
            cofactor_encoding = 1;
        else
            goto cleanup;
    }
    *encode_explicit = explicit_encoding;
    *encode_cofactor = cofactor_encoding;
    ok = 1;

cleanup:
    OPENSSL_free(value);
    return ok;
}

static int bign_set_variant_from_params(bee2_bign_key_t *key, const OSSL_PARAM params[]) {
    const OSSL_PARAM *p;
    char *group = NULL;
    const bee2_bign_variant_t *variant = NULL;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (!p)
        return key->variant != NULL;

    if (!OSSL_PARAM_get_utf8_string(p, &group, 0))
        return 0;
    variant = bee2_bign_variant_from_name(group);
    OPENSSL_free(group);
    if (!variant)
        return 0;
    if (key->variant && key->variant != variant)
        return 0;
    key->variant = variant;
    return 1;
}

static void *bign_new_common(const bee2_bign_variant_t *variant) {
    return bee2_bign_key_new(variant);
}

static void *bign256_new(void *provctx) {
    (void)provctx;
    return bign_new_common(bee2_bign_variant_256());
}

static void *bign384_new(void *provctx) {
    (void)provctx;
    return bign_new_common(bee2_bign_variant_384());
}

static void *bign512_new(void *provctx) {
    (void)provctx;
    return bign_new_common(bee2_bign_variant_512());
}

static void *bign_new(void *provctx) {
    (void)provctx;
    return bign_new_common(NULL);
}

static void bign_key_free(void *vkey) {
    bee2_bign_key_free(vkey);
}

static int bign_has(const void *vkey, int selection) {
    const bee2_bign_key_t *key = vkey;
    int ok = 1;

    if (!key)
        return 0;
    if (!key->variant)
        return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        ok &= key->has_pub;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        ok &= key->has_priv;
    return ok;
}

static int bign_match(const void *vkey1, const void *vkey2, int selection) {
    const bee2_bign_key_t *k1 = vkey1;
    const bee2_bign_key_t *k2 = vkey2;
    size_t priv_len;
    size_t pub_len;

    if (!k1 || !k2)
        return 0;
    if (!k1->variant || !k2->variant)
        return 0;
    if (k1->variant != k2->variant)
        return 0;

    priv_len = bee2_bign_priv_len(k1->variant);
    pub_len = bee2_bign_pub_len(k1->variant);

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!k1->has_priv || !k2->has_priv)
            return 0;
        if (!bee2_constant_time_equal(k1->priv, k2->priv, priv_len))
            return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!k1->has_pub || !k2->has_pub)
            return 0;
        if (!bee2_constant_time_equal(k1->pub, k2->pub, pub_len))
            return 0;
    }
    return 1;
}

static int bign_validate(const void *vkey, int selection, int checktype) {
    const bee2_bign_key_t *key = vkey;
    (void)checktype;
    if (!bign_has(vkey, selection))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        return bee2_bign_key_validate_pair(key);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) &&
        !bee2_bign_key_validate_public(key))
        return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        unsigned char derived[BEE2_BIGN_MAX_WORDS * 16];
        int valid = bee2_bign_derive_pubkey(key->variant, derived, key->priv);

        bee2_bign_cleanse(derived, sizeof(derived));
        return valid;
    }
    return 1;
}

/* Derive missing public data into a caller-local buffer. Key queries and
 * exports must not mutate an EVP_PKEY that other threads may be reading. */
static int bign_public_bytes(const bee2_bign_key_t *key,
                             unsigned char derived[BEE2_BIGN_MAX_WORDS * 16],
                             const unsigned char **pub)
{
    if (key->has_pub) {
        *pub = key->pub;
        return 1;
    }
    if (!key->has_priv ||
        !bee2_bign_derive_pubkey(key->variant, derived, key->priv))
        return 0;
    *pub = derived;
    return 1;
}

static int bign_get_params(void *vkey, OSSL_PARAM params[]) {
    const bee2_bign_key_t *key = vkey;
    OSSL_PARAM *p, *public_param, *encoded_param;
    const unsigned char *pub = NULL;
    unsigned char derived[BEE2_BIGN_MAX_WORDS * 16] = {0};
    size_t priv_len, pub_len;
    int ok = 0;

    if (!key || !key->variant)
        return 0;
    priv_len = bee2_bign_priv_len(key->variant);
    pub_len = bee2_bign_pub_len(key->variant);

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p && !OSSL_PARAM_set_utf8_string(p, key->variant->curve_oid))
        goto cleanup;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p && !OSSL_PARAM_set_int(p, (int)key->variant->bits))
        goto cleanup;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p && !OSSL_PARAM_set_int(p, (int)key->variant->security_bits))
        goto cleanup;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, bee2_bign_sig_len(key->variant)))
        goto cleanup;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
    if (p && !OSSL_PARAM_set_utf8_string(p, key->variant->default_digest))
        goto cleanup;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p && (!key->has_priv || !OSSL_PARAM_set_octet_string(p, key->priv, priv_len)))
        goto cleanup;

    public_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    encoded_param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (public_param || encoded_param) {
        if (!bign_public_bytes(key, derived, &pub))
            goto cleanup;
        if ((public_param && !OSSL_PARAM_set_octet_string(public_param, pub, pub_len)) ||
            (encoded_param && !OSSL_PARAM_set_octet_string(encoded_param, pub, pub_len)))
            goto cleanup;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_ENCODING);
    if (p && !OSSL_PARAM_set_utf8_string(p,
                                         key->encode_explicit ? OSSL_PKEY_EC_ENCODING_EXPLICIT
                                                              : OSSL_PKEY_EC_ENCODING_GROUP))
        goto cleanup;
    ok = 1;

cleanup:
    OPENSSL_cleanse(derived, sizeof(derived));
    return ok;
}

static const OSSL_PARAM *bign_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_bign_keymgmt_gettable_params;
}

int bee2_bign_import_params(void *vkey, int selection, const OSSL_PARAM params[]) {
    bee2_bign_key_t *key = vkey;
    bee2_bign_key_t candidate;
    const OSSL_PARAM *p;
    const void *buf = NULL;
    size_t len = 0;
    size_t priv_len;
    size_t pub_len;
    int have_priv_in = 0;
    int have_pub_in = 0;

    int ok = 0;

    if (!key || !params)
        return 0;
    candidate = *key;
    if (!bign_apply_encoding_params(&candidate.encode_explicit, &candidate.encode_cofactor, params))
        goto cleanup;
    if (!bign_set_variant_from_params(&candidate, params))
        goto cleanup;

    priv_len = bee2_bign_priv_len(candidate.variant);
    pub_len = bee2_bign_pub_len(candidate.variant);

    p = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
            ? OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) : NULL;
    if (p) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &buf, &len))
            goto cleanup;
        if (buf == NULL || len != priv_len)
            goto cleanup;
        memcpy(candidate.priv, buf, priv_len);
        candidate.has_priv = 1;
        have_priv_in = 1;
    }

    p = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
            ? OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY) : NULL;
    if (!p && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p) {
        if (!OSSL_PARAM_get_octet_string_ptr(p, &buf, &len))
            goto cleanup;
        if (buf == NULL || len != pub_len)
            goto cleanup;
        memcpy(candidate.pub, buf, pub_len);
        candidate.has_pub = 1;
        have_pub_in = 1;
    }

    if (have_priv_in && !have_pub_in) {
        bee2_bign_cleanse(candidate.pub, sizeof(candidate.pub));
        candidate.has_pub = 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !candidate.has_priv)
        goto cleanup;

    if (!have_priv_in && !have_pub_in && !(selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS))
        goto cleanup;
    if (candidate.has_priv) {
        unsigned char derived[BEE2_BIGN_MAX_WORDS * 16];
        int valid = bee2_bign_derive_pubkey(candidate.variant, derived, candidate.priv);

        if (valid && candidate.has_pub)
            valid = bee2_constant_time_equal(derived, candidate.pub, pub_len);
        if (valid && !candidate.has_pub &&
            (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
            memcpy(candidate.pub, derived, pub_len);
            candidate.has_pub = 1;
        }
        bee2_bign_cleanse(derived, sizeof(derived));
        if (!valid)
            goto cleanup;
    } else if (candidate.has_pub && !bee2_bign_key_validate_public(&candidate)) {
        goto cleanup;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !candidate.has_pub)
        goto cleanup;

    *key = candidate;
    ok = 1;

cleanup:
    bee2_bign_cleanse(&candidate, sizeof(candidate));
    return ok;
}

static const OSSL_PARAM *bign_import_types(int selection) {
    (void)selection;
    return bee2_bign_keymgmt_impexp_types;
}

#ifdef OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX
static const OSSL_PARAM *bign_import_types_ex(void *provctx, int selection) {
    (void)provctx;
    (void)selection;
    return bee2_bign_keymgmt_impexp_types;
}

#endif

int bee2_bign_export_params(void *vkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg) {
    const bee2_bign_key_t *key = vkey;
    OSSL_PARAM params[6];
    unsigned char derived[BEE2_BIGN_MAX_WORDS * 16] = {0};
    const unsigned char *pub = NULL;
    size_t n = 0, priv_len, pub_len;
    char *encoding;
    int ok = 0;

    if (!key || !param_cb || !key->variant)
        return 0;
    priv_len = bee2_bign_priv_len(key->variant);
    pub_len = bee2_bign_pub_len(key->variant);
    encoding = key->encode_explicit ? OSSL_PKEY_EC_ENCODING_EXPLICIT : OSSL_PKEY_EC_ENCODING_GROUP;

    if (selection & (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS |
                     OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *)key->variant->curve_oid, 0);
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, encoding, 0);

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (!bign_public_bytes(key, derived, &pub))
            goto cleanup;
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                        (void *)pub, pub_len);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (void *)pub, pub_len);
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!key->has_priv)
            goto cleanup;
        params[n++] =
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)key->priv, priv_len);
    }

    params[n] = OSSL_PARAM_construct_end();
    ok = param_cb(params, cbarg);

cleanup:
    OPENSSL_cleanse(derived, sizeof(derived));
    return ok;
}

static const OSSL_PARAM *bign_export_types(int selection) {
    (void)selection;
    return bee2_bign_keymgmt_impexp_types;
}

#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
static const OSSL_PARAM *bign_export_types_ex(void *provctx, int selection) {
    (void)provctx;
    (void)selection;
    return bee2_bign_keymgmt_impexp_types;
}

#endif

static int bign_set_params(void *vkey, const OSSL_PARAM params[]) {
    bee2_bign_key_t *key = vkey;
    int selection = 0;

    if (!params)
        return 1;
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME))
        selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY))
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY) ||
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY))
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    if (selection == 0)
        return bign_apply_encoding_params(&key->encode_explicit, &key->encode_cofactor, params);
    return bee2_bign_import_params(vkey, selection, params);
}

static const OSSL_PARAM *bign_settable_params(void *provctx) {
    (void)provctx;
    return bee2_bign_keymgmt_settable_params;
}

static void *bign_dup(const void *vkey_from, int selection) {
    const bee2_bign_key_t *src = vkey_from;
    bee2_bign_key_t *dst;
    size_t priv_len;
    size_t pub_len;

    if (!src->variant)
        return NULL;
    dst = bign_new_common(src->variant);
    if (!dst)
        return NULL;
    dst->encode_explicit = src->encode_explicit;
    dst->encode_cofactor = src->encode_cofactor;

    priv_len = bee2_bign_priv_len(src->variant);
    pub_len = bee2_bign_pub_len(src->variant);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && src->has_priv) {
        memcpy(dst->priv, src->priv, priv_len);
        dst->has_priv = 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && src->has_pub) {
        memcpy(dst->pub, src->pub, pub_len);
        dst->has_pub = 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && !dst->has_pub && src->has_priv) {
        if (!bee2_bign_derive_pubkey(src->variant, dst->pub, src->priv)) {
            bign_key_free(dst);
            return NULL;
        }
        dst->has_pub = 1;
    }

    return dst;
}

static void *bign_load(const void *reference, size_t reference_sz) {
    const bee2_bign_key_t *src = NULL;

    if (!reference || reference_sz != sizeof(src))
        return NULL;
    memcpy(&src, reference, sizeof(src));
    if (!src || !src->variant)
        return NULL;

    return bign_dup(src, OSSL_KEYMGMT_SELECT_KEYPAIR);
}

static void *
bign_gen_init_common(void *provctx,
                     const bee2_bign_variant_t *variant,
                     int selection,
                     const OSSL_PARAM params[]) {
    bee2_bign_gen_ctx_t *gctx;

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return NULL;
    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (!gctx)
        return NULL;
    gctx->libctx = bee2_provider_libctx(provctx);
    gctx->variant = variant;
    gctx->selection = selection;
    if (!bign_apply_encoding_params(&gctx->encode_explicit, &gctx->encode_cofactor, params)) {
        OPENSSL_free(gctx);
        return NULL;
    }
    return gctx;
}

static void *bign256_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) {
    return bign_gen_init_common(provctx, bee2_bign_variant_256(), selection, params);
}

static void *bign384_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) {
    return bign_gen_init_common(provctx, bee2_bign_variant_384(), selection, params);
}

static void *bign512_gen_init(void *provctx, int selection, const OSSL_PARAM params[]) {
    return bign_gen_init_common(provctx, bee2_bign_variant_512(), selection, params);
}

static int bign_gen_set_template(void *vgenctx, void *vtempl) {
    bee2_bign_gen_ctx_t *gctx = vgenctx;
    const bee2_bign_key_t *templ = vtempl;

    if (!gctx || !templ)
        return 0;
    if (!templ->variant || (gctx->variant && templ->variant != gctx->variant))
        return 0;
    gctx->variant = templ->variant;
    return 1;
}

static int bign_gen_set_params(void *vgenctx, const OSSL_PARAM params[]) {
    bee2_bign_gen_ctx_t *gctx = vgenctx;

    return bign_apply_encoding_params(&gctx->encode_explicit, &gctx->encode_cofactor, params);
}

static const OSSL_PARAM *bign_gen_settable_params(void *genctx, void *provctx) {
    (void)genctx;
    (void)provctx;
    return bee2_bign_gen_settable_params;
}

static void *bign_gen(void *vgenctx, OSSL_CALLBACK *cb, void *cbarg) {
    bee2_bign_gen_ctx_t *gctx = vgenctx;
    bee2_bign_key_t *key = NULL;
    size_t priv_len;
    size_t pub_len;
    bee2_bign_rng_t rng = {0};
    int ok = 0;

    (void)cb;
    (void)cbarg;
    if (!gctx->variant)
        return NULL;
    rng.libctx = gctx->libctx;

    key = bign_new_common(gctx->variant);
    if (!key)
        goto cleanup;
    key->encode_explicit = gctx->encode_explicit;
    key->encode_cofactor = gctx->encode_cofactor;

    priv_len = bee2_bign_priv_len(gctx->variant);
    pub_len = bee2_bign_pub_len(gctx->variant);
    if (!bee2_bign_keypair_generate(gctx->variant, key->priv, key->pub, &rng) ||
        rng.failed)
        goto cleanup;

    key->has_priv = 1;
    key->has_pub = 1;

    if (!(gctx->selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        bee2_bign_cleanse(key->priv, priv_len);
        key->has_priv = 0;
    }
    if (!(gctx->selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        bee2_bign_cleanse(key->pub, pub_len);
        key->has_pub = 0;
    }
    ok = 1;

cleanup:
    if (!ok) {
        bign_key_free(key);
        key = NULL;
    }
    return key;
}

static void bign_gen_cleanup(void *vgenctx) {
    bee2_bign_gen_ctx_t *gctx = vgenctx;

    bee2_bign_cleanse(gctx, sizeof(*gctx));
    OPENSSL_clear_free(gctx, sizeof(*gctx));
}

static const char *bign256_query_operation_name(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE)
        return "bign-256";
    if (operation_id == OSSL_OP_ASYM_CIPHER)
        return "bign-keytransport";
    if (operation_id == OSSL_OP_KEYEXCH)
        return "bign-256";
    return NULL;
}

static const char *bign384_query_operation_name(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE)
        return "bign-384";
    if (operation_id == OSSL_OP_ASYM_CIPHER)
        return "bign-keytransport";
    if (operation_id == OSSL_OP_KEYEXCH)
        return "bign-384";
    return NULL;
}

static const char *bign512_query_operation_name(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE)
        return "bign-512";
    if (operation_id == OSSL_OP_ASYM_CIPHER)
        return "bign-keytransport";
    if (operation_id == OSSL_OP_KEYEXCH)
        return "bign-512";
    return NULL;
}

static const char *bign_query_operation_name(int operation_id) {
    if (operation_id == OSSL_OP_SIGNATURE || operation_id == OSSL_OP_KEYEXCH)
        return "bign";
    if (operation_id == OSSL_OP_ASYM_CIPHER)
        return "bign-keytransport";
    return NULL;
}

#ifdef OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX
#define BEE2_BIGN_KEYMGMT_IMPORT_TYPES_EX_DISPATCH \
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX, (void (*)(void))bign_import_types_ex},
#else
#define BEE2_BIGN_KEYMGMT_IMPORT_TYPES_EX_DISPATCH
#endif

#ifdef OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX
#define BEE2_BIGN_KEYMGMT_EXPORT_TYPES_EX_DISPATCH \
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX, (void (*)(void))bign_export_types_ex},
#else
#define BEE2_BIGN_KEYMGMT_EXPORT_TYPES_EX_DISPATCH
#endif

#define BEE2_BIGN_KEYMGMT_DISPATCH(SFX, NEW_FN, GEN_INIT_FN, QUERY_FN) \
    const OSSL_DISPATCH bee2_bign_##SFX##_keymgmt_functions[] = { \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))NEW_FN}, \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))bign_key_free}, \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))bign_get_params}, \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))bign_gettable_params}, \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))bign_set_params}, \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))bign_settable_params}, \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))bign_has}, \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))bign_match}, \
        {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))bign_validate}, \
        {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))bign_load}, \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))bee2_bign_import_params}, \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))bign_import_types}, \
        BEE2_BIGN_KEYMGMT_IMPORT_TYPES_EX_DISPATCH{OSSL_FUNC_KEYMGMT_EXPORT, \
                                                   (void (*)(void))bee2_bign_export_params}, \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))bign_export_types}, \
        BEE2_BIGN_KEYMGMT_EXPORT_TYPES_EX_DISPATCH{OSSL_FUNC_KEYMGMT_DUP, \
                                                   (void (*)(void))bign_dup}, \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))GEN_INIT_FN}, \
        {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (void (*)(void))bign_gen_set_template}, \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))bign_gen_set_params}, \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))bign_gen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))bign_gen}, \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))bign_gen_cleanup}, \
        {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))QUERY_FN}, \
        {0, NULL}}

BEE2_BIGN_KEYMGMT_DISPATCH(256, bign256_new, bign256_gen_init, bign256_query_operation_name);
BEE2_BIGN_KEYMGMT_DISPATCH(384, bign384_new, bign384_gen_init, bign384_query_operation_name);
BEE2_BIGN_KEYMGMT_DISPATCH(512, bign512_new, bign512_gen_init, bign512_query_operation_name);

const OSSL_DISPATCH bee2_bign_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))bign_new},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))bign_key_free},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))bign_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))bign_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))bign_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))bign_settable_params},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))bign_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))bign_match},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))bign_validate},
    {OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))bign_load},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))bee2_bign_import_params},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))bign_import_types},
    BEE2_BIGN_KEYMGMT_IMPORT_TYPES_EX_DISPATCH{OSSL_FUNC_KEYMGMT_EXPORT,
                                               (void (*)(void))bee2_bign_export_params},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))bign_export_types},
    BEE2_BIGN_KEYMGMT_EXPORT_TYPES_EX_DISPATCH{OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))bign_dup},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))bign_query_operation_name},
    {0, NULL}};
