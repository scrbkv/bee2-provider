#include "bee2_backend.h"
#include "bee2_oids.h"
#include "bign_common.h"
#include "bign_asn1.h"

#include <openssl/core_names.h>
#include <bee2/crypto/bign128.h>
#include <bee2/crypto/bign192.h>
#include <bee2/crypto/bign256.h>

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string.h>

#define BEE2_SIGNATURE_PARAM_SIG "sig"

typedef enum {
    BEE2_BIGN_SIG_IDLE = 0,
    BEE2_BIGN_SIG_SIGN = 1,
    BEE2_BIGN_SIG_VERIFY = 2
} bee2_bign_sig_mode_t;

typedef struct {
    OSSL_LIB_CTX *libctx;
    const bee2_bign_variant_t *variant;
    const char *fixed_digest;
    bee2_bign_key_t *key;
    bee2_bign_sig_mode_t mode;
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    char mdname[64];
    char mdprops[128];
    char propq[128];
    unsigned char aid_buf[256];
    size_t aid_len;
    unsigned int deterministic;
    int hspec;
    char hash_oid[96];
    int md_started;
} bee2_bign_sig_ctx_t;

static const OSSL_PARAM bee2_bign_sig_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM bee2_bign_sig_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_utf8_string(BEE2_SIGNATURE_PARAM_SIG, NULL, 0),
    OSSL_PARAM_END};

static int bign_str_copy(char *dst, size_t dst_size, const char *src) {
    size_t n;
    if (!src) {
        dst[0] = '\0';
        return 1;
    }
    n = strlen(src);
    if (n >= dst_size)
        return 0;
    memcpy(dst, src, n + 1u);
    return 1;
}

typedef struct {
    const char *name;
    const char *signature_oid;
    const char *hash_oid;
} bign_sig_md_oid_t;

static const bign_sig_md_oid_t bign_sig_md_oids[] = {
    {"belt-hash", BEE2_OID_BIGN_WITH_HBELT, BEE2_OID_BELT_HASH},
    {"bash256", BEE2_OID_BIGN_WITH_BASH256, BEE2_OID_BASH256},
    {"bash384", BEE2_OID_BIGN_WITH_BASH384, BEE2_OID_BASH384},
    {"bash512", BEE2_OID_BIGN_WITH_BASH512, BEE2_OID_BASH512}
};

static const bign_sig_md_oid_t *bign_sig_find_md(const char *name)
{
    size_t i;

    if (name == NULL)
        return NULL;
    for (i = 0; i < sizeof(bign_sig_md_oids) / sizeof(bign_sig_md_oids[0]); ++i)
        if (OPENSSL_strcasecmp(name, bign_sig_md_oids[i].name) == 0)
            return &bign_sig_md_oids[i];
    return NULL;
}

static const char *bign_sig_mdname_to_oid(const char *name)
{
    const bign_sig_md_oid_t *info = bign_sig_find_md(name);
    return info ? info->signature_oid : NULL;
}

static const char *bign_sig_mdname_to_hash_oid(const char *name)
{
    const bign_sig_md_oid_t *info = bign_sig_find_md(name);
    return info ? info->hash_oid : NULL;
}

/* Bee2 signs the DER OID of the hash function, not of the signature scheme. */
static const char *bign_sig_hash_oid(const bee2_bign_sig_ctx_t *ctx) {
    const char *name;

    /* bign_sig_set_md() resolves the hash OID together with the digest. */
    if (ctx->md)
        return ctx->hash_oid[0] != '\0' ? ctx->hash_oid : NULL;
    if (ctx->hspec)
        return NULL;
    name = ctx->fixed_digest ? ctx->fixed_digest :
           (ctx->variant ? ctx->variant->default_digest : NULL);
    return bign_sig_mdname_to_hash_oid(name);
}

/* The public fixed-curve APIs cache their curve and precomputation.
 * Their signature functions hardcode the hash OID; use the generic API
 * whenever that OID does not match the selected digest. */
static int bign_sig_fixed_curve(const bee2_bign_sig_ctx_t *ctx,
                                const char *hash_oid) {
    if (ctx->variant == bee2_bign_variant_256() &&
        strcmp(hash_oid, BEE2_OID_BELT_HASH) == 0)
        return 1;
    if (ctx->variant == bee2_bign_variant_384() &&
        strcmp(hash_oid, BEE2_OID_BASH384) == 0)
        return 2;
    if (ctx->variant == bee2_bign_variant_512() &&
        strcmp(hash_oid, BEE2_OID_BASH512) == 0)
        return 3;
    return 0;
}

static const char *bign_sig_md_to_oid(const bee2_bign_sig_ctx_t *ctx) {
    if (ctx->hspec)
        return BEE2_OID_BIGN_WITH_HSPEC;
    if (ctx->md) {
        size_t i;

        for (i = 0; i < sizeof(bign_sig_md_oids) / sizeof(bign_sig_md_oids[0]); ++i)
            if (EVP_MD_is_a(ctx->md, bign_sig_md_oids[i].name))
                return bign_sig_md_oids[i].signature_oid;
        /* An identified, externally selected digest is bign-with-hspec. */
        return ctx->hash_oid[0] != '\0' ? BEE2_OID_BIGN_WITH_HSPEC : NULL;
    }
    return bign_sig_mdname_to_oid(ctx->fixed_digest ? ctx->fixed_digest :
           (ctx->variant ? ctx->variant->default_digest : NULL));
}

static int bign_sig_update_algid(bee2_bign_sig_ctx_t *ctx) {
    const char *oid, *hash_oid;

    ctx->aid_len = 0;
    oid = bign_sig_md_to_oid(ctx);
    if (!oid)
        return 0;
    hash_oid = strcmp(oid, BEE2_OID_BIGN_WITH_HSPEC) == 0
                   ? bign_sig_hash_oid(ctx) : NULL;
    if (ctx->hspec && hash_oid == NULL)
        return 0;
    return bee2_bign_asn1_build_algid(oid, hash_oid,
                                      ctx->aid_buf, sizeof(ctx->aid_buf), &ctx->aid_len);
}

static void bign_sig_reset_md(bee2_bign_sig_ctx_t *ctx, int keep_algorithm) {
    EVP_MD_CTX_free(ctx->mdctx);
    ctx->mdctx = NULL;
    if (!keep_algorithm) {
        EVP_MD_free(ctx->md);
        ctx->md = NULL;
        ctx->mdname[0] = '\0';
        ctx->mdprops[0] = '\0';
        ctx->hash_oid[0] = '\0';
        ctx->aid_len = 0;
    }
}

static int bign_sig_set_md(bee2_bign_sig_ctx_t *ctx, const char *mdname, const char *mdprops) {
    EVP_MD *md;
    bee2_bign_sig_ctx_t candidate;
    const char *properties;

    if (mdname == NULL || mdname[0] == '\0') {
        if (ctx->fixed_digest)
            return 0;
        bign_sig_reset_md(ctx, 0);
        return 1;
    }
    properties = mdprops && mdprops[0] != '\0' ? mdprops : NULL;
    if (properties == NULL && !ctx->hspec &&
        bign_sig_mdname_to_oid(mdname) != NULL && ctx->propq[0] != '\0')
        properties = ctx->propq;
    md = EVP_MD_fetch(ctx->libctx, mdname, properties);
    if (md == NULL)
        return 0;
    if (ctx->fixed_digest && !EVP_MD_is_a(md, ctx->fixed_digest)) {
        EVP_MD_free(md);
        return 0;
    }
    if (ctx->variant && EVP_MD_get_size(md) != (int)bee2_bign_priv_len(ctx->variant)) {
        EVP_MD_free(md);
        return 0;
    }

    candidate = *ctx;
    candidate.md = md;
    if (!bee2_bign_asn1_resolve_hash_oid(md, mdname,
                                        bign_sig_mdname_to_hash_oid(EVP_MD_get0_name(md)),
                                        candidate.hash_oid, sizeof(candidate.hash_oid))) {
        EVP_MD_free(md);
        return 0;
    }
    if (!bign_str_copy(candidate.mdname, sizeof(candidate.mdname), mdname) ||
        !bign_str_copy(candidate.mdprops, sizeof(candidate.mdprops),
                       mdprops != NULL ? mdprops : "") ||
        !bign_sig_update_algid(&candidate)) {
        EVP_MD_free(md);
        return 0;
    }

    EVP_MD_free(ctx->md);
    ctx->md = md;
    memcpy(ctx->mdname, candidate.mdname, sizeof(ctx->mdname));
    memcpy(ctx->mdprops, candidate.mdprops, sizeof(ctx->mdprops));
    memcpy(ctx->hash_oid, candidate.hash_oid, sizeof(ctx->hash_oid));
    ctx->aid_len = candidate.aid_len;
    memcpy(ctx->aid_buf, candidate.aid_buf, candidate.aid_len);
    return 1;
}

static int bign_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int bign_sig_assign_key(bee2_bign_sig_ctx_t *ctx, void *vkey, int for_sign) {
    bee2_bign_key_t *key = vkey;
    const bee2_bign_variant_t *variant;

    if (!key)
        return 0;
    variant = ctx->variant ? ctx->variant : key->variant;
    if (!variant || key->variant != variant)
        return 0;
    if (ctx->md && EVP_MD_get_size(ctx->md) != (int)bee2_bign_priv_len(variant))
        return 0;
    if (for_sign && !key->has_priv)
        return 0;
    if (!for_sign && !bee2_bign_key_validate_public(key))
        return 0;
    ctx->variant = variant;
    ctx->key = key;
    ctx->mode = for_sign ? BEE2_BIGN_SIG_SIGN : BEE2_BIGN_SIG_VERIFY;
    bign_sig_reset_md(ctx, 1);
    ctx->md_started = 0;
    return 1;
}

static int bign_sig_hash_oneshot(const EVP_MD *md,
                                 const unsigned char *in,
                                 size_t inlen,
                                 unsigned char out[EVP_MAX_MD_SIZE],
                                 size_t *outlen) {
    unsigned int mdlen = 0;

    if ((inlen != 0 && in == NULL) ||
        !EVP_Digest(in, inlen, out, &mdlen, md, NULL))
        return 0;
    *outlen = (size_t)mdlen;
    return 1;
}

static int bign_sig_sign_hash(const bee2_bign_sig_ctx_t *ctx,
                              unsigned char *sig, size_t *siglen, size_t sigsize,
                              const unsigned char *hash, size_t hashlen) {
    bign_params curve;
    bee2_bign_rng_t rng = {0};
    size_t need_sig_len;
    const char *hash_oid;
    unsigned char oid_der[32];
    size_t oid_der_len = sizeof(oid_der);
    err_t code = ERR_BAD_PARAMS;
    int ok = 0;

    if (!ctx->key || !ctx->key->has_priv || !siglen || !hash)
        return 0;
    need_sig_len = bee2_bign_sig_len(ctx->variant);
    if (!sig) {
        *siglen = need_sig_len;
        return 1;
    }
    if (sigsize < need_sig_len || hashlen != bee2_bign_priv_len(ctx->variant))
        return 0;

    hash_oid = bign_sig_hash_oid(ctx);
    if (!hash_oid)
        return 0;
    rng.libctx = ctx->libctx;
    OPENSSL_cleanse(&curve, sizeof(curve));
    switch (bign_sig_fixed_curve(ctx, hash_oid)) {
    case 1:
        code = ctx->deterministic ?
            bign128Sign2(sig, hash, ctx->key->priv, NULL, 0) :
            bign128Sign(sig, hash, ctx->key->priv, bee2_bign_openssl_rng, &rng);
        break;
    case 2:
        code = ctx->deterministic ?
            bign192Sign2(sig, hash, ctx->key->priv, NULL, 0) :
            bign192Sign(sig, hash, ctx->key->priv, bee2_bign_openssl_rng, &rng);
        break;
    case 3:
        code = ctx->deterministic ?
            bign256Sign2(sig, hash, ctx->key->priv, NULL, 0) :
            bign256Sign(sig, hash, ctx->key->priv, bee2_bign_openssl_rng, &rng);
        break;
    default:
        if (bignOidToDER(oid_der, &oid_der_len, hash_oid) != ERR_OK ||
            !bee2_bign_curve_init_std(ctx->variant, &curve))
            goto cleanup;
        code = ctx->deterministic ?
            bignSign2(sig, &curve, oid_der, oid_der_len, hash,
                      ctx->key->priv, NULL, 0) :
            bignSign(sig, &curve, oid_der, oid_der_len, hash,
                     ctx->key->priv, bee2_bign_openssl_rng, &rng);
        break;
    }
    if (code != ERR_OK || rng.failed)
        goto cleanup;
    *siglen = need_sig_len;
    ok = 1;

cleanup:
    bee2_bign_cleanse(&curve, sizeof(curve));
    return ok;
}

static int bign_sig_verify_hash(const bee2_bign_sig_ctx_t *ctx,
                                const unsigned char *sig, size_t siglen,
                                const unsigned char *hash, size_t hashlen) {
    bign_params curve;
    const char *hash_oid;
    unsigned char oid_der[32];
    size_t oid_der_len = sizeof(oid_der);
    err_t code = ERR_BAD_PARAMS;

    if (!ctx->key || !ctx->key->has_pub || !sig || !hash)
        return 0;
    if (siglen != bee2_bign_sig_len(ctx->variant) ||
        hashlen != bee2_bign_priv_len(ctx->variant))
        return 0;
    hash_oid = bign_sig_hash_oid(ctx);
    if (!hash_oid)
        return 0;

    OPENSSL_cleanse(&curve, sizeof(curve));
    switch (bign_sig_fixed_curve(ctx, hash_oid)) {
    case 1:
        code = bign128Verify(hash, sig, ctx->key->pub);
        break;
    case 2:
        code = bign192Verify(hash, sig, ctx->key->pub);
        break;
    case 3:
        code = bign256Verify(hash, sig, ctx->key->pub);
        break;
    default:
        if (bignOidToDER(oid_der, &oid_der_len, hash_oid) != ERR_OK ||
            !bee2_bign_curve_init_std(ctx->variant, &curve))
            break;
        code = bignVerify(&curve, oid_der, oid_der_len, hash,
                          sig, ctx->key->pub);
        break;
    }
    bee2_bign_cleanse(&curve, sizeof(curve));
    return code == ERR_OK;
}

static int bign_sig_reset_mdctx(bee2_bign_sig_ctx_t *ctx) {
    if (!ctx->md)
        return 0;
    if (!ctx->mdctx) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (!ctx->mdctx)
            return 0;
    }
    return EVP_DigestInit_ex2(ctx->mdctx, ctx->md, NULL);
}

static int bign_sig_begin(bee2_bign_sig_ctx_t *ctx, const char *mdname,
                          void *vkey, const OSSL_PARAM params[],
                          int for_sign, int digest_operation);

static int bign_sig_digest_init_common(bee2_bign_sig_ctx_t *ctx,
                                       const char *mdname,
                                       void *vkey,
                                       const OSSL_PARAM params[],
                                       int for_sign) {
    return bign_sig_begin(ctx, mdname, vkey, params, for_sign, 1);
}

static void *bign_sig_newctx_common(void *provctx,
                                    const bee2_bign_variant_t *variant,
                                     const char *fixed_digest,
                                     const char *propq) {
    bee2_bign_sig_ctx_t *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->libctx = bee2_provider_libctx(provctx);
    ctx->variant = variant;
    ctx->fixed_digest = fixed_digest;
    if (!bign_str_copy(ctx->propq, sizeof(ctx->propq), propq)) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

#define BIGN_SIG_NEWCTX(NAME, VARIANT, DIGEST) \
    static void *NAME(void *provctx, const char *propq) { \
        return bign_sig_newctx_common(provctx, VARIANT, DIGEST, propq); \
    }

BIGN_SIG_NEWCTX(bign256_sig_newctx, bee2_bign_variant_256(), NULL)
BIGN_SIG_NEWCTX(bign384_sig_newctx, bee2_bign_variant_384(), NULL)
BIGN_SIG_NEWCTX(bign512_sig_newctx, bee2_bign_variant_512(), NULL)
BIGN_SIG_NEWCTX(bign256_hbelt_sig_newctx, bee2_bign_variant_256(), "belt-hash")
BIGN_SIG_NEWCTX(bign256_bash256_sig_newctx, bee2_bign_variant_256(), "bash256")
BIGN_SIG_NEWCTX(bign384_bash384_sig_newctx, bee2_bign_variant_384(), "bash384")
BIGN_SIG_NEWCTX(bign512_bash512_sig_newctx, bee2_bign_variant_512(), "bash512")
BIGN_SIG_NEWCTX(bign_sig_newctx, NULL, NULL)

static void *bign_hspec_sig_newctx(void *provctx, const char *propq) {
    bee2_bign_sig_ctx_t *ctx = bign_sig_newctx_common(provctx, NULL, NULL, propq);
    if (ctx)
        ctx->hspec = 1;
    return ctx;
}

static void bign_sig_freectx(void *vctx) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    if (!ctx)
        return;
    bign_sig_reset_md(ctx, 0);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* Duplication is needed only when OpenSSL explicitly copies an EVP context.
 * The hash state belongs to EVP, while a BIGN sign itself is a single Bee2 call. */
static void *bign_sig_dupctx(void *vctx) {
    const bee2_bign_sig_ctx_t *src = vctx;
    bee2_bign_sig_ctx_t *dst = OPENSSL_memdup(src, sizeof(*src));

    if (!dst)
        return NULL;
    dst->md = NULL;
    dst->mdctx = NULL;
    if (src->md) {
        if (!EVP_MD_up_ref(src->md))
            goto err;
        dst->md = src->md;
    }
    if (src->mdctx) {
        dst->mdctx = EVP_MD_CTX_new();
        if (!dst->mdctx || !EVP_MD_CTX_copy_ex(dst->mdctx, src->mdctx))
            goto err;
    }
    return dst;

err:
    bign_sig_freectx(dst);
    return NULL;
}

/* Init is transactional, but does not allocate an extra signature context.
 * Stream hashing is initialized lazily at its first nonempty Update. */
static int bign_sig_begin(bee2_bign_sig_ctx_t *ctx, const char *mdname,
                          void *vkey, const OSSL_PARAM params[],
                          int for_sign, int digest_operation) {
    bee2_bign_sig_ctx_t next = *ctx;

    next.md = NULL;
    next.mdctx = NULL;
    if (ctx->md) {
        if (!EVP_MD_up_ref(ctx->md))
            goto err;
        next.md = ctx->md;
    }
    if (!bign_sig_assign_key(&next, vkey, for_sign) ||
        (params != NULL && !bign_sig_set_ctx_params(&next, params)))
        goto err;
    if (digest_operation) {
        if (mdname && mdname[0] != '\0') {
            if (!bign_sig_set_md(&next, mdname, next.mdprops))
                goto err;
        } else if (!next.md) {
            const char *digest;

            if (next.hspec)
                goto err;
            digest = next.fixed_digest ? next.fixed_digest : next.variant->default_digest;
            if (!bign_sig_set_md(&next, digest, NULL))
                goto err;
        }
    }
    bign_sig_reset_md(ctx, 0);
    *ctx = next;
    return 1;

err:
    bign_sig_reset_md(&next, 0);
    ctx->mode = BEE2_BIGN_SIG_IDLE;
    return 0;
}

static int bign_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    return bign_sig_begin(vctx, NULL, vkey, params, 1, 0);
}

static int bign_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    return bign_sig_begin(vctx, NULL, vkey, params, 0, 0);
}

static int bign_sig_sign(void *vctx,
                         unsigned char *sig,
                         size_t *siglen,
                         size_t sigsize,
                         const unsigned char *tbs,
                         size_t tbslen) {
    bee2_bign_sig_ctx_t *ctx = vctx;

    if (ctx->mode != BEE2_BIGN_SIG_SIGN)
        return 0;
    return bign_sig_sign_hash(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int bign_sig_verify(
    void *vctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    bee2_bign_sig_ctx_t *ctx = vctx;

    if (ctx->mode != BEE2_BIGN_SIG_VERIFY)
        return 0;
    return bign_sig_verify_hash(ctx, sig, siglen, tbs, tbslen);
}

static int
bign_sig_digest_sign_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[]) {
    return bign_sig_digest_init_common(vctx, mdname, vkey, params, 1);
}

static int
bign_sig_digest_verify_init(void *vctx, const char *mdname, void *vkey, const OSSL_PARAM params[]) {
    return bign_sig_digest_init_common(vctx, mdname, vkey, params, 0);
}

static int bign_sig_digest_update(void *vctx, const unsigned char *data,
                                  size_t datalen, bee2_bign_sig_mode_t mode) {
    bee2_bign_sig_ctx_t *ctx = vctx;

    if (ctx->mode != mode)
        return 0;
    if (datalen == 0)
        return 1;
    if (!ctx->mdctx && !bign_sig_reset_mdctx(ctx))
        return 0;
    if (!EVP_DigestUpdate(ctx->mdctx, data, datalen))
        return 0;
    ctx->md_started = 1;
    return 1;
}

static int bign_sig_digest_sign_update(void *vctx, const unsigned char *data, size_t datalen) {
    return bign_sig_digest_update(vctx, data, datalen, BEE2_BIGN_SIG_SIGN);
}

static int bign_sig_digest_verify_update(void *vctx, const unsigned char *data, size_t datalen) {
    return bign_sig_digest_update(vctx, data, datalen, BEE2_BIGN_SIG_VERIFY);
}

/* DigestFinal must not modify the saved state: callers can repeat Final. */
static int bign_sig_digest_final_hash(const EVP_MD_CTX *ctx,
                                      unsigned char out[EVP_MAX_MD_SIZE],
                                      unsigned int *out_len) {
    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    int ok = tmp != NULL;

    if (ok)
        ok = EVP_MD_CTX_copy_ex(tmp, ctx) && EVP_DigestFinal_ex(tmp, out, out_len);
    EVP_MD_CTX_free(tmp);
    return ok;
}

static int
bign_sig_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    int ok;

    if (ctx->mode != BEE2_BIGN_SIG_SIGN || !siglen)
        return 0;
    if (!sig) {
        *siglen = bee2_bign_sig_len(ctx->variant);
        return 1;
    }
    ok = ctx->mdctx ? bign_sig_digest_final_hash(ctx->mdctx, md_buf, &md_len) :
                      EVP_Digest("", 0, md_buf, &md_len, ctx->md, NULL);
    if (ok)
        ok = bign_sig_sign_hash(ctx, sig, siglen, sigsize, md_buf, (size_t)md_len);
    bee2_bign_cleanse(md_buf, sizeof(md_buf));
    return ok;
}

static int bign_sig_digest_verify_final(void *vctx, const unsigned char *sig, size_t siglen) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    int ok;

    if (ctx->mode != BEE2_BIGN_SIG_VERIFY)
        return 0;
    ok = ctx->mdctx ? bign_sig_digest_final_hash(ctx->mdctx, md_buf, &md_len) :
                      EVP_Digest("", 0, md_buf, &md_len, ctx->md, NULL);
    if (ok)
        ok = bign_sig_verify_hash(ctx, sig, siglen, md_buf, (size_t)md_len);
    bee2_bign_cleanse(md_buf, sizeof(md_buf));
    return ok;
}

static int bign_sig_digest_oneshot_hash(bee2_bign_sig_ctx_t *ctx,
                                         const unsigned char *data, size_t len,
                                         unsigned char out[EVP_MAX_MD_SIZE], size_t *out_len)
{
    if (!ctx->md &&
        (ctx->hspec ||
         !bign_sig_set_md(ctx, ctx->fixed_digest ? ctx->fixed_digest :
                          ctx->variant->default_digest, NULL)))
        return 0;
    return bign_sig_hash_oneshot(ctx->md, data, len, out, out_len);
}

static int bign_sig_digest_sign(void *vctx,
                                unsigned char *sigret,
                                size_t *siglen,
                                size_t sigsize,
                                const unsigned char *tbs,
                                size_t tbslen) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    size_t md_len = 0;
    int ok;

    if (ctx->mode != BEE2_BIGN_SIG_SIGN)
        return 0;
    if (!bign_sig_digest_oneshot_hash(ctx, tbs, tbslen, md_buf, &md_len))
        return 0;
    ok = bign_sig_sign_hash(ctx, sigret, siglen, sigsize, md_buf, md_len);
    bee2_bign_cleanse(md_buf, sizeof(md_buf));
    return ok;
}

static int bign_sig_digest_verify(
    void *vctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    size_t md_len = 0;
    int ok;

    if (ctx->mode != BEE2_BIGN_SIG_VERIFY)
        return 0;
    if (!bign_sig_digest_oneshot_hash(ctx, tbs, tbslen, md_buf, &md_len))
        return 0;
    ok = bign_sig_verify_hash(ctx, sig, siglen, md_buf, md_len);
    bee2_bign_cleanse(md_buf, sizeof(md_buf));
    return ok;
}

static int bign_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    const OSSL_PARAM *p;
    char *mdname = NULL;
    char *mdprops = NULL;
    char *sig_mode = NULL;
    unsigned int deterministic;
    unsigned int new_deterministic;
    int ok = 1;

    if (!params)
        return 1;
    new_deterministic = ctx->deterministic;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p) {
        if (!OSSL_PARAM_get_uint(p, &deterministic)) {
            ok = 0;
            goto cleanup;
        }
        new_deterministic = deterministic != 0;
    }

    p = OSSL_PARAM_locate_const(params, BEE2_SIGNATURE_PARAM_SIG);
    if (p) {
        if (!OSSL_PARAM_get_utf8_string(p, &sig_mode, 0) ||
            OPENSSL_strcasecmp(sig_mode, "deterministic") != 0) {
            ok = 0;
            goto cleanup;
        }
        new_deterministic = 1;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
    if (p && !OSSL_PARAM_get_utf8_string(p, &mdprops, 0)) {
        ok = 0;
        goto cleanup;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && !OSSL_PARAM_get_utf8_string(p, &mdname, 0)) {
        ok = 0;
        goto cleanup;
    }

    /* Changing the digest cannot discard data already fed to DigestUpdate. */
    if (ctx->md_started && (mdname || mdprops)) {
        ok = 0;
        goto cleanup;
    }

    if (mdname) {
        const char *props = mdprops ? mdprops : ctx->mdprops;
        ok = bign_sig_set_md(ctx, mdname, props);
    } else if (mdprops && ctx->mdname[0] != '\0') {
        ok = bign_sig_set_md(ctx, ctx->mdname, mdprops);
    }
    if (!ok)
        goto cleanup;

    /* Only a digest/property change requires restarting an empty digest. */
    if ((mdname || mdprops) && ctx->mdctx && ctx->md &&
        !bign_sig_reset_mdctx(ctx)) {
        ok = 0;
        goto cleanup;
    }
    ctx->deterministic = new_deterministic;

cleanup:
    OPENSSL_free(mdname);
    OPENSSL_free(mdprops);
    OPENSSL_free(sig_mode);
    return ok;
}

static const OSSL_PARAM *bign_sig_settable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_bign_sig_settable_ctx_params;
}

static int bign_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    bee2_bign_sig_ctx_t *ctx = vctx;
    OSSL_PARAM *p;



    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        if (ctx->aid_len == 0 && !bign_sig_update_algid(ctx))
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, ctx->aid_len == 0 ? NULL : ctx->aid_buf, ctx->aid_len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p && (ctx->md || ctx->fixed_digest)) {
        const char *name = ctx->md ? EVP_MD_get0_name(ctx->md) : ctx->fixed_digest;
        if (!OSSL_PARAM_set_utf8_string(p, name))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p && (ctx->md || ctx->fixed_digest)) {
        size_t md_size = ctx->md ? (size_t)EVP_MD_get_size(ctx->md) :
                                       bee2_bign_priv_len(ctx->variant);

        if (!OSSL_PARAM_set_size_t(p, md_size))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p && !OSSL_PARAM_set_uint(p, ctx->deterministic))
        return 0;

    return 1;
}

static const OSSL_PARAM *bign_sig_gettable_ctx_params(void *vctx, void *provctx) {
    (void)vctx;
    (void)provctx;
    return bee2_bign_sig_gettable_ctx_params;
}

#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
static const char *const bee2_bign256_key_types[] = {"bign-256", NULL};
static const char *const bee2_bign384_key_types[] = {"bign-384", NULL};
static const char *const bee2_bign512_key_types[] = {"bign-512", NULL};
static const char *const bee2_bign_key_types[] = {"bign", NULL};

static const char **bign_sig_query_key_types_256(void) {
    return (const char **)bee2_bign256_key_types;
}

static const char **bign_sig_query_key_types_384(void) {
    return (const char **)bee2_bign384_key_types;
}

static const char **bign_sig_query_key_types_512(void) {
    return (const char **)bee2_bign512_key_types;
}

static const char **bign_sig_query_key_types(void) {
    return (const char **)bee2_bign_key_types;
}

#endif

#ifdef OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES
#define BEE2_BIGN_SIG_QUERY_KEY_TYPES_DISPATCH(QUERY_KEY_TYPES_FN) \
    {OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES, (void (*)(void))QUERY_KEY_TYPES_FN},
#else
#define BEE2_BIGN_SIG_QUERY_KEY_TYPES_DISPATCH(QUERY_KEY_TYPES_FN)
#endif

#define BEE2_BIGN_SIG_DISPATCH(SFX, NEWCTX_FN, QUERY_KEY_TYPES_FN) \
    const OSSL_DISPATCH bee2_bign_##SFX##_signature_functions[] = { \
        {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))NEWCTX_FN}, \
        {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))bign_sig_freectx}, \
        {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))bign_sig_dupctx}, \
        {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))bign_sig_sign_init}, \
        {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))bign_sig_sign}, \
        {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))bign_sig_verify_init}, \
        {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))bign_sig_verify}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))bign_sig_digest_sign_init}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))bign_sig_digest_sign_update}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))bign_sig_digest_sign_final}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))bign_sig_digest_sign}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))bign_sig_digest_verify_init}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))bign_sig_digest_verify_update}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))bign_sig_digest_verify_final}, \
        {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))bign_sig_digest_verify}, \
        {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))bign_sig_get_ctx_params}, \
        {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))bign_sig_gettable_ctx_params}, \
        {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))bign_sig_set_ctx_params}, \
        {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))bign_sig_settable_ctx_params}, \
        BEE2_BIGN_SIG_QUERY_KEY_TYPES_DISPATCH(QUERY_KEY_TYPES_FN){0, NULL}}

BEE2_BIGN_SIG_DISPATCH(256, bign256_sig_newctx, bign_sig_query_key_types_256);
BEE2_BIGN_SIG_DISPATCH(384, bign384_sig_newctx, bign_sig_query_key_types_384);
BEE2_BIGN_SIG_DISPATCH(512, bign512_sig_newctx, bign_sig_query_key_types_512);
BEE2_BIGN_SIG_DISPATCH(256_hbelt, bign256_hbelt_sig_newctx, bign_sig_query_key_types_256);
BEE2_BIGN_SIG_DISPATCH(256_bash256, bign256_bash256_sig_newctx, bign_sig_query_key_types_256);
BEE2_BIGN_SIG_DISPATCH(384_bash384, bign384_bash384_sig_newctx, bign_sig_query_key_types_384);
BEE2_BIGN_SIG_DISPATCH(512_bash512, bign512_bash512_sig_newctx, bign_sig_query_key_types_512);
BEE2_BIGN_SIG_DISPATCH(hspec, bign_hspec_sig_newctx, bign_sig_query_key_types);
BEE2_BIGN_SIG_DISPATCH(generic, bign_sig_newctx, bign_sig_query_key_types);
