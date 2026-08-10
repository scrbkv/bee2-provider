/*
 * bash_digest.c — OpenSSL 3.x provider: BASH sponge hash (STB 34.101.77)
 *
 * The BASH hash function is parametrised by security level l.
 * Output size = 2*l bits. Bee2 names variants by security level:
 *
 *   bash_hash128  l=128  → 256-bit  (32-byte) output  BASH-256
 *   bash_hash192  l=192  → 384-bit  (48-byte) output  BASH-384
 *   bash_hash256  l=256  → 512-bit  (64-byte) output  BASH-512
 *
 * OIDs (STB 34.101.77):
 *   BASH-256  1.2.112.0.2.0.34.101.77.11
 *   BASH-384  1.2.112.0.2.0.34.101.77.12
 *   BASH-512  1.2.112.0.2.0.34.101.77.13
 *
 * Sponge state = 1536 bits.  Block (rate) sizes:
 *   l=128: capacity=256b  → rate=1280b = 160 bytes
 *   l=192: capacity=384b  → rate=1152b = 144 bytes
 *   l=256: capacity=512b  → rate=1024b = 128 bytes
 */

#include "bee2_backend.h"
#include "provider.h"

/* ------------------------------------------------------------------ */
/*  Variant descriptors                                                 */
/* ------------------------------------------------------------------ */

typedef void (*bash_init_fn)(bash_hash_ctx);
typedef void (*bash_update_fn)(bash_hash_ctx, const void *, size_t);
typedef void (*bash_get_fn)(bash_hash_ctx, void *);
typedef void (*bash_cleanup_fn)(bash_hash_ctx);

typedef struct {
    size_t output_size; /* digest length in bytes */
    size_t block_size;  /* sponge rate in bytes   */
    bash_init_fn backend_init;
    bash_update_fn backend_update;
    bash_get_fn backend_get;
    bash_cleanup_fn backend_cleanup;
} bash_variant_t;

/* Thin wrappers to convert function-pointer variables to plain functions. */
static void bash128_update_w(bash_hash_ctx c, const void *d, size_t l) {
    bash_hash128_update(c, d, l);
}
static void bash128_get_w(bash_hash_ctx c, void *h) {
    bash_hash128_get(c, h);
}
static void bash192_update_w(bash_hash_ctx c, const void *d, size_t l) {
    bash_hash192_update(c, d, l);
}
static void bash192_get_w(bash_hash_ctx c, void *h) {
    bash_hash192_get(c, h);
}
static void bash256_update_w(bash_hash_ctx c, const void *d, size_t l) {
    bash_hash256_update(c, d, l);
}
static void bash256_get_w(bash_hash_ctx c, void *h) {
    bash_hash256_get(c, h);
}

/*
 * Variants named by security level (l), exposed as output-size based names.
 * bash_sec128 → BASH-256 (32-byte output)
 * bash_sec192 → BASH-384 (48-byte output)
 * bash_sec256 → BASH-512 (64-byte output)
 */
static const bash_variant_t bash_sec128 = {
    32, 160, bash_hash128_init, bash128_update_w, bash128_get_w, bash_hash128_cleanup};
static const bash_variant_t bash_sec192 = {
    48, 144, bash_hash192_init, bash192_update_w, bash192_get_w, bash_hash192_cleanup};
static const bash_variant_t bash_sec256 = {
    64, 128, bash_hash256_init, bash256_update_w, bash256_get_w, bash_hash256_cleanup};

/* ------------------------------------------------------------------ */
/*  Context                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    bash_hash_ctx_t backend_state;
    const bash_variant_t *var;
} bee2_bash_ctx_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                           */
/* ------------------------------------------------------------------ */

static void *bash_newctx(void *provctx, const bash_variant_t *var) {
    (void)provctx;
    bee2_bash_ctx_t *c = OPENSSL_malloc(sizeof(*c));
    if (!c)
        return NULL;
    c->var = var;
    var->backend_init(&c->backend_state);
    return c;
}

static void bash_freectx(void *vctx) {
    bee2_bash_ctx_t *c = vctx;
    if (!c)
        return;
    c->var->backend_cleanup(&c->backend_state);
    OPENSSL_clear_free(c, sizeof(*c));
}

static void *bash_dupctx(void *vctx) {
    bee2_bash_ctx_t *src = vctx;
    bee2_bash_ctx_t *dst = OPENSSL_malloc(sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    return dst;
}

/* variant-specific newctx wrappers */
static void *bash256_newctx(void *p) {
    return bash_newctx(p, &bash_sec128);
}
static void *bash384_newctx(void *p) {
    return bash_newctx(p, &bash_sec192);
}
static void *bash512_newctx(void *p) {
    return bash_newctx(p, &bash_sec256);
}

/* ------------------------------------------------------------------ */
/*  Hash operations                                                     */
/* ------------------------------------------------------------------ */

static int bash_init(void *vctx, const OSSL_PARAM params[]) {
    bee2_bash_ctx_t *c = vctx;
    (void)params;
    c->var->backend_init(&c->backend_state);
    return 1;
}

static int bash_update(void *vctx, const unsigned char *in, size_t inl) {
    bee2_bash_ctx_t *c = vctx;
    if (inl == 0)
        return 1;
    c->var->backend_update(&c->backend_state, in, inl);
    return 1;
}

static int bash_final(void *vctx, unsigned char *out, size_t *outl, size_t outsz) {
    bee2_bash_ctx_t *c = vctx;
    if (outsz < c->var->output_size)
        return 0;
    c->var->backend_get(&c->backend_state, out);
    *outl = c->var->output_size;
    return 1;
}

/* variant-specific one-shot helpers */
#define BASH_DIGEST_FN(OUTBITS, NEWCTX_FN)                                                         \
    static int bash##OUTBITS##_digest(void *provctx,                                               \
                                      const unsigned char *in,                                     \
                                      size_t inl,                                                  \
                                      unsigned char *out,                                          \
                                      size_t *outl,                                                \
                                      size_t outsz) {                                              \
        bee2_bash_ctx_t *tmp = NEWCTX_FN(provctx);                                                 \
        int ok = 0;                                                                                \
        if (!tmp)                                                                                  \
            return 0;                                                                              \
        if (outsz < tmp->var->output_size)                                                         \
            goto done;                                                                             \
        bash_update(tmp, in, inl);                                                                 \
        bash_final(tmp, out, outl, outsz);                                                         \
        ok = 1;                                                                                    \
    done:                                                                                          \
        bash_freectx(tmp);                                                                         \
        return ok;                                                                                 \
    }

BASH_DIGEST_FN(256, bash256_newctx)
BASH_DIGEST_FN(384, bash384_newctx)
BASH_DIGEST_FN(512, bash512_newctx)

/* ------------------------------------------------------------------ */
/*  Algorithm parameters                                                */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM bee2_bash_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bash_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_bash_gettable_params;
}

static int bash_get_params_impl(OSSL_PARAM params[], size_t output_size, size_t block_size) {
    OSSL_PARAM *p;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, output_size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p && !OSSL_PARAM_set_size_t(p, block_size))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p && !OSSL_PARAM_set_int(p, 0))
        return 0;
    return 1;
}

static int bash256_get_params(OSSL_PARAM p[]) {
    return bash_get_params_impl(p, 32, 160);
}
static int bash384_get_params(OSSL_PARAM p[]) {
    return bash_get_params_impl(p, 48, 144);
}
static int bash512_get_params(OSSL_PARAM p[]) {
    return bash_get_params_impl(p, 64, 128);
}

static const OSSL_PARAM bee2_bash_ctx_gettable[] = {OSSL_PARAM_END};

static const OSSL_PARAM *bash_gettable_ctx_params(void *dctx, void *pctx) {
    (void)dctx;
    (void)pctx;
    return bee2_bash_ctx_gettable;
}

static int bash_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
    (void)vctx;
    (void)params;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Dispatch tables — named by OUTPUT size (not security level)         */
/* ------------------------------------------------------------------ */

#define BASH_DISPATCH(OUTBITS)                                                                     \
    const OSSL_DISPATCH bee2_bash##OUTBITS##_functions[] = {                                       \
        {OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))bash##OUTBITS##_newctx},                         \
        {OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))bash_freectx},                                  \
        {OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))bash_dupctx},                                    \
        {OSSL_FUNC_DIGEST_INIT, (void (*)(void))bash_init},                                        \
        {OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))bash_update},                                    \
        {OSSL_FUNC_DIGEST_FINAL, (void (*)(void))bash_final},                                      \
        {OSSL_FUNC_DIGEST_DIGEST, (void (*)(void))bash##OUTBITS##_digest},                         \
        {OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))bash##OUTBITS##_get_params},                 \
        {OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))bash_gettable_params},                  \
        {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void))bash_get_ctx_params},                    \
        {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void))bash_gettable_ctx_params},          \
        {0, NULL}}

BASH_DISPATCH(256);
BASH_DISPATCH(384);
BASH_DISPATCH(512);
