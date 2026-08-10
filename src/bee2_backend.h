#ifndef BEE2_PROVIDER_BACKEND_H
#define BEE2_PROVIDER_BACKEND_H

/*
 * Small, provider-local adaptation layer over the upstream Bee2 API.
 * All cryptographic operations below are implemented by Bee2's Start/Step
 * interfaces; the previous backend is not used.
 */

#include <bee2/core/err.h>
#include <bee2/core/u32.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BELT_BLOCK_SIZE 16u
#define BELT_IV_SIZE 16u
#define BELT_KEY_SIZE 32u
#define BELT_MAC_SIZE 8u
#define BELT_HASH_DIGEST_SIZE 32u
#define BASH_PRGAE_MAX_KEY_SIZE 60u
#define BASH_PRGAE_MAX_IV_SIZE 60u
#define BEE2_BIGN_MAX_WORDS 8u

/* Bee2 keep() values are intentionally hidden behind an aligned fixed-size
 * store so provider contexts remain trivially copyable for dupctx(). */
#define BEE2_BACKEND_STATE_SIZE 4096u
typedef union {
    max_align_t align;
    octet bytes[BEE2_BACKEND_STATE_SIZE];
} bee2_backend_state_t;

static inline int bee2_backend_is_compatible(void) {
    return beltHash_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltECB_keep() <= BEE2_BACKEND_STATE_SIZE && beltCBC_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltCFB_keep() <= BEE2_BACKEND_STATE_SIZE && beltCTR_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltBDE_keep() <= BEE2_BACKEND_STATE_SIZE && beltCHE_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltDWP_keep() <= BEE2_BACKEND_STATE_SIZE && beltMAC_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltHMAC_keep() <= BEE2_BACKEND_STATE_SIZE &&
           beltSDE_keep() <= BEE2_BACKEND_STATE_SIZE &&
           bashHash_keep() <= BEE2_BACKEND_STATE_SIZE && bashPrg_keep() <= BEE2_BACKEND_STATE_SIZE;
}

static inline void bee2_backend_cleanup(void *ctx, size_t size) {
    if (ctx)
        OPENSSL_cleanse(ctx, size);
}

/* Preserve bee2evp's formatted-key byte representation. */
static inline void bee2_belt_expand_key(const void *key, size_t key_len, octet expanded[32]) {
    u32 words[8];

    beltKeyExpand2(words, key, key_len);
    u32To(expanded, sizeof(words), words);
    OPENSSL_cleanse(words, sizeof(words));
}

/* Hash adapters. */
typedef bee2_backend_state_t belt_hash_ctx_t;
typedef belt_hash_ctx_t *belt_hash_ctx;
static inline void belt_hash_init(belt_hash_ctx c) {
    beltHashStart(c);
}
static inline void belt_hash_update(belt_hash_ctx c, const void *p, size_t n) {
    beltHashStepH(p, n, c);
}
static inline void belt_hash_get(belt_hash_ctx c, void *out) {
    beltHashStepG(out, c);
}
static inline void belt_hash_cleanup(belt_hash_ctx c) {
    bee2_backend_cleanup(c, sizeof(*c));
}

typedef bee2_backend_state_t bash_hash_ctx_t;
typedef bash_hash_ctx_t *bash_hash_ctx;
#define BASH_HASH_ADAPTER(BITS, LEVEL, OUTLEN) \
    static inline void bash_hash##BITS##_init(bash_hash_ctx c) { \
        bashHashStart(c, LEVEL); \
    } \
    static inline void bash_hash##BITS##_update(bash_hash_ctx c, const void *p, size_t n) { \
        bashHashStepH(p, n, c); \
    } \
    static inline void bash_hash##BITS##_get(bash_hash_ctx c, void *out) { \
        bashHashStepG(out, OUTLEN, c); \
    } \
    static inline void bash_hash##BITS##_cleanup(bash_hash_ctx c) { \
        bee2_backend_cleanup(c, sizeof(*c)); \
    }
BASH_HASH_ADAPTER(128, 128u, 32u)
BASH_HASH_ADAPTER(192, 192u, 48u)
BASH_HASH_ADAPTER(256, 256u, 64u)

/* BELT block-mode adapters. */
typedef struct {
    bee2_backend_state_t state;
    unsigned char key[32];
    unsigned char iv[16];
    int key_set;
    int iv_set;
} bee2_belt_mode_ctx_t;
typedef bee2_belt_mode_ctx_t belt_ecb_ctx_t;
typedef bee2_belt_mode_ctx_t belt_cbc_ctx_t;
typedef bee2_belt_mode_ctx_t belt_cfb_ctx_t;
typedef bee2_belt_mode_ctx_t belt_ctr_ctx_t;
typedef bee2_belt_mode_ctx_t belt_bde_ctx_t;

static inline void
bee2_belt_mode_store_key(bee2_belt_mode_ctx_t *c, const void *key, size_t key_len) {
    if (key_len == BELT_KEY_SIZE)
        memcpy(c->key, key, BELT_KEY_SIZE);
    else
        bee2_belt_expand_key(key, key_len, c->key);
    c->key_set = 1;
}

static inline void belt_ecb_restart(belt_ecb_ctx_t *c) {
    if (c->key_set)
        beltECBStart(&c->state, c->key, BELT_KEY_SIZE);
}
static inline void belt_ecb_set_key(belt_ecb_ctx_t *c, const void *key, size_t key_len) {
    bee2_belt_mode_store_key(c, key, key_len);
    belt_ecb_restart(c);
}
static inline void belt_ecb_set_iv(belt_ecb_ctx_t *c, const void *iv, size_t iv_len) {
    (void)c;
    (void)iv;
    (void)iv_len;
}
static inline void belt_ecb_init(belt_ecb_ctx_t *c) {
    memset(c, 0, sizeof(*c));
}
static inline void belt_ecb_encrypt(belt_ecb_ctx_t *c, const void *in, size_t blocks, void *out) {
    memmove(out, in, (size_t)blocks * 16u);
    beltECBStepE(out, (size_t)blocks * 16u, &c->state);
}
static inline void belt_ecb_decrypt(belt_ecb_ctx_t *c, const void *in, size_t blocks, void *out) {
    memmove(out, in, (size_t)blocks * 16u);
    beltECBStepD(out, (size_t)blocks * 16u, &c->state);
}
static inline void belt_ecb_cleanup(belt_ecb_ctx_t *c) {
    bee2_backend_cleanup(c, sizeof(*c));
}

#define BELT_IV_MODE(PFX, CAMEL, ENCSTEP, DECSTEP) \
    static inline void PFX##_init(PFX##_ctx_t *c) { \
        memset(c, 0, sizeof(*c)); \
    } \
    static inline void PFX##_restart(PFX##_ctx_t *c) { \
        if (c->key_set && c->iv_set) \
            CAMEL##Start(&c->state, c->key, 32, c->iv); \
    } \
    static inline void PFX##_set_key(PFX##_ctx_t *c, const void *key, size_t key_len) { \
        bee2_belt_mode_store_key(c, key, key_len); \
        PFX##_restart(c); \
    } \
    static inline void PFX##_set_iv(PFX##_ctx_t *c, const void *iv, size_t iv_len) { \
        (void)iv_len; \
        memcpy(c->iv, iv, 16); \
        c->iv_set = 1; \
        PFX##_restart(c); \
    } \
    static inline void PFX##_encrypt(PFX##_ctx_t *c, const void *in, size_t blocks, void *out) { \
        memmove(out, in, (size_t)blocks * 16u); \
        ENCSTEP(out, (size_t)blocks * 16u, &c->state); \
    } \
    static inline void PFX##_decrypt(PFX##_ctx_t *c, const void *in, size_t blocks, void *out) { \
        memmove(out, in, (size_t)blocks * 16u); \
        DECSTEP(out, (size_t)blocks * 16u, &c->state); \
    } \
    static inline void PFX##_cleanup(PFX##_ctx_t *c) { \
        bee2_backend_cleanup(c, sizeof(*c)); \
    }

BELT_IV_MODE(belt_cbc, beltCBC, beltCBCStepE, beltCBCStepD)
BELT_IV_MODE(belt_cfb, beltCFB, beltCFBStepE, beltCFBStepD)
BELT_IV_MODE(belt_ctr, beltCTR, beltCTRStepE, beltCTRStepE)
BELT_IV_MODE(belt_bde, beltBDE, beltBDEStepE, beltBDEStepD)

/* BELT AEAD adapters. */
typedef bee2_belt_mode_ctx_t belt_che_ctx_t;
typedef bee2_belt_mode_ctx_t belt_dwp_ctx_t;
#define BELT_AEAD_ADAPTER(PFX, CAMEL) \
    static inline void PFX##_init(PFX##_ctx_t *c) { \
        memset(c, 0, sizeof(*c)); \
    } \
    static inline void PFX##_restart(PFX##_ctx_t *c) { \
        if (c->key_set && c->iv_set) \
            CAMEL##Start(&c->state, c->key, 32, c->iv); \
    } \
    static inline void PFX##_set_key(PFX##_ctx_t *c, const void *key, size_t key_len) { \
        bee2_belt_mode_store_key(c, key, key_len); \
        PFX##_restart(c); \
    } \
    static inline void PFX##_set_iv(PFX##_ctx_t *c, const void *iv, size_t iv_len) { \
        (void)iv_len; \
        memcpy(c->iv, iv, 16); \
        c->iv_set = 1; \
        PFX##_restart(c); \
    } \
    static inline void PFX##_update_ad(PFX##_ctx_t *c, const void *in, size_t n) { \
        CAMEL##StepI(in, n, &c->state); \
    } \
    static inline void PFX##_encrypt(PFX##_ctx_t *c, const void *in, size_t n, void *out) { \
        memmove(out, in, n); \
        CAMEL##StepE(out, n, &c->state); \
        CAMEL##StepA(out, n, &c->state); \
    } \
    static inline void PFX##_decrypt(PFX##_ctx_t *c, const void *in, size_t n, void *out) { \
        memmove(out, in, n); \
        CAMEL##StepA(out, n, &c->state); \
        CAMEL##StepD(out, n, &c->state); \
    } \
    static inline void PFX##_get_mac(PFX##_ctx_t *c, void *out) { \
        CAMEL##StepG(out, &c->state); \
    } \
    static inline void PFX##_cleanup(PFX##_ctx_t *c) { \
        bee2_backend_cleanup(c, sizeof(*c)); \
    }
BELT_AEAD_ADAPTER(belt_che, beltCHE)
BELT_AEAD_ADAPTER(belt_dwp, beltDWP)

/* BELT MAC. */
typedef struct {
    bee2_backend_state_t state;
    unsigned char key[BELT_KEY_SIZE];
    int key_set;
} belt_mac_ctx_t;
static inline void belt_mac_init(belt_mac_ctx_t *c) {
    memset(c, 0, sizeof(*c));
}
static inline void belt_mac_restart(belt_mac_ctx_t *c) {
    if (c->key_set)
        beltMACStart(&c->state, c->key, BELT_KEY_SIZE);
}
static inline void belt_mac_set_key(belt_mac_ctx_t *c, const void *key, size_t key_len) {
    if (key_len == BELT_KEY_SIZE)
        memcpy(c->key, key, BELT_KEY_SIZE);
    else
        bee2_belt_expand_key(key, key_len, c->key);
    c->key_set = 1;
    belt_mac_restart(c);
}
static inline void belt_mac_update(belt_mac_ctx_t *c, const void *in, size_t n) {
    beltMACStepA(in, n, &c->state);
}
static inline void belt_mac_get(belt_mac_ctx_t *c, void *out) {
    beltMACStepG(out, &c->state);
}
static inline void belt_mac_cleanup(belt_mac_ctx_t *c) {
    bee2_backend_cleanup(c, sizeof(*c));
}

/* HMAC-HBELT. */
typedef bee2_backend_state_t belt_hmac_ctx_t;
static inline void belt_hmac_init(belt_hmac_ctx_t *c, const void *key, size_t key_len) {
    beltHMACStart(c, key, key_len);
}
static inline void belt_hmac_update(belt_hmac_ctx_t *c, const void *in, size_t n) {
    beltHMACStepA(in, n, c);
}
static inline void belt_hmac_get(belt_hmac_ctx_t *c, void *out) {
    beltHMACStepG(out, c);
}
static inline void belt_hmac_cleanup(belt_hmac_ctx_t *c) {
    bee2_backend_cleanup(c, sizeof(*c));
}

/* BELT SDE. */
typedef bee2_belt_mode_ctx_t belt_sde_ctx_t;
static inline void belt_sde_init(belt_sde_ctx_t *c) {
    memset(c, 0, sizeof(*c));
}
static inline void belt_sde_restart(belt_sde_ctx_t *c) {
    if (c->key_set)
        beltSDEStart(&c->state, c->key, BELT_KEY_SIZE);
}
static inline void belt_sde_set_key(belt_sde_ctx_t *c, const void *key, size_t key_len) {
    bee2_belt_mode_store_key(c, key, key_len);
    belt_sde_restart(c);
}
static inline void belt_sde_set_iv(belt_sde_ctx_t *c, const void *iv, size_t iv_len) {
    (void)iv_len;
    memcpy(c->iv, iv, 16);
    c->iv_set = 1;
}
static inline void belt_sde_encrypt(belt_sde_ctx_t *c, const void *in, size_t blocks, void *out) {
    memmove(out, in, (size_t)blocks * 16u);
    beltSDEStepE(out, (size_t)blocks * 16u, c->iv, &c->state);
}
static inline void belt_sde_decrypt(belt_sde_ctx_t *c, const void *in, size_t blocks, void *out) {
    memmove(out, in, (size_t)blocks * 16u);
    beltSDEStepD(out, (size_t)blocks * 16u, c->iv, &c->state);
}
static inline void belt_sde_cleanup(belt_sde_ctx_t *c) {
    bee2_backend_cleanup(c, sizeof(*c));
}

/* BASH-PRG-AE adapters used by the existing provider implementation. */
typedef struct {
    bee2_backend_state_t state;
    unsigned char key[60];
    size_t key_len;
    unsigned char iv[60];
    size_t iv_len;
    int key_set;
    int iv_set;
} bash_prgae_ctx_t;
typedef bash_prgae_ctx_t *bash_prgae_ctx;
#define BASH_PRGAE_ADAPTER(SFX, LEVEL, D) \
    static inline void bash_prgae_##SFX##_init(bash_prgae_ctx c) { \
        memset(c, 0, sizeof(*c)); \
    } \
    static inline void bash_prgae_##SFX##_restart(bash_prgae_ctx c) { \
        if (c->key_set && c->iv_set) \
            bashPrgStart(&c->state, LEVEL, D, c->iv, c->iv_len, c->key, c->key_len); \
    } \
    static inline void bash_prgae_##SFX##_set_key(bash_prgae_ctx c, const void *p, size_t n) { \
        memcpy(c->key, p, n); \
        c->key_len = n; \
        c->key_set = 1; \
        bash_prgae_##SFX##_restart(c); \
    } \
    static inline void bash_prgae_##SFX##_set_iv(bash_prgae_ctx c, const void *p, size_t n) { \
        memcpy(c->iv, p, n); \
        c->iv_len = n; \
        c->iv_set = 1; \
        bash_prgae_##SFX##_restart(c); \
    } \
    static inline void bash_prgae_##SFX##_update_ad(bash_prgae_ctx c, const void *p, size_t n) { \
        bashPrgAbsorb(p, n, &c->state); \
    } \
    static inline void bash_prgae_##SFX##_encrypt( \
        bash_prgae_ctx c, const void *in, size_t n, void *out) { \
        memmove(out, in, n); \
        bashPrgEncr(out, n, &c->state); \
    } \
    static inline void bash_prgae_##SFX##_decrypt( \
        bash_prgae_ctx c, const void *in, size_t n, void *out) { \
        memmove(out, in, n); \
        bashPrgDecr(out, n, &c->state); \
    } \
    static inline void bash_prgae_##SFX##_get_mac(bash_prgae_ctx c, void *out, size_t n) { \
        bashPrgSqueeze(out, n, &c->state); \
    } \
    static inline void bash_prgae_##SFX##_cleanup(bash_prgae_ctx c) { \
        bee2_backend_cleanup(c, sizeof(*c)); \
    }
BASH_PRGAE_ADAPTER(1281, 128u, 1u)
BASH_PRGAE_ADAPTER(1282, 128u, 2u)
BASH_PRGAE_ADAPTER(1921, 192u, 1u)
BASH_PRGAE_ADAPTER(1922, 192u, 2u)
BASH_PRGAE_ADAPTER(2561, 256u, 1u)
BASH_PRGAE_ADAPTER(2562, 256u, 2u)

#endif /* BEE2_PROVIDER_BACKEND_H */
