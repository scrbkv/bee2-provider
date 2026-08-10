#include "provider.h"

#include "bee2_backend.h"
#include "bee2_oids.h"

#include <openssl/objects.h>

static OSSL_FUNC_BIO_read_ex_fn *bee2_core_bio_read_ex_fn = NULL;
static OSSL_FUNC_BIO_write_ex_fn *bee2_core_bio_write_ex_fn = NULL;

/* ------------------------------------------------------------------ */
/*  OID registration (signatures and digests)                          */
/* ------------------------------------------------------------------ */

static int bee2_add_sigid(int signid, int mdid, int pkeyid) {
    int md = 0;
    int pk = 0;
    if (OBJ_find_sigid_algs(signid, &md, &pk))
        return 1;
    return OBJ_add_sigid(signid, mdid, pkeyid);
}

typedef struct {
    const char *oid;
    const char *name;
} bee2_oid_definition_t;

static const bee2_oid_definition_t bee2_oid_definitions[] = {
    {BEE2_OID_BIGN_PUBKEY, "bign-pubkey"},
    {BEE2_OID_BIGN_CURVE256, "bign-curve256v1"},
    {BEE2_OID_BIGN_CURVE384, "bign-curve384v1"},
    {BEE2_OID_BIGN_CURVE512, "bign-curve512v1"},
    {BEE2_OID_BIGN_PRIMEFIELD, "bign-primefield"},
    {BEE2_OID_BIGN_WITH_HSPEC, "bign-with-hspec"},
    {BEE2_OID_BIGN_WITH_HBELT, "bign-with-hbelt"},
    {BEE2_OID_BIGN_WITH_BASH256, "bign-with-bash256"},
    {BEE2_OID_BIGN_WITH_BASH384, "bign-with-bash384"},
    {BEE2_OID_BIGN_WITH_BASH512, "bign-with-bash512"},
    {BEE2_OID_BIGN_KEYTRANSPORT, "bign-keytransport"},
    {BEE2_OID_BELT_HASH, "belt-hash"},
    {BEE2_OID_BASH256, "bash256"},
    {BEE2_OID_BASH384, "bash384"},
    {BEE2_OID_BASH512, "bash512"},
    {BEE2_OID_BELT_128_ECB, "belt-ecb128"},
    {BEE2_OID_BELT_192_ECB, "belt-ecb192"},
    {BEE2_OID_BELT_256_ECB, "belt-ecb256"},
    {BEE2_OID_BELT_128_CBC, "belt-cbc128"},
    {BEE2_OID_BELT_192_CBC, "belt-cbc192"},
    {BEE2_OID_BELT_256_CBC, "belt-cbc256"},
    {BEE2_OID_BELT_128_CFB, "belt-cfb128"},
    {BEE2_OID_BELT_192_CFB, "belt-cfb192"},
    {BEE2_OID_BELT_256_CFB, "belt-cfb256"},
    {BEE2_OID_BELT_128_CTR, "belt-ctr128"},
    {BEE2_OID_BELT_192_CTR, "belt-ctr192"},
    {BEE2_OID_BELT_256_CTR, "belt-ctr256"},
    {BEE2_OID_BELT_256_BDE, "belt-bde256"},
    {BEE2_OID_BELT_256_SDE, "belt-sde256"},
    {BEE2_OID_BELT_128_KWP, "belt-kwp128"},
    {BEE2_OID_BELT_192_KWP, "belt-kwp192"},
    {BEE2_OID_BELT_KWP, "belt-kwp256"},
    {BEE2_OID_BELT_128_CHE, "belt-che128"},
    {BEE2_OID_BELT_192_CHE, "belt-che192"},
    {BEE2_OID_BELT_256_CHE, "belt-che256"},
    {BEE2_OID_BELT_128_DWP, "belt-dwp128"},
    {BEE2_OID_BELT_192_DWP, "belt-dwp192"},
    {BEE2_OID_BELT_256_DWP, "belt-dwp256"},
    {BEE2_OID_BELT_MAC128, "belt-mac128"},
    {BEE2_OID_BELT_MAC192, "belt-mac192"},
    {BEE2_OID_BELT_MAC, "belt-mac256"},
    {BEE2_OID_BELT_PBKDF, "belt-pbkdf"},
    {BEE2_OID_HMAC_HBELT, "belt-hmac"},
    {BEE2_OID_BRNG_CTR_HBELT, "brng-ctr-hbelt"},
    {BEE2_OID_BRNG_HMAC_HBELT, "brng-hmac-hbelt"},
    {BEE2_OID_BASH_PRGAE_1281, "bash-prg-ae1281"},
    {BEE2_OID_BASH_PRGAE_1282, "bash-prg-ae1282"},
    {BEE2_OID_BASH_PRGAE_1921, "bash-prg-ae1921"},
    {BEE2_OID_BASH_PRGAE_1922, "bash-prg-ae1922"},
    {BEE2_OID_BASH_PRGAE_2561, "bash-prg-ae2561"},
    {BEE2_OID_BASH_PRGAE_2562, "bash-prg-ae2562"}};

static int bee2_register_bign_oids(void) {
    int nid_bign_pubkey;
    static const char *signature_oids[] = {BEE2_OID_BIGN_WITH_HSPEC,
                                           BEE2_OID_BIGN_WITH_HBELT,
                                           BEE2_OID_BIGN_WITH_BASH256,
                                           BEE2_OID_BIGN_WITH_BASH384,
                                           BEE2_OID_BIGN_WITH_BASH512};
    size_t i;

    for (i = 0; i < sizeof(bee2_oid_definitions) / sizeof(bee2_oid_definitions[0]); ++i) {
        const bee2_oid_definition_t *definition = &bee2_oid_definitions[i];
        if (OBJ_txt2nid(definition->oid) == NID_undef &&
            OBJ_create(definition->oid, definition->name, definition->name) == NID_undef)
            return 0;
    }

    nid_bign_pubkey = OBJ_txt2nid(BEE2_OID_BIGN_PUBKEY);
    if (nid_bign_pubkey == NID_undef)
        return 0;
    for (i = 0; i < sizeof(signature_oids) / sizeof(signature_oids[0]); ++i) {
        int signature_nid = OBJ_txt2nid(signature_oids[i]);
        if (signature_nid == NID_undef ||
            !bee2_add_sigid(signature_nid, NID_undef, nid_bign_pubkey))
            return 0;
    }
    return 1;
}

int bee2_core_bio_read(OSSL_CORE_BIO *bio, void *data, size_t data_len, size_t *bytes_read) {
    if (!bee2_core_bio_read_ex_fn) {
        return 0;
    }
    return bee2_core_bio_read_ex_fn(bio, data, data_len, bytes_read);
}

int bee2_core_bio_write(OSSL_CORE_BIO *bio,
                        const void *data,
                        size_t data_len,
                        size_t *bytes_written) {
    if (!bee2_core_bio_write_ex_fn) {
        return 0;
    }
    return bee2_core_bio_write_ex_fn(bio, data, data_len, bytes_written);
}

/* ------------------------------------------------------------------ */
/*  Algorithm tables                                                    */
/* ------------------------------------------------------------------ */

static const OSSL_ALGORITHM bee2_ciphers[] = {
    /* ---- BELT block cipher modes (STB 34.101.31) ---- */
    {BEE2_ALG_BELT_128_ECB, "provider=bee2", bee2_belt_128_ecb_functions, "BELT-128 in ECB mode"},
    {BEE2_ALG_BELT_192_ECB, "provider=bee2", bee2_belt_192_ecb_functions, "BELT-192 in ECB mode"},
    {BEE2_ALG_BELT_256_ECB, "provider=bee2", bee2_belt_256_ecb_functions, "BELT-256 in ECB mode"},
    {BEE2_ALG_BELT_128_CBC, "provider=bee2", bee2_belt_128_cbc_functions, "BELT-128 in CBC mode"},
    {BEE2_ALG_BELT_192_CBC, "provider=bee2", bee2_belt_192_cbc_functions, "BELT-192 in CBC mode"},
    {BEE2_ALG_BELT_256_CBC, "provider=bee2", bee2_belt_256_cbc_functions, "BELT-256 in CBC mode"},
    {BEE2_ALG_BELT_128_CFB, "provider=bee2", bee2_belt_128_cfb_functions, "BELT-128 in CFB mode"},
    {BEE2_ALG_BELT_192_CFB, "provider=bee2", bee2_belt_192_cfb_functions, "BELT-192 in CFB mode"},
    {BEE2_ALG_BELT_256_CFB, "provider=bee2", bee2_belt_256_cfb_functions, "BELT-256 in CFB mode"},
    {BEE2_ALG_BELT_128_CTR, "provider=bee2", bee2_belt_128_ctr_functions, "BELT-128 in CTR mode"},
    {BEE2_ALG_BELT_192_CTR, "provider=bee2", bee2_belt_192_ctr_functions, "BELT-192 in CTR mode"},
    {BEE2_ALG_BELT_256_CTR, "provider=bee2", bee2_belt_256_ctr_functions, "BELT-256 in CTR mode"},
    {"belt-bde128",
     "provider=bee2",
     bee2_belt_128_bde_functions,
     "BELT-128-BDE (XEX disk encryption)"},
    {"belt-bde192",
     "provider=bee2",
     bee2_belt_192_bde_functions,
     "BELT-192-BDE (XEX disk encryption)"},
    {BEE2_ALG_BELT_256_BDE,
     "provider=bee2",
     bee2_belt_256_bde_functions,
     "BELT-256-BDE (XEX disk encryption)"},
    {"belt-sde128",
     "provider=bee2",
     bee2_belt_128_sde_functions,
     "BELT-128-SDE (wide-block sector encryption)"},
    {"belt-sde192",
     "provider=bee2",
     bee2_belt_192_sde_functions,
     "BELT-192-SDE (wide-block sector encryption)"},
    {BEE2_ALG_BELT_256_SDE,
     "provider=bee2",
     bee2_belt_256_sde_functions,
     "BELT-256-SDE (wide-block sector encryption)"},

    /* ---- BELT AEAD modes (STB 34.101.31) ---- */
    {BEE2_ALG_BELT_128_CHE,
     "provider=bee2",
     bee2_belt_128_che_functions,
     "BELT-128-CHE (CTR+GMAC AEAD)"},
    {BEE2_ALG_BELT_192_CHE,
     "provider=bee2",
     bee2_belt_192_che_functions,
     "BELT-192-CHE (CTR+GMAC AEAD)"},
    {BEE2_ALG_BELT_256_CHE,
     "provider=bee2",
     bee2_belt_256_che_functions,
     "BELT-256-CHE (CTR+GMAC AEAD)"},
    {BEE2_ALG_BELT_128_DWP,
     "provider=bee2",
     bee2_belt_128_dwp_functions,
     "BELT-128-DWP (duplex AEAD)"},
    {BEE2_ALG_BELT_192_DWP,
     "provider=bee2",
     bee2_belt_192_dwp_functions,
     "BELT-192-DWP (duplex AEAD)"},
    {BEE2_ALG_BELT_256_DWP,
     "provider=bee2",
     bee2_belt_256_dwp_functions,
     "BELT-256-DWP (duplex AEAD)"},

    /* ---- BELT-KWP key wrapping (STB 34.101.31) ---- */
    {BEE2_ALG_BELT_128_KWP,
     "provider=bee2",
     bee2_belt_kwp128_functions,
     "BELT-KWP-128 (key wrapping)"},
    {BEE2_ALG_BELT_192_KWP,
     "provider=bee2",
     bee2_belt_kwp192_functions,
     "BELT-KWP-192 (key wrapping)"},
    {BEE2_ALG_BELT_KWP, "provider=bee2", bee2_belt_kwp256_functions, "BELT-KWP-256 (key wrapping)"},

    /* ---- BASH-PRGAE AEAD variants (STB 34.101.77) ---- */
    {BEE2_ALG_BASH_PRGAE_1281,
     "provider=bee2",
     bee2_bash_prgae_1281_functions,
     "BASH-PRG-AE l=128 d=1"},
    {BEE2_ALG_BASH_PRGAE_1282,
     "provider=bee2",
     bee2_bash_prgae_1282_functions,
     "BASH-PRG-AE l=128 d=2"},
    {BEE2_ALG_BASH_PRGAE_1921,
     "provider=bee2",
     bee2_bash_prgae_1921_functions,
     "BASH-PRG-AE l=192 d=1"},
    {BEE2_ALG_BASH_PRGAE_1922,
     "provider=bee2",
     bee2_bash_prgae_1922_functions,
     "BASH-PRG-AE l=192 d=2"},
    {BEE2_ALG_BASH_PRGAE_2561,
     "provider=bee2",
     bee2_bash_prgae_2561_functions,
     "BASH-PRG-AE l=256 d=1"},
    {BEE2_ALG_BASH_PRGAE_2562,
     "provider=bee2",
     bee2_bash_prgae_2562_functions,
     "BASH-PRG-AE l=256 d=2"},

    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_digests[] = {
    /* ---- BELT-Hash (STB 34.101.31) ---- */
    {BEE2_ALG_BELT_HASH, "provider=bee2", bee2_belt_hash_functions, "BELT hash, 256-bit output"},

    /* ---- BASH sponge hash — OIDs per STB 34.101.77 ----
     *  Output size = 2 × security level
     *  BASH-256: l=128  OID .77.11   32-byte output
     *  BASH-384: l=192  OID .77.12   48-byte output
     *  BASH-512: l=256  OID .77.13   64-byte output          */
    {BEE2_ALG_BASH256,
     "provider=bee2",
     bee2_bash256_functions,
     "BASH hash, 256-bit output (l=128)"},
    {BEE2_ALG_BASH384,
     "provider=bee2",
     bee2_bash384_functions,
     "BASH hash, 384-bit output (l=192)"},
    {BEE2_ALG_BASH512,
     "provider=bee2",
     bee2_bash512_functions,
     "BASH hash, 512-bit output (l=256)"},

    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_macs[] = {
    /* Generic HMAC over provider digests (BELT-HASH, BASH-*) */
    {BEE2_ALG_HMAC_HBELT, "provider=bee2", bee2_hmac_functions, "HMAC over STB digests"},
    {BEE2_ALG_BELT_MAC128,
     "provider=bee2",
     bee2_belt_mac128_functions,
     "BELT-MAC-128 (STB 34.101.31)"},
    {BEE2_ALG_BELT_MAC192,
     "provider=bee2",
     bee2_belt_mac192_functions,
     "BELT-MAC-192 (STB 34.101.31)"},
    {BEE2_ALG_BELT_MAC,
     "provider=bee2",
     bee2_belt_mac256_functions,
     "BELT-MAC-256 (STB 34.101.31)"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_kdfs[] = {
    {BEE2_ALG_BELT_PBKDF, "provider=bee2", bee2_belt_pbkdf_functions, "BELT PBKDF"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_asym_ciphers[] = {{BEE2_ALG_BIGN_KEYTRANSPORT,
                                                    "provider=bee2",
                                                    bee2_bign_keytransport_functions,
                                                    "BIGN key transport"},
                                                   {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_rands[] = {{BEE2_ALG_BRNG_CTR_HBELT,
                                             "provider=bee2",
                                             bee2_brng_ctr_hbelt_functions,
                                             "BRNG CTR over HBELT (STB 34.101.47)"},
                                            {BEE2_ALG_BRNG_HMAC_HBELT,
                                             "provider=bee2",
                                             bee2_brng_hmac_hbelt_functions,
                                             "BRNG HMAC over HBELT (STB 34.101.47)"},
                                            {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_keymgmts[] = {{BEE2_ALG_BIGN_KEY,
                                                "provider=bee2",
                                                bee2_bign_keymgmt_functions,
                                                "BIGN key management for encoded keys"},
                                               {BEE2_ALG_BIGN_256,
                                                "provider=bee2",
                                                bee2_bign_256_keymgmt_functions,
                                                "BIGN key management, curve 256-bit"},
                                               {BEE2_ALG_BIGN_384,
                                                "provider=bee2",
                                                bee2_bign_384_keymgmt_functions,
                                                "BIGN key management, curve 384-bit"},
                                               {BEE2_ALG_BIGN_512,
                                                "provider=bee2",
                                                bee2_bign_512_keymgmt_functions,
                                                "BIGN key management, curve 512-bit"},
                                               {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_keyexchanges[] = {{BEE2_ALG_BIGN,
                                                    "provider=bee2",
                                                    bee2_bign_keyexchange_functions,
                                                    "BIGN Diffie--Hellman key agreement"},
                                                   {BEE2_ALG_BIGN_256,
                                                    "provider=bee2",
                                                    bee2_bign_keyexchange_functions,
                                                    "BIGN-256 Diffie--Hellman key agreement"},
                                                   {BEE2_ALG_BIGN_384,
                                                    "provider=bee2",
                                                    bee2_bign_keyexchange_functions,
                                                    "BIGN-384 Diffie--Hellman key agreement"},
                                                   {BEE2_ALG_BIGN_512,
                                                    "provider=bee2",
                                                    bee2_bign_keyexchange_functions,
                                                    "BIGN-512 Diffie--Hellman key agreement"},
                                                   {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_signatures[] = {{BEE2_ALG_BIGN,
                                                  "provider=bee2",
                                                  bee2_bign_generic_signature_functions,
                                                  "BIGN signature for encoded keys"},
                                                 {BEE2_ALG_BIGN_256 ":" BEE2_ALG_BIGN_WITH_HSPEC
                                                                    ":" BEE2_ALG_BIGN_WITH_HBELT
                                                                    ":" BEE2_ALG_BIGN_WITH_BASH256,
                                                  "provider=bee2",
                                                  bee2_bign_256_signature_functions,
                                                  "BIGN signature on 256-bit curve"},
                                                 {BEE2_ALG_BIGN_384 ":" BEE2_ALG_BIGN_WITH_BASH384,
                                                  "provider=bee2",
                                                  bee2_bign_384_signature_functions,
                                                  "BIGN signature on 384-bit curve"},
                                                 {BEE2_ALG_BIGN_512 ":" BEE2_ALG_BIGN_WITH_BASH512,
                                                  "provider=bee2",
                                                  bee2_bign_512_signature_functions,
                                                  "BIGN signature on 512-bit curve"},
                                                 {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_encoders[] = {
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,output=pem,structure=PrivateKeyInfo",
     bee2_bign_pem_encoder_functions,
     "BIGN private key encoder (PEM, PKCS#8)"},
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,output=der,structure=PrivateKeyInfo",
     bee2_bign_der_encoder_functions,
     "BIGN private key encoder (DER, PKCS#8)"},
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,output=pem,structure=SubjectPublicKeyInfo",
     bee2_bign_pem_encoder_functions,
     "BIGN public key encoder (PEM, SPKI)"},
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,output=der,structure=SubjectPublicKeyInfo",
     bee2_bign_der_encoder_functions,
     "BIGN public key encoder (DER, SPKI)"},
    {BEE2_ALG_BIGN_256,
     "provider=bee2,output=pem,structure=PrivateKeyInfo",
     bee2_bign_256_pem_encoder_functions,
     "BIGN-256 private key encoder (PEM, PKCS#8)"},
    {BEE2_ALG_BIGN_384,
     "provider=bee2,output=pem,structure=PrivateKeyInfo",
     bee2_bign_384_pem_encoder_functions,
     "BIGN-384 private key encoder (PEM, PKCS#8)"},
    {BEE2_ALG_BIGN_512,
     "provider=bee2,output=pem,structure=PrivateKeyInfo",
     bee2_bign_512_pem_encoder_functions,
     "BIGN-512 private key encoder (PEM, PKCS#8)"},
    {BEE2_ALG_BIGN_256,
     "provider=bee2,output=der,structure=PrivateKeyInfo",
     bee2_bign_256_der_encoder_functions,
     "BIGN-256 private key encoder (DER, PKCS#8)"},
    {BEE2_ALG_BIGN_384,
     "provider=bee2,output=der,structure=PrivateKeyInfo",
     bee2_bign_384_der_encoder_functions,
     "BIGN-384 private key encoder (DER, PKCS#8)"},
    {BEE2_ALG_BIGN_512,
     "provider=bee2,output=der,structure=PrivateKeyInfo",
     bee2_bign_512_der_encoder_functions,
     "BIGN-512 private key encoder (DER, PKCS#8)"},
    {BEE2_ALG_BIGN_256,
     "provider=bee2,output=pem,structure=SubjectPublicKeyInfo",
     bee2_bign_256_pem_encoder_functions,
     "BIGN-256 public key encoder (PEM, SPKI)"},
    {BEE2_ALG_BIGN_384,
     "provider=bee2,output=pem,structure=SubjectPublicKeyInfo",
     bee2_bign_384_pem_encoder_functions,
     "BIGN-384 public key encoder (PEM, SPKI)"},
    {BEE2_ALG_BIGN_512,
     "provider=bee2,output=pem,structure=SubjectPublicKeyInfo",
     bee2_bign_512_pem_encoder_functions,
     "BIGN-512 public key encoder (PEM, SPKI)"},
    {BEE2_ALG_BIGN_256,
     "provider=bee2,output=der,structure=SubjectPublicKeyInfo",
     bee2_bign_256_der_encoder_functions,
     "BIGN-256 public key encoder (DER, SPKI)"},
    {BEE2_ALG_BIGN_384,
     "provider=bee2,output=der,structure=SubjectPublicKeyInfo",
     bee2_bign_384_der_encoder_functions,
     "BIGN-384 public key encoder (DER, SPKI)"},
    {BEE2_ALG_BIGN_512,
     "provider=bee2,output=der,structure=SubjectPublicKeyInfo",
     bee2_bign_512_der_encoder_functions,
     "BIGN-512 public key encoder (DER, SPKI)"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_decoders[] = {
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,input=der,structure=PrivateKeyInfo",
     bee2_bign_decoder_functions,
     "BIGN private key decoder (DER, PKCS#8)"},
    {BEE2_ALG_BIGN_KEY,
     "provider=bee2,input=der,structure=SubjectPublicKeyInfo",
     bee2_bign_decoder_functions,
     "BIGN public key decoder (DER, SPKI)"},
    {NULL, NULL, NULL, NULL}};

static const OSSL_ALGORITHM bee2_store_loaders[] = {
    {"bign", "provider=bee2", bee2_bign_store_functions, "BIGN key store loader"},
    {NULL, NULL, NULL, NULL}};

/* ------------------------------------------------------------------ */
/*  Provider callbacks                                                  */
/* ------------------------------------------------------------------ */

static const OSSL_ALGORITHM *bee2_query(void *provctx, int operation_id, int *no_cache) {
    (void)provctx;
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return bee2_ciphers;
    case OSSL_OP_DIGEST:
        return bee2_digests;
    case OSSL_OP_MAC:
        return bee2_macs;
    case OSSL_OP_KDF:
        return bee2_kdfs;
    case OSSL_OP_ASYM_CIPHER:
        return bee2_asym_ciphers;
    case OSSL_OP_RAND:
        return bee2_rands;
    case OSSL_OP_KEYMGMT:
        return bee2_keymgmts;
    case OSSL_OP_KEYEXCH:
        return bee2_keyexchanges;
    case OSSL_OP_SIGNATURE:
        return bee2_signatures;
    case OSSL_OP_ENCODER:
        return bee2_encoders;
    case OSSL_OP_DECODER:
        return bee2_decoders;
    case OSSL_OP_STORE:
        return bee2_store_loaders;
    default:
        return NULL;
    }
}

static void bee2_teardown(void *provctx) {
    (void)provctx;
}

static const OSSL_ITEM bee2_reason_strings[] = {{0, NULL}};

static const OSSL_ITEM *bee2_get_reason_strings(void *provctx) {
    (void)provctx;
    return bee2_reason_strings;
}

static const OSSL_PARAM bee2_gettable_provider_params[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *bee2_gettable_params(void *provctx) {
    (void)provctx;
    return bee2_gettable_provider_params;
}

static int bee2_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *param;

    (void)provctx;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, "Bee2 provider"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, BEE2_PROVIDER_VERSION))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, "Bee2 backend"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (param != NULL && !OSSL_PARAM_set_int(param, 1))
        return 0;
    return 1;
}

static const OSSL_DISPATCH bee2_provider_functions[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))bee2_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))bee2_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))bee2_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))bee2_query},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))bee2_get_reason_strings},
    {0, NULL}};

/* ------------------------------------------------------------------ */
/*  Provider entry point                                                */
/* ------------------------------------------------------------------ */

/*
 * OSSL_provider_init — called by libcrypto when the provider is loaded.
 *
 * Bee2 is linked directly into the module; no external backend
 * initialisation is required here.
 */
BEE2_PROVIDER_EXPORT OSSL_provider_init_fn OSSL_provider_init;

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    (void)handle;

    if (in == NULL || out == NULL || provctx == NULL || !bee2_backend_is_compatible())
        return 0;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_BIO_READ_EX:
            bee2_core_bio_read_ex_fn = OSSL_FUNC_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            bee2_core_bio_write_ex_fn = OSSL_FUNC_BIO_write_ex(in);
            break;
        default:
            break;
        }
    }

    if (!bee2_register_bign_oids())
        return 0;

    *out = bee2_provider_functions;
    *provctx = NULL;
    return 1;
}
