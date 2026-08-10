#ifndef BEE2_PROVIDER_H
#define BEE2_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define BEE2_PROVIDER_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define BEE2_PROVIDER_EXPORT __attribute__((visibility("default")))
#else
#define BEE2_PROVIDER_EXPORT
#endif

/* ---- Cipher dispatch tables --------------------------------------- */

/* BELT block cipher modes (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_128_ecb_functions[];
extern const OSSL_DISPATCH bee2_belt_192_ecb_functions[];
extern const OSSL_DISPATCH bee2_belt_256_ecb_functions[];
extern const OSSL_DISPATCH bee2_belt_128_cbc_functions[];
extern const OSSL_DISPATCH bee2_belt_192_cbc_functions[];
extern const OSSL_DISPATCH bee2_belt_256_cbc_functions[];
extern const OSSL_DISPATCH bee2_belt_128_cfb_functions[];
extern const OSSL_DISPATCH bee2_belt_192_cfb_functions[];
extern const OSSL_DISPATCH bee2_belt_256_cfb_functions[];
extern const OSSL_DISPATCH bee2_belt_128_ctr_functions[];
extern const OSSL_DISPATCH bee2_belt_192_ctr_functions[];
extern const OSSL_DISPATCH bee2_belt_256_ctr_functions[];
extern const OSSL_DISPATCH bee2_belt_128_bde_functions[];
extern const OSSL_DISPATCH bee2_belt_192_bde_functions[];
extern const OSSL_DISPATCH bee2_belt_256_bde_functions[];

/* BELT disk encryption (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_128_sde_functions[];
extern const OSSL_DISPATCH bee2_belt_192_sde_functions[];
extern const OSSL_DISPATCH bee2_belt_256_sde_functions[];

/* BELT AEAD modes (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_128_che_functions[];
extern const OSSL_DISPATCH bee2_belt_192_che_functions[];
extern const OSSL_DISPATCH bee2_belt_256_che_functions[];
extern const OSSL_DISPATCH bee2_belt_128_dwp_functions[];
extern const OSSL_DISPATCH bee2_belt_192_dwp_functions[];
extern const OSSL_DISPATCH bee2_belt_256_dwp_functions[];

/* BELT-KWP key wrapping (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_kwp128_functions[];
extern const OSSL_DISPATCH bee2_belt_kwp192_functions[];
extern const OSSL_DISPATCH bee2_belt_kwp256_functions[];

/* BASH-PRGAE AEAD variants (STB 34.101.77) */
extern const OSSL_DISPATCH bee2_bash_prgae_1281_functions[];
extern const OSSL_DISPATCH bee2_bash_prgae_1282_functions[];
extern const OSSL_DISPATCH bee2_bash_prgae_1921_functions[];
extern const OSSL_DISPATCH bee2_bash_prgae_1922_functions[];
extern const OSSL_DISPATCH bee2_bash_prgae_2561_functions[];
extern const OSSL_DISPATCH bee2_bash_prgae_2562_functions[];

/* ---- Digest dispatch tables --------------------------------------- */

/* BELT-Hash (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_hash_functions[];

/* BASH sponge hash — named by OUTPUT size (STB 34.101.77)
 *   bee2_bash256_functions  ←  bash_hash128, security l=128, 32-byte output
 *   bee2_bash384_functions  ←  bash_hash192, security l=192, 48-byte output
 *   bee2_bash512_functions  ←  bash_hash256, security l=256, 64-byte output  */
extern const OSSL_DISPATCH bee2_bash256_functions[];
extern const OSSL_DISPATCH bee2_bash384_functions[];
extern const OSSL_DISPATCH bee2_bash512_functions[];

/* ---- MAC dispatch tables ------------------------------------------ */

/* HMAC over STB digests */
extern const OSSL_DISPATCH bee2_hmac_functions[];

/* BELT-MAC (STB 34.101.31) */
extern const OSSL_DISPATCH bee2_belt_mac128_functions[];
extern const OSSL_DISPATCH bee2_belt_mac192_functions[];
extern const OSSL_DISPATCH bee2_belt_mac256_functions[];

/* ---- KDF dispatch tables ------------------------------------------ */

extern const OSSL_DISPATCH bee2_belt_pbkdf_functions[];

/* ---- RAND dispatch tables ----------------------------------------- */

/* BRNG (STB 34.101.47) */
extern const OSSL_DISPATCH bee2_brng_ctr_hbelt_functions[];
extern const OSSL_DISPATCH bee2_brng_hmac_hbelt_functions[];

/* ---- KEYMGMT dispatch tables -------------------------------------- */

/* BIGN key management (STB 34.101.45) */
extern const OSSL_DISPATCH bee2_bign_256_keymgmt_functions[];
extern const OSSL_DISPATCH bee2_bign_384_keymgmt_functions[];
extern const OSSL_DISPATCH bee2_bign_512_keymgmt_functions[];
extern const OSSL_DISPATCH bee2_bign_keymgmt_functions[];

/* ---- KEYEXCH dispatch tables ------------------------------------- */

/* BIGN Diffie--Hellman and optional BAKE-KDF (STB 34.101.45/66) */
extern const OSSL_DISPATCH bee2_bign_keyexchange_functions[];

/* ---- SIGNATURE dispatch tables ------------------------------------ */

/* BIGN signature (STB 34.101.45) */
extern const OSSL_DISPATCH bee2_bign_256_signature_functions[];
extern const OSSL_DISPATCH bee2_bign_384_signature_functions[];
extern const OSSL_DISPATCH bee2_bign_512_signature_functions[];
extern const OSSL_DISPATCH bee2_bign_generic_signature_functions[];

/* ---- Asymmetric cipher dispatch tables ---------------------------- */

extern const OSSL_DISPATCH bee2_bign_keytransport_functions[];

/* ---- ENCODER/DECODER dispatch tables ----------------------------- */

extern const OSSL_DISPATCH bee2_bign_256_pem_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_256_der_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_384_pem_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_384_der_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_512_pem_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_512_der_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_pem_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_der_encoder_functions[];
extern const OSSL_DISPATCH bee2_bign_decoder_functions[];
extern const OSSL_DISPATCH bee2_bign_store_functions[];

/* ---- CORE BIO helpers -------------------------------------------- */

int bee2_core_bio_read(OSSL_CORE_BIO *bio, void *data, size_t data_len, size_t *bytes_read);
int bee2_core_bio_write(OSSL_CORE_BIO *bio,
                        const void *data,
                        size_t data_len,
                        size_t *bytes_written);

#endif /* BEE2_PROVIDER_H */
