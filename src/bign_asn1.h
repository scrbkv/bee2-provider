#ifndef BEE2_PROVIDER_BIGN_ASN1_H
#define BEE2_PROVIDER_BIGN_ASN1_H
#include "bign_common.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

typedef enum {
    BIGN_DECODE_PRIVATE, BIGN_DECODE_PUBLIC, BIGN_DECODE_DER, BIGN_DECODE_PEM
} bign_decode_kind;

typedef struct {
    bign_decode_kind kind;
    OSSL_LIB_CTX *libctx;
    unsigned int max_pbkdf2_iterations;
} bee2_bign_decoder_ctx_t;

PKCS8_PRIV_KEY_INFO *bee2_bign_asn1_pkcs8(const bee2_bign_key_t *key);
X509_PUBKEY *bee2_bign_asn1_spki(const bee2_bign_key_t *key);
int bee2_bign_asn1_decode_pkcs8_der(const unsigned char *buf, size_t len,
                                    const bee2_bign_variant_t *expected, bee2_bign_key_t *key);
int bee2_bign_asn1_decode_spki_der(const unsigned char *buf, size_t len,
                                  const bee2_bign_variant_t *expected, bee2_bign_key_t *key);
int bee2_bign_asn1_decoder_decode(void *vctx, OSSL_CORE_BIO *in, int selection,
                                  OSSL_CALLBACK *data_cb, void *data_cbarg,
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg);
int bee2_bign_asn1_resolve_hash_oid(const EVP_MD *md, const char *mdname,
                                   const char *known, char *oid, size_t size);
int bee2_bign_asn1_build_algid(const char *oid, const char *hash_oid,
                               unsigned char *buf, size_t buf_len, size_t *out_len);
#endif
