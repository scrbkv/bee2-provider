#ifndef BEE2_BIGN_STB_PBES2_H
#define BEE2_BIGN_STB_PBES2_H

#include <openssl/x509.h>
#include <stddef.h>

#define BEE2_STB_PBKDF2_MIN_ITER 10000u
#define BEE2_STB_PBKDF2_MIN_SALT 8u
#define BEE2_STB_PBKDF2_DEFAULT_SALT 16u
#define BEE2_STB_PBKDF2_PARAM_ITER "stb-pbkdf2-iterations"
#define BEE2_STB_PBKDF2_PARAM_SALTLEN "stb-pbkdf2-saltlen"
#define BEE2_STB_PBKDF2_PARAM_MAX_DECODE_ITER "stb-pbkdf2-max-decode-iterations"
#define BEE2_STB_PBKDF2_DEFAULT_MAX_DECODE_ITER 1000000u

/* Check the PBES2 encryption OID without requesting a password. */
int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted);

/* Bound the work of the provider's legacy PBES2/PBKDF2 fallback. */
int bee2_stb_pbes2_legacy_pbkdf2_allowed(const X509_SIG *encrypted,
                                          unsigned int max_iterations);

/* DER-encoded EncryptedPrivateKeyInfo, allocated with OPENSSL_malloc(). */
unsigned char *bee2_stb_pbes2_encrypt(const unsigned char *der, size_t der_len,
                                      const unsigned char *password, size_t password_len,
                                      size_t key_len, unsigned int iterations,
                                      size_t salt_len, OSSL_LIB_CTX *libctx, size_t *out_len);

/* The caller must distinguish an unrecognised legacy scheme from a malformed
 * STB scheme or an incorrect password, and never fall back for the latter. */
PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len,
                                            unsigned int max_iterations, int *recognised);

#endif
