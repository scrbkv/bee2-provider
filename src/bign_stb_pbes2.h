#ifndef BEE2_BIGN_STB_PBES2_H
#define BEE2_BIGN_STB_PBES2_H

#include <openssl/x509.h>
#include <stddef.h>

#define BEE2_STB_PBKDF2_DEFAULT_ITER 10000u
#define BEE2_STB_PBKDF2_DEFAULT_SALT 16u
#define BEE2_STB_PBKDF2_PARAM_ITER "stb-pbkdf2-iterations"
#define BEE2_STB_PBKDF2_PARAM_SALTLEN "stb-pbkdf2-saltlen"
#define BEE2_STB_PBKDF2_PARAM_MAX_DECODE_ITER "stb-pbkdf2-max-decode-iterations"
#define BEE2_STB_PBKDF2_DEFAULT_MAX_DECODE_ITER 1000000u

X509_SIG *bee2_stb_pbes2_protect(const unsigned char *scalar, size_t scalar_len,
                               const unsigned char *password, size_t password_len,
                               unsigned int iterations, size_t salt_len, OSSL_LIB_CTX *libctx);

/* Check the PBES2 encryption OID without requesting a password. */
int bee2_stb_pbes2_is_stb(const X509_SIG *encrypted);

/* A malformed STB PBES2 object must not fall back to other decoders. */
PKCS8_PRIV_KEY_INFO *bee2_stb_pbes2_decrypt(const X509_SIG *encrypted,
                                            const unsigned char *password,
                                            size_t password_len,
                                            unsigned int max_iterations, int *recognised);

#endif
