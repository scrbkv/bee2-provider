/* Inject failure at the ASN.1 ownership-transfer boundary.
 * Test that both named and explicit curve parameters are released safely.
 * The linker redirects PKCS8_pkey_set0 and X509_PUBKEY_set0_param in this executable.
 */
#include "bign_asn1.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

static int attempted;
static int pubkey_attempted;

static int transfer_failure = 1;
static int fail_allocation_at;
static int allocation_count;

static int allocation_failure(void)
{
    return fail_allocation_at != 0 && ++allocation_count == fail_allocation_at;
}

/* This wrapper affects only references compiled into this test executable,
 * not OpenSSL's independently linked allocator implementation.
 */
void *__real_CRYPTO_malloc(size_t size, const char *file, int line);
void *__real_CRYPTO_zalloc(size_t size, const char *file, int line);
void *__real_CRYPTO_realloc(void *ptr, size_t size, const char *file, int line);
void *__real_CRYPTO_memdup(const void *ptr, size_t size, const char *file, int line);
int __real_PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *alg,
                           int version, int parameter_type, void *parameters,
                           unsigned char *key, int key_len);
int __real_X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *alg,
                                 int parameter_type, void *parameters,
                                 unsigned char *key, int key_len);

void *__wrap_CRYPTO_malloc(size_t size, const char *file, int line)
{
    return allocation_failure() ? NULL : __real_CRYPTO_malloc(size, file, line);
}

void *__wrap_CRYPTO_zalloc(size_t size, const char *file, int line)
{
    return allocation_failure() ? NULL : __real_CRYPTO_zalloc(size, file, line);
}

void *__wrap_CRYPTO_realloc(void *ptr, size_t size, const char *file, int line)
{
    return allocation_failure() ? NULL : __real_CRYPTO_realloc(ptr, size, file, line);
}

void *__wrap_CRYPTO_memdup(const void *ptr, size_t size, const char *file, int line)
{
    return allocation_failure() ? NULL : __real_CRYPTO_memdup(ptr, size, file, line);
}


int __wrap_PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *alg,
                           int version, int parameter_type, void *parameters,
                           unsigned char *key, int key_len)
{
    (void)priv;
    (void)alg;
    (void)version;
    (void)parameter_type;
    (void)parameters;
    (void)key;
    (void)key_len;
    ++attempted;
    if (transfer_failure)
        return 0;
    return __real_PKCS8_pkey_set0(priv, alg, version, parameter_type,
                                  parameters, key, key_len);
}


int __wrap_X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *alg,
                                 int parameter_type, void *parameters,
                                 unsigned char *key, int key_len)
{
    (void)pub;
    (void)alg;
    (void)parameter_type;
    (void)parameters;
    (void)key;
    (void)key_len;
    ++pubkey_attempted;
    if (transfer_failure)
        return 0;
    return __real_X509_PUBKEY_set0_param(pub, alg, parameter_type,
                                         parameters, key, key_len);
}

int main(void)
{
    bee2_bign_key_t key;
    int explicit_params;

    memset(&key, 0, sizeof(key));
    key.variant = bee2_bign_variant_256();
    key.has_priv = 1;
    key.priv[0] = 3;
    if (!bee2_bign_derive_pubkey(key.variant, key.pub, key.priv)) {
        fprintf(stderr, "BIGN test public key calculation failed\n");
        return 1;
    }
    key.has_pub = 1;

    for (explicit_params = 0; explicit_params < 2; ++explicit_params) {
        unsigned char *der;
        size_t length = 1234;
        int calls = attempted;

        key.encode_explicit = explicit_params;
        der = bee2_bign_asn1_encode_pkcs8_der(&key, &length);
        if (der != NULL || length != 0 || attempted != calls + 1) {
            fprintf(stderr, "BIGN PKCS#8 ownership rollback failed (%s)\n",
                    explicit_params ? "explicit" : "named");
            OPENSSL_free(der);
            return 1;
        }
        length = 1234;
        calls = pubkey_attempted;
        der = bee2_bign_asn1_encode_spki_der(&key, &length);
        if (der != NULL || length != 0 || pubkey_attempted != calls + 1) {
            fprintf(stderr, "BIGN SPKI ownership rollback failed (%s)\n",
                    explicit_params ? "explicit" : "named");
            OPENSSL_free(der);
            return 1;
        }
    }
    /* Drive each allocation failure in the provider's own serialization
     * paths. Leak and use-after-free detection is handled by ASan/LSan.
     * A successful fallback remains valid; a failed operation must not
     * return an allocated or partly written result.
     */
    transfer_failure = 0;
    for (explicit_params = 0; explicit_params < 2; ++explicit_params) {
        int format, attempt;
        key.encode_explicit = explicit_params;
        for (format = 0; format < 2; ++format) {
            int failures = 0, successes = 0;
            for (attempt = 1; attempt <= 64; ++attempt) {
                unsigned char *der;
                size_t length = 1234;

                fail_allocation_at = attempt;
                allocation_count = 0;
                der = format ? bee2_bign_asn1_encode_spki_der(&key, &length) :
                               bee2_bign_asn1_encode_pkcs8_der(&key, &length);
                fail_allocation_at = 0;
                if (!der) {
                    if (length != 0) {
                        fprintf(stderr, "ASN.1 output length changed on allocation failure\n");
                        return 1;
                    }
                    ++failures;
                } else {
                    if (length == 0) {
                        fprintf(stderr, "ASN.1 serialization returned an empty result\n");
                        OPENSSL_free(der);
                        return 1;
                    }
                    ++successes;
                    OPENSSL_free(der);
                }
            }
            if (!failures || !successes) {
                fprintf(stderr, "ASN.1 allocation failure matrix was not exercised\n");
                return 1;
            }
        }
    }
    OPENSSL_cleanse(&key, sizeof(key));
    return 0;
}
