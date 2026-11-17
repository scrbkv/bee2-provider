/* Inject failure at the ASN.1 ownership-transfer boundary.
 * Test that both named and explicit curve parameters are released safely.
 * The linker redirects PKCS8_pkey_set0 and X509_PUBKEY_set0_param in this executable.
 */
#include "bign_asn1.h"
#include "bign_stb_pbes2.h"

#include <openssl/crypto.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>
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


/* Fail selected OpenSSL operations at their provider-owned call sites.
 * Unlike global OpenSSL allocator hooks, linker wrapping does not interfere
 * with OpenSSL internals or the random generator's own allocations. */
enum asn1_fault_kind {
    ASN1_FAULT_NONE,
    ASN1_FAULT_RANDOM,
    ASN1_FAULT_PACK,
    ASN1_FAULT_ALGORITHM,
    ASN1_FAULT_INTEGER,
    ASN1_FAULT_OCTETS
};

static enum asn1_fault_kind asn1_fault;
static int asn1_fault_at, asn1_fault_calls;

static int should_fail_asn1(enum asn1_fault_kind kind)
{
    return asn1_fault == kind && ++asn1_fault_calls == asn1_fault_at;
}

int __real_RAND_priv_bytes_ex(OSSL_LIB_CTX *libctx, unsigned char *buf,
                              size_t count, unsigned int strength);
ASN1_STRING *__real_ASN1_item_pack(void *object, const ASN1_ITEM *item,
                                  ASN1_OCTET_STRING **output);
int __real_X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *oid,
                           int type, void *value);
int __real_ASN1_INTEGER_set(ASN1_INTEGER *integer, long value);
int __real_ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *string,
                                 const unsigned char *bytes, int length);

int __wrap_RAND_priv_bytes_ex(OSSL_LIB_CTX *libctx, unsigned char *buf,
                              size_t count, unsigned int strength)
{
    return should_fail_asn1(ASN1_FAULT_RANDOM) ? 0 :
           __real_RAND_priv_bytes_ex(libctx, buf, count, strength);
}

ASN1_STRING *__wrap_ASN1_item_pack(void *object, const ASN1_ITEM *item,
                                  ASN1_OCTET_STRING **output)
{
    return should_fail_asn1(ASN1_FAULT_PACK) ? NULL :
           __real_ASN1_item_pack(object, item, output);
}

int __wrap_X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *oid,
                           int type, void *value)
{
    return should_fail_asn1(ASN1_FAULT_ALGORITHM) ? 0 :
           __real_X509_ALGOR_set0(alg, oid, type, value);
}

int __wrap_ASN1_INTEGER_set(ASN1_INTEGER *integer, long value)
{
    return should_fail_asn1(ASN1_FAULT_INTEGER) ? 0 :
           __real_ASN1_INTEGER_set(integer, value);
}

int __wrap_ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *string,
                                 const unsigned char *bytes, int length)
{
    return should_fail_asn1(ASN1_FAULT_OCTETS) ? 0 :
           __real_ASN1_OCTET_STRING_set(string, bytes, length);
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

    /* Exercise STB encrypted PKCS#8 allocation rollback as well as plain
     * DER.  The injected failures affect provider-owned allocations only;
     * ASan/LSan check that no sensitive buffers survive any failed attempt. */
    {
        static const unsigned char password[] = "allocation-fault-test";
        unsigned char *plain = NULL;
        size_t plain_len = 0;
        int attempt, successes = 0, failures = 0;

        plain = bee2_bign_asn1_encode_pkcs8_der(&key, &plain_len);
        if (plain == NULL)
            return 1;
        for (attempt = 1; attempt <= 8; ++attempt) {
            unsigned char *der = NULL;
            const unsigned char *p;
            X509_SIG *info = NULL;
            size_t der_len = 1234;
            int valid;

            fail_allocation_at = attempt;
            allocation_count = 0;
            der = bee2_stb_pbes2_encrypt(
                plain, plain_len, password, sizeof(password) - 1,
                32, BEE2_STB_PBKDF2_MIN_ITER, BEE2_STB_PBKDF2_MIN_SALT,
                NULL, &der_len);
            fail_allocation_at = 0;
            valid = der == NULL ? der_len == 0 : der_len != 0;
            if (der != NULL) {
                p = der;
                info = d2i_X509_SIG(NULL, &p, (long)der_len);
                valid = valid && info != NULL &&
                        p == der + der_len && bee2_stb_pbes2_is_stb(info);
                ++successes;
            } else {
                ++failures;
            }
            X509_SIG_free(info);
            OPENSSL_clear_free(der, der_len);
            if (!valid) {
                fprintf(stderr, "STB PBES2 encryption allocation rollback failed\n");
                OPENSSL_clear_free(plain, plain_len);
                return 1;
            }
        }
        OPENSSL_clear_free(plain, plain_len);
        if (successes == 0 || failures == 0) {
            fprintf(stderr, "STB PBES2 allocation failures were not exercised\n");
            return 1;
        }
    }


    /* The failure may occur after the KWP payload was allocated or after a
     * portion of the ASN.1 tree was constructed.  Every failed call must
     * leave no ciphertext and reset the reported length. */
    {
        static const unsigned char password[] = "asn1-call-fault";
        unsigned char *plain = NULL;
        size_t plain_len = 0;
        enum asn1_fault_kind kind;

        key.encode_explicit = 0;
        plain = bee2_bign_asn1_encode_pkcs8_der(&key, &plain_len);
        if (plain == NULL)
            return 1;

        for (kind = ASN1_FAULT_RANDOM; kind <= ASN1_FAULT_OCTETS; ++kind) {
            int index, failures = 0, successes = 0;

            for (index = 1; index <= 6; ++index) {
                unsigned char *der;
                size_t length = 1234;
                int valid;

                asn1_fault = kind;
                asn1_fault_at = index;
                asn1_fault_calls = 0;
                der = bee2_stb_pbes2_encrypt(
                    plain, plain_len, password, sizeof(password) - 1,
                    32, BEE2_STB_PBKDF2_MIN_ITER, BEE2_STB_PBKDF2_MIN_SALT,
                    NULL, &length);
                asn1_fault = ASN1_FAULT_NONE;

                valid = der == NULL ? length == 0 : length != 0;
                if (der == NULL) {
                    ++failures;
                } else {
                    const unsigned char *p = der;
                    X509_SIG *info = d2i_X509_SIG(NULL, &p, (long)length);

                    valid = valid && info != NULL && p == der + length &&
                            bee2_stb_pbes2_is_stb(info);
                    X509_SIG_free(info);
                    ++successes;
                }
                OPENSSL_clear_free(der, length);
                if (!valid) {
                    fprintf(stderr, "STB PBES2 failed call rollback (%d/%d)\n",
                            (int)kind, index);
                    OPENSSL_clear_free(plain, plain_len);
                    return 1;
                }
            }
            if (failures == 0 || successes == 0) {
                fprintf(stderr, "ASN.1 call failure injection was not reached (%d)\n",
                        (int)kind);
                OPENSSL_clear_free(plain, plain_len);
                return 1;
            }
        }
        OPENSSL_clear_free(plain, plain_len);
    }

    OPENSSL_cleanse(&key, sizeof(key));
    return 0;
}
