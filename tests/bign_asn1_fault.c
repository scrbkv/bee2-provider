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
    return 0;
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
    return 0;
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
    OPENSSL_cleanse(&key, sizeof(key));
    return 0;
}
