#ifndef BEE2_PROVIDER_DER_FRAME_H
#define BEE2_PROVIDER_DER_FRAME_H

#include <limits.h>
#include <stddef.h>
#include <openssl/asn1.h>

#define BIGN_MAX_KEY_INPUT (1024u * 1024u)

/* Check the complete outer SEQUENCE before passing its body to ASN.1 decoders.
 * This is a framing check, not a full DER canonicality validator. */
int bign_der_sequence_body(const unsigned char *data, size_t length,
                           const unsigned char **body);

#endif
