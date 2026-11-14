#ifndef BEE2_PROVIDER_DER_FRAME_H
#define BEE2_PROVIDER_DER_FRAME_H

#include <limits.h>
#include <stddef.h>
#include <openssl/asn1.h>

#define BIGN_MAX_KEY_INPUT (1024u * 1024u)

/* Check the complete outer SEQUENCE before passing its body to ASN.1 decoders.
 * This is a framing check, not a full DER canonicality validator. */
static int bign_der_sequence_body(const unsigned char *data, size_t length,
                                  const unsigned char **body)
{
    const unsigned char *p = data;
    long body_length = 0;
    int tag = 0;
    int xclass = 0;
    int status;

    if (data == NULL || body == NULL || length == 0 ||
        length > BIGN_MAX_KEY_INPUT || length > LONG_MAX)
        return 0;

    status = ASN1_get_object(&p, &body_length, &tag, &xclass, (long)length);
    if ((status & 0x81) != 0 || (status & V_ASN1_CONSTRUCTED) == 0 ||
        tag != V_ASN1_SEQUENCE || xclass != V_ASN1_UNIVERSAL ||
        body_length < 0 || (size_t)body_length != (size_t)(data + length - p))
        return 0;

    *body = p;
    return 1;
}

#endif
