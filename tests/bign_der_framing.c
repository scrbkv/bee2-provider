/* Test the exact DER framing helper used by the BIGN key decoder.
 * The openssl pkey CLI intentionally accepts one DER object followed by data. */
#include "../src/bign_der_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(const char *label, const unsigned char *der, size_t size,
                 int should_accept)
{
    const unsigned char *body = NULL;
    int accepted = bign_der_sequence_body(der, size, &body);

    if (accepted != should_accept ||
        (accepted && (body == NULL || body < der || body > der + size))) {
        fprintf(stderr, "Unexpected DER framing result: %s\n", label);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const unsigned char valid_empty[] = {0x30, 0x00};
    static const unsigned char valid_nested[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    static const unsigned char trailing[] = {0x30, 0x00, 0x00};
    static const unsigned char short_body[] = {0x30, 0x03, 0x02, 0x01};
    static const unsigned char indefinite[] = {0x30, 0x80, 0x00, 0x00};
    static const unsigned char wrong_tag[] = {0x04, 0x00};
    static const unsigned char primitive_seq[] = {0x10, 0x00};
    unsigned char *oversized;
    int ok = 1;

    ok &= check("empty", valid_empty, sizeof(valid_empty), 1);
    ok &= check("nested", valid_nested, sizeof(valid_nested), 1);
    ok &= check("trailing", trailing, sizeof(trailing), 0);
    ok &= check("truncated", short_body, sizeof(short_body), 0);
    ok &= check("indefinite", indefinite, sizeof(indefinite), 0);
    ok &= check("wrong tag", wrong_tag, sizeof(wrong_tag), 0);
    ok &= check("primitive sequence", primitive_seq, sizeof(primitive_seq), 0);
    ok &= check("no data", NULL, 0, 0);

    oversized = malloc(BIGN_MAX_KEY_INPUT + 1u);
    if (oversized == NULL) {
        fprintf(stderr, "Unable to allocate oversized DER test buffer\n");
        return 1;
    }
    memset(oversized, 0, BIGN_MAX_KEY_INPUT + 1u);
    oversized[0] = 0x30;
    oversized[1] = 0x00;
    ok &= check("oversized", oversized, BIGN_MAX_KEY_INPUT + 1u, 0);
    free(oversized);

    return ok ? 0 : 1;
}
