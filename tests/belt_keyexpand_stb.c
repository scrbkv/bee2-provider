/*
 * STB 34.101.31-2020, 8.1.2 and Table A.27.
 * The normative expected values below do not come from Bee2.
 */
#include "bee2_backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char key[32] = {
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
    0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37,
    0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6
};

static const unsigned char expanded128[32] = {
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
    0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
    0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47
};

static const unsigned char expanded192[32] = {
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
    0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37,
    0x4B, 0x09, 0xA1, 0x7E, 0x84, 0x50, 0xBF, 0x66
};

/* Independent, bytewise transcription of 8.1.2: words K_i are 4 bytes. */
static void expand_from_standard(unsigned char dst[32],
                                 const unsigned char *src, size_t len) {
    size_t i;

    memcpy(dst, src, len);
    if (len == 16) {
        memcpy(dst + 16, dst, 16);
    } else if (len == 24) {
        for (i = 0; i < 4; ++i) {
            dst[24 + i] = (unsigned char)(src[i] ^ src[4 + i] ^ src[8 + i]);
            dst[28 + i] = (unsigned char)(src[12 + i] ^ src[16 + i] ^ src[20 + i]);
        }
    }
}

static int check(const unsigned char *source, size_t len,
                 const unsigned char *reference, const char *label) {
    unsigned char result[32];
    unsigned char in_place[32];
    int ok = 1;

    bee2_belt_expand_key(source, len, result);
    if (memcmp(result, reference, sizeof(result)) != 0) {
        fprintf(stderr, "[FAIL] %s: provider key expansion differs from STB\n", label);
        ok = 0;
    }
    memset(in_place, 0, sizeof(in_place));
    memcpy(in_place, source, len);
    bee2_belt_expand_key(in_place, len, in_place);
    if (memcmp(in_place, reference, sizeof(in_place)) != 0) {
        fprintf(stderr, "[FAIL] %s: in-place key expansion differs from STB\n", label);
        ok = 0;
    }
    OPENSSL_cleanse(result, sizeof(result));
    OPENSSL_cleanse(in_place, sizeof(in_place));
    return ok;
}


int main(void) {
    unsigned char reference[32];
    unsigned char input[32];
    const unsigned char *known[] = {expanded128, expanded192, key};
    const size_t lengths[] = {16, 24, 32};
    size_t i, j, sample;
    int ok = 1;

    for (i = 0; i < 3; ++i) {
        expand_from_standard(reference, key, lengths[i]);
        if (memcmp(reference, known[i], sizeof(reference)) != 0) {
            fprintf(stderr, "[FAIL] transcription of STB A.27 (%zu-bit)\n",
                    lengths[i] * 8);
            ok = 0;
        }
        if (!check(key, lengths[i], known[i], "A.27 expansion"))
            ok = 0;
    }
    /* Additional independently evaluated 8.1.2 cases beyond Table A.27. */
    for (sample = 0; sample < 32; ++sample) {
        for (j = 0; j < sizeof(input); ++j)
            input[j] = (unsigned char)(sample * 37u + j * 13u + (sample ^ j));
        for (i = 0; i < 3; ++i) {
            expand_from_standard(reference, input, lengths[i]);
            if (!check(input, lengths[i], reference, "8.1.2 varied key"))
                ok = 0;
        }
    }
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(reference, sizeof(reference));
    if (ok)
        puts("[OK] STB 34.101.31-2020 8.1.2 / A.27 (128, 192, 256)");
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
