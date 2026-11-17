/* Reject a Bee2 ABI whose state is larger than the provider's fixed store. */
#include "bee2_backend.h"

#include <stdio.h>

static int rejected_keep = -1;

/* Instrument the actual adapter check, preserving the real Bee2 keep() sizes
 * except for the deliberately oversized state under test. */
#define WRAP_KEEP(FUNCTION, INDEX)                                           \
    size_t __real_##FUNCTION(void);                                          \
    size_t __wrap_##FUNCTION(void)                                           \
    {                                                                        \
        return rejected_keep == (INDEX) ? BEE2_BACKEND_STATE_SIZE + 1u :     \
                                           __real_##FUNCTION();              \
    }

WRAP_KEEP(beltHash_keep, 0)
WRAP_KEEP(beltECB_keep, 1)
WRAP_KEEP(beltCBC_keep, 2)
WRAP_KEEP(beltCFB_keep, 3)
WRAP_KEEP(beltCTR_keep, 4)
WRAP_KEEP(beltBDE_keep, 5)
WRAP_KEEP(beltCHE_keep, 6)
WRAP_KEEP(beltDWP_keep, 7)
WRAP_KEEP(beltMAC_keep, 8)
WRAP_KEEP(beltHMAC_keep, 9)
WRAP_KEEP(beltSDE_keep, 10)
WRAP_KEEP(brngCTR_keep, 11)
WRAP_KEEP(brngHMAC_keep, 12)
WRAP_KEEP(bashHash_keep, 13)
WRAP_KEEP(bashPrg_keep, 14)

int main(void)
{
    int i;

    if (!bee2_backend_is_compatible()) {
        fprintf(stderr, "Bee2 backend is incompatible with the fixed state store\n");
        return 1;
    }
    for (i = 0; i < 15; ++i) {
        rejected_keep = i;
        if (bee2_backend_is_compatible()) {
            fprintf(stderr, "Oversized Bee2 state %d was accepted\n", i);
            return 1;
        }
    }
    return 0;
}
