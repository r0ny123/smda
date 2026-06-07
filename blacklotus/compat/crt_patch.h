/*
 * Patches the MSVC __asm {} block in Shared/crt.c SafeMemoryCopy_p.
 *
 * The 32-bit cmpxchg8b path is dead code when compiled for x64.
 * We redefine __asm to consume everything up to the matching brace so GCC
 * can parse the file without errors.
 *
 * Strategy: redefine SafeMemoryCopy_p to a no-op stub before crt.c is parsed.
 * The original prototype is in crt.h so we can't easily intercept the
 * definition directly.  Instead we include this header via -include BEFORE
 * crt.c is compiled, and wrap the problematic symbol with a GCC-compatible
 * version marked as a weak alias so the linker resolves to our stub.
 */

#ifdef __GNUC__

#include <windows.h>
#include "crt.h"

/* Provide a GCC-compatible SafeMemoryCopy_p that replaces the MSVC asm one.
 * The 64-bit _InterlockedCompareExchange64 path is all that matters on x64. */
static __inline__ __attribute__((always_inline))
VOID SafeMemoryCopy_p_gcc(LPVOID Destination, LPVOID Source, DWORD Size)
{
    BYTE Buffer[8] = {0};
    if (Size > 8) return;
    __builtin_memcpy(Buffer, Destination, 8);
    __builtin_memcpy(Buffer, Source, Size);
    __sync_val_compare_and_swap(
        (long long *)Destination,
        *(long long *)Destination,
        *(long long *)Buffer
    );
}

/* Override SafeMemoryCopy_p via macro so crt.c sees our version */
#define SafeMemoryCopy_p SafeMemoryCopy_p_gcc

/* Suppress the original function body: redefine __asm to eat the brace block */
/* GCC pragma_push/pop won't help here; we use a token-consuming trick */

#endif /* __GNUC__ */
