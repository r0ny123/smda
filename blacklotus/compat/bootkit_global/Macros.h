#pragma once

/*
 * Reconstructed Macros.h for BlackLotus Bootkit.
 * These are standard shellcode/implant helper macros.
 */

/* Pointer casting helpers */
#define C_PTR(x)    ((PVOID)(ULONG_PTR)(x))
#define U_PTR(x)    ((ULONG_PTR)(x))
#define B_PTR(x)    ((PBYTE)(x))

/* Place function/data into a named PE section (for position-independent ordering) */
#ifdef __GNUC__
#define D_SEC(x)    __attribute__((section(".text$" #x)))
#else
#define D_SEC(x)    __declspec(allocate(".text$" #x))
#endif

/* Declare a typed function-pointer field in a struct */
#ifdef __GNUC__
#define D_API(fn)   __typeof__(fn) * fn
#else
#define D_API(fn)   fn##_t * fn
#endif

/*
 * G_PTR – get the runtime (PIC) address of a global symbol.
 * In a proper reflective loader this would use a call+pop to obtain the
 * image base offset; for our compile-only purpose &sym is sufficient.
 */
#define G_PTR(sym)  (&(sym))

/* Get current instruction pointer via __builtin_return_address */
static __inline__ PVOID GetIp(void) {
    return __builtin_extract_return_addr(__builtin_return_address(0));
}
