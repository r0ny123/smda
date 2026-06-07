/*
 * MinGW cross-compilation compatibility header for BlackLotus.
 * Injected via -include to silence MSVC-isms in the source tree.
 */

#ifndef _MINGW_COMPAT_H_
#define _MINGW_COMPAT_H_

/* Silence MSVC pragmas that GCC doesn't understand */
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#endif

#define __pragma(x)

/* SAL (Source Annotation Language) macros – MSVC-only, define as empty */
#define __out_data_source(kind)
#define __in_bcount_opt(size)
#define __in_ecount_opt(size)
#define __in_bcount(size)
#define __in_ecount(size)
#define __out_bcount_opt(size)
#define __out_bcount(size)
#define __out_ecount(size)
#define __out_ecount_opt(size)
#define __in_opt
#define __out_opt
#define __inout_opt
#define __in
#define __out
#define __inout
#define __deref_out_opt

/* _byteswap_* are provided by MinGW's <intrin.h> – do NOT redefine them here.
 * Defining them as macros before intrin.h is parsed causes parse errors when
 * intrin.h later tries to declare them as inline functions. */

/* Guard redefinition of OBJECT_ATTRIBUTES that MinGW headers already provide */
#define _OBJECT_ATTRIBUTES_DEFINED_GUARD_

/* Prevent gnu-efi from redefining types already defined by <windows.h>.
 * gnu-efi/efi.h conditionally defines CHAR/VOID etc. based on these guards. */
#ifdef __EFI_H__
#undef CHAR
#endif

/* MSVC __cdecl / __stdcall are already handled by MinGW, but ensure WINAPI exists */
#ifndef WINAPI
#define WINAPI __stdcall
#endif
#ifndef NTAPI
#define NTAPI  __stdcall
#endif

/* MSVC-style inline assembly is NOT supported in GCC – the SafeMemoryCopy_p
 * x86 path in crt.c is only reached when Is64Bit() == FALSE, which cannot
 * happen in an x64 build, so we simply eliminate the unreachable block. */
#ifdef __GNUC__
#define MSVC_ASM_BLOCK_BEGIN  if (0) {
#define MSVC_ASM_BLOCK_END    }
#endif

#endif /* _MINGW_COMPAT_H_ */
