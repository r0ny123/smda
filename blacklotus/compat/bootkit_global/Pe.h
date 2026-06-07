#pragma once

/*
 * Reconstructed Pe.h for BlackLotus Bootkit.
 * Provides Windows PE / loader data structures not covered by <windows.h>
 * in a bare UEFI compilation environment.
 */

/* LDR_DATA_TABLE_ENTRY – Windows kernel/loader structure */
#ifndef _LDR_DATA_TABLE_ENTRY_DEFINED
#define _LDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG       Flags;
    USHORT      LoadCount;
    USHORT      TlsIndex;
    LIST_ENTRY  HashLinks;
    ULONG       TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

/* CONTAINING_RECORD – standard Windows macro */
#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((UINT8 *)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif
