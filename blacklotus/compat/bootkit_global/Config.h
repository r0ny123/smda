#pragma once

/*
 * Reconstructed Config.h for BlackLotus Bootkit.
 *
 * This structure is appended directly after the EfiMain shellcode blob at
 * offset +11 bytes from GetIp().  EfiMain reads it to locate the embedded
 * victim EFI binary's AddressOfNewExeHeader and AddressOfEntrypoint so it
 * can re-execute the original image after hooking ExitBootServices.
 */

typedef struct __attribute__((packed)) {
    ULONG   AddressOfNewExeHeader;   /* e_lfanew of the patched PE */
    ULONG   AddressOfEntrypoint;     /* RVA of the original entry point */
} CONFIG, *PCONFIG;
