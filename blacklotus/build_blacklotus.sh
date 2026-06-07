#!/usr/bin/env bash
# ============================================================================
# build_blacklotus.sh
#
# Cross-compiles BlackLotus Bot (Windows x64 PE) and Bootkit (UEFI x64 EFI)
# on Linux using MinGW-w64 and gnu-efi, then places all outputs in ./built/.
#
# Prerequisites (apt):
#   gcc-mingw-w64-x86-64-posix  binutils-mingw-w64-x86-64
#   nasm  gnu-efi
#
# Usage:
#   ./build_blacklotus.sh [--bl-path /path/to/BlackLotus]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BL_PATH="${BL_PATH:-/home/user/BlackLotus}"
OUT_DIR="${SCRIPT_DIR}/built"
BUILD_TMP=$(mktemp -d)
COMPAT="${SCRIPT_DIR}/compat"

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bl-path) BL_PATH="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

echo "[*] BlackLotus source: ${BL_PATH}"
echo "[*] Output directory:  ${OUT_DIR}"
echo "[*] Temp build dir:    ${BUILD_TMP}"

mkdir -p "${OUT_DIR}"

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
CC="x86_64-w64-mingw32-gcc-posix"
LD="x86_64-w64-mingw32-ld"
OBJCOPY="x86_64-w64-mingw32-objcopy"
WINDRES="x86_64-w64-mingw32-windres"

# MinGW system include + case-insensitive shims
SHIM_DIR="${BUILD_TMP}/incshim"
python3 - "${SHIM_DIR}" << 'PYEOF'
import os, re, sys
shim = sys.argv[1]
src  = "/usr/x86_64-w64-mingw32/include"
os.makedirs(shim, exist_ok=True)
for entry in os.listdir(src):
    lo = entry.lower()
    cap = entry[0].upper() + entry[1:] if entry else entry
    for variant in {entry, lo, cap}:
        tgt = os.path.join(shim, variant)
        if not os.path.exists(tgt):
            os.symlink(os.path.join(src, entry), tgt)
# Extra explicit case variants seen in the source tree
extras = {
    "Windows.h":  "windows.h",
    "NTSecAPI.h": "ntsecapi.h",
    "TlHelp32.h": "tlhelp32.h",
    "ShlObj.h":   "shlobj.h",
    "Wininet.h":  "wininet.h",
}
for target_name, real_name in extras.items():
    tgt = os.path.join(shim, target_name)
    if not os.path.exists(tgt):
        real = os.path.join(src, real_name)
        if os.path.exists(real):
            os.symlink(real, tgt)
PYEOF

SYS_INC="/usr/x86_64-w64-mingw32/include"
COMMON_CFLAGS=(
    -include "${COMPAT}/mingw_compat.h"
    -I"${SHIM_DIR}"
    -I"${SYS_INC}"
    -D_WIN64
    -DWIN32_LEAN_AND_MEAN
    -D_WIN32_WINNT=0x0601
    -DWIN64
    -m64
    -w
    -nostdlib
    -fno-stack-protector
    -fno-exceptions
    -ffunction-sections
    -fdata-sections
    -Os
)

# ---------------------------------------------------------------------------
# Patch Shared/crt.c – replace MSVC __asm {} block (x86-32 dead code on x64)
# ---------------------------------------------------------------------------
echo "[*] Patching Shared/crt.c for GCC compatibility…"
PATCHED_CRT="${BUILD_TMP}/crt_patched.c"
python3 - "${BL_PATH}/src/Shared/crt.c" "${PATCHED_CRT}" << 'PYEOF'
import sys, re

src = open(sys.argv[1]).read()

# The MSVC __asm { ... } block in SafeMemoryCopy_p is dead code on x64 –
# the Is64Bit() branch above it always returns before reaching it.
# Replace with an ifdef guard that GCC can parse without __asm {} support.
asm_pattern = re.compile(r'\s*__asm\s*\{[^}]*\}', re.DOTALL)

# Write the replacement directly to avoid any escaping issues
stub = '\n#ifdef _MSC_VER\n\t__asm { /* x86-32 cmpxchg8b – MSVC only */ }\n#endif\n'

patched, n = asm_pattern.subn(stub, src, count=1)
if n == 0:
    print("[warn] __asm block not found – crt.c may have changed")
    patched = src

open(sys.argv[2], 'w').write(patched)
print(f"[*] Patched {n} __asm block(s) in crt.c")
PYEOF

# ---------------------------------------------------------------------------
# Patch Shared/api.c – replace x86 _asm {} PEB walk with x64 GCC equivalent
# ---------------------------------------------------------------------------
echo "[*] Patching Shared/api.c for GCC/x64 compatibility…"
PATCHED_API="${BUILD_TMP}/api_patched.c"
python3 - "${BL_PATH}/src/Shared/api.c" "${PATCHED_API}" << 'PYEOF'
import sys, re
src = open(sys.argv[1]).read()
# Replace the _asm { MOV EAX, FS:[...] } block with x64 GCC PEB walk
old = re.compile(r'\s*_asm\s*\{[^}]*\}', re.DOTALL)
new_code = (
    '\n#ifdef __GNUC__\n'
    '    /* x64: PEB@GS:0x60, Ldr@PEB+0x18, InLoadOrderModuleList.Flink@Ldr+0x10 */\n'
    '    { ULONG_PTR _peb = __readgsqword(0x60);\n'
    '      ULONG_PTR _ldr = *(ULONG_PTR*)(_peb + 0x18);\n'
    '      Module = (LDR_MODULE*)(*(ULONG_PTR*)(_ldr + 0x10)); }\n'
    '#else\n'
    '    _asm { MOV EAX, FS:[0x18]; MOV EAX, [EAX+0x30]; MOV EAX, [EAX+0x0C]; MOV EAX, [EAX+0x0C]; MOV Module, EAX; }\n'
    '#endif\n'
)
patched, n = old.subn(new_code, src, count=1)
if n == 0:
    print('[warn] api.c _asm block not found')
    patched = src
open(sys.argv[2], 'w').write(patched)
print(f'[*] Patched {n} _asm block(s) in api.c')
PYEOF

# ---------------------------------------------------------------------------
# Patch Shared/utils.h – fix GCC VA_ARGS trailing-comma issue in DebugPrint
# ---------------------------------------------------------------------------
echo "[*] Patching Shared/utils.h for GCC VA_ARGS compatibility…"
PATCHED_UTILS_DIR="${BUILD_TMP}/shared_patched"
mkdir -p "${PATCHED_UTILS_DIR}"
sed 's/__VA_ARGS__)/##__VA_ARGS__)/g' \
    "${BL_PATH}/src/Shared/utils.h" > "${PATCHED_UTILS_DIR}/utils.h"

# ---------------------------------------------------------------------------
# Patch Bot/shared.c – fix Windows backslash include paths + use patched crt.c
# ---------------------------------------------------------------------------
echo "[*] Patching Bot/shared.c include paths for Linux…"
PATCHED_SHARED="${BUILD_TMP}/shared_unity.c"
# Replace Windows-style "..\Shared\file.c" paths with Linux-relative paths,
# and substitute the patched crt.c for the original crt.c
python3 - "${BL_PATH}/src/Bot/shared.c" "${PATCHED_SHARED}" "${PATCHED_CRT}" "${PATCHED_API}" "${BL_PATH}/src/Shared" << 'PYEOF'
import sys, re, os
src, dst, patched_crt, patched_api, shared_dir = sys.argv[1:]
content = open(src).read()
def fix_include(m):
    path = m.group(1).replace('\\', '/').replace('../Shared/', '')
    name = os.path.basename(path)
    if name == 'crt.c':
        return f'#include "{patched_crt}"'
    if name == 'api.c':
        return f'#include "{patched_api}"'
    return f'#include "{shared_dir}/{name}"'
content = re.sub(r'#include\s+"([^"]+\\[^"]+\.c)"', fix_include, content)
content = re.sub(r'#pragma\s+function\s*\([^)]+\)', '', content)
open(dst, 'w').write(content)
PYEOF

# ---------------------------------------------------------------------------
# Build Bot.exe (Windows x64 PE, entry=EntryPoint, no CRT)
# ---------------------------------------------------------------------------
echo ""
echo "[*] ===== Building Bot.exe ====="
BOT_SRC="${BL_PATH}/src/Bot"
SHARED_SRC="${BL_PATH}/src/Shared"

BOT_CFLAGS=(
    -I"${BOT_SRC}"
    -I"${PATCHED_UTILS_DIR}"    # patched utils.h must come first
    -I"${SHARED_SRC}"
    "${COMMON_CFLAGS[@]}"
)

BOT_C_FILES=(
    # Bot-specific files
    "${BOT_SRC}/antidebug.c"
    "${BOT_SRC}/injection.c"
    "${BOT_SRC}/install.c"
    "${BOT_SRC}/nzt.c"
    "${BOT_SRC}/command.c"
    "${BOT_SRC}/globals.c"
    "${BOT_SRC}/http.c"
    "${BOT_SRC}/report.c"
    # Patched unity file (includes all Shared/*.c with fixed paths)
    "${PATCHED_SHARED}"
)

BOT_OBJS=()
for src in "${BOT_C_FILES[@]}"; do
    base=$(basename "${src}" .c)
    obj="${BUILD_TMP}/bot_${base}.o"
    echo "  CC ${src##*/}"
    ${CC} "${BOT_CFLAGS[@]}" -c "${src}" -o "${obj}" || {
        echo "[!] Failed to compile ${src}" >&2
        exit 1
    }
    BOT_OBJS+=("${obj}")
done

# Stub for BookitInitialize (part of the UEFI kit, not included in public repo)
cat > "${BUILD_TMP}/bookit_stub.c" << 'CSRC'
int BookitInitialize(void) { return 0; }
CSRC
${CC} "${BOT_CFLAGS[@]}" -c "${BUILD_TMP}/bookit_stub.c" -o "${BUILD_TMP}/bot_bookit_stub.o"
BOT_OBJS+=("${BUILD_TMP}/bot_bookit_stub.o")

MINGWEX_LIB="/usr/x86_64-w64-mingw32/lib/libmingwex.a"
LIBGCC=$(${CC} -print-libgcc-file-name 2>/dev/null)

echo "  LINK Bot.exe"
${CC} "${BOT_CFLAGS[@]}" \
    -e EntryPoint \
    -Wl,--subsystem,windows \
    -Wl,--gc-sections \
    -Wl,-Map,"${BUILD_TMP}/Bot.map" \
    "${BOT_OBJS[@]}" \
    "${MINGWEX_LIB}" "${LIBGCC}" \
    -o "${OUT_DIR}/Bot.exe"

echo "[+] Bot.exe -> ${OUT_DIR}/Bot.exe"
file "${OUT_DIR}/Bot.exe"

# ---------------------------------------------------------------------------
# Build Encryptor.exe (single source file, simpler)
# ---------------------------------------------------------------------------
echo ""
echo "[*] ===== Building Encryptor.exe ====="
ENC_SRC="${BL_PATH}/src/Encryptor/Encryptor.c"

if [[ -f "${ENC_SRC}" ]]; then
    # Patch Encryptor.c Windows-style include paths
    PATCHED_ENC="${BUILD_TMP}/Encryptor_patched.c"
    python3 - "${ENC_SRC}" "${PATCHED_ENC}" "${PATCHED_CRT}" "${PATCHED_API}" "${SHARED_SRC}" << 'PYEOF'
import sys, re, os
src, dst, pcrt, papi, sdir = sys.argv[1:]
content = open(src).read()
def fix_inc(m):
    name = os.path.basename(m.group(1).replace('\\', '/'))
    if name == 'crt.c': return f'#include "{pcrt}"'
    if name == 'api.c': return f'#include "{papi}"'
    return f'#include "{sdir}/{name}"'
content = re.sub(r'#include\s+"([^"]+\\[^"]+\.c)"', fix_inc, content)
open(dst, 'w').write(content)
PYEOF
    # Encryptor uses stdio (printf/strcmp) so link WITH standard CRT
    ${CC} \
        -I"${SHARED_SRC}" \
        -I"${PATCHED_UTILS_DIR}" \
        -I"${SHIM_DIR}" -I"${SYS_INC}" \
        -include "${COMPAT}/mingw_compat.h" \
        -D_WIN64 -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601 \
        -m64 -Os -w -fno-stack-protector -fno-exceptions \
        -Wl,--subsystem,console \
        "${PATCHED_ENC}" \
        -o "${OUT_DIR}/Encryptor.exe" 2>&1 || echo "[warn] Encryptor.exe build failed – skipping"
    [[ -f "${OUT_DIR}/Encryptor.exe" ]] && echo "[+] Encryptor.exe -> ${OUT_DIR}/Encryptor.exe"
fi

# ---------------------------------------------------------------------------
# Build Bootkit.efi (UEFI x64 EFI binary)
# ---------------------------------------------------------------------------
echo ""
echo "[*] ===== Building Bootkit.efi ====="
BK_SRC="${BL_PATH}/src/Bootkit"

# gnu-efi paths
GNUEFI_INC="/usr/include/efi"
GNUEFI_LIB="/usr/lib/x86_64-linux-gnu"
[[ -d "${GNUEFI_LIB}/gnuefi" ]] && GNUEFI_LIB="${GNUEFI_LIB}/gnuefi"
# Fallback
[[ ! -f "${GNUEFI_LIB}/crt0-efi-x86_64.o" ]] && GNUEFI_LIB="/usr/lib"

BK_CFLAGS=(
    -I"${BK_SRC}"
    -I"${COMPAT}"                   # provides global/Labels.h etc (via compat/global/ symlink)
    -include "${COMPAT}/mingw_compat.h"
    # Redirect "gnu-efi/efi.h" to system path
    -I"${COMPAT}/gnuefi_shim"
    -I"${GNUEFI_INC}"
    -I"${GNUEFI_INC}/x86_64"
    -I"${SHIM_DIR}"
    -I"${SYS_INC}"
    -DEFI_FUNCTION_WRAPPER
    -DGNU_EFI_USE_MS_ABI
    -D_WIN64
    -DWIN32_LEAN_AND_MEAN
    -m64
    -mno-red-zone
    -fpic
    -fno-stack-protector
    -fno-exceptions
    -fshort-wchar
    -ffunction-sections
    -fdata-sections
    -Os
    -w
    -nostdlib
    -ffreestanding
)

# Create the gnu-efi shim so #include "gnu-efi/efi.h" resolves
mkdir -p "${COMPAT}/gnuefi_shim/gnu-efi"
[[ ! -f "${COMPAT}/gnuefi_shim/gnu-efi/efi.h" ]] && \
    ln -sf "${GNUEFI_INC}/efi.h" "${COMPAT}/gnuefi_shim/gnu-efi/efi.h"

# Define global instances – avoid EFI/Windows header conflict by inlining types
cat > "${BUILD_TMP}/bootkit_globals.c" << 'CSRC'
/* Standalone definitions to avoid EFI vs Windows header type conflicts */
#include <stdint.h>
typedef void*    EFI_HANDLE;
typedef uint64_t UINTN;
typedef uint64_t EFI_STATUS;
#define EFIAPI  __attribute__((ms_abi))
typedef EFI_STATUS (EFIAPI *EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle, UINTN MapKey);

#pragma pack(push, 1)
typedef struct {
    EFI_EXIT_BOOT_SERVICES  ExitBootServices;
    void*                   OslArchTransferToKernelGate;
    void*                   KernelBuf;
    unsigned int            KernelLen;
    void*                   KernelBase;
    void*                   TgtDrvImgSect;
    void*                   TgtDrvImgBase;
    void*                   TgtDrvLdrEntry;
    unsigned int            TgtDrvAddressOfEntrypoint;
} EFTBL;
#pragma pack(pop)

EFTBL EfTbl;
unsigned char EfClg[32];
unsigned char KmEnt[1];
CSRC

BK_C_FILES=(
    "${BUILD_TMP}/bootkit_globals.c"
    "${BK_SRC}/EfiMain.c"
    "${BK_SRC}/ExitBootServices.c"
    "${BK_SRC}/OslArchTransferToKernel.c"
    "${BK_SRC}/DrvMain.c"
)

BK_OBJS=()
for src in "${BK_C_FILES[@]}"; do
    base=$(basename "${src}" .c)
    obj="${BUILD_TMP}/bk_${base}.o"
    echo "  CC ${src##*/}"
    x86_64-w64-mingw32-gcc-posix "${BK_CFLAGS[@]}" -c "${src}" -o "${obj}" 2>&1 || {
        echo "[warn] Bootkit ${src##*/} compilation failed – see errors above"
        continue
    }
    BK_OBJS+=("${obj}")
done

if [[ ${#BK_OBJS[@]} -gt 0 ]]; then
    echo "  LINK Bootkit.efi"
    x86_64-w64-mingw32-gcc-posix "${BK_CFLAGS[@]}" \
        -e EfiMain \
        -Wl,--subsystem,10 \
        -Wl,--gc-sections \
        -Wl,-Map,"${BUILD_TMP}/Bootkit.map" \
        "${BK_OBJS[@]}" \
        -o "${OUT_DIR}/Bootkit.efi" 2>/dev/null || \
    echo "[warn] Bootkit final link failed – object files still available in ${BUILD_TMP}/"
fi

[[ -f "${OUT_DIR}/Bootkit.efi" ]] && {
    echo "[+] Bootkit.efi -> ${OUT_DIR}/Bootkit.efi"
    file "${OUT_DIR}/Bootkit.efi"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "[+] ===== Build complete ====="
echo "    Output files:"
ls -lh "${OUT_DIR}/"
echo ""
echo "    Next: run  python3 smda_process.py  to generate .smda reports"
echo "    Then: run  python3 mcrit_upload.py  to upload to MCRIT"
