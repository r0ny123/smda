"""Ground-truth extraction for corpora this repository builds itself.

Every built corpus derives its function starts from what the *unstripped*
artifact declares — a symbol table, a pclntab, or .NET metadata — and the
benchmark then measures the stripped twin. Stripping does not move code, so the
two share an address space; the truth is therefore compiler-emitted rather than
disassembler-derived, which is the property no public PE corpus of this shape
offers.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Dict, List, Optional, Set

import lief

#: symbols a linker emits that name a boundary or a data object rather than a
#: function body; scoring against them would measure the marker, not the code
NON_FUNCTION_SYMBOL_NAMES = {
    "$a",
    "$d",
    "$t",
    "$x",
    "_edata",
    "_end",
    "_etext",
    "__bss_start",
}


def _executableRanges(binary) -> List[tuple]:
    ranges = []
    for section in binary.sections:
        try:
            characteristics = section.characteristics
        except (AttributeError, TypeError):
            characteristics = None
        is_executable = False
        if characteristics is not None:
            is_executable = bool(characteristics & 0x20000000)
        else:
            flags = getattr(section, "flags", 0)
            is_executable = bool(flags & 0x4)
        if is_executable and section.size:
            ranges.append((section.virtual_address, section.virtual_address + section.size))
    return ranges


def _inExecutableRange(address: int, ranges: List[tuple]) -> bool:
    return any(start <= address < end for start, end in ranges)


def elfFunctionStarts(path: str) -> Dict[str, object]:
    """STT_FUNC symbol addresses from an unstripped ELF, plus its PLT stubs.

    PLT entries are code and every disassembler in this comparison reports them,
    so the dissertation's rule — count the jmp stubs as functions — applies here
    too; they are returned separately so a caller can score either convention.
    """
    binary = lief.ELF.parse(path)
    if binary is None:
        raise RuntimeError(f"not an ELF: {path}")
    image_base = 0
    ranges = _executableRanges(binary)
    starts: Set[int] = set()
    for symbol in binary.symtab_symbols:
        if symbol.type != lief.ELF.Symbol.TYPE.FUNC:
            continue
        if not symbol.value or symbol.name in NON_FUNCTION_SYMBOL_NAMES:
            continue
        # SHN_UNDEF names an import, which has no body in this image
        if symbol.shndx == 0:
            continue
        address = symbol.value & ~1 if binary.header.machine_type == lief.ELF.ARCH.ARM else symbol.value
        if ranges and not _inExecutableRange(address, ranges):
            continue
        starts.add(address + image_base)
    plt: Set[int] = set()
    for section in binary.sections:
        if section.name in (".plt", ".plt.sec", ".plt.got") and section.entry_size:
            for offset in range(0, section.size, section.entry_size):
                plt.add(section.virtual_address + offset)
    return {
        "starts": sorted(starts),
        "plt": sorted(plt),
        "bitness": 64 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32,
        "entrypoint": binary.header.entrypoint,
        "source": "elf symtab STT_FUNC",
    }


def peFunctionStarts(path: str) -> Dict[str, object]:
    """Function starts from a PE's COFF symbol table (what MinGW emits unstripped)."""
    binary = lief.PE.parse(path)
    if binary is None:
        raise RuntimeError(f"not a PE: {path}")
    image_base = binary.optional_header.imagebase
    sections = list(binary.sections)
    ranges = _executableRanges(binary)
    starts: Set[int] = set()
    for symbol in binary.symbols:
        if not symbol.is_function or symbol.is_undefined:
            continue
        # section_idx is 1-based; 0 and the negative sentinels name no section
        index = symbol.section_idx - 1
        if index < 0 or index >= len(sections):
            continue
        relative = sections[index].virtual_address + symbol.value
        if ranges and not _inExecutableRange(relative, ranges):
            continue
        starts.add(image_base + relative)
    return {
        "starts": sorted(starts),
        "plt": [],
        "bitness": 64 if binary.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 32,
        "entrypoint": image_base + binary.optional_header.addressof_entrypoint,
        "image_base": image_base,
        "source": "pe coff symbol table",
    }


def goFunctionStarts(path: str, go_binary: str = "go") -> Dict[str, object]:
    """Text symbol addresses as Go's own `nm` reads them out of the pclntab."""
    completed = subprocess.run([go_binary, "tool", "nm", path], capture_output=True, text=True, timeout=600)
    if completed.returncode != 0:
        raise RuntimeError(f"go tool nm failed on {path}: {completed.stderr[-400:]}")
    starts: Set[int] = set()
    names = 0
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        address, kind, name = fields[0], fields[1], fields[2]
        if kind not in ("T", "t"):
            continue
        if name in ("runtime.text", "runtime.etext", "runtime.enoptrbss", "runtime.end"):
            continue
        try:
            starts.add(int(address, 16))
        except ValueError:
            continue
        names += 1
    return {"starts": sorted(starts), "plt": [], "symbols_seen": names, "source": "go tool nm (pclntab)"}


def writeTruth(
    truth_dir: str,
    name: str,
    starts: List[int],
    meta: Dict[str, object],
) -> str:
    os.makedirs(truth_dir, exist_ok=True)
    path = os.path.join(truth_dir, name + ".json")
    with open(path, "w", encoding="utf-8") as truth_file:
        json.dump({"starts": sorted(set(starts)), **meta}, truth_file, indent=1, sort_keys=True)
    return path


def stripCopy(source: str, destination: str, strip_binary: str = "strip") -> Optional[str]:
    """Copy `source` to `destination` and strip it; None when the strip fails."""
    with open(source, "rb") as reader, open(destination, "wb") as writer:
        writer.write(reader.read())
    completed = subprocess.run([strip_binary, destination], capture_output=True, text=True)
    if completed.returncode != 0:
        return None
    return destination
