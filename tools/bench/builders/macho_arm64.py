"""Materialize the ARM64 Mach-O corpus the repository already carries.

`tests/aarch64_macho_corpus` holds real ARM64 Mach-O malware, obfuscated on disk.
Each one declares its own function starts in `LC_FUNCTION_STARTS`, which the linker
writes and no disassembler contributes to, so the corpus arrives with ground truth
attached and needs no download.

This is the only AArch64 accuracy corpus available here: the frozen corpora are
x86 and x86-64 only, and the Go family's ARM64 cells share one compiler. A second
population matters for any AArch64 claim, and this one is a different compiler, a
different container and a different kind of program.

The decoded binaries are written under the ground-truth root, never back into the
repository.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Tuple

import lief

from bench.builders.truth import writeTruth

#: the repository directory the fixtures live in, relative to the repository root
FIXTURE_ROOT = os.path.join("tests", "aarch64_macho_corpus")

#: LC_FUNCTION_STARTS entries are file offsets from the image base
FUNCTION_STARTS_COMMAND = "FunctionStarts"


def decode(data: bytes) -> bytes:
    """Undo the corpus' on-disk obfuscation, which the bundled manifest documents."""
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _functionStartsCommand(binary) -> Optional[object]:
    for command in binary.commands:
        if FUNCTION_STARTS_COMMAND in type(command).__name__:
            return command
    return None


def machoFunctionStarts(binary) -> List[int]:
    """Absolute function starts a Mach-O declares, or an empty list when it declares none.

    A stripped or hand-built image can carry the load command with nothing in it, and
    an empty truth set is not a corpus cell -- it would score every detection as a
    false positive and read as a catastrophic result rather than as missing truth.
    """
    command = _functionStartsCommand(binary)
    offsets = list(getattr(command, "functions", []) or []) if command is not None else []
    return sorted({binary.imagebase + offset for offset in offsets})


def _sectionExtent(binary, name: str) -> Optional[Tuple[int, int]]:
    for section in binary.sections:
        if section.name == name:
            return section.virtual_address, section.virtual_address + section.size
    return None


def symbolStubStarts(binary) -> List[int]:
    """Every entry of a section the image declares to be symbol stubs.

    A stub is an import trampoline: code, called from other code, and reported by
    every engine in this comparison, so it is truth here for the same reason an ELF
    PLT entry is. `LC_FUNCTION_STARTS` does not name them, and the section itself
    does -- `S_SYMBOL_STUBS` carries the stride in its `reserved2` field, the direct
    counterpart of an ELF section's entry size.
    """
    starts: List[int] = []
    for section in binary.sections:
        if "SYMBOL_STUBS" not in str(section.type):
            continue
        stride = section.reserved2
        if stride <= 0:
            continue
        for offset in range(0, section.size, stride):
            starts.append(section.virtual_address + offset)
    return sorted(starts)


def scoredRanges(binary) -> List[Tuple[int, int]]:
    """The address ranges this corpus' oracles actually speak for.

    `LC_FUNCTION_STARTS` covers `__text` and the stub sections declare their own
    entries. Nothing here declares the contents of `__objc_stubs` or `__stub_helper`:
    an ObjC message stub is as much a function as an import stub, but no oracle in the
    image names one, and its size is not declared anywhere. Scoring those ranges would
    charge the engine for what the corpus cannot label, so they are left out and what
    lands in them is counted and reported instead of judged.
    """
    ranges = []
    text = _sectionExtent(binary, "__text")
    if text is not None:
        ranges.append(text)
    for section in binary.sections:
        if "SYMBOL_STUBS" in str(section.type) and section.reserved2 > 0:
            ranges.append((section.virtual_address, section.virtual_address + section.size))
    return sorted(ranges)


def buildMachoArm64(out_dir: str, repository_root: str) -> Dict[str, object]:
    fixture_root = os.path.join(repository_root, FIXTURE_ROOT)
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(binary_dir, exist_ok=True)
    cells: List[Dict[str, object]] = []
    for directory, _subdirs, files in sorted(os.walk(fixture_root)):
        for filename in sorted(files):
            if not filename.endswith(".xored"):
                continue
            source = os.path.join(directory, filename)
            name = filename[: -len(".xored")]
            group = os.path.basename(directory)
            with open(source, "rb") as fixture_file:
                data = decode(fixture_file.read())
            fat = lief.MachO.parse(list(data))
            if fat is None or len(fat) != 1:
                cells.append({"name": name, "group": group, "status": "not_a_single_slice_macho"})
                continue
            binary = fat.at(0)
            architecture = str(binary.header.cpu_type).rsplit(".", 1)[-1]
            if architecture != "ARM64":
                cells.append({"name": name, "group": group, "status": "wrong_architecture", "detail": architecture})
                continue
            starts = machoFunctionStarts(binary)
            if not starts:
                cells.append({"name": name, "group": group, "status": "declares_no_function_starts"})
                continue
            text = _sectionExtent(binary, "__text")
            outside = [start for start in starts if text is None or not text[0] <= start < text[1]]
            stubs = symbolStubStarts(binary)
            ranges = scoredRanges(binary)
            with open(os.path.join(binary_dir, name), "wb") as binary_file:
                binary_file.write(data)
            writeTruth(
                truth_dir,
                name,
                starts,
                {
                    "source": "LC_FUNCTION_STARTS plus declared symbol stubs",
                    "group": group,
                    "image_base": binary.imagebase,
                    "text": list(text) if text else None,
                    "starts_outside_text": len(outside),
                    "plt": stubs,
                    "scored_ranges": [list(extent) for extent in ranges],
                },
            )
            cells.append(
                {
                    "name": name,
                    "group": group,
                    "status": "ok",
                    "truth_functions": len(starts) + len(stubs),
                    "declared_starts": len(starts),
                    "symbol_stubs": len(stubs),
                    "starts_outside_text": len(outside),
                    "size": len(data),
                }
            )
    manifest = {
        "family": "macho-arm64",
        "fixture_root": FIXTURE_ROOT,
        "ok": sum(1 for cell in cells if cell["status"] == "ok"),
        "failed": sum(1 for cell in cells if cell["status"] != "ok"),
        "cells": cells,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
