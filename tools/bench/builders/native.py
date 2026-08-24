"""Build the C / C++ corpus: one binary per (program, compiler, options) cell.

Ground truth comes from the unstripped link; the corpus keeps the stripped
twin, so what the benchmark measures has no symbol table to read. A cell that
fails to build is recorded with its compiler error rather than skipped, because
a silently shrinking matrix reads as a passing one.
"""

from __future__ import annotations

import contextlib
import glob
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

from bench.builders.sources import PROGRAMS, SourceProgram, fetch
from bench.builders.truth import elfFunctionStarts, peFunctionStarts, writeTruth


@dataclass
class Toolchain:
    key: str
    cc: str
    cxx: str
    strip: str
    container: str
    bitness: int
    #: flags every cell of this toolchain needs
    base_flags: List[str]


TOOLCHAINS: Dict[str, Toolchain] = {
    "gcc-x64": Toolchain("gcc-x64", "gcc", "g++", "strip", "elf", 64, []),
    "clang-x64": Toolchain("clang-x64", "clang", "clang++", "strip", "elf", 64, []),
    "mingw-x64": Toolchain(
        "mingw-x64", "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-strip", "pe", 64, []
    ),
    "mingw-x86": Toolchain(
        "mingw-x86", "i686-w64-mingw32-gcc", "i686-w64-mingw32-g++", "i686-w64-mingw32-strip", "pe", 32, []
    ),
}

#: (label, extra flags). PIE and static linking change what a disassembler sees
#: as much as the optimization level does, so both axes are in the matrix.
VARIANTS = [
    ("O0", ["-O0"]),
    ("O1", ["-O1"]),
    ("O2", ["-O2"]),
    ("O3", ["-O3"]),
    ("Os", ["-Os"]),
    ("O2-static", ["-O2", "-static"]),
    ("O2-nopie", ["-O2", "-no-pie", "-fno-pie"]),
]

PE_VARIANTS = [
    ("O0", ["-O0"]),
    ("O1", ["-O1"]),
    ("O2", ["-O2"]),
    ("O3", ["-O3"]),
    ("Os", ["-Os"]),
    ("O2-static", ["-O2", "-static"]),
]


def _expandSources(root: str, patterns: List[str]) -> List[str]:
    files: List[str] = []
    for pattern in patterns:
        matched = sorted(glob.glob(os.path.join(root, pattern)))
        files.extend(matched)
    # lua ships both an interpreter and a compiler main; two `main` symbols do not link
    return [path for path in files if not path.endswith(("luac.c", "lua.c.orig"))]


def buildCell(
    program: SourceProgram,
    toolchain: Toolchain,
    variant: str,
    flags: List[str],
    source_root: str,
    work_dir: str,
) -> Dict[str, object]:
    compiler = toolchain.cxx if program.language == "cxx" else toolchain.cc
    if shutil.which(compiler) is None:
        return {"status": "toolchain_unavailable", "compiler": compiler}
    sources = _expandSources(source_root, program.sources)
    if not sources:
        return {"status": "no_sources"}
    name = f"{program.key}_{toolchain.key}_{variant}"
    unstripped = os.path.join(work_dir, name + ".unstripped")
    command = [compiler, "-g", "-w"]
    command += toolchain.base_flags + flags + program.extra_flags
    command += [f"-I{os.path.join(source_root, include)}" for include in program.include_dirs or ["."]]
    command += [f"-D{define}" for define in program.defines]
    command += sources
    command += ["-o", unstripped]
    if toolchain.container == "elf":
        command += ["-lm", "-lpthread", "-ldl"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if completed.returncode != 0 or not os.path.isfile(unstripped):
        return {"status": "build_failed", "error": completed.stderr[-600:], "command": " ".join(command[:8])}
    return {"status": "built", "name": name, "unstripped": unstripped}


def harvestCell(
    cell: Dict[str, object],
    toolchain: Toolchain,
    program: SourceProgram,
    variant: str,
    binary_dir: str,
    truth_dir: str,
) -> Dict[str, object]:
    name = str(cell["name"])
    unstripped = str(cell["unstripped"])
    try:
        truth = elfFunctionStarts(unstripped) if toolchain.container == "elf" else peFunctionStarts(unstripped)
    except (RuntimeError, OSError) as failure:
        return {"status": "truth_failed", "error": str(failure)[:300]}
    if not truth["starts"]:
        return {"status": "truth_empty"}
    os.makedirs(binary_dir, exist_ok=True)
    stripped = os.path.join(binary_dir, name)
    shutil.copyfile(unstripped, stripped)
    completed = subprocess.run([toolchain.strip, stripped], capture_output=True, text=True)
    if completed.returncode != 0:
        os.remove(stripped)
        return {"status": "strip_failed", "error": completed.stderr[-300:]}
    writeTruth(
        truth_dir,
        name,
        list(truth["starts"]),
        {
            "plt": truth.get("plt", []),
            "bitness": truth["bitness"],
            "container": toolchain.container,
            "image_base": truth.get("image_base", 0),
            "entrypoint": truth.get("entrypoint", 0),
            "program": program.key,
            "language": program.language,
            "toolchain": toolchain.key,
            "variant": variant,
            "truth_source": truth["source"],
        },
    )
    return {
        "status": "ok",
        "name": name,
        "truth_functions": len(truth["starts"]),
        "plt_entries": len(truth.get("plt", [])),
        "size": os.path.getsize(stripped),
    }


def build(
    out_dir: str,
    cache_dir: str,
    work_dir: str,
    programs: Optional[List[str]] = None,
    toolchains: Optional[List[str]] = None,
) -> Dict[str, object]:
    binary_dir = os.path.join(out_dir, "binary")
    truth_dir = os.path.join(out_dir, "truth")
    os.makedirs(work_dir, exist_ok=True)
    cells: List[Dict[str, object]] = []
    for program_key in programs or sorted(PROGRAMS):
        program = PROGRAMS[program_key]
        if program.language not in ("c", "cxx"):
            continue
        source_root = fetch(program, cache_dir)
        if source_root is None:
            cells.append({"program": program_key, "status": "source_unavailable"})
            continue
        for toolchain_key in toolchains or sorted(TOOLCHAINS):
            toolchain = TOOLCHAINS[toolchain_key]
            variants = PE_VARIANTS if toolchain.container == "pe" else VARIANTS
            for variant, flags in variants:
                built = buildCell(program, toolchain, variant, flags, source_root, work_dir)
                record = {"program": program_key, "toolchain": toolchain_key, "variant": variant}
                if built["status"] != "built":
                    record.update(built)
                    cells.append(record)
                    continue
                harvested = harvestCell(built, toolchain, program, variant, binary_dir, truth_dir)
                record.update(harvested)
                cells.append(record)
                with contextlib.suppress(OSError):
                    os.remove(str(built["unstripped"]))
    manifest = {
        "family": "native",
        "cells": cells,
        "ok": sum(1 for cell in cells if cell.get("status") == "ok"),
        "failed": sum(1 for cell in cells if cell.get("status") not in ("ok",)),
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=1, sort_keys=True)
    return manifest
