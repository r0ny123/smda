"""Corpus discovery and ground-truth loading for the accuracy benchmark.

Each corpus contributes `Sample` records that pair one binary with the set of
function-start addresses its ground truth names. The two on-disk truth formats
are deliberately kept apart: ByteWeight ships `start end` extents plus a
separate thunk list, malpedia ships one line per *instruction* with its owning
function. Unifying them would have to invent information one of them lacks.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

DUMP_BASE_RE = re.compile(r"_0x(?P<base_addr>[0-9a-fA-F]{8,16})$")
OPT_LEVEL_RE = re.compile(r"_(?P<opt>O[0-9a-zA-Z]+)_")


@dataclass
class Sample:
    name: str
    path: str
    truth: Set[int]
    #: load address for headerless input; None means the engine parses a container
    base_addr: Optional[int] = None
    #: architecture hint for engines that cannot infer it from a headerless dump
    bitness: Optional[int] = None
    #: address ranges the ground truth covers; None scores the whole image. A corpus
    #: whose oracle speaks for part of an image sets this rather than charging the
    #: engine for the rest.
    scored_ranges: Optional[List[Tuple[int, int]]] = None
    meta: Dict[str, object] = field(default_factory=dict)


@dataclass
class Corpus:
    key: str
    title: str
    #: human-readable description of where the ground truth comes from
    truth_source: str
    loader: Callable[[str], List[Sample]]
    #: relative path under the groundtruth root this corpus lives at
    relative_root: str

    def load(self, root: str) -> List[Sample]:
        return self.loader(os.path.join(root, self.relative_root))


def parseBaseAddrFromName(name: str) -> Optional[int]:
    match = DUMP_BASE_RE.search(name)
    if match is None:
        return None
    return int(match.group("base_addr"), 16)


def bitnessFromName(name: str) -> int:
    """The corpus convention for a headerless sample: 64 only if the name says so.

    A dump carries no container to read the instruction set from, so the
    evaluation this replicates decides it from the file name and defaults to
    32-bit. Keeping that rule is what makes a number comparable with the
    published one; measuring what SMDA infers instead is a separate question
    the harness answers under `--bitness auto`.
    """
    return 64 if ("x64-" in name or "_64_" in name) else 32


def parseOptLevel(name: str) -> Optional[str]:
    match = OPT_LEVEL_RE.search(name)
    if match is None:
        return None
    return match.group("opt")


def loadByteweightTruth(function_path: str, thunk_path: Optional[str]) -> Set[int]:
    """Function starts from a ByteWeight `start end` file, plus its thunk list.

    Thunks are part of the ground truth: the dissertation's own comparison
    script folds `thunks_*` into the truth set alongside `msvs_*` before
    scoring, so leaving them out would score against a smaller truth set than
    the paper used.
    """
    starts: Set[int] = set()
    with open(function_path, encoding="utf-8", errors="replace") as function_file:
        for line in function_file:
            fields = line.split()
            if not fields:
                continue
            starts.add(int(fields[0], 16))
    if thunk_path and os.path.isfile(thunk_path):
        with open(thunk_path, encoding="utf-8", errors="replace") as thunk_file:
            for line in thunk_file:
                fields = line.split()
                if not fields:
                    continue
                starts.add(int(fields[0], 16))
    return starts


def loadFnmapTruth(fnmap_path: str) -> Set[int]:
    """Function starts from a malpedia `.fnmap` (`ins_addr;fn_addr;mnemonic`)."""
    starts: Set[int] = set()
    with open(fnmap_path, encoding="utf-8", errors="replace") as fnmap_file:
        for line in fnmap_file:
            fields = line.strip().split(";")
            if len(fields) < 2:
                continue
            starts.add(int(fields[1], 16))
    return starts


def _byteweightLoader(binary_dir_name: str, truth_dir_name: str, dumped: bool, bitness: int):
    def load(root: str) -> List[Sample]:
        binary_dir = os.path.join(root, binary_dir_name) if binary_dir_name else root
        function_dir = os.path.join(root, truth_dir_name, "function")
        thunk_dir = os.path.join(root, truth_dir_name, "thunk")
        if not os.path.isdir(binary_dir):
            raise FileNotFoundError(f"corpus directory missing: {binary_dir}")
        if not os.path.isdir(function_dir):
            raise FileNotFoundError(f"ground-truth directory missing: {function_dir}")
        samples = []
        for name in sorted(os.listdir(binary_dir)):
            binary_path = os.path.join(binary_dir, name)
            if not os.path.isfile(binary_path):
                continue
            function_path = os.path.join(function_dir, name)
            if not os.path.isfile(function_path):
                continue
            truth = loadByteweightTruth(function_path, os.path.join(thunk_dir, name))
            samples.append(
                Sample(
                    name=name,
                    path=binary_path,
                    truth=truth,
                    base_addr=parseBaseAddrFromName(name) if dumped else None,
                    bitness=bitnessFromName(name),
                    meta={"opt": parseOptLevel(name), "dumped": dumped, "bitness": bitness},
                )
            )
        return samples

    return load


def _malpediaLoader(root: str) -> List[Sample]:
    binary_dir = os.path.join(root, "binary")
    truth_dir = os.path.join(root, "truth")
    if not os.path.isdir(binary_dir):
        raise FileNotFoundError(f"corpus directory missing: {binary_dir}")
    samples = []
    for name in sorted(os.listdir(binary_dir)):
        binary_path = os.path.join(binary_dir, name)
        if not os.path.isfile(binary_path):
            continue
        fnmap_path = os.path.join(truth_dir, name + ".fnmap")
        if not os.path.isfile(fnmap_path):
            continue
        samples.append(
            Sample(
                name=name,
                path=binary_path,
                bitness=bitnessFromName(name),
                truth=loadFnmapTruth(fnmap_path),
                base_addr=parseBaseAddrFromName(name),
                meta={"family": name.split("_")[0], "dumped": True},
            )
        )
    return samples


def loadBuiltTruth(truth_path: str) -> Dict[str, object]:
    with open(truth_path, encoding="utf-8") as truth_file:
        return json.load(truth_file)


def _builtLoader(family: str, plt_in_truth: bool = True):
    """Loader for a corpus this repository builds from source.

    PLT / import stubs are folded into the truth set by default, matching the
    convention the PE corpora already use: every engine in this comparison
    reports them, so excluding them would score a labelling choice rather than
    a detection difference.
    """

    def load(root: str) -> List[Sample]:
        binary_dir = os.path.join(root, "binary")
        truth_dir = os.path.join(root, "truth")
        if not os.path.isdir(binary_dir):
            raise FileNotFoundError(f"corpus directory missing: {binary_dir}")
        samples = []
        for name in sorted(os.listdir(binary_dir)):
            binary_path = os.path.join(binary_dir, name)
            truth_path = os.path.join(truth_dir, name + ".json")
            if not os.path.isfile(binary_path) or not os.path.isfile(truth_path):
                continue
            record = loadBuiltTruth(truth_path)
            truth = set(record["starts"])
            if plt_in_truth:
                truth |= set(record.get("plt", []))
            meta = {key: value for key, value in record.items() if key not in ("starts", "plt")}
            meta["family"] = family
            scored = record.get("scored_ranges")
            samples.append(
                Sample(
                    name=name,
                    path=binary_path,
                    truth=truth,
                    base_addr=None,
                    bitness=record.get("bitness"),
                    scored_ranges=[(int(start), int(end)) for start, end in scored] if scored else None,
                    meta=meta,
                )
            )
        return samples

    return load


BYTEWEIGHT_ROOT = "20200312-bao_byteweight"
BUILT_ROOT = "built"

CORPORA: Dict[str, Corpus] = {
    "bao-x86": Corpus(
        key="bao-x86",
        title="Bao byteweight msvc10-32",
        truth_source="CMU ByteWeight PE corpus, compiler-derived extents plus thunk list",
        loader=_byteweightLoader("binary", "gt", dumped=False, bitness=32),
        relative_root=os.path.join(BYTEWEIGHT_ROOT, "pe-x86"),
    ),
    "bao-x86-64": Corpus(
        key="bao-x86-64",
        title="Bao byteweight msvc10-64",
        truth_source="CMU ByteWeight PE corpus, compiler-derived extents plus thunk list",
        loader=_byteweightLoader("", "", dumped=False, bitness=64),
        relative_root=os.path.join(BYTEWEIGHT_ROOT, "pe-x86-64"),
    ),
    "bao-x86-dumped": Corpus(
        key="bao-x86-dumped",
        title="Bao_Dumped msvc10-32-d",
        truth_source="CMU ByteWeight PE corpus, PE headers stripped to stand in for a memory dump",
        loader=_byteweightLoader("binary", "gt", dumped=True, bitness=32),
        relative_root=os.path.join(BYTEWEIGHT_ROOT, "pe-x86-dumped"),
    ),
    "bao-x86-64-dumped": Corpus(
        key="bao-x86-64-dumped",
        title="Bao_Dumped msvc10-64-d",
        truth_source="CMU ByteWeight PE corpus, PE headers stripped to stand in for a memory dump",
        loader=_byteweightLoader("binary", "gt", dumped=True, bitness=64),
        relative_root=os.path.join(BYTEWEIGHT_ROOT, "pe-x86-64-dumped"),
    ),
    "native": Corpus(
        key="native",
        title="Built C/C++ (gcc, clang, mingw)",
        truth_source="symbol table of the unstripped link, measured on the stripped twin",
        loader=_builtLoader("native"),
        relative_root=os.path.join(BUILT_ROOT, "native"),
    ),
    "go": Corpus(
        key="go",
        title="Built Go (pclntab truth)",
        truth_source="go tool nm over the unstripped build, measured on the stripped twin",
        loader=_builtLoader("go"),
        relative_root=os.path.join(BUILT_ROOT, "go"),
    ),
    "rust": Corpus(
        key="rust",
        title="Built Rust (gnu targets)",
        truth_source="symbol table of the unstripped link, measured on the stripped twin",
        loader=_builtLoader("rust"),
        relative_root=os.path.join(BUILT_ROOT, "rust"),
    ),
    "macho-arm64": Corpus(
        key="macho-arm64",
        title="ARM64 Mach-O (LC_FUNCTION_STARTS)",
        truth_source="LC_FUNCTION_STARTS, written by the linker, in the repository's own fixture corpus",
        loader=_builtLoader("macho-arm64"),
        relative_root=os.path.join(BUILT_ROOT, "macho-arm64"),
    ),
    "dotnet": Corpus(
        key="dotnet",
        title="Built .NET (CIL and NativeAOT)",
        truth_source="assembly metadata for CIL; symbol table for the NativeAOT native image",
        loader=_builtLoader("dotnet"),
        relative_root=os.path.join(BUILT_ROOT, "dotnet"),
    ),
    "malpedia": Corpus(
        key="malpedia",
        title="Plohmann malpedia itw",
        truth_source="IDA databases plus manual labelling, one memory dump per malware family",
        loader=_malpediaLoader,
        relative_root="20200312-plohmann_disasm",
    ),
}

#: the dissertation's tables exclude these optimization levels; the harness
#: default keeps every build, so a row is only comparable when it names its filter
PAPER_OPT_LEVELS = {"O1", "O2"}

#: Ground-truth files established to describe a different build from the binary they
#: are paired with, keyed by the name stem so a dumped variant of the same program is
#: covered too. Excluded only when asked for, because every published figure for these
#: corpora includes them and a silently smaller population is not comparable.
KNOWN_TRUTH_DEFECTS: Dict[str, str] = {
    "msvs_whatever_32_Od_SfxSetup": (
        "truth spans 0x401000-0x414d86 while the binary's only executable section ends at "
        "0x411000; 181 of its 472 starts fall outside it, it shares 4 addresses with the O1 "
        "build's truth despite having the same 472 entries, and every sibling build matches "
        "its own truth to the address"
    ),
}


def knownTruthDefect(name: str) -> Optional[str]:
    for stem, reason in KNOWN_TRUTH_DEFECTS.items():
        if name.startswith(stem):
            return reason
    return None


def filterSamples(samples: List[Sample], opt_filter: str) -> List[Sample]:
    if opt_filter == "all":
        return list(samples)
    if opt_filter == "paper":
        # a corpus with no optimization level in its names (malpedia) is not a
        # compiler-build matrix, so the filter has nothing to exclude there
        return [
            sample for sample in samples if sample.meta.get("opt") is None or sample.meta.get("opt") in PAPER_OPT_LEVELS
        ]
    raise ValueError(f"unknown filter: {opt_filter}")
