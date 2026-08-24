"""Corpus integrity checks that run before a comparison is reported.

A benchmark that silently averages in a binary paired with the wrong ground
truth is not measuring the disassembler. This module answers one question the
corpora can answer about themselves: does every ground-truth function start
land inside an executable section of the binary it is paired with?
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import lief

from bench.corpora import Sample
from smda.utility.ElfFileLoader import ElfFileLoader
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.PeFileLoader import PeFileLoader

_LOADERS = (PeFileLoader, ElfFileLoader, MachoFileLoader)

# the malware dumps are damaged by construction and lief narrates every repair to
# stderr; the check reads section extents only, where those repairs do not apply
lief.logging.disable()


@dataclass
class IntegrityFinding:
    name: str
    truth: int
    outside: int
    ranges: List[Tuple[int, int]]

    @property
    def share(self) -> float:
        return 100.0 * self.outside / self.truth if self.truth else 0.0


def executableRanges(path: str, base_addr: Optional[int] = None) -> Optional[List[Tuple[int, int]]]:
    """Executable address ranges the binary's own container declares, or None.

    None means the check does not apply — a headerless dump names no sections, so
    there is nothing to test the truth against, and silence must not be read as a
    pass. A dump loaded somewhere other than its link-time base has its ranges
    shifted onto the address space its ground truth is written in.
    """
    with open(path, "rb") as binary_file:
        data = binary_file.read()
    for loader in _LOADERS:
        if not loader.isCompatible(data):
            continue
        areas = loader.getCodeAreas(data)
        if not areas:
            return None
        shift = 0 if base_addr is None else base_addr - loader.getBaseAddress(data)
        return [(int(start) + shift, int(end) + shift) for start, end in areas]
    return None


def checkSample(sample: Sample) -> Optional[IntegrityFinding]:
    if not appliesTo(sample):
        return None
    ranges = executableRanges(sample.path, sample.base_addr)
    if ranges is None:
        return None
    outside = [start for start in sample.truth if not any(low <= start < high for low, high in ranges)]
    if not outside:
        return None
    return IntegrityFinding(name=sample.name, truth=len(sample.truth), outside=len(outside), ranges=ranges)


def appliesTo(sample: Sample) -> bool:
    """Whether truth and section table are in the same address space.

    A managed assembly's method starts are file offsets, because that is what the
    CIL backend reports; comparing them against virtual section ranges compares two
    unrelated numbers and would flag every managed sample.
    """
    return (sample.meta or {}).get("address_space", "virtual") == "virtual"


def checkCorpus(samples: List[Sample]) -> Tuple[List[IntegrityFinding], Dict[str, int]]:
    """Findings plus a control: how many samples the check could actually run on."""
    findings = []
    checked = 0
    for sample in samples:
        if not appliesTo(sample):
            continue
        ranges = executableRanges(sample.path, sample.base_addr)
        if ranges is None:
            continue
        checked += 1
        finding = checkSample(sample)
        if finding is not None:
            findings.append(finding)
    return findings, {"checked": checked, "unchecked": len(samples) - checked, "total": len(samples)}
