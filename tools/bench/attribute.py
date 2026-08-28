#!/usr/bin/env python3
"""Attribute a corpus' false positives to the candidate passes that booked each address.

A precision number says how many addresses are wrong; it does not say which part of
candidate discovery produced them, and every repair is aimed at one part.

    tools/bench/attribute.py --corpus native-arm64 --out results/attr-arm64

Two views, because neither answers alone. **First** is the pass whose call came first, which
is what a trace shows -- but the prologue sweep runs once over the whole image before
anything else, so it is first for every address that merely looks like an entry, whether or
not that is why the address survived. **Sole** counts only addresses that exactly one pass
ever booked: those are the ones that disappear if that pass is changed, and they are what a
repair can actually claim. An address several passes agree on is reported under both, and
turning off any one of them would not remove it.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from typing import Dict, List, Optional, Set

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.corpora import CORPORA, filterSamples
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig

DEFAULT_ROOT = os.environ.get("SMDA_BENCH_GROUNDTRUTH", os.path.expanduser("~/groundtruth_data"))

#: every entry point candidate discovery has. `addCandidate` is the shared tail several of
#: the others call, so it is recorded last and only ever answers for a caller none of the
#: named passes covers.
BOOKING_METHODS = (
    "addSymbolCandidate",
    "addExceptionCandidate",
    "addLanguageSpecCandidate",
    "addReferenceCandidate",
    "addPrologueCandidate",
    "addTailcallCandidate",
    "addGapCandidate",
    "addCandidate",
)


def _managerClasses():
    """Every candidate-manager class in the tree, base and per-architecture.

    A subclass that overrides a booking method and does not call up would be invisible to a
    wrapper installed only on the base, and the AArch64 manager overrides two of them.
    """
    from smda.aarch64.FunctionCandidateManager import FunctionCandidateManager as AArch64Manager
    from smda.common.FunctionCandidateManager import FunctionCandidateManager as CommonManager
    from smda.intel.FunctionCandidateManager import FunctionCandidateManager as IntelManager

    return [CommonManager, IntelManager, AArch64Manager]


class BookingRecorder:
    """Wraps the booking methods for one analysis and remembers who booked what."""

    def __init__(self):
        self.first: Dict[int, str] = {}
        self.passes: Dict[int, Set[str]] = {}
        self._restore = []

    def __enter__(self):
        for manager_class in _managerClasses():
            for name in BOOKING_METHODS:
                if name not in manager_class.__dict__:
                    continue
                original = manager_class.__dict__[name]
                setattr(manager_class, name, self._wrap(name, original))
                self._restore.append((manager_class, name, original))
        return self

    def __exit__(self, *_exc):
        for manager_class, name, original in reversed(self._restore):
            setattr(manager_class, name, original)
        self._restore = []
        return False

    def _wrap(self, name, original):
        recorder = self

        def wrapped(manager, addr, *args, **kwargs):
            recorder.first.setdefault(addr, name)
            recorder.passes.setdefault(addr, set()).add(name)
            return original(manager, addr, *args, **kwargs)

        return wrapped


def attributeSample(sample, timeout: int) -> Optional[Dict[str, object]]:
    config = SmdaConfig()
    config.TIMEOUT = timeout
    disassembler = Disassembler(config=config)
    with BookingRecorder() as recorder:
        if sample.base_addr is None:
            report = disassembler.disassembleFile(sample.path)
        else:
            with open(sample.path, "rb") as binary_file:
                buffer = binary_file.read()
            report = disassembler.disassembleBuffer(buffer, sample.base_addr, bitness=sample.bitness)
    if report.status != "ok":
        return None
    detected: Set[int] = {function.offset for function in report.getFunctions()}
    false_positives = detected - sample.truth
    recovered = detected & sample.truth

    def sole(addresses):
        counter: collections.Counter = collections.Counter()
        for addr in addresses:
            booked = recorder.passes.get(addr, set())
            if len(booked) == 1:
                counter[next(iter(booked))] += 1
        return counter

    return {
        "name": sample.name,
        "truth": len(sample.truth),
        "detected": len(detected),
        "false_positives": len(false_positives),
        "first_pass": dict(collections.Counter(recorder.first.get(a, "unrecorded") for a in false_positives)),
        "sole_pass": dict(sole(false_positives)),
        "true_positives_first_pass": dict(collections.Counter(recorder.first.get(a, "unrecorded") for a in recovered)),
        "true_positives_sole_pass": dict(sole(recovered)),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", required=True, help="one corpus key: " + ",".join(sorted(CORPORA)))
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--filter", default="all", choices=["all", "paper"])
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    corpus = CORPORA.get(args.corpus)
    if corpus is None:
        print(f"unknown corpus: {args.corpus}", file=sys.stderr)
        return 2
    samples = filterSamples(corpus.load(args.root), args.filter)
    if args.limit:
        samples = samples[: args.limit]
    if not samples:
        print(f"{args.corpus}: no samples under {args.root}", file=sys.stderr)
        return 1

    rows, failed = [], []
    for sample in samples:
        row = attributeSample(sample, args.timeout)
        if row is None:
            failed.append(sample.name)
            continue
        rows.append(row)

    columns = ("first_pass", "sole_pass", "true_positives_first_pass", "true_positives_sole_pass")
    totals = {column: collections.Counter() for column in columns}
    for row in rows:
        for column in columns:
            totals[column].update(row[column])
    false_positives = sum(totals["first_pass"].values())

    # A pass is only worth aiming at once its cost is read beside what it recovers, and only
    # the sole columns say what changing that one pass would move.
    print(f"\n{corpus.title} -- {len(rows)} samples analysed, {len(failed)} failed, {false_positives} false positives")
    print(f"{'pass':<28}{'FP first':>10}{'share':>8}{'FP sole':>10}{'TP first':>10}{'TP sole':>10}")
    for name, count in totals["first_pass"].most_common():
        share = 100.0 * count / false_positives if false_positives else 0.0
        print(
            f"{name:<28}{count:>10}{share:>7.1f}%{totals['sole_pass'].get(name, 0):>10}"
            f"{totals['true_positives_first_pass'].get(name, 0):>10}{totals['true_positives_sole_pass'].get(name, 0):>10}"
        )
    if failed:
        print(f"[!] not analysed: {', '.join(sorted(failed))}", file=sys.stderr)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, f"attribution_{args.corpus}_{args.filter}.json")
        with open(path, "w") as handle:
            json.dump(
                {
                    "corpus": args.corpus,
                    "filter": args.filter,
                    "module": os.path.dirname(os.path.abspath(sys.modules["smda"].__file__)),
                    "samples": rows,
                    "failed": failed,
                    **{column: dict(totals[column]) for column in columns},
                },
                handle,
                indent=2,
                sort_keys=True,
            )
        print(f"[+] wrote {path}")
    return 1 if not rows else 0


if __name__ == "__main__":
    raise SystemExit(main())
