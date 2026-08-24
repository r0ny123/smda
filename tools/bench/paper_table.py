#!/usr/bin/env python3
"""Replicate the origin paper's disassembler-comparison table with today's engines.

The paper reports recall and precision per (data set, pack, compiler, optimization)
and presents two different aggregations depending on the row:

- a row whose binaries carry an `O0`-`O3` optimization label is split by that label
  and each cell is the **geometric mean** across the binaries at that level;
- a row whose binaries carry no such label (the dumped and memory-dump corpora) is a
  single cell holding the **arithmetic mean** across all of them.

Both come from the same per-binary rates. This script reproduces that presentation
from result files written by `run.py`, and prints the paper's own recorded figures
beside them so a divergence is visible in the table rather than only in prose.

    tools/bench/paper_table.py results/ --paper-era bundle/accuracy-eval/results
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import sys
from typing import Dict, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.corpora import PAPER_OPT_LEVELS  # noqa: F401  (imported for the filter vocabulary)

#: Table 6.5 of the dissertation, transcribed for the rows whose corpora are
#: available here. Values are (TPR, PPV) as printed, on a 0-1 scale. The IDA and
#: nucleus columns were produced by the paper's own run and are not re-measured.
PAPER_TABLE: Dict[Tuple[str, str], Dict[str, Tuple[float, float]]] = {
    ("bao-x86", "O1"): {
        "ghidra-9.1.2": (0.804, 0.952),
        "ida74": (0.835, 0.996),
        "nucleus": (0.975, 0.923),
        "smda-1.2.5": (0.992, 0.935),
    },
    ("bao-x86", "O2"): {
        "ghidra-9.1.2": (0.809, 0.950),
        "ida74": (0.833, 0.996),
        "nucleus": (0.975, 0.894),
        "smda-1.2.5": (0.992, 0.927),
    },
    ("bao-x86-64", "O1"): {
        "ghidra-9.1.2": (0.675, 0.999),
        "ida74": (0.813, 0.999),
        "nucleus": (0.949, 0.969),
        "smda-1.2.5": (0.975, 0.983),
    },
    ("bao-x86-64", "O2"): {
        "ghidra-9.1.2": (0.703, 0.999),
        "ida74": (0.811, 0.999),
        "nucleus": (0.948, 0.938),
        "smda-1.2.5": (0.972, 0.981),
    },
    ("bao-x86-dumped", "-"): {
        "ghidra-9.1.2": (0.775, 0.953),
        "ida74": (0.743, 0.928),
        "nucleus": (0.745, 0.621),
        "smda-1.2.5": (0.967, 0.910),
    },
    ("bao-x86-64-dumped", "-"): {
        "ghidra-9.1.2": (0.653, 0.999),
        "ida74": (0.543, 0.999),
        "nucleus": (0.645, 0.413),
        "smda-1.2.5": (0.932, 0.985),
    },
    ("malpedia", "-"): {
        "ghidra-9.1.2": (0.819, 0.940),
        "ida74": (0.847, 0.964),
        "nucleus": (0.914, 0.627),
        "smda-1.2.5": (0.976, 0.935),
    },
}

#: rows the paper splits by optimization level, in the order it prints them
SPLIT_BY_OPT = {"bao-x86", "bao-x86-64"}

ROW_ORDER = [
    ("bao-x86", "O1"),
    ("bao-x86", "O2"),
    ("bao-x86-64", "O1"),
    ("bao-x86-64", "O2"),
    ("bao-x86-dumped", "-"),
    ("bao-x86-64-dumped", "-"),
    ("malpedia", "-"),
]

TITLES = {
    "bao-x86": "GB  ByteWeight  msvc10-32",
    "bao-x86-64": "GB  ByteWeight  msvc10-64",
    "bao-x86-dumped": "GB* ByteWeight* msvc10-32",
    "bao-x86-64-dumped": "GB* ByteWeight* msvc10-64",
    "malpedia": "GM  Malpedia57  -",
}


def _geomean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    if any(value <= 0 for value in values):
        return 0.0
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _mean(values: List[float]) -> Optional[float]:
    return sum(values) / len(values) if values else None


def cell(samples: List[Dict], corpus_key: str, opt: str) -> Optional[Tuple[float, float, int]]:
    """(TPR, PPV, n) for one table cell, aggregated the way the paper prints it."""
    if corpus_key in SPLIT_BY_OPT:
        chosen = [sample for sample in samples if (sample.get("meta") or {}).get("opt") == opt]
        aggregator = _geomean
    else:
        chosen = list(samples)
        aggregator = _mean
    tprs = [sample["tpr"] for sample in chosen if sample["tpr"] is not None]
    ppvs = [sample["ppv"] for sample in chosen if sample["ppv"] is not None]
    if not tprs:
        return None
    tpr, ppv = aggregator(tprs), aggregator(ppvs)
    if tpr is None or ppv is None:
        return None
    return tpr / 100.0, ppv / 100.0, len(chosen)


def loadMeasured(results_dir: str) -> Dict[str, Dict]:
    measured: Dict[str, Dict] = {}
    for path in sorted(glob.glob(os.path.join(results_dir, "*.json"))):
        if os.path.basename(path).startswith("summary_"):
            continue
        with open(path, encoding="utf-8") as result_file:
            payload = json.load(result_file)
        if "samples" not in payload:
            continue
        engine = payload["engine"]["engine"]
        version = payload["engine"].get("version", "?")
        measured.setdefault(f"{engine}-{version}", {})[payload["corpus"]["key"]] = payload["samples"]
    return measured


def _fmt(value: Optional[float]) -> str:
    return "  -  " if value is None else f"{value:.3f}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", help="directory of result JSONs written by run.py")
    parser.add_argument("--json", default="", help="also write the table as machine-readable JSON")
    args = parser.parse_args(argv)

    measured = loadMeasured(args.results)
    if not measured:
        print(f"[!] no engine results in {args.results}", file=sys.stderr)
        return 1
    engines = sorted(measured)

    paper_columns = ["ghidra-9.1.2", "ida74", "nucleus", "smda-1.2.5"]
    header = f"{'row':<28} {'opt':<4} {'n':>4} |"
    for column in paper_columns:
        header += f" {column + ' (paper)':>22} |"
    for engine in engines:
        header += f" {engine + ' (measured)':>25} |"
    print(header)
    print("-" * len(header))

    payload_rows = []
    missing = []
    for corpus_key, opt in ROW_ORDER:
        recorded = PAPER_TABLE[(corpus_key, opt)]
        line_n = None
        cells = {}
        for engine in engines:
            samples = measured.get(engine, {}).get(corpus_key)
            if not samples:
                cells[engine] = None
                missing.append(f"{engine}:{corpus_key}")
                continue
            computed = cell(samples, corpus_key, opt)
            cells[engine] = computed
            if computed:
                line_n = computed[2]
        line = f"{TITLES[corpus_key]:<28} {opt:<4} {str(line_n or '-'):>4} |"
        for column in paper_columns:
            tpr, ppv = recorded[column]
            line += f"   TPR {tpr:.3f} PPV {ppv:.3f} |"
        for engine in engines:
            computed = cells[engine]
            if computed is None:
                line += f" {'not measured':>25} |"
            else:
                line += f"      TPR {_fmt(computed[0])} PPV {_fmt(computed[1])} |"
        print(line)
        payload_rows.append(
            {
                "corpus": corpus_key,
                "optimization": opt,
                "n": line_n,
                "paper": {name: {"tpr": value[0], "ppv": value[1]} for name, value in recorded.items()},
                "measured": {
                    engine: (None if cells[engine] is None else {"tpr": cells[engine][0], "ppv": cells[engine][1]})
                    for engine in engines
                },
            }
        )

    print()
    print(
        "[control] rows="
        f"{len(payload_rows)} engines_measured={engines} "
        f"paper_columns_are_recorded_not_remeasured={paper_columns} missing={sorted(set(missing))}"
    )
    if args.json:
        with open(args.json, "w", encoding="utf-8") as json_file:
            json.dump({"rows": payload_rows, "engines": engines, "paper_columns": paper_columns}, json_file, indent=1)
        print(f"[+] wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
