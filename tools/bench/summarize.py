#!/usr/bin/env python3
"""Re-aggregate saved benchmark results without re-running any engine.

Result files keep every per-sample count, so a different filter, a different
mean, or a comparison between two runs is a re-read rather than a re-measure.

    tools/bench/summarize.py results/ --filter paper
    tools/bench/summarize.py results/ --compare baseline/
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.corpora import PAPER_OPT_LEVELS
from bench.metrics import Aggregate, SampleScore, aggregate
from bench.report import renderRow, renderTable


def loadResult(path: str) -> Dict[str, object]:
    with open(path, encoding="utf-8") as result_file:
        return json.load(result_file)


def scoresFrom(payload: Dict[str, object], opt_filter: str) -> List[SampleScore]:
    scores = []
    for entry in payload["samples"]:
        meta = entry.get("meta") or {}
        if opt_filter == "paper":
            opt = meta.get("opt")
            if opt is not None and opt not in PAPER_OPT_LEVELS:
                continue
        scores.append(
            SampleScore(
                name=entry["name"],
                truth=entry["truth"],
                detected=entry["detected"],
                true_positives=entry["tp"],
                false_positives=entry["fp"],
                false_negatives=entry["fn"],
                meta=meta,
            )
        )
    return scores


def collect(directory: str, opt_filter: str) -> Dict[str, Tuple[Dict, List[SampleScore], Aggregate]]:
    collected = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        if os.path.basename(path).startswith("summary_"):
            continue
        payload = loadResult(path)
        if "samples" not in payload:
            continue
        scores = scoresFrom(payload, opt_filter)
        if not scores:
            continue
        key = f"{payload['engine']['engine']}:{payload['corpus']['key']}"
        collected[key] = (payload, scores, aggregate(scores))
    return collected


def _delta(new: Optional[float], old: Optional[float]) -> str:
    if new is None or old is None:
        return "     -"
    return f"{new - old:+6.3f}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", help="directory of result JSONs")
    parser.add_argument("--filter", default="all", choices=["all", "paper"])
    parser.add_argument("--mean", default="macro", choices=["macro", "geometric", "micro"])
    parser.add_argument("--compare", default="", help="second results directory to diff against")
    args = parser.parse_args(argv)

    current = collect(args.results, args.filter)
    if not current:
        print(f"[!] no result files with samples in {args.results}", file=sys.stderr)
        return 1

    if not args.compare:
        rows = []
        for key in sorted(current):
            payload, _, aggregated = current[key]
            rows.append(
                renderRow(payload["corpus"]["title"], payload["engine"]["engine"], args.filter, aggregated, args.mean)
            )
        print(renderTable(rows, args.mean))
        total_truth = sum(entry[2].total_truth for entry in current.values())
        print(f"\n[control] rows={len(rows)} truth_functions={total_truth} mean={args.mean} filter={args.filter}")
        return 0

    baseline = collect(args.compare, args.filter)
    header = (
        f"{'config':<34} {'engine':<10} {'n':>4} {'dPPV':>7} {'dTPR':>7} {'dF1':>7} {'dTP':>7} {'dFP':>7} {'dFN':>7}"
    )
    rows = [header, "-" * len(header)]
    regressions = []
    for key in sorted(current):
        if key not in baseline:
            continue
        payload, _, new = current[key]
        _, _, old = baseline[key]
        if new.n != old.n:
            print(
                f"[!] {key}: n differs ({old.n} -> {new.n}); the two sides are different populations", file=sys.stderr
            )
            return 1
        picks = {
            "macro": ("macro_ppv", "macro_tpr", "macro_f1"),
            "geometric": ("geo_ppv", "geo_tpr", "geo_f1"),
            "micro": ("micro_ppv", "micro_tpr", "micro_f1"),
        }[args.mean]
        new_ppv, new_tpr, new_f1 = (getattr(new, name) for name in picks)
        old_ppv, old_tpr, old_f1 = (getattr(old, name) for name in picks)
        rows.append(
            f"{payload['corpus']['title']:<34} {payload['engine']['engine']:<10} {new.n:>4} "
            f"{_delta(new_ppv, old_ppv)} {_delta(new_tpr, old_tpr)} {_delta(new_f1, old_f1)} "
            f"{new.total_tp - old.total_tp:>+7} {new.total_fp - old.total_fp:>+7} {new.total_fn - old.total_fn:>+7}"
        )
        if new_tpr is not None and old_tpr is not None and new_tpr < old_tpr:
            regressions.append(f"{key}: TPR {old_tpr:.4f} -> {new_tpr:.4f}")
    print("\n".join(rows))
    print(f"\n[control] compared={len(rows) - 2} mean={args.mean} filter={args.filter}")
    if regressions:
        print("\n[!] TPR regressed — this is a reject under the accuracy gates:", file=sys.stderr)
        for regression in regressions:
            print(f"    {regression}", file=sys.stderr)
        return 1
    print("[ok] no TPR regression on any compared config")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
