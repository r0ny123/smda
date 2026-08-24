#!/usr/bin/env python3
"""Function-start accuracy benchmark for SMDA and comparison engines.

Runs one or more engines over one or more ground-truth corpora and reports
PPV / TPR / F1 per corpus. Every row names its corpus, its `n` and the
optimization-level filter it was computed under, because the same corpus under
two filters is two different populations.

    tools/bench/run.py --corpus bao-x86 --engine smda --filter all

The harness refuses to print a comparison when a run did not actually work: a
sample whose engine errored, timed out or returned nothing is counted and, past
a threshold, aborts the report rather than averaging over failures.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bench.corpora import CORPORA, Sample, filterSamples, knownTruthDefect
from bench.integrity import checkCorpus
from bench.metrics import SampleScore, aggregate, scoreSample
from bench.report import renderRow, renderTable, writeResults
from smda.SmdaConfig import SmdaConfig

DEFAULT_ROOT = os.environ.get("SMDA_BENCH_GROUNDTRUTH", os.path.expanduser("~/groundtruth_data"))

_WORKER_ENGINE = None
_WORKER_KIND = None
_WORKER_OPTIONS: Dict[str, object] = {}


def buildEngine(kind: str, options: Dict[str, object]):
    if kind == "smda":
        from bench.engines.smda_engine import SmdaEngine

        return SmdaEngine(timeout=int(options.get("timeout", SmdaConfig.TIMEOUT)))
    if kind == "ghidra":
        from bench.engines.ghidra_engine import GhidraEngine

        return GhidraEngine(
            install_dir=str(options.get("ghidra_dir", "")),
            timeout=int(options.get("timeout", SmdaConfig.TIMEOUT)),
        )
    raise ValueError(f"unknown engine: {kind}")


def _initWorker(kind: str, options: Dict[str, object]) -> None:
    global _WORKER_ENGINE, _WORKER_KIND, _WORKER_OPTIONS
    _WORKER_KIND = kind
    _WORKER_OPTIONS = options
    _WORKER_ENGINE = buildEngine(kind, options)


def _runOne(sample: Sample) -> Tuple[str, List[int], Dict]:
    bitness = None if _WORKER_OPTIONS.get("bitness") == "auto" else sample.bitness
    starts, info = _WORKER_ENGINE.run(sample.path, sample.base_addr, bitness)
    return sample.name, sorted(starts), info


def runCorpus(
    kind: str,
    options: Dict[str, object],
    samples: List[Sample],
    jobs: int,
) -> Tuple[List[SampleScore], Dict[str, object], List[str]]:
    by_name = {sample.name: sample for sample in samples}
    scores: List[SampleScore] = []
    failures: List[str] = []
    if jobs > 1:
        with ProcessPoolExecutor(max_workers=jobs, initializer=_initWorker, initargs=(kind, options)) as pool:
            results = list(pool.map(_runOne, samples, chunksize=1))
    else:
        _initWorker(kind, options)
        results = [_runOne(sample) for sample in samples]
    for name, starts, info in results:
        sample = by_name[name]
        status = str(info.get("status", "unknown"))
        if status != "ok" or not starts:
            failures.append(f"{name}: status={status} detected={len(starts)} {str(info.get('message', ''))[:160]}")
        meta = dict(sample.meta)
        meta.update({"seconds": info.get("seconds"), "status": status})
        scores.append(scoreSample(name, sample.truth, set(starts), meta, sample.scored_ranges))
    engine_info = buildEngine(kind, options).describe()
    return scores, engine_info, failures


def parseArgs(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--corpus",
        default="all",
        help="comma-separated corpus keys, or 'all' ({})".format(",".join(sorted(CORPORA))),
    )
    parser.add_argument("--engine", default="smda", help="comma-separated engines: smda,ghidra")
    parser.add_argument("--filter", default="all", choices=["all", "paper"], help="optimization-level filter")
    parser.add_argument(
        "--mean",
        default="macro",
        choices=["macro", "geometric", "micro"],
        help="which aggregation the printed table shows; every one is saved to the result JSON",
    )
    parser.add_argument("--root", default=DEFAULT_ROOT, help="ground-truth root directory")
    parser.add_argument("--out", default="", help="directory to write per-run result JSON into")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument(
        "--timeout",
        type=int,
        default=SmdaConfig.TIMEOUT,
        help="per-sample engine timeout in seconds; the default is SMDA's own, so a run is comparable "
        "with anything measured at stock settings",
    )
    parser.add_argument("--ghidra-dir", default=os.environ.get("GHIDRA_INSTALL_DIR", ""))
    parser.add_argument(
        "--bitness",
        default="corpus",
        choices=["corpus", "auto"],
        help="'corpus' hands the engine the bitness the corpus declares, which is what the "
        "published comparisons did; 'auto' withholds it, which is what a caller analysing an "
        "unknown dump actually gets",
    )
    parser.add_argument(
        "--exclude-known-defects",
        action="store_true",
        help="drop samples whose ground truth is recorded as describing a different build; off by "
        "default because every published figure for these corpora includes them",
    )
    parser.add_argument("--limit", type=int, default=0, help="analyse at most this many samples per corpus")
    parser.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="tolerate this many failed samples before refusing to report",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parseArgs(argv)
    corpus_keys = sorted(CORPORA) if args.corpus == "all" else [key.strip() for key in args.corpus.split(",")]
    engines = [name.strip() for name in args.engine.split(",")]
    unknown = [key for key in corpus_keys if key not in CORPORA]
    if unknown:
        print(f"unknown corpus keys: {unknown}", file=sys.stderr)
        return 2
    options = {"timeout": args.timeout, "ghidra_dir": args.ghidra_dir, "bitness": args.bitness}

    rows: List[str] = []
    all_failures: List[str] = []
    summary: Dict[str, Dict] = {}
    for corpus_key in corpus_keys:
        corpus = CORPORA[corpus_key]
        try:
            samples = corpus.load(args.root)
        except FileNotFoundError as missing:
            print(f"[!] skipping {corpus_key}: {missing}", file=sys.stderr)
            continue
        samples = filterSamples(samples, args.filter)
        findings, integrity = checkCorpus(samples)
        print(
            f"[integrity] {corpus_key}: {integrity['checked']} of {integrity['total']} samples have a "
            f"section table to check against, {len(findings)} hold truth outside every executable section"
            + ("".join(f"\n             {f.name}: {f.outside}/{f.truth} ({f.share:.1f}%)" for f in findings)),
            file=sys.stderr,
        )
        if args.exclude_known_defects:
            excluded = [sample.name for sample in samples if knownTruthDefect(sample.name)]
            samples = [sample for sample in samples if not knownTruthDefect(sample.name)]
            for name in excluded:
                print(f"[integrity] excluding {name}: {knownTruthDefect(name)}", file=sys.stderr)
        if args.limit:
            samples = samples[: args.limit]
        if not samples:
            print(f"[!] skipping {corpus_key}: no samples after filter={args.filter}", file=sys.stderr)
            continue
        corpus_info = {
            "key": corpus.key,
            "title": corpus.title,
            "truth_source": corpus.truth_source,
            "n": len(samples),
            "filter": args.filter,
            "bitness_source": args.bitness,
            "truth_functions": sum(len(sample.truth) for sample in samples),
        }
        for engine_name in engines:
            scores, engine_info, failures = runCorpus(engine_name, options, samples, args.jobs)
            aggregated = aggregate(scores)
            all_failures.extend(f"[{engine_name}/{corpus_key}] {failure}" for failure in failures)
            rows.append(renderRow(corpus.title, engine_name, args.filter, aggregated, args.mean))
            summary[f"{engine_name}:{corpus_key}:{args.filter}"] = aggregated.toDict()
            if args.out:
                suffix = args.filter if args.bitness == "corpus" else f"{args.filter}-autobitness"
                path = writeResults(
                    args.out, corpus_key, engine_name, suffix, engine_info, corpus_info, scores, aggregated
                )
                print(f"[+] wrote {path}", file=sys.stderr)

    if not rows:
        print("[!] nothing measured; refusing to report", file=sys.stderr)
        return 1

    print()
    print(renderTable(rows, args.mean))
    print()
    total_truth = sum(entry["total_truth"] for entry in summary.values())
    total_detected = sum(entry["total_detected"] for entry in summary.values())
    print(
        f"[control] rows={len(rows)} truth_functions={total_truth} detected_functions={total_detected} "
        f"failed_samples={len(all_failures)}"
    )
    if all_failures:
        for failure in all_failures[:20]:
            print(f"[fail] {failure}", file=sys.stderr)
        if len(all_failures) > args.max_failures:
            print(
                f"[!] {len(all_failures)} sample(s) failed, above --max-failures={args.max_failures}; "
                "the table above is not a valid comparison",
                file=sys.stderr,
            )
            return 1
    if args.out:
        summary_path = os.path.join(args.out, f"summary_{args.filter}.json")
        with open(summary_path, "w", encoding="utf-8") as summary_file:
            json.dump(summary, summary_file, indent=2, sort_keys=True)
        print(f"[+] wrote {summary_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
