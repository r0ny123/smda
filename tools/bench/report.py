"""Result serialization and table rendering for the accuracy benchmark."""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional, Sequence

from bench.metrics import Aggregate, SampleScore

#: which Aggregate fields each aggregation names, so a caller picks a mean once
MEAN_FIELDS = {
    "macro": ("macro_ppv", "macro_tpr", "macro_f1"),
    "geometric": ("geo_ppv", "geo_tpr", "geo_f1"),
    "micro": ("micro_ppv", "micro_tpr", "micro_f1"),
}


def _fmt(value: Optional[float], width: int = 7, digits: int = 3) -> str:
    if value is None:
        return "-".rjust(width)
    return f"{value:{width}.{digits}f}"


def header(mean: str = "macro") -> str:
    label = {"macro": "arith", "geometric": "geo", "micro": "micro"}[mean]
    return (
        f"{'config':<34} {'engine':<10} {'filter':<7} {'n':>4} "
        f"{'PPV/' + label:>8} {'TPR/' + label:>8} {'F1/' + label:>8} {'TP':>8} {'FP':>8} {'FN':>8}"
    )


ROW_HEADER = header()


def renderRow(title: str, engine: str, opt_filter: str, aggregate: Aggregate, mean: str = "macro") -> str:
    ppv, tpr, f1 = (getattr(aggregate, name) for name in MEAN_FIELDS[mean])
    return (
        f"{title:<34} {engine:<10} {opt_filter:<7} {aggregate.n:>4} "
        f"{_fmt(ppv, 8)} {_fmt(tpr, 8)} {_fmt(f1, 8)} "
        f"{aggregate.total_tp:>8} {aggregate.total_fp:>8} {aggregate.total_fn:>8}"
    )


def renderTable(rows: Sequence[str], mean: str = "macro") -> str:
    head = header(mean)
    return "\n".join([head, "-" * len(head), *rows])


def writeResults(
    out_dir: str,
    corpus_key: str,
    engine_name: str,
    opt_filter: str,
    engine_info: Dict[str, object],
    corpus_info: Dict[str, object],
    scores: List[SampleScore],
    aggregate: Aggregate,
) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{engine_name}_{corpus_key}_{opt_filter}.json")
    payload = {
        "corpus": corpus_info,
        "engine": engine_info,
        "filter": opt_filter,
        "aggregate": aggregate.toDict(),
        "samples": [score.toDict() for score in scores],
    }
    with open(path, "w", encoding="utf-8") as result_file:
        json.dump(payload, result_file, indent=2, sort_keys=True)
    return path
