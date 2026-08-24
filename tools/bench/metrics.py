"""Function-start detection metrics.

A detected function start counts as a true positive only when it matches a
ground-truth start exactly; the corpora this harness reads label starts, not
extents, so a tolerance window would score a different question.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class SampleScore:
    name: str
    truth: int
    detected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    meta: Dict[str, object] = field(default_factory=dict)

    @property
    def ppv(self) -> Optional[float]:
        """Precision; 0 when the engine returned nothing, not undefined.

        An engine that recovers no function at all has failed on that binary,
        and averaging it away would let a crash flatter the mean.
        """
        if self.detected == 0:
            return None if self.truth == 0 else 0.0
        return 100.0 * self.true_positives / self.detected

    @property
    def tpr(self) -> Optional[float]:
        #: undefined only when the binary has no ground truth to recall
        if self.truth == 0:
            return None
        return 100.0 * self.true_positives / self.truth

    @property
    def f1(self) -> Optional[float]:
        ppv, tpr = self.ppv, self.tpr
        if ppv is None or tpr is None:
            return None
        if ppv + tpr == 0:
            return 0.0
        return 2 * ppv * tpr / (ppv + tpr)

    def toDict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "truth": self.truth,
            "detected": self.detected,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "ppv": self.ppv,
            "tpr": self.tpr,
            "f1": self.f1,
            "meta": self.meta,
        }


def _inside(address: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def scoreSample(
    name: str,
    truth: Set[int],
    detected: Set[int],
    meta: Optional[Dict] = None,
    scored_ranges: Optional[List[Tuple[int, int]]] = None,
) -> SampleScore:
    """Score one binary, optionally only where the corpus' oracle has authority.

    `scored_ranges` names the address ranges the ground truth covers. A detection
    outside them is neither a true nor a false positive: the corpus says nothing
    there, and counting it as an error would charge the engine for the oracle's
    coverage. The number dropped is recorded, because a scored region that quietly
    shrank reads exactly like precision that rose.
    """
    recorded = dict(meta or {})
    if scored_ranges:
        in_scope = {address for address in detected if _inside(address, scored_ranges)}
        recorded["outside_scored_region"] = len(detected) - len(in_scope)
        detected = in_scope
    true_positives = truth & detected
    return SampleScore(
        name=name,
        truth=len(truth),
        detected=len(detected),
        true_positives=len(true_positives),
        false_positives=len(detected - truth),
        false_negatives=len(truth - detected),
        meta=recorded,
    )


@dataclass
class Aggregate:
    """Three aggregations of the same per-sample scores.

    `macro_*` is the arithmetic mean of the per-binary rates and is what the
    project's own accuracy tables report. `geo_*` is the geometric mean, which
    is what the dissertation uses so that an outlier binary is penalised rather
    than averaged away — a replication of its tables has to compare against
    this one. `micro_*` pools the counts and answers "how many mistakes in
    total" rather than "how does a typical binary score"; all three diverge
    whenever binary sizes do.
    """

    n: int
    macro_ppv: Optional[float]
    macro_tpr: Optional[float]
    macro_f1: Optional[float]
    geo_ppv: Optional[float]
    geo_tpr: Optional[float]
    geo_f1: Optional[float]
    micro_ppv: Optional[float]
    micro_tpr: Optional[float]
    micro_f1: Optional[float]
    total_truth: int
    total_detected: int
    total_tp: int
    total_fp: int
    total_fn: int
    stdev_f1: Optional[float]

    def toDict(self) -> Dict[str, object]:
        return {
            "n": self.n,
            "macro_ppv": self.macro_ppv,
            "macro_tpr": self.macro_tpr,
            "macro_f1": self.macro_f1,
            "geo_ppv": self.geo_ppv,
            "geo_tpr": self.geo_tpr,
            "geo_f1": self.geo_f1,
            "micro_ppv": self.micro_ppv,
            "micro_tpr": self.micro_tpr,
            "micro_f1": self.micro_f1,
            "total_truth": self.total_truth,
            "total_detected": self.total_detected,
            "total_tp": self.total_tp,
            "total_fp": self.total_fp,
            "total_fn": self.total_fn,
            "stdev_f1": self.stdev_f1,
        }


def _mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return sum(values) / len(values)


def _geomean(values: List[float]) -> Optional[float]:
    """Geometric mean, with a zero anywhere collapsing the result to zero.

    A binary that scored 0 is a total failure on that binary, and the paper's
    choice of this mean is precisely so such a case cannot be averaged away.
    """
    if not values:
        return None
    if any(value <= 0 for value in values):
        return 0.0
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / (len(values) - 1))


def _rate(numerator: int, denominator: int) -> Optional[float]:
    if denominator == 0:
        return None
    return 100.0 * numerator / denominator


def aggregate(scores: Iterable[SampleScore]) -> Aggregate:
    scores = list(scores)
    total_tp = sum(score.true_positives for score in scores)
    total_fp = sum(score.false_positives for score in scores)
    total_fn = sum(score.false_negatives for score in scores)
    micro_ppv = _rate(total_tp, total_tp + total_fp)
    micro_tpr = _rate(total_tp, total_tp + total_fn)
    micro_f1 = None
    if micro_ppv is not None and micro_tpr is not None and micro_ppv + micro_tpr > 0:
        micro_f1 = 2 * micro_ppv * micro_tpr / (micro_ppv + micro_tpr)
    per_sample_f1 = [score.f1 for score in scores if score.f1 is not None]
    per_sample_ppv = [score.ppv for score in scores if score.ppv is not None]
    per_sample_tpr = [score.tpr for score in scores if score.tpr is not None]
    return Aggregate(
        n=len(scores),
        macro_ppv=_mean(per_sample_ppv),
        macro_tpr=_mean(per_sample_tpr),
        macro_f1=_mean(per_sample_f1),
        geo_ppv=_geomean(per_sample_ppv),
        geo_tpr=_geomean(per_sample_tpr),
        geo_f1=_geomean(per_sample_f1),
        micro_ppv=micro_ppv,
        micro_tpr=micro_tpr,
        micro_f1=micro_f1,
        total_truth=sum(score.truth for score in scores),
        total_detected=sum(score.detected for score in scores),
        total_tp=total_tp,
        total_fp=total_fp,
        total_fn=total_fn,
        stdev_f1=_stdev(per_sample_f1),
    )
