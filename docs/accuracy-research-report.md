# Function-detection accuracy: findings, fixes, and what is left

A research report on how well SMDA recovers function start addresses, what was measured, what was
changed, what was measured *worse*, and what remains — with the ceiling for each remaining item.

Companion documents: `docs/accuracy-research-log.md` is the running record with every measurement
in the order it happened; `docs/paper-replication.md` records the origin evaluation's metric
definitions and corpus composition; `tools/bench/README.md` documents the harness.

Every number in this report states the corpus it was measured on, the sample count `n`, and the
optimization filter. A figure without all three is not comparable with anything.

## 1. What was built

A benchmark that runs from a clean checkout: `tools/bench/run.py` measures one or more engines over
one or more ground-truth corpora; `tools/bench/summarize.py` re-aggregates and diffs saved results
without re-running an engine and fails a comparison in which recall dropped;
`tools/bench/build_corpus.py` builds the corpora that no public dataset covers.

It was validated before it was used for anything: SMDA 4.4.1 from PyPI reproduces a previously
recorded five-corpus measurement to three decimals under both optimization filters, with the
imported module's path written into every result file so the tree that ran is not in doubt.

