#!/usr/bin/env bash
# Build every corpus this repository generates, in one pass, logging each family.
#
#   SMDA_BENCH_GROUNDTRUTH=~/groundtruth_data tools/bench/build_all.sh
#
# Each family writes a manifest recording the cells it attempted and why any failed,
# so a matrix that quietly shrank cannot be mistaken for one that passed.
set -u

ROOT="${SMDA_BENCH_GROUNDTRUTH:-$HOME/groundtruth_data}"
PYTHON="${PYTHON:-.venv/bin/python}"
LOGS="${BUILD_LOG_DIR:-$HOME/corpus_build_logs}"
mkdir -p "$LOGS"

status=0
for family in native go rust dotnet macho-arm64; do
    echo "=== building $family ==="
    "$PYTHON" tools/bench/build_corpus.py --family "$family" --out "$ROOT/built" \
        > "$LOGS/$family.log" 2>&1
    code=$?
    tail -3 "$LOGS/$family.log"
    echo "[$family] exit=$code log=$LOGS/$family.log"
    [ "$code" -eq 0 ] || status=1
done
exit "$status"
