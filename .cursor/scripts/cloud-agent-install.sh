#!/usr/bin/env bash
set -euo pipefail

export CXX=g++ CC=gcc

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip "setuptools>=64.0.0,<83.1.0" "wheel>=0.47.0"
python -m pip install -e ".[dev]"
