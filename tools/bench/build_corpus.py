#!/usr/bin/env python3
"""Build the corpora this repository generates from source.

Each family produces `<out>/<family>/binary/<name>` plus
`<out>/<family>/truth/<name>.json`, and a `manifest.json` recording every cell —
including the ones that failed, with the reason, so a matrix that quietly shrank
cannot be mistaken for one that passed.

    tools/bench/build_corpus.py --family native,go,rust --out ~/groundtruth_data/built
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: the checkout this script lives in; the ARM64 Mach-O corpus is carried in it
REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FAMILIES = ["native", "native-arm64", "go", "rust", "dotnet", "macho-arm64"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--family", default="all", help="comma-separated: " + ",".join(FAMILIES) + ", or 'all'")
    parser.add_argument(
        "--out",
        default=os.path.join(
            os.environ.get("SMDA_BENCH_GROUNDTRUTH", os.path.expanduser("~/groundtruth_data")), "built"
        ),
    )
    parser.add_argument("--cache", default=os.path.expanduser("~/corpus_src"), help="source download cache")
    parser.add_argument("--work", default=os.path.expanduser("~/corpus_work"), help="scratch build directory")
    parser.add_argument("--programs", default="", help="restrict the native family to these program keys")
    parser.add_argument("--toolchains", default="", help="restrict the native family to these toolchain keys")
    parser.add_argument("--dotnet", default=os.environ.get("DOTNET_ROOT", ""), help="dotnet SDK directory")
    parser.add_argument("--go", default="go", help="go binary to build with")
    args = parser.parse_args(argv)

    families = FAMILIES if args.family == "all" else [name.strip() for name in args.family.split(",")]
    unknown = [name for name in families if name not in FAMILIES]
    if unknown:
        print(f"unknown families: {unknown}", file=sys.stderr)
        return 2

    exit_code = 0
    for family in families:
        out_dir = os.path.join(args.out, family)
        os.makedirs(out_dir, exist_ok=True)
        work_dir = os.path.join(args.work, family)
        if family in ("native", "native-arm64"):
            from bench.builders.native import build as buildNative

            # native-arm64 is the same programs and variants through the AArch64 cross
            # compiler, kept in its own corpus so the x86 matrix stays comparable to the
            # figures already published for it rather than becoming a mixed population.
            requested = [key.strip() for key in args.toolchains.split(",")] if args.toolchains else None
            manifest = buildNative(
                out_dir,
                args.cache,
                work_dir,
                programs=[key.strip() for key in args.programs.split(",")] if args.programs else None,
                toolchains=requested or (["gcc-arm64"] if family == "native-arm64" else None),
                family=family,
            )
        elif family == "go":
            from bench.builders.go_family import build as buildGo

            manifest = buildGo(out_dir, work_dir, go_binary=args.go)
        elif family == "rust":
            from bench.builders.rust_family import build as buildRust

            manifest = buildRust(out_dir, work_dir)
        elif family == "macho-arm64":
            from bench.builders.macho_arm64 import buildMachoArm64

            manifest = buildMachoArm64(out_dir, REPOSITORY_ROOT)
        else:
            from bench.builders.dotnet_family import build as buildDotnet

            manifest = buildDotnet(out_dir, work_dir, dotnet_root=args.dotnet)
        print(f"[{family}] ok={manifest['ok']} failed={manifest['failed']} -> {out_dir}")
        for cell in manifest["cells"]:
            if cell.get("status") != "ok":
                print(f"  [skip] {json.dumps({k: v for k, v in cell.items() if k != 'error'}, sort_keys=True)}")
        if manifest["ok"] == 0:
            print(f"[!] {family}: no cell produced a binary; the corpus is empty", file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
