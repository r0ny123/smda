#!/usr/bin/env python3
"""SMDA Profiling and Performance Benchmarking CLI.

Provides benchmark timing, cross-git-ref regression comparison, and focused
CPU/Memory profiling.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Pattern matching for target discovery
DUMP_PATTERN = re.compile(r"dump7?_0x[0-9a-fA-F]{8,16}")
UNPACKED_PATTERN = re.compile(r"_unpacked(_x64)?$")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# Helper functions for instruction counting and file parsing
def is_instruction_record(value: Any) -> bool:
    if not isinstance(value, (list, tuple)) or len(value) < 3:
        return False
    address_like = isinstance(value[0], int) or (isinstance(value[0], str) and value[0].isdigit())
    mnemonic_like = any(isinstance(item, str) for item in value[2:4])
    return address_like and mnemonic_like


def count_instructions(value: Any) -> int:
    if is_instruction_record(value):
        return 1
    if isinstance(value, dict):
        return sum(count_instructions(item) for item in value.values())
    if isinstance(value, list):
        if value and all(is_instruction_record(item) for item in value):
            return len(value)
        return sum(count_instructions(item) for item in value)
    return 0


def get_binary_data(buffer: bytes, start: int, length: int) -> int:
    formats = {2: "H", 4: "I", 8: "Q"}
    if length not in formats:
        raise RuntimeError("Unsupported data length")
    return struct.unpack(formats[length], buffer[start : start + length])[0]


def get_word(buffer: bytes, start: int) -> int:
    return get_binary_data(buffer, start, 2)


def get_dword(buffer: bytes, start: int) -> int:
    return get_binary_data(buffer, start, 4)


def get_pe_offset(content: bytes) -> int:
    if len(content) >= 0x40:
        return get_word(content, 0x3C)
    raise RuntimeError("Buffer too small to extract PE offset")


def check_bitness(content: bytes) -> int | None:
    try:
        pe_offset = get_pe_offset(content)
    except RuntimeError:
        return None
    if pe_offset and len(content) >= pe_offset + 6:
        machine = get_word(content, pe_offset + 4)
        return {0x14C: 32, 0x8664: 64}.get(machine, 0)
    return None


def parse_base_addr(filename: str) -> int:
    match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})", filename)
    return int(match.group("base_addr"), 16) if match else 0


def get_bitness_from_filename(filename: str) -> int:
    match = re.search(r"0x(?P<base_addr>[0-9a-fA-F]{8,16})", filename)
    if not match:
        return 0
    return 32 if len(match.group("base_addr")) == 8 else 64


def infer_mode(filename: str) -> str:
    return "dump" if DUMP_PATTERN.search(filename) else "file"


def discover_targets(corpus_dir: Path, limit: int = 0) -> list[dict[str, Any]]:
    targets = []
    for root, dirs, files in os.walk(corpus_dir):
        dirs[:] = [item for item in dirs if item not in {".git", "__MACOSX"}]
        root_path = Path(root)
        for filename in sorted(files):
            if filename.startswith("."):
                continue
            if not (DUMP_PATTERN.search(filename) or UNPACKED_PATTERN.search(filename)):
                continue
            filepath = root_path / filename
            targets.append(
                {
                    "filename": filename,
                    "path": str(filepath),
                    "mode": infer_mode(filename),
                    "size_bytes": filepath.stat().st_size,
                }
            )
    targets = sorted(targets, key=lambda item: item["filename"])
    return targets[:limit] if limit > 0 else targets


def import_smda() -> Any:
    import importlib.util

    if importlib.util.find_spec("smda") is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
    from smda.Disassembler import Disassembler

    return Disassembler()


def disassemble_target(disassembler: Any, target: dict[str, Any]) -> dict[str, Any]:
    input_path = Path(target["path"])
    started = time.perf_counter()
    report = None
    error = None
    try:
        if target["mode"] == "dump":
            content = input_path.read_bytes()
            base_addr = parse_base_addr(target["filename"])
            bitness = get_bitness_from_filename(target["filename"])
            report = disassembler.disassembleBuffer(content, base_addr, bitness)
        else:
            report = disassembler.disassembleFile(str(input_path))
    except Exception as exc:
        error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(limit=10),
        }
    duration = time.perf_counter() - started
    result = {
        "filename": target["filename"],
        "mode": target["mode"],
        "size_bytes": target["size_bytes"],
        "duration": duration,
        "status": "exception" if error else "ok",
        "num_functions": 0,
        "num_instructions": 0,
    }
    if error:
        result["error"] = error
    if report is not None:
        report_dict = report.toDict()
        result.update(
            {
                "status": report_dict.get("status", result["status"]),
                "num_functions": len(report_dict.get("xcfg") or {}),
                "num_instructions": count_instructions(report_dict.get("xcfg") or {}),
            }
        )
    return result


def benchmark_corpus(corpus_dir: Path, limit: int, warmups: int, iterations: int) -> dict[str, Any]:
    targets = discover_targets(corpus_dir, limit)
    if not targets:
        raise ValueError(f"No benchmark targets found in {corpus_dir}")

    disassembler = import_smda()
    results = []

    print(f"Starting benchmark over {len(targets)} targets (warmups={warmups}, iterations={iterations})...", flush=True)

    for index, target in enumerate(targets, start=1):
        # Warmup phase
        for _ in range(warmups):
            disassemble_target(disassembler, target)

        # Timed iterations
        durations = []
        last_res = {}
        for _ in range(iterations):
            last_res = disassemble_target(disassembler, target)
            durations.append(last_res["duration"])

        # Calculate statistics
        med_duration = statistics.median(durations)
        min_duration = min(durations)
        max_duration = max(durations)
        mean_duration = statistics.mean(durations)
        stdev_duration = statistics.stdev(durations) if len(durations) > 1 else 0.0

        last_res.update(
            {
                "duration": med_duration,
                "min_duration": min_duration,
                "max_duration": max_duration,
                "mean_duration": mean_duration,
                "stdev_duration": stdev_duration,
                "durations": durations,
            }
        )
        results.append(last_res)

        print(
            f"[{index}/{len(targets)}] {target['filename']} "
            f"status={last_res['status']} median_time={med_duration:.4f}s funcs={last_res['num_functions']}",
            flush=True,
        )

    # Compute aggregate stats
    total_execution_time = sum(item["duration"] for item in results)
    total_functions = sum(item["num_functions"] for item in results)
    total_instructions = sum(item["num_instructions"] for item in results)
    total_size = sum(item["size_bytes"] for item in results)

    summary = {
        "generated_at": utc_now_iso(),
        "target_count": len(targets),
        "total_execution_time_seconds": total_execution_time,
        "total_functions": total_functions,
        "total_instructions": total_instructions,
        "total_input_bytes": total_size,
        "functions_per_second": total_functions / total_execution_time if total_execution_time > 0 else 0.0,
        "instructions_per_second": total_instructions / total_execution_time if total_execution_time > 0 else 0.0,
        "mb_per_second": (total_size / 1048576) / total_execution_time if total_execution_time > 0 else 0.0,
        "results": results,
    }
    return summary


def cmd_benchmark(args: argparse.Namespace) -> int:
    summary = benchmark_corpus(args.corpus_dir, args.limit, args.warmups, args.iterations)
    args.output_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\nBenchmark Summary:")
    print(f"  Targets processed: {summary['target_count']}")
    print(f"  Total Functions:   {summary['total_functions']}")
    print(f"  Total Instructions:{summary['total_instructions']}")
    print(f"  Total Execution:   {summary['total_execution_time_seconds']:.3f}s")
    print(f"  Throughput:        {summary['functions_per_second']:.2f} funcs/sec")
    print(f"                     {summary['instructions_per_second']:.2f} instrs/sec")
    print(f"                     {summary['mb_per_second']:.2f} MB/sec")
    print(f"Results saved to: {args.output_json}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    print(f"Comparing git refs: base='{args.base}' vs target='{args.target}'...", flush=True)

    # Find the repo root path
    repo_root = Path(__file__).resolve().parent

    temp_dir = tempfile.mkdtemp(prefix="smda-compare-")
    temp_dir_path = Path(temp_dir)
    print(f"Created temporary workspace at {temp_dir_path}")

    base_results_path = temp_dir_path / "base_results.json"
    target_results_path = temp_dir_path / "target_results.json"

    # Define temporary worktree paths
    base_wt = temp_dir_path / "base_repo"
    target_wt = temp_dir_path / "target_repo"

    try:
        # Create worktrees
        print(f"Adding worktree for base: {args.base}")
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "add", "--detach", str(base_wt), args.base],
            check=True,
            capture_output=True,
        )

        print(f"Adding worktree for target: {args.target}")
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "add", "--detach", str(target_wt), args.target],
            check=True,
            capture_output=True,
        )

        # Setup virtual environments
        base_venv = base_wt / "venv"
        target_venv = target_wt / "venv"

        print("Provisioning base venv...")
        subprocess.run([sys.executable, "-m", "venv", str(base_venv)], check=True)
        subprocess.run(
            [str(base_venv / "bin" / "pip"), "install", "--upgrade", "pip", "setuptools", "wheel"],
            check=True,
            capture_output=True,
        )
        subprocess.run([str(base_venv / "bin" / "pip"), "install", str(base_wt)], check=True, capture_output=True)

        print("Provisioning target venv...")
        subprocess.run([sys.executable, "-m", "venv", str(target_venv)], check=True)
        subprocess.run(
            [str(target_venv / "bin" / "pip"), "install", "--upgrade", "pip", "setuptools", "wheel"],
            check=True,
            capture_output=True,
        )
        subprocess.run([str(target_venv / "bin" / "pip"), "install", str(target_wt)], check=True, capture_output=True)

        # Run benchmark on base ref
        print("Running benchmark on base ref...")
        base_run_cmd = [
            str(base_venv / "bin" / "python"),
            __file__,
            "benchmark",
            str(args.corpus_dir),
            "--warmups",
            str(args.warmups),
            "--iterations",
            str(args.iterations),
            "--limit",
            str(args.limit),
            "--output-json",
            str(base_results_path),
        ]
        subprocess.run(base_run_cmd, check=True)

        # Run benchmark on target ref
        print("Running benchmark on target ref...")
        target_run_cmd = [
            str(target_venv / "bin" / "python"),
            __file__,
            "benchmark",
            str(args.corpus_dir),
            "--warmups",
            str(args.warmups),
            "--iterations",
            str(args.iterations),
            "--limit",
            str(args.limit),
            "--output-json",
            str(target_results_path),
        ]
        subprocess.run(target_run_cmd, check=True)

    finally:
        # Cleanup worktrees
        print("Cleaning up git worktrees...")
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(base_wt)], capture_output=True
        )
        subprocess.run(
            ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(target_wt)], capture_output=True
        )
        # We delete temp workspace files later, but keep the outputs we need for rendering

    # Load results
    base_summary = json.loads(base_results_path.read_text(encoding="utf-8"))
    target_summary = json.loads(target_results_path.read_text(encoding="utf-8"))

    # Cleanup temp directory completely
    shutil.rmtree(temp_dir)

    # Compare results
    base_results_map = {item["filename"]: item for item in base_summary["results"]}
    target_results_map = {item["filename"]: item for item in target_summary["results"]}
    common_filenames = sorted(set(base_results_map.keys()) & set(target_results_map.keys()))

    lines = [
        "# SMDA Performance Regression Comparison",
        "",
        f"Generated: `{utc_now_iso()}`",
        f"Base Ref: `{args.base}`",
        f"Target Ref: `{args.target}`",
        "",
        "## Overall Comparison Summary",
        "",
        "| Metric | Base | Target | Delta | Speedup % |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]

    base_med_time = statistics.median(item["duration"] for item in base_summary["results"])
    target_med_time = statistics.median(item["duration"] for item in target_summary["results"])
    time_diff = target_med_time - base_med_time
    time_reduction_pct = ((base_med_time - target_med_time) / base_med_time * 100) if base_med_time else 0.0

    lines.append(
        f"| Median Execution Time | {base_med_time:.4f}s | {target_med_time:.4f}s | {time_diff:+.4f}s | {time_reduction_pct:+.2f}% |"
    )
    lines.append(
        f"| Total Functions | {base_summary['total_functions']} | {target_summary['total_functions']} | {target_summary['total_functions'] - base_summary['total_functions']:+} | |"
    )
    lines.append(
        f"| Total Instructions | {base_summary['total_instructions']} | {target_summary['total_instructions']} | {target_summary['total_instructions'] - base_summary['total_instructions']:+} | |"
    )
    lines.append(
        f"| Functions / Sec | {base_summary['functions_per_second']:.2f} | {target_summary['functions_per_second']:.2f} | {target_summary['functions_per_second'] - base_summary['functions_per_second']:+.2f} | |"
    )
    lines.append(
        f"| Instructions / Sec | {base_summary['instructions_per_second']:.2f} | {target_summary['instructions_per_second']:.2f} | {target_summary['instructions_per_second'] - base_summary['instructions_per_second']:+.2f} | |"
    )
    lines.append(
        f"| Throughput MB / Sec | {base_summary['mb_per_second']:.2f} | {target_summary['mb_per_second']:.2f} | {target_summary['mb_per_second'] - base_summary['mb_per_second']:+.2f} | |"
    )

    lines.extend(
        [
            "",
            "## Per-File Comparison Details",
            "",
            "| Filename | Base Median Time | Target Median Time | Time Delta | Speedup % | Base Funcs | Target Funcs | Funcs Delta |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for filename in common_filenames:
        base_item = base_results_map[filename]
        target_item = target_results_map[filename]
        b_med = base_item["duration"]
        t_med = target_item["duration"]
        t_diff = t_med - b_med
        t_pct = ((b_med - t_med) / b_med * 100) if b_med else 0.0
        lines.append(
            f"| {filename} | {b_med:.4f}s | {t_med:.4f}s | {t_diff:+.4f}s | {t_pct:+.2f}% | {base_item['num_functions']} | {target_item['num_functions']} | {target_item['num_functions'] - base_item['num_functions']:+} |"
        )

    report_md = "\n".join(lines) + "\n"
    args.output_md.write_text(report_md, encoding="utf-8")
    print(f"\nComparison report saved to: {args.output_md}")
    print(report_md)
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    print(f"Profiling target: '{args.binary_path}' using '{args.profiler}'...", flush=True)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    mode = args.mode or infer_mode(args.binary_path.name)
    binary_path = args.binary_path

    # Read binary contents for base_addr / bitness parsing
    content = binary_path.read_bytes()
    base_addr = parse_base_addr(binary_path.name)
    bitness = get_bitness_from_filename(binary_path.name)

    if args.profiler == "none":
        disassembler = import_smda()
        started = time.perf_counter()
        if mode == "dump":
            disassembler.disassembleBuffer(content, base_addr, bitness)
        else:
            disassembler.disassembleFile(str(binary_path))
        print(f"Simple disassembly took {time.perf_counter() - started:.4f}s")
        return 0

    elif args.profiler == "cprofile":
        import cProfile
        import pstats

        disassembler = import_smda()

        prof = cProfile.Profile()
        prof.enable()
        if mode == "dump":
            disassembler.disassembleBuffer(content, base_addr, bitness)
        else:
            disassembler.disassembleFile(str(binary_path))
        prof.disable()

        prof_file = output_dir / "cprofile.prof"
        txt_file = output_dir / "cprofile_top30.txt"

        pstats.Stats(prof).sort_stats(pstats.SortKey.CUMULATIVE).dump_stats(str(prof_file))
        with txt_file.open("w", encoding="utf-8") as f:
            stats = pstats.Stats(prof, stream=f)
            stats.strip_dirs().sort_stats("cumulative").print_stats(30)

        print(f"cProfile results saved under: {output_dir}")
        return 0

    elif args.profiler == "py-spy":
        # Launch py-spy as a subprocess targetting this same profile.py profile command with none
        svg_file = output_dir / "py_spy.svg"
        native_args = ["--native"] if platform.system() == "Linux" else []
        cmd = [
            "py-spy",
            "record",
            *native_args,
            "-o",
            str(svg_file),
            "--",
            sys.executable,
            __file__,
            "profile",
            str(binary_path),
            "--profiler",
            "none",
            "--mode",
            mode,
        ]
        print(f"Running command: {' '.join(cmd)}")
        proc = subprocess.run(cmd)
        if proc.returncode == 0:
            print(f"py-spy flamegraph saved to: {svg_file}")
            return 0
        else:
            print(f"py-spy exited with error code {proc.returncode}")
            return proc.returncode

    elif args.profiler == "line-profiler":
        try:
            from line_profiler import LineProfiler
        except ImportError:
            print("Error: line_profiler is not installed. Please install line-profiler first.", file=sys.stderr)
            return 1

        disassembler = import_smda()
        from smda.intel.IntelDisassembler import IntelDisassembler

        lp = LineProfiler()
        lp.add_function(IntelDisassembler.analyzeFunction)
        try:
            from smda.intel.FunctionCandidateManager import FunctionCandidateManager

            lp.add_function(FunctionCandidateManager.isFunctionCandidate)
        except ImportError:
            pass

        lp_wrapper = lp(disassembler.disassembleFile if mode == "file" else disassembler.disassembleBuffer)
        if mode == "file":
            lp_wrapper(str(binary_path))
        else:
            lp_wrapper(content, base_addr, bitness)

        txt_file = output_dir / "line_profiler.txt"
        with txt_file.open("w", encoding="utf-8") as f:
            lp.print_stats(stream=f)

        print(f"line_profiler results saved to: {txt_file}")
        return 0

    elif args.profiler == "memray":
        try:
            import memray
        except ImportError:
            print("Error: memray is not installed. Please install memray first.", file=sys.stderr)
            return 1

        disassembler = import_smda()
        bin_file = output_dir / "memray.bin"
        html_file = output_dir / "memray_flamegraph.html"

        print("Recording allocations with memray...")
        with memray.Tracker(str(bin_file), native_traces=True):
            if mode == "file":
                disassembler.disassembleFile(str(binary_path))
            else:
                disassembler.disassembleBuffer(content, base_addr, bitness)

        print("Generating flamegraph HTML...")
        subprocess.run([sys.executable, "-m", "memray", "flamegraph", "--force", "-o", str(html_file), str(bin_file)])
        print(f"memray results saved under: {output_dir}")
        return 0

    elif args.profiler == "tracemalloc":
        import tracemalloc

        disassembler = import_smda()

        tracemalloc.start(25)
        snapshot1 = tracemalloc.take_snapshot()

        if mode == "file":
            disassembler.disassembleFile(str(binary_path))
        else:
            disassembler.disassembleBuffer(content, base_addr, bitness)

        snapshot2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot2.compare_to(snapshot1, "lineno")
        txt_file = output_dir / "tracemalloc.txt"
        with txt_file.open("w", encoding="utf-8") as f:
            f.write("Top 50 memory allocation differences:\n")
            for stat in top_stats[:50]:
                f.write(str(stat) + "\n")

        print(f"tracemalloc results saved to: {txt_file}")
        return 0

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Benchmark timing across a folder of binaries.")
    bench_parser.add_argument("corpus_dir", type=Path, help="Directory containing binaries.")
    bench_parser.add_argument("--warmups", type=int, default=1, help="Warm-up cycles per target.")
    bench_parser.add_argument("--iterations", type=int, default=3, help="Timed iterations per target.")
    bench_parser.add_argument("--limit", type=int, default=0, help="Limit processed targets.")
    bench_parser.add_argument(
        "--output-json", type=Path, default=Path("benchmark_results.json"), help="Output JSON path."
    )
    bench_parser.set_defaults(func=cmd_benchmark)

    # compare
    comp_parser = subparsers.add_parser("compare", help="Compare two git refs in isolated worktrees.")
    comp_parser.add_argument("corpus_dir", type=Path, help="Directory containing binaries.")
    comp_parser.add_argument("--base", required=True, help="Base git ref (e.g. master).")
    comp_parser.add_argument("--target", required=True, help="Target git ref (e.g. HEAD).")
    comp_parser.add_argument("--warmups", type=int, default=1, help="Warm-up cycles.")
    comp_parser.add_argument("--iterations", type=int, default=3, help="Timed iterations.")
    comp_parser.add_argument("--limit", type=int, default=0, help="Limit processed targets.")
    comp_parser.add_argument(
        "--output-md", type=Path, default=Path("comparison_report.md"), help="Output Markdown report path."
    )
    comp_parser.set_defaults(func=cmd_compare)

    # profile
    prof_parser = subparsers.add_parser("profile", help="Profile CPU or Memory on a single binary.")
    prof_parser.add_argument("binary_path", type=Path, help="Path to binary to profile.")
    prof_parser.add_argument(
        "--profiler",
        choices=["py-spy", "cprofile", "line-profiler", "memray", "tracemalloc", "none"],
        required=True,
        help="Profiler engine to use.",
    )
    prof_parser.add_argument("--output-dir", type=Path, default=Path("profiles"), help="Output directory.")
    prof_parser.add_argument("--mode", choices=["file", "dump"], help="Override disassembly mode.")
    prof_parser.set_defaults(func=cmd_profile)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
