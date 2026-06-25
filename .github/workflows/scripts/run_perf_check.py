#!/usr/bin/env python3
import argparse
import json
import logging
import os
import statistics
import sys
import time

# Make the script runnable from a checkout without masking an explicit
# PYTHONPATH, which the workflow uses to benchmark base-repo/src vs src.
PROJECT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src"))
if PROJECT_SRC not in sys.path:
    sys.path.append(PROJECT_SRC)

try:
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig
except ImportError as e:
    print(f"Error importing SMDA. Make sure you run this script from the repository root: {e}", file=sys.stderr)
    sys.exit(1)


def _parse_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _iter_instruction_offsets(blocks):
    iterable = blocks.values() if isinstance(blocks, dict) else blocks
    for block in iterable:
        if isinstance(block, dict):
            instructions = block.get("instructions", block.get("insns", []))
        elif isinstance(block, list):
            instructions = block
        else:
            instructions = []
        for instruction in instructions:
            if isinstance(instruction, list) and instruction:
                yield _parse_int(instruction[0])
            elif isinstance(instruction, dict):
                yield _parse_int(instruction.get("offset", instruction.get("address")))


def _rooted_instruction_addrs(report_dict, functions):
    starts = set(functions)
    base_addr = report_dict.get("base_addr") or 0
    oep = report_dict.get("oep")
    oep_values = {
        candidate for candidate in (oep, base_addr + oep if oep is not None else None) if candidate is not None
    }

    def closure(seed_predicate):
        queue = [start for start, function in functions.items() if seed_predicate(function)]
        seen = set(queue)
        for start in queue:
            for target in functions[start]["outrefs"]:
                if target in starts and target not in seen:
                    seen.add(target)
                    queue.append(target)
        rooted = set()
        for start in seen:
            rooted.update(functions[start]["insns"])
        return rooted

    seeded = closure(
        lambda function: (
            function["start"] in oep_values
            or bool(function["insns"] & oep_values)
            or bool(function["is_exported"])
            or bool(function["function_name"])
        )
    )
    if seeded:
        return seeded, "seed-closure"

    xref_rooted = closure(lambda function: bool(function["inrefs"]))
    if xref_rooted:
        return xref_rooted, "xref-closure"

    all_insns = set()
    for function in functions.values():
        all_insns.update(function["insns"])
    return all_insns, "all-instructions"


def _instruction_sets(report):
    if report is None:
        return set(), set(), "empty"
    report_dict = report.toDict()
    xcfg = report_dict.get("xcfg", {})
    function_starts = {_parse_int(addr) for addr in xcfg}
    all_instruction_addrs = set()
    functions = {}
    for addr, function_data in xcfg.items():
        function_start = _parse_int(addr)
        blocks = function_data.get("blocks", {})
        function_insns = {offset for offset in _iter_instruction_offsets(blocks) if offset is not None}
        all_instruction_addrs.update(function_insns)

        outrefs = set()
        for targets in function_data.get("outrefs", {}).values():
            for target in targets:
                target_addr = _parse_int(target)
                if target_addr in function_starts:
                    outrefs.add(target_addr)

        functions[function_start] = {
            "start": function_start,
            "insns": function_insns,
            "outrefs": outrefs,
            "inrefs": function_data.get("inrefs", []),
            "is_exported": function_data.get("is_exported", False),
            "function_name": function_data.get("metadata", {}).get("function_name", ""),
        }

    rooted_instruction_addrs, rooted_mode = _rooted_instruction_addrs(report_dict, functions)
    return all_instruction_addrs, rooted_instruction_addrs, rooted_mode


def decrypt_binary(filepath):
    """Decrypts a XOR-obfuscated test fixture binary."""
    with open(filepath, "rb") as f:
        binary = f.read()
    decrypted = bytearray()
    for index, byte in enumerate(binary):
        if isinstance(byte, str):
            byte = ord(byte)
        decrypted.append(byte ^ (index % 256))
    return bytes(decrypted)


def run_benchmark(iterations, output_file):
    # Disable logging during benchmark to avoid stdout/file write overhead in the timed region
    logging.disable(logging.CRITICAL)
    config = SmdaConfig()
    config.PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    config.API_COLLECTION_FILES = {"winxp": os.path.join(config.PROJECT_ROOT, "data", "apiscout_winxp_prof_sp3.json")}

    fixtures = [
        {"name": "asprox", "filename": "asprox_0x008D0000_xored", "base_addr": 0x8D0000, "backend": "intel"},
        {"name": "cutwail", "filename": "cutwail_xored", "base_addr": 0x4000000, "backend": "intel"},
        {"name": "bashlite", "filename": "bashlite_xored", "base_addr": 0, "backend": "intel"},
        {"name": "blockblast", "filename": "blockblast_classes_xored", "base_addr": 0, "backend": "dalvik"},
        {"name": "komplex", "filename": "komplex_xored", "base_addr": 0, "backend": "intel"},
        {"name": "njrat", "filename": "njrat_xored", "base_addr": 0, "backend": "cil"},
        {"name": "pe_export", "filename": "pe_export_label_test_xored", "base_addr": 0, "backend": "intel"},
    ]

    results = {}
    tests_dir = os.path.join(config.PROJECT_ROOT, "tests")

    for fixture in fixtures:
        filepath = os.path.join(tests_dir, fixture["filename"])
        if not os.path.exists(filepath):
            print(f"Skipping {fixture['name']} - file not found: {filepath}", file=sys.stderr)
            continue

        print(f"Benchmarking {fixture['name']} ({fixture['backend']})...")
        binary_bytes = decrypt_binary(filepath)

        times = []
        report = None
        for _ in range(iterations):
            disasm = Disassembler(config, backend=fixture["backend"])
            start = time.perf_counter()
            if fixture["backend"] in ("dalvik", "cil"):
                report = disasm.disassembleUnmappedBuffer(binary_bytes)
            else:
                if fixture["base_addr"] != 0:
                    report = disasm.disassembleBuffer(binary_bytes, fixture["base_addr"])
                else:
                    report = disasm.disassembleUnmappedBuffer(binary_bytes)
            end = time.perf_counter()
            times.append(end - start)

        num_functions = report.num_functions if report else 0
        num_instructions = report.num_instructions if report else 0
        num_blocks = report.num_blocks if report else 0
        instruction_addrs, rooted_instruction_addrs, rooted_mode = _instruction_sets(report)

        # Extract function level details for correctness validation
        functions_meta = {}
        if report:
            for fn in report.getFunctions():
                functions_meta[hex(fn.offset)] = {
                    "num_blocks": len(list(fn.getBlocks())),
                    "num_instructions": len(list(fn.getInstructions())),
                }

        results[fixture["name"]] = {
            "backend": fixture["backend"],
            "execution_times": times,
            "median_time": statistics.median(times),
            "num_functions": num_functions,
            "num_instructions": num_instructions,
            "num_blocks": num_blocks,
            "instruction_addrs": sorted(instruction_addrs),
            "rooted_instruction_addrs": sorted(rooted_instruction_addrs),
            "rooted_instruction_mode": rooted_mode,
            "functions": functions_meta,
        }

    if output_file:
        # Create output directory if it doesn't exist
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, sort_keys=True)
        print(f"Benchmark results successfully written to {output_file}")
    else:
        print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SMDA performance and correctness checks on test fixtures")
    parser.add_argument("--iterations", type=int, default=3, help="Number of benchmark iterations")
    parser.add_argument("--output", type=str, default="", help="Path to write output JSON results")
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    run_benchmark(args.iterations, args.output)
