#!/usr/bin/env python
"""Validate SMDA against Malpedia macOS AArch64 Mach-O ``*_unpacked`` samples.

The script is intended to run inside a hardened GitHub Actions container. It
never executes samples. Raw sample bytes are only read for parsing and optional
XOR-obfuscated fixture export.
"""

import argparse
import hashlib
import json
import os
import signal
import struct
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path

from smda.aarch64.definitions import BTI_PROLOGUES, INSTRUCTION_SIZE, PAC_PROLOGUES
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.MachoFileLoader import MachoFileLoader
from smda.utility.MemoryFileLoader import MemoryFileLoader

MAX_IMAGE_SIZE = SmdaConfig.MAX_IMAGE_SIZE
MAX_FIXTURE_COUNT = 6
MAX_TOTAL_FIXTURE_BYTES = 10 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 30
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
THIN_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}
FAT_MACHO_MAGICS = {
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
MACOS_HINTS = (
    "osx",
    "macos",
    "macho",
    "darwin",
    "apple_macos",
    "apple macos",
    "mac os",
)
SKIP_DIRS = {
    ".git",
    "modules",
    "yara",
    "rules",
    "docs",
    "doc",
    "images",
    "resources",
}


class SampleTimeout(RuntimeError):
    pass


@dataclass
class Candidate:
    path: Path
    relative_path: str
    family: str
    folder_reason: str


def _timeout_handler(_signum, _frame):
    raise SampleTimeout("sample analysis timed out")


def _with_timeout(seconds, func, *args):
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(seconds)
    try:
        return func(*args)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def xor_fixture(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def family_from_relative(relative_path):
    parts = Path(relative_path).parts
    return parts[0] if parts else ""


def is_under_skipped_dir(path):
    return any(part in SKIP_DIRS for part in path.parts)


def load_macos_metadata_dirs(corpus_root):
    macos_dirs = set()
    metadata_names = {"meta.json", "metadata.json", "config.json", "README.md", "README.txt"}
    for root, dirs, files in os.walk(corpus_root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        root_path = Path(root)
        for filename in files:
            if filename not in metadata_names and not filename.endswith((".json", ".yaml", ".yml")):
                continue
            metadata_path = root_path / filename
            try:
                if metadata_path.stat().st_size > 2 * 1024 * 1024:
                    continue
                text = metadata_path.read_text(errors="ignore").lower()
            except OSError:
                continue
            if any(hint in text for hint in MACOS_HINTS):
                macos_dirs.add(root_path)
                macos_dirs.add(root_path.parent)
    return macos_dirs


def is_macos_candidate_folder(path, corpus_root, macos_metadata_dirs):
    relative = path.relative_to(corpus_root)
    lowered = str(relative).lower()
    if any(hint in lowered for hint in MACOS_HINTS):
        return True, "path_hint"
    if any(parent in macos_metadata_dirs for parent in [path, *path.parents]):
        return True, "metadata_hint"
    return False, ""


def iter_candidates(corpus_root):
    macos_metadata_dirs = load_macos_metadata_dirs(corpus_root)
    folder_count = 0
    skipped_folder_count = 0
    for root, dirs, files in os.walk(corpus_root):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        root_path = Path(root)
        if is_under_skipped_dir(root_path.relative_to(corpus_root)):
            continue
        folder_count += 1
        folder_ok, folder_reason = is_macos_candidate_folder(root_path, corpus_root, macos_metadata_dirs)
        if not folder_ok:
            skipped_folder_count += 1
            continue
        for filename in sorted(files):
            if not filename.endswith("_unpacked"):
                continue
            path = root_path / filename
            try:
                if not path.is_file() or path.is_symlink():
                    continue
            except OSError:
                continue
            relative_path = str(path.relative_to(corpus_root))
            yield Candidate(
                path=path,
                relative_path=relative_path,
                family=family_from_relative(relative_path),
                folder_reason=folder_reason,
            )
    iter_candidates.folder_count = folder_count
    iter_candidates.skipped_folder_count = skipped_folder_count


iter_candidates.folder_count = 0
iter_candidates.skipped_folder_count = 0


def parse_fat_slices(data):
    if len(data) < 8 or data[:4] not in FAT_MACHO_MAGICS:
        return []
    magic = int.from_bytes(data[:4], "big")
    if magic in {FAT_MAGIC, FAT_MAGIC_64}:
        endian = ">"
    elif magic in {FAT_CIGAM, FAT_CIGAM_64}:
        endian = "<"
    else:
        return []
    is_64 = magic in {FAT_MAGIC_64, FAT_CIGAM_64}
    arch_size = 32 if is_64 else 20
    nfat_arch = int.from_bytes(data[4:8], "big" if endian == ">" else "little")
    slices = []
    offset = 8
    for _index in range(min(nfat_arch, 64)):
        if offset + arch_size > len(data):
            break
        if is_64:
            cputype, cpusubtype, slice_offset, size, align, reserved = struct.unpack(
                f"{endian}IIQQII", data[offset : offset + arch_size]
            )
            del cpusubtype, align, reserved
        else:
            cputype, cpusubtype, slice_offset, size, align = struct.unpack(
                f"{endian}IIIII", data[offset : offset + arch_size]
            )
            del cpusubtype, align
        if slice_offset < len(data) and size <= len(data) - slice_offset:
            slices.append({"cputype": cputype, "offset": slice_offset, "size": size})
        offset += arch_size
    return slices


def select_macho_bytes(data):
    magic = data[:4]
    if magic in THIN_MACHO_MAGICS:
        return data, "thin", None
    if magic not in FAT_MACHO_MAGICS:
        return None, "non_macho", None
    slices = parse_fat_slices(data)
    for macho_slice in slices:
        if macho_slice["cputype"] == CPU_TYPE_ARM64:
            start = macho_slice["offset"]
            end = start + macho_slice["size"]
            return data[start:end], "fat", macho_slice
    return None, "fat_no_aarch64", {"slice_count": len(slices)}


def count_code_words(loader, expected_words):
    mapped = loader.getData()
    base_addr = loader.getBaseAddress()
    count = 0
    for start, end in loader.getCodeAreas():
        start_offset = max(0, start - base_addr)
        end_offset = min(len(mapped), end - base_addr)
        for offset in range(start_offset, max(start_offset, end_offset - INSTRUCTION_SIZE + 1), INSTRUCTION_SIZE):
            word = int.from_bytes(mapped[offset : offset + INSTRUCTION_SIZE], "little")
            if word in expected_words:
                count += 1
    return count


def stringref_count(report):
    return sum(len(function.stringrefs or []) for function in report.getFunctions())


def dataref_count(report):
    return sum(len(targets) for targets in (report.data_refs_from or {}).values())


def analyze_macho(candidate, data, macho_data, macho_kind, slice_info, timeout):
    if len(macho_data) > MAX_IMAGE_SIZE:
        return {"status": "too_large", "reason": "slice exceeds MAX_IMAGE_SIZE"}

    parsed = MachoFileLoader.parseBinary(macho_data)
    architecture = MachoFileLoader.getArchitecture(macho_data, parsed=parsed)
    bitness = MachoFileLoader.getBitness(macho_data, parsed=parsed)
    if architecture != "aarch64" or bitness != 64:
        return {
            "status": "non_aarch64",
            "architecture": architecture,
            "bitness": bitness,
            "macho_kind": macho_kind,
        }

    def run():
        config = SmdaConfig()
        config.TIMEOUT = timeout
        config.WITH_STRINGS = True
        config.STORE_BUFFER = False
        with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
            report = Disassembler(config).disassembleUnmappedBuffer(macho_data)
            loader = MemoryFileLoader(macho_data, map_file=True)
        return report, loader

    try:
        report, loader = _with_timeout(timeout + 5, run)
    except SampleTimeout as exc:
        return {"status": "timeout", "reason": str(exc), "architecture": architecture, "bitness": bitness}

    result = {
        "status": report.status,
        "architecture": report.architecture,
        "bitness": report.bitness,
        "macho_kind": macho_kind,
        "filetype": str(getattr(parsed, "file_type", "")),
        "code_areas": loader.getCodeAreas(),
        "function_count": report.num_functions,
        "block_count": report.num_blocks,
        "instruction_count": report.num_instructions,
        "stringref_count": stringref_count(report),
        "dataref_count": dataref_count(report),
        "pac_count": count_code_words(loader, PAC_PROLOGUES),
        "bti_count": count_code_words(loader, BTI_PROLOGUES),
    }
    if report.status != "ok":
        result["reason"] = report.execution_error or report.status
    if slice_info:
        result["slice_offset"] = slice_info["offset"]
        result["slice_size"] = slice_info["size"]
    result["candidate_fixture_bytes"] = macho_data if report.status == "ok" else None
    return result


def analyze_candidate(candidate, timeout):
    started = time.monotonic()
    base = {
        "relative_path": candidate.relative_path,
        "family": candidate.family,
        "folder_reason": candidate.folder_reason,
    }
    try:
        size = candidate.path.stat().st_size
        base["size"] = size
        if size > MAX_IMAGE_SIZE:
            base.update({"status": "too_large", "reason": "file exceeds MAX_IMAGE_SIZE"})
            return base
        data = candidate.path.read_bytes()
        base["raw_sha256"] = sha256(data)
        macho_data, macho_kind, slice_info = select_macho_bytes(data)
        if macho_data is None:
            base.update({"status": macho_kind})
            if slice_info:
                base.update(slice_info)
            return base
        if macho_data is not data:
            base["slice_sha256"] = sha256(macho_data)
            base["slice_size"] = len(macho_data)
        result = analyze_macho(candidate, data, macho_data, macho_kind, slice_info, timeout)
        fixture_bytes = result.pop("candidate_fixture_bytes", None)
        base.update(result)
        base["_fixture_bytes"] = fixture_bytes
        return base
    except Exception as exc:
        base.update(
            {
                "status": "error",
                "reason": str(exc),
                "traceback": traceback.format_exc(limit=5),
            }
        )
        return base
    finally:
        base["elapsed_seconds"] = round(time.monotonic() - started, 3)


def fixture_tags(result):
    tags = []
    if result.get("stringref_count", 0) > 0:
        tags.append("stringrefs")
    if result.get("dataref_count", 0) > 0:
        tags.append("datarefs")
    if result.get("pac_count", 0) > 0:
        tags.append("pac")
    if result.get("bti_count", 0) > 0:
        tags.append("bti")
    return tags


def choose_fixture(result, bucket):
    return {
        "bucket": bucket,
        "result": result,
        "score": (
            result.get("size", 0),
            result.get("relative_path", ""),
        ),
    }


def select_fixtures(results):
    successes = [
        result
        for result in results
        if result.get("status") == "ok"
        and result.get("architecture") == "aarch64"
        and result.get("bitness") == 64
        and result.get("function_count", 0) > 0
        and result.get("code_areas")
        and result.get("_fixture_bytes")
    ]
    selected = []
    selected_paths = set()
    selected_families = set()
    buckets = [
        ("smallest-executable", lambda r: r),
        ("smallest-dylib-or-bundle", lambda r: "DYLIB" in r.get("filetype", "") or "BUNDLE" in r.get("filetype", "")),
        ("string-data-signal", lambda r: r.get("stringref_count", 0) + r.get("dataref_count", 0)),
        ("pac", lambda r: r.get("pac_count", 0)),
        ("bti", lambda r: r.get("bti_count", 0)),
        ("largest-under-cap", lambda r: r.get("size", 0)),
    ]

    def add_result(bucket, result):
        if not result or result["relative_path"] in selected_paths:
            return
        if len(selected) >= MAX_FIXTURE_COUNT:
            return
        if sum(item["result"].get("size", 0) for item in selected) + result.get("size", 0) > MAX_TOTAL_FIXTURE_BYTES:
            return
        selected.append(choose_fixture(result, bucket))
        selected_paths.add(result["relative_path"])
        selected_families.add(result.get("family", ""))

    for bucket, predicate in buckets:
        candidates = []
        for result in successes:
            value = predicate(result)
            if not value:
                continue
            candidates.append(result)
        if not candidates:
            continue
        if bucket in {"string-data-signal", "pac", "bti", "largest-under-cap"}:
            candidates.sort(key=lambda r: (predicate(r), -r.get("size", 0)), reverse=True)
        else:
            candidates.sort(key=lambda r: (r.get("size", 0), r.get("relative_path", "")))
        add_result(bucket, candidates[0])

    for result in sorted(successes, key=lambda r: (r.get("family", "") in selected_families, r.get("size", 0))):
        add_result("fallback-distinct-family", result)
        if len(selected) >= MAX_FIXTURE_COUNT:
            break
    return selected


def write_selected_fixtures(selected, output_dir, malpedia_commit, smda_commit):
    fixture_dir = output_dir / "selected_fixtures"
    fixture_dir.mkdir(exist_ok=True)
    manifest = {
        "source": "Malpedia",
        "malpedia_commit": malpedia_commit,
        "smda_commit": smda_commit,
        "xor_scheme": "byte ^ (index % 256)",
        "fixtures": [],
    }
    for item in selected:
        result = item["result"]
        raw = result["_fixture_bytes"]
        xored = xor_fixture(raw)
        fixture_name = f"{result.get('family')}_{sha256(raw)[:12]}.xored".replace("/", "_")
        (fixture_dir / fixture_name).write_bytes(xored)
        manifest["fixtures"].append(
            {
                "fixture": fixture_name,
                "selection_bucket": item["bucket"],
                "malpedia_commit": malpedia_commit,
                "family": result.get("family"),
                "inner_path": result.get("relative_path"),
                "raw_sha256": sha256(raw),
                "xor_sha256": sha256(xored),
                "size": len(raw),
                "filetype": result.get("filetype", ""),
                "architecture": result.get("architecture"),
                "bitness": result.get("bitness"),
                "expected_min_functions": max(1, min(3, result.get("function_count", 1))),
                "feature_tags": fixture_tags(result),
                "function_count": result.get("function_count", 0),
                "block_count": result.get("block_count", 0),
                "instruction_count": result.get("instruction_count", 0),
                "stringref_count": result.get("stringref_count", 0),
                "dataref_count": result.get("dataref_count", 0),
                "pac_count": result.get("pac_count", 0),
                "bti_count": result.get("bti_count", 0),
                "macho_kind": result.get("macho_kind"),
            }
        )
    (output_dir / "selected_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def summarize(results, selected, malpedia_commit, smda_commit):
    counts = {}
    for result in results:
        counts[result.get("status", "unknown")] = counts.get(result.get("status", "unknown"), 0) + 1
    lines = [
        "# Malpedia macOS Mach-O Validation",
        "",
        f"- Malpedia commit: `{malpedia_commit}`",
        f"- SMDA commit: `{smda_commit}`",
        f"- Candidate folders scanned: `{iter_candidates.folder_count}`",
        f"- Candidate folders skipped by macOS prefilter: `{iter_candidates.skipped_folder_count}`",
        f"- `_unpacked` candidates analyzed: `{len(results)}`",
        f"- Selected XOR fixtures: `{len(selected)}`",
        "",
        "## Outcomes",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status, count in sorted(counts.items()):
        lines.append(f"| `{status}` | {count} |")
    pac_present = any(result.get("pac_count", 0) > 0 for result in results)
    bti_present = any(result.get("bti_count", 0) > 0 for result in results)
    lines.extend(
        [
            "",
            "## Feature Coverage",
            "",
            f"- PAC-bearing successful sample present: `{pac_present}`",
            f"- BTI-bearing successful sample present: `{bti_present}`",
            "",
            "## Selected Fixtures",
            "",
        ]
    )
    if not selected:
        lines.append("No fixtures selected.")
    else:
        lines.extend(
            ["| Bucket | Family | Path | Size | Functions | Tags |", "| --- | --- | --- | ---: | ---: | --- |"]
        )
        for item in selected:
            result = item["result"]
            lines.append(
                "| `{}` | `{}` | `{}` | {} | {} | `{}` |".format(
                    item["bucket"],
                    result.get("family", ""),
                    result.get("relative_path", ""),
                    result.get("size", 0),
                    result.get("function_count", 0),
                    ",".join(fixture_tags(result)),
                )
            )
    return "\n".join(lines) + "\n"


def public_result(result):
    sanitized = {key: value for key, value in result.items() if key != "_fixture_bytes"}
    if "traceback" in sanitized:
        sanitized["traceback"] = sanitized["traceback"].splitlines()[-1]
    return sanitized


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_root", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--malpedia-commit", default="")
    parser.add_argument("--smda-commit", default="")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--select-fixtures", action="store_true")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for candidate in iter_candidates(args.corpus_root):
        result = analyze_candidate(candidate, args.timeout)
        results.append(result)

    selected = select_fixtures(results) if args.select_fixtures else []
    if args.select_fixtures:
        write_selected_fixtures(selected, args.output_dir, args.malpedia_commit, args.smda_commit)

    public_results = [public_result(result) for result in results]
    (args.output_dir / "results.json").write_text(
        json.dumps(
            {
                "malpedia_commit": args.malpedia_commit,
                "smda_commit": args.smda_commit,
                "folder_count": iter_candidates.folder_count,
                "skipped_folder_count": iter_candidates.skipped_folder_count,
                "results": public_results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    (args.output_dir / "summary.md").write_text(
        summarize(public_results, selected, args.malpedia_commit, args.smda_commit)
    )


if __name__ == "__main__":
    main()
