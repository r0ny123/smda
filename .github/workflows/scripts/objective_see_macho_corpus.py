#!/usr/bin/env python3
"""Validate SMDA's AArch64 Mach-O support against Objective-See samples.

This script is intentionally defensive: it never executes extracted files, it
rejects archive path traversal and symlinks, it deletes every extracted member
after analysis, and it writes only sanitized reports plus XOR-obfuscated
selected fixtures.
"""

import argparse
import hashlib
import json
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import lief

try:
    import pyzipper
except ImportError:  # pragma: no cover - pyzipper is installed in CI, zipfile is the fallback.
    pyzipper = None

from smda.aarch64.definitions import BTI_PROLOGUES, INSTRUCTION_SIZE, PAC_PROLOGUES
from smda.common.SmdaReport import SmdaReport
from smda.Disassembler import Disassembler
from smda.SmdaConfig import SmdaConfig
from smda.utility.MemoryFileLoader import MemoryFileLoader

MACHO_MAGIC = {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}
STATUS_ORDER = ["ok", "timeout", "error", "unsupported", "too_large", "rejected"]


def _xor_bytes(data):
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _slug(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "sample"


def _is_symlink(info):
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _safe_member_path(temp_dir, member_name):
    target = (temp_dir / member_name).resolve()
    root = temp_dir.resolve()
    if target == root or root not in target.parents:
        return None
    return target


def _open_zip(path, password):
    if pyzipper is not None:
        archive = pyzipper.AESZipFile(path)
        archive.setpassword(password)
        return archive
    archive = zipfile.ZipFile(path)
    archive.setpassword(password)
    return archive


def _read_member_to_temp(archive, info, target, max_member_bytes):
    if info.file_size > max_member_bytes:
        return "too_large", None, None
    target.parent.mkdir(parents=True, exist_ok=True)
    sha = hashlib.sha256()
    size = 0
    with archive.open(info, "r") as src, target.open("wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_member_bytes:
                return "too_large", None, None
            sha.update(chunk)
            dst.write(chunk)
    return "ok", sha.hexdigest(), size


def _macho_architecture(binary):
    if isinstance(binary, lief.MachO.Binary):
        header = getattr(binary, "header", None)
        if header is None:
            return ""
        cpu_type = getattr(header, "cpu_type", None)
        return getattr(cpu_type, "name", str(cpu_type))
    return ""


def _macho_filetype(binary):
    header = getattr(binary, "header", None)
    file_type = getattr(header, "file_type", None)
    return getattr(file_type, "name", str(file_type or ""))


def _iter_macho_slices(raw_data, parsed):
    if isinstance(parsed, lief.MachO.Binary):
        yield raw_data, parsed, "thin", 0
        return
    if isinstance(parsed, lief.MachO.FatBinary):
        for binary in parsed.it_binaries:
            if not isinstance(binary, lief.MachO.Binary):
                continue
            start = int(getattr(binary, "fat_offset", 0) or 0)
            size = int(getattr(binary, "original_size", 0) or 0)
            if start < 0 or size <= 0 or start + size > len(raw_data):
                continue
            yield raw_data[start : start + size], binary, "fat-slice", start


def _count_prologue_words(mapped_binary, base_addr, code_areas):
    pac_count = 0
    bti_count = 0
    for start, end in code_areas:
        rel_start = max(0, start - base_addr)
        rel_end = min(len(mapped_binary), end - base_addr)
        cursor = rel_start - (rel_start % INSTRUCTION_SIZE)
        while cursor + INSTRUCTION_SIZE <= rel_end:
            word = int.from_bytes(mapped_binary[cursor : cursor + INSTRUCTION_SIZE], "little")
            if word in PAC_PROLOGUES:
                pac_count += 1
            if word in BTI_PROLOGUES:
                bti_count += 1
            cursor += INSTRUCTION_SIZE
    return pac_count, bti_count


def _analyze_slice(slice_data, parsed_binary, args, zip_name, inner_path, raw_sha):
    arch_name = _macho_architecture(parsed_binary)
    if arch_name not in {"ARM64", "ARM64_32"}:
        return {
            "status": "unsupported",
            "reason": f"macho_cpu={arch_name}",
            "zip_name": zip_name,
            "inner_path": inner_path,
            "raw_sha256": raw_sha,
            "raw_size": len(slice_data),
            "architecture": "",
            "bitness": 0,
        }

    try:
        loader = MemoryFileLoader(slice_data, map_file=True)
    except Exception as exc:
        return {
            "status": "error",
            "reason": f"loader failed: {type(exc).__name__}: {exc}",
            "zip_name": zip_name,
            "inner_path": inner_path,
            "raw_sha256": raw_sha,
            "raw_size": len(slice_data),
            "architecture": "",
            "bitness": 0,
        }
    architecture = loader.getArchitecture()
    bitness = loader.getBitness()
    code_areas = loader.getCodeAreas()
    if architecture != "aarch64" or bitness != 64 or not code_areas:
        return {
            "status": "unsupported",
            "reason": "loader did not expose aarch64/64 with code areas",
            "zip_name": zip_name,
            "inner_path": inner_path,
            "raw_sha256": raw_sha,
            "raw_size": len(slice_data),
            "architecture": architecture,
            "bitness": bitness,
            "code_area_count": len(code_areas),
        }

    config = SmdaConfig()
    config.TIMEOUT = args.analysis_timeout
    config.WITH_STRINGS = True
    config.STORE_BUFFER = False
    start_ts = time.monotonic()
    try:
        report = Disassembler(config).disassembleUnmappedBuffer(slice_data)
        duration = time.monotonic() - start_ts
    except Exception as exc:  # sample-specific parser failures are recorded, not fatal.
        return {
            "status": "error",
            "reason": f"{type(exc).__name__}: {exc}",
            "zip_name": zip_name,
            "inner_path": inner_path,
            "raw_sha256": raw_sha,
            "raw_size": len(slice_data),
            "architecture": architecture,
            "bitness": bitness,
            "code_area_count": len(code_areas),
        }

    functions = list(report.getFunctions())
    function_count = len(functions)
    block_count = sum(function.num_blocks for function in functions)
    instruction_count = sum(function.num_instructions for function in functions)
    stringref_count = sum(len(function.stringrefs or []) for function in functions)
    dataref_count = sum(len(values) for values in report.data_refs_from.values())
    roundtrip_ok = False
    try:
        roundtrip = SmdaReport.fromDict(report.toDict())
        roundtrip_ok = roundtrip.status == report.status and roundtrip.architecture == report.architecture
    except Exception:
        roundtrip_ok = False
    pac_count, bti_count = _count_prologue_words(loader.getData(), loader.getBaseAddress(), code_areas)
    feature_tags = []
    if stringref_count:
        feature_tags.append("stringrefs")
    if dataref_count:
        feature_tags.append("datarefs")
    if pac_count:
        feature_tags.append("pac")
    if bti_count:
        feature_tags.append("bti")

    status = report.status
    if status == "ok" and (function_count == 0 or not roundtrip_ok):
        status = "error"
    return {
        "status": status,
        "reason": "" if status == "ok" else "SMDA report did not meet corpus acceptance criteria",
        "zip_name": zip_name,
        "inner_path": inner_path,
        "raw_sha256": raw_sha,
        "raw_size": len(slice_data),
        "filetype": _macho_filetype(parsed_binary),
        "slice_kind": "thin",
        "architecture": report.architecture,
        "bitness": report.bitness,
        "base_addr": report.base_addr,
        "oep": report.oep,
        "code_area_count": len(code_areas),
        "function_count": function_count,
        "block_count": block_count,
        "instruction_count": instruction_count,
        "stringref_count": stringref_count,
        "dataref_count": dataref_count,
        "pac_count": pac_count,
        "bti_count": bti_count,
        "roundtrip_ok": roundtrip_ok,
        "analysis_seconds": round(duration, 4),
        "feature_tags": feature_tags,
    }


def _process_member(path, info, args, zip_name):
    member_result = {
        "zip_name": zip_name,
        "inner_path": info.filename,
        "status": "unsupported",
        "reason": "not Mach-O",
    }
    with tempfile.TemporaryDirectory(prefix="smda-objective-see-") as tmp:
        temp_dir = Path(tmp)
        target = _safe_member_path(temp_dir, info.filename)
        if target is None:
            return [{**member_result, "status": "rejected", "reason": "archive path traversal"}]
        if _is_symlink(info):
            return [{**member_result, "status": "rejected", "reason": "archive symlink"}]
        try:
            with _open_zip(path, args.password.encode()) as archive:
                status, raw_sha, raw_size = _read_member_to_temp(archive, info, target, args.max_member_bytes)
        except Exception as exc:
            return [{**member_result, "status": "error", "reason": f"zip read failed: {type(exc).__name__}: {exc}"}]
        if status != "ok":
            return [{**member_result, "status": status, "reason": f"member_size>{args.max_member_bytes}"}]
        raw_data = target.read_bytes()
        target.unlink(missing_ok=True)

    if raw_data[:4] not in MACHO_MAGIC:
        return [{**member_result, "raw_sha256": raw_sha, "raw_size": raw_size}]

    try:
        parsed = lief.parse(raw_data)
    except Exception as exc:
        return [
            {
                **member_result,
                "status": "error",
                "reason": f"lief parse failed: {type(exc).__name__}: {exc}",
                "raw_sha256": raw_sha,
                "raw_size": raw_size,
            }
        ]
    if parsed is None:
        return [{**member_result, "status": "error", "reason": "lief parse returned None"}]

    results = []
    for slice_data, parsed_binary, slice_kind, slice_offset in _iter_macho_slices(raw_data, parsed):
        slice_sha = _sha256(slice_data)
        result = _analyze_slice(slice_data, parsed_binary, args, zip_name, info.filename, slice_sha)
        result["slice_kind"] = slice_kind
        result["slice_offset"] = slice_offset
        results.append((result, slice_data))
    if not results:
        return [
            {
                **member_result,
                "status": "unsupported",
                "reason": "no parseable thin Mach-O slice",
                "raw_sha256": raw_sha,
                "raw_size": raw_size,
            }
        ]
    return results


def _score_strings(candidate):
    return candidate.get("stringref_count", 0) + candidate.get("dataref_count", 0)


def _choose_selected(successes, max_selected, max_selected_bytes):
    selected = []
    selected_families = set()
    selected_shas = set()
    total = 0

    def add(candidate, bucket):
        nonlocal total
        if candidate is None:
            return False
        family = candidate["zip_name"]
        raw_sha = candidate["raw_sha256"]
        size = candidate["raw_size"]
        if family in selected_families or raw_sha in selected_shas:
            return False
        if len(selected) >= max_selected or total + size > max_selected_bytes:
            return False
        entry = dict(candidate)
        entry["selection_bucket"] = bucket
        selected.append(entry)
        selected_families.add(family)
        selected_shas.add(raw_sha)
        total += size
        return True

    def smallest(items):
        return min(items, key=lambda c: (c["raw_size"], c["zip_name"], c["inner_path"]), default=None)

    def largest(items):
        return max(items, key=lambda c: (c["raw_size"], c["zip_name"], c["inner_path"]), default=None)

    add(smallest([c for c in successes if "EXECUTE" in c.get("filetype", "")]), "smallest-executable")
    add(
        smallest([c for c in successes if any(t in c.get("filetype", "") for t in ("DYLIB", "BUNDLE"))]),
        "smallest-library",
    )
    add(
        max(successes, key=lambda c: (_score_strings(c), -c["raw_size"], c["zip_name"]), default=None),
        "string-data-signal",
    )
    add(smallest([c for c in successes if c.get("pac_count", 0) > 0]), "pac")
    add(smallest([c for c in successes if c.get("bti_count", 0) > 0]), "bti")
    add(largest(successes), "largest-under-cap")

    for candidate in sorted(successes, key=lambda c: (c["raw_size"], c["zip_name"], c["inner_path"])):
        if len(selected) >= max_selected:
            break
        add(candidate, "fallback-distinct-family")
    return selected


def _write_selected(output_dir, selected, bytes_by_sha, commit_sha):
    selected_dir = output_dir / "selected_fixtures"
    selected_dir.mkdir(parents=True, exist_ok=True)
    fixtures = []
    for entry in selected:
        raw_data = bytes_by_sha[entry["raw_sha256"]]
        xored = _xor_bytes(raw_data)
        fixture_name = f"{_slug(Path(entry['zip_name']).stem)}_{entry['raw_sha256'][:12]}.xored"
        (selected_dir / fixture_name).write_bytes(xored)
        fixtures.append(
            {
                "fixture": fixture_name,
                "objective_see_commit": commit_sha,
                "zip_name": entry["zip_name"],
                "inner_path": entry["inner_path"],
                "raw_sha256": entry["raw_sha256"],
                "xor_sha256": _sha256(xored),
                "size": len(raw_data),
                "filetype": entry.get("filetype", ""),
                "architecture": "aarch64",
                "bitness": 64,
                "expected_min_functions": max(1, min(entry.get("function_count", 1), 3)),
                "function_count": entry.get("function_count", 0),
                "block_count": entry.get("block_count", 0),
                "instruction_count": entry.get("instruction_count", 0),
                "stringref_count": entry.get("stringref_count", 0),
                "dataref_count": entry.get("dataref_count", 0),
                "pac_count": entry.get("pac_count", 0),
                "bti_count": entry.get("bti_count", 0),
                "feature_tags": entry.get("feature_tags", []),
                "selection_bucket": entry.get("selection_bucket", ""),
            }
        )

    manifest = {
        "source": "Objective-See/Malware",
        "objective_see_commit": commit_sha,
        "xor_scheme": "byte ^ (index % 256)",
        "fixtures": fixtures,
    }
    (selected_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (selected_dir / "README.md").write_text(
        "# AArch64 Mach-O Corpus Fixtures\n\n"
        "These fixtures are malware-derived samples from Objective-See/Malware, stored in XOR-obfuscated form only.\n\n"
        "- Do not execute fixture contents.\n"
        "- De-XOR only in memory during tests.\n"
        "- Source archive password is intentionally not needed for these committed fixtures.\n"
        "- Source repository is GPLv3; keep provenance in `manifest.json`.\n"
    )
    shutil.make_archive(str(output_dir / "selected_fixtures"), "gztar", selected_dir)


def _write_report(output_dir, commit_sha, zip_count, results, selected):
    counts = dict.fromkeys(STATUS_ORDER, 0)
    for result in results:
        counts[result.get("status", "error")] = counts.get(result.get("status", "error"), 0) + 1
    successes = [r for r in results if isinstance(r, dict) and r.get("status") == "ok"]
    report = {
        "source": "Objective-See/Malware",
        "objective_see_commit": commit_sha,
        "zip_count": zip_count,
        "member_or_slice_result_count": len(results),
        "status_counts": counts,
        "aarch64_macho_success_count": len(successes),
        "selected_count": len(selected),
        "selected_total_bytes": sum(s["raw_size"] for s in selected),
        "selected": selected,
        "results": results,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Objective-See Mach-O Corpus Validation",
        "",
        f"- Objective-See commit: `{commit_sha}`",
        f"- ZIP archives processed: {zip_count}",
        f"- Member/slice results: {len(results)}",
        f"- AArch64 Mach-O successes: {len(successes)}",
        f"- Selected fixtures: {len(selected)}",
        "",
        "## Status Counts",
        "",
    ]
    for status in sorted(counts):
        lines.append(f"- `{status}`: {counts[status]}")
    lines.extend(["", "## Selected Fixtures", ""])
    for entry in selected:
        lines.append(
            "- `{zip_name}` `{inner_path}` -> {bucket}, size={size}, funcs={funcs}, "
            "strings={strings}, datarefs={datarefs}, pac={pac}, bti={bti}".format(
                zip_name=entry["zip_name"],
                inner_path=entry["inner_path"],
                bucket=entry.get("selection_bucket", ""),
                size=entry.get("raw_size", 0),
                funcs=entry.get("function_count", 0),
                strings=entry.get("stringref_count", 0),
                datarefs=entry.get("dataref_count", 0),
                pac=entry.get("pac_count", 0),
                bti=entry.get("bti_count", 0),
            )
        )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--password", required=True)
    parser.add_argument("--objective-see-commit", required=True)
    parser.add_argument("--analysis-timeout", type=int, default=20)
    parser.add_argument("--max-member-bytes", type=int, default=SmdaConfig.MAX_IMAGE_SIZE)
    parser.add_argument("--max-selected", type=int, default=6)
    parser.add_argument("--max-selected-bytes", type=int, default=10 * 1024 * 1024)
    args = parser.parse_args(argv)

    zip_paths = sorted(args.samples_root.glob("*.zip"))
    results = []
    candidate_bytes = {}
    for index, zip_path in enumerate(zip_paths, start=1):
        print(f"[{index}/{len(zip_paths)}] {zip_path.name}", flush=True)
        try:
            with _open_zip(zip_path, args.password.encode()) as archive:
                infos = sorted(
                    [info for info in archive.infolist() if not info.is_dir()],
                    key=lambda i: i.filename,
                )
        except Exception as exc:
            results.append(
                {
                    "zip_name": zip_path.name,
                    "inner_path": "",
                    "status": "error",
                    "reason": f"zip open failed: {type(exc).__name__}: {exc}",
                }
            )
            continue
        for info in infos:
            member_results = _process_member(zip_path, info, args, zip_path.name)
            for item in member_results:
                if isinstance(item, tuple):
                    result, raw_data = item
                    results.append(result)
                    if result.get("status") == "ok":
                        candidate_bytes[result["raw_sha256"]] = raw_data
                else:
                    results.append(item)

    successes = [result for result in results if result.get("status") == "ok"]
    selected = _choose_selected(successes, args.max_selected, args.max_selected_bytes)
    _write_report(args.output_dir, args.objective_see_commit, len(zip_paths), results, selected)
    if selected:
        _write_selected(args.output_dir, selected, candidate_bytes, args.objective_see_commit)
    else:
        print("No AArch64 Mach-O fixtures selected", file=sys.stderr)
        return 2
    print(f"Selected {len(selected)} fixtures from {len(successes)} successful AArch64 Mach-O candidates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
