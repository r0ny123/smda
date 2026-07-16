#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

PDB_GUID_RE = re.compile(r"(?im)^\s*(?:guid|uniqueid)\s*:\s*\{?([0-9a-f-]{36})\}?")
PDB_AGE_RE = re.compile(r"(?im)^\s*age\s*:\s*(\d+)")


@dataclass(frozen=True)
class PeDebugIdentity:
    guid: str
    age: int
    pdb_filename: str


@dataclass(frozen=True)
class PdbIdentity:
    guid: str
    age: int


@dataclass(frozen=True)
class Candidate:
    pe_path: Path
    pdb_path: Path
    pe_identity: PeDebugIdentity
    pdb_identity: PdbIdentity


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rva_to_offset(data, pe_offset, optional_header_size, rva):
    optional_offset = pe_offset + 24
    if optional_offset + 64 > len(data):
        return None
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    if rva < size_of_headers:
        return rva if rva < len(data) else None
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    section_offset = optional_offset + optional_header_size
    for index in range(section_count):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            return None
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        section_size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + section_size:
            file_offset = raw_offset + rva - virtual_address
            return file_offset if file_offset < len(data) else None
    return None


def parse_pe_debug_identity(path):
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if machine != 0x8664 or optional_offset + optional_header_size > len(data):
        return None
    if struct.unpack_from("<H", data, optional_offset)[0] != 0x20B:
        return None
    debug_directory_offset = optional_offset + 112 + 6 * 8
    if debug_directory_offset + 8 > optional_offset + optional_header_size:
        return None
    debug_rva, debug_size = struct.unpack_from("<II", data, debug_directory_offset)
    debug_offset = rva_to_offset(data, pe_offset, optional_header_size, debug_rva)
    if debug_offset is None or debug_size < 28 or debug_offset + debug_size > len(data):
        return None
    for offset in range(debug_offset, debug_offset + debug_size - 27, 28):
        debug_type, data_size = struct.unpack_from("<II", data, offset + 12)
        data_offset = struct.unpack_from("<I", data, offset + 24)[0]
        if debug_type != 2 or data_size < 25 or data_offset + data_size > len(data):
            continue
        codeview = data[data_offset : data_offset + data_size]
        if codeview[:4] != b"RSDS":
            continue
        guid = str(uuid.UUID(bytes_le=codeview[4:20]))
        age = struct.unpack_from("<I", codeview, 20)[0]
        pdb_path = codeview[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        pdb_filename = pdb_path.replace("\\", "/").rsplit("/", 1)[-1]
        if pdb_filename:
            return PeDebugIdentity(guid=guid, age=age, pdb_filename=pdb_filename)
    return None


def parse_pdb_identity(output):
    guid_match = PDB_GUID_RE.search(output)
    age_match = PDB_AGE_RE.search(output)
    if guid_match is None or age_match is None:
        raise ValueError("llvm-pdbutil summary did not include a PDB GUID and age")
    return PdbIdentity(guid=str(uuid.UUID(guid_match.group(1))).lower(), age=int(age_match.group(1)))


def get_pdb_identity(llvm_pdbutil, path):
    return parse_pdb_identity(run([llvm_pdbutil, "dump", "--summary", str(path)]).stdout)


def build_pdb_index(source_root):
    index = {}
    for path in sorted(path for path in source_root.rglob("*.pdb") if path.is_file()):
        index.setdefault(path.name.casefold(), []).append(path)
    return index


def discover_candidates(source_root, llvm_pdbutil):
    pdb_index = build_pdb_index(source_root)
    pdb_identity_cache = {}
    candidates = []
    pe_debug_candidate_count = 0
    for pe_path in sorted(
        path for path in source_root.rglob("*") if path.is_file() and path.suffix.lower() in {".exe", ".dll"}
    ):
        identity = parse_pe_debug_identity(pe_path)
        if identity is None:
            continue
        pe_debug_candidate_count += 1
        matching_paths = pdb_index.get(identity.pdb_filename.casefold(), [])
        if len(matching_paths) != 1:
            continue
        pdb_path = matching_paths[0]
        pdb_identity = pdb_identity_cache.get(pdb_path)
        if pdb_identity is None:
            pdb_identity = get_pdb_identity(llvm_pdbutil, pdb_path)
            pdb_identity_cache[pdb_path] = pdb_identity
        if identity.guid != pdb_identity.guid or identity.age != pdb_identity.age:
            continue
        candidates.append(Candidate(pe_path, pdb_path, identity, pdb_identity))
    return candidates, pe_debug_candidate_count


def stage_file(path, directory, staged_by_hash):
    digest = sha256(path)
    staged_path = staged_by_hash.get(digest)
    if staged_path is None:
        staged_path = directory / f"{digest}-{path.name}"
        shutil.copy2(path, staged_path)
        staged_by_hash[digest] = staged_path
    return digest, staged_path


def write_artifact(candidates, pe_debug_candidate_count, source_root, output_dir, context):
    output_dir.mkdir(parents=True, exist_ok=True)
    binaries_dir = output_dir / "binaries"
    symbols_dir = output_dir / "symbols"
    binaries_dir.mkdir(exist_ok=True)
    symbols_dir.mkdir(exist_ok=True)
    staged_binaries = {}
    staged_symbols = {}
    records = []
    for candidate in candidates:
        pe_digest, staged_pe = stage_file(candidate.pe_path, binaries_dir, staged_binaries)
        pdb_digest, staged_pdb = stage_file(candidate.pdb_path, symbols_dir, staged_symbols)
        records.append(
            {
                "schema_version": 1,
                "pe": {
                    "source_path": str(candidate.pe_path.relative_to(source_root)),
                    "artifact_path": str(staged_pe.relative_to(output_dir)),
                    "sha256": pe_digest,
                    "size": candidate.pe_path.stat().st_size,
                    "machine": "AMD64",
                    "optional_header": "PE32+",
                    "codeview": {
                        "signature": "RSDS",
                        "guid": candidate.pe_identity.guid,
                        "age": candidate.pe_identity.age,
                        "pdb_filename": candidate.pe_identity.pdb_filename,
                    },
                },
                "pdb": {
                    "source_path": str(candidate.pdb_path.relative_to(source_root)),
                    "artifact_path": str(staged_pdb.relative_to(output_dir)),
                    "sha256": pdb_digest,
                    "size": candidate.pdb_path.stat().st_size,
                    "guid": candidate.pdb_identity.guid,
                    "age": candidate.pdb_identity.age,
                },
                "collection": context,
            }
        )
    with (output_dir / "manifest.jsonl").open("w") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    summary = {
        "schema_version": 1,
        "status": "matched" if records else "no_matches",
        "pe_debug_candidate_count": pe_debug_candidate_count,
        "match_record_count": len(records),
        "unique_binary_count": len(staged_binaries),
        "unique_symbol_count": len(staged_symbols),
        "collection": context,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_dir / "toolchain.json").write_text(json.dumps(context, indent=2, sort_keys=True) + "\n")
    return summary


def write_error_artifact(output_dir, context, error):
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.jsonl").write_text("")
    summary = {
        "schema_version": 1,
        "status": "error",
        "pe_debug_candidate_count": 0,
        "match_record_count": 0,
        "unique_binary_count": 0,
        "unique_symbol_count": 0,
        "error": str(error),
        "collection": context,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output_dir / "toolchain.json").write_text(json.dumps(context, indent=2, sort_keys=True) + "\n")
    return summary


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--llvm-pdbutil", required=True)
    parser.add_argument("--context-json", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    context = json.loads(args.context_json.read_text())
    try:
        candidates, pe_debug_candidate_count = discover_candidates(args.source_root, args.llvm_pdbutil)
        summary = write_artifact(candidates, pe_debug_candidate_count, args.source_root, args.output_dir, context)
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        summary = write_error_artifact(args.output_dir, context, error)
        print(json.dumps(summary, sort_keys=True))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
