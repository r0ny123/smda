#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

BUILD_ID_RE = re.compile(r"Build ID: ([0-9a-fA-F]+)")


@dataclass(frozen=True)
class Candidate:
    package: str
    raw_path: Path
    debug_package: str
    debug_path: Path
    build_id: str
    reconstructed_path: Path
    elf_header: dict[str, str]


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_elf_header(output):
    fields = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.strip().split(":", 1)
        if key in {"Class", "Data", "Type", "Machine"}:
            fields[key.lower()] = value.strip()
    return fields


def get_build_id(path):
    match = BUILD_ID_RE.search(run(["readelf", "-n", str(path)]).stdout)
    return match.group(1).lower() if match else None


def get_elf_header(path):
    return parse_elf_header(run(["readelf", "-h", str(path)]).stdout)


def package_metadata(packages_dir):
    metadata = {}
    for package_file in sorted(list(packages_dir.glob("*.deb")) + list(packages_dir.glob("*.ddeb"))):
        fields = run(
            [
                "dpkg-deb",
                "-W",
                "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
                str(package_file),
            ]
        ).stdout.splitlines()
        if len(fields) != 3:
            raise ValueError(f"could not read metadata from {package_file}")
        metadata[fields[0]] = {
            "name": fields[0],
            "version": fields[1],
            "architecture": fields[2],
            "deb_filename": package_file.name,
            "deb_sha256": sha256(package_file),
        }
    return metadata


def build_debug_index(debug_root):
    index = {}
    for path in sorted(debug_root.rglob("*.debug")):
        relative = path.relative_to(debug_root)
        if ".build-id" not in relative.parts:
            continue
        marker = relative.parts.index(".build-id")
        if len(relative.parts) != marker + 3:
            continue
        prefix, suffix = relative.parts[marker + 1 :]
        if len(prefix) != 2 or not suffix.endswith(".debug"):
            continue
        index.setdefault((prefix + suffix[: -len(".debug")]).lower(), (relative.parts[0], path))
    return index


def reconstruct_candidates(runtime_root, debug_index, reconstructed_root):
    candidates = []
    for package_root in sorted(path for path in runtime_root.iterdir() if path.is_dir()):
        for raw_path in sorted(path for path in package_root.rglob("*") if path.is_file()):
            try:
                header = get_elf_header(raw_path)
            except subprocess.CalledProcessError:
                continue
            if header.get("machine") != "AArch64":
                continue
            build_id = get_build_id(raw_path)
            debug_entry = debug_index.get(build_id)
            if debug_entry is None:
                continue
            debug_package, debug_path = debug_entry
            relative = raw_path.relative_to(package_root)
            reconstructed_path = reconstructed_root / package_root.name / relative
            reconstructed_path.parent.mkdir(parents=True, exist_ok=True)
            run(["eu-unstrip", "-o", str(reconstructed_path), str(raw_path), str(debug_path)])
            candidates.append(
                Candidate(
                    package=package_root.name,
                    raw_path=raw_path,
                    debug_package=debug_package,
                    debug_path=debug_path,
                    build_id=build_id,
                    reconstructed_path=reconstructed_path,
                    elf_header=header,
                )
            )
    return candidates


def scan_matches(yr, compiled_rules, candidates, work_dir):
    if not candidates:
        return {}
    scan_list = work_dir / "scan-list.txt"
    scan_list.write_text("\n".join(str(candidate.reconstructed_path) for candidate in candidates) + "\n")
    result = run(
        [
            yr,
            "scan",
            "--compiled-rules",
            "--output-format",
            "ndjson",
            "--scan-list",
            str(compiled_rules),
            str(scan_list),
        ]
    )
    matches = {}
    for line in result.stdout.splitlines():
        item = json.loads(line)
        rules = [rule["identifier"] for rule in item.get("rules", [])]
        if rules:
            matches[Path(item["path"]).resolve()] = rules
    return matches


def package_record(metadata, name):
    return metadata.get(
        name, {"name": name, "version": None, "architecture": None, "deb_filename": None, "deb_sha256": None}
    )


def write_artifact(candidates, matches, output_dir, metadata, context):
    output_dir.mkdir(parents=True, exist_ok=True)
    binaries_dir = output_dir / "binaries"
    binaries_dir.mkdir(exist_ok=True)
    manifest_path = output_dir / "manifest.jsonl"
    staged_by_hash = {}
    records = []
    for candidate in candidates:
        rules = matches.get(candidate.reconstructed_path.resolve())
        if not rules:
            continue
        digest = sha256(candidate.reconstructed_path)
        staged_path = staged_by_hash.get(digest)
        if staged_path is None:
            staged_path = binaries_dir / f"{digest}-{candidate.reconstructed_path.name}"
            shutil.copy2(candidate.reconstructed_path, staged_path)
            staged_by_hash[digest] = staged_path
        records.append(
            {
                "schema_version": 1,
                "rules": rules,
                "package": package_record(metadata, candidate.package),
                "debug_package": package_record(metadata, candidate.debug_package),
                "build_id": candidate.build_id,
                "original_path": str(candidate.raw_path),
                "debug_path": str(candidate.debug_path),
                "artifact_path": str(staged_path.relative_to(output_dir)),
                "sha256": digest,
                "size": candidate.reconstructed_path.stat().st_size,
                "elf": candidate.elf_header,
                "collection": context,
            }
        )
    with manifest_path.open("w") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    summary = {
        "schema_version": 1,
        "status": "matched" if records else "no_matches",
        "candidate_count": len(candidates),
        "match_record_count": len(records),
        "unique_binary_count": len(staged_by_hash),
        "collection": context,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def write_error_artifact(output_dir, rules_source, context, error):
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.jsonl").write_text("")
    shutil.copy2(rules_source, output_dir / rules_source.name)
    with (output_dir / "packages.tsv").open("w") as handle:
        handle.write("name\tversion\tarchitecture\tdeb_filename\tdeb_sha256\n")
    summary = {
        "schema_version": 1,
        "status": "error",
        "candidate_count": 0,
        "match_record_count": 0,
        "unique_binary_count": 0,
        "error": str(error),
        "collection": context,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--debug-root", type=Path, required=True)
    parser.add_argument("--packages-dir", type=Path, required=True)
    parser.add_argument("--reconstructed-root", type=Path, required=True)
    parser.add_argument("--compiled-rules", type=Path, required=True)
    parser.add_argument("--rules-source", type=Path, required=True)
    parser.add_argument("--yr", default="yr")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-suite", required=True)
    parser.add_argument("--runner-label", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--yara-version", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    context = {
        "source_suite": args.source_suite,
        "runner_label": args.runner_label,
        "runner_os": args.runner_os,
        "runner_arch": args.runner_arch,
        "runner_image": args.runner_image,
        "yara_version": args.yara_version,
        "rules_sha256": sha256(args.rules_source),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_sha": os.environ.get("GITHUB_SHA"),
    }
    try:
        metadata = package_metadata(args.packages_dir)
        debug_index = build_debug_index(args.debug_root)
        candidates = reconstruct_candidates(args.runtime_root, debug_index, args.reconstructed_root)
        matches = scan_matches(args.yr, args.compiled_rules, candidates, args.reconstructed_root)
        summary = write_artifact(candidates, matches, args.output_dir, metadata, context)
        shutil.copy2(args.rules_source, args.output_dir / args.rules_source.name)
        with (args.output_dir / "packages.tsv").open("w") as handle:
            handle.write("name\tversion\tarchitecture\tdeb_filename\tdeb_sha256\n")
            for item in sorted(metadata.values(), key=lambda value: value["name"]):
                handle.write("{name}\t{version}\t{architecture}\t{deb_filename}\t{deb_sha256}\n".format(**item))
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        summary = write_error_artifact(args.output_dir, args.rules_source, context, error)
        print(json.dumps(summary, sort_keys=True))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
