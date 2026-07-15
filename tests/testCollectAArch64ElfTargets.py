import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / ".github" / "workflows" / "scripts" / "collect_aarch64_elf_targets.py"
SPEC = importlib.util.spec_from_file_location("collect_aarch64_elf_targets", SCRIPT)
COLLECTOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COLLECTOR
SPEC.loader.exec_module(COLLECTOR)


class AArch64ElfTargetCollectorTestSuite(unittest.TestCase):
    def test_build_debug_index_uses_build_id_and_package(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            debug_file = root / "libc6-dbgsym" / "usr" / "lib" / "debug" / ".build-id" / "ab" / "cd.debug"
            debug_file.parent.mkdir(parents=True)
            debug_file.write_bytes(b"debug")

            self.assertEqual(COLLECTOR.build_debug_index(root), {"abcd": ("libc6-dbgsym", debug_file)})

    def test_reconstruct_candidates_pairs_build_id_and_uses_eu_unstrip(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path = root / "runtime" / "libc6" / "usr" / "bin" / "sample"
            debug_path = root / "debug" / "libc6-dbgsym" / "usr" / "lib" / "debug" / ".build-id" / "ab" / "cd.debug"
            raw_path.parent.mkdir(parents=True)
            debug_path.parent.mkdir(parents=True)
            raw_path.write_bytes(b"stripped")
            debug_path.write_bytes(b"debug")

            def fake_run(command):
                self.assertEqual(command[:2], ["eu-unstrip", "-o"])
                Path(command[2]).write_bytes(b"reconstructed")
                return SimpleNamespace(stdout="")

            with (
                patch.object(COLLECTOR, "get_elf_header", return_value={"machine": "AArch64", "type": "DYN"}),
                patch.object(COLLECTOR, "get_build_id", return_value="abcd"),
                patch.object(COLLECTOR, "run", side_effect=fake_run),
            ):
                candidates = COLLECTOR.reconstruct_candidates(
                    root / "runtime",
                    {"abcd": ("libc6-dbgsym", debug_path)},
                    root / "reconstructed",
                )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].build_id, "abcd")
            self.assertEqual(candidates[0].debug_package, "libc6-dbgsym")
            self.assertEqual(candidates[0].reconstructed_path.read_bytes(), b"reconstructed")

    def test_scan_matches_writes_scan_list_and_parses_ndjson(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            reconstructed = root / "reconstructed" / "sample"
            reconstructed.parent.mkdir()
            reconstructed.write_bytes(b"binary")
            candidate = COLLECTOR.Candidate(
                "libc6",
                root / "runtime" / "sample",
                "libc6-dbgsym",
                root / "debug" / "sample",
                "abcd",
                reconstructed,
                {"machine": "AArch64"},
            )
            output = json.dumps(
                {"path": str(reconstructed), "rules": [{"identifier": "aarch64_elf_with_eh_frame_symbols"}]}
            )
            with patch.object(COLLECTOR, "run", return_value=SimpleNamespace(stdout=output)) as mocked_run:
                matches = COLLECTOR.scan_matches("yr", root / "rules.yarc", [candidate], root)

            self.assertEqual(matches, {reconstructed.resolve(): ["aarch64_elf_with_eh_frame_symbols"]})
            self.assertEqual((root / "scan-list.txt").read_text(), f"{reconstructed}\n")
            self.assertEqual(mocked_run.call_args.args[0][:2], ["yr", "scan"])

    def test_package_metadata_records_dpkg_fields_and_digest(self):
        with TemporaryDirectory() as directory:
            package_file = Path(directory) / "libc6_1_arm64.deb"
            package_file.write_bytes(b"package")
            with patch.object(COLLECTOR, "run", return_value=SimpleNamespace(stdout="libc6\n1\narm64\n")) as mocked_run:
                metadata = COLLECTOR.package_metadata(Path(directory))

            self.assertEqual(metadata["libc6"]["version"], "1")
            self.assertEqual(metadata["libc6"]["deb_sha256"], hashlib.sha256(b"package").hexdigest())
            self.assertEqual(
                mocked_run.call_args.args[0],
                [
                    "dpkg-deb",
                    "-W",
                    "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
                    str(package_file),
                ],
            )

    def test_write_artifact_deduplicates_binaries_and_records_matches(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "reconstructed" / "libc6" / "usr" / "bin" / "first"
            second = root / "reconstructed" / "libgcc-s1" / "usr" / "bin" / "second"
            for path in (first, second):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"same aarch64 binary")
            digest = hashlib.sha256(first.read_bytes()).hexdigest()
            candidates = [
                COLLECTOR.Candidate(
                    "libc6",
                    root / "runtime" / "first",
                    "libc6-dbgsym",
                    root / "debug" / "first",
                    "abcd",
                    first,
                    {"machine": "AArch64"},
                ),
                COLLECTOR.Candidate(
                    "libgcc-s1",
                    root / "runtime" / "second",
                    "libgcc-s1-dbgsym",
                    root / "debug" / "second",
                    "bcde",
                    second,
                    {"machine": "AArch64"},
                ),
            ]
            metadata = {
                "libc6": {
                    "name": "libc6",
                    "version": "1",
                    "architecture": "arm64",
                    "deb_filename": "libc6.deb",
                    "deb_sha256": "a",
                },
                "libc6-dbgsym": {
                    "name": "libc6-dbgsym",
                    "version": "1",
                    "architecture": "arm64",
                    "deb_filename": "libc6.ddeb",
                    "deb_sha256": "b",
                },
            }
            output = root / "output"
            summary = COLLECTOR.write_artifact(
                candidates,
                {
                    first.resolve(): ["aarch64_elf_with_eh_frame_symbols"],
                    second.resolve(): ["aarch64_elf_with_eh_frame_symbols"],
                },
                output,
                metadata,
                {"runner_arch": "ARM64"},
            )

            self.assertEqual(summary["status"], "matched")
            self.assertEqual(summary["match_record_count"], 2)
            self.assertEqual(summary["unique_binary_count"], 1)
            self.assertEqual(len(list((output / "binaries").iterdir())), 1)
            records = [json.loads(line) for line in (output / "manifest.jsonl").read_text().splitlines()]
            self.assertEqual({record["sha256"] for record in records}, {digest})
            self.assertEqual({record["artifact_path"] for record in records}, {f"binaries/{digest}-first"})

    def test_write_artifact_marks_empty_collection(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            summary = COLLECTOR.write_artifact([], {}, output, {}, {"runner_arch": "ARM64"})

            self.assertEqual(summary["status"], "no_matches")
            self.assertEqual(summary["unique_binary_count"], 0)
            self.assertEqual((output / "manifest.jsonl").read_text(), "")

    def test_write_error_artifact_preserves_failure_status_and_rule(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "targets.yar"
            rule.write_text("rule target { condition: true }\n")
            summary = COLLECTOR.write_error_artifact(
                root / "output", rule, {"runner_arch": "ARM64"}, ValueError("bad package")
            )

            self.assertEqual(summary["status"], "error")
            self.assertEqual(summary["error"], "bad package")
            self.assertEqual((root / "output" / "targets.yar").read_text(), rule.read_text())
            self.assertEqual((root / "output" / "manifest.jsonl").read_text(), "")


if __name__ == "__main__":
    unittest.main()
