import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import smda_profiler  # The smda_profiler.py CLI script we just created


class TestSMDAProfiler(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.corpus_dir = Path(self.temp_dir) / "corpus"
        self.corpus_dir.mkdir()
        self.output_dir = Path(self.temp_dir) / "output"
        self.output_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_instruction_counting_helpers(self):
        # Empty block
        self.assertEqual(smda_profiler.count_instructions({}), 0)
        # Standard instruction record
        inst = [0x401000, 1, "NOP", ""]
        self.assertTrue(smda_profiler.is_instruction_record(inst))
        self.assertEqual(smda_profiler.count_instructions(inst), 1)

        # Complex blocks structure (dict or nested list)
        blocks = {
            "0x401000": [
                [0x401000, 1, "MOV", "EAX, 1"],
                [0x401001, 1, "NOP", ""],
            ],
            "0x401002": [
                [0x401002, 1, "RET", ""],
            ],
        }
        self.assertEqual(smda_profiler.count_instructions(blocks), 3)

    def test_filename_helpers(self):
        self.assertEqual(smda_profiler.parse_base_addr("dump_0x00400000"), 0x00400000)
        self.assertEqual(smda_profiler.parse_base_addr("dump7_0x00007ff712345678"), 0x00007FF712345678)
        self.assertEqual(smda_profiler.parse_base_addr("normal_file.exe"), 0)
        self.assertEqual(smda_profiler.get_bitness_from_filename("dump_0x00400000"), 32)
        self.assertEqual(smda_profiler.get_bitness_from_filename("dump_0x00007ff712345678"), 64)
        self.assertEqual(smda_profiler.get_bitness_from_filename("normal_file.exe"), 0)
        self.assertEqual(smda_profiler.infer_mode("dump_0x00400000"), "dump")
        self.assertEqual(smda_profiler.infer_mode("normal_file.exe"), "file")

    def test_discover_targets(self):
        (self.corpus_dir / "dump_0x00400000").write_bytes(b"MZ\x00\x00")
        (self.corpus_dir / "malware_unpacked").write_bytes(b"MZ\x00\x00")
        (self.corpus_dir / "random.txt").write_bytes(b"hello")

        targets = smda_profiler.discover_targets(self.corpus_dir)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["filename"], "dump_0x00400000")
        self.assertEqual(targets[0]["mode"], "dump")
        self.assertEqual(targets[1]["filename"], "malware_unpacked")
        self.assertEqual(targets[1]["mode"], "file")

    @patch("smda_profiler.import_smda")
    def test_benchmark_command(self, mock_import_smda):
        (self.corpus_dir / "dump_0x00400000").write_bytes(b"MZ\x00\x00")

        mock_disassembler = MagicMock()
        mock_report = MagicMock()
        mock_report.toDict.return_value = {"status": "ok", "xcfg": {"0x401000": [[0x401000, 1, "NOP", ""]]}}
        mock_disassembler.disassembleBuffer.return_value = mock_report
        mock_import_smda.return_value = mock_disassembler

        output_json = Path(self.temp_dir) / "results.json"
        argv = [
            "benchmark",
            str(self.corpus_dir),
            "--warmups",
            "1",
            "--iterations",
            "2",
            "--output-json",
            str(output_json),
        ]

        retval = smda_profiler.main(argv)
        self.assertEqual(retval, 0)
        self.assertTrue(output_json.exists())

        results = json.loads(output_json.read_text(encoding="utf-8"))
        self.assertEqual(results["target_count"], 1)
        self.assertEqual(results["total_functions"], 1)
        self.assertEqual(results["total_instructions"], 1)
        self.assertEqual(len(results["results"]), 1)
        self.assertEqual(results["results"][0]["status"], "ok")

    @patch("smda_profiler.import_smda")
    def test_profile_cprofile(self, mock_import_smda):
        binary_path = self.corpus_dir / "normal_file_unpacked"
        binary_path.write_bytes(b"MZ\x00\x00")

        mock_disassembler = MagicMock()
        mock_report = MagicMock()
        mock_report.toDict.return_value = {"status": "ok", "xcfg": {}}
        mock_disassembler.disassembleFile.return_value = mock_report
        mock_import_smda.return_value = mock_disassembler

        output_dir = Path(self.temp_dir) / "profiles"
        argv = [
            "profile",
            str(binary_path),
            "--profiler",
            "cprofile",
            "--output-dir",
            str(output_dir),
        ]

        retval = smda_profiler.main(argv)
        self.assertEqual(retval, 0)
        self.assertTrue((output_dir / "cprofile.prof").exists())
        self.assertTrue((output_dir / "cprofile_top30.txt").exists())

    @patch("subprocess.run")
    def test_compare_command(self, mock_run):
        # We need mock_run calls to return success
        mock_run.return_value = MagicMock(returncode=0)

        output_md = Path(self.temp_dir) / "comparison.md"

        # Create dummy benchmark outputs that compare subcommand expects to load from /tmp/smda-compare-*/...
        base_results = {
            "total_functions": 100,
            "total_instructions": 500,
            "functions_per_second": 10.0,
            "instructions_per_second": 50.0,
            "mb_per_second": 0.5,
            "results": [
                {
                    "filename": "target_a",
                    "duration": 1.0,
                    "num_functions": 10,
                }
            ],
        }
        target_results = {
            "total_functions": 100,
            "total_instructions": 500,
            "functions_per_second": 12.0,
            "instructions_per_second": 60.0,
            "mb_per_second": 0.6,
            "results": [
                {
                    "filename": "target_a",
                    "duration": 0.8,
                    "num_functions": 10,
                }
            ],
        }

        # We patch Path.read_text and json.loads to return the above dummy metrics
        # when smda_profiler.py compare runs and reads base/target result files.
        orig_read_text = Path.read_text

        def mock_read_text(self_path, *args, **kwargs):
            if "base_results.json" in str(self_path):
                return json.dumps(base_results)
            if "target_results.json" in str(self_path):
                return json.dumps(target_results)
            return orig_read_text(self_path, *args, **kwargs)

        argv = [
            "compare",
            str(self.corpus_dir),
            "--base",
            "master",
            "--target",
            "HEAD",
            "--warmups",
            "1",
            "--iterations",
            "2",
            "--output-md",
            str(output_md),
        ]

        with patch.object(Path, "read_text", mock_read_text):
            retval = smda_profiler.main(argv)

        self.assertEqual(retval, 0)
        self.assertTrue(output_md.exists())

        report_content = output_md.read_text(encoding="utf-8")
        self.assertIn("Base Ref: `master`", report_content)
        self.assertIn("Target Ref: `HEAD`", report_content)
        self.assertIn("target_a", report_content)
        self.assertIn("+20.00%", report_content)


if __name__ == "__main__":
    unittest.main()
