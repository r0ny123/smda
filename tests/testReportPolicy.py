import unittest
from types import SimpleNamespace
from unittest.mock import patch

from smda.common.BinaryInfo import BinaryInfo
from smda.DisassemblyResult import DisassemblyResult
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.intel.ReportPolicy import (
    _remove_function,
    compute_connected_and_rooted_metrics,
    find_boundary_merge_pairs,
    is_prologue_only_orphan,
    trim_post_ret_padding,
)
from smda.SmdaConfig import SmdaConfig


class _PolicySnapshot:
    """Minimal disassembly-shaped snapshot for pure helper unit tests."""

    def __init__(self, **fields):
        self.functions = fields.get("functions", {})
        self.function_borders = fields.get("function_borders", {})
        self.code_refs_to = fields.get("code_refs_to", {})
        self.code_refs_from = fields.get("code_refs_from", {})
        self.ins2fn = fields.get("ins2fn", {})
        self.exported_functions = fields.get("exported_functions", set())
        self.function_symbols = fields.get("function_symbols", {})
        oep = fields.get("oep")
        base_addr = fields.get("base_addr", 0)
        if "binary_info" in fields:
            self.binary_info = fields["binary_info"]
        else:
            self.binary_info = SimpleNamespace(base_addr=base_addr, getOep=lambda: oep)


def _candidate(**fields):
    defaults = {
        "is_initial_candidate": True,
        "call_ref_sources": set(),
        "is_gap_candidate": False,
        "is_tailcall": False,
        "is_symbol": False,
        "is_exception_handler": False,
    }
    defaults.update(fields)
    defaults.setdefault("hasCommonFunctionStart", lambda: True)
    return SimpleNamespace(**defaults)


class TestReportPolicy(unittest.TestCase):
    def _cutwail_like_policy_snapshot(self):
        config = SmdaConfig()
        with open("tests/cutwail_xored", "rb") as handle:
            data = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        from smda.common.BinaryInfo import BinaryInfo as BI
        from smda.utility.FileLoader import FileLoader

        loader = FileLoader("/", map_file=True)
        loader._loadFile(data)
        binary_info = BI(loader.getData())
        binary_info.base_addr = loader.getBaseAddress()
        binary_info.bitness = loader.getBitness()
        binary_info.code_areas = loader.getCodeAreas()
        binary_info.oep = binary_info.getOep()
        disassembler = IntelDisassembler(config)
        import smda.intel.ReportPolicy as report_policy

        saved = report_policy.apply_intel_report_policy
        report_policy.apply_intel_report_policy = lambda _disassembler: {}
        try:
            disassembly = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        finally:
            report_policy.apply_intel_report_policy = saved
        return disassembly, disassembler.fc_manager.candidates

    def test_cutwail_orphans_are_detected_before_policy(self):
        disassembly, candidates = self._cutwail_like_policy_snapshot()
        self.assertTrue(is_prologue_only_orphan(0x4002420, disassembly, candidates[0x4002420], candidates))
        merge_children = {child for _parent, child in find_boundary_merge_pairs(disassembly, candidates)}
        self.assertIn(0x4001630, merge_children)

    def test_cutwail_report_excludes_orphans_after_policy(self):
        config = SmdaConfig()
        with open("tests/cutwail_xored", "rb") as handle:
            data = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        from smda.Disassembler import Disassembler

        report = Disassembler(config).disassembleUnmappedBuffer(data)
        self.assertNotIn(0x4002420, report.xcfg)
        self.assertNotIn(0x4001630, report.xcfg)
        self.assertIn("rooted_instruction_count", report.statistics.toDict())

    def test_trim_post_ret_padding_drops_synthetic_tail(self):
        disassembly = DisassemblyResult()
        disassembly.binary_info = BinaryInfo(b"\xc3\xcc\xcc")
        disassembly.binary_info.base_addr = 0x401000
        fn_start = 0x401000
        disassembly.functions[fn_start] = [[(0x401000, 1, "ret", "", b"\xc3"), (0x401001, 2, "db", "", b"\xcc\xcc")]]
        disassembly.function_borders[fn_start] = (0x401000, 0x401003)
        disassembly.instructions[0x401000] = ("ret", 1)
        disassembly.instructions[0x401001] = ("db", 2)
        for addr in range(0x401000, 0x401003):
            ins = 0x401000 if addr == 0x401000 else 0x401001
            disassembly.code_map[addr] = ins
            disassembly.ins2fn[addr] = fn_start
        removed = trim_post_ret_padding(disassembly)
        self.assertIn(0x401001, removed)
        self.assertEqual(disassembly.function_borders[fn_start][1], 0x401001)

    def test_trim_post_ret_padding_keeps_partial_padding_before_real_instruction(self):
        disassembly = DisassemblyResult()
        disassembly.binary_info = BinaryInfo(b"\xc3\xcc\x31")
        disassembly.binary_info.base_addr = 0x401000
        fn_start = 0x401000
        disassembly.functions[fn_start] = [
            [
                (0x401000, 1, "ret", "", b"\xc3"),
                (0x401001, 1, "db", "", b"\xcc"),
                (0x401002, 1, "xor", "eax, eax", b"\x31"),
            ]
        ]
        disassembly.function_borders[fn_start] = (0x401000, 0x401003)
        disassembly.instructions[0x401000] = ("ret", 1)
        disassembly.instructions[0x401001] = ("db", 1)
        disassembly.instructions[0x401002] = ("xor", 1)
        for addr in range(0x401000, 0x401003):
            disassembly.code_map[addr] = addr
            disassembly.ins2fn[addr] = fn_start

        removed = trim_post_ret_padding(disassembly)

        self.assertEqual(removed, set())
        self.assertIn(0x401001, disassembly.instructions)
        self.assertEqual(disassembly.function_borders[fn_start], (0x401000, 0x401003))

    def test_remove_function_cleans_inbound_and_outbound_refs_before_maps(self):
        disassembly = DisassemblyResult()
        disassembly.functions = {
            0x1000: [[(0x1000, 1, "call", "0x2002", b"")]],
            0x2000: [[(0x2000, 2, "jmp", "0x3000", b""), (0x2002, 1, "ret", "", b"")]],
            0x3000: [[(0x3000, 1, "ret", "", b"")]],
            0x4000: [[(0x4000, 1, "call", "0x5000", b"")]],
            0x5000: [[(0x5000, 1, "ret", "", b"")]],
        }
        disassembly.function_borders = {
            0x1000: (0x1000, 0x1001),
            0x2000: (0x2000, 0x2003),
            0x3000: (0x3000, 0x3001),
            0x4000: (0x4000, 0x4001),
            0x5000: (0x5000, 0x5001),
        }
        for fn_start, blocks in disassembly.functions.items():
            for block in blocks:
                for addr, size, mnemonic, *_rest in block:
                    disassembly.instructions[addr] = (mnemonic, size)
                    for offset in range(size):
                        disassembly.code_map[addr + offset] = addr
                        disassembly.ins2fn[addr + offset] = fn_start
        disassembly.addCodeRefs(0x1000, 0x2002)
        disassembly.addCodeRefs(0x2000, 0x3000)
        disassembly.addCodeRefs(0x4000, 0x5000)

        _remove_function(disassembly, 0x2000)

        self.assertNotIn(0x2000, disassembly.functions)
        self.assertNotIn(0x2002, disassembly.code_refs_to)
        self.assertNotIn(0x2000, disassembly.code_refs_from)
        self.assertNotIn(0x2000, disassembly.code_refs_to.get(0x3000, set()))
        self.assertEqual(disassembly.code_refs_from[0x4000], {0x5000})
        self.assertEqual(disassembly.code_refs_to[0x5000], {0x4000})

    def test_rooted_metrics_include_connected_fields(self):
        disassembly, candidates = self._cutwail_like_policy_snapshot()
        metrics = compute_connected_and_rooted_metrics(disassembly, candidates)
        self.assertIn("connected_function_count", metrics)
        self.assertIn("rooted_instruction_count", metrics)
        self.assertIn(metrics["rooted_mode"], ("seed-closure", "xref-closure", "all-instructions"))

    def test_orphan_detection_on_snapshot(self):
        snapshot = _PolicySnapshot(
            functions={0x2000: [[(0x2000, 1, "ret", "", b"")]]},
            function_borders={0x2000: (0x2000, 0x2001)},
            code_refs_to={},
            ins2fn={0x2000: 0x2000},
        )
        orphan_candidate = _candidate()
        self.assertTrue(is_prologue_only_orphan(0x2000, snapshot, orphan_candidate, {0x2000: orphan_candidate}))

        seeded = _PolicySnapshot(
            functions={0x1000: [[(0x1000, 1, "ret", "", b"")]]},
            function_borders={0x1000: (0x1000, 0x1001)},
            exported_functions={0x1000},
            ins2fn={0x1000: 0x1000},
        )
        seed_candidate = _candidate()
        self.assertFalse(is_prologue_only_orphan(0x1000, seeded, seed_candidate, {0x1000: seed_candidate}))

    def test_inbound_ref_detection_ignores_intraprocedural_refs(self):
        snapshot = _PolicySnapshot(
            functions={0x2000: [[(0x2000, 1, "call", "0x2005", b""), (0x2005, 1, "ret", "", b"")]]},
            function_borders={0x2000: (0x2000, 0x2006)},
            code_refs_to={0x2005: {0x2000}},
            ins2fn={0x2000: 0x2000, 0x2005: 0x2000},
        )
        candidate = _candidate()
        self.assertTrue(is_prologue_only_orphan(0x2000, snapshot, candidate, {0x2000: candidate}))

        referenced = _PolicySnapshot(
            functions={
                0x1000: [[(0x1000, 1, "call", "0x2000", b"")]],
                0x2000: [[(0x2000, 1, "ret", "", b"")]],
            },
            function_borders={0x1000: (0x1000, 0x1001), 0x2000: (0x2000, 0x2001)},
            code_refs_to={0x2000: {0x1000}},
            ins2fn={0x1000: 0x1000, 0x2000: 0x2000},
        )
        callee = _candidate()
        self.assertFalse(is_prologue_only_orphan(0x2000, referenced, callee, {0x2000: callee}))

    def test_rooted_metrics_on_snapshot(self):
        snapshot = _PolicySnapshot(
            functions={
                0x1000: [[(0x1000, 1, "call", "0x2000", b"")]],
                0x2000: [[(0x2000, 1, "ret", "", b"")]],
            },
            function_borders={0x1000: (0x1000, 0x1001), 0x2000: (0x2000, 0x2001)},
            code_refs_from={0x1000: {0x2000}},
            code_refs_to={0x2000: {0x1000}},
            ins2fn={0x1000: 0x1000, 0x2000: 0x2000},
            base_addr=0x1000,
            oep=0,
        )
        candidates = {0x1000: _candidate(is_symbol=True), 0x2000: _candidate()}
        metrics = compute_connected_and_rooted_metrics(snapshot, candidates)
        self.assertEqual(metrics["rooted_mode"], "seed-closure")
        self.assertGreaterEqual(metrics["rooted_function_count"], 1)

    def test_pe_export_buffer_disassemble_has_five_instructions(self):
        with open("tests/pe_export_label_test_xored", "rb") as handle:
            data = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        from smda.Disassembler import Disassembler

        report = Disassembler(SmdaConfig()).disassembleBuffer(data, 0x400000)
        function = report.getFunction(0x401000)
        self.assertIsNotNone(function)
        self.assertEqual(function.num_instructions, 5)
        self.assertGreater(len(function.getPicHashAsHex()), 0)

    def test_disassemble_buffer_auto_detect_survives_empty_code_areas(self):
        with open("tests/pe_export_label_test_xored", "rb") as handle:
            data = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        from smda.Disassembler import Disassembler
        from smda.utility.MemoryFileLoader import MemoryFileLoader

        with patch.object(MemoryFileLoader, "getCodeAreas", return_value=[]):
            report = Disassembler(SmdaConfig()).disassembleBuffer(data, 0x400000)
        function = report.getFunction(0x401000)
        self.assertIsNotNone(function)
        self.assertEqual(function.num_instructions, 5)

    def test_plan_buffer_entry_points_match_policy_expectations(self):
        from smda.Disassembler import Disassembler

        config = SmdaConfig()
        with open("tests/cutwail_xored", "rb") as handle:
            cutwail = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        cutwail_report = Disassembler(config).disassembleBuffer(cutwail, 0x4000000)
        self.assertEqual(cutwail_report.num_functions, 31)
        self.assertNotIn(0x4002420, cutwail_report.xcfg)
        self.assertNotIn(0x4001630, cutwail_report.xcfg)
        stats = cutwail_report.statistics.toDict()
        self.assertIn("rooted_instruction_count", stats)
        self.assertIn("connected_function_count", stats)

        with open("tests/mirai_x64_xored", "rb") as handle:
            mirai = bytes(byte ^ (index % 256) for index, byte in enumerate(handle.read()))
        mirai_report = Disassembler(config).disassembleBuffer(mirai, 0)
        self.assertEqual(mirai_report.num_functions, 135)


if __name__ == "__main__":
    unittest.main()
