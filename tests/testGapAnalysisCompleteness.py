import unittest

from smda.common.BinaryInfo import BinaryInfo
from smda.intel.CfgEdgeValidator import CfgEdgeValidator
from smda.intel.FunctionCandidate import FunctionCandidate
from smda.intel.FunctionCandidateManager import FunctionCandidateManager
from smda.intel.IntelDisassembler import IntelDisassembler
from smda.SmdaConfig import SmdaConfig


class TestGapAnalysisCompleteness(unittest.TestCase):
    def _unaligned_loop_fixture(self):
        # main @0x1000 calls unaligned target 0x1012; callee is a prologue + jmp back-edge, no ret.
        callee = 0x1012
        buf = (
            b"\x55"  # 0x1000: push rbp
            + b"\x48\x89\xe5"  # mov rbp, rsp
            + b"\xe8\x09\x00\x00\x00"  # call 0x1012
            + b"\x5d\xc3"  # pop rbp; ret
            + b"\xcc" * (callee - 0x100C)
            + b"\x55"  # 0x1012: push rbp
            + b"\x48\x89\xe5"  # mov rbp, rsp
            + b"\x48\x83\xec\x40"  # sub rsp, 0x40
            + b"\x31\xc0"  # xor eax, eax
            + b"\xeb\xf6"  # jmp 0x101a -> 0x1016
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(0x1000, 0x1000 + len(buf))]
        binary_info.oep = 0
        binary_info._callee_addr = callee
        return binary_info

    def test_trusted_candidate_bypasses_alignment_filter(self):
        binary_info = self._unaligned_loop_fixture()
        candidate = FunctionCandidate(binary_info, binary_info._callee_addr)
        candidate.setInitialCandidate(True)
        candidate.addCallRef(0x1004)

        self.assertEqual(candidate.alignment, 0)
        self.assertTrue(candidate.bypassesAlignmentFilter())
        self.assertTrue(candidate.bypassesGapSanityCheck())

    def test_unaligned_call_ref_target_recovered_with_default_alignment(self):
        config = SmdaConfig()
        self.assertTrue(config.USE_ALIGNMENT)
        binary_info = self._unaligned_loop_fixture()
        callee = binary_info._callee_addr
        result = IntelDisassembler(config).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        self.assertIn(callee, result.code_map)
        self.assertIn(0x1000, result.functions)
        self.assertEqual(result.ins2fn.get(callee), result.ins2fn[callee])

    def test_gap_sweep_retries_trusted_candidate_in_same_interval(self):
        binary_info = self._unaligned_loop_fixture()
        callee = binary_info._callee_addr
        manager = FunctionCandidateManager(SmdaConfig())
        manager.disassembly = type(
            "D",
            (),
            {
                "code_map": {},
                "binary_info": binary_info,
                "getRawBytes": lambda _self, offset, size: binary_info.binary[offset : offset + size],
            },
        )()
        manager.ensureCandidate(callee)
        manager.candidates[callee].setInitialCandidate(True)
        manager.candidates[callee].addCallRef(0x1004)
        manager.function_gaps = [[0x100C, 0x1040, 0x34]]
        manager.markGapAttempted(0x100C)
        retry = manager.nextTrustedCandidateInGap(0x100C)
        self.assertEqual(retry, callee)

    def _switch_dispatch_fixture(self):
        # Parent function with interior dispatch targets converging at a shared block.
        shared = 0x1044
        buf = (
            b"\x55"
            + b"\x48\x89\xe5"
            + b"\xeb\x2d"
            + b"\xcc" * (0x1016 - 0x1006)
            + b"\x48\x89\xe7"
            + b"\xe8\x00\x00\x00\x00"
            + b"\xeb\x2a"
            + b"\xcc" * (0x102B - 0x1020)
            + b"\x48\x89\xf8"
            + b"\xeb\x18"
            + b"\xcc" * (0x1035 - 0x102F)
            + b"\x31\xc0"
            + b"\xeb\x0c"
            + b"\xcc" * (shared - 0x103A)
            + b"\x5d\xc3"
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(0x1000, 0x1000 + len(buf))]
        binary_info.oep = 0
        return binary_info, shared

    def test_interior_gap_blocks_extend_parent_without_oversplit(self):
        binary_info, shared = self._switch_dispatch_fixture()
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        parent = 0x1000
        self.assertIn(parent, result.functions)
        self.assertNotIn(0x1016, result.functions)
        self.assertNotIn(0x102B, result.functions)
        self.assertEqual(result.ins2fn.get(shared), parent)
        self.assertEqual(result.ins2fn.get(0x1016), parent)

    def test_cfg_edge_validator_reports_clean_fixture(self):
        binary_info = self._unaligned_loop_fixture()
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        summary = CfgEdgeValidator(result).summarize()
        self.assertEqual(summary["mismatches"], 0)

    def test_interior_merge_preserves_instruction_count(self):
        binary_info, shared = self._switch_dispatch_fixture()
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        parent = 0x1000
        parent_insn_starts = sorted(addr for addr in result.instructions if result.ins2fn.get(addr) == parent)
        self.assertGreaterEqual(len(parent_insn_starts), 8)
        self.assertIn(shared, parent_insn_starts)

    def test_switch_dispatch_fixture_has_full_instruction_recall(self):
        binary_info, shared = self._switch_dispatch_fixture()
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        parent = 0x1000
        parent_starts = {addr for addr in result.instructions if result.ins2fn.get(addr) == parent}
        completeness = CfgEdgeValidator(result).measureExecutableCompleteness(
            [(binary_info.base_addr, binary_info.base_addr + len(binary_info.binary), "fixture")]
        )
        self.assertGreaterEqual(completeness["recall"], 0.99)
        self.assertIn(shared, parent_starts)

    def test_recovered_function_start_collision_is_not_recorded_as_failure(self):
        config = SmdaConfig()
        disassembler = IntelDisassembler(config)
        binary_info = self._unaligned_loop_fixture()
        result = disassembler.analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        callee = binary_info._callee_addr
        fn_start = result.ins2fn[callee]
        disassembler.analyzeFunction(fn_start)

        candidate = disassembler.fc_manager.getFunctionCandidate(fn_start)
        self.assertFalse(candidate.analysis_aborted)
        self.assertTrue(candidate.isFinished())

    def test_incremental_border_cache_matches_full_rebuild(self):
        # The sorted-borders cache is maintained incrementally during gap recovery
        # (updateBorder / removeBorder / syncBorder) instead of being re-sorted on every
        # mutation. It must stay bit-identical to a from-scratch sorted(function_borders),
        # and containment lookups must match a brute-force search after every change.
        manager = FunctionCandidateManager(SmdaConfig())
        borders = {}
        manager.disassembly = type("D", (), {"function_borders": borders})()

        def brute_contains(addr):
            matches = [
                (fmax - fmin, start) for start, (fmin, fmax) in borders.items() if start != addr and fmin <= addr < fmax
            ]
            return min(matches)[1] if matches else None

        def assert_consistent():
            cached = manager._get_sorted_borders()
            self.assertEqual(
                {tuple(e) for e in cached},
                {(fmin, fmax, start) for start, (fmin, fmax) in borders.items()},
            )
            starts = [e[0] for e in cached]
            self.assertEqual(starts, sorted(starts))
            self.assertGreaterEqual(manager._max_fn_len, max((f - m for m, f, _ in cached), default=0))
            for probe in (0x1008, 0x1040, 0x1055, 0x1200, 0x900):
                self.assertEqual(manager.getContainingFunctionStart(probe), brute_contains(probe))

        # seed + initial full build
        for start in (0x1000, 0x1100, 0x1050):
            borders[start] = (start, start + 0x20)
        manager._borders_dirty = True
        assert_consistent()

        # incremental insert of a function that contains an earlier probe
        borders[0x1004] = (0x1004, 0x1080)
        manager.updateBorder(0x1004, 0x1004, 0x1080)
        assert_consistent()

        # resize-grow (a re-merge extends the parent's fmax)
        borders[0x1000] = (0x1000, 0x1060)
        manager.updateBorder(0x1000, 0x1000, 0x1060)
        assert_consistent()

        # remove a function (pruned interior child / reverted gap function)
        del borders[0x1050]
        manager.removeBorder(0x1050)
        assert_consistent()

        # syncBorder upsert then drop, mirroring analyzeFunction finalize vs abort
        borders[0x1200] = (0x1200, 0x1240)
        manager.syncBorder(0x1200)
        assert_consistent()
        del borders[0x1200]
        manager.syncBorder(0x1200)
        assert_consistent()


if __name__ == "__main__":
    unittest.main()
