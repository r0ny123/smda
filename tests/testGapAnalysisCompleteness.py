import unittest
from types import SimpleNamespace

from smda.common.BinaryInfo import BinaryInfo
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.DisassemblyResult import DisassemblyResult
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

    def test_deferred_interior_hole_merge_flushes_on_attempt_limit(self):
        class StubManager:
            function_gaps = [(0x1001, 0x1010, 0xF)]

            def _gapIntervalForAddr(self, _addr):
                return (0x1001, 0x1010)

            def getInteriorExtensionParent(self, addr):
                return parent if addr == 0x1001 else None

            def updateBorder(self, _start, _fmin, _fmax):
                return

        class StubState:
            num_blocks_analyzed = 1
            instructions = [(0x1001, 1, "ret", "", b"\xc3")]
            code_refs = set()
            data_refs = set()
            data_bytes = set()

        parent = 0x1000
        disassembler = IntelDisassembler(SmdaConfig())
        result = DisassemblyResult()
        result.functions[parent] = [[(parent, 1, "nop", "", b"\x90")]]
        result.function_borders[parent] = (parent, parent + 0x10)
        result.instructions[parent] = ("nop", 1)
        result.code_map[parent] = parent
        result.ins2fn[parent] = parent
        disassembler.disassembly = result
        disassembler.fc_manager = StubManager()
        disassembler._gap_extra_analyses = 0
        disassembler._gap_recovery_limit = 10

        def analyze_and_merge(_addr, _timeout=None):
            state = StubState()
            disassembler._mergeExtensionIntoParent(state, parent)
            return state

        disassembler._analyze_gap_function = analyze_and_merge

        disassembler._fillInteriorFunctionHoles(max_attempts=1)

        self.assertIsNone(disassembler._deferred_parent_merges)
        self.assertEqual(result.ins2fn.get(0x1001), parent)
        parent_starts = {ins[0] for block in result.functions[parent] for ins in block}
        self.assertIn(0x1001, parent_starts)

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

    def test_cfg_completeness_fallback_unpacks_section_tuples(self):
        binary_info = BinaryInfo(b"\xc3\x90")
        binary_info.base_addr = 0x1000
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(0x1000, 0x1001)]
        binary_info.getSections = lambda: [(".text", 0x1000, 0x1001), (".data", 0x1001, 0x1002)]
        result = DisassemblyResult()
        result.binary_info = binary_info
        result.instructions[0x1000] = ("ret", 1)
        result.code_map[0x1000] = 0x1000

        completeness = CfgEdgeValidator(result).measureExecutableCompleteness()

        self.assertEqual(completeness["capstone_instruction_starts"], 1)
        self.assertEqual(completeness["recall"], 1.0)

    def test_revert_gap_function_only_removes_gap_owner_instructions(self):
        class StubState:
            def __init__(self):
                self.instructions = []
                self.code_refs = set()
                self.data_refs = set()
                self.reverted = []

            def revertAnalysis(self):
                self.reverted = list(self.instructions)

        owner = 0x2000
        other_owner = 0x3000
        colliding_addr = owner
        other_addr_in_border = owner + 4
        state = StubState()
        disassembler = IntelDisassembler(SmdaConfig())
        result = DisassemblyResult()
        result.functions[owner] = [[(owner, 1, "push", "", b""), (other_addr_in_border, 1, "ret", "", b"")]]
        result.function_borders[owner] = (owner, owner + 8)
        result.instructions[owner] = ("push", 1)
        result.instructions[other_addr_in_border] = ("ret", 1)
        result.ins2fn[owner] = owner
        result.ins2fn[other_addr_in_border] = other_owner
        disassembler.disassembly = result
        disassembler.backend = SimpleNamespace(createAnalysisState=lambda _owner, _disassembly: state)
        disassembler.fc_manager = SimpleNamespace(
            candidates={owner: SimpleNamespace(is_gap_candidate=True)},
            removeBorder=lambda _owner: None,
            updateAnalysisAborted=lambda _owner, _reason: None,
        )

        self.assertTrue(disassembler._revertGapFunction(colliding_addr, 0x1000))
        self.assertEqual([ins[0] for ins in state.reverted], [owner])

    def test_gap_candidate_without_code_map_growth_is_not_treated_as_extension(self):
        class StubState:
            num_blocks_analyzed = 1

            def getBlocks(self):
                return [[(0x2000, 1, "ret", "", b"")]]

        class StubCandidateManager:
            def __init__(self):
                self.gap_pointer = None
                self.previously_analyzed_gap = 0
                self.clear_count = 0
                self.marked = []
                self.aborted = []
                self.advanced = []
                self._returned = False

            def clearGapAttempts(self):
                self.clear_count += 1

            def refreshFunctionGaps(self):
                return

            def nextGapCandidate(self, _next_gap=None):
                if self._returned:
                    return None
                self._returned = True
                return 0x2000

            def markGapAttempted(self, addr):
                self.marked.append(addr)

            def nextTrustedCandidateInGap(self, _addr):
                return None

            def updateAnalysisAborted(self, addr, reason):
                self.aborted.append((addr, reason))

            def advanceGapScan(self, addr):
                self.advanced.append(addr)

        disassembler = IntelDisassembler(SmdaConfig())
        disassembler.backend = SimpleNamespace(name="stub")
        disassembler.disassembly = DisassemblyResult()
        disassembler.disassembly.binary_info = BinaryInfo(b"")
        disassembler.fc_manager = StubCandidateManager()
        disassembler.analyzeFunction = lambda _addr, as_gap=False: StubState()

        disassembler._runGapRecoveryPasses()

        self.assertEqual(disassembler.fc_manager.clear_count, 1)
        self.assertEqual(disassembler.fc_manager.marked, [0x2000])
        self.assertEqual(disassembler.fc_manager.advanced, [0x2000])
        self.assertEqual(disassembler.fc_manager.aborted[0][0], 0x2000)

    def test_plt_recovery_uses_section_tuple_ranges(self):
        disassembler = IntelDisassembler(SmdaConfig())
        result = DisassemblyResult()
        result.binary_info = SimpleNamespace(
            getSections=lambda: [(".plt", 0x1000, 0x100C), (".plt.got", 0x2000, 0x2006)]
        )
        disassembler.disassembly = result
        attempted = []
        disassembler._analyze_gap_function = lambda addr, _timeout=None: attempted.append(addr) or None

        disassembler._recoverPltStubs()

        self.assertEqual(attempted, [0x1000, 0x1006])

    def test_interior_jmp_ref_target_splits_large_mapped_parent(self):
        base = 0x10000
        prologue = b"\x55\x48\x89\xe5"
        jmp_site = base + 0x500
        callee = base + 0x12000
        rel = callee - (jmp_site + 5)
        buf = (
            prologue
            + b"\x90" * (jmp_site - base - len(prologue))
            + b"\xe9"
            + rel.to_bytes(4, "little", signed=True)
            + b"\x90" * (callee - jmp_site - 5)
            + prologue
            + b"\x5d\xc3"
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(base, base + len(buf))]
        binary_info.oep = 0
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        self.assertIn(base, result.functions)
        self.assertIn(callee, result.functions)
        self.assertEqual(result.ins2fn.get(callee), callee)

    def test_unmapped_call_ref_recovers_hole_in_large_parent(self):
        base = 0x10000
        prologue = b"\x55\x48\x89\xe5"
        call_site = base + 0x1000
        hole_fn = base + 0x5001
        after_hole = base + 0x6000
        rel = hole_fn - (call_site + 5)
        buf = (
            prologue
            + b"\x90" * (call_site - base - len(prologue))
            + b"\xe8"
            + rel.to_bytes(4, "little", signed=True)
            + b"\x90" * (hole_fn - (call_site + 5))
            + prologue
            + b"\x5d\xc3"
            + b"\x90" * (after_hole - (hole_fn + len(prologue) + 2))
            + b"\xc3"
            + b"\x90" * (base + 0x12000 - after_hole - 1)
            + b"\xc3"
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(base, base + len(buf))]
        binary_info.oep = 0
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        self.assertIn(base, result.functions)
        self.assertIn(hole_fn, result.functions)

    def test_lea_rip_relative_recovers_unmapped_hole_in_large_parent(self):
        base = 0x10000
        prologue = b"\x55\x48\x89\xe5"
        lea_site = base + 0x1000
        hole_fn = base + 0x5001
        after_hole = base + 0x6000
        rel = hole_fn - (lea_site + 7)
        buf = (
            prologue
            + b"\x90" * (lea_site - base - len(prologue))
            + b"\x48\x8d\x0d"
            + rel.to_bytes(4, "little", signed=True)
            + b"\xe9"
            + (after_hole - (lea_site + 7) - 5).to_bytes(4, "little", signed=True)
            + b"\x90" * (hole_fn - (lea_site + 7) - 5)
            + prologue
            + b"\x5d\xc3"
            + b"\x90" * (base + 0x12000 - after_hole)
            + b"\xc3"
        )
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base
        binary_info.bitness = 64
        binary_info.architecture = "intel"
        binary_info.code_areas = [(base, base + len(buf))]
        binary_info.oep = 0
        result = IntelDisassembler(SmdaConfig()).analyzeBuffer(binary_info, cbAnalysisTimeout=None)
        self.assertIn(base, result.functions)
        self.assertIn(hole_fn, result.functions)

    def test_unmapped_direct_jmp_target_without_prologue_is_recovered_first(self):
        base = 0x1000
        target = base + 0x100
        rel = target - (base + 5)
        buf = b"\xe9" + rel.to_bytes(4, "little", signed=True) + b"\xcc" * (target - base - 5) + b"\xc1\xc0\x03\xc3"
        binary_info = BinaryInfo(buf)
        binary_info.base_addr = base
        binary_info.bitness = 32
        binary_info.architecture = "intel"
        binary_info.code_areas = [(base, base + len(buf))]

        disassembler = IntelDisassembler(SmdaConfig())
        result = DisassemblyResult()
        result.setBinaryInfo(binary_info)
        result.functions[base] = [[(base, 5, "jmp", hex(target), buf[:5])]]
        result.function_borders[base] = (base, base + 5)
        result.instructions[base] = ("jmp", 5)
        for offset in range(5):
            result.code_map[base + offset] = base
            result.ins2fn[base + offset] = base

        disassembler.disassembly = result
        disassembler.tailcall_analyzer = TailcallAnalyzer()
        disassembler.indcall_analyzer = disassembler.backend.createIndirectCallAnalyzer(disassembler)
        disassembler.jumptable_analyzer = disassembler.backend.createJumpTableAnalyzer(disassembler)
        disassembler.fc_manager = disassembler.backend.createCandidateManager(disassembler.config)
        disassembler.fc_manager.init(result)
        disassembler.capstone = disassembler.backend.createCapstone(binary_info.bitness)
        disassembler._reset_gap_recovery_budget()

        disassembler._recoverUnmappedDirectBranchTargets()

        self.assertIn(target, result.functions)
        self.assertEqual(result.ins2fn.get(target), target)
        self.assertIn(target, result.code_refs_from[base])

    def test_direct_jmp_ref_allows_large_parent_split_without_prologue(self):
        parent = 0x10000
        ref_from = parent + 0x10
        target = parent + 0x12000
        disassembler = IntelDisassembler(SmdaConfig())
        result = DisassemblyResult()
        result.functions[parent] = [[(ref_from, 5, "jmp", hex(target), b"\xe9\xeb\xff\x00\x00")]]
        result.function_borders[parent] = (parent, target + 0x20)
        result.instructions[ref_from] = ("jmp", 5)
        for addr in range(ref_from, ref_from + 5):
            result.code_map[addr] = ref_from
            result.ins2fn[addr] = parent
        result.code_map[target] = target
        result.ins2fn[target] = parent
        result.addCodeRefs(ref_from, target)
        disassembler.disassembly = result

        self.assertTrue(disassembler._should_split_interior_code_ref_target(target, parent, {ref_from}))

    def test_direct_branch_recovery_priority_handles_partial_result_without_binary_info(self):
        disassembler = IntelDisassembler(SmdaConfig())
        disassembler.disassembly = DisassemblyResult()

        self.assertEqual(disassembler._direct_branch_recovery_priority(0x2000, {0x1000}, {}), (2, 0x2000))

    def test_failed_interior_split_restores_parent_code_refs(self):
        class StubCandidateManager:
            def addCandidate(self, _addr, reference_source=None):
                self.reference_source = reference_source

            def updateBorder(self, _start, _fmin, _fmax):
                return

        def make_disassembler(parent, split, ref_from, instructions):
            disassembler = IntelDisassembler(SmdaConfig())
            result = DisassemblyResult()
            result.functions[parent] = [instructions]
            result.function_borders[parent] = (
                min(ins[0] for ins in instructions),
                max(ins[0] + ins[1] for ins in instructions),
            )
            result.instructions = {ins[0]: (ins[2], ins[1]) for ins in instructions}
            for addr, size, *_rest in instructions:
                for offset in range(size):
                    result.code_map[addr + offset] = addr
                    result.ins2fn[addr + offset] = parent
            result.addCodeRefs(ref_from, split)
            disassembler.disassembly = result
            disassembler.fc_manager = StubCandidateManager()
            disassembler._gap_extra_analyses = 0
            disassembler._gap_recovery_limit = 1
            disassembler.analyzeFunction = lambda _addr: None
            return disassembler, result

        parent = 0x1000
        split = 0x1010
        ref_from = 0x1004
        disassembler, result = make_disassembler(
            parent,
            split,
            ref_from,
            [
                (parent, 1, "push", "", b"\x55"),
                (ref_from, 5, "call", "", b"\xe8\x07\x00\x00\x00"),
                (split, 1, "push", "", b"\x55"),
            ],
        )

        self.assertFalse(disassembler._split_function_at_interior_target(parent, split, ref_from))
        self.assertEqual(result.code_refs_from, {ref_from: {split}})
        self.assertEqual(result.code_refs_to, {split: {ref_from}})

        parent = 0x2000
        split = 0x1FF0
        ref_from = 0x1FF5
        disassembler, result = make_disassembler(
            parent,
            split,
            ref_from,
            [
                (split, 1, "push", "", b"\x55"),
                (ref_from, 5, "call", "", b"\xe8\xf6\xff\xff\xff"),
            ],
        )

        self.assertFalse(disassembler._split_function_at_interior_target(parent, split, ref_from))
        self.assertEqual(result.code_refs_from, {ref_from: {split}})
        self.assertEqual(result.code_refs_to, {split: {ref_from}})

    def test_rolled_back_interior_split_removes_temporary_child_refs(self):
        class StubCandidateManager:
            def addCandidate(self, _addr, reference_source=None):
                self.reference_source = reference_source

            def updateBorder(self, _start, _fmin, _fmax):
                return

            def removeBorder(self, _start):
                return

        parent = 0x3000
        ref_from = parent + 4
        split = parent + 0x20
        after_split = split + 2
        child_target = 0x8000
        unrelated_src = 0x9000
        unrelated_target = 0xA000
        instructions = [
            (parent, 1, "push", "", b"\x55"),
            (ref_from, 5, "jmp", hex(split), b"\xe9\x17\x00\x00\x00"),
            (split, 1, "push", "", b"\x55"),
            (after_split, 1, "ret", "", b"\xc3"),
        ]
        config = SmdaConfig()
        config.GAP_DIRECT_BRANCH_SPLIT_MAX_LOST_INSTRUCTIONS = 0
        disassembler = IntelDisassembler(config)
        result = DisassemblyResult()
        result.functions[parent] = [instructions]
        result.function_borders[parent] = (parent, after_split + 1)
        result.instructions = {ins[0]: (ins[2], ins[1]) for ins in instructions}
        for addr, size, *_rest in instructions:
            for offset in range(size):
                result.code_map[addr + offset] = addr
                result.ins2fn[addr + offset] = parent
        result.addCodeRefs(ref_from, split)
        result.addCodeRefs(unrelated_src, unrelated_target)
        disassembler.disassembly = result
        disassembler.fc_manager = StubCandidateManager()
        disassembler._gap_extra_analyses = 0
        disassembler._gap_recovery_limit = 1

        def analyze_child(_addr):
            result.functions[split] = [[(split, 1, "jmp", hex(child_target), b"\xeb")]]
            result.function_borders[split] = (split, split + 1)
            result.instructions[split] = ("jmp", 1)
            result.code_map[split] = split
            result.ins2fn[split] = split
            result.addCodeRefs(split, child_target)
            return None

        disassembler.analyzeFunction = analyze_child

        self.assertFalse(
            disassembler._split_function_at_interior_target(parent, split, ref_from, preserve_existing_starts=True)
        )
        self.assertEqual(result.code_refs_from[ref_from], {split})
        self.assertEqual(result.code_refs_to[split], {ref_from})
        self.assertNotIn(split, result.code_refs_from)
        self.assertNotIn(child_target, result.code_refs_to)
        self.assertEqual(result.code_refs_from[unrelated_src], {unrelated_target})
        self.assertEqual(result.code_refs_to[unrelated_target], {unrelated_src})
        self.assertEqual(result.ins2fn[after_split], parent)

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
