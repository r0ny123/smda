import bisect
import logging
import re
import struct

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.utility.BracketQueue import BracketQueue
from smda.utility.PriorityQueue import PriorityQueue

from .definitions import DEFAULT_PROLOGUES, GAP_SEQUENCES
from .FunctionCandidate import FunctionCandidate
from .LanguageAnalyzer import LanguageAnalyzer

LOGGER = logging.getLogger(__name__)


class FunctionCandidateManager:
    def __init__(self, config):
        self.config = config
        self.lang_analyzer = None
        self.disassembly = None
        self.bitness = None
        self._code_areas = []
        self.candidates = {}
        self.candidate_queue = []
        self.cached_candidates = None
        self._candidate_offsets = set()
        self.candidate_index = 0
        self._all_call_refs = {}
        self.symbol_addresses = []
        self.identified_alignment = 0
        self.go_objects = None
        self.delphi_kb_objects = None
        self.language_candidates_only = False
        # gap filling
        self.function_gaps = None
        self.max_function_addr = 0
        self.gap_pointer = None
        self.previously_analyzed_gap = 0
        self._gap_attempted_addrs = set()
        self.capstone = None
        # backstop against memory usage explosion during candidate identification
        self._candidate_cap_logged = False
        self._cb_analysis_timeout = None
        self._borders_dirty = True
        self._cached_borders = None
        self._cached_borders_starts = []
        self._max_fn_len = 0
        self._code_area_starts = []
        self._code_area_ends = []

    def init(self, disassembly, cbAnalysisTimeout=None):
        if disassembly.binary_info.code_areas:
            self._code_areas = sorted(disassembly.binary_info.code_areas, key=lambda x: x[0])
            self._code_area_starts = [a[0] for a in self._code_areas]
            self._code_area_ends = [a[1] for a in self._code_areas]
        else:
            self._code_areas = []
            self._code_area_starts = []
            self._code_area_ends = []
        self.disassembly = disassembly
        self._cb_analysis_timeout = cbAnalysisTimeout
        self.lang_analyzer = LanguageAnalyzer(disassembly)
        self.disassembly.language = self.lang_analyzer.identify()
        self.bitness = disassembly.binary_info.bitness
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_32)
        if self.bitness == 64:
            self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        self.locateCandidates()
        self.disassembly.identified_alignment = self.identified_alignment
        self._buildQueue()

    def _passesCodeFilter(self, addr):
        if addr is None:
            return False
        if self._code_areas:
            idx = bisect.bisect_right(self._code_area_starts, addr) - 1
            return idx >= 0 and addr < self._code_area_ends[idx]
        return True

    def getBitMask(self):
        if self.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def setInitialCandidate(self, addr):
        if addr in self.candidates:
            self.candidates[addr].setInitialCandidate(True)

    def isFunctionCandidate(self, addr):
        return addr in self.candidates

    def getFunctionCandidate(self, addr):
        if addr in self.candidates:
            return self.candidates[addr]
        return None

    def getAbortedCandidates(self):
        aborted = []
        for addr, candidate in self.candidates.items():
            if candidate.analysis_aborted:
                aborted.append(addr)
        return aborted

    def updateAnalysisAborted(self, addr, reason):
        LOGGER.debug("function analysis of 0x%08x aborted: %s", addr, reason)
        if addr in self.candidates:
            self.candidates[addr].setAnalysisAborted(reason)

    def updateAnalysisFinished(self, addr):
        LOGGER.debug("function analysis of 0x%08x successfully completed.", addr)
        if addr in self.candidates:
            self.candidates[addr].setAnalysisCompleted()

    def updateCandidates(self, state):
        if self.config.HIGH_ACCURACY:
            conflicts = state.identifyCallConflicts(self._all_call_refs)
            if conflicts:
                use_bracket = getattr(self.config, "CANDIDATE_QUEUE", "") == "BracketQueue"
                for candidate_addr, conflict in conflicts.items():
                    self.candidates[candidate_addr].removeCallRefs(conflict)
                    # depending on implementation, update candidates individually
                    if use_bracket:
                        self.candidate_queue.update(self.candidates[candidate_addr])
                self.candidate_queue.update()

    def _addCappedCallRef(self, candidate, source_ref):
        """add an inbound call reference, honoring MAX_CALL_REFS_PER_CANDIDATE to bound set growth and rescoring."""
        cap = getattr(self.config, "MAX_CALL_REFS_PER_CANDIDATE", 0)
        if cap == 0 or len(candidate.call_ref_sources) < cap:
            candidate.addCallRef(source_ref)

    def addCandidate(self, addr, is_gap=False, reference_source=None):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr not in self.candidates:
            return False
        self.candidates[addr].setIsGapCandidate(is_gap)
        if reference_source:
            # register in _all_call_refs as well so late references still
            # participate in HIGH_ACCURACY call-conflict resolution
            self._all_call_refs[reference_source] = addr
            self._addCappedCallRef(self.candidates[addr], reference_source)
        self.candidate_queue.add(self.candidates[addr])
        self.candidate_queue.update()

    def getNextFunctionStartCandidate(self):
        strict_gap_promotion = getattr(self.disassembly.binary_info, "architecture", "") == "intel"
        for candidate in self.candidate_queue:
            if not (candidate.isFinished() or candidate.getScore() == 0):
                if strict_gap_promotion and candidate.is_gap_candidate and not candidate.bypassesGapSanityCheck():
                    continue
                if self.language_candidates_only and candidate.lang_spec is None:
                    continue
                if (
                    self.identified_alignment
                    and candidate.alignment < self.identified_alignment
                    and not candidate.bypassesAlignmentFilter()
                ):
                    continue
                yield candidate

    def getFunctionStartCandidates(self):
        return self._candidate_offsets

    def updateFunctionGaps(self):
        # function_borders are half-open [fmin, fmax); derive gaps per code area with the
        # same convention used by DisassemblyResult._finalizeCoverageMetrics so that suffix
        # gaps land on a real boundary and code areas with no recovered function are covered.
        intervals = sorted(self.disassembly.function_borders.values(), key=lambda x: x[0])
        gaps = []
        for area_start, area_end in self._code_areas:
            clipped = []
            for fmin, fmax in intervals:
                start = max(fmin, area_start)
                end = min(fmax, area_end)
                if start < end:
                    clipped.append((start, end))

            merged = []
            for start, end in clipped:
                if not merged or merged[-1][1] < start:
                    merged.append([start, end])
                else:
                    merged[-1][1] = max(merged[-1][1], end)

            cursor = area_start
            for start, end in merged:
                if cursor < start:
                    gaps.append([cursor, start, start - cursor])
                cursor = max(cursor, end)
            if cursor < area_end:
                gaps.append([cursor, area_end, area_end - cursor])
        self.function_gaps = sorted(gaps)

    def initGapSearch(self):
        if self.gap_pointer is None:
            LOGGER.debug("initGapSearch()")
            self.gap_pointer = self.getBitMask()
            self.updateFunctionGaps()
            if self.function_gaps:
                self.gap_pointer = self.function_gaps[0][0]
        LOGGER.debug("initGapSearch() gaps are:")
        for gap in self.function_gaps:
            LOGGER.debug("initGapSearch() 0x%08x - 0x%08x == %d", gap[0], gap[1], gap[2])
        return

    def getNextGap(self, dont_skip=False):
        next_gap = self.getBitMask()
        for gap in self.function_gaps:
            if gap[0] > self.gap_pointer:
                next_gap = gap[0]
                break
        LOGGER.debug(
            "getNextGap(%s) for 0x%08x based on gap_map: 0x%08x",
            dont_skip,
            self.gap_pointer,
            next_gap,
        )
        # we potentially just disassembled a function and want to continue directly behind it in case we would otherwise miss more
        if dont_skip and self.gap_pointer in self.disassembly.code_map:
            function = self.disassembly.ins2fn[self.gap_pointer]
            next_gap = min(next_gap, self.disassembly.function_borders[function][1])
            LOGGER.debug(
                "getNextGap(%s) without skip => after checking versus code map: 0x%08x",
                dont_skip,
                next_gap,
            )
        LOGGER.debug("getNextGap(%s) final gap_ptr: 0x%08x", dont_skip, next_gap)
        return next_gap

    def isEffectiveNop(self, byte_sequence):
        return byte_sequence in GAP_SEQUENCES[len(byte_sequence)]

    def isAlignmentSequence(self, instruction_sequence):
        is_alignment_sequence = False
        instructions_analyzed = 0
        if len(instruction_sequence) > 0:
            current_offset = instruction_sequence[0].address
            for instruction in instruction_sequence:
                if instruction.bytes in GAP_SEQUENCES[len(instruction.bytes)]:
                    instructions_analyzed += 1
                    current_offset += len(instruction.bytes)
                    if current_offset % 16 == 0:
                        is_alignment_sequence = True
                        break
                else:
                    break
        if len(instruction_sequence) > instructions_analyzed and instruction_sequence[
            instructions_analyzed
        ].mnemonic in [
            "leave",
            "ret",
            "retn",
        ]:
            is_alignment_sequence = False
        return is_alignment_sequence

    def nextGapCandidate(self, start_gap_pointer=None):
        if self.language_candidates_only:
            return None
        if self.gap_pointer is None:
            self.initGapSearch()
        if start_gap_pointer:
            self.gap_pointer = start_gap_pointer
        LOGGER.debug(
            "nextGapCandidate() finding new gap candidate, current gap_ptr: 0x%08x",
            self.gap_pointer,
        )
        window_offset = -1
        window_bytes = b""

        def get_window_slice(offset, length):
            nonlocal window_offset, window_bytes
            if window_offset <= offset and offset + length <= window_offset + len(window_bytes):
                start = offset - window_offset
                return window_bytes[start : start + length]
            window_offset = offset
            window_bytes = self.disassembly.getRawBytes(offset, max(256, length))
            return window_bytes[:length]

        while True:
            if self.disassembly.binary_info.base_addr + self.disassembly.binary_info.binary_size < self.gap_pointer:
                LOGGER.debug("nextGapCandidate() gap_ptr: 0x%08x - finishing", self.gap_pointer)
                return None
            gap_offset = self.gap_pointer - self.disassembly.binary_info.base_addr
            if gap_offset >= self.disassembly.binary_info.binary_size:
                return None
            # compatibility with python2/3...
            byte = b""
            try:
                byte = get_window_slice(gap_offset, 1)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.warning("could not fetch raw byte for gap pointer.")
            # try to find padding symbols and skip them
            if byte in GAP_SEQUENCES[1]:
                LOGGER.debug(
                    "nextGapCandidate() found 0xCC / 0x00 - gap_ptr += 1: 0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer += 1
                continue
            # try to find instructions that directly encode as NOP and skip them
            ins_buf = list(self.capstone.disasm_lite(get_window_slice(gap_offset, 15), gap_offset))
            if ins_buf:
                i_address, i_size, i_mnemonic, i_op_str = ins_buf[0]
                if i_mnemonic == "nop":
                    nop_instruction = i_mnemonic + " " + i_op_str
                    nop_length = i_size
                    LOGGER.debug(
                        "nextGapCandidate() found nop instruction (%s) - gap_ptr += %d: 0x%08x",
                        nop_instruction,
                        nop_length,
                        self.gap_pointer,
                    )
                    self.gap_pointer += nop_length
                    continue
            # try to find effective NOPs and skip them.
            found_multi_byte_nop = False
            for gap_length in range(max(GAP_SEQUENCES.keys()), 1, -1):
                if get_window_slice(gap_offset, gap_length) in GAP_SEQUENCES[gap_length]:
                    LOGGER.debug(
                        "nextGapCandidate() found %d byte effective nop - gap_ptr += %d: 0x%08x",
                        gap_length,
                        gap_length,
                        self.gap_pointer,
                    )
                    self.gap_pointer += gap_length
                    found_multi_byte_nop = True
                    break
            if found_multi_byte_nop:
                continue
            # we know this place from data already
            if self.gap_pointer in self.disassembly.data_map:
                LOGGER.debug(
                    "nextGapCandidate() gap_ptr is already inside data map: 0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer += 1
                continue
            if self.gap_pointer in self.disassembly.code_map:
                LOGGER.debug(
                    "nextGapCandidate() gap_ptr is already inside code map: 0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer = self.getNextGap()
                continue
            # we may have a candidate here
            LOGGER.debug("nextGapCandidate() using 0x%08x as candidate", self.gap_pointer)
            start_byte = byte[0] if byte else 0
            existing_candidate = self.candidates.get(self.gap_pointer)
            is_trusted_candidate = existing_candidate is not None and existing_candidate.bypassesGapSanityCheck()
            has_common_prologue = FunctionCandidate(
                self.disassembly.binary_info, self.gap_pointer
            ).hasCommonFunctionStart()
            if self.previously_analyzed_gap == self.gap_pointer:
                LOGGER.debug(
                    "--- HRM, nextGapCandidate() gap_ptr at: 0x%08x was previously analyzed",
                    self.gap_pointer,
                )
                self.gap_pointer = self.getNextGap(dont_skip=True)
            elif not (has_common_prologue or is_trusted_candidate):
                LOGGER.debug(
                    "--- HRM, nextGapCandidate() gap_ptr at: 0x%08x has no common prologue (0x%02x)",
                    self.gap_pointer,
                    start_byte,
                )
                self.gap_pointer = self.getNextGap(dont_skip=True)
            elif self.shouldRejectInteriorGapStart(self.gap_pointer):
                LOGGER.debug(
                    "nextGapCandidate() skipping interior gap candidate @0x%08x",
                    self.gap_pointer,
                )
                self.gap_pointer = self.getNextGap(dont_skip=True)
            else:
                self.previously_analyzed_gap = self.gap_pointer
                self.addGapCandidate(self.gap_pointer)
                return self.gap_pointer
        return None

    def checkFunctionOverlap(self):
        function_boundaries = []
        for function in self.disassembly.functions:
            min_addr = self.getBitMask()
            max_addr = 0
            for block in self.disassembly.functions[function]:
                min_addr = min(min_addr, min([instruction[0] for instruction in block]))
                max_addr = max(
                    max_addr,
                    max([instruction[0] + instruction[1] for instruction in block]),
                )
            function_boundaries.append((min_addr, max_addr))
        current_entry = (0, 0)
        for entry in sorted(function_boundaries):
            if current_entry[1] > entry[0]:
                return True
            current_entry = entry
        return False

    def checkCodePadding(self):
        pattern_functions = []
        for _pattern_count, pattern in enumerate(
            re.finditer(r"((\xCC){2,}|(\x90){2,})", self.disassembly.binary_info.binary), 1
        ):
            pattern_functions.append(pattern.span()[1] + 1)

    def ensureCandidate(self, addr):
        """create candidate if it does not exist yet, returns True if newly created, else False"""
        if addr not in self.candidates:
            cap = getattr(self.config, "MAX_FUNCTION_CANDIDATES", 0)
            if cap and len(self.candidates) >= cap:
                if not self._candidate_cap_logged:
                    LOGGER.warning(
                        "MAX_FUNCTION_CANDIDATES cap (%d) reached during candidate identification; "
                        "refusing further candidates to bound memory usage.",
                        cap,
                    )
                    self._candidate_cap_logged = True
                return False
            self.candidates[addr] = FunctionCandidate(self.disassembly.binary_info, addr)
            return True
        return False

    def addGapCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsGapCandidate(True)

    def markGapAttempted(self, addr):
        self._gap_attempted_addrs.add(addr)

    def clearGapAttempts(self):
        self._gap_attempted_addrs.clear()

    def advanceGapScan(self, failed_addr):
        """Continue the linear gap sweep inside the current interval instead of skipping it."""
        interval = self._gapIntervalForAddr(failed_addr)
        next_addr = failed_addr + 1
        if interval is not None:
            _gap_start, gap_end = interval
            if next_addr >= gap_end:
                self.gap_pointer = gap_end
                return
        self.gap_pointer = next_addr

    def refreshFunctionGaps(self):
        self.function_gaps = None
        # functions may have been recovered/merged since the borders were last cached;
        # invalidate so containment and parent-extension decisions see fresh borders.
        self._borders_dirty = True
        self.updateFunctionGaps()

    def _gapIntervalForAddr(self, addr):
        if not self.function_gaps:
            return None
        for gap_start, gap_end, _ in self.function_gaps:
            if gap_start <= addr < gap_end:
                return gap_start, gap_end
        return None

    def nextTrustedCandidateInGap(self, failed_addr):
        interval = self._gapIntervalForAddr(failed_addr)
        if interval is None:
            return None
        gap_start, gap_end = interval
        for addr in sorted(self.candidates.keys()):
            if addr < gap_start:
                continue
            if addr >= gap_end:
                # candidates are sorted ascending, so nothing further is in this gap
                break
            if addr in self._gap_attempted_addrs or addr in self.disassembly.code_map:
                continue
            candidate = self.candidates[addr]
            if not candidate.bypassesGapSanityCheck():
                continue
            if self.shouldRejectInteriorGapStart(addr):
                continue
            self.gap_pointer = addr
            self.addGapCandidate(addr)
            return addr
        return None

    def _get_sorted_borders(self):
        if getattr(self, "_borders_dirty", True) or getattr(self, "_cached_borders", None) is None:
            self._cached_borders = sorted(
                [(fmin, fmax, start) for start, (fmin, fmax) in self.disassembly.function_borders.items()],
                key=lambda x: x[0],
            )
            self._cached_borders_starts = [x[0] for x in self._cached_borders]
            if self._cached_borders:
                self._max_fn_len = max(x[1] - x[0] for x in self._cached_borders)
            else:
                self._max_fn_len = 0
            self._borders_dirty = False
        return self._cached_borders

    def getContainingFunctionStart(self, addr):
        """Return the tightest function whose recorded borders contain addr."""
        borders = self._get_sorted_borders()
        if not borders:
            return None
        idx = bisect.bisect_right(self._cached_borders_starts, addr)
        matches = []
        max_len = self._max_fn_len
        for i in range(idx - 1, -1, -1):
            fmin, fmax, start = borders[i]
            if addr - fmin > max_len:
                break
            if start == addr:
                continue
            if fmin <= addr < fmax:
                matches.append((fmax - fmin, start))
        if not matches:
            return None
        return min(matches)[1]

    def shouldRejectInteriorGapStart(self, addr):
        """Reject gap-derived starts that overwrite an existing interior function body."""
        if addr not in self.disassembly.code_map:
            return False
        parent_start = self.getContainingFunctionStart(addr)
        if parent_start is None:
            return False
        candidate = self.candidates.get(addr)
        if candidate is None:
            return True
        if candidate.is_symbol or candidate.is_exception_handler:
            return False
        if candidate.call_ref_sources:
            return False
        parent_fmin, parent_fmax = self.disassembly.function_borders[parent_start]
        for ref_from in self.disassembly.code_refs_to.get(addr, set()):
            if ref_from < parent_fmin or ref_from >= parent_fmax:
                return False
        return True

    def getInteriorExtensionParent(self, addr):
        """Return a containing function start for an uncovered interior gap hole."""
        if addr in self.disassembly.code_map:
            return None
        parent = self.getContainingFunctionStart(addr)
        if parent is not None:
            return parent
        best_parent = None
        best_gap = None
        borders = self._get_sorted_borders()
        if not borders:
            return None
        idx = bisect.bisect_right(self._cached_borders_starts, addr)
        max_len = self._max_fn_len
        for i in range(idx - 1, -1, -1):
            fmin, fmax, start = borders[i]
            if addr - fmin > max_len + 32:
                break
            if fmax > addr or start >= addr:
                continue
            if fmax - fmin > 0x10000:
                continue
            gap = addr - fmax
            if gap > 32:
                continue
            if best_gap is None or gap < best_gap:
                best_parent = start
                best_gap = gap
        return best_parent

    def addTailcallCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsTailcallCandidate(True)

    def addReferenceCandidate(self, addr, source_ref):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self._all_call_refs[source_ref] = addr
        if addr in self.candidates:
            self._addCappedCallRef(self.candidates[addr], source_ref)

    def addLanguageSpecCandidate(self, addr, lang_spec):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setLanguageSpec(lang_spec)

    def addPrologueCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        return self.ensureCandidate(addr)

    def addSymbolCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsSymbol(True)
            self.candidates[addr].setInitialCandidate(True)

    def addExceptionCandidate(self, addr):
        if not self._passesCodeFilter(addr):
            return False
        self.ensureCandidate(addr)
        if addr in self.candidates:
            self.candidates[addr].setIsExceptionHandler(True)
            self.candidates[addr].setInitialCandidate(True)

    def resolvePointerReference(self, offset):
        if self.bitness == 32:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            function_pointer = struct.unpack("I", addr_block)[0]
            return self.disassembly.dereferenceDword(function_pointer)
        if self.bitness == 64:
            addr_block = self.disassembly.getRawBytes(offset + 2, 4)
            function_pointer = struct.unpack("i", addr_block)[0]
            # we need to calculate RIP + offset + 7 (48 ff 25 ** ** ** **)
            if self.disassembly.getRawBytes(offset, 2) == b"\xff\x25":
                function_pointer += offset + 7
            elif self.disassembly.getRawBytes(offset, 2) == b"\xff\x15":
                function_pointer += offset + 6
            else:
                raise Exception("resolvePointerReference: should only be used on call/jmp * ptr")
            return self.disassembly.binary_info.base_addr + function_pointer
        raise Exception("resolvePointerReference: undefined bitness")

    def _identifyAlignment(self):
        identified_alignment = 0
        if self.config.USE_ALIGNMENT:
            candidates_with_refs = [c for c in self.candidates.values() if len(c.call_ref_sources) > 1]
            num_candidates = len(candidates_with_refs)
            if num_candidates > 20:
                max_unaligned_16_budget = int(0.05 * num_candidates)
                max_unaligned_4_budget = int(0.05 * num_candidates)
                unaligned_16_count = 0
                unaligned_4_count = 0
                for candidate in candidates_with_refs:
                    if candidate.alignment != 16:
                        unaligned_16_count += 1
                    if candidate.alignment < 4:
                        unaligned_4_count += 1
                    if unaligned_16_count > max_unaligned_16_budget and unaligned_4_count > max_unaligned_4_budget:
                        break
                if unaligned_4_count <= max_unaligned_4_budget:
                    identified_alignment = 4
                if unaligned_16_count <= max_unaligned_16_budget:
                    identified_alignment = 16
        return identified_alignment

    def _candidateTimeoutTripped(self):
        """returns True once the wall-clock analysis timeout has been hit during candidate identification."""
        if self.disassembly is not None and self.disassembly.analysis_timeout:
            return True
        if self._cb_analysis_timeout is not None and self._cb_analysis_timeout():
            if self.disassembly is not None:
                self.disassembly.analysis_timeout = True
            return True
        return False

    def locateCandidates(self):
        # add guaranteed / high-value starts first so that, if the candidate cap is hit, the most reliable
        # candidates are retained before the high-volume prologue and stub-chain scans can consume the budget.
        self.locateSymbolCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateReferenceCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateExceptionHandlerCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateLangSpecCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locatePrologueCandidates()
        if self._candidateTimeoutTripped():
            return
        self.locateStubChainCandidates()
        self.identified_alignment = self._identifyAlignment()

    def _buildQueue(self):
        LOGGER.debug("Located %d function candidates", len(self.candidates))
        # increase lookup speed with static set
        self._candidate_offsets = {c.addr for c in self.candidates.values()}
        self.cached_candidates = list(self.candidates.values())
        if self.config.CANDIDATE_QUEUE == "BracketQueue":
            self.candidate_queue = BracketQueue(candidates=self.cached_candidates)
            LOGGER.debug("Using BracketQueue")
        else:
            self.candidate_queue = PriorityQueue(content=self.cached_candidates)
            LOGGER.debug("Using PriorityQueue")

    def locateSymbolCandidates(self):
        for symbol_addr in self.symbol_addresses:
            self.addSymbolCandidate(symbol_addr)

    def locateReferenceCandidates(self):
        # check for potential call instructions and check if their destinations have a common function prologue
        for match_count, call_match in enumerate(re.finditer(b"\xe8", self.disassembly.binary_info.binary)):
            if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                return
            if not self._passesCodeFilter(self.disassembly.binary_info.base_addr + call_match.start()):
                continue
            if len(self.disassembly.binary_info.binary) - call_match.start() > 5:
                packed_call = self.disassembly.getRawBytes(call_match.start() + 1, 4)
                rel_call_offset = struct.unpack("i", packed_call)[0]
                # ignore zero offset calls, as they will likely not lead to functions but are rather used for positioning in shellcode etc
                if rel_call_offset == 0:
                    continue
                call_destination = (
                    self.disassembly.binary_info.base_addr + rel_call_offset + call_match.start() + 5
                ) & self.getBitMask()
                if self.disassembly.isAddrWithinMemoryImage(call_destination):
                    self.addReferenceCandidate(
                        call_destination,
                        self.disassembly.binary_info.base_addr + call_match.start(),
                    )
                    self.setInitialCandidate(call_destination)
        # also check for "jmp dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
        if self.bitness == 32:
            for match_count, match in enumerate(re.finditer(b"\xff\x25", self.disassembly.binary_info.binary)):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                    return
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(
                        function_addr,
                        self.disassembly.binary_info.base_addr + match.start(),
                    )
                    self.setInitialCandidate(function_addr)
            # also check for "call dword ptr <offset>", as they sometimes point to local functions (i.e. non-API)
            for match_count, match in enumerate(re.finditer(b"\xff\x15", self.disassembly.binary_info.binary)):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                    return
                function_addr = self.resolvePointerReference(match.start())
                if not self._passesCodeFilter(function_addr):
                    continue
                if self.disassembly.isAddrWithinMemoryImage(function_addr):
                    self.addReferenceCandidate(
                        function_addr,
                        self.disassembly.binary_info.base_addr + match.start(),
                    )
                    self.setInitialCandidate(function_addr)

    def locatePrologueCandidates(self):
        # next check for the default function prologue regardless of references
        for re_prologue in DEFAULT_PROLOGUES:
            for match_count, prologue_match in enumerate(
                re.finditer(re.escape(re_prologue), self.disassembly.binary_info.binary)
            ):
                if match_count % 4096 == 0 and self._candidateTimeoutTripped():
                    return
                if not self._passesCodeFilter(self.disassembly.binary_info.base_addr + prologue_match.start()):
                    continue
                self.addPrologueCandidate(
                    (self.disassembly.binary_info.base_addr + prologue_match.start()) & self.getBitMask()
                )
                self.setInitialCandidate(
                    (self.disassembly.binary_info.base_addr + prologue_match.start()) & self.getBitMask()
                )

    def locateLangSpecCandidates(self):
        if self.lang_analyzer.checkGo():
            self.go_objects = self.lang_analyzer.getGoObjects()
            LOGGER.debug(
                "Programming language recognized as Go, adding function start addresses from PCLNTAB: %d",
                len(self.go_objects),
            )
            for add in self.go_objects:
                self.addLanguageSpecCandidate(add, "go")
        if self.lang_analyzer.checkDelphiKb():
            LOGGER.debug("File recognized as Delphi knowledge base")
            self.language_candidates_only = True
            self.delphi_kb_objects = self.lang_analyzer.getDelphiKbObjects()
            LOGGER.debug("Knowledge Base Objects parsed.")
            # apply relocations with imaginary base_addr at 0x400000 (provided by file loader)
            relocations = self.lang_analyzer.delphi_kb_resolver.getRelocations()
            image_base_as_bytes = struct.pack("I", self.disassembly.binary_info.base_addr)
            LOGGER.debug("Iterating relocations.")
            binary_as_array = bytearray(self.disassembly.binary_info.binary)
            for relocation_offset in relocations:
                # don't relocate relative jumps/calls
                if self.disassembly.binary_info.binary[relocation_offset - 1] not in [
                    0xE8,
                    0xE9,
                ]:
                    binary_as_array[relocation_offset] = image_base_as_bytes[0]
                    binary_as_array[relocation_offset + 1] = image_base_as_bytes[1]
                    binary_as_array[relocation_offset + 2] = image_base_as_bytes[2]
                    binary_as_array[relocation_offset + 3] = image_base_as_bytes[3]
            self.disassembly.binary_info.binary = bytes(binary_as_array)
            LOGGER.debug("Adding function start addresses via parser: %d", len(self.delphi_kb_objects))
            for add in self.delphi_kb_objects:
                self.addLanguageSpecCandidate(add, "delphi_kb")
        elif self.lang_analyzer.checkDelphi():
            LOGGER.debug("Programming language recognized as Delphi, adding function start addresses from VMTs")
            delphi_objects = self.lang_analyzer.getDelphiObjects()
            LOGGER.debug("delphi candidates based on legacy VMT analysis: %d", len(delphi_objects))
            for obj in delphi_objects:
                self.addLanguageSpecCandidate(obj, "delphi")

            # Also extract symbols using DelphiReSym metadata parsing
            LOGGER.debug("Extracting Delphi symbols using DelphiReSym metadata parsing")
            delphi_resym_objects = self.lang_analyzer.getDelphiReSymObjects()
            LOGGER.debug("delphi candidates based on DelphiReSym analysis: %d", len(delphi_resym_objects))
            for obj in delphi_resym_objects:
                self.addLanguageSpecCandidate(obj, "delphi_resym")

    def locateStubChainCandidates(self):
        # binaries often contain long sequences of stubs, consisting only of jmp dword ptr <offset>, add such chains as candidates
        for block in re.finditer(b"(?P<block>(\xff\x25[\\S\\s]{4}){2,})", self.disassembly.binary_info.binary):
            for match in re.finditer(b"\xff\x25(?P<function>[\\S\\s]{4})", block.group("block")):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
        # structure for plt entries is similar but interleaved with additional code not considered functions
        for block in re.finditer(
            b"(?P<block>(\xff\x25[\\S\\s]{4}\x68[\\S\\s]{4}\xe9[\\S\\s]{4}){2,})",
            self.disassembly.binary_info.binary,
        ):
            for match in re.finditer(b"\xff\x25(?P<function>[\\S\\s]{4})", block.group("block")):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
                # define data bytes inbetween
                for offset in range(10):
                    self.disassembly.data_map.add(stub_addr + 6 + offset)
        # structure for plt.sec (Intel Control Flow Enforcement Technology) entries
        """
        those look e.g. like this (64bit):
        .plt.sec:000000000000CF70                                           ; =============== S U B R O U T I N E =======================================
        .plt.sec:000000000000CF70
        .plt.sec:000000000000CF70                                           ; Attributes: thunk
        .plt.sec:000000000000CF70
        .plt.sec:000000000000CF70                                           ; time_t time(time_t *timer)
        .plt.sec:000000000000CF70                                           _time           proc near               ; CODE XREF: main+BE↓p
        .plt.sec:000000000000CF70                                                                                   ; li_rand_init+37↓p ...
        .plt.sec:000000000000CF70 F3 0F 1E FA                                               endbr64
        .plt.sec:000000000000CF74 F2 FF 25 0D 2E 05 00                                      bnd jmp cs:time_ptr
        .plt.sec:000000000000CF74                                           _time           endp
        .plt.sec:000000000000CF74
        .plt.sec:000000000000CF74                                           ; ---------------------------------------------------------------------------
        .plt.sec:000000000000CF7B 0F 1F 44 00 00                                            align 20h
        """
        for block in re.finditer(
            b"(?P<block>(\xf3\x0f\x1e\xfa\xf2\xff\x25[\\S\\s]{4}\x0f\x1f\x44\x00\x00){2,})",
            self.disassembly.binary_info.binary,
        ):
            for match in re.finditer(
                b"\xf3\x0f\x1e\xfa\xf2\xff\x25(?P<function>[\\S\\s]{4})",
                block.group("block"),
            ):
                stub_addr = self.disassembly.binary_info.base_addr + block.start() + match.start()
                if not self._passesCodeFilter(stub_addr):
                    continue
                stub_addr_masked = stub_addr & self.getBitMask()
                self.addPrologueCandidate(stub_addr_masked)
                self.setInitialCandidate(stub_addr_masked)
                if stub_addr_masked in self.candidates:
                    self.candidates[stub_addr_masked].setIsStub(True)
                # define data bytes inbetween
                for offset in range(5):
                    self.disassembly.data_map.add(stub_addr + 7 + offset)

    def locateExceptionHandlerCandidates(self):
        # 64bit only - if we have a .pdata section describing exception handlers, we extract entries of guaranteed function starts from it.
        if self.disassembly.binary_info.bitness == 64:
            for section_info in self.disassembly.binary_info.getSections():
                section_name, section_va_start, section_va_end = section_info
                if section_name == ".pdata":
                    rva_start = section_va_start - self.disassembly.binary_info.base_addr
                    rva_end = section_va_end - self.disassembly.binary_info.base_addr
                    # .pdata entries are 12 bytes long (3 DWORDs)
                    for offset in range(rva_start, rva_end - 11, 12):
                        packed_dword = self.disassembly.binary_info.binary[offset : offset + 4]
                        if len(packed_dword) < 4:
                            break
                        rva_function_candidate = struct.unpack("I", packed_dword)[0]
                        if rva_function_candidate == 0:
                            break
                        self.addExceptionCandidate(self.disassembly.binary_info.base_addr + rva_function_candidate)
