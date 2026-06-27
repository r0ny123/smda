#!/usr/bin/python

import datetime
import logging
import re

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
from smda.common.labelprovider.ElfApiResolver import ElfApiResolver
from smda.common.labelprovider.ElfSymbolProvider import ElfSymbolProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.common.labelprovider.MachoSymbolProvider import MachoSymbolProvider
from smda.common.labelprovider.PdbSymbolProvider import PdbSymbolProvider
from smda.common.labelprovider.PeSymbolProvider import PeSymbolProvider
from smda.common.labelprovider.RustSymbolProvider import RustSymbolProvider
from smda.common.labelprovider.WinApiResolver import WinApiResolver
from smda.common.TailcallAnalyzer import TailcallAnalyzer
from smda.DisassemblyResult import DisassemblyResult

LOGGER = logging.getLogger(__name__)


class RecursiveDisassembler:
    """Architecture-agnostic recursive CFG-recovery engine.

    Owns the recursive traversal, function-candidate orchestration, gap/tailcall
    passes and label/symbol resolution. All architecture-specific behaviour
    (capstone setup, instruction classification, candidate manager, analysis
    state, jump-table / indirect-call analyzers, TF-IDF) is provided by an
    injected :class:`~smda.common.arch.ArchBackend.ArchBackend`.
    """

    def __init__(self, config, backend, forced_bitness=None):
        self.config = config
        self.backend = backend
        self._forced_bitness = forced_bitness
        self.capstone = None
        self._tfidf = None
        self.binary_info = None
        self.label_providers = []
        self.api_providers = []
        self.symbol_providers = []
        self.active_api_providers = []
        self.active_symbol_providers = []
        self._addLabelProviders()
        self.fc_manager = None
        self.tailcall_analyzer = None
        self.indcall_analyzer = None
        self.jumptable_analyzer = None
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)
        self._symbol_cache = {}
        self._api_cache = {}

    def _addLabelProviders(self):
        self._registerLabelProvider(WinApiResolver(self.config))
        self._registerLabelProvider(ElfApiResolver(self.config))
        # Language-specific symbol providers (checked first for proper demangling)
        self._registerLabelProvider(RustSymbolProvider(self.config))
        self._registerLabelProvider(GoSymbolProvider(self.config))
        self._registerLabelProvider(DelphiKbSymbolProvider(self.config))
        self._registerLabelProvider(DelphiReSymProvider(self.config))
        # Generic binary format providers (fallback)
        self._registerLabelProvider(ElfSymbolProvider(self.config))
        self._registerLabelProvider(PeSymbolProvider(self.config))
        self._registerLabelProvider(MachoSymbolProvider(self.config))
        self._registerLabelProvider(PdbSymbolProvider(self.config))

    def _registerLabelProvider(self, provider):
        self.label_providers.append(provider)
        if provider.isApiProvider():
            self.api_providers.append(provider)
        if provider.isSymbolProvider():
            self.symbol_providers.append(provider)

    def _updateLabelProviders(self, binary_info):
        for provider in self.label_providers:
            provider.update(binary_info)
        self.active_api_providers = [p for p in self.api_providers if p.is_active()]
        self.active_symbol_providers = [p for p in self.symbol_providers if p.is_active()]

    def addPdbFile(self, binary_info, pdb_path):
        LOGGER.debug("adding PDB file: %s", pdb_path)
        if pdb_path and binary_info.base_addr:
            pdb_info = BinaryInfo(b"")
            pdb_info.file_path = pdb_path
            pdb_info.base_addr = binary_info.base_addr
            for provider in self.label_providers:
                provider.update(pdb_info)
            self.active_api_providers = [p for p in self.api_providers if p.is_active()]
            self.active_symbol_providers = [p for p in self.symbol_providers if p.is_active()]

    def resolveApi(self, to_address, api_address):
        if not hasattr(self, "_api_cache"):
            self._api_cache = {}
        cache_key = (to_address, api_address)
        if cache_key in self._api_cache:
            return self._api_cache[cache_key]
        active_providers = getattr(self, "active_api_providers", self.api_providers)
        for provider in active_providers:
            dll, api = provider.getApi(to_address, api_address)
            if dll or api:
                self._api_cache[cache_key] = (dll, api)
                return (dll, api)

        self._api_cache[cache_key] = ("", "")
        return ("", "")

    def resolveSymbol(self, address):
        if not hasattr(self, "_symbol_cache"):
            self._symbol_cache = {}
        if address in self._symbol_cache:
            return self._symbol_cache[address]
        active_providers = getattr(self, "active_symbol_providers", self.symbol_providers)
        for provider in active_providers:
            result = provider.getSymbol(address)
            if result:
                self._symbol_cache[address] = result
                return result
        self._symbol_cache[address] = ""
        return ""

    def getSymbolCandidates(self):
        symbol_offsets = set()
        active_providers = getattr(self, "active_symbol_providers", self.symbol_providers)
        for provider in active_providers:
            function_symbols = provider.getFunctionSymbols()
            symbol_offsets.update(function_symbols)
        return list(symbol_offsets)

    def getBitMask(self):
        if self.disassembly.binary_info.bitness == 64:
            return 0xFFFFFFFFFFFFFFFF
        return 0xFFFFFFFF

    def getReferencedAddr(self, op_str):
        # preserve a leading sign so that negative displacements (e.g. "qword ptr [rip - 0x20]")
        # resolve to the correct address instead of being treated as positive
        referenced_addr = re.search(r"(?P<sign>[+-])?\s*0x(?P<value>[a-fA-F0-9]+)", op_str)
        if referenced_addr:
            value = int(referenced_addr.group("value"), 16)
            return -value if referenced_addr.group("sign") == "-" else value
        return 0

    def resolveIndirectSwitch(self, addr_switch_array, size):
        indirect_switch_bytes = []
        current_offset = addr_switch_array + size * 4
        if self.disassembly.isAddrWithinMemoryImage(current_offset):
            LOGGER.debug(
                "0x%08x analyzing potentially indirect switch table (size: 0x%08x).",
                current_offset,
                size,
            )
            current_byte = self.disassembly.getByte(current_offset)
            if isinstance(current_byte, str):
                current_byte = ord(current_byte)
            while (
                current_byte is not None
                and current_byte < size
                and current_offset not in self.fc_manager.getFunctionStartCandidates()
            ):
                indirect_switch_bytes.append(current_offset)
                current_offset += 1
                current_byte = self.disassembly.getByte(current_offset)
                if isinstance(current_byte, str):
                    current_byte = ord(current_byte)
            LOGGER.debug("0x%08x found %d bytes.", current_offset, len(indirect_switch_bytes))
        return indirect_switch_bytes

    def _handleCallTarget(self, state, from_addr, to_addr):
        # explicit None check: address 0 is valid in base-0 buffers
        if to_addr is not None and self.disassembly.isAddrWithinMemoryImage(to_addr):
            state.addCodeRef(from_addr, to_addr)
            if to_addr not in self.disassembly.code_map and hasattr(self.fc_manager, "addReferenceCandidate"):
                self.fc_manager.addReferenceCandidate(to_addr, from_addr)
        if state.start_addr == to_addr:
            state.setRecursion(True)

    def _handleApiTarget(self, from_addr, to_addr, dereferenced):
        if to_addr:
            # identify API calls on the fly
            dll, api = self.resolveApi(to_addr, dereferenced)
            if dll or api:
                self._updateApiInformation(from_addr, dereferenced, dll, api)
                return (dll, api)
            elif not self.disassembly.isAddrWithinMemoryImage(to_addr):
                LOGGER.debug("potentially uncovered DLL address: 0x%08x", to_addr)

    def _updateApiInformation(self, from_addr, to_addr, dll, api):
        api_entry = {"referencing_addr": [], "dll_name": dll, "api_name": api}
        if to_addr in self.disassembly.apis:
            api_entry = self.disassembly.apis[to_addr]
        if from_addr not in api_entry["referencing_addr"]:
            api_entry["referencing_addr"].append(from_addr)
        self.disassembly.apis[to_addr] = api_entry

    def _getDisasmWindowBuffer(self, addr):
        relative_start = addr - self.disassembly.binary_info.base_addr
        relative_end = relative_start + self.backend.max_instruction_size
        return self.disassembly.binary_info.binary[relative_start:relative_end]

    def _revertGapFunction(self, colliding_addr, current_start_addr):
        """When a tailcall-discovered candidate's analysis reaches bytes already
        claimed by a gap function, the gap function is almost certainly part of
        the candidate's body (the gap scan over-eagerly claimed the fall-through
        before the tailcall candidate was known). Revert the gap function so the
        current analysis can absorb its bytes as ordinary blocks.

        Returns True if a gap function was reverted.
        """
        owner_fn = self.disassembly.ins2fn.get(colliding_addr)
        if owner_fn is None or owner_fn == current_start_addr:
            return False
        candidate = self.fc_manager.candidates.get(owner_fn)
        if candidate is None or not candidate.is_gap_candidate:
            return False
        if owner_fn not in self.disassembly.functions:
            return False
        owner_state = self.backend.createAnalysisState(owner_fn, self.disassembly)
        # Rebuild a minimal state from the disassembly's stored instructions
        # so revertAnalysis can undo code_map/ins2fn/function_borders entries.
        fn_min, fn_max = self.disassembly.function_borders[owner_fn]
        owner_state.instructions = []
        for addr in sorted(self.disassembly.instructions.keys()):
            if fn_min <= addr < fn_max:
                mnemonic, size = self.disassembly.instructions[addr]
                owner_state.instructions.append((addr, size, mnemonic, "", b""))
        owner_state.code_refs = set()
        owner_state.data_refs = set()
        owner_state.revertAnalysis()
        if hasattr(self.fc_manager, "removeBorder"):
            self.fc_manager.removeBorder(owner_fn)
        self.fc_manager.updateAnalysisAborted(
            owner_fn, f"Reverted: absorbed by tailcall candidate 0x{current_start_addr:08x}"
        )
        LOGGER.debug(
            "Reverted gap function 0x%08x (absorbed by tailcall candidate 0x%08x)",
            owner_fn,
            current_start_addr,
        )
        return True

    def analyzeFunction(self, start_addr, as_gap=False):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        self.tailcall_analyzer.initFunction()
        i = None
        state = self.backend.createAnalysisState(start_addr, self.disassembly)
        if as_gap and hasattr(state, "setGapCandidateContext"):
            state.setGapCandidateContext(self.fc_manager.getFunctionCandidate(start_addr))
        if state.isProcessedFunction():
            owning_function = self.disassembly.ins2fn.get(start_addr)
            if owning_function == start_addr or start_addr in self.disassembly.functions:
                self.fc_manager.updateAnalysisFinished(start_addr)
                return state
            self.fc_manager.updateAnalysisAborted(
                start_addr,
                f"collision with existing code of function 0x{owning_function:08x}",
            )
            return state
        while state.hasUnprocessedBlocks():
            LOGGER.debug(
                "  current block queue: %s",
                ", ".join([f"0x{addr:x}" for addr in state.block_queue]),
            )
            state.chooseNextBlock()
            LOGGER.debug("  analyzeFunction() now processing block @0x%08x", state.block_start)
            # in capstone, disassembly is more expensive than calling the function, so we use the maximum instruction
            # size as look-ahead. disasm_lite() also provides faster disassembly than disasm(), so we work with tuples.
            cache = list(self.capstone.disasm_lite(self._getDisasmWindowBuffer(state.block_start), state.block_start))
            cache_pos = 0
            previous_i = None
            while True:
                for i in cache:
                    i_address, i_size, i_mnemonic, i_op_str = i
                    i_op_str = i_op_str.strip()
                    i_relative_address = i_address - self.disassembly.binary_info.base_addr
                    i_bytes = self.disassembly.binary_info.binary[i_relative_address : i_relative_address + i_size]
                    LOGGER.debug(
                        "  analyzeFunction() now processing instruction @0x%08x: %s",
                        i_address,
                        i_mnemonic + " " + i_op_str,
                    )
                    cache_pos += i_size
                    state.setNextInstructionReachable(True)
                    # count "suspicious" all-zero instructions (e.g. x86 `00 00`,
                    # AArch64 `udf #0`) that indicate non-function code. Testing for an
                    # all-zero decoded instruction is architecture-independent; a
                    # fixed-width constant would never match wider fixed-width ISAs.
                    if i_bytes and not any(i_bytes):
                        state.suspicious_ins_count += 1
                        LOGGER.debug(
                            "    analyzeFunction() found suspicious function @0x%08x",
                            i_address,
                        )
                        if state.suspicious_ins_count > 1:
                            self.fc_manager.updateAnalysisAborted(
                                start_addr,
                                f"too many suspicious instructions @0x{i_address:08x}",
                            )
                            return state
                    # delegate architecture-specific control-flow analysis to the backend;
                    # a True return means: cut the block here without booking this instruction
                    if self.backend.analyzeInstruction(self, i, state, previous_i, start_addr):
                        break
                    previous_i = i
                    if (
                        i_address not in self.disassembly.code_map
                        and i_address not in self.disassembly.data_map
                        and not state.isProcessed(i_address)
                    ):
                        LOGGER.debug(
                            "  analyzeFunction() booked instruction @0x%08x: %s for processed state",
                            i_address,
                            i_mnemonic + " " + i_op_str,
                        )
                        state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                    elif i_address in self.disassembly.code_map:
                        LOGGER.debug(
                            "  analyzeFunction() was already present?! instruction @0x%08x: %s (function: 0x%08x)",
                            i_address,
                            i_mnemonic + " " + i_op_str,
                            self.disassembly.ins2fn[i_address],
                        )
                        # If the collision is with a gap function, revert it and
                        # book this instruction so the current function absorbs it.
                        # Only apply during the tailcall re-drain (as_gap=False),
                        # not during the gap pass itself — gap candidates are
                        # expected to have independent analysis there.
                        if not as_gap and self._revertGapFunction(i_address, start_addr):
                            state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
                        else:
                            state.setBlockEndingInstruction(True)
                            state.addCollision(i_address)
                    else:
                        LOGGER.debug("  analyzeFunction() was already present in local function.")
                        state.setBlockEndingInstruction(True)
                    if state.isBlockEndingInstruction():
                        state.endBlock()
                        break
                else:
                    # if the inner loop did not break, we need to refill the cache in order to finish the block-analysis
                    cache = list(
                        self.capstone.disasm_lite(
                            self._getDisasmWindowBuffer(state.block_start + cache_pos),
                            state.block_start + cache_pos,
                        )
                    )
                    if not cache:
                        break
                    continue
                # if the inner loop did break, the cache didn't run empty and thus block-analysis is finished
                break
            if not state.isBlockEndingInstruction():
                if i is not None:
                    LOGGER.debug(
                        "No block submitted, last instruction: 0x%08x -> 0x%08x %s || %s",
                        start_addr,
                        i_address,
                        i_mnemonic + " " + i_op_str,
                        self.fc_manager.getFunctionCandidate(start_addr),
                    )
                else:
                    LOGGER.debug(
                        "No block submitted with no ins, last instruction: 0x%08x || %s",
                        start_addr,
                        self.fc_manager.getFunctionCandidate(start_addr),
                    )
        state.label = self.resolveSymbol(state.start_addr)
        extension_parent = None
        if self._intelInteriorGapEnabled() and as_gap:
            extension_parent = self.fc_manager.getInteriorExtensionParent(start_addr)
        if self._intelInteriorGapEnabled() and as_gap and self.fc_manager.shouldRejectInteriorGapStart(start_addr):
            self.fc_manager.updateAnalysisAborted(
                start_addr,
                "interior gap candidate without external entry",
            )
            return state
        analysis_result = state.finalizeAnalysis(as_gap, extend_into_parent=extension_parent is not None)
        if analysis_result and extension_parent is not None:
            self._mergeExtensionIntoParent(state, extension_parent)
            if self.config.RESOLVE_REGISTER_CALLS:
                self.indcall_analyzer.resolveRegisterCalls(state)
                self.tailcall_analyzer.finalizeFunction(state)
            self.fc_manager.updateAnalysisFinished(start_addr)
            self.fc_manager.updateCandidates(state)
            if hasattr(self.fc_manager, "syncBorder"):
                self.fc_manager.syncBorder(start_addr)
            return state
        if analysis_result and self.config.RESOLVE_REGISTER_CALLS:
            self.indcall_analyzer.resolveRegisterCalls(state)
            self.tailcall_analyzer.finalizeFunction(state)
        self.fc_manager.updateAnalysisFinished(start_addr)
        self.fc_manager.updateCandidates(state)
        if hasattr(self.fc_manager, "syncBorder"):
            self.fc_manager.syncBorder(start_addr)
        return state

    def _reset_gap_recovery_budget(self):
        self._gap_extra_analyses = 0
        self._gap_recovery_limit = self._gap_recovery_budget_limit()

    def _gap_recovery_budget_limit(self):
        fixed = getattr(self.config, "GAP_RECOVERY_MAX_EXTRA_ANALYSES", 0)
        cap = getattr(self.config, "GAP_RECOVERY_MAX_EXTRA_ANALYSES_CAP", 8000)
        if fixed > 0:
            return fixed
        binary_info = self.disassembly.binary_info
        binary_size = getattr(binary_info, "binary_size", 0) or len(getattr(binary_info, "binary", b"") or b"")
        per_mb = getattr(self.config, "GAP_RECOVERY_EXTRA_ANALYSES_PER_MB", 200)
        floor = getattr(self.config, "GAP_RECOVERY_EXTRA_ANALYSES_FLOOR", 500)
        mb = max(1, binary_size // (1024 * 1024))
        return min(cap, max(floor, mb * per_mb))

    def _gap_budget_remaining(self):
        return self._gap_extra_analyses < self._gap_recovery_limit

    def _consume_gap_budget(self, count=1):
        if not self._gap_budget_remaining():
            return False
        self._gap_extra_analyses += count
        return True

    def _analyze_gap_function(self, addr, cbAnalysisTimeout=None):
        if cbAnalysisTimeout and cbAnalysisTimeout():
            return None
        if not self._consume_gap_budget():
            return None
        return self.analyzeFunction(addr, as_gap=True)

    def _iter_interior_hole_starts(self, fmin, interval_end, max_scan_bytes):
        code_map = self.disassembly.code_map
        data_map = self.disassembly.data_map
        instructions = self.disassembly.instructions
        addr = fmin
        end = interval_end
        scanned = 0
        while addr < end and scanned < max_scan_bytes:
            # Skip the mapped run (function body). Stride a whole instruction at a time
            # over code_map (every byte of an instruction maps to its start) instead of
            # byte-by-byte; this lands on the exact same first-unmapped address and
            # advances `scanned` by the identical byte count.
            while addr < end and (addr in code_map or addr in data_map):
                if addr in code_map:
                    ins_start = code_map[addr]
                    meta = instructions.get(ins_start)
                    step = (ins_start + meta[1] - addr) if meta is not None else 1
                    if step < 1:
                        step = 1
                else:
                    step = 1
                if addr + step > end:
                    step = end - addr
                addr += step
                scanned += step
            if addr >= end or scanned >= max_scan_bytes:
                break
            yield addr
            while addr < end and addr not in code_map and addr not in data_map:
                addr += 1
                scanned += 1

    def _collect_insn_map_for_merge(self, parent_start, child_start=None, child_starts=None, extra_blocks=()):
        fn_ids = {parent_start}
        if child_start is not None:
            fn_ids.add(child_start)
        if child_starts:
            fn_ids.update(child_starts)
        ins_by_addr = {}
        for block in self.disassembly.functions.get(parent_start, []):
            for ins in block:
                ins_by_addr[ins[0]] = ins
        for block in extra_blocks:
            for ins in block:
                ins_by_addr[ins[0]] = ins

        # Scan functions fmin..fmax ranges rather than all instructions in the binary
        borders = []
        parent_borders = self.disassembly.function_borders.get(parent_start)
        if not parent_borders:
            parent_blocks = self.disassembly.functions.get(parent_start)
            if parent_blocks:
                all_ins = [ins for block in parent_blocks for ins in block]
                if all_ins:
                    parent_borders = (min(ins[0] for ins in all_ins), max(ins[0] + ins[1] for ins in all_ins))
        if parent_borders:
            borders.append(parent_borders)

        all_children = []
        if child_start is not None:
            all_children.append(child_start)
        if child_starts:
            all_children.extend(child_starts)

        for child in all_children:
            child_borders = self.disassembly.function_borders.get(child)
            if child_borders:
                borders.append(child_borders)

        # Fallback if child borders weren't found/cached
        if extra_blocks and (
            not all_children or not any(self.disassembly.function_borders.get(c) for c in all_children)
        ):
            all_ins = [ins for block in extra_blocks for ins in block]
            if all_ins:
                borders.append((min(ins[0] for ins in all_ins), max(ins[0] + ins[1] for ins in all_ins)))

        for fmin, fmax in borders:
            addr = fmin
            while addr < fmax:
                if (
                    addr in self.disassembly.instructions
                    and addr not in ins_by_addr
                    and self.disassembly.ins2fn.get(addr) in fn_ids
                ):
                    meta = self.disassembly.instructions[addr]
                    mnemonic, size = meta[0], meta[1]
                    ins_by_addr[addr] = (addr, size, mnemonic, "", b"")
                if addr in self.disassembly.instructions:
                    addr += self.disassembly.instructions[addr][1]
                else:
                    addr += 1
        return ins_by_addr

    def _rebuild_merged_function(self, parent_start, ins_by_addr):
        if not ins_by_addr:
            return
        for ins in ins_by_addr.values():
            addr, size = ins[0], ins[1]
            self.disassembly.instructions[addr] = (ins[2], ins[1])
            for offset in range(size):
                self.disassembly.code_map[addr + offset] = addr
                self.disassembly.ins2fn[addr + offset] = parent_start

        state = self.backend.createAnalysisState(parent_start, self.disassembly)
        for ins in sorted(ins_by_addr.values(), key=lambda x: x[0]):
            state.instructions.append(ins)
            state.instruction_start_bytes.add(ins[0])
            state.jump_targets.add(ins[0])
        for addr in sorted(ins_by_addr.keys()):
            if addr not in self.disassembly.code_refs_from:
                continue
            parts = ins_by_addr[addr][2].split()
            mnemonic = parts[0] if parts else ""
            by_jump = mnemonic != "call" and (mnemonic.startswith("j") or mnemonic in state.END_MNEMONICS)
            for target in self.disassembly.code_refs_from[addr]:
                state.addCodeRef(addr, target, by_jump=by_jump)

        fn_min = min(ins[0] for ins in ins_by_addr.values())
        fn_max = max(ins[0] + ins[1] for ins in ins_by_addr.values())
        self.disassembly.function_borders[parent_start] = (fn_min, fn_max)
        self.disassembly.functions[parent_start] = state.getBlocks()
        if hasattr(self.fc_manager, "updateBorder"):
            self.fc_manager.updateBorder(parent_start, fn_min, fn_max)

    def _runGapRecoveryPasses(self, cbAnalysisTimeout=None):
        self._reset_gap_recovery_budget()
        max_passes = getattr(self.config, "GAP_RECOVERY_MAX_PASSES", 2) if self._intelInteriorGapEnabled() else 1
        for pass_index in range(max_passes):
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            if hasattr(self.fc_manager, "refreshFunctionGaps"):
                self.fc_manager.gap_pointer = None
                self.fc_manager.previously_analyzed_gap = 0
                if hasattr(self.fc_manager, "clearGapAttempts"):
                    self.fc_manager.clearGapAttempts()
                self.fc_manager.refreshFunctionGaps()
            gap_candidate = self.fc_manager.nextGapCandidate()
            while gap_candidate is not None:
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    break
                LOGGER.debug("based on gap, performing function analysis of 0x%08x", gap_candidate)
                state = self.analyzeFunction(gap_candidate, as_gap=True)
                function_blocks = state.getBlocks()
                if function_blocks:
                    LOGGER.debug("+ got some blocks here -> 0x%08x", gap_candidate)
                recovered = gap_candidate in self.disassembly.functions
                extended = state.num_blocks_analyzed > 0 and not recovered
                if recovered:
                    fn_min = self.disassembly.function_borders[gap_candidate][0]
                    fn_max = self.disassembly.function_borders[gap_candidate][1]
                    LOGGER.debug("+++ YAY, is now a function! -> 0x%08x - 0x%08x", fn_min, fn_max)
                    if hasattr(self.fc_manager, "clearGapAttempts"):
                        self.fc_manager.clearGapAttempts()
                    next_gap = self.fc_manager.getNextGap(dont_skip=True)
                    gap_candidate = self.fc_manager.nextGapCandidate(next_gap)
                elif extended:
                    if hasattr(self.fc_manager, "clearGapAttempts"):
                        self.fc_manager.clearGapAttempts()
                    gap_candidate = self.fc_manager.nextGapCandidate()
                else:
                    if hasattr(self.fc_manager, "markGapAttempted"):
                        self.fc_manager.markGapAttempted(gap_candidate)
                        retry_candidate = self.fc_manager.nextTrustedCandidateInGap(gap_candidate)
                        if retry_candidate is not None:
                            gap_candidate = retry_candidate
                            continue
                    self.fc_manager.updateAnalysisAborted(
                        gap_candidate,
                        "Gap candidate did not fulfil function criteria.",
                    )
                    if hasattr(self.fc_manager, "advanceGapScan"):
                        self.fc_manager.advanceGapScan(gap_candidate)
                    gap_candidate = self.fc_manager.nextGapCandidate()
            LOGGER.debug(
                "Finished gap analysis pass %d, functions: %d", pass_index + 1, len(self.disassembly.functions)
            )
            if self._intelInteriorGapEnabled():
                self._pruneInteriorGapFunctions()
                if self._gap_budget_remaining():
                    self._fillInteriorFunctionHoles(cbAnalysisTimeout)
                if self._gap_budget_remaining():
                    self._recoverLargeUnmappedGaps(
                        cbAnalysisTimeout,
                        min_gap=getattr(self.config, "GAP_LARGE_UNMAPPED_MIN_BYTES", 512),
                    )
                fn_threshold = getattr(self.config, "GAP_SMALL_UNMAPPED_ONLY_WHEN_FUNCTIONS_BELOW", 3000)
                if self._gap_budget_remaining() and len(self.disassembly.functions) < fn_threshold:
                    self._recoverLargeUnmappedGaps(
                        cbAnalysisTimeout,
                        min_gap=getattr(self.config, "GAP_SMALL_UNMAPPED_MIN_BYTES", 64),
                    )
                if self._gap_budget_remaining():
                    self._recoverPltStubs(cbAnalysisTimeout)
                if self._gap_budget_remaining():
                    self._recoverUnmappedCodeRefTargets(cbAnalysisTimeout)
                if self._gap_budget_remaining():
                    self._recoverLeaRipRelativeCodeTargets(cbAnalysisTimeout)
                if self._gap_budget_remaining():
                    self._recoverInteriorCodeRefSplits(cbAnalysisTimeout)
                LOGGER.debug("After interior gap recovery, functions: %d", len(self.disassembly.functions))
            if pass_index + 1 < max_passes and hasattr(self.fc_manager, "refreshFunctionGaps"):
                before = len(self.disassembly.code_map)
                self.fc_manager.refreshFunctionGaps()
                remaining = sum(gap[2] for gap in (self.fc_manager.function_gaps or []) if gap[2] > 1)
                if remaining == 0 or len(self.disassembly.code_map) == before:
                    break

    def _instruction_mnemonic(self, addr):
        meta = self.disassembly.instructions.get(addr)
        return meta[0] if meta else ""

    def _instruction_mnemonic_base(self, addr):
        return self._instruction_mnemonic(addr).split(" ")[-1]

    def _is_call_or_jmp_insn(self, addr):
        from smda.intel.definitions import CALL_INS, JMP_INS

        mnemonic = self._instruction_mnemonic_base(addr)
        return mnemonic in CALL_INS or mnemonic in JMP_INS

    def _purge_code_refs_for_addr(self, addr):
        for target in list(self.disassembly.code_refs_from.get(addr, ())):
            refs_to = self.disassembly.code_refs_to.get(target)
            if refs_to is not None:
                refs_to.discard(addr)
                if not refs_to:
                    self.disassembly.code_refs_to.pop(target, None)
        self.disassembly.code_refs_from.pop(addr, None)
        for src in list(self.disassembly.code_refs_to.get(addr, ())):
            refs_from = self.disassembly.code_refs_from.get(src)
            if refs_from is not None:
                refs_from.discard(addr)
                if not refs_from:
                    self.disassembly.code_refs_from.pop(src, None)
        self.disassembly.code_refs_to.pop(addr, None)

    def _collect_owned_instruction_map(self, fn_start, max_addr=None):
        ins_by_addr = {}
        for block in self.disassembly.functions.get(fn_start, []):
            for ins in block:
                if max_addr is not None and ins[0] >= max_addr:
                    continue
                if self.disassembly.ins2fn.get(ins[0]) != fn_start:
                    continue
                ins_by_addr[ins[0]] = ins
        return ins_by_addr

    def _clear_owned_instructions_from(self, fn_start, min_addr, max_addr=None):
        for addr in sorted(
            addr for addr in self.disassembly.instructions if self.disassembly.ins2fn.get(addr) == fn_start
        ):
            if addr < min_addr:
                continue
            if max_addr is not None and addr >= max_addr:
                continue
            self._purge_code_refs_for_addr(addr)
            _mnemonic, size = self.disassembly.instructions.pop(addr)
            for byte_offset in range(size):
                mapped = addr + byte_offset
                self.disassembly.code_map.pop(mapped, None)
                self.disassembly.ins2fn.pop(mapped, None)

    def _snapshot_code_refs(self):
        return (
            {addr: set(targets) for addr, targets in self.disassembly.code_refs_from.items()},
            {addr: set(sources) for addr, sources in self.disassembly.code_refs_to.items()},
        )

    def _restore_code_refs(self, refs_snapshot):
        refs_from, refs_to = refs_snapshot
        self.disassembly.code_refs_from = {addr: set(targets) for addr, targets in refs_from.items()}
        self.disassembly.code_refs_to = {addr: set(sources) for addr, sources in refs_to.items()}

    def _interior_split_target_has_prologue(self, target):
        cache = getattr(self, "_interior_prologue_cache", None)
        if cache is None:
            cache = {}
            self._interior_prologue_cache = cache
        if target in cache:
            return cache[target]
        from smda.intel.FunctionCandidate import FunctionCandidate

        binary_info = self.disassembly.binary_info
        if not binary_info:
            cache[target] = False
            return False
        cache[target] = FunctionCandidate(binary_info, target).hasCommonFunctionStart()
        return cache[target]

    def _preflight_interior_split_target(self, target, owner):
        if target in self.disassembly.functions:
            return False
        if target not in self.disassembly.code_map:
            return False
        return self.disassembly.ins2fn.get(target) == owner

    def _interior_code_refs_are_parent_local(self, owner, ref_froms):
        borders = self.disassembly.function_borders.get(owner)
        if not borders or not ref_froms:
            return False
        fmin, fmax = borders
        return all(fmin <= ref_from < fmax for ref_from in ref_froms)

    def _should_split_interior_code_ref_target(self, target, owner, ref_froms):
        if target in self.disassembly.functions:
            return False
        if self.disassembly.ins2fn.get(target) != owner:
            return False
        borders = self.disassembly.function_borders.get(owner)
        if not borders:
            return False
        parent_span = borders[1] - borders[0]
        min_parent_span = getattr(self.config, "GAP_INTERIOR_CODE_REF_SPLIT_MIN_PARENT_SPAN", 0x10000)
        if parent_span <= 16:
            return False
        from smda.intel.definitions import CALL_INS, JMP_INS

        refs_parent_local = self._interior_code_refs_are_parent_local(owner, ref_froms)
        has_call_ref = any(self._instruction_mnemonic_base(ref_from) in CALL_INS for ref_from in ref_froms)
        has_jmp_ref = any(self._instruction_mnemonic_base(ref_from) in JMP_INS for ref_from in ref_froms)
        if not has_call_ref and not has_jmp_ref:
            return False
        if refs_parent_local and parent_span <= min_parent_span:
            return False
        if has_jmp_ref and not has_call_ref:
            if parent_span <= min_parent_span:
                return False
            return self._interior_split_target_has_prologue(target)
        if refs_parent_local:
            return self._interior_split_target_has_prologue(target)
        # External call into a large merged parent: split without prologue (IDA-style nested entry).
        return has_call_ref

    def _split_function_at_interior_target(self, parent_start, split_addr, reference_source, cbAnalysisTimeout=None):
        if split_addr in self.disassembly.functions or split_addr not in self.disassembly.code_map:
            return False
        if self.disassembly.ins2fn.get(split_addr) != parent_start:
            return False
        if cbAnalysisTimeout and cbAnalysisTimeout():
            return False
        if not self._gap_budget_remaining():
            return False
        full_parent_ins = self._collect_owned_instruction_map(parent_start)
        if not full_parent_ins:
            return False
        code_refs_snapshot = self._snapshot_code_refs()
        if parent_start <= split_addr:
            parent_ins = self._collect_owned_instruction_map(parent_start, max_addr=split_addr)
            if not parent_ins:
                return False
            self._clear_owned_instructions_from(parent_start, split_addr)
            self._rebuild_merged_function(parent_start, parent_ins)
        else:
            # The containing border can start above an interior xref target.
            self._clear_owned_instructions_from(parent_start, split_addr, parent_start)
            parent_ins = self._collect_owned_instruction_map(parent_start)
            if not parent_ins:
                self._rebuild_merged_function(parent_start, full_parent_ins)
                self._restore_code_refs(code_refs_snapshot)
                return False
            self._rebuild_merged_function(parent_start, parent_ins)
        self.fc_manager.addCandidate(split_addr, reference_source=reference_source)
        if not self._consume_gap_budget():
            self._rebuild_merged_function(parent_start, full_parent_ins)
            self._restore_code_refs(code_refs_snapshot)
            return False
        self.analyzeFunction(split_addr)
        if split_addr not in self.disassembly.functions:
            self._rebuild_merged_function(parent_start, full_parent_ins)
            self._restore_code_refs(code_refs_snapshot)
            return False
        return True

    def _recoverInteriorCodeRefSplits(self, cbAnalysisTimeout=None):
        if not self._intelInteriorGapEnabled():
            return
        self._interior_prologue_cache = {}

        split_jobs = []
        pending_targets = {}
        for addr_from, targets in self.disassembly.code_refs_from.items():
            if not self._is_call_or_jmp_insn(addr_from):
                continue
            for target in targets:
                if target in self.disassembly.functions:
                    continue
                owner = self.disassembly.ins2fn.get(target)
                if owner is None or owner == target:
                    continue
                if target not in pending_targets:
                    ref_froms = self.disassembly.code_refs_to.get(target)
                    if not ref_froms:
                        continue
                    pending_targets[target] = (owner, ref_froms)
        for target, (owner, ref_froms) in pending_targets.items():
            if not self._should_split_interior_code_ref_target(target, owner, ref_froms):
                continue
            if not self.fc_manager._passesCodeFilter(target):
                continue
            split_jobs.append((target, owner, min(ref_froms)))

        target_limit = getattr(self.config, "GAP_INTERIOR_CODE_REF_SPLIT_LIMIT", 512)
        if target_limit <= 0:
            return
        for target, owner, reference_source in sorted(split_jobs, key=lambda job: job[0])[:target_limit]:
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            if not self._gap_budget_remaining():
                break
            if not self._preflight_interior_split_target(target, owner):
                continue
            self._split_function_at_interior_target(owner, target, reference_source, cbAnalysisTimeout)

    def _resolve_lea_rip_relative_target(self, insn_addr):
        insn_meta = self.disassembly.instructions.get(insn_addr)
        if not insn_meta or insn_meta[0] != "lea":
            return None
        insn_size = insn_meta[1]
        for ins in self.capstone.disasm_lite(self._getDisasmWindowBuffer(insn_addr), insn_addr):
            if ins[0] != insn_addr:
                continue
            if "rip" not in ins[3].lower():
                return None
            return insn_addr + insn_size + self.getReferencedAddr(ins[3])
        return None

    def _collect_lea_code_pointer_targets(self, target_limit):
        lea_targets = {}
        for insn_addr, (mnemonic, _insn_size) in self.disassembly.instructions.items():
            if mnemonic != "lea":
                continue
            target = self._resolve_lea_rip_relative_target(insn_addr)
            if target is None or not self.disassembly.isAddrWithinMemoryImage(target):
                continue
            if not self.fc_manager._passesCodeFilter(target):
                continue
            refs = lea_targets.get(target)
            if refs is None:
                if len(lea_targets) >= target_limit:
                    continue
                refs = set()
                lea_targets[target] = refs
            refs.add(insn_addr)
        return lea_targets

    def _get_enclosing_parent_for_gap_addr(self, addr, ref_froms=None):
        matches = []
        for start, (fmin, fmax) in self.disassembly.function_borders.items():
            if fmin <= addr < fmax:
                matches.append((fmax - fmin, start, fmin, fmax))
        if not matches:
            return None
        if ref_froms:
            local = [
                (span, start)
                for span, start, fmin, fmax in matches
                if any(fmin <= ref_from < fmax for ref_from in ref_froms)
            ]
            if local:
                return max(local)[1]
        return max(matches)[1]

    def _get_lea_recovery_parent(self, target, ref_froms):
        parent = self._get_enclosing_parent_for_gap_addr(target, ref_froms)
        if parent is not None:
            return parent
        standard_span = getattr(self.config, "GAP_INTERIOR_HOLE_STANDARD_FUNCTION_SPAN", 0x10000)
        for ref_from in sorted(ref_froms):
            candidate = self._get_enclosing_parent_for_gap_addr(ref_from)
            if candidate is None:
                continue
            borders = self.disassembly.function_borders.get(candidate)
            if borders and borders[1] - borders[0] > standard_span:
                return candidate
        return None

    def _should_recover_lea_code_pointer_target(self, target, ref_froms):
        if target in self.disassembly.functions:
            return False
        if not self._interior_split_target_has_prologue(target):
            return False
        standard_span = getattr(self.config, "GAP_INTERIOR_HOLE_STANDARD_FUNCTION_SPAN", 0x10000)
        parent = self._get_lea_recovery_parent(target, ref_froms)
        if parent is None:
            return False
        borders = self.disassembly.function_borders.get(parent)
        if not borders:
            return False
        parent_span = borders[1] - borders[0]
        if parent_span <= 16:
            return False
        if target in self.disassembly.code_map or target in self.disassembly.data_map:
            return False
        return parent_span > standard_span

    def _recoverLeaRipRelativeCodeTargets(self, cbAnalysisTimeout=None):
        if not self._intelInteriorGapEnabled():
            return
        self._interior_prologue_cache = getattr(self, "_interior_prologue_cache", {})
        target_limit = getattr(self.config, "GAP_LEA_RIP_RELATIVE_TARGET_LIMIT", 256)
        if target_limit <= 0:
            return
        lea_targets = self._collect_lea_code_pointer_targets(target_limit)
        for target, ref_froms in sorted(lea_targets.items(), key=lambda item: item[0]):
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            if not self._gap_budget_remaining():
                break
            if not self._should_recover_lea_code_pointer_target(target, ref_froms):
                continue
            if target in self.disassembly.code_map or target in self.disassembly.data_map:
                continue
            reference_source = min(ref_froms)
            self.fc_manager.addReferenceCandidate(target, reference_source)
            if not self._consume_gap_budget():
                break
            self.analyzeFunction(target)

    def _unmapped_code_ref_targets(self):
        targets = set()
        for target in self.disassembly.code_refs_to:
            if target in self.disassembly.code_map or target in self.disassembly.data_map:
                continue
            if not self.disassembly.isAddrWithinMemoryImage(target):
                continue
            if not self.fc_manager._passesCodeFilter(target):
                continue
            targets.add(target)
        return targets

    def _recoverUnmappedCodeRefTargets(self, cbAnalysisTimeout=None):
        if not hasattr(self.fc_manager, "addReferenceCandidate"):
            return
        if not self._intelInteriorGapEnabled():
            targets = self._unmapped_code_ref_targets()
        else:
            self._interior_prologue_cache = getattr(self, "_interior_prologue_cache", {})
            standard_span = getattr(self.config, "GAP_INTERIOR_HOLE_STANDARD_FUNCTION_SPAN", 0x10000)
            targets = set()
            for target in self._unmapped_code_ref_targets():
                ref_froms = self.disassembly.code_refs_to.get(target)
                if not ref_froms or not any(self._is_call_or_jmp_insn(ref_from) for ref_from in ref_froms):
                    continue
                parent = self.fc_manager.getContainingFunctionStart(target)
                if parent is not None:
                    borders = self.disassembly.function_borders.get(parent)
                    parent_span = borders[1] - borders[0] if borders else 0
                    if parent_span > standard_span and not self._interior_split_target_has_prologue(target):
                        continue
                targets.add(target)
        target_limit = getattr(self.config, "GAP_UNMAPPED_CODE_REF_TARGET_LIMIT", 512)
        if target_limit <= 0:
            return
        for target in sorted(targets)[:target_limit]:
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            if not self._gap_budget_remaining():
                break
            if target in self.disassembly.code_map:
                continue
            self.fc_manager.addReferenceCandidate(target, min(self.disassembly.code_refs_to[target]))
            if not self._consume_gap_budget():
                break
            self.analyzeFunction(target)

    def _intelInteriorGapEnabled(self):
        return getattr(self.backend, "name", "") == "intel"

    def _pruneInteriorGapFunctions(self):
        manager = self.fc_manager
        parent_to_children = {}
        for fn_start in list(self.disassembly.functions.keys()):
            candidate = manager.candidates.get(fn_start)
            if candidate is None or not candidate.is_gap_candidate:
                continue
            if manager.shouldRejectInteriorGapStart(fn_start):
                parent_start = manager.getContainingFunctionStart(fn_start)
                if parent_start is not None:
                    parent_to_children.setdefault(parent_start, []).append(fn_start)

        for parent_start, children in sorted(parent_to_children.items(), reverse=True):
            all_child_blocks = []
            for child_start in children:
                child_blocks = self.disassembly.functions.pop(child_start, None)
                if child_blocks:
                    all_child_blocks.extend(child_blocks)
                self.disassembly.function_borders.pop(child_start, None)
                if hasattr(self.fc_manager, "removeBorder"):
                    self.fc_manager.removeBorder(child_start)
                self.disassembly.function_symbols.pop(child_start, None)
                self.disassembly.recursive_functions.discard(child_start)
                self.disassembly.leaf_functions.discard(child_start)
                self.disassembly.thunk_functions.discard(child_start)

                candidate = manager.candidates.get(child_start)
                if candidate is not None:
                    candidate.setAnalysisAborted("pruned interior gap function")

            if all_child_blocks:
                ins_by_addr = self._collect_insn_map_for_merge(
                    parent_start,
                    child_starts=children,
                    extra_blocks=all_child_blocks,
                )
                self._rebuild_merged_function(parent_start, ins_by_addr)

    def _mergeExtensionIntoParent(self, state, parent_start):
        if not state.instructions:
            return
        parent_borders = self.disassembly.function_borders.get(parent_start)
        standard_span = getattr(self.config, "GAP_INTERIOR_HOLE_STANDARD_FUNCTION_SPAN", 0x10000)
        if parent_borders is not None and parent_borders[1] - parent_borders[0] > standard_span:
            if state.num_blocks_analyzed:
                state._finalizeRegularAnalysis()
            return
        for cref in state.code_refs:
            self.disassembly.addCodeRefs(cref[0], cref[1])
        for dref in state.data_refs:
            self.disassembly.addDataRefs(dref[0], dref[1])
        self.disassembly.data_map.update(state.data_bytes)

        ins_by_addr = self._collect_insn_map_for_merge(parent_start)
        for ins in state.instructions:
            ins_by_addr[ins[0]] = ins
        self._rebuild_merged_function(parent_start, ins_by_addr)

    def _fillInteriorFunctionHoles(
        self,
        cbAnalysisTimeout=None,
        max_function_span=None,
        min_function_span=0,
        max_attempts=None,
        max_scan_bytes=None,
    ):
        max_rounds = getattr(self.config, "GAP_INTERIOR_HOLE_MAX_ROUNDS", 2)
        if max_attempts is None:
            max_attempts = getattr(self.config, "GAP_INTERIOR_HOLE_MAX_ATTEMPTS_PER_PASS", 256)
        if max_scan_bytes is None:
            max_scan_bytes = getattr(self.config, "GAP_INTERIOR_HOLE_MAX_SCAN_BYTES", 4096)
        if max_function_span is None:
            max_function_span = getattr(self.config, "GAP_INTERIOR_HOLE_STANDARD_FUNCTION_SPAN", 0x10000)
        attempts = 0
        for _round in range(max_rounds):
            if not self._gap_budget_remaining():
                break
            progress = False
            for fn_start, (fmin, fmax) in list(self.disassembly.function_borders.items()):
                span = fmax - fmin
                if span > max_function_span or span <= min_function_span:
                    continue
                interval_end = fmax
                if hasattr(self.fc_manager, "_gapIntervalForAddr"):
                    interval = self.fc_manager._gapIntervalForAddr(fmax - 1)
                    if interval is not None:
                        interval_end = interval[1]
                for hole_start in self._iter_interior_hole_starts(fmin, interval_end, max_scan_bytes):
                    if attempts >= max_attempts or not self._gap_budget_remaining():
                        return
                    if self.fc_manager.getInteriorExtensionParent(hole_start) != fn_start:
                        continue
                    state = self._analyze_gap_function(hole_start, cbAnalysisTimeout)
                    attempts += 1
                    if state and state.num_blocks_analyzed:
                        progress = True
            if not progress:
                break

    def _recoverPltStubs(self, cbAnalysisTimeout=None):
        if not self.disassembly.binary_info:
            return
        plt_ranges = []
        for section in self.disassembly.binary_info.getSections() or []:
            name = str(getattr(section, "name", "") or "")
            if ".plt" not in name or ".plt." in name:
                continue
            section_start = getattr(section, "virtual_address", 0)
            section_size = getattr(section, "size", 0)
            if section_size:
                plt_ranges.append((section_start, section_start + section_size))
        if not plt_ranges:
            return
        for section_start, section_end in plt_ranges:
            for addr in range(section_start, section_end, 6):
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    return
                if addr in self.disassembly.code_map:
                    continue
                state = self._analyze_gap_function(addr, cbAnalysisTimeout)
                if state and state.num_blocks_analyzed:
                    LOGGER.debug("recovered PLT stub @0x%08x", addr)

    def _firstExecutableInsnInRange(self, start_addr, end_addr):
        binary_info = self.disassembly.binary_info
        buf = binary_info.binary or b""
        base = binary_info.base_addr or 0
        offset = start_addr - base
        if offset < 0 or offset >= len(buf):
            return None
        window = buf[offset : offset + max(0, end_addr - start_addr)]
        for ins in self.capstone.disasm_lite(window, start_addr):
            if start_addr <= ins[0] < end_addr:
                return ins[0]
        return None

    def _recoverLargeUnmappedGaps(self, cbAnalysisTimeout=None, min_gap=512):
        if not hasattr(self.fc_manager, "refreshFunctionGaps"):
            return
        self.fc_manager.refreshFunctionGaps()
        for gap_start, gap_end, gap_len in sorted(self.fc_manager.function_gaps or [], key=lambda gap: -gap[2]):
            if gap_len < min_gap:
                continue
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            scan_addr = gap_start
            if scan_addr not in self.disassembly.code_map:
                scan_addr = self._firstExecutableInsnInRange(gap_start, min(gap_start + 64, gap_end)) or gap_start
            if scan_addr in self.disassembly.code_map:
                continue
            state = self._analyze_gap_function(scan_addr, cbAnalysisTimeout)
            if state and state.num_blocks_analyzed:
                LOGGER.debug(
                    "recovered large gap function @0x%08x (%d bytes, %d blocks)",
                    gap_start,
                    gap_len,
                    state.num_blocks_analyzed,
                )

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug(
            "Analyzing buffer with %d bytes @0x%08x",
            binary_info.binary_size,
            binary_info.base_addr,
        )
        self._updateLabelProviders(binary_info)
        self._symbol_cache = {}
        self._api_cache = {}
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = self.backend.name
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        if self.disassembly.binary_info.bitness not in [32, 64]:
            self.disassembly.binary_info.bitness = self.backend.probeBitness(self.disassembly)
            LOGGER.debug(
                "Automatically Recognized Bitness as: %d",
                self.disassembly.binary_info.bitness,
            )
        else:
            LOGGER.debug("Using defined Bitness as: %d", self.disassembly.binary_info.bitness)
        if self._forced_bitness:
            self.disassembly.binary_info.bitness = self._forced_bitness
            LOGGER.debug("Forced Bitness override to: %d", self.disassembly.binary_info.bitness)

        self.tailcall_analyzer = TailcallAnalyzer()
        self.indcall_analyzer = self.backend.createIndirectCallAnalyzer(self)
        self.jumptable_analyzer = self.backend.createJumpTableAnalyzer(self)

        self.fc_manager = self.backend.createCandidateManager(self.config)
        if self.config.USE_SYMBOLS_AS_CANDIDATES:
            self.fc_manager.symbol_addresses = self.getSymbolCandidates()
        # once we are initialized, add OEP
        if binary_info.oep is not None:
            self.fc_manager.symbol_addresses.append(binary_info.base_addr + binary_info.oep)
        self.fc_manager.init(self.disassembly)
        self.capstone = self.backend.createCapstone(self.disassembly.binary_info.bitness)
        self._tfidf = self.backend.createTfIdf(self.disassembly.binary_info.bitness)
        LOGGER.debug("Starting heuristical analysis.")
        # first pass, analyze locations identifiable by heuristics (e.g. call-reference, common prologue)
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            self.analyzeFunction(candidate.addr)
        LOGGER.debug(
            "Finished heuristical analysis, functions: %d",
            len(self.disassembly.functions),
        )
        # second pass, analyze remaining gaps (multi-pass gap recovery)
        self._runGapRecoveryPasses(cbAnalysisTimeout)
        # candidates may have been discovered during gap analysis (e.g. tailcall targets triggered
        # by _analyzeUncondBranch); drain them before moving to the tailcall pass.
        for candidate in self.fc_manager.getNextFunctionStartCandidate():
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            self.analyzeFunction(candidate.addr)
        # third pass, fix potential tailcall functions that were identified during analysis
        if self.config.RESOLVE_TAILCALLS:
            tailcalled_functions = self.tailcall_analyzer.resolveTailcalls(self)
            for addr in tailcalled_functions:
                self.fc_manager.addTailcallCandidate(addr)
            LOGGER.debug("Finished tailcall analysis, functions.")
            # drain any candidates that were added during tailcall resolution
            for candidate in self.fc_manager.getNextFunctionStartCandidate():
                if cbAnalysisTimeout and cbAnalysisTimeout():
                    break
                self.analyzeFunction(candidate.addr)
        self.disassembly.failed_analysis_addr = self.fc_manager.getAbortedCandidates()
        # package up and finish
        for addr, candidate in self.fc_manager.candidates.items():
            if addr in self.disassembly.functions:
                function_blocks = self.disassembly.getBlocksAsDict(addr)
                function_tfidf = self._tfidf.getTfIdfFromBlocks(function_blocks)
                candidate.setTfIdf(function_tfidf)
                candidate.getConfidence()
            self.disassembly.candidates[addr] = candidate
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
