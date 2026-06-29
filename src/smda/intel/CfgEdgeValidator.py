"""Capstone-grounded CFG edge validation for recovered Intel functions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import capstone

from .definitions import CALL_INS, CJMP_INS, END_INS, JMP_INS, LOOP_INS


@dataclass
class CfgEdgeMismatch:
    function: int
    from_addr: int
    reported_to: int
    expected_to: set[int] = field(default_factory=set)
    mnemonic: str = ""
    reason: str = ""


class CfgEdgeValidator:
    """Validate SMDA code references against SMDA-compatible operand decoding."""

    def __init__(self, disassembly):
        self.disassembly = disassembly
        self.bitness = disassembly.binary_info.bitness

    @staticmethod
    def _base_mnemonic(mnemonic):
        return mnemonic.split()[-1]

    def _valid_fallthrough(self, addr):
        return addr in self.disassembly.code_map or addr in self.disassembly.data_map

    def _resolve_memory_target(self, addr, op_str):
        referenced = 0
        match = re.search(r"(?P<sign>[+-])?\s*0x(?P<value>[a-fA-F0-9]+)", op_str)
        if match:
            value = int(match.group("value"), 16)
            referenced = -value if match.group("sign") == "-" else value
        if op_str.startswith(("qword ptr [rip", "dword ptr [rip")):
            ins_size = self.disassembly.instructions[addr][1]
            return (addr + ins_size) + referenced
        if op_str.startswith(("dword ptr [0x", "qword ptr [0x")):
            return referenced
        return None

    def _deref_slot(self, slot):
        if not self.disassembly.isAddrWithinMemoryImage(slot):
            return None
        if self.bitness == 64:
            return self.disassembly.dereferenceQword(slot)
        return self.disassembly.dereferenceDword(slot)

    def _api_targets_for(self, addr):
        targets = set()
        for api_addr, entry in self.disassembly.apis.items():
            if addr in entry.get("referencing_addr", []):
                targets.add(api_addr)
        return targets

    def _operand_target(self, addr, op_str):
        """Resolve a branch/call operand to its absolute target address(es).

        Capstone prints direct targets as a single absolute immediate -- hex
        ("0x1050") OR bare decimal for small values, including "0" (LSN-004:
        capstone omits the 0x prefix for address 0). Returns an empty set for
        indirect transfers (register operand, or a memory operand whose slot
        cannot be statically resolved)."""
        if op_str.startswith(("dword ptr", "qword ptr", "word ptr", "byte ptr")):
            slot = self._resolve_memory_target(addr, op_str)
            if slot is None:
                return set()
            targets = {slot}
            dereferenced = self._deref_slot(slot)
            if dereferenced is not None:
                targets.add(dereferenced)
            return targets
        stripped = op_str.strip()
        if not stripped or "[" in stripped:
            return set()
        try:
            return {int(stripped, 0)}
        except ValueError:
            return set()

    def _expected_targets(self, addr, mnemonic, op_str):
        """Return (expected_targets, verifiable). verifiable is False when a
        control transfer's target is indirect (register / unresolved memory) and
        thus the reported taken edge cannot be checked statically."""
        base = self._base_mnemonic(mnemonic)
        next_addr = addr + self.disassembly.instructions[addr][1]
        is_branch = base in CALL_INS or base in JMP_INS or base in CJMP_INS or base in LOOP_INS
        operand_targets = self._operand_target(addr, op_str) if is_branch else set()
        targets = set(operand_targets)

        # call / conditional-jump / loop fall through to the next instruction, as
        # does any non-control-flow instruction; unconditional jmp and END do not.
        falls_through = (
            base in CALL_INS or base in CJMP_INS or base in LOOP_INS or (not is_branch and base not in END_INS)
        )
        if falls_through and self._valid_fallthrough(next_addr):
            targets.add(next_addr)

        verifiable = not (is_branch and not operand_targets)
        return targets, verifiable

    def _edges_match(self, addr, expected, reported, verifiable):
        if not verifiable:
            # indirect transfer target is unknowable statically; cannot flag a mismatch
            return True
        expanded = set(expected)
        expanded.update(self._api_targets_for(addr))
        # SMDA may legitimately omit implicit fallthrough edges; every edge it DOES
        # report must be an expected/known target.
        return reported.issubset(expanded)

    def validateFunction(self, function_addr):
        mismatches = []
        if function_addr not in self.disassembly.functions:
            return mismatches
        for block in self.disassembly.functions[function_addr]:
            for ins in block:
                addr, _size, mnemonic, op_str, _raw = ins
                if addr not in self.disassembly.instructions:
                    continue
                base = self._base_mnemonic(mnemonic)
                expected, verifiable = self._expected_targets(addr, mnemonic, op_str)
                reported = set(self.disassembly.code_refs_from.get(addr, set()))
                if base in {"nop", "db"} and not reported:
                    continue
                if not expected and not reported:
                    continue
                if self._edges_match(addr, expected, reported, verifiable):
                    continue
                mismatches.append(
                    CfgEdgeMismatch(
                        function=function_addr,
                        from_addr=addr,
                        reported_to=sorted(reported)[0] if len(reported) == 1 else 0,
                        expected_to=expected,
                        mnemonic=mnemonic,
                        reason="edge mismatch",
                    )
                )
        return mismatches

    def validateAll(self, limit=0):
        mismatches = []
        for function_addr in sorted(self.disassembly.functions.keys()):
            mismatches.extend(self.validateFunction(function_addr))
            if limit and len(mismatches) >= limit:
                break
        return mismatches[:limit] if limit else mismatches

    def summarize(self, limit=32):
        mismatches = self.validateAll()
        checked_edges = 0
        for _function_addr, blocks in self.disassembly.functions.items():
            for block in blocks:
                for ins in block:
                    if ins[0] in self.disassembly.code_refs_from:
                        checked_edges += len(self.disassembly.code_refs_from[ins[0]])
        return {
            "functions": len(self.disassembly.functions),
            "checked_edges": checked_edges,
            "mismatches": len(mismatches),
            "samples": [
                {
                    "function": hex(m.function),
                    "from": hex(m.from_addr),
                    "reported": [hex(t) for t in sorted(self.disassembly.code_refs_from.get(m.from_addr, set()))],
                    "expected": [hex(t) for t in sorted(m.expected_to)],
                    "mnemonic": m.mnemonic,
                }
                for m in mismatches[:limit]
            ],
        }

    def measureExecutableCompleteness(self, sections=None):
        """Compare capstone-linear instruction starts in ELF exec sections against SMDA."""
        binary_info = self.disassembly.binary_info
        base = binary_info.base_addr or 0
        buf = binary_info.binary or b""
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.bitness == 64 else capstone.CS_MODE_32)
        exec_sections = sections or []
        if not exec_sections and binary_info.getSections():
            code_areas = getattr(binary_info, "code_areas", None) or []
            for section_name, section_start, section_end in binary_info.getSections():
                if code_areas:
                    for code_start, code_end in code_areas:
                        overlap_start = max(section_start, code_start)
                        overlap_end = min(section_end, code_end)
                        if overlap_end > overlap_start:
                            exec_sections.append((overlap_start, overlap_end, section_name))
                elif section_end > section_start:
                    exec_sections.append((section_start, section_end, section_name))
        capstone_starts = set()
        smda_starts = set(self.disassembly.instructions.keys())
        for section_start, section_end, _name in exec_sections:
            addr = section_start
            while addr < section_end:
                rel = addr - base
                if rel < 0 or rel >= len(buf):
                    addr += 1
                    continue
                decoded = list(md.disasm(buf[rel : rel + 16], addr, count=1))
                if decoded and decoded[0].address == addr and decoded[0].size > 0:
                    capstone_starts.add(addr)
                    addr += decoded[0].size
                else:
                    addr += 1
        overlap = capstone_starts & smda_starts
        return {
            "capstone_instruction_starts": len(capstone_starts),
            "smda_instruction_starts": len([addr for addr in smda_starts if addr in capstone_starts]),
            "overlap": len(overlap),
            "recall": round(len(overlap) / len(capstone_starts), 4) if capstone_starts else 1.0,
            "missing_samples": [hex(addr) for addr in sorted(capstone_starts - smda_starts)[:16]],
        }
