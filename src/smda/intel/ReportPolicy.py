"""Intel report-output policy: boundary merges, orphan demotion, padding trim, rooted metrics."""

from __future__ import annotations

from bisect import bisect_left
from collections import deque

_PADDING_BYTES = {0x00, 0x90, 0xCC}
_END_MNEMONICS = {"ret", "retn", "retf"}


def _normalize_byte(byte):
    if isinstance(byte, str):
        return ord(byte)
    return byte


def _oep_addrs(disassembly):
    base = disassembly.binary_info.base_addr or 0
    oep = disassembly.binary_info.getOep()
    if oep is None:
        return set()
    return {base + oep, oep}


def _is_seed_function(fn_start, disassembly, candidate):
    if fn_start in disassembly.exported_functions:
        return True
    if candidate is not None and (candidate.is_symbol or candidate.is_exception_handler):
        return True
    if fn_start in _oep_addrs(disassembly):
        return True
    return bool(disassembly.function_symbols.get(fn_start))


def _has_inbound_code_refs(fn_start, disassembly, sorted_targets=None):
    borders = disassembly.function_borders.get(fn_start)
    if borders is None:
        return bool(disassembly.code_refs_to.get(fn_start))
    fmin, fmax = borders
    code_refs_to = disassembly.code_refs_to
    if sorted_targets is None:
        # fn_start always lies within [fmin, fmax); the range check covers it.
        in_range = (addr for addr in code_refs_to if addr == fn_start or (fmin <= addr < fmax))
    else:
        in_range = sorted_targets[bisect_left(sorted_targets, fmin) : bisect_left(sorted_targets, fmax)]
    for target_addr in in_range:
        refs = code_refs_to.get(target_addr)
        if not refs:
            continue
        for ref_from in refs:
            caller_fn = disassembly.ins2fn.get(ref_from)
            if caller_fn is not None and caller_fn != fn_start:
                return True
    return False


def _has_external_inbound_refs_at_start(fn_start, disassembly):
    for ref_from in disassembly.code_refs_to.get(fn_start, set()):
        caller_fn = disassembly.ins2fn.get(ref_from)
        if caller_fn is not None and caller_fn != fn_start:
            return True
    return False


def _is_boundary_merge_child(child_start, disassembly, candidate, candidates):
    if candidate is None or not candidate.hasCommonFunctionStart():
        return False
    if candidate.call_ref_sources or candidate.is_gap_candidate or candidate.is_tailcall:
        return False
    if _is_seed_function(child_start, disassembly, candidate):
        return False
    return not _has_external_inbound_refs_at_start(child_start, disassembly)


def is_prologue_only_orphan(fn_start, disassembly, candidate, candidates, sorted_targets=None):
    """True when a function should be demoted from report output."""
    if _is_seed_function(fn_start, disassembly, candidate):
        return False
    if _has_inbound_code_refs(fn_start, disassembly, sorted_targets):
        return False
    if candidate is None:
        return False
    if candidate.call_ref_sources:
        return False
    if candidate.is_gap_candidate:
        return False
    if candidate.is_tailcall:
        return False
    return candidate.is_initial_candidate or candidate.hasCommonFunctionStart()


def find_boundary_merge_pairs(disassembly, candidates):
    """Return (parent_start, child_start) for adjacent zero-inref prologue splits."""
    borders = [
        (start, bounds) for start, bounds in disassembly.function_borders.items() if start in disassembly.functions
    ]
    # Index neighbours by their shared boundary so adjacency is O(1) instead of
    # an O(F^2) all-pairs scan; sorted ref targets let inbound checks bisect.
    starts_at = {bounds[0]: start for start, bounds in borders}
    ends_at = {bounds[1]: start for start, bounds in borders}
    sorted_targets = sorted(disassembly.code_refs_to)
    merge_target_cache = {}

    def _parent_is_merge_target(parent_start):
        if parent_start in merge_target_cache:
            return merge_target_cache[parent_start]
        parent_candidate = candidates.get(parent_start)
        result = (
            _is_seed_function(parent_start, disassembly, parent_candidate)
            or _has_inbound_code_refs(parent_start, disassembly, sorted_targets)
            or (parent_candidate is not None and bool(parent_candidate.call_ref_sources))
        )
        merge_target_cache[parent_start] = result
        return result

    child_to_parent = {}
    for child_start, (child_min, child_max) in borders:
        child_candidate = candidates.get(child_start)
        if not _is_boundary_merge_child(child_start, disassembly, child_candidate, candidates):
            continue
        # A child adjacent to a parent on either side merges into it; when both
        # neighbours qualify the right-hand parent wins, matching the original
        # min-sorted "last write wins" iteration order.
        right_parent = starts_at.get(child_max)
        left_parent = ends_at.get(child_min)
        if right_parent is not None and right_parent != child_start and _parent_is_merge_target(right_parent):
            child_to_parent[child_start] = right_parent
        elif left_parent is not None and left_parent != child_start and _parent_is_merge_target(left_parent):
            child_to_parent[child_start] = left_parent
    return [(parent, child) for child, parent in sorted(child_to_parent.items())]


def trim_post_ret_padding(disassembly):
    """Remove trailing synthetic padding instructions after ret/retn/retf."""
    removed_addrs = set()
    for fn_start in list(disassembly.functions.keys()):
        blocks = disassembly.functions.get(fn_start)
        if not blocks:
            continue
        all_ins = [ins for block in blocks for ins in block]
        if not all_ins:
            continue
        last_real = None
        for ins in sorted(all_ins, key=lambda row: row[0]):
            mnemonic = ins[2].split()[-1] if ins[2] else ""
            if mnemonic in _END_MNEMONICS:
                last_real = ins
        if last_real is None:
            continue
        trim_from = last_real[0] + last_real[1]
        parent_min, parent_max = disassembly.function_borders.get(fn_start, (fn_start, trim_from))
        addr = trim_from
        local_removed = set()
        while addr < parent_max:
            if addr not in disassembly.instructions:
                break
            mnemonic, size = disassembly.instructions[addr]
            base_mnemonic = mnemonic.split()[-1] if mnemonic else ""
            if base_mnemonic not in ("db", "nop"):
                break
            byte_vals = [
                _normalize_byte(disassembly.getByte(addr + offset))
                for offset in range(size)
                if disassembly.getByte(addr + offset) is not None
            ]
            if not byte_vals or any(val not in _PADDING_BYTES for val in byte_vals):
                break
            local_removed.add(addr)
            disassembly.instructions.pop(addr, None)
            for offset in range(size):
                disassembly.code_map.pop(addr + offset, None)
                disassembly.ins2fn.pop(addr + offset, None)
            addr += size
        if local_removed:
            removed_addrs |= local_removed
            new_end = trim_from if addr >= parent_max else addr
            disassembly.function_borders[fn_start] = (parent_min, new_end)
            rebuilt = []
            for block in blocks:
                kept = [ins for ins in block if ins[0] not in local_removed]
                if kept:
                    rebuilt.append(kept)
            if rebuilt:
                disassembly.functions[fn_start] = rebuilt
    return removed_addrs


def build_function_call_graph(disassembly):
    """Map each function start -> set of callee function starts, in ONE pass over
    code_refs_from. Replaces a per-function O(refs) rescan so closures are O(R + F)."""
    ins2fn = disassembly.ins2fn
    functions = disassembly.functions
    out = {}
    for src, targets in disassembly.code_refs_from.items():
        owner = ins2fn.get(src)
        if owner is None:
            continue
        bucket = out.get(owner)
        if bucket is None:
            bucket = out[owner] = set()
        for target in targets:
            target_owner = ins2fn.get(target)
            if target_owner is not None and target_owner in functions:
                bucket.add(target_owner)
    return out


def compute_rooted_closure(disassembly, seed_predicate, call_graph=None):
    """Return (rooted_function_starts, rooted_instruction_addrs)."""
    if call_graph is None:
        call_graph = build_function_call_graph(disassembly)
    queue = deque(sorted(start for start in disassembly.functions if seed_predicate(start)))
    seen = set(queue)
    while queue:
        fn_start = queue.popleft()
        for target in call_graph.get(fn_start, ()):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    rooted_insns = set()
    functions = disassembly.functions
    for fn_start in seen:
        for block in functions.get(fn_start, []):
            for ins in block:
                rooted_insns.add(ins[0])
    return seen, rooted_insns


def compute_connected_and_rooted_metrics(disassembly, candidates):
    """Compute rooted/connected function and instruction counts for statistics."""
    _rooted_functions, metrics = _compute_rooted_metrics(disassembly, candidates)
    return metrics


def _compute_rooted_metrics(disassembly, candidates):
    oep_values = _oep_addrs(disassembly)
    call_graph = build_function_call_graph(disassembly)

    def seed_predicate(fn_start):
        candidate = candidates.get(fn_start)
        if fn_start in oep_values or fn_start in disassembly.exported_functions:
            return True
        if candidate is not None and (candidate.is_symbol or candidate.is_exception_handler):
            return True
        return bool(disassembly.function_symbols.get(fn_start))

    rooted_functions, rooted_insns = compute_rooted_closure(disassembly, seed_predicate, call_graph)
    if rooted_functions:
        return rooted_functions, {
            "rooted_function_count": len(rooted_functions),
            "rooted_instruction_count": len(rooted_insns),
            "connected_function_count": len(rooted_functions),
            "connected_instruction_count": len(rooted_insns),
            "rooted_mode": "seed-closure",
        }

    sorted_targets = sorted(disassembly.code_refs_to)

    def xref_predicate(fn_start):
        return _has_inbound_code_refs(fn_start, disassembly, sorted_targets)

    rooted_functions, rooted_insns = compute_rooted_closure(disassembly, xref_predicate, call_graph)
    if rooted_functions:
        return rooted_functions, {
            "rooted_function_count": len(rooted_functions),
            "rooted_instruction_count": len(rooted_insns),
            "connected_function_count": len(rooted_functions),
            "connected_instruction_count": len(rooted_insns),
            "rooted_mode": "xref-closure",
        }

    all_insns = set()
    for fn_start in disassembly.functions:
        for block in disassembly.functions[fn_start]:
            for ins in block:
                all_insns.add(ins[0])
    all_functions = set(disassembly.functions.keys())
    return all_functions, {
        "rooted_function_count": len(all_functions),
        "rooted_instruction_count": len(all_insns),
        "connected_function_count": len(all_functions),
        "connected_instruction_count": len(all_insns),
        "rooted_mode": "all-instructions",
    }


def _build_code_ref_reverse_index(disassembly):
    """Build an exact reverse of code_refs_from (target -> {sources}) plus a grouping of
    referenced targets by their owning function. Lets _remove_function drop inbound edges in
    O(removed edges) instead of rescanning every source per removal (the quadratic hot path).

    Built from code_refs_from directly (not code_refs_to, which is not guaranteed symmetric)
    so the touched (source, target) edges match the original full-scan filter exactly.
    """
    reverse = {}
    targets_by_fn = {}
    ins2fn = disassembly.ins2fn
    for src, targets in disassembly.code_refs_from.items():
        for target in targets:
            srcs = reverse.get(target)
            if srcs is None:
                reverse[target] = srcs = set()
                owner = ins2fn.get(target)
                if owner is not None:
                    targets_by_fn.setdefault(owner, []).append(target)
            srcs.add(src)
    return reverse, targets_by_fn


def _remove_function(disassembly, fn_start, ref_index=None):
    blocks = disassembly.functions.pop(fn_start, None)
    disassembly.function_borders.pop(fn_start, None)
    disassembly.function_symbols.pop(fn_start, None)
    disassembly.recursive_functions.discard(fn_start)
    disassembly.leaf_functions.discard(fn_start)
    disassembly.thunk_functions.discard(fn_start)
    if not blocks:
        return
    for block in blocks:
        for ins in block:
            addr, size = ins[0], ins[1]
            disassembly.instructions.pop(addr, None)
            for offset in range(size):
                disassembly.code_map.pop(addr + offset, None)
                disassembly.ins2fn.pop(addr + offset, None)
    # Drop inbound code-ref edges pointing at addresses still owned by this function.
    # Equivalent to filtering every code_refs_from[src] by `ins2fn[target] != fn_start`, but
    # reached through a prebuilt reverse index so the cost is O(removed edges) instead of
    # O(functions-removed * all-refs) -- the quadratic form dominated large-binary runtime.
    if ref_index is not None:
        reverse, targets_by_fn = ref_index
        candidate_targets = targets_by_fn.get(fn_start, ())
    else:
        reverse, _ = _build_code_ref_reverse_index(disassembly)
        candidate_targets = [t for t in reverse if disassembly.ins2fn.get(t) == fn_start]
    for target in candidate_targets:
        # Only addresses whose ins2fn survived the instruction-byte pop above are still owned
        # by fn_start; this mirrors the original per-target `ins2fn[target] == fn_start` test.
        if disassembly.ins2fn.get(target) != fn_start:
            continue
        for src in reverse.get(target, ()):
            refs = disassembly.code_refs_from.get(src)
            if refs is None:
                continue
            refs.discard(target)
            if not refs:
                disassembly.code_refs_from.pop(src, None)
    disassembly.code_refs_to.pop(fn_start, None)


def apply_intel_report_policy(disassembler):
    """Mutate disassembly to match Intel report-output policy before SmdaReport build."""
    disassembly = disassembler.disassembly
    candidates = disassembler.fc_manager.candidates

    for parent_start, child_start in find_boundary_merge_pairs(disassembly, candidates):
        child_blocks = disassembly.functions.pop(child_start, None)
        if not child_blocks:
            continue
        disassembly.function_borders.pop(child_start, None)
        disassembly.function_symbols.pop(child_start, None)
        disassembly.recursive_functions.discard(child_start)
        disassembly.leaf_functions.discard(child_start)
        disassembly.thunk_functions.discard(child_start)
        ins_by_addr = disassembler._collect_insn_map_for_merge(
            parent_start,
            child_start=child_start,
            extra_blocks=child_blocks,
        )
        disassembler._rebuild_merged_function(parent_start, ins_by_addr)

    trim_post_ret_padding(disassembly)

    sorted_targets = sorted(disassembly.code_refs_to)
    # Reverse-index code refs once so orphan removal purges inbound edges in O(removed edges)
    # rather than rescanning every source per removal (previously the quadratic hot path).
    ref_index = _build_code_ref_reverse_index(disassembly)
    for fn_start in sorted(disassembly.functions.keys()):
        candidate = candidates.get(fn_start)
        if is_prologue_only_orphan(fn_start, disassembly, candidate, candidates, sorted_targets):
            _remove_function(disassembly, fn_start, ref_index)

    metrics = compute_connected_and_rooted_metrics(disassembly, candidates)
    disassembly.report_policy_metrics = metrics
    return metrics
