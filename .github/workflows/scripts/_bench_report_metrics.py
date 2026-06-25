"""Shared SMDA report parsing + rooted-instruction closure for the benchmark scripts.

Both ``run_perf_check.py`` (fixture gate) and ``evaluate_runtime.py`` (Malpedia
evaluation) need to derive, from a *serialized* SMDA report, the set of
instruction addresses in the statically-evidenced execution component. They run
against both the base and PR reports, so this logic deliberately works off the
JSON (``xcfg``) rather than importing the SMDA package under test.
"""

from __future__ import annotations


def parse_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def iter_instruction_offsets(blocks):
    """Yield instruction start offsets from a function's serialized ``blocks``.

    ``blocks`` is ``{block_offset: [instruction, ...]}`` (the shape emitted by
    ``SmdaFunction.toDict()``) but a plain list of blocks is also accepted.
    """
    iterable = blocks.values() if isinstance(blocks, dict) else blocks
    for block in iterable:
        if isinstance(block, dict):
            instructions = block.get("instructions", block.get("insns", []))
        elif isinstance(block, list):
            instructions = block
        else:
            instructions = []
        for instruction in instructions:
            if isinstance(instruction, list) and instruction:
                yield parse_int(instruction[0])
            elif isinstance(instruction, dict):
                yield parse_int(instruction.get("offset", instruction.get("address")))


def extract_functions(xcfg):
    """Build ``{function_start: {...}}`` from a serialized ``xcfg`` dict.

    Returns ``(functions, all_instruction_addrs)``.
    """
    function_starts = {parse_int(addr) for addr in xcfg}
    functions = {}
    all_instruction_addrs = set()
    for addr, func_data in xcfg.items():
        function_start = parse_int(addr)
        blocks = func_data.get("blocks", {})
        function_insns = {offset for offset in iter_instruction_offsets(blocks) if offset is not None}
        all_instruction_addrs.update(function_insns)

        outrefs = set()
        for targets in func_data.get("outrefs", {}).values():
            for target in targets:
                target_addr = parse_int(target)
                if target_addr in function_starts:
                    outrefs.add(target_addr)

        functions[function_start] = {
            "start": function_start,
            "insns": function_insns,
            "outrefs": outrefs,
            "inrefs": func_data.get("inrefs", []),
            "is_exported": func_data.get("is_exported", False),
            "function_name": func_data.get("metadata", {}).get("function_name", ""),
        }
    return functions, all_instruction_addrs


def rooted_instruction_addrs(report_dict, functions):
    """Instruction addresses in the statically-evidenced execution component.

    Prefer report-visible seeds (OEP, exports, symbols) plus their function-call
    closure; fall back to xref-rooted functions, then to all instructions, so
    prologue-only/orphan islands do not dominate the gate. Returns
    ``(addrs, mode, rooted_function_count)``.
    """
    starts = set(functions)
    base_addr = report_dict.get("base_addr") or 0
    oep = report_dict.get("oep")
    oep_values = {
        candidate for candidate in (oep, base_addr + oep if oep is not None else None) if candidate is not None
    }

    def has_oep(function):
        return function["start"] in oep_values or bool(function["insns"] & oep_values)

    def closure(seed_predicate):
        queue = [start for start, function in functions.items() if seed_predicate(function)]
        seen = set(queue)
        for start in queue:
            for target in functions[start]["outrefs"]:
                if target in starts and target not in seen:
                    seen.add(target)
                    queue.append(target)
        rooted = set()
        for start in seen:
            rooted.update(functions[start]["insns"])
        return rooted, len(seen)

    rooted, rooted_functions = closure(
        lambda function: has_oep(function) or bool(function["is_exported"]) or bool(function["function_name"])
    )
    if rooted:
        return rooted, "seed-closure", rooted_functions

    rooted, rooted_functions = closure(lambda function: bool(function["inrefs"]))
    if rooted:
        return rooted, "xref-closure", rooted_functions

    all_insns = set()
    for function in functions.values():
        all_insns.update(function["insns"])
    return all_insns, "all-instructions", len(functions)
