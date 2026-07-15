// Locate real binaries to validate SMDA's opt-in AArch64 ELF FDE candidates.
// Matched files retain both unwind metadata and a symbol-table boundary oracle.

import "elf"

rule aarch64_elf_with_eh_frame_symbols
{
    meta:
        source_flag = "USE_ELF_EH_FRAME_CANDIDATES"
        ground_truth = ".symtab function symbols"
    condition:
        elf.machine == elf.EM_AARCH64
        and for any s in elf.sections : (s.name == ".eh_frame")
        and for any s in elf.sections : (s.name == ".symtab")
}
