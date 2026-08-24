# Replicating the origin evaluation

SMDA's origin paper — Daniel Plohmann, *Classification, Characterization, and Contextualization of
Windows Malware using Static Behavior and Similarity Analysis*, University of Bonn, 2022 —
evaluates function-entry-point recovery against three other disassemblers. This document records
what that evaluation measured, precisely enough to re-run, and reproduces the comparison with
today's SMDA and today's Ghidra.

`tools/bench/paper_table.py` prints the table. Run it over a results directory produced by
`tools/bench/run.py`.

## What the paper measures

**A true positive is an exact function-start address match.** Recall and precision are computed
per binary and then aggregated:

```
TPR = |detected ∩ truth| / |truth|
PPV = |detected ∩ truth| / |detected|
```

Function *boundaries* are not scored — only starts. The paper says why: boundary and start results
track each other closely in the evaluation it aligns with, and start discovery is the heuristic
under study. Instruction recovery is discussed but not tabulated.

**Aggregation differs by row, and this is easy to get wrong.** Rows whose binaries carry an
`O0`–`O3` optimization label are split by that label and each cell is the **geometric** mean over
the binaries at that level, chosen so an outlier binary is penalised rather than averaged away.
Rows whose binaries carry no such label — the memory-dumped corpora, where every binary is
labelled `dump7`, and the malware corpus, labelled `-` — are a single cell holding the
**arithmetic** mean over all of them. Mixing the two produces numbers that look almost right.

**`Os`, `Od` and `Ox` builds are excluded** from every aggregate. On the 32-bit ByteWeight corpus
that is 34 binaries rather than 68.

## What counts as a function in the ground truth

- **Import thunks count.** The paper states the reasoning: the stubs are referenced by other code
  and consist of code themselves, albeit one `jmp`, and every disassembler in the comparison
  reports the PE ones. It folds all of them into the truth set. The ByteWeight corpus ships them
  in a separate list from the function extents; both are read.
- **External functions do not.** An import represented only by an offset has no code. Ghidra and
  IDA both enumerate these with an `external` flag, and the paper discards them on that flag. This
  harness does the same, and additionally drops entries outside an executable memory block.
- The corpus's own labelling study puts the manual labelling behind the malware corpus at 99.16%
  recall against ByteWeight's compiler-derived truth, with 392 false positives and 52 false
  negatives over 6,213 functions. A disagreement on that corpus is therefore evidence to
  investigate, not automatically a defect.

## Corpus composition

| paper's name | what | in this harness |
|---|---|---|
| `GB` ByteWeight | 68 MSVC-built PE files, 32- and 64-bit, `O1` and `O2` | `bao-x86`, `bao-x86-64` under `--filter paper` |
| `GB*` ByteWeight* | the same programs re-mapped as memory dumps with the PE headers zeroed | `bao-x86-dumped`, `bao-x86-64-dumped` |
| `GM` Malpedia57 | 57 memory dumps sampled from Malpedia, covering 56 families | `malpedia` |
| `GA` Andriesse | SPEC CPU2006, servers and glibc, Linux | not available here — SPEC is licence-restricted |

The `GB*` corpus is derived rather than published: the binaries are mapped as they would be in
memory, which shifts code from file offset 0x400 to RVA 0x1000, and the PE headers are then
overwritten with zeroes so no structural information survives.

## Design goals the evaluation is written against

These are the paper's own stated priorities, and a change that improves a metric while violating
one of them is a regression, not a gain:

1. **The same result whether the input is an unmapped file with full context or shellcode with
   none.** Assumptions about structural layout are deliberately minimised.
2. **Completeness over precision.** FEP discovery and gap analysis are described as deliberately
   aggressive; the paper accepts the resulting false positives explicitly.
3. **Memory dumps are the target**, not on-disk executables. The dumped and malware corpora are
   where the approach is meant to win.

## Engine versions

The paper evaluates Ghidra 9.1.2, IDA Pro 6.7 (figures carried over from Andriesse et al.), IDA Pro
7.4, nucleus, and SMDA 1.2.5.

There is no IDA licence available here, so **IDA 6.7, IDA 7.4 and nucleus are not re-measured**.
Their columns come from the original evaluation's own per-binary result files and are labelled
`(paper)` in every table. Ghidra and SMDA are re-measured live and labelled `(measured)`. The
distinction is in the table itself, not only in the prose around it.
