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

## Numbers taken from the paper rather than re-measured

`docs/paper-tables.json` holds the paper's Table 6.3 (quality of the manual labelling), Table 6.4
(entry-point reliability by reference count) and Table 6.5 (the disassembler comparison) as
machine-readable data, together with the corpus descriptions and the design goals above. Nothing in
that file is a measurement made here.

Two figures from it are load-bearing for how a disagreement on these corpora should be read:

- **Gap search supplies 45.08% of all recovered starts on the ByteWeight corpus, at precision
  0.933** — every other reference count is at 0.99 or better. On the malware corpus gap search
  supplies only 20.19%, at precision 0.786. Precision on these corpora is dominated by one
  mechanism, and it is the one the design deliberately runs aggressively.
- **The ByteWeight ground truth is not complete.** The paper's own labelling study found 249
  functions in `client7z` that are referenced by other code and absent from the PDB-derived truth.
  `client7z` is still among the lowest-scoring binaries in the corpus today, which is consistent
  with a truth gap rather than a detection failure.

## What reproduced

Geometric mean per optimization level for the split rows, arithmetic mean for the rest, exactly as
the origin evaluation aggregates them. TPR / PPV.

| row | opt | n | ghidra 9.1.2 (recorded) | ghidra 12.1.3 (measured) | smda 1.2.5 (recorded) | smda 4.4.7 (measured) |
|---|---|---|---|---|---|---|
| `GB` ByteWeight msvc10-32 | O1 | 17 | 0.804 / 0.952 | 0.817 / 0.953 | 0.992 / 0.935 | 0.994 / 0.938 |
| `GB` ByteWeight msvc10-32 | O2 | 17 | 0.809 / 0.950 | 0.822 / 0.951 | 0.992 / 0.927 | 0.994 / 0.932 |
| `GB` ByteWeight msvc10-64 | O1 | 17 | 0.675 / 0.999 | incomplete | 0.975 / 0.983 | 0.998 / 0.993 |
| `GB` ByteWeight msvc10-64 | O2 | 17 | 0.703 / 0.999 | 0.809 / 0.999 | 0.972 / 0.981 | 0.998 / 0.993 |
| `GB*` ByteWeight* msvc10-32 | – | 56 | 0.775 / 0.953 | 0.777 / 0.953 | 0.967 / 0.910 | 0.975 / 0.912 |
| `GB*` ByteWeight* msvc10-64 | – | 56 | 0.653 / 0.999 | 0.663 / 0.999 | 0.932 / 0.985 | 0.998 / 0.989 |
| `GM` Malpedia57 | – | 57 | 0.819 / 0.940 | pending | 0.976 / 0.935 | 0.986 / 0.926 |

**Ghidra reproduces.** On four of the five comparable cells, Ghidra 12.1.3 lands within 0.002 to
0.013 of what was recorded for Ghidra 9.1.2 — a different major version, five years apart, and the
same metric implementation returning the published numbers. That is the strongest available check
that this harness computes the paper's metric rather than a metric of its own: the earlier check
compared SMDA against a recorded SMDA measurement, which cannot rule out a shared assumption.

**SMDA has moved, and unevenly.** Recall rises on every row, and almost all of the change is on the
hardest one: the dumped 64-bit corpus goes from 0.932 to 0.998, where the corpora with headers were
already close to their ceiling. Precision is flat to slightly better everywhere.

**Ghidra has barely moved.** Its largest change on a comparable cell is +0.013 recall. The gap the
origin evaluation reported between the two tools on memory dumps is wider today than it was.

## Where a replication is expected to diverge from the published numbers

1. **Engine versions.** SMDA is at 4.4.7 rather than 1.2.5, and Ghidra at 12.1.3 rather than 9.1.2.
   Both have had years of development; the comparison answers "where do these tools stand today",
   not "does the old measurement reproduce bit for bit".
2. **IDA and nucleus are not re-measured.** No IDA licence is available, so those columns are the
   original evaluation's own per-binary results, labelled as such in the table.
3. **The Andriesse corpus is absent.** Its SPEC component is licence-restricted, so the `GA` rows
   cannot be reproduced at all. A second corpus built from source stands in for the cross-check it
   would have provided.
4. **One ByteWeight binary is paired with the wrong ground truth** (see the research log). It is
   included by default, because every published figure for this corpus includes it.
5. **The analysis budget is this harness' choice, and on one binary it decides the answer.** Both
   engines get the timeout `--timeout` names, defaulting to SMDA's own so neither is favoured.
   Ghidra does not finish `msvs_whatever_64_O1_vim` — 5,445 truth functions — inside it, and an
   incomplete run scores 0. The geometric mean this evaluation applies to an optimization-level row
   then carries the zero into the whole cell, so that cell is marked and the sample named rather than
   printed as a number. Read the Ghidra column as *Ghidra under this budget*.

## Running the replication

```
tools/bench/run.py --corpus all --engine smda,ghidra --filter all --out results/
tools/bench/paper_table.py results/ --json results/paper_table.json
```

The table prints the paper's recorded values and the measured ones side by side, with `(paper)` and
`(measured)` in the column headers, and ends with a control line naming which engines were actually
measured and which columns are recorded. A corpus an engine has not been run on prints
`not measured` rather than a blank, so a missing engine cannot be read as a bad score.
