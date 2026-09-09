# Description edits for PR #300

Replace the `## The numbers` section wholesale, and patch the individual figures listed after it. Everything else in the body still reads correctly.

---

## REPLACE: the whole `## The numbers` section

## The numbers

Measured against compiler symbol tables on corpora built from source, both trees run back to back on the same machine, against master at `6240b74` — i.e. with #304, #307, #309, #310, #311 and #312 already in. Arithmetic macro mean (mean of per-binary rates), `--filter all`, stock config.

| corpus | n | PPV before → after | TPR before → after | ΔFP | ΔTP |
|---|---|---|---|---|---|
| Built C/C++ AArch64 ELF (gcc cross) | 72 | 91.497 → **94.947** | 97.705 → **98.069** | −3,645 | +151 |
| Built Rust (gnu targets) | 24 | 79.659 → **87.480** | 98.237 → **98.361** | −1,641 | +19 |
| Built Go (pclntab truth) | 47 | 95.361 → **95.626** | 99.367 → 99.367 | −408 | 0 |
| ARM64 Mach-O (linker truth) | 11 | 94.281 → **94.499** | 96.402 → **97.207** | −27 | +38 |
| Built C/C++, MinGW PE cells | 120 | bit-identical | bit-identical | 0 | 0 |
| ByteWeight msvc10-64 | 68 | bit-identical | bit-identical | 0 | 0 |
| ByteWeight msvc10-64, headers stripped | 56 | bit-identical | bit-identical | 0 | 0 |
| Malpedia dumps (`.fnmap` truth) | 57 | 92.645 → 92.648 | 98.552 → 98.552 | −1 | 0 |

**No corpus loses recall.** That is the same gate every change here had to clear, re-checked against today's master rather than against the tree these rules were written on.

Most of what the first version of this table claimed has since been earned by the merged PRs rather than by this branch — master's own AArch64 ELF precision has gone from the 76.676 recorded here to 91.497 in the meantime. What is left on top of that is 3.450 points of precision and 3,645 false positives on the AArch64 corpus, with recall up rather than traded, and 7.821 points on Rust.

Two rows read differently from the first version of this table and it is worth saying why rather than quietly re-titling them:

- **Go is no longer a bit-identical control.** It is −408 false positives at identical TP and FN. Not a rule firing where it should not: Go carries no `.gcc_except_table`, and the FDE-interior rule needs a recovered range start it does not have there. It is the `RESOLVE_TAILCALLS` gate in section 5, whose Go effect was always written up in that section and simply never reached this table.
- **The C/C++ row is a 120-cell MinGW-PE population, not the 260-cell matrix.** On it this branch is byte-for-byte identical to master, which is the correct outcome: `USE_LSDA_LANDING_PADS`, `USE_ELF_FDE_INTERIOR_GAPS` and the `endbr64` interior rule all decode nothing unless lief reports an ELF, so a PE-only C/C++ population is exactly where they should show nothing. The gcc/clang ELF half of the 260-cell matrix was not available to re-measure, so its old figure is withdrawn rather than restated.

---

## PATCH: section 2, the ReadyToRun figure

Old: `recall goes **66.93% → 100.00%**`

New: on `6240b74` the gap scan already reaches most of that image unaided, so the headroom is smaller and the endpoint is the same: **419 → 626 functions**, which is 626 of the 626 starts the exception directory declares — recall 100.00%, and nothing recovered that the directory does not name.

---

## PATCH: section 5, the tailcall gate

Old: `ARM64 Mach-O n=11 and Go n=45: **12 recovered, 458 false positives removed.**`

New, measured on `6240b74` with everything else in this branch on, gate off → gate on:

| corpus | ΔPPV | ΔTPR | ΔFP | ΔTP |
|---|---|---|---|---|
| ARM64 Mach-O, n=11 | +0.201 | +0.092 | −27 | +11 |
| Built C/C++ AArch64 ELF, n=72 | +0.359 | **−0.070** | −580 | **−53** |
| Built Go, n=47 | (see below) | | | |

The AArch64 ELF corpus was not measured for this change originally, and on it the gate is a trade rather than a free win: 580 false positives against 53 real functions. See the note in the review thread — happy to drop the gate if the strict per-change recall rule should win.

---

## PATCH: sections 8 and 9, the per-rule corpus figures

The 260-cell C/C++ figures in both sections are withdrawn for the reason above. The AArch64 and Rust figures are re-measured; see the review thread.

---

## PATCH: `## Two bundled fixture baselines moved`

`aarch64_static` now moves 278 → 276 functions, and the address in question has moved with #311: the branch refuses both `0x40DF34` (Binary Ninja's reading) and `0x40DF30` (where the gap scan puts the same routine since #311 stopped skipping a word that opens on a conditional branch). The FDE at `0x40DDC0` covers both. Same disagreement, one instruction over.

The Mach-O fixture's primary pass moves 256 → 271 — 143 of `LC_FUNCTION_STARTS`' 147 entries, against 128 — with the total unchanged at 274 once the table pass runs.

---

## PATCH: `## Tests`

Replace the counts with the ones from the rebased tree; see the review thread for the exact figures.

---

## PATCH: `## The `Evaluate & Report` gate goes red`

Written against the old base. Worth re-running before the description quotes it.
