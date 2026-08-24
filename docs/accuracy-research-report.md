# Function-detection accuracy: findings, fixes, and what is left

A research report on how well SMDA recovers function start addresses, what was measured, what was
changed, what was measured *worse*, and what remains — with the ceiling for each remaining item.

Companion documents: `docs/accuracy-research-log.md` is the running record with every measurement
in the order it happened; `docs/paper-replication.md` records the origin evaluation's metric
definitions and corpus composition; `tools/bench/README.md` documents the harness.

Every number in this report states the corpus it was measured on, the sample count `n`, and the
optimization filter. A figure without all three is not comparable with anything.

## 1. What was built

A benchmark that runs from a clean checkout: `tools/bench/run.py` measures one or more engines over
one or more ground-truth corpora; `tools/bench/summarize.py` re-aggregates and diffs saved results
without re-running an engine and fails a comparison in which recall dropped;
`tools/bench/build_corpus.py` builds the corpora that no public dataset covers.

It was validated before it was used for anything: SMDA 4.4.1 from PyPI reproduces a previously
recorded five-corpus measurement to three decimals under both optimization filters, with the
imported module's path written into every result file so the tree that ran is not in doubt.

## 2. What the origin evaluation measured, and what reproduces

`docs/paper-replication.md` records the metric definitions, corpus composition, ground-truth
derivation and stated design goals, and `docs/paper-tables.json` holds the paper's own tables as
data. Three of its conclusions are load-bearing for everything below:

- **Precision on these corpora is dominated by one mechanism.** Gap search supplies 45.08% of all
  recovered starts on the ByteWeight corpus at precision 0.933; every other reference count is at
  0.99 or better. On the malware corpus gap search supplies 20.19% at precision 0.786.
- **Over-detection is intentional.** The paper states the trade explicitly: FEP discovery and gap
  analysis are deliberately aggressive, and the resulting false positives are accepted because
  completeness is the priority. A change that raises precision by lowering recall is therefore a
  regression against the design, not an improvement.
- **The ByteWeight ground truth is incomplete in at least one known place.** The paper's own
  labelling study found 249 functions in `client7z` that are referenced by other code and missing
  from the PDB-derived truth. `client7z` remains among the lowest-scoring binaries today.

## 3. Where today's SMDA stands

Filter `all`, arithmetic macro mean, commit `802e627` (SMDA 4.4.7), against SMDA 4.4.1 measured
through the same harness:

| corpus | n | PPV | TPR | F1 | Δ F1 vs 4.4.1 | Δ TPR vs 4.4.1 |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | 68 | 92.041 | 97.872 | 94.713 | +1.378 | +0.245 |
| Bao byteweight msvc10-64 | 68 | 99.080 | 99.838 | 99.454 | +0.109 | +0.109 |
| Bao_Dumped msvc10-32-d | 56 | 91.189 | 97.510 | 94.060 | +1.739 | +0.297 |
| Bao_Dumped msvc10-64-d | 56 | 98.874 | 99.811 | 99.338 | +1.026 | +2.059 |
| Plohmann malpedia itw | 57 | 92.639 | 98.561 | 95.142 | −0.164 | +0.098 |

Recall is up on all five. The single F1 regression is on the malware corpus, and it is a precision
trade — PPV 92.976 → 92.639 with TPR 98.463 → 98.561 — which is the direction the design prefers,
but it is the one place the accumulated work since 4.4.1 has cost something and it is stated rather
than averaged away.

Two of these figures are depressed by a corpus defect rather than by the disassembler: one binary
in the 32-bit ByteWeight set is paired with a ground-truth file describing a different build, worth
1.374 macro F1 there and 1.662 on its dumped variant, and 1.4 points of *recall*. The research log
records the evidence; the harness now reports it before printing any metric.

## 4. Fix landed: a container header in the buffer outranks the byte probes

**The class.** Two places decided what a buffer's bytes *are* by counting byte patterns, while the
buffer's own container header stated the answer outright. `BitnessAnalyzer` reads the share of
`0x48` bytes that introduce a REX.W-compatible opcode; `Disassembler.disassembleBuffer` chose a
backend by counting aligned AArch64 return words. Both are sound heuristics for a headerless dump
and both were being consulted for images that carry headers.

**Evidence, bitness.** Over the three memory-dump corpora, against the bitness each corpus declares:

| corpus | n | probe agrees | probe disagrees |
|---|---|---|---|
| Bao_Dumped msvc10-32-d | 56 | 56 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 56 | 0 |
| Plohmann malpedia itw | 57 | 51 | 6 |

All six disagreements read a 32-bit image as 64-bit. Three carry an intact PE32 header whose COFF
machine field says so.

**Evidence, architecture.** A real ARM64 Mach-O from the bundled Objective-See corpus sits below
the density heuristic's floor:

| `BlueNoroff_469fd8a280e8` | architecture | bitness | functions | status | time |
|---|---|---|---|---|---|
| routed by density | intel | 32 | 1 | timeout | 60.0 s |
| routed by its header | aarch64 | 64 | 6 | ok | 0.0 s |

Locally built ARM64 artifacts reproduce it in the other two containers.

**Result**, memory dumps with the bitness withheld (`--bitness auto`), filter `all`:

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP | ΔFN |
|---|---|---|---|---|---|---|---|
| Bao_Dumped msvc10-32-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Plohmann malpedia itw | 57 | +0.056 | **+0.245** | **+0.155** | +93 | −64 | −93 |

The two headerless corpora are bit-identical — the control that the change fires only where a
header exists — and exactly three of the 57 malware dumps moved. Precision and recall both rose.

**What it deliberately does not do.** A managed PE is still routed to the intel backend: its CLR
metadata is addressed by file offset, which a mapped image no longer has, so naming `cil` from the
header would lose the sample. That carve-out is pinned against a real .NET fixture.

## 5. Measured worse

### A second REX-prefix statistic for the headerless bitness cases

The `0x48` probe's premise — that in 32-bit code the byte after `0x48` is unrelated — fails exactly
when `0x48` is a real `dec eax`, because the instruction that follows it is `mov`, `lea` or
`add imm8`, which are also the opcodes REX.W introduces. The proposed repair was a second statistic
over `0x44`, `0x45`, `0x4C`, `0x4D` — REX bytes selecting the extended register file in 64-bit code,
and `inc`/`dec esp`/`ebp` in 32-bit code, which compilers do not emit.

Measured over 169 dumps, observation floor 64: the new statistic's 32-bit range reaches 0.268 and
its 64-bit range starts at 0.089, so the two overlap across a wide band that contains 17 genuine
64-bit samples. The statistic already in use separates them far better (32-bit p90 0.335, 64-bit
p10 0.908). Any conjunction strong enough to reject the failing 32-bit samples also rejects real
64-bit ones, and misreading a 64-bit image as 32-bit is the worse error. **Rejected.**

