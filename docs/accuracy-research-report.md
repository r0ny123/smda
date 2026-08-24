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

## 6. Fix landed: the exception table's address is declared, not conventional

**The defect.** `locateExceptionHandlerCandidates` found the PE x64 exception table by looking for
a section *named* `.pdata`. The table's address is declared in the image's own exception data
directory; the section name is only the convention MSVC follows. When an image puts the same table
somewhere else, every guaranteed function start in it is lost — and the carve fallback does not
help, because it only runs for an image with no sections at all.

**Where it fires**, with the corpus named for each figure:

| corpus | PEs | with an exception directory | of those, inside `.pdata` | elsewhere |
|---|---|---|---|---|
| ByteWeight msvc10-64 | 68 | 68 | 68 | 0 |
| ByteWeight msvc10-32 | 68 | 0 | – | – |
| malpedia (parseable PEs) | 48 | 3 | 3 | 0 |
| built .NET | 3 | 1 | 0 | **1** (626 entries, in `.data`) |

The frozen corpora never reach this path. The only artifact that does is a .NET ReadyToRun image,
which is why it had not been found: no corpus in the previous evaluation contains one.

**Result** on that image, scored against the 626 `RUNTIME_FUNCTION` starts its own directory
declares, intel backend:

| | detected | TP | FP | FN | PPV | TPR |
|---|---|---|---|---|---|---|
| before | 419 | 419 | 0 | 207 | 100.00 | 66.93 |
| after | 627 | **626** | 1 | **0** | 99.84 | **100.00** |

Recall on declared native functions goes from two thirds to all of them. The single false positive
is one additional function found in a gap, which is the intended over-detection.

## 7. What the harness itself contributes

Three properties were added because a measurement without them has already misled this project:

- **Every row states its corpus, `n` and filter.** Two fake regressions in the project's history
  came from comparing an unfiltered population against a filtered one.
- **The harness refuses to report on a run that did not work.** A sample whose engine errored,
  timed out or returned nothing is counted and listed, and past a threshold aborts the comparison.
  Two identical sets of *errors* otherwise read as "no difference".
- **Corpus integrity is checked before any metric is printed**, with its own control: how many
  samples the check could run on at all. It found a binary paired with the wrong ground truth,
  worth 1.4 points of recall on the corpus that carries it.

`summarize.py --compare` refuses a comparison whose two sides have different `n` and exits non-zero
if recall fell on any config, so the reject criterion is enforced by the tool rather than by
remembering to look.

## 8. Ranked remaining agenda, with ceilings

Each item names what it would be worth and on which corpus, so nothing here is ranked on plausibility alone.

### 1. NativeAOT precision — the worst measured result of any family

PPV **73.40** on a 5,749-function native image, against 92.0 on the 32-bit ByteWeight set and 92.6
on the malware corpus. 2,039 false positives on one binary. Nothing has looked at what they are.
The image carries .NET metadata beside its native code, which is a candidate source no pass
currently consults, and it also carries a full exception table.
**Ceiling:** perfect precision on this cell is +26.6 PPV and +16.1 F1 on it. Whether that
generalises needs more than one NativeAOT artifact, which the builder can produce.

### 2. ReadyToRun native code is not analysed at all under default routing

626 native functions per assembly, recoverable at 99.84 precision once the intel backend sees the
image, and zero recovered as shipped because the CLR header routes it to the CIL backend. This is a
design decision rather than a defect — a CIL report addresses methods by file offset and a native
report by virtual address, so the two cannot be merged without changing the report contract — and
it needs a maintainer's call on the shape. **Ceiling:** the entire precompiled native body of every
ReadyToRun assembly, which is most of what such an assembly ships.

### 3. The CIL backend reports file offsets while every other backend reports virtual addresses

A consequence of the above, and worth stating separately: a managed report's function offsets are
not comparable with `base_addr` plus an RVA. Anything correlating a CIL report with a native one is
comparing two address spaces. **Ceiling:** not an accuracy number; a correctness question for
downstream consumers.

### 4. Three headerless dumps still get their bitness wrong

`geodo`, `hamweq` and `tinba` carry no header, so the fix landed here cannot reach them, and the
obvious second statistic was measured worse. Attacking it needs decoding coverage in both modes
rather than another byte statistic. **Ceiling:** three of 57 samples on one corpus, and only under
`--bitness auto`; nothing at all under the configuration published figures use.

### 5. Corpus hygiene

The mispaired ByteWeight binary is worth **1.374 macro F1 and 1.4 points of recall** on Bao 32, and
**1.662** on its dumped variant, as pure measurement error. Repairing the truth file rather than
excluding the binary would recover a real 472-function sample.

## 9. Per-family results

Every family below is measured on a corpus built for this work; none of them had ever been measured
for function-start accuracy. Filter `all`, arithmetic macro mean.

| family | n | PPV | TPR | F1 | truth functions |
|---|---|---|---|---|---|
| Go (pclntab truth) | 45 | 94.843 | 99.618 | 97.118 | 162,621 |
| .NET (CIL + NativeAOT) | 4 | 93.349 | 99.461 | 95.968 | 7,441 |
| Rust (gnu targets) | 24 | **75.817** | 97.493 | 85.193 | 33,817 |

For comparison, the corpora the previous evaluation used, same settings: ByteWeight 32-bit 92.041 /
97.872, ByteWeight 64-bit 99.080 / 99.838, malware dumps 92.639 / 98.561.

**Go.** Recall is essentially perfect and stripping costs nothing — `-ldflags="-s -w"` scores 94.939
/ 99.668 against the unstripped 94.916 / 99.668 over 21 cells each, which is the design's claim
about pclntab-driven recovery, measured end to end for the first time. Precision, however, depends
on the target architecture with recall held at 100: false positives per truth function are 0.0173
on 386, 0.0367 on amd64 and **0.1340 on arm64**, on identical source. The AArch64 backend
over-detects 3.6× more than the intel one and does so on every program and both operating systems.
99.6% of those extra detections are interior to a real function's span.

**.NET.** Managed CIL is exact — 100/100/100 on 564 methods in each of three publish modes, because
metadata enumerates every body. NativeAOT is native code and scores 73.40 precision, the lowest
figure anywhere here; at least a third of that is a truth gap rather than over-detection (see the
research log), leaving roughly 1,337 unexplained false positives on one binary.

**Rust.** The lowest precision of any family whose truth is complete, and the truth *is* complete —
`.eh_frame` names fewer ranges than the symbol table and their union adds nothing. 95.3% of its
false positives are interior splits, and one byte pattern accounts for half of the reference-less
ones: `push r15; push r14` seeded four bytes inside functions that open with
`push rbp; mov rbp, rsp`.

