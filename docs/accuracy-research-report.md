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

Five corpora came with it, none of which existed for this project before:

| corpus | cells | truth functions | ground truth |
|---|---|---|---|
| C/C++ | 260 | 203,351 | symbol table of the unstripped link |
| Go | 45 | 162,621 | `go tool nm` over the unstripped build |
| Rust | 24 | 33,817 | symbol table of the unstripped link |
| .NET | 4 | 7,441 | assembly metadata; symbols for the native image |
| ARM64 Mach-O | 11 | 2,753 | `LC_FUNCTION_STARTS`, plus the stub entries the image declares |

The C/C++ matrix is ten programs — sqlite3, lua, zlib, xxhash, cjson, lz4, brotli, googletest,
tinyxml2, miniz — across gcc, clang and both MinGW targets, at `O0` through `O3`, `Os`, static and
no-PIE. Every builder writes a manifest naming each cell it attempted and why the failures failed,
because 253 of 260 reads as a complete run everywhere except in the manifest. The ARM64 Mach-O
corpus needs no toolchain and no download: it decodes fixtures the repository already carries.

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
- **A table cell that averaged an incomplete run says so.** The per-sample status is written into
  every result file, and the replication table marks a cell holding one, names the sample and counts
  it on its control line. Ghidra does not finish the largest ByteWeight x64 binary inside the
  analysis budget; that sample scores 0 and the geometric mean an optimization-level row uses
  carries the zero into the cell, which without the mark reads as an engine that found nothing on 17
  binaries rather than one that did not answer on one.

`summarize.py --compare` refuses a comparison whose two sides have different `n` and exits non-zero
if recall fell on any config, so the reject criterion is enforced by the tool rather than by
remembering to look.

## 8. Ranked remaining agenda, with ceilings

Each item names what it would be worth and on which corpus, so nothing here is ranked on
plausibility alone. The first two have a mechanism established and a candidate change measured
against it; the rest have a measurement and no fix yet.

### 1. AArch64 recall on code with no symbol oracle

Micro recall **90.229** on eleven real ARM64 Mach-O binaries, against 99.838 on the 64-bit ByteWeight
set — the largest architecture gap measured anywhere in this work. It is invisible on the Go family,
where the pclntab names every function and recall is essentially perfect, so it took a corpus whose
truth comes from a linker to see it: `LC_FUNCTION_STARTS` names the functions whether or not a symbol
table survives.

The gap is a function of size. Every sample with fewer than 90 truth functions is recovered
completely; every larger one is not — 157 missed of 1,087, 55 of 556, 30 of 274, 19 of 481.

Classifying every miss on one binary splits them cleanly. Sixteen of thirty are **swallowed by the
function before them**: `0x100008900` absorbs eight declared functions spaced 0x50 apart, and the
merge point is a `bl` to a callee that does not return, so the caller has no `ret` and decoding runs
on into the next function. The AArch64 backend already has a rule for that shape — it checks for a
`bl` as the previous instruction and asks for a fall-through boundary — and its predicate declines
here, which makes this a rule to tighten rather than a feature to add. Eight more are runs of
**one-instruction `b` veneers** that are never analysed at all, and the split within a run is not
random: of twelve adjacent declared veneers, the eight branching to two particular targets are
missed and the four branching elsewhere are found.

**Ceiling:** closing the merges alone is roughly half the gap, and the whole gap is +9.6 micro recall
on this corpus, which would put AArch64 within a point of intel. How much one change reaches is the
next thing to measure, not to assert.

### 2. Rust/ELF: a seeded prologue four bytes inside a function

Rust is the worst-scoring family measured here — PPV **75.817** on n=24 with 33,817 truth functions,
against 92.0 on the 32-bit ByteWeight set. It is not a truth defect: the same `.eh_frame` cross-check
that exonerated NativeAOT found the Rust truth complete.

The mechanism is a single byte pattern. Of 150 false positives that no reference points at and that
came in as initial candidates, **123 begin `41 57`** (`push r15`). All 123 are preceded by
`55 48 89 e5` (`push rbp; mov rbp, rsp`), and **120 of 123 (97.6%)** have a real function start
exactly four bytes earlier: the prologue scanner matched the second half of a frame setup it had
already matched the first half of.

Removing the `41 57` seed outright is rejected — a counterfactual over 18 binaries attributes 15
unique true positives to it, and recall may not fall. The narrower rule, *do not seed a prologue
match that begins exactly where another seeded prologue match ends*, drops **33 to 123 false
positives per Rust ELF cell and zero true positives**, and is inert on all eight mingw PE cells and
on both MSVC corpora, where the seed contributes neither a true nor a false positive.
**Ceiling:** the 400 unique false positives the seed contributes across the Rust set, worth roughly
+1.2 PPV on the family; the change itself is scoped narrower than that and is next to land.

### 3. Go/AArch64: a tailcall path the shared engine gates and this backend does not

Go arm64 produces **0.1340 false positives per truth function** against 0.0367 on amd64 and 0.0173
on 386 — a 3.6× rate on the same source programs. **170 of 246** false positives on
`hello_linux-arm64_default` are tailcall candidates, a source that contributes 0 on every intel
cell, and their first instructions are `sub`, `adrp`, `ldr`: mid-function shapes.

`SmdaConfig.RESOLVE_TAILCALLS` is `False` by default and `RecursiveDisassembler` honours it on both
of its tailcall paths. The AArch64 backend calls `addTailcallCandidate` from two sites of its own and
neither consults the flag; the AArch64 candidate manager additionally records a capped call
reference for the seed, manufacturing the evidence that makes it score highly — something the shared
implementation never does. Go is exactly the code that makes this expensive: it branches backwards
within a function constantly and its runtime calls are `bl` followed by more of the same function.
**Ceiling:** roughly 2,907 false positives across the six arm64 cells, taking the rate from 0.134
towards 0.045 and PPV on those cells from 85.6 towards about 95, with recall untouched — 100.0% of
Go true positives on every architecture come from the pclntab, and no other candidate source
contributes a single one. The frozen corpora have no AArch64 member, so the bundled AArch64
fixtures are the only local regression check, and they hold 1 and 0 tailcall-only candidates.

### 4. NativeAOT precision — the worst single cell of any family

PPV **73.40** on a 5,749-function native image, 2,039 false positives on one binary. Part of that is
truth: `.eh_frame` in the same image declares 6,513 ranges against the symbol table's 5,749, and
**702 of the 2,039 apparent false positives are FDE-declared**, so scoring against the union gives
82.55 / 95.09. That leaves 1,337 genuine false positives and, in the other direction, **326 FDE
ranges not reported at all**. The image carries .NET metadata beside its native code, which no
candidate pass consults, and a full exception table.
**Ceiling:** +9.2 PPV from the truth correction alone, which is bookkeeping rather than a fix; the
remaining 1,337 are worth about +17 PPV on this cell and need more than one NativeAOT artifact
before a mechanism can be claimed.

### 5. ReadyToRun native code is not analysed at all under default routing

626 native functions per assembly, recoverable at 99.84 precision once the intel backend sees the
image, and zero recovered as shipped because the CLR header routes it to the CIL backend. This is a
design decision rather than a defect — a CIL report addresses methods by file offset and a native
report by virtual address, so the two cannot be merged without changing the report contract — and
it needs a maintainer's call on the shape. **Ceiling:** the entire precompiled native body of every
ReadyToRun assembly, which is most of what such an assembly ships.

### 6. The CIL backend reports file offsets while every other backend reports virtual addresses

A consequence of the above, and worth stating separately: a managed report's function offsets are
not comparable with `base_addr` plus an RVA. Anything correlating a CIL report with a native one is
comparing two address spaces. **Ceiling:** not an accuracy number; a correctness question for
downstream consumers.

### 7. Three headerless dumps still get their bitness wrong

`geodo`, `hamweq` and `tinba` carry no header, so the fix landed in section 4 cannot reach them, and
the second statistic tried instead was measured worse (section 5). Attacking it needs decoding coverage in
both modes rather than another byte statistic. **Ceiling:** three of 57 samples on one corpus, and
only under `--bitness auto`; nothing at all under the configuration published figures use.

### 8. Corpus hygiene

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
| ARM64 Mach-O (linker truth) | 11 | 93.986 | **95.616** | 94.381 | 2,753 |

For comparison, the corpora the previous evaluation used, same settings: ByteWeight 32-bit
(n=68) 92.041 / 97.872, ByteWeight 64-bit (n=68) 99.080 / 99.838, malware dumps (n=57)
92.639 / 98.561.

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

**ARM64 Mach-O.** The only AArch64 corpus here whose truth comes from a linker rather than one
compiler's metadata: eleven real Mach-O binaries, each declaring its own function starts in
`LC_FUNCTION_STARTS`. The finding is recall. Every sample under 90 truth functions is recovered
completely and every sample above it is not — 157 missed of 1,087 on the largest, 55 of 556, 30 of
274 — and micro recall is **90.229** against 99.838 on the 64-bit ByteWeight set. That is the
largest architecture gap measured anywhere in this work, and the opposite of what the Go family
suggested, where recall is essentially perfect because the pclntab names every function and SMDA
reads it. Take the symbol oracle away and AArch64 recovery falls a long way behind intel recovery on
comparable code.

The first measurement of this corpus said PPV 39.901, and it was the corpus rather than the
disassembler. Section 11 records what was wrong and how it was found; the short version is that
Mach-O stub sections are the counterpart of an ELF PLT and `LC_FUNCTION_STARTS` does not name them.

**Rust.** The lowest precision of any family whose truth is complete, and the truth *is* complete —
`.eh_frame` names fewer ranges than the symbol table and their union adds nothing. 95.3% of its
false positives are interior splits, and one byte pattern accounts for half of the reference-less
ones: `push r15; push r14` seeded four bytes inside functions that open with
`push rbp; mov rbp, rsp`.

## 10. What is not covered, and why

- **The Andriesse corpus is absent.** Its SPEC CPU2006 component is licence-restricted, so the
  origin evaluation's `GA` rows cannot be reproduced. The corpora built here stand in for the
  cross-check it would have given, and are named as a substitute rather than an equivalent.
- **IDA Pro and nucleus are not re-measured.** No licence is available. Their columns come from the
  origin evaluation's own per-binary result files and are labelled `(paper)` in the table itself,
  not only in prose.
- **The Go cgo axis is host-only.** Cross-compiling cgo needs a C toolchain for the target, so the
  known Mach-O chained-fixup gap — a pre-1.18 pclntab in an externally linked Mach-O stores
  pointer-wide entry addresses that Apple's linker writes as chained fixups rather than addresses —
  cannot be reproduced from a Linux host. It remains open and is not measured here.
- **A .NET single-file publish is not scoreable.** The managed assembly is embedded in the apphost
  bundle and nothing in this toolchain unpacks it. That is itself the finding.
- **Delphi is not covered.** No Delphi toolchain is available here, so the family stays on the
  agenda with no measurement behind it. The bundled Delphi fixtures exercise the symbol providers
  but not function-start accuracy.

## 11. Method notes worth keeping

Three habits earned their place during this work and are worth stating, because each of them
changed a conclusion:

**A zero-difference result needs a positive control in the same output.** The exception-table change
was claimed inert on the bundled fixtures. Checking only that both runs produced functions would
have proved nothing; checking that the directory and the section walk read the *same entry counts*
— 48, 7 and 1,666 — proved it.

**Ask whether the truth is right before attributing a low score to the tool.** NativeAOT's 73.40
precision looked like the worst defect found. A second independent declaration in the same image —
`.eh_frame` — named 764 ranges the symbol table did not, and 702 of the "false positives" were
among them. Running the same check on Rust, where it would have been equally convenient to blame the
corpus, found the truth complete and the over-detection real.

The ARM64 Mach-O corpus made the same point at four times the size. Its first measurement was
PPV **39.901**, which would have been the headline finding of this entire report. Histogramming the
false positives by owning section answered it in one line: they were in `__stubs` and `__objc_stubs`,
the Mach-O counterpart of an ELF PLT, which this harness' own convention counts as functions and
which `LC_FUNCTION_STARTS` does not name. Folding in the entries the image itself declares — an
`S_SYMBOL_STUBS` section carries its stride in `reserved2`, exactly as an ELF section carries its
entry size — and declining to score the sections nothing declares moved the same measurement to
**93.986**. A 54-point error, in the direction of a dramatic result, from a truth set that looked
authoritative because a linker wrote it.

**Histogram the failures by the source that produced them.** Every conclusion about *where* to fix
something came from tagging each recovered address with the candidate source that seeded it. It
turned "Rust precision is bad" into "one seeded byte pattern, four bytes inside a function", and
"AArch64 is worse than intel" into "a tailcall path the shared engine gates behind a flag and this
backend does not".

