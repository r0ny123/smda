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

"Runs from a clean checkout" is checked rather than asserted: a fresh clone of this branch, an empty
ground-truth root, and the clone's own `src` on `PYTHONPATH` builds the ARM64 Mach-O corpus and
measures it to the same figures this report prints — 94.008 / 96.345 / 94.778 over 2,753 truth
functions, with the same fixture skipped for the same recorded reason. That corpus is the one this
can be shown on end to end because it needs no toolchain and no download; the others need their
compilers and go through the same code path.

Five corpora came with it, none of which existed for this project before:

| corpus | cells | truth functions | ground truth |
|---|---|---|---|
| C/C++ | 260 | 213,441 | symbol table of the unstripped link, plus PLT entries |
| Go | 45 | 162,621 | `go tool nm` over the unstripped build |
| Rust | 24 | 33,817 | symbol table of the unstripped link, plus PLT entries |
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

## 3. The replication, and what it validates

All seven of the origin evaluation's rows now carry a measured Ghidra column beside the recorded one,
aggregated the way that evaluation aggregates them — geometric mean per optimization level for rows
whose binaries carry an `O0`-`O3` label, arithmetic mean for the rest. TPR / PPV:

| row | opt | n | ghidra 9.1.2 (recorded) | ghidra 12.1.3 (measured) | smda 1.2.5 (recorded) | smda 4.4.7 (measured) |
|---|---|---|---|---|---|---|
| ByteWeight msvc10-32 | O1 | 17 | 0.804 / 0.952 | 0.817 / 0.953 | 0.992 / 0.935 | 0.994 / 0.938 |
| ByteWeight msvc10-32 | O2 | 17 | 0.809 / 0.950 | 0.822 / 0.951 | 0.992 / 0.927 | 0.994 / 0.932 |
| ByteWeight msvc10-64 | O1 | 17 | 0.675 / 0.999 | incomplete | 0.975 / 0.983 | 0.998 / 0.993 |
| ByteWeight msvc10-64 | O2 | 17 | 0.703 / 0.999 | 0.809 / 0.999 | 0.972 / 0.981 | 0.998 / 0.993 |
| ByteWeight* msvc10-32 | – | 56 | 0.775 / 0.953 | 0.777 / 0.953 | 0.967 / 0.910 | 0.975 / 0.912 |
| ByteWeight* msvc10-64 | – | 56 | 0.653 / 0.999 | 0.663 / 0.999 | 0.932 / 0.985 | 0.998 / 0.989 |
| Malpedia57 | – | 57 | 0.819 / 0.940 | 0.849 / 0.961 | 0.976 / 0.935 | 0.986 / 0.926 |

The IDA and nucleus columns are in the tool's own output and omitted here; they are the origin
evaluation's figures, labelled `(paper)` in the table itself because no licence is available to
re-run them. The `O1` 64-bit Ghidra cell holds one binary the engine did not finish inside the
analysis budget, and is marked and named rather than printed.

**This validates the harness against a second engine.** Ghidra 12.1.3 lands within 0.002 to 0.013 of
the figures recorded for Ghidra 9.1.2 on four of the six comparable cells — a different tool, a
different decade, the same metric implementation reproducing published numbers. The earlier check
showed SMDA 4.4.1 reproducing a recorded SMDA measurement; this one shows the metric is not tuned to
one engine's output shape.

It also says something about the two tools. Ghidra has moved very little on these corpora in five
years: +0.013 recall at most on a ByteWeight cell, and +0.030 on the malware corpus, its one real
improvement. SMDA has moved a great deal, and almost all of it on the hardest row — **the dumped
64-bit set goes from 0.932 recall to 0.998**, where the unpacked sets were already near their
ceiling. On that row the gap between the two tools is now 0.663 against 0.998.

## 4. Where today's SMDA stands

This is the **baseline** these corpora were at before any change on this branch — section 17 has the
end state. Filter `all`, arithmetic macro mean, commit `802e627` (SMDA 4.4.7), against SMDA 4.4.1
measured through the same harness:

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

## 5. Fix landed: a container header in the buffer outranks the byte probes

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

## 6. Measured worse, and measured not worth doing

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

### Every byte-level test for what an `endbr64` marks

`endbr64` is a CET landing pad, and the prologue scan seeds every one. It marks every indirect-branch
target rather than every function: 14,986 of the 69,971 in the C/C++ corpus' `.text` sections — 21.4%
— are not at a declared function start, and on the worst cell 1,085 of 1,095 false positives begin
with one.

The proposed rule was to seed one only where the bytes before it end a function or pad between
functions. Cross-tabulated over all 140 ELF cells: how many spurious pads each variant refuses,
against how many declared starts it refuses with them.

| variant | refuses spurious | costs declared | ratio |
|---|---|---|---|
| padding only (`int3`, `nop` forms) | 13,689 | 15,737 | 0.87 |
| 16-byte aligned | 13,319 | 14,149 | 0.94 |
| 16-aligned **and** (`ret` or padding) | 14,027 | 15,727 | 0.89 |
| `ret` or padding | 13,009 | 3,418 | 3.81 |
| 16-aligned **or** (`ret` or padding) | 12,301 | 1,840 | 6.69 |

The best still refuses 1,840 real function starts. **Rejected**, all five. The reason is structural: a
jump-table case body commonly ends in `jmp <shared epilogue>` with the next case's pad after it, so a
preceding terminator describes an interior pad as accurately as a function entry; and a function that
follows a call which does not return has no terminator before it at all. The two are not separable by
the bytes in front of them.

### Refusing a reference-less `endbr64`

If the bytes cannot decide it, perhaps the references can. On the worst cell the split looked
decisive: **none** of its 1,095 false positives is referenced by any recovered code, against 57.9% of
its true positives. Measured over four cells spanning toolchains and programs, the rule removes 1,085
false positives and **1,214 true positives** — more real functions than spurious ones. **Rejected.**

googletest is a static test framework linked without tests, so most of its code is never called from
inside the binary and a real function there is as reference-less as a spurious pad. sqlite3 makes the
point louder: 653 real functions with no internal caller and no false positives to trade for them.

Two rejected repairs on the same finding, from opposite directions, both because the discriminator
was assumed rather than measured. Section 13 records where it has to come from instead.

### Gating both AArch64 tailcall sites together

The AArch64 backend seeds tailcall candidates from two sites of its own and neither consults
`SmdaConfig.RESOLVE_TAILCALLS`, which is `False` by default and which the shared engine honours on
both of its own tailcall paths. On Go arm64 that source produces 170 of 246 false positives per
binary and contributes none on any intel cell, so making the backend honour the flag is the obvious
consistency repair.

Measured on the ARM64 Mach-O corpus with the boundary rule's cut kept and only the seeding gated:
PPV 94.008 → 94.684, F1 94.778 → 95.203, and macro **TPR 96.345 → 96.314**. A recall drop on any
corpus is the reject criterion, so this is a **reject** — and the per-sample view says why it should
be: the two sites together cost 33 false positives and earn 7 true positives, and those seven
functions on two binaries are reached by nothing else.

On the Go corpus the same gate removes **640 false positives and loses none**, recall identical to
the digit, and the 386 and amd64 cells are bit-identical while every one of the 640 comes from an
arm64 cell. So the trade across both corpora is 673 false positives against 7 true positives.

Gating both together is what made this look like one decision. Separating the two sites — section 10
— shows they do opposite things: the `bl` fall-through site is strictly worse than not having it and
is now gated, and the branch-target site earns all 7 of those true positives and is left alone. The
net that reads as a small recall drop is those 7 losses and 12 gains partly cancelling. Section 12
carries the branch-target site as the open item it still is.

### Not worth changing: the `endbr64`-then-prologue interior seed

A CET-enabled function opens `endbr64; push rbp; mov rbp, rsp`, and the second half is on the seeded
list, so the scan books a candidate four bytes inside every such function. The byte statistic is as
clean as any here: **19,536** such adjacencies in the C/C++ corpus, the `endbr64` a declared function
start in all 19,536 and the follower a declared start in none.

It changes nothing. Over five binaries holding 9,512 of those adjacencies, **6** of 3,332 false
positives sit at `endbr64 + 4`: the recursive analysis reaches the function at the `endbr64` first
and claims those bytes as code, so the interior candidate is discarded before it can be reported.
Left alone.

The first attempt to measure this returned a clean zero on six binaries, five of which contained
none of the pattern — a zero with no positive control beside it, behind a perfect byte statistic that
made it look like confirmation. Section 16 has the habit that caught it.

## 7. Fix landed: the exception table's address is declared, not conventional

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

## 8. Fix landed: a call that does not return is a function boundary

**The defect.** On AArch64 a callee that never returns leaves its caller with no `ret`, so decoding
runs straight out of one function and into the next. The backend has a rule for exactly that shape —
after a `bl`, ask whether the fall-through address starts a function — and it accepts only three
answers: the address is already a candidate, or NOP padding was skipped and what follows is a
candidate or is 16-aligned. With no padding and nothing having seeded the next entry, all three
decline and the two functions merge. On one 274-function image that cost fifteen functions in two
runs.

**Why the existing one-word test cannot be widened.** The word at the merge point is
`sub sp, sp, #imm`, and `is_function_prologue` deliberately does not recognise it: a bare stack
allocation is as common inside a function as at its head, the same reason the intel side scores
`sub rsp, imm8` but never seeds on it.

**The rule.** A stack allocation *followed within three instructions by the frame record*
`stp x29, x30, [sp, #imm]` — the frame pointer and link register stored into the frame that
allocation just made. Nothing mid-function re-saves the incoming link register into a frame it has
only now created. Read as two words instead of one the shape is not ambiguous, and it is consulted
only at a `bl` fall-through, never scanned across an image.

**Counterfactual, before the change was wired in:**

| population | `bl` instructions | predicate fires | declared start | not declared |
|---|---|---|---|---|
| ARM64 Mach-O, 11 samples | 14,273 | 47 | **47** | **0** |
| Go arm64, 12 cells | 55,964 | 0 | 0 | 0 |

Go is the inertness control, not a second confirmation: its callees return and its prologue is the
pre-indexed form, so the rule cannot fire there and cannot cost anything.

**Result**, ARM64 Mach-O corpus, n=11, filter `all`, arithmetic macro mean:

| | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| before | 93.986 | 95.616 | 94.381 | 2,484 | 263 | 269 |
| after | 94.008 | **96.345** | 94.778 | **2,512** | **263** | **241** |

Twenty-eight functions recovered and **not one false positive added** — the false-positive count is
identical either side, which is the control that the rule fires only where it was measured to.

Against every other corpus in the harness the change is bit-identical: both ByteWeight sets, both
dumped variants, the malware dumps, Go, Rust and .NET, nine configs compared in total. Seven of the
eight are intel, and the eighth — Go on arm64 — is the population where the static counterfactual
said the predicate fires zero times in 55,964 `bl` instructions. The measured run agrees with the
static count exactly.

## 9. Fix landed: a prologue that opens where another prologue ends

**The defect.** A function's opening instructions are its prologue, so the address just past one is
inside that function's body. The whole-image prologue scan did not check, and one seeded pattern
lands there constantly: clang opens a frame with `push rbp; mov rbp, rsp` and follows it with the
callee-saved run `push r15; push r14`, which is on the seeded list too. Matched four bytes in, it
books the body of a function the scan had already found.

**Evidence.** Of 150 false positives on the Rust corpus that no reference points at and that arrived
as initial candidates, **123 begin `41 57`**, all 123 are preceded by `55 48 89 e5`, and **120 of the
123 (97.6%)** have a real function start exactly four bytes earlier.

**Why not remove the seed.** A counterfactual over 18 binaries attributes 15 unique true positives to
it. A recall drop is the reject criterion, so the repair has to keep the seed and refuse only the
matches that are provably interior — and only when the earlier address is already a candidate, so a
byte coincidence cannot trigger it. It generalises the hotpatch adjustment beside it, which refuses a
bare `push ebp; mov ebp, esp` two bytes into a `mov edi, edi` pad on the same reasoning. No function
consists solely of its own prologue, which is what makes the rule safe.

**Result**, filter `all`, arithmetic macro mean, against the same tree without it:

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|---|
| Rust (gnu targets) | 24 | **+3.134** | +0.000 | **+1.992** | 0 | **−790** |
| .NET (CIL + NativeAOT) | 4 | +0.240 | +0.000 | +0.156 | 0 | −99 |
| C/C++ (gcc, clang, mingw) | 260 | +0.034 | +0.000 | +0.017 | 0 | −22 |
| malware dumps | 57 | +0.003 | +0.000 | +0.002 | 0 | −1 |
| Go, ARM64 Mach-O, and all four ByteWeight sets | 45/11/68/68/56/56 | 0 | 0 | 0 | 0 | 0 |

912 false positives removed across ten corpora and **not one true positive anywhere**. Rust goes from
the lowest precision measured here to 78.951, and the C/C++ corpus barely moves despite being built
by the same clang — the pattern needs two prologues back to back, which Rust's code generation
produces far more often than C or C++ does.

**It also repairs control-flow graphs, which this metric cannot see.** A spurious candidate seeded
four bytes inside a function does not only add a false positive: the real function stops at it and is
reported as a single block. On two Rust cells, base against PR: 123 addresses dropped and **none of
them declared**, 0 gained, **119 functions grew and every one of them from a single block** — the
largest going 1 → 327 — and **nothing shrank**. A function truncated to its first block still has the
right start, so the start-based metric scores it as a hit either way.

## 10. Fix landed: after a call, the cut recovers the function, not a seed

**The defect.** The AArch64 backend seeds tailcall candidates from two sites of its own, and neither
consults `SmdaConfig.RESOLVE_TAILCALLS` — `False` by default, and honoured by the shared engine on
both of its own tailcall paths. Gating both together loses recall, which reads as "the source is
worth keeping". Gating them separately shows they do opposite things.

**The `bl` fall-through site is strictly worse than not having it.** The same code path already cuts
the caller at the boundary, and that cut is what recovers the next function: once the caller ends
there, the ordinary candidate machinery reaches the entry with better extents than a tailcall-flagged
candidate does. Seeding one as well costs precision *and* recall.

| corpus | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|
| ARM64 Mach-O, n=11 | +0.209 | **+0.101** | +0.158 | **+12** | **−28** |
| Built Go, n=45 | +0.268 | +0.000 | +0.148 | 0 | **−430** |

Every one of the 430 comes from an arm64 cell; Go's 386 and amd64 cells are bit-identical, which is
the control that the change reaches only what it was meant to.

**The branch-target site is deliberately left alone.** Gating it costs 7 true positives on the Mach-O
corpus — functions on two binaries nothing else reaches — and a recall drop on any corpus is the
reject criterion. Gating both hid this: those 7 losses and these 12 gains partly cancel into a small
net recall drop that reads as a reason to reject the whole idea. Section 6 records that rejection and
section 13 carries the branch-target site as an open item.

## 11. Fix landed: a candidate snapshot taken before analysis hides half the functions

**The defect.** The AArch64 gap sweep refuses a straight-line run whose unconditional branch lands in
already-decoded code that is not a function-start candidate — the shape of a mid-function tail rather
than a new function. The set it consults, `getFunctionStartCandidates()`, is a **snapshot taken
before analysis begins**: `_buildQueue` fills it once from the discovery passes, and gap analysis
never adds to it. On one image it holds **211 addresses while 261 functions are recovered**, so 50
recovered functions are invisible to it and a branch to any of them reads as a branch into somebody
else's interior.

**How it showed up.** Twelve adjacent one-instruction branch veneers on one image, every one declared
by the linker, and only four recovered. The four that were recovered branch to functions the prologue
scan seeded; the eight that were not branch to two functions **gap analysis discovered**. The
correlation first recorded — that a veneer survives when its target opens with a recognised prologue —
was a symptom of which pass found the target, not of what the target looks like.

| veneer target | in `code_map` | is a recovered function | in the snapshot |
|---|---|---|---|
| `0x10000642c`, `0x10000643c` | yes | **yes** | **no** |
| `0x100006400`, `0x100007984`, `0x100007aec` | yes | yes | yes |

**The rule.** Ask the live function set as well. A branch to something already recovered as a function
is not a branch into an interior, whichever pass recovered it.

**The class, swept.** The set has one definition, so its six readers can be enumerated rather than
guessed at. Three are already correct — the two `X86Backend` jump classifiers and
`AArch64Backend._analyzeUncondBranch` all test `disassembly.functions` first and fall back to the
snapshot only for addresses that are not yet functions, which is what the snapshot is good for. Two
are the same defect and are corrected with it: `_callFallthroughFunctionStart`, whose two tests have
no live-set check in front of them, and `_isLikelyInteriorBtiCandidate`, whose condition is identical
to the one fixed here. Both are **inert on every corpus available** — the figures below are the same
with and without them — and are corrected because they are the same defect and the correction can
only stop the code suppressing at an address already recovered as a function, which cannot lose one.

**Result**, ARM64 Mach-O, n=11:

| | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| before | 94.217 | 96.446 | 94.936 | 2,524 | 235 | 229 |
| after | 94.220 | **96.711** | 95.074 | **2,532** | **235** | **221** |

Eight functions recovered with the false-positive count identical, and on `osx.frostyferret` the
veneer run goes from 5 of 13 to **13 of 13**. Go and both ByteWeight sets are bit-identical.

## 12. What the harness itself contributes

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

## 13. Ranked remaining agenda, with ceilings

Each item names what it would be worth and on which corpus, so nothing here is ranked on
plausibility alone. The first two have a mechanism established and a candidate change measured
against it; the rest have a measurement and no fix yet.

### 1. AArch64 precision, and the recall gap that is not one

**This item was ranked on the wrong axis, and section 21's corpus is what says so.** It read micro
recall **91.246** on eleven real ARM64 Mach-O binaries against 99.745 on the 64-bit ByteWeight set and
called that the largest architecture gap in this work. Those are two different populations — real
macOS images with linker truth against MSVC-built open-source PEs — and holding source, programs,
variants and compiler family constant says something else. Over 63 matched cells:

| | macro PPV | macro TPR |
|---|---|---|
| `gcc-x64` | 94.684 | 96.899 |
| `gcc-arm64` | **77.594** | 95.364 |

Recall differs by **1.5** points and precision by **17.1**. Pooled over the same 63 cells, micro
recall is **97.750** on AArch64 against **96.170** on x86 — AArch64 is *ahead* — while micro precision
is 81.559 against 90.464. The architecture gap is a precision gap. What follows below
is the Mach-O recall analysis as it was recorded, which remains true of that corpus and is what the
fixes in sections 8 and 11 were built from; it is no longer evidence that AArch64 recall is
structurally behind intel's.

It is invisible on the Go family, where the pclntab names every
function and recall is essentially perfect, so it took a corpus whose truth comes from a linker to
see it at all.

The gap is a function of size: every sample with fewer than 90 truth functions is recovered
completely, and every larger one is not.

Classifying every miss on one binary split them cleanly, and half of them are now fixed. Sixteen of
thirty were **swallowed by the function before them** — that is what section 8 addresses, and fifteen
of those sixteen are recovered. Eight more were runs of **one-instruction `b` veneers** never analysed at all; **section 11 fixes
that half** — the gap sweep was refusing them because their targets were discovered by a pass whose
results a pre-analysis snapshot does not carry.

**Ceiling:** with sections 8 and 11 landed, 23 of the 30 misses on that binary are recovered and
7 remain. Across the corpus the remaining gap is worth about +8 micro recall, which would put AArch64
within a point and a half of intel; what is left has no single mechanism identified yet.

### 2. `endbr64` is seeded as a function start and marks every indirect-branch target

The worst cell in the 260-binary C/C++ matrix reports 2,284 functions where 1,194 exist — PPV 52.06
at TPR 99.58 — and **1,085 of its 1,095 false positives begin with `endbr64`**. None of them carries
a symbol and none is declared by the binary's own `.eh_frame`, which corroborates the truth to within
one range, so the over-detection is real.

`endbr64` is a CET landing pad and the prologue scan seeds every one it finds. A landing pad marks
every indirect-branch target, not every function: under `-fcf-protection` gcc emits one at each
jump-table destination, so a `switch` produces a dozen of them inside a single function body.

A byte scan across all 140 ELF cells finds **69,971 `endbr64` occurrences in `.text`, of which 14,986
(21.4%) are not at a declared function start** — 12,564 from gcc and 2,422 from clang. The corpus
holds 26,702 false positives in total, so this one pattern bounds more than half of them.

**Closed.** Two rules built on what the image declares — sections 20 and 23 — take this class to
nothing. Measured over six representative C/C++ cells, with both options turned off to isolate what
they contribute:

| configuration | false positives | of which `endbr64`-headed | true positives |
|---|---|---|---|
| this branch with both options off | 1,210 | **822** | 5,695 |
| as shipped, `USE_LSDA_LANDING_PADS` on | 119 | **0** | 5,717 |
| plus `USE_ELF_FDE_INTERIOR_GAPS` | 80 | **0** | 5,718 |

Not one `endbr64`-headed false positive survives either rule, and true positives rise rather than
fall at each step. The worst cell in the table above, `googletest_gcc-x64_O2`, goes from 858 false
positives to 63. What is left is 80 addresses that have nothing to do with this pattern, so the
ceiling this item named is reached rather than approached.

The obvious repair — seed an `endbr64` only where the bytes before it end a function or pad between
functions — was measured and **rejected**; section 6 records all five variants tried and what each
cost. The best of them refuses 12,301 spurious pads and 1,840 real function starts with them, and a
recall drop is the reject criterion.

The bytes in front of the pad cannot decide this, structurally rather than by tuning: a jump-table
case body commonly ends in `jmp <shared epilogue>` with the next case's pad after it, so a preceding
terminator describes both roles, and a function following a call that does not return has no
terminator before it at all. What separates them is what the address is *used as* — a landing pad is
the target of an indirect branch from inside a function, a function entry is the target of a call —
and SMDA resolves jump tables during analysis. That suggested a filter after analysis, on candidates
the jump-table pass has claimed, rather than one on bytes before it.

**That measurement has now been made, and it refutes the filter.** Over the 140 ELF cells, of the
5,076 false positives that open with `endbr64`, the jump-table pass resolved **zero** — against
46,411 targets resolved in the same run, with the same intersection catching two true positives, so
the zero carries its controls.

It is zero *by construction*, which is the useful part. A resolved target becomes a block of the
enclosing function and never a function of its own, so the resolved set and the spurious set are
disjoint by definition: the spurious pads are exactly the case bodies the pass **failed** to resolve.
No filter on what the pass claimed can reach them. The shape agrees — all 5,076 sit strictly inside a
real function, shattering 1,846 of them, and 121 of those carry eight or more apiece, which is an
unresolved dispatch rather than scattered bad guesses.

**Ceiling and direction, re-ranked.** The lever is jump-table resolution itself, not a filter. Each
case body the pass learns to resolve stops being a false positive *and* stops splitting a real
function in the same move, and cannot cost recall, because the address stays in the report as a
block. Worth roughly 5 points of precision on this corpus; and being unable to fail the
no-recall-drop gate, it is the first item to pick up rather than the second.

### 3. Rust precision after the interior-prologue fix

Section 9 removed 790 of the Rust corpus' false positives and took it from PPV 75.817 to **78.951**,
which is still the lowest of any family here. 95.3% of what remains are interior splits, so the class
is the same and the byte pattern is not.

That histogram has since been taken, and it moves this item off the seeding scan entirely. Attributing
all 8,678 surviving false positives over the 24 cells to the pass that first books each address:
**`addGapCandidate` 6,093 (70.2%)**, `addReferenceCandidate` 2,215 (25.5%), `addPrologueCandidate`
**370 (4.3%)**. The prologue scan is the only source a byte pattern can reach, so a second pattern is
bounded at 370 of 8,678 however well chosen.

**Ceiling:** matching the 92.0 the 32-bit ByteWeight set scores is another 13 points, and it is not
reachable through the seeding scan. Seven in ten of what remains is the gap scan carving entries out
of regions nothing claimed, and one in four is a reference the analysis believed; the next measurement
is what those 6,093 gap candidates look like, not which bytes they start with.

### 4. Go/AArch64: what is left of the tailcall path after section 10

Go arm64 produced **0.1340 false positives per truth function** against 0.0367 on amd64 and 0.0173 on
386 — a 3.6× rate on the same source programs — and **170 of 246** false positives on
`hello_linux-arm64_default` came from tailcall seeding, a source that contributes 0 on every intel
cell. Section 10 gated the half of that source which was strictly worse than not having it, removing
430 of them on Go and 28 on the ARM64 Mach-O corpus.

What remains is the branch-target site: it seeds the target of a backward branch or a short no-frame
stub, and the AArch64 candidate manager records a capped call reference for the seed, manufacturing
the evidence that makes it score highly — something the shared implementation never does.

**Ceiling and the next step.** Gating this site too would remove a further **215** false positives —
210 on the Go arm64 cells and 5 on the Mach-O corpus — and cost **7 true positives**, functions on
two binaries that nothing else reaches, so it is rejected as a switch. Reaching the 244 needs the
narrower shape the landed fixes took — keep the source, refuse the cases that are provably interior —
and characterising those seven is what comes first. The frozen corpora have no AArch64 member, so the
ARM64 Mach-O corpus and the bundled fixtures are the regression check.

### 5. NativeAOT precision — the worst single cell of any family

PPV **74.36** on a 5,749-function native image — 1,940 false positives on one binary, after section 9
removed 99 of them. Part of that is truth rather than over-detection: `.eh_frame` in the same image
declares 6,513 ranges against the symbol table's 5,749, and **702 of the 1,940 apparent false
positives are FDE-declared**, so scoring against the union of the two gives 83.64 / 95.09. That
leaves **1,238** genuine false positives and, in the other direction, **326 FDE ranges not reported
at all**. The image carries .NET metadata beside its native code, which no candidate pass consults,
and a full exception table.
**Ceiling:** +9.3 PPV from the truth correction alone, which is bookkeeping rather than a fix; the
remaining 1,238 are worth about +16 PPV on this cell and need more than one NativeAOT artifact
before a mechanism can be claimed.

### 6. ReadyToRun native code is not analysed at all under default routing

626 native functions per assembly, recoverable at 99.84 precision once the intel backend sees the
image, and zero recovered as shipped because the CLR header routes it to the CIL backend. This is a
design decision rather than a defect — a CIL report addresses methods by file offset and a native
report by virtual address, so the two cannot be merged without changing the report contract — and
it needs a maintainer's call on the shape. **Ceiling:** the entire precompiled native body of every
ReadyToRun assembly, which is most of what such an assembly ships.

### 7. The CIL backend reports file offsets while every other backend reports virtual addresses

A consequence of the above, and worth stating separately: a managed report's function offsets are
not comparable with `base_addr` plus an RVA. Anything correlating a CIL report with a native one is
comparing two address spaces. **Ceiling:** not an accuracy number; a correctness question for
downstream consumers.

### 8. Three headerless dumps still get their bitness wrong

`geodo`, `hamweq` and `tinba` carry no header, so the fix landed in section 5 cannot reach them, and
the second statistic tried instead was measured worse (section 6). Decoding coverage in both modes
was the next thing to try and has since been **built and rejected**: counting where a sweep has to
restart separates the classes by an order of magnitude over `.text` sections, and is wrong on 9 of
12 whole 64-bit images, because non-code bytes fail to decode far more often as 64-bit than as
32-bit. The ratio tracks how much of a buffer is not code rather than what mode it is; the nine
32-bit dumps agreed with it because the bias points at 32 and they happen to be 32. A decode
statistic can work, but only over code, and a headerless dump is exactly the case where nothing
declares where the code is — which puts this downstream of establishing code extent rather than
beside it. `hamweq` is out of reach either way: it stumbles once in each mode over 12 KB.
**Ceiling:** three of 57 samples on one corpus, and only under `--bitness auto`; nothing at all
under the configuration published figures use.

### 9. Corpus hygiene

The mispaired ByteWeight binary is worth **1.374 macro F1 and 1.4 points of recall** on Bao 32, and
**1.662** on its dumped variant, as pure measurement error. Repairing the truth file rather than
excluding the binary would recover a real 472-function sample.

## 14. Per-family results

Every family below is measured on a corpus built for this work; none of them had ever been measured
for function-start accuracy. Filter `all`, arithmetic macro mean.

| family | n | PPV | TPR | F1 | truth functions |
|---|---|---|---|---|---|
| C/C++ (gcc, clang, mingw) | 260 | 91.878 | 95.523 | 93.428 | 213,441 |
| Go (pclntab truth) | 45 | 94.843 | 99.618 | 97.118 | 162,621 |
| .NET (CIL + NativeAOT) | 4 | 93.589 | 99.461 | 96.124 | 7,441 |
| Rust (gnu targets) | 24 | **78.951** | 97.493 | 87.185 | 33,817 |
| ARM64 Mach-O (linker truth) | 11 | 94.220 | **96.711** | 95.074 | 2,753 |

For comparison, the corpora the previous evaluation used, same settings: ByteWeight 32-bit
(n=68) 92.041 / 97.872, ByteWeight 64-bit (n=68) 99.080 / 99.838, malware dumps (n=57)
92.639 / 98.561.

**C/C++.** The largest corpus here and the closest thing to the population the frozen ByteWeight sets
represent, built by different compilers: 260 binaries, ten programs, gcc, clang and both MinGW
targets, `O0` through `O3` plus `Os`, static and no-PIE. It scores **95.523** recall against the
97.872 of the 32-bit ByteWeight set and the 99.838 of the 64-bit one, on 213,441 truth functions —
so the recall the published figures show is not a property of the disassembler alone but of the
corpus those figures were measured on, which is one compiler at four optimization levels.

**Go.** Recall is essentially perfect and stripping costs nothing — `-ldflags="-s -w"` scores 94.939
/ 99.668 against the unstripped 94.916 / 99.668 over 21 cells each, which is the design's claim
about pclntab-driven recovery, measured end to end for the first time. Precision, however, depends
on the target architecture with recall held at 100: false positives per truth function are 0.0173
on 386, 0.0367 on amd64 and **0.1340 on arm64**, on identical source. The AArch64 backend
over-detects 3.6× more than the intel one and does so on every program and both operating systems.
99.6% of those extra detections are interior to a real function's span.

Ghidra was run over this family too, which no published comparison covers, under the same analysis
budget: PPV 93.501 / TPR **86.430** macro, micro recall **78.313** against SMDA's 99.618 — 70.22 on
386, 91.76 on amd64 and 62.89 on arm64. Two of its 45 samples did not finish inside the budget and
score 0. Ghidra is the more precise of the two here and recovers far fewer functions, which is the
pclntab: SMDA reads Go's own function table, and without it most of a Go binary is unreachable to
recursive traversal. It is the clearest illustration in this work of the trade the origin evaluation
states — deliberate over-detection buying completeness — on a family that evaluation never covered.

**.NET.** Managed CIL is exact — 100/100/100 on 564 methods in each of three publish modes, because
metadata enumerates every body. NativeAOT is native code and scores 74.36 precision, the lowest
figure anywhere here; 702 of its 1,940 false positives are ranges the same image's `.eh_frame`
declares and the symbol table does not, leaving 1,238 unexplained.

**ARM64 Mach-O.** The only AArch64 corpus here whose truth comes from a linker rather than one
compiler's metadata: eleven real Mach-O binaries, each declaring its own function starts in
`LC_FUNCTION_STARTS`. The finding is recall. Every sample under 90 truth functions is recovered
completely and every sample above it is not, and micro recall is **91.246** — after the fix in
section 8, from 90.229 before it — against 99.745 on the 64-bit ByteWeight set. That is the largest
architecture gap measured anywhere in this work, and the opposite of what the Go family suggested,
where recall is essentially perfect because the pclntab names every function and SMDA reads it. Take
the symbol oracle away and AArch64 recovery falls a long way behind intel recovery on comparable
code.

The figures above are measured with `SmdaConfig.USE_MACHO_FUNCTION_STARTS` at its default, which is
off. That option makes SMDA read the same table this corpus uses as ground truth; measured with it
on, the corpus scores the engine against the answer key it was handed.

The first measurement of this corpus said PPV 39.901, and it was the corpus rather than the
disassembler. Section 16 records what was wrong and how it was found; the short version is that
Mach-O stub sections are the counterpart of an ELF PLT and `LC_FUNCTION_STARTS` does not name them.

**Rust.** The lowest precision of any family whose truth is complete even after section 9 took it
from 75.817 to 78.951, and the truth *is* complete —
`.eh_frame` names fewer ranges than the symbol table and their union adds nothing. 95.3% of its
false positives are interior splits, and one byte pattern accounts for half of the reference-less
ones: `push r15; push r14` seeded four bytes inside functions that open with
`push rbp; mov rbp, rsp`.

## 15. What is not covered, and why

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
- **There is no AArch64 *build* corpus.** clang here can target `aarch64-linux-gnu` and lld can link
  it, but no AArch64 libc headers or sysroot are installed, so nothing that includes a standard
  header compiles and no real project can be built for the architecture. The ARM64 Mach-O corpus
  stands in, and it is real code with linker-written truth rather than a substitute for a build
  matrix — it covers one platform, one linker and one kind of program.
- **Ghidra is measured under this harness' analysis budget.** Both engines get the timeout
  `--timeout` names, defaulting to SMDA's own so neither is favoured, and on the largest ByteWeight
  binary that choice decides the result. The cell is marked rather than averaged; read the column as
  *Ghidra under this budget*.
- **Delphi is not covered.** No Delphi toolchain is available here, so the family stays on the
  agenda with no measurement behind it. The bundled Delphi fixtures exercise the symbol providers
  but not function-start accuracy.

## 16. Method notes worth keeping

Three habits earned their place during this work and are worth stating, because each of them
changed a conclusion:

**A zero-difference result needs a positive control in the same output.** The exception-table change
was claimed inert on the bundled fixtures. Checking only that both runs produced functions would
have proved nothing; checking that the directory and the section walk read the *same entry counts*
— 48, 7 and 1,666 — proved it.

**Ask whether the truth is right before attributing a low score to the tool.** NativeAOT's low
precision looked like the worst defect found. A second independent declaration in the same image —
`.eh_frame` — declares 6,513 ranges against the symbol table's 5,749, and 702 of the "false
positives" are among them. Running the same check on Rust, where it would have been equally convenient to blame the
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
something came from tagging each recovered address with the candidate source that seeded it, or with
the first instruction of the function it produced. It turned "Rust precision is bad" into "one seeded
byte pattern, four bytes inside a function"; "AArch64 recall is bad" into "sixteen functions
swallowed after a call that does not return, and eight unanalysed branch veneers"; and "this C++ cell
scores 52" into "1,085 of 1,095 false positives begin with `endbr64`".

**A zero result with no positive control beside it says nothing.** The `endbr64`-then-prologue seed
was measured on six binaries and returned a clean zero — and five of those six contained none of the
pattern. What made it dangerous was the byte statistic in front of it: 19,536 adjacencies with a
perfect 19,536-to-0 split, which made a meaningless zero read as confirmation. Redone on binaries
that carry the pattern, the answer was still small enough not to act on, but it was an answer.

**Measure the discriminator before building on it.** The `endbr64` finding suggested two repairs and
both looked obviously right. Filtering on the bytes before the pad: rejected, because a jump-table
case ends in a `jmp` exactly as a function does. Filtering on whether anything references the pad:
rejected, and this one had a table behind it — 0% of that cell's false positives were referenced
against 57.9% of its true positives — which turned out to be a property of one static library nothing
calls, not of landing pads. Measured over four cells it would have removed more real functions than
spurious ones. Both are recorded in section 6 rather than quietly dropped, because the next person to
have the same idea should find the measurement waiting.

## 17. Where every corpus stands at the end of this branch

Filter `all`, arithmetic macro mean, one run of the whole harness at the last commit:

| corpus | n | PPV | TPR | F1 | truth | detected |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | 68 | 92.041 | 97.872 | 94.713 | 110,195 | 115,792 |
| Bao byteweight msvc10-64 | 68 | 99.080 | 99.838 | 99.454 | 108,187 | 109,584 |
| Bao_Dumped msvc10-32-d | 56 | 91.189 | 97.510 | 94.060 | 108,486 | 114,162 |
| Bao_Dumped msvc10-64-d | 56 | 98.874 | 99.811 | 99.338 | 106,679 | 108,455 |
| Plohmann malpedia itw | 57 | 92.643 | 98.561 | 95.144 | 21,924 | 24,270 |
| Built C/C++ (gcc, clang, mingw) | 260 | 92.623 | 95.525 | 93.875 | 213,441 | 225,405 |
| Built C/C++ AArch64 (gcc cross) | 72 | 76.676 | 95.939 | 84.852 | 56,127 | 69,108 |
| Built Go (pclntab truth) | 45 | 95.111 | 99.618 | 97.266 | 162,621 | 171,338 |
| Built Rust (gnu targets) | 24 | 78.951 | 97.493 | 87.185 | 33,817 | 41,663 |
| Built .NET (CIL + NativeAOT) | 4 | 93.589 | 99.461 | 96.124 | 7,441 | 9,257 |
| ARM64 Mach-O (linker truth) | 11 | 94.220 | 96.711 | 95.074 | 2,753 | 2,767 |

**931,671 truth functions across eleven corpora, 991,801 detections, no failed sample.** Six of the
eleven corpora and 476,200 of those truth functions did not exist for this project before this
branch.

## 18. Summary of what landed

| fix | corpus that shows it | before → after |
|---|---|---|
| container header outranks the byte probes | malware dumps, bitness withheld, n=57 | F1 +0.155, 93 recovered, 64 false positives removed |
| exception table read from the declared directory | .NET ReadyToRun image, 626 declared starts | recall 66.93 → **100.00** |
| a call that does not return is a boundary | ARM64 Mach-O, n=11 | recall 95.616 → **96.345**, 28 recovered, 0 new false positives |
| a prologue that opens where another ends | ten corpora | **912** false positives removed, **0** true positives lost |
| the cut after a call recovers the function, not a seed | ARM64 Mach-O n=11 and Go n=45 | 12 recovered, **458** false positives removed |
| a candidate snapshot taken before analysis hides half the functions | ARM64 Mach-O n=11 | 8 recovered, **0** new false positives |
| a landing pad inside a declared unwind range is not a function | C/C++, n=260 | **3,977** false positives removed, 18 recovered against 7 lost |

The landed rules cost no measurable time, and the controls are what make that a claim rather than a
guess. Both trees checked out into the same directory in turn, one pass at a time on an idle machine,
the leading side rotated per pass, min of three: malware dumps (n=57) −0.19% [−0.60%, +0.57%], Rust
(n=24) +1.46% [−2.65%, +6.51%], ARM64 Mach-O (n=11) −2.83% [−3.62%, +2.98%]. Running one commit
against *itself* across two sessions on that same machine gives +1.37% [+0.10%, +1.80%] at p = 0.008,
so every figure above is smaller than the disagreement between two measurements of identical code.
Section 19 records what happens when that control is missing.

No corpus lost recall at any step. Five further proposals were measured and not landed — four
rejected for costing recall or removing more real functions than spurious ones, one found to change
nothing worth changing — and all five are in section 6 with the numbers that settled them. One of
those five, gating both AArch64 tailcall sites, is where the fix in section 10 came from: separating
the two sites turned a rejected whole into a landed half.


## 19. Fix landed: the benchmark's timing verdict was a comparison between two machines

Three consecutive runs of this branch's malpedia benchmark reported **+1.26%** (*inconclusive*),
**−13.18%** (*PR is slower*, Wilcoxon **p = 0.0000**) and **−15.53%** (*PR is slower*) over 155 files.
The source changes between those heads touch `AArch64Backend` and a comment, on a corpus of x86 and
x64 images.

The runs' own artifacts say what moved.

- **The base side of all three verdicts is the same data.** Base `total_time` 252.53414500000002 and
  `total_functions` 175973 in every one, and the three base passes' corpus medians identical to the
  last digit across all three. `Restore cached base results` hit, and every step after it was skipped:
  the cache carried the first run's base measurements into the two that followed.
- **The PR side did identical work in all three** — 175942 recovered functions every time, the same
  two differing files, the same changed addresses, the same 59 block-count drifts.
- **The PR side got slower each time**: sum-of-best-times **252.83 s → 282.21 s → 289.04 s**, a spread
  of **14.3%** for output that never changed, and the benchmark step itself 370 s → 396 s of wall
  clock for the same three passes. A different runner each time, over two hours.
- **The noise band could not see it.** It is `max(base_cv, pr_cv)`, where each `cv` is the variation
  across *one side's* repeated passes — all of which run inside one job on one machine. It measures
  within-runner jitter and is used to bound a between-runner offset. In all three runs it was 5.032%,
  because in all three it was set by the same cached base data.

Within one run the same spread is already visible: the first run's nine pairwise base-vs-PR
comparisons span **−8.25% to +5.26%** for the same two trees.

The fix makes the comparison a comparison. The malpedia job no longer splits into a base leg and a PR
leg on two runners with the base leg cached across runs; it times both sides in one job, on one
machine, in base/PR/PR/base/base/PR order — which is what the fixture gate in the same workflow
already does, and for the reason its own comment gives. The base cache goes with it: a cached side is
by construction a measurement from another machine and another hour. The correctness comparison is
unaffected, both sides being deterministic, and the cost is one runner's time rather than two running
in parallel.

**Verified on the first run of the repaired workflow**, against the same head that had just been called
15.53% slower: verdict *inconclusive — within run-to-run noise (±6.8%)*, median paired speedup
**+0.82%** with 95% CI [−0.40%, +2.06%] and Wilcoxon **p = 0.242**. The base side is 210.82 s and was
measured rather than restored — it had been frozen at 252.53 s for three runs — and the correctness
finding is unchanged, which is the control that only the timing arrangement moved. That figure also
agrees with the local measurement above, +0.82% [−0.40%, +2.06%] on CI's corpus against −0.19%
[−0.60%, +0.57%] on this machine's, where the two instruments had previously disagreed by 15 points.

Section 12 lists the properties this project's own harness gained because a measurement without them
had already misled it, and the first is that every row states its corpus, `n` and filter — two fake
regressions in its history came from comparing an unfiltered population against a filtered one. This
is the same failure with machines in place of populations, and the run that produced it carried the
evidence to catch it.

## 20. Fix landed: a landing pad inside a declared unwind range is not a function

**The defect.** `endbr64` is a CET landing pad and the prologue scan seeds every one it finds. A
landing pad marks every *indirect-branch target*, not every function: under `-fcf-protection` gcc
emits one at each jump-table destination, each computed-goto label and each exception landing pad
inside a body, so one `switch` produces a dozen spurious function starts. Section 13 ranked this as
the largest single precision mechanism found here and recorded five byte-level filters that were
tried and rejected, the best of them refusing 1,840 real function starts along with the spurious
pads.

**What the agenda proposed, and why it is dead.** The repair was to be a filter on candidates the
jump-table pass had claimed, since a pad is what an indirect branch arrives at. Instrumenting
`JumpTableAnalyzer.getJumpTargets` over six cells: **0 of 4,627** of the `endbr64`-headed false
positives is a jump-table target. The control is that the pass claims 43 to 84 targets per image, so
it ran — on the worst image it resolves 43 addresses while 1,085 spurious pads sit in it.

**What they are instead.** Every one of 4,690 over ten ELF cells sits **strictly inside a range the
image's own `.eh_frame` declares**, a median of 892 to 2,067 bytes in. The unwinder's record is the
evidence the bytes cannot supply: an FDE covers one routine, so a pad that is not its range's own
start is inside that routine.

**The rule.** Decline to *seed* an `endbr64` prologue match that begins strictly inside a declared FDE
range. Decline to add a candidate, never remove one — reference discovery, symbols and exception
records all run before the prologue scan, so an address the image already names keeps its candidacy.
It is the only seeded pattern that names a place a branch can arrive rather than a way a function
opens, and the only one the test applies to.

**Result**, ten corpora in one run:

| corpus | n | before | after |
|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | 91.878 / 95.523 / 93.428 | **92.623** / 95.525 / **93.875** |
| the other nine | — | — | bit-identical |

3,977 false positives removed. The nine unchanged corpora are the control that the rule reaches only
ELF images with a readable `.eh_frame` section — every PE, Mach-O and memory-dump corpus is inert by
construction, and Go emits no `.eh_frame` at all. The worst cell in the matrix,
`googletest_gcc-x64_Os`, goes from **52.058 PPV to 97.701**.

**Recall is not free here.** Eighteen true positives are gained and **seven lost**, on four of the 260
cells, for a net of +11 and 11 fewer misses; `summarize.py --compare` reports `compared=10` with no
TPR regression on any corpus. None of the seven is inside a declared range, so the rule refused none
of them directly — they are lost because the analysis that reached them descended from a pad it did
refuse. That is a smaller claim than the interior-prologue rule in section 9, which lost nothing
anywhere, and it is stated rather than rounded away.

**The gap scan, built and rejected.** The same interior test applied to gap analysis removes the
remaining pads, and costs every CET `.plt` stub: on one cell **179 of 179** functions lost are PLT
entries, and recall falls from 99.581 to 84.673. The whole PLT block sits under a single FDE, so the
test reads every stub after the first as interior; and on a CET binary it is the gap scan rather than
`locateStubChainCandidates` that recovers them, because that pass matches the classic
`jmp qword ptr [rip+...]` stub shape and not the `endbr64`-prefixed one. The seeding half is free on
the PLT for exactly that reason — the gap scan is its safety net. Teaching the stub pass the CET form
is what would let the gap half land, and is the next step rather than part of this one.

**The class, swept.** AArch64's BTI landing pad is the same construct — `is_bti_landing_pad` is seeded
by `locatePrologueCandidates` and guarded only by `_isLikelyInteriorBtiCandidate`, which fires solely
for addresses already in `code_map`, so an interior pad in a not-yet-decoded region is still seeded.
The declared-range predicate lives in the shared candidate manager and would apply unchanged. It is
**not fixed here because nothing available can measure it**: the Go arm64 cells carry zero FDE ranges
(Go emits no `.eh_frame`), the ARM64 Mach-O corpus has no such section, and the one bundled AArch64
ELF with 276 readable ranges has no ground truth, so a change there could only be scored by counting
recovered addresses — which section 16 records as the wrong instrument. An AArch64 ELF corpus with
symbol truth is the prerequisite, and it is the first entry on the agenda that this fix creates.

## 21. Corpus added: AArch64 ELF with compiler truth

The fix in section 20 was recorded with its AArch64 sibling unmeasurable, and the reason was that
nothing here reached it: Go's arm64 cells carry zero FDE ranges, the ARM64 Mach-O corpus has no
`.eh_frame` section, and the one bundled AArch64 ELF has no ground truth. `native-arm64` is that
prerequisite — the same ten C and C++ programs and the same seven variants through
`gcc-aarch64-linux-gnu`, truth from the same compiler's symbol table. 72 cells of 80; the eight
failures are all `xxhash`, whose `XXHSUM_DISPATCH` is x86-specific, and the manifest says so.

It is its own corpus rather than extra cells of `native`, so the x86 matrix stays comparable to the
figures already published for it rather than becoming a mixed-architecture population.

**n=72: PPV 76.676, TPR 95.939, F1 84.852**, 56,127 truth functions, 69,108 detections.

### What it re-ranks

Section 13's first item is corrected by it, and the correction is in that section. Holding source,
programs, variants and compiler family constant over 63 matched cells, recall differs between the
architectures by 1.5 points and precision by 17.1 — the gap this project has been calling a recall
gap is a precision gap, and the Mach-O figure that suggested otherwise was comparing two populations.

### The BTI sibling: measured, and rejected by the gate

The corpus carries an `O2-bti` cell because nothing else here has the construct in any density:
**3,830** BTI landing pads across its nine binaries against **21** in the same programs built without
`-mbranch-protection`, which is the control that the cell measures what it claims to.

Extending the declared-range test to `is_bti_landing_pad` — today guarded only by a `code_map` check
that cannot see a not-yet-decoded region — measures on those cells: **2,068 of 2,068** false-positive
pads sit strictly inside a declared FDE range, and **0** true positives opening with a pad do. That
is a cleaner split than the x86 case in section 20, which touched 2,131 real functions, all of them
PLT stubs.

End to end, n=72: PPV 76.676 → **78.050**, F1 84.852 → 85.828, **2,861 false positives removed** —
and **one true positive lost**, `0xe1744` on `sqlite3_gcc-arm64_O2-bti`. TPR 95.9386 → 95.9379.

`summarize.py --compare` rejects it and the change is reverted. A TPR drop on any corpus is the
stated criterion and it carries no size threshold. For whoever revisits it: `0xe1744` opens `paciasp`
rather than a pad and sits in no declared range, so the rule refused nothing about it — it is the same
second-order class as the seven section 20 costs, and recovering it needs the pad-to-victim chain
instrumented rather than a narrower predicate. Whether 2,861 false positives for one function in
56,127 is a trade worth taking is a judgement about the gate, not about the evidence.

### The measurement that was wrong first

The first BTI run reported a clean **0 of 2,068** — the opposite answer — behind three controls that
all looked healthy: the pads present, 2,068 of them recovered as false positives, and 124 to 1,777
FDE ranges decoded per image. The script built its per-file record with two dictionary keys of the
same name, so the false-positive column was silently overwritten by the true-positive one and every
figure it printed for that column was the wrong quantity. Re-deriving the same number out of a
second, independent script is what caught it. Controls establish that a probe ran; they say nothing
about whether the line that reported it computed what it claimed.

## 22. Finding: master lost precision on the malware corpus after 4.4.7, and it is one condition

This section is about `master`, not about this branch. Nothing here is landed; it is a measured
finding with the options priced, because a regression that a recall-watching gate cannot see is
exactly the kind that survives.

### The observation, and the control that makes it one

An upstream pull request merged 2026-08-11 recorded malpedia macro F1 **95.4551** at TPR 98.5302.
Today's `master` measures **95.142**. Before comparing anything, re-measure that pull request's tip
(`e394a45`) through **today's** harness: F1 **95.455**, TPR **98.530**. The historical figure
reproduces to three decimals, so the two instruments agree and the difference that follows is between
commits rather than between ways of counting.

| commit | date | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|---|
| `e394a45` | 2026-08-11 | 93.193 | 98.530 | 95.455 | 21,682 | 2,501 | 242 |
| `802e627` | 2026-08-24 | 92.639 | 98.561 | 95.142 | 21,688 | 2,583 | 236 |

**Recall went up.** A gate that watches recall alone — the gate this branch holds itself to — sees
nothing here at all.

### Bisected to one commit, then to one line

Six measurements over the 24 commits touching `src/smda/` in that window put effectively all of it on
`5f70672`, which trades 7 true positives for 75 false positives. Attribution over the recovered
address sets, per sample and per booking pass, concentrates it further: **8 of 57 samples change**,
and two of them carry 73 of the 76 gained false positives.

Two hypotheses were refuted by measurement before the third held. The commit's new register-base
jump-table recovery resolves the *same five dispatch sites with the same targets* either side, on the
sample that changes most. Its apparent widening of the backward-walk allowlist is a pure move with
identical membership. The cause is one condition added to the inferred alignment floor:

```python
and not candidate.call_ref_sources
```

Reverting that line alone, with the rest of the commit in place, returns the false-positive count to
**2,508 — the pre-commit figure to the unit**.

### It is not a defect, and that is the point

Measured on the 50-binary ELF corpus the commit was justified against, with that corpus' own scoring
harness and its own `body_splits` metric:

| variant | recall | recovered | body splits |
|---|---|---|---|
| exemption as shipped | **95.098%** | 10,826 / 11,384 | 306 |
| narrowed to more than one call reference | 95.081% | 10,824 | 308 |
| no exemption | 94.993% | 10,814 | 308 |

It buys 12 real functions there. It is a predicate that is right on ELF executables and wrong on
memory dumps — which wants a narrower predicate, not a revert.

### A narrower predicate, chosen from what the exemption actually admits

Profiling the admitted candidates rather than the net effect is what picks the rule, and the first
version of that profile was wrong in a way worth recording. Scoring an ELF address as an error when
it is absent from the truth set made the exemption look 45% precise there, with the *spurious* side
carrying more call references and higher confidence than the real side — the signature of PLT stubs,
which this corpus labels not at all and whose own metric declines to penalise. Reclassified the way
that corpus classifies an address:

| 100 exempted and recovered, 50 ELF binaries | labelled start | body split | unlabelled |
|---|---|---|---|
| count | 45 | **0** | 55 |

**Zero body splits** — the exemption produces no errors at all where it was justified. On the malware
corpus, where the truth includes thunks so absence is a genuine error:

| 94 exempted and recovered, 57 dumps | real (71) | spurious (23) |
|---|---|---|
| has a common entry shape | 66 (93.0%) | 5 (21.7%) |
| exactly one call reference | 49 (69.0%) | **23 (100.0%)** |
| **neither of the two** | **3 (4.2%)** | **18 (78.3%)** |

So waive the floor only for a candidate that is call-referenced **and** either entry-shaped or
referenced more than once:

| 50 ELF binaries | recall | recovered | body splits |
|---|---|---|---|
| exemption as shipped | 95.098% | 10,826 | 306 |
| **entry shape or more than one reference** | **95.098%** | **10,826** | **306** |
| more than one reference only | 95.081% | 10,824 | 308 |
| no exemption | 94.993% | 10,814 | 308 |

| 57 malware dumps | PPV | TPR | F1 | TP | FP |
|---|---|---|---|---|---|
| exemption as shipped | 92.639 | 98.561 | 95.142 | 21,688 | 2,583 |
| **entry shape or more than one reference** | 92.911 | 98.551 | **95.306** | 21,686 | **2,552** |
| more than one reference only | 93.038 | 98.548 | 95.373 | 21,685 | 2,540 |
| no exemption | 93.180 | 98.515 | 95.439 | 21,679 | 2,508 |

**It is byte-identical to what ships on the ELF corpus** — same recall, same recovered count, same
body splits — while removing 31 of the 75 false positives on the malware corpus. Against recovered
sets rather than aggregates it is a strict subset: 31 false positives dropped, 2 true positives
dropped, **0 addresses gained**.

The `getConfidence` threshold alone — more than one inbound reference, which that model already
scores at 1.0 outright — removes more false positives (43) and is *not* free on ELF: it costs 2
functions and adds 2 body splits. It is the worse of the two.

Neither clears a no-recall-drop gate, which is why both are recorded rather than proposed. The two
functions the better one costs are `0xb8c08e` on `feodo` and `0x1e05ae9` on `urlzone`, each a real
function whose entire evidence is a single call reference with no recognised entry shape — the same
bucket holding 18 of the 23 spurious admissions. Separating two from eighteen is not a rule, so no
third clause is offered.

### Full ledger, both sides at `5f70672`

| corpus | n | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|
| boundary corpus (50 ELF) | 50 | *recall +0.105 pt* | **+12** | *−2 body splits* |
| Bao_Dumped msvc10-32-d | 56 | +0.013 | +2 | −2 |
| Bao byteweight msvc10-32 | 68 | +0.011 | +2 | −2 |
| Built C/C++ (gcc, clang, mingw) | 260 | −0.001 | +34 | +26 |
| Bao byteweight msvc10-64 | 68 | −0.002 | −3 | +6 |
| Bao_Dumped msvc10-64-d | 56 | −0.036 | −3 | **+75** |
| Plohmann malpedia itw | 57 | **−0.297** | +9 | **+75** |

**The discriminator is not "is a memory dump".** The 32-bit dumped ByteWeight set gains 0.013, and the
malware sample that gains the most false positives is itself a 32-bit dump. Establishing what actually
separates them is what would turn the narrowed predicate into a free one, and it is the first item on
the malware-corpus agenda.

### What this says about the corpora, beyond this one line

The issue that published the 50-binary corpus already carried the warning: 93% of its labelled
functions come from ten statically-linked builds, so it measures glibc recovery, and *"SMDA's stated
design target is CFG recovery from memory dumps, which this corpus does not represent at all."*

This is that warning happening. A change was measured carefully — 50 binaries, stripped copies,
body splits down from 712 to 316, no file regressed — and the corpus it was measured on does not
contain the workload that pays for it. The general form is already recorded here from the opposite
direction, where a guard measured *free* on an available corpus cost real functions on the one that
exercised the path. Same instrument error, opposite sign, and neither is visible without running both.

### Why the residue is not reachable, which is the more useful result

The predicate above leaves a bucket it cannot judge: a candidate with one call reference and no
entry shape. Asking where that one reference comes from separates it completely — on the malware
corpus **all 18** spurious admissions are referenced from an instruction that is not real code,
against **0 of 18**, while every one of the 5 on the ELF corpus is.

Repeated over every recovered candidate carrying exactly one call reference rather than only the
ones this exemption admits — 8,836 on the dumps — it holds at scale:

| malpedia, one call reference | count | precision |
|---|---|---|
| the reference comes from real code | 8,120 | **98.9%** |
| it does not | 716 | **6.1%** |

A sixteen-fold separation. It does not separate on the 50 ELF binaries, and that is the point rather
than a disappointment: only 60 of 2,197 land in the weak bucket at all, because on a compiler-built
binary nearly every call site is a real instruction. The signal exists where misdecoded regions do,
which explains the entire corpus split without appealing to the corpus.

**And the engine cannot see it.** That test answered "is the referencing instruction real code" from
ground truth. The nearest question the engine can ask is "did I decode an instruction there", and
measured side by side the proxy collapses the separation from sixteen-fold to 2.3-fold — because 82%
of the spurious references point at an instruction SMDA decoded. The decoding is the thing that is
wrong, so asking it to check its own work catches almost nothing. As a filter the proxy trades 88
real functions for 135 spurious ones against the ground-truth version's 15 to 1.

So this class of false positive is not reachable from inside the disassembly. Anything that reaches
it has to bring evidence the *image* declares — an entry, an unwind record, a symbol, a relocation —
rather than evidence the engine derived. Section 20's landing-pad rule and the gap-scan position
family in the log both arrived at that conclusion by different routes; this is the first time it
comes with a measured mechanism rather than an inference.

## 23. Fix landed: the declared landing pad, and the resume point that decides whether it costs recall

Section 20 landed half of this: an `endbr64` prologue seed opening strictly inside a declared FDE
range is refused. It left the other half open — "the gap scan, built and rejected", because the same
interior test applied there cost every CET PLT stub, 179 of 179 on one cell, recall 99.581 to 84.673.
Section 21 left the AArch64 sibling in the same state, measured and refused by the gate: 2,861 false
positives removed for **one** true positive lost.

Both are now landed, by replacing the interior test with a narrower one and — the part that actually
decides it — by choosing where the scan resumes.

**The predicate.** Not "is this address inside a declared function" but "is this address one the
image declares as an exception landing pad". Each FDE whose CIE announces `L` points at its LSDA;
the LSDA's call-site table names each pad as an offset from `LPStart`, which defaults to the
function start the FDE names rather than to zero. That is a strictly smaller set than "interior",
and it contains no PLT stub, which is why the PLT collapse that stopped section 20 does not occur.

**The resume point.** Refusing the pad is not enough. Stepping one instruction past it lands *inside*
the pad, and the scan books that instead — a worse candidate than the one just refused, because it
opens mid-body and its analysis runs on through whatever follows. Traced on
`googletest_gcc-arm64_O2`: refusing the declared pad at `0x1dd60`, the scan books `0x1dd64` and the resulting
function swallows two real ones. That single behaviour is the difference between the rule costing 5
true positives on the AArch64 corpus and gaining 15.

Resuming at the end of the FDE that declares the pad passes over that function's body and nothing
else. Checked rather than assumed, by counting true starts lying strictly between a pad and that
end: **0 of 41,215 pads** across the three corpora that carry any.

**The sibling, swept.** x86 books declared pads through the gap scan only — `endbr64` is not one of
its prologue shapes. AArch64 books them through **both** the gap scan and `locatePrologueCandidates`,
because `bti` *is* a recognized entry prologue there; on a small C++ fixture the prologue scan books
all five and the gap scan none. Its existing `_isLikelyInteriorBtiCandidate` shape test is what lets
them through: under `-mbranch-protection` every pad opens with a `bti`, and the test reads that as
evidence of a legitimate indirect-call target. Before any rule, the AArch64 corpus declares 12,585
pads, the engine books **4,108** of them as functions, and **0** of the 12,585 is a real start.

**Result**, six corpora, both sides run back to back on one tree:

| corpus | n | PPV | TPR | F1 | dTP | dFP |
|---|---|---|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | 92.623 → **94.109** | 95.525 → **95.595** | 93.875 → 94.718 | +193 | −7,312 |
| Built C/C++ AArch64 (gcc cross) | 72 | 76.676 → **79.172** | 95.939 → **95.963** | 84.852 → 86.632 | +15 | −4,487 |
| Built Rust (gnu targets) | 24 | 78.951 → **82.435** | 97.493 → **97.578** | 87.185 → 89.192 | +13 | −654 |
| Built Go, ARM64 Mach-O, Built .NET | 60 | — | — | bit-identical | 0 | 0 |

12,453 false positives removed and 221 real functions gained, with recall up on every corpus that
moves. The three unchanged corpora are the control that the rule reaches only ELF images carrying an
LSDA. It ships **on by default**: no pre-existing bundled fixture moves, and on the two cells with
the most pads analysis is 3.8% faster, because the candidates it refuses are ones nothing then
analyses.

This is the first change on this branch to improve precision and recall together on three corpora at
once, and it is the same lesson section 22 reaches from the other end — the evidence that works is
what the *image* declares, not what the engine derives.

## 24. The malpedia gate, judged from its own artifacts

The 155-file corpus gate goes red whenever the recovered function set changes and states, correctly,
that it cannot tell an improvement from a regression. That is a reason to read its artifacts, not a
reason to stop. Both sides upload every `.smda` report; a 366 MB artifact zip opens over HTTP range
requests, so judging three files costs about 30 MB rather than 730.

| sample | base → PR | what the changed addresses are |
|---|---|---|
| `elf.akira` | 13,229 → 13,181 (−48) | **all 48 still decoded inside a surviving function** — a boundary moved, no code lost. 59 functions gained blocks, several from 1 block to between 25 and 982. |
| `elf.akira` (Rust) | 3,020 → 2,932 (−88) | none absorbed; 74 of 88 open with `mov`, which is how a Rust landing pad starts. Nothing branches to a pad, so it stops being decoded once it is not booked — the intended effect, and the same rule gains 13 true positives on the 24-cell Rust corpus that has symbol truth. |
| `win.konni` x64 | 3,870 → 3,887 (+20 / −3) | every one of the 20 added opens with a textbook MSVC x64 prologue; one carries 22 blocks and 220 instructions and was not decoded at all before. |

**The three addresses the gate labels "likely real function lost" are not losses.** Two open with
`dec r13` followed by `je +0x19` — a loop counter decrement and its exit branch, which is not a
prologue; the inbound reference the label rests on is the loop's own back-edge. The third is a
one-instruction `jmp` at the end of a two-hop tail-jump chain, and the same sample's other dropped
entry has its first instruction at a *different address* than the function it is filed under, which
is a malformed entry rather than a routine.

So the label heuristic reads an inbound reference as evidence of a real function, and a loop
back-edge and a tail jump both supply one. That is worth stating precisely because the heuristic is
useful: it narrowed 139 changed addresses down to three worth opening.

Nothing readable in those artifacts is a regression. The gate stays red because the set changed, and
that is what it is built to report.
