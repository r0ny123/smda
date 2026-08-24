# Function-detection accuracy research log

Running record of an effort to push SMDA's function-start detection across every binary family it
supports, with a reproducible benchmark behind every number. Written as the work happens; the
oldest entries are at the top.

Every row in this document states the corpus, the sample count `n`, and the filter it was computed
under. The same corpus under two filters is two different populations, and a number quoted without
both has fabricated a regression here before.

## The harness

`tools/bench/run.py` runs one or more engines over one or more ground-truth corpora and prints
PPV / TPR / F1 per corpus. `tools/bench/summarize.py` re-aggregates saved results without
re-running anything, and diffs two result directories while refusing to pass a comparison in which
TPR fell.

```
tools/bench/run.py --corpus bao-x86 --engine smda,ghidra --filter paper --out results/
tools/bench/summarize.py results/ --compare baseline/ --mean macro
```

### Metric definitions

A detected function start is a true positive only on an exact address match. Per binary:

- `TPR = |detected ∩ truth| / |truth|`
- `PPV = |detected ∩ truth| / |detected|`
- `F1  = 2·TPR·PPV / (TPR + PPV)`

Corpus-level figures aggregate the per-binary rates, never pooled counts, in one of three ways —
all three are written to every result file and the printed table names which one it shows:

- `macro` — arithmetic mean of the per-binary rates. What this project's own accuracy tables use.
- `geometric` — geometric mean. What the origin paper's tables use, so that one bad binary is
  penalised rather than averaged away.
- `micro` — pooled counts. Answers "how many mistakes in total", not "how does a typical binary
  score".

### Ground-truth conventions

- **Thunks count as functions.** The ByteWeight corpus ships them in a separate `gt/thunk/` list;
  they are folded into the truth set. This is the corpus's own convention and the origin paper
  states it explicitly: the stubs are referenced by other code and consist of code themselves.
- **External functions do not.** An entry that exists only as an import offset has no body. Ghidra
  and IDA both list them with an `external` flag; the harness discards those.
- **Optimization filter.** `--filter all` keeps every build; `--filter paper` drops `Os`/`Od`/`Ox`,
  which is the population the published tables use. On the 32-bit ByteWeight set that is 68 versus
  34 binaries and the two differ by more than two points of PPV.
- **Bitness of a headerless sample** comes from its file name (`x64-` or `_64_` prefix, otherwise
  32-bit), because a dump carries no container to read it from. This is the corpus convention;
  what SMDA infers instead is measured separately below.

## Corpora

| key | what | n | truth source |
|---|---|---|---|
| `bao-x86` | ByteWeight PE, MSVC, 32-bit | 68 | compiler-derived extents + thunk list |
| `bao-x86-64` | ByteWeight PE, MSVC, 64-bit | 68 | compiler-derived extents + thunk list |
| `bao-x86-dumped` | same programs, PE headers stripped | 56 | as above |
| `bao-x86-64-dumped` | same programs, PE headers stripped | 56 | as above |
| `malpedia` | one memory dump per malware family | 57 | IDA databases plus manual labelling |


---

## 2026-08-24 — Harness validated against a recorded measurement

The harness was written independently of the evaluation this project used previously, so before
using it for anything it had to reproduce a number that already existed. SMDA **4.4.1** from PyPI,
measured through `tools/bench/run.py` with the module path recorded in every result file:

| config | filter | n | PPV | TPR | F1 | recorded 2026-07-31 |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | all | 68 | 89.717 | 97.627 | 93.335 | 89.717 / 97.627 / 93.335 |
| Bao byteweight msvc10-64 | all | 68 | 98.970 | 99.729 | 99.345 | 98.970 / 99.729 / 99.345 |
| Bao_Dumped msvc10-32-d | all | 56 | 88.245 | 97.213 | 92.321 | 88.245 / 97.213 / 92.321 |
| Bao_Dumped msvc10-64-d | all | 56 | 98.893 | 97.752 | 98.312 | 98.893 / 97.752 / 98.312 |
| Plohmann malpedia itw | all | 57 | 92.976 | 98.463 | 95.306 | 92.976 / 98.463 / 95.306 |
| Bao byteweight msvc10-32 | O1+O2 | 34 | 92.232 | 99.132 | 95.440 | 92.232 / 99.132 / 95.440 |

Every row matches to three decimals under both filters. Two independent checks agree with it: the
truth loader produces exactly 272 function starts for `msvs_whatever_32_O1_7z`, which is the count
the corpus's own labelling study records for that binary, and the bundled per-binary result files
from the origin evaluation re-aggregate into the paper's published table exactly.

**One harness bug was found and fixed before this reproduced.** The malpedia loader initially
declared every sample 32-bit. Three of the 57 are 64-bit dumps, and forcing them into 32-bit mode
cost recall *and* turned a 14-second corpus into a 20-minute one. The corpus marks those three with
an `x64-` name prefix; the loader now reads the bitness from the name, which is the rule the corpus
was labelled under.

## 2026-08-24 — Baseline on today's master

Commit `802e627`, SMDA 4.4.7, filter `all`, arithmetic macro mean.

| config | n | PPV | TPR | F1 | Δ F1 vs 4.4.1 | Δ TPR vs 4.4.1 |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | 68 | 92.041 | 97.872 | 94.713 | **+1.378** | +0.245 |
| Bao byteweight msvc10-64 | 68 | 99.080 | 99.838 | 99.454 | +0.109 | +0.109 |
| Bao_Dumped msvc10-32-d | 56 | 91.189 | 97.510 | 94.060 | **+1.739** | +0.297 |
| Bao_Dumped msvc10-64-d | 56 | 98.874 | 99.811 | 99.338 | **+1.026** | **+2.059** |
| Plohmann malpedia itw | 57 | 92.639 | 98.561 | 95.142 | **−0.164** | +0.098 |

Recall is up on all five. The one F1 regression is on the malware corpus and is a precision trade:
PPV fell 92.976 → 92.639 while TPR rose 98.463 → 98.561. Under this project's stated design
priority — completeness over precision — that is the intended direction, but it is the only config
where the accumulated work since 4.4.1 has cost anything, and it is recorded here rather than
averaged away.

---

## 2026-08-24 — A container header in the buffer settles what the byte probes guess

Measuring the memory-dump corpus with the bitness *withheld* — the configuration a caller gets
when they hand SMDA a dump and do not know what is in it — turned up a class of defect the
existing accuracy work had never looked at, because it is not an FEP heuristic at all. It is the
step before: deciding what instruction set the bytes are.

### The measurement that exposed it

`BitnessAnalyzer` reads the share of `0x48` bytes that introduce a REX.W-compatible opcode. Run
over every dump in the two corpora, against the bitness each corpus declares:

| corpus | n | probe agrees | probe disagrees |
|---|---|---|---|
| Bao_Dumped msvc10-32-d | 56 | 56 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 56 | 0 |
| Plohmann malpedia itw | 57 | 51 | **6** |

All six disagreements are in the same direction — a 32-bit image read as 64-bit — and three of
them (`bolek`, `corebot`, `heloag`) carry an intact PE32 header at offset 0 whose COFF machine
field says `0x14c`. The probe was overruling an authoritative answer that was sitting in the
buffer. The other three are genuinely headerless and remain a probe problem.

`corebot` is the sample the origin paper singles out for embedding a complete 64-bit PE inside a
data section; its outer header still says 32-bit, so reading the header gets it right for exactly
the reason the paper describes.

### The same class, one step earlier: which backend the buffer goes to

`Disassembler.disassembleBuffer` chose between backends by DEX magic and then by counting aligned
AArch64 return words. That density heuristic has a floor, so a small image falls under it. It is
not hypothetical — a real ARM64 Mach-O sample from the bundled Objective-See corpus is below it:

| `BlueNoroff_469fd8a280e8` | architecture | bitness | functions | status | time |
|---|---|---|---|---|---|
| routed by density (before) | intel | 32 | 1 | **timeout** | 60.0 s |
| routed by its Mach-O header | aarch64 | 64 | **6** | ok | **0.0 s** |

Locally built ARM64 artifacts reproduce it in both other containers: a 1 KB ARM64 PE recovered 0
functions as intel and is read correctly once the header decides, and the same for a small ARM64
ELF passed as raw bytes.

### The fix, and what it deliberately does not do

Both sites now ask the container first and fall back to the byte evidence when there is no
container to ask — which is what a headerless dump or shellcode gets, unchanged. A managed PE is
deliberately still routed to the intel backend: its CLR metadata is addressed by file offset, so a
mapped image cannot be read by the CIL backend and naming `cil` from the header alone would lose
the sample. That carve-out is pinned by a test against a real .NET fixture.

### Result — memory dumps, bitness withheld (`--bitness auto`), filter `all`

| corpus | n | PPV | TPR | F1 | ΔPPV | ΔTPR | ΔF1 |
|---|---|---|---|---|---|---|---|
| Plohmann malpedia itw | 57 | 92.495 | 98.306 | 94.961 | +0.056 | **+0.244** | **+0.155** |

TP +93, FP −64, FN −93. Exactly three of the 57 samples changed — the three with a PE header the
probe was overruling — and the other 54 are bit-identical. Precision and recall both rose; nothing
regressed.

The three headerless mis-probes (`geodo`, `hamweq`, `tinba`) are untouched by this change, by
construction: they carry no header, so there is nothing authoritative to consult. They are the
remaining half of the class and are on the agenda below.

### Sweep for the same class elsewhere

The signature is: *an authoritative container header is present in the buffer and a heuristic
decides instead.* Every site that answers a "what are these bytes" question was checked.

| site | verdict | evidence |
|---|---|---|
| `BitnessAnalyzer.determineBitness` | **fixed** | 3 malpedia dumps corrected; 112 headerless ByteWeight dumps unchanged |
| `Disassembler.disassembleBuffer` architecture selection | **fixed** | real ARM64 Mach-O sample the density probe misses; ARM64 PE and ELF reproduce it |
| ELF bitness from a headerless probe | checked, benign | a 32-bit x86 ELF is probed correctly both raw and mapped, so there is no failing case to fix |
| `disassembleUnmappedBuffer` / `disassembleFile` | not in class | both already dispatch through `FileLoader`, which reads the container |
| `AArch64Backend.probeBitness` | not in class | AArch64 is 64-bit by definition; nothing is being guessed |

One limitation is worth stating rather than leaving to be discovered: a **mapped** ELF does not
necessarily keep its header at the image base, so on that path the ELF reader can find nothing to
read. It fires for raw ELF bytes handed to `disassembleBuffer`, which is where the ARM64 ELF case
reproduces. Mapped PE and Mach-O images do keep their headers, which is where the corpus evidence
comes from.

---

## 2026-08-24 — One binary in the ByteWeight corpus is paired with the wrong ground truth

`msvs_whatever_32_Od_SfxSetup` scores F1 2.66 while its `O1`, `O2` and `Ox` siblings score 97.9,
97.7 and 97.7. Four independent facts say the truth file describes a different build:

- Its truth spans `0x401000`–`0x414d86`, and the binary's only executable section ends at
  `0x411000`. **181 of its 472 starts fall outside every executable section.** All 67 other
  binaries in the corpus, and all 68 in the 64-bit corpus, have zero.
- It has exactly 472 entries — the same count as the `O1` build's truth — while sharing only **4
  addresses** with it.
- SMDA recovers 279 functions spanning `0x401000`–`0x41088c`, a coherent region, and matches 10.
- The `O1` build's truth ends at `0x4104a6` and SMDA's last detection is `0x4104a6` exactly. The
  siblings fit their truth to the address; this one does not fit at all.

### What it costs

| corpus | filter | n | F1 | n | F1 with the sample dropped | Δ |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | all | 68 | 94.713 | 67 | 96.087 | **+1.374** |
| Bao_Dumped msvc10-32-d | all | 56 | 94.060 | 55 | 95.722 | **+1.662** |

Recall is hit harder than precision: TPR 97.872 → 99.301 on Bao 32. Since a recall drop is the hard
reject criterion for any accuracy change, a single mispaired binary depressing TPR by 1.4 points is
a measurement hazard, not a curiosity.

### What the harness does about it

`tools/bench/integrity.py` now checks every sample whose binary has a section table, and `run.py`
prints the result before it prints any metric — including the control, how many samples the check
could run on at all. A headerless dump names no sections, so the check does not apply there and
must not be read as a pass.

The exclusion is **off by default**: every published figure for these corpora includes this binary,
and a silently smaller population is not comparable with them. `--exclude-known-defects` turns it
on, and prints what it dropped and why.

### The same check on the malware corpus says something different

Twelve of the 47 checkable malpedia dumps hold some truth outside their executable sections, but
mostly a handful of addresses (0.1–2%). Two are substantial — `dyre` at 37.7% and `pandabanker` at
11.2%. That is not mispairing: it is what a packed sample looks like once it has unpacked itself
into a region the section table never marked executable. The check is a diagnostic there, not a
verdict, and is reported as such.

### Measured worse: a second REX-prefix statistic does not rescue the headerless cases

The bitness probe reads the share of `0x48` bytes that introduce a REX.W-compatible opcode. Its
premise is that in 32-bit code, where `0x48` is the complete instruction `dec eax`, the following
byte is unrelated. Histogramming the followers on the three headerless samples it gets wrong shows
why the premise fails: on `geodo` the top followers are `8b` (176), `89` (74), `8d` (53), `83` (37)
— `mov`, `mov`, `lea`, `add/sub imm8`. Those are ordinary 32-bit instructions following a real
`dec eax`, and they are also exactly the opcodes a REX.W prefix introduces. The probe is weak
precisely when `0x48` is code rather than data.

The obvious repair is a second statistic over `0x44`, `0x45`, `0x4C`, `0x4D`, which are REX bytes
selecting the extended register file in 64-bit code and `inc`/`dec esp`/`ebp` in 32-bit code —
instructions a compiler almost never emits. Measured over 169 dumps (112 ByteWeight, 57 malpedia),
observation floor 64:

| statistic | 32-bit (n=100–110) | 64-bit (n=59) |
|---|---|---|
| `0x48` share | min 0.042, p90 0.335, max 0.933 | min 0.863, p10 0.908, max 0.964 |
| `0x44/45/4C/4D` share | min 0.013, p90 0.094, max 0.268 | **min 0.089**, p10 0.184, max 0.649 |

**Rejected.** The proposed statistic separates the two classes *worse* than the one already in use:
its ranges overlap from 0.089 to 0.268, and 17 genuine 64-bit samples sit inside the band the six
failing 32-bit samples occupy. Used as a conjunction — require both statistics to clear a threshold
— any cut strong enough to reject the failing 32-bit samples also rejects real 64-bit ones, and
misreading a 64-bit image as 32-bit is the more damaging error of the two.

The existing threshold of 0.5 is well placed: it sits between the 32-bit p90 of 0.335 and the
64-bit p10 of 0.908.

**Ceiling on what is left here.** Three headerless samples out of 57 on one corpus, reachable only
under `--bitness auto`; under the corpus-declared configuration every published figure uses, the
remaining error is worth exactly nothing. Attacking it needs a different instrument — decoding
coverage in both modes rather than another byte statistic — and that is a larger change than the
prize justifies.

---

## 2026-08-24 — Building the corpora no public dataset covers

The evaluation this project inherited is one compiler on one platform: MSVC-built PE files, plus
memory dumps of the same, plus Windows malware. Everything the disassembler claims to support
beyond that — Go, .NET, Rust, GCC and Clang C/C++, MinGW PE — has never been measured for
function-start accuracy at all.

`tools/bench/build_corpus.py` builds four families from source and derives their ground truth from
what the *unstripped* artifact declares:

| family | ground truth | what is measured |
|---|---|---|
| `native` | symbol table of the unstripped link | the stripped twin |
| `go` | `go tool nm` reading the pclntab of the unstripped build | the stripped twin |
| `rust` | symbol table of the unstripped link | the stripped twin |
| `dotnet` | assembly metadata for CIL, symbols for the NativeAOT native image | the published artifact |

Stripping moves no code, so the two describe the same addresses.

### Conventions settled while building it

- **PLT0 is not a function.** The first entry of an ELF `.plt` is the lazy-binding trampoline: it is
  reached by falling out of a stub, never called, and no engine here reports it. Counting it would
  penalise every engine for correctly declining to call it a function. Every other `.plt`,
  `.plt.sec` and `.plt.got` entry is truth. The origin evaluation's ELF convention took every
  aligned `.plt` entry including the first; this is a deliberate divergence, recorded here.
- **A managed PE's method starts are its metadata's body RVAs**, not addresses — the CIL backend
  reports offsets into the file, which is a different address space from every other family here.
  The CIL and NativeAOT cells are therefore kept as separate rows rather than pooled.

---

## 2026-08-24 — .NET: two of the three shapes are exact, the third is the weakest family measured

Built corpus, `dotnet`, filter `all`. Truth for a managed assembly is every `MethodDef` row with a
non-zero RVA, mapped to a **file offset**, because that is the address space the CIL backend
reports in. Truth for the NativeAOT image is the symbol table of the `.dbg` companion the publish
emits beside the stripped binary.

| cell | kind | truth | detected | TP | FP | FN | PPV | TPR | F1 |
|---|---|---|---|---|---|---|---|---|---|
| framework-dependent | CIL | 564 | 564 | 564 | 0 | 0 | 100.00 | 100.00 | 100.00 |
| self-contained | CIL | 564 | 564 | 564 | 0 | 0 | 100.00 | 100.00 | 100.00 |
| readytorun | CIL | 564 | 564 | 564 | 0 | 0 | 100.00 | 100.00 | 100.00 |
| nativeaot | native | 5,749 | 7,664 | 5,625 | 2,039 | 124 | **73.40** | 97.84 | 83.87 |

Managed CIL is exact and uninteresting: metadata enumerates every method body, and the backend
reads it. **NativeAOT is a different problem entirely** — at PPV 73.40 it is the least precise
result of any corpus measured here, against 92.0 on the 32-bit ByteWeight set and 92.6 on the
malware corpus, and it is native x86-64 code reached through the ordinary intel path.

### ReadyToRun scores 100% because two thirds of its code is not looked at

The `readytorun` cell's perfect score is an artefact. Its `.text` is 110,080 bytes against 60,928
for the same program published without ReadyToRun — roughly 49 KB of precompiled native x86-64
code. SMDA sees the CLR header, routes the image to the CIL backend, reports the 564 CIL method
bodies, and never touches the native code.

The image declares that code outright. Its PE exception directory holds **626 `RUNTIME_FUNCTION`
entries** — an authoritative table of every precompiled method:

| routing | native functions recovered | PPV | TPR |
|---|---|---|---|
| default (CIL backend) | 0 | – | 0.00 |
| intel backend forced | 419 | 100.00 | 66.93 |

So the native code is recoverable, at perfect precision, and the default routing recovers none of
it. That is a design decision rather than a bug — a CIL report addresses methods by file offset and
a native report by virtual address, so the two cannot simply be merged — and it is recorded here
for the maintainer rather than changed.

### The missing third has a mechanism, and it is the same class as this branch's first fix

Forcing the intel backend recovers 419 of 626. `locateExceptionHandlerCandidates` finds the
exception table by looking for a **section named `.pdata`**. In a ReadyToRun image the table lives
in `.data`, and the code neither reads the PE exception *directory* — which names its address
outright — nor falls back to carving, because that fallback only runs when the image has no
sections at all.

Surveyed across every PE available here, with the corpus named for each figure:

| corpus | PEs | with an exception directory | of those, inside `.pdata` | elsewhere |
|---|---|---|---|---|
| ByteWeight msvc10-64 | 68 | 68 | 68 | 0 |
| ByteWeight msvc10-32 | 68 | 0 | – | – |
| malpedia (parseable PEs) | 48 | 3 | 3 | 0 |
| built .NET | 3 | 1 | 0 | **1** (626 entries, in `.data`) |

The frozen corpora do not exercise this path at all: MSVC always names the section `.pdata`. The
only corpus that reaches it is the one built for this work, which is precisely why it had never
been found.

---

## 2026-08-24 — Corpus inventory built

| family | cells built | cells failed | truth functions | notes |
|---|---|---|---|---|
| `dotnet` | 4 | 1 | 7,441 | the failure is `single-file`: the assembly is inside the apphost bundle and nothing here unpacks it |
| `go` | 45 | 2 | 162,621 | 3 programs × 7 GOOS/GOARCH × default/stripped/pie, plus a cgo axis |
| `rust` | 24 | 0 | 33,817 | 2 crates × 3 targets (linux-gnu, windows-gnu x64 and x86) × debug/release/release-lto/release-panic-abort |
| `native` | building | | | 10 programs × gcc/clang/mingw-x64/mingw-x86 × O0/O1/O2/O3/Os/static/no-pie |

A Go `stripped` cell is scored against the symbols of its unstripped twin, because `-ldflags="-s -w"`
removes exactly the table `go tool nm` reads. The builder asserts the two agree on the text
section's address and size before pairing them, and records `layout_moved` rather than pairing them
if they do not.

`single-file` not being scoreable is itself the finding: a .NET single-file publish embeds the
managed assembly inside a native apphost bundle, and nothing in this toolchain reaches the CIL
inside it.

### Controls for the exception-table change

Before measuring anything, the question "can this move an existing baseline at all" was answered
directly. Every PE fixture bundled with the test suite, decoded:

| fixture | exception directory | section holding it |
|---|---|---|
| `cxx_pe_gnu_xored` | yes | `.pdata` |
| `msvc_cxx_pe_xored` | yes | `.pdata` |
| `rust_pe_gnu_xored` | yes | `.pdata` |
| `dotnet_readytorun_pe_xored` | yes | **`.data`** |
| `cutwail`, `njrat`, `pe_export_label_test`, `msvc_cxx_pdb_pe`, `rust_pe_msvc_i686` | no | – |

For the three that already worked, the directory and the section-extent walk read the *same* number
of entries — 48, 7 and 1,666 respectively — so the two paths are not merely both non-empty, they
agree entry for entry. The only fixture where they differ is the one added for this change.

### The NativeAOT precision figure is partly a truth gap

PPV 73.40 on the NativeAOT image is the worst number in this whole evaluation, so before treating
it as a defect it was worth asking whether the truth is right. The image carries a second,
independent declaration of where its functions are: `.eh_frame`.

| source | function ranges |
|---|---|
| symbol table of the `.dbg` companion | 5,749 |
| `.eh_frame` FDE ranges | 6,513 |
| in both | 5,608 |
| union | 6,654 |

**702 of the 2,039 apparent false positives are ranges `.eh_frame` declares** — real function bodies
the symbol table does not name. Scored against the union instead:

| truth | PPV | TPR |
|---|---|---|
| symbol table only | 73.40 | 97.84 |
| symbols ∪ `.eh_frame` | **82.55** | 95.09 |

The corpus keeps the symbol-table truth, because SMDA *reads* `.eh_frame` itself as a candidate
source — using it as ground truth would score the disassembler against its own input. The right
reading is that the symbol-only precision is a **lower bound**: at least 702 of those false
positives are the disassembler correctly reading an authority the truth file omits, and roughly
1,337 remain genuinely unexplained. That 1,337 is the number worth attacking, not 2,039.

**A second lead falls out of the same measurement.** 326 of the 6,513 FDE-declared ranges are not
reported at all, and every one of them is inside an executable section — this image has two
non-standard ones, `__managedcode` (790 KB) and `__unbox`. SMDA reports 95% of what `.eh_frame`
declares here; the missing 5% is a recall question that is not specific to .NET and should be
checked against the C/C++ corpus, where symbol tables are complete enough to tell a truth gap from
a miss.

### A test bug worth recording: lief section objects do not own their parse

Writing the fallback test, `[section.name for section in lief.PE.parse(buffer).sections]` segfaulted
the interpreter. The parsed binary is a temporary; its section objects reference it and outlive it.
Binding each parse to a name fixes it. Nothing in the disassembler does this — every reader there
holds the parse — but it is an easy shape to write in a test and it fails as a crash rather than a
wrong answer.

---

## 2026-08-24 — Go: recall is essentially perfect, and precision depends on the architecture

Built corpus, `go`, 45 cells, 3 programs × 7 GOOS/GOARCH × default/stripped, plus PIE on the host
triple. Truth is `go tool nm` reading the pclntab of the unstripped build; a stripped cell is scored
against its twin after asserting both place `.text` at the same address and size.

| | n | PPV | TPR | F1 |
|---|---|---|---|---|
| whole corpus | 45 | 94.843 | 99.618 | 97.118 |

**Stripping costs nothing.** default 94.916 / 99.668 against stripped 94.939 / 99.668 over 21 cells
each. The pclntab survives `-ldflags="-s -w"` and the recovery that reads it does too, which is the
behaviour the design intends and had not previously been measured end to end.

### Precision is a function of the target architecture, and recall is not

Same three programs, same toolchain, same OS — only `GOARCH` differs:

| architecture | false positives | truth functions | FP per truth function |
|---|---|---|---|
| 386 | 375 | 21,691 | 0.0173 |
| amd64 | 1,196 | 32,565 | 0.0367 |
| **arm64** | **2,907** | 21,687 | **0.1340** |

Per program, `default` mode, precision:

| program | linux/amd64 | linux/arm64 | linux/386 | darwin/amd64 | darwin/arm64 |
|---|---|---|---|---|---|
| cryptozip | 96.346 | 87.914 | 98.870 | 94.569 | 92.891 |
| hello | 96.079 | 88.041 | 99.096 | 94.000 | 92.141 |
| netjson | 97.053 | **80.906** | 97.905 | 95.845 | 93.781 |

The AArch64 backend over-detects **3.6× more per function than the intel backend on identical
source**, and it does so on every program and both operating systems. Recall is unaffected — TPR is
100.000 on all six linux/arm64 cells.

### The extra detections are splits, not inventions

On `hello_linux-arm64_default`: 245 of 246 false positives (99.6%) fall **inside a real function's
span**. The amd64 build of the same program has 72 of 73 (98.6%) — the same shape, a third as often.
Nothing is being invented in data; real function bodies are being cut in two.

The two architectures cut in different places. On amd64 the commonest offset from the enclosing
function's start is **+4** (28 of 73). On arm64 the offsets are spread — 48, 176, 52, 56, 64, 60 —
which is deeper into the body than a prologue-shape mistake and looks like interior branch targets
being promoted to entries.

---

## 2026-08-24 — Rust: the least precise family, and the truth is not the reason

Built corpus, `rust`, 24 cells: 2 crates × {linux-gnu-x64, windows-gnu-x64, windows-gnu-x86} ×
{debug, release, release-lto, release-panic-abort}. Truth is the unstripped link's symbol table;
the corpus keeps the stripped twin.

| | n | PPV | TPR | F1 |
|---|---|---|---|---|
| whole corpus | 24 | **75.817** | 97.493 | 85.193 |

| target | n | PPV | TPR | FP per truth function |
|---|---|---|---|---|
| linux-gnu-x64 | 8 | 71.927 | 98.061 | 0.3941 |
| windows-gnu-x64 | 8 | 81.696 | 97.628 | 0.2133 |
| windows-gnu-x86 | 8 | 73.828 | 96.790 | 0.3093 |

For scale: the same measure on the 32-bit ByteWeight corpus is about 0.06, and on Go/amd64 0.037.

**The truth is complete.** The NativeAOT result made this worth checking: `.eh_frame` there named 764
ranges the symbol table omitted. On Rust it names *fewer* — 571 FDEs against 577 symbols on
`fmtheavy_linux-gnu-x64_release` — and the union equals the symbol truth exactly. The precision
figure is genuine over-detection.

### Where the false positives come from

95.3% are interior to a sized function body, so real bodies are being cut, not data invented.
Histogramming them by the candidate source that seeded them:

| cell | gap search | initial, no reference | initial with a call reference |
|---|---|---|---|
| `fmtheavy_linux-gnu-x64_release` (ELF) | 101 | **139** | 0 |
| `panicheavy_windows-gnu-x86_release` (PE) | 450 | 29 | 167 |

The 32-bit PE profile is the familiar one — gap search dominating, as the origin paper's own
reliability table shows. **The ELF x64 profile is not**: 139 of 253 are candidates seeded with no
reference pointing at them at all.

### 123 of those 139 are one byte pattern, four bytes inside a real function

Decoding the reference-less false positives on `fmtheavy_linux-gnu-x64_release`:

| first instruction | count |
|---|---|
| `push r15` | **123** |
| `push rbp` | 16 |
| `jmp qword ptr [rip + …]` | 9 (import stubs) |

`push r15` is the head of `41 57 41 56` — `push r15; push r14` — which is on the whole-binary
**seeded** prologue list. The four bytes immediately before all 123 are identical:

```
55 48 89 e5     push rbp; mov rbp, rsp
41 57 41 56     push r15; push r14      <- seeded as a separate function
```

and **120 of the 123 (97.6%) have a real function start exactly four bytes earlier**. The seeded
prologue is firing on the second instruction pair of a function whose first pair is itself a
prologue on the same list.

### The counterfactual the pattern registry asks for

Before changing a seeded prologue, the registry requires measuring seeded against scoring-only
directly. Counting the starts that **only** the seed found — no call reference, no symbol, not from
gap search, not an exception record or stub — over 18 sampled 64-bit binaries:

| corpus | seed-only true positives | seed-only false positives |
|---|---|---|
| Rust linux-gnu-x64 (4 cells) | 15 | 400 |
| Go darwin amd64/arm64 (4 cells) | 0 | 0 |
| ByteWeight msvc10-64 (6 cells) | 0 | 0 |
| ByteWeight msvc10-64 dumped (4 cells) | 0 | 0 |
| **total** | **15** | **400** |

Twenty-six false positives per uniquely recovered function — and **nothing at all on the MSVC
corpora**, so the seed's value is not coming from the corpus it was presumably added for.

**Removing the seed outright is nevertheless rejected**: those 15 are true positives nothing else
finds, and a recall drop on any corpus is the reject criterion regardless of what it does to
precision. The narrower rule — *do not seed a prologue match that begins exactly where another
seeded prologue match ends* — drops 33 to 123 false positives per Rust ELF cell and **zero true
positives**, and is inert on all eight mingw PE cells.

---

## 2026-08-24 — Go on AArch64: every true positive comes from the pclntab, and the extra candidates are the whole precision gap

Provenance of every recovered function on `hello_*_default`, by the candidate source that seeded it:

| cell | true positives | of those carrying a symbol | false positives | dominant false-positive source |
|---|---|---|---|---|
| linux/amd64 | 1,789 | **1,789 (100.0%)** | 73 | gap search, 72 |
| linux/386 | 1,864 | **1,864 (100.0%)** | 17 | gap search, 15 |
| windows/amd64 | 1,848 | **1,848 (100.0%)** | 50 | gap search, 49 |
| linux/amd64 stripped | 1,789 | **1,789 (100.0%)** | 72 | gap search, 72 |
| **linux/arm64** | 1,811 | 1,811 (100.0%) | **246** | **tailcall, 170** |

On a Go binary the pclntab names every function, and it is recovered. **No other candidate source
contributes a single true positive on any architecture** — every one of them contributes only false
positives. The stripped cell is identical, because `-ldflags="-s -w"` leaves the pclntab in place.

The arm64 excess is not gap search. 170 of its 246 false positives are **tailcall candidates**, a
source that contributes 0 on the intel cells. Their first instructions are `sub` (91), `adrp` (58),
`ldr` (30) — mid-function shapes, not entries.

### The mechanism is an asymmetry between the two backends

`SmdaConfig.RESOLVE_TAILCALLS` is `False` by default, and the shared engine honours it —
`RecursiveDisassembler` gates both of its tailcall paths on the flag. The AArch64 backend calls
`addTailcallCandidate` from two sites of its own, and neither consults it: one when an unconditional
branch targets code before the current entry or comes from a short no-frame stub, the other on a
`bl` fall-through boundary.

Go is exactly the code that makes this expensive: it branches backwards within a function
constantly, and its runtime calls are `bl` followed by more of the same function.

**Ceiling.** Suppressing tailcall-seeded candidates that fall inside a symbol-declared function
would remove roughly 170 of 246 false positives per Go arm64 binary — 2,907 across the six arm64
cells — taking false positives per truth function from 0.134 towards 0.045 and precision from 85.6
towards about 95, with recall untouched because recall on this family is entirely symbol-driven.
Whether that generalises beyond Go needs the frozen corpora, which have no AArch64 member; the
AArch64 fixtures in the test suite are the only local check.

### The exception-table change on the frozen corpora

Filter `all`, arithmetic macro mean, against the same tree without the change:

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP | ΔFN |
|---|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | 68 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao byteweight msvc10-64 | 68 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-32-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Plohmann malpedia itw | 57 | 0 | 0 | 0 | 0 | 0 | 0 |

The 32-bit sets cannot be reached at all — the path is gated on 64-bit — and every 64-bit sample
reads the identical table either way, which the fixture-level entry counts had already established:
all 68 ByteWeight x64 binaries and all 3 malpedia x64 dumps declare a table that lands inside a
section named `.pdata`, so the two ways of finding it name the same bytes.

A table of zeroes on its own is the shape a change that never ran also produces, so the claim rests
on the positive control beside it and not on this table: the same build, on the ReadyToRun image
whose table is in `.data`, goes from 419 functions to 627. The 5 × 0 says the change is confined to
images the old rule could not reach; the 419 → 627 says it reaches them.

**Result** on that image, scored against the 626 `RUNTIME_FUNCTION` starts its own directory
declares, intel backend:

| | detected | TP | FP | FN | PPV | TPR |
|---|---|---|---|---|---|---|
| before | 419 | 419 | 0 | 207 | 100.00 | 66.93 |
| after | 627 | **626** | 1 | **0** | 99.84 | **100.00** |

Every one of the 419 the old path recovered was already a declared start, and the new run recovers
all 626 declared starts, so the before set is contained in the after set and no recall was traded
for the gain. The one address outside the declaration is a function the table does not name, not a
start the old run had rejected.

**Survey — where the table actually lives**, over every corpus available here:

| population | n with a table | in `.pdata` | elsewhere |
|---|---|---|---|
| ByteWeight PE x64 | 68 | 68 | 0 |
| malpedia PE64 dumps | 3 | 3 | 0 |
| built .NET, ReadyToRun | 1 | 0 | 1 (`.data`, 626 entries) |

MSVC's own layout is the reason the section-name rule worked for as long as it did. The rule that
replaces it reads the address the image declares, and keeps the section-name walk for an image whose
directory is gone but whose section is not.

---

## 2026-08-24 — the harness asserted its own success and then wrote the assertion away

`run.py` counts every sample the engine did not complete, lists it, and refuses to report past
`--max-failures`. The result file it writes keeps each sample's status. Nothing downstream read it,
so `paper_table.py`, rebuilding the origin evaluation's table from those files, printed this:

```
GB  ByteWeight  msvc10-64    O1     17 | ... |  ghidra-12.1.3 TPR 0.000 PPV 0.000 |
```

One binary — `msvs_whatever_64_O1_vim`, 5,445 truth functions — exceeded the analysis budget after
420 s and was recorded `status=timeout`, `detected=0`. Scoring an incomplete run as 0 is the right
call, and the geometric mean the origin evaluation applies to an optimization-level row then carries
that zero into the cell. The arithmetic is correct and the presentation is not: `TPR 0.000` reads as
an engine that found nothing on 17 binaries rather than one that did not answer on one of them.

`paper_table.py` now marks such a cell `!k`, names the samples under the table, and counts them on
its control line. The number itself is left as computed — a cell that averaged a failure should look
wrong, it should just also say why.

This is the same failure mode as the frozen-corpus zeroes above, seen from the other side: there, a
table of zeroes needed a positive control to mean anything; here, a single zero needed the reason
printed beside it.

### Ghidra's budget is a choice this harness makes

The per-file analysis timeout is whatever `--timeout` says, defaulting to SMDA's own so both engines
get the same budget. That is defensible for a comparison and it is still a choice, and on the
largest binary in the corpus it decided the result. Recorded here so that the Ghidra column is read
as *Ghidra under this budget*, not as Ghidra.

---

## 2026-08-24 — an AArch64 corpus, and the truth it needed before it meant anything

The frozen corpora are x86 and x86-64 only, and the Go family's ARM64 cells share one compiler, so
every AArch64 statement so far rested on one population. The repository already carries a second:
`tests/aarch64_macho_corpus`, twelve real ARM64 Mach-O binaries. Each declares its own function
starts in `LC_FUNCTION_STARTS`, written by the linker and contributed to by no disassembler, so the
corpus arrives with ground truth attached and needs no download and no toolchain. Eleven are usable;
the twelfth carries the load command with nothing in it and is skipped and named in the manifest,
because an empty truth set scores every detection as a false positive and reads as a catastrophic
result rather than as missing truth.

**The first measurement was wrong, and the number was spectacular enough to be worth checking.**

| | PPV | TPR | F1 | truth | detected |
|---|---|---|---|---|---|
| `LC_FUNCTION_STARTS` alone | **39.901** | 94.008 | 51.401 | 2,056 | 2,900 |
| after the correction below | **93.986** | 95.616 | 94.381 | 2,753 | 2,747 |

A precision of 39.9 would have been by far the worst result anywhere in this work, and the histogram
said why immediately. On `osx.frostyferret`, 127 of 129 false positives were in `__stubs`; on
`osx.poseidonstealer`, 21 in `__stubs` and 125 in `__objc_stubs`; on `Kitty`, 27 and 28. These are
import and message trampolines — the Mach-O counterpart of an ELF PLT entry — and this harness'
own stated convention is that a thunk is a function. `LC_FUNCTION_STARTS` does not name them.

Two different repairs, because the two sections are not equally declared:

- **`__stubs` is truth.** The section's type is `S_SYMBOL_STUBS` and its `reserved2` field carries
  the stride, the exact counterpart of an ELF section's entry size. The entries are derived from the
  image's own declaration, not from a byte pattern. SMDA finds every one: 127 of 127 on frostyferret,
  27 of 27 on Kitty, 21 of 21 on poseidonstealer.
- **`__objc_stubs` is not scored.** An ObjC message stub is as much a function as an import stub, but
  the section is `S_REGULAR`, nothing in the image declares its stride, and inferring one from what
  the disassembler found would let the tool define its own truth. The corpus declares a scored region
  — `__text` plus the declared stub sections — and 153 detections landing outside it are counted and
  reported rather than judged.

The scored region is a harness mechanism, not a corpus footnote: `scoreSample` takes it, drops the
out-of-scope detections, and records how many it dropped, because a scored region that quietly
shrank reads exactly like precision that rose.

### What the corrected corpus then says

| sample | truth | detected | TP | FP | FN | PPV | TPR |
|---|---|---|---|---|---|---|---|
| osx.gimmick | 1,087 | 1,156 | 930 | 226 | 157 | 80.45 | 85.56 |
| RustyPages | 556 | 503 | 501 | 2 | 55 | 99.60 | 90.11 |
| LockBit | 481 | 470 | 462 | 8 | 19 | 98.30 | 96.05 |
| osx.frostyferret | 274 | 246 | 244 | 2 | 30 | 99.19 | 89.05 |
| osx.poseidonstealer | 89 | 84 | 81 | 3 | 8 | 96.43 | 91.01 |
| JokerSpy | 83 | 85 | 83 | 2 | 0 | 97.65 | 100.00 |
| osx.interception | 58 | 58 | 58 | 0 | 0 | 100.00 | 100.00 |
| osx.amodaltea | 51 | 52 | 51 | 1 | 0 | 98.08 | 100.00 |
| osx.hloader | 35 | 35 | 35 | 0 | 0 | 100.00 | 100.00 |
| Kitty | 34 | 53 | 34 | 19 | 0 | 64.15 | 100.00 |
| BlueNoroff | 5 | 5 | 5 | 0 | 0 | 100.00 | 100.00 |

Macro 93.986 / 95.616 / 94.381; micro 90.426 / 90.229 over 2,753 truth functions.

**The finding is recall, not precision.** Every sample under 90 truth functions is recovered
completely, and every sample above it is not: 157 missed on gimmick, 55 on RustyPages, 30 on
frostyferret, 19 on LockBit. Micro recall is **90.2** against 99.8 on the 64-bit ByteWeight set —
the largest recall gap between two architectures measured anywhere in this work, and the opposite
of what the Go corpus suggested, where recall is essentially perfect because the pclntab names every
function and SMDA reads it. Strip the symbol oracle away, as these binaries do, and AArch64 recovery
falls a long way behind intel recovery on comparable code.

That is now the top AArch64 item, ahead of the tailcall precision work: the tailcall finding is worth
about 170 false positives per Go arm64 binary, and this is worth 10 points of recall on real code.

### Where the AArch64 recall goes, on one binary

`osx.frostyferret`, 274 truth functions, 30 missed. Each miss classified by whether a detected
function's span already covers it:

| class | n | shape |
|---|---|---|
| swallowed by the function before it | 16 | runs of uniformly sized functions merged into one |
| never analysed at all | 8 | one-instruction `b` veneers |
| other | 6 | — |

**Swallowed.** `0x100008900` absorbs eight declared functions at `0x100008950`, `0x1000089a0`, …,
spaced exactly 0x50 apart; `0x100008cac` absorbs seven more. The merge point is a call:

```
0x10000894c: bl   #0x100008470
0x100008950: sub  sp, sp, #0x40      <- declared function start
```

The callee does not return, the caller therefore has no `ret`, and decoding runs straight on into the
next function. The AArch64 backend has a rule for exactly this — `analyzeInstruction` checks for a
`bl` as the previous instruction and asks `_callFallthroughFunctionStart` for a boundary — and it
declines here. The mechanism exists and its predicate is too strict; that is a much better starting
point than a missing feature.

**Veneers.** A run of one-instruction branch islands, and the split is not random:

```
0x100007abc: b #0x10000642c   missed        0x100007ad4: b #0x10000643c   missed
0x100007ac0: b #0x10000642c   missed        0x100007ad8: b #0x10000643c   missed
0x100007ac4: b #0x10000642c   missed        0x100007adc: b #0x10000643c   missed
0x100007ac8: b #0x10000642c   missed        0x100007ae0: b #0x10000643c   missed
0x100007acc: b #0x100006400   found         0x100007ae4: b #0x100007aec   found
0x100007ad0: b #0x100007984   found         0x100007ae8: b #0x100007aec   found
```

Twelve adjacent single-instruction functions, all declared; the eight that branch to `0x10000642c`
or `0x10000643c` are never analysed and the four that branch elsewhere are. Duplication is not the
rule — `0x100007ae4` and `0x100007ae8` share a target and both are found — so it is something about
those two targets. Not yet run down.

Neither class is a scoring artefact: all 30 are `LC_FUNCTION_STARTS` entries and none is a stub whose
address this work derived.

---

## 2026-08-24 — the C/C++ matrix is complete

260 of 260 cells, no failures, 203,351 truth functions of which 10,090 are PLT entries. Ten programs
(sqlite3, lua, zlib, xxhash, cjson, lz4, brotli, googletest, tinyxml2, miniz) across four toolchains
and seven build variants:

| axis | values |
|---|---|
| toolchain | gcc-x64 (70), clang-x64 (70), mingw-x64 (60), mingw-x86 (60) |
| variant | O0, O1, O2, O3, Os, O2-static (40 each), O2-nopie (20, ELF only) |

The last seven failures were zlib under clang: `gzwrite.c` reaches for `write()` and `close()` only
when told the header is there, and clang rejects an implicit declaration outright. zlib's own
configure defines `HAVE_UNISTD_H`; the recipe now does too. Recording this because the manifest is
the only thing that distinguishes a matrix that shrank from one that passed, and 253 of 260 read as
a complete run everywhere except in the manifest.

### Why the existing fall-through rule declines, and what would have to change

`_callFallthroughFunctionStart` accepts a boundary after a `bl` in three cases: the fall-through
address is already a candidate; NOP padding was skipped and the address after it is a candidate; or
NOP padding was skipped and the address after it is 16-aligned. At `0x100008950` none holds — the
next function begins immediately, with no padding, and nothing had made it a candidate.

The word there is `sub sp, sp, #0x40`, and `is_function_prologue` deliberately does not recognise
that shape: a bare stack adjustment is as common inside a function as at its head, which is the same
reason the intel side scores `sub rsp, imm8` but never seeds on it. So the one-word test cannot be
widened here without the false positives it was written to avoid.

What is unambiguous is the *sequence*:

```
sub  sp, sp, #0x40
stp  x20, x19, [sp, #0x20]
stp  x29, x30, [sp, #0x30]
add  x29, sp, #0x30
```

A stack allocation, callee-saved stores into the frame it just made, and the frame-pointer
establishment. Read as four words rather than one it is not ambiguous at all, and the place it would
be consulted is narrow: only at a `bl` fall-through, never scanned across the image. The risk to
quantify before landing it is how often a mid-function `bl` is followed by that whole sequence, which
is a counterfactual the Go arm64 and Mach-O corpora can both answer.

Recorded as the next AArch64 item; not implemented yet.

---

## 2026-08-24 — the no-return call boundary, measured

The sequence from the previous entry, turned into a predicate and measured before being wired in.

**Counterfactual first.** Over every `bl` in every ARM64 Mach-O sample, how often does the
fall-through address open a frame — `sub sp, sp, #imm` followed within three instructions by
`stp x29, x30, [sp, #imm]` — and when it does, is that address a declared function start?

| population | `bl` instructions | predicate fires | declared start | not declared |
|---|---|---|---|---|
| ARM64 Mach-O, 7 of 11 samples | 14,273 | 47 | **47** | **0** |
| Go arm64, 12 cells | 55,964 | 0 | 0 | 0 |

Forty-seven fires, forty-seven declared starts, no misfires. The Go population is the inertness
control rather than a second confirmation: Go's callees return and its prologue is the pre-indexed
form, so the predicate never fires there and cannot cost anything. The confirming samples span both
upstreams the corpus draws on — Kitty, LockBit and RustyPages from one, frostyferret, gimmick,
interception and poseidonstealer from the other.

**Why a two-word test and not a one-word one.** `sub sp, sp, #imm` alone is exactly as common inside
a function as at its head, which is why `is_function_prologue` refuses it and why the intel side
scores `sub rsp, imm8` but never seeds on it. The frame record stored into the frame that allocation
just made is what removes the ambiguity: nothing mid-function re-saves the incoming link register
into a frame it has only now created.

**Result**, ARM64 Mach-O corpus, n=11, filter `all`, arithmetic macro mean:

| | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| before | 93.986 | 95.616 | 94.381 | 2,484 | 263 | 269 |
| after | 94.008 | **96.345** | 94.778 | **2,512** | **263** | **241** |

Twenty-eight true positives gained and **not one false positive added** — the false-positive count is
identical, which is the control that the rule fires only where it was measured to.

On `osx.frostyferret` alone the misses go 30 to 15, and the fifteen recovered are exactly the run
`0x100008950` through `0x100008f08` that `0x100008900` and `0x100008cac` had swallowed. Those fifteen
addresses are pinned by a test against that fixture, which is in the repository already.

### The corpus can be made circular, and must not be

SMDA can already be told to read `LC_FUNCTION_STARTS` as a candidate source, through
`SmdaConfig.USE_MACHO_FUNCTION_STARTS`, which is off by default. That is the same table this corpus
uses as ground truth. Measured with the option on, the corpus scores the engine against the answer
key it was handed and the number means nothing.

Every figure recorded from this corpus is measured with the default, and the builder and the harness
README both say so. Worth stating rather than assuming, because the option exists, is one line to
flip, and would turn a 96.3 into a much better-looking figure that measured nothing.

It also gives the boundary rule an independent check. The bundled fixture test that pins this image
compares the primary pass against the primary pass plus the table:

| | functions | of which the table declares |
|---|---|---|
| before, table pass off | 246 | 117 |
| after, table pass off | **261** | **132** |
| before and after, table pass on | 275 | 146 |

The total with the table pass on is unchanged. The primary pass now discovers by itself fifteen of
the entries the table was compensating for, which is the same fifteen the boundary rule cuts — two
different routes to the same addresses, agreeing. The frozen baseline moves from 246 to 261 and 117
to 132 as a deliberate consequence, recorded in the test itself.

---

## 2026-08-24 — the interior prologue rule, measured

Applied and measured against the same tree without it. Filter `all`, arithmetic macro mean.

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP | ΔFN |
|---|---|---|---|---|---|---|---|
| Built Rust (gnu targets) | 24 | **+3.134** | +0.000 | **+1.992** | 0 | **−790** | 0 |
| Built .NET (CIL + NativeAOT) | 4 | +0.240 | +0.000 | +0.156 | 0 | −99 | 0 |
| Built Go (pclntab truth) | 45 | 0 | 0 | 0 | 0 | 0 | 0 |
| ARM64 Mach-O | 11 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao byteweight msvc10-32 | 68 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao byteweight msvc10-64 | 68 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-32-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 0 | 0 | 0 | 0 | 0 | 0 |
| Plohmann malpedia itw | 57 | +0.003 | +0.000 | +0.002 | 0 | −1 | 0 |
| Built C/C++ (gcc, clang, mingw) | 260 | +0.034 | +0.000 | +0.017 | 0 | −22 | 0 |

912 false positives removed across ten corpora and **not one true positive anywhere**, which is what
the counterfactual predicted: the seed contributes 15 unique true positives and 400 unique false
positives on the Rust set, and the rule refuses only matches that begin exactly where an earlier
seeded match ends. Rust goes from the lowest precision measured here to 78.951.

The C/C++ corpus barely moves — 22 false positives over 260 binaries — even though it is built by the
same clang that produces the Rust adjacency. That is worth stating rather than smoothing over: the
pattern needs the two prologues to land back to back, which Rust's code generation produces far more
often than C or C++ does.

The rule cannot fire on the MSVC corpora at all — `push r15; push r14` after `push rbp; mov rbp, rsp`
is a clang and gcc idiom — and the single malpedia false positive it removes is the one place the
frozen sets touch it. Go and the ARM64 corpus are untouched because neither compiles through this
path in a way that produces the adjacency.

Thirty bundled fixtures produce byte-identical function sets either side, which is the regression
control; the positive control is a synthetic buffer where the interior match is seeded without the
rule and not with it, while a standalone match of the same pattern is seeded in both.

---

## 2026-08-24 — the origin evaluation's table, re-measured

Six of the seven rows now carry a measured Ghidra column beside the recorded one. Geometric mean per
optimization level for the split rows, arithmetic mean for the rest, exactly as the origin evaluation
aggregates them.

| row | opt | n | ghidra 9.1.2 (recorded) | ghidra 12.1.3 (measured) | smda 1.2.5 (recorded) | smda 4.4.7 (measured) |
|---|---|---|---|---|---|---|
| ByteWeight msvc10-32 | O1 | 17 | 0.804 / 0.952 | 0.817 / 0.953 | 0.992 / 0.935 | 0.994 / 0.938 |
| ByteWeight msvc10-32 | O2 | 17 | 0.809 / 0.950 | 0.822 / 0.951 | 0.992 / 0.927 | 0.994 / 0.932 |
| ByteWeight msvc10-64 | O1 | 17 | 0.675 / 0.999 | incomplete | 0.975 / 0.983 | 0.998 / 0.993 |
| ByteWeight msvc10-64 | O2 | 17 | 0.703 / 0.999 | 0.809 / 0.999 | 0.972 / 0.981 | 0.998 / 0.993 |
| ByteWeight* msvc10-32 | – | 56 | 0.775 / 0.953 | 0.777 / 0.953 | 0.967 / 0.910 | 0.975 / 0.912 |
| ByteWeight* msvc10-64 | – | 56 | 0.653 / 0.999 | 0.663 / 0.999 | 0.932 / 0.985 | 0.998 / 0.989 |

TPR / PPV. The `O1` 64-bit Ghidra cell holds one binary the engine did not finish inside the analysis
budget; it is marked and named rather than printed, for the reasons recorded above. The seventh row,
the malware corpus, is still running under Ghidra and prints `not measured` rather than a blank until
it lands.

**This is the harness validating itself against a second engine.** Ghidra 12.1.3 lands within 0.002
to 0.013 of the figures recorded for Ghidra 9.1.2 on four of the five comparable cells — a different
tool, a different decade, and the same metric implementation reproducing the published numbers. The
earlier validation showed SMDA 4.4.1 reproducing a recorded SMDA measurement; this shows the metric
is not tuned to one engine's output shape.

It also says something about the two tools. Ghidra has moved very little on these corpora in five
years — the largest change on a comparable cell is +0.013 recall. SMDA has moved a great deal, and
almost all of it on the hardest row: **the dumped 64-bit set goes from 0.932 recall to 0.998**, +6.6
points, where the unpacked sets were already near their ceiling.

---

## 2026-08-24 — the C/C++ matrix, measured

260 binaries, ten programs, four toolchains, seven build variants, 213,441 truth functions including
10,090 PLT entries. Filter `all`, arithmetic macro mean, at the commit that lands the interior
prologue rule:

| corpus | n | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | 91.878 | 95.523 | 93.428 | 202,669 | 26,702 | 10,772 |

**Recall is 95.523 here against 97.872 on the 32-bit ByteWeight set and 99.838 on the 64-bit one.**
That is the closest comparison available — the same kind of program, the same metric, a different set
of compilers — and it says the recall the published figures show is a property of the corpus as much
as of the disassembler. ByteWeight is one compiler at four optimization levels; this is three
compilers at seven build configurations, and it costs two to four points of recall.

**By toolchain**, arithmetic macro mean, and false positives per truth function:

| toolchain | n | PPV | TPR | F1 | FP/truth |
|---|---|---|---|---|---|
| clang-x64 | 70 | 95.115 | 97.116 | 95.993 | 0.0849 |
| gcc-x64 | 70 | 92.272 | 96.809 | 94.086 | 0.1562 |
| mingw-x64 | 60 | 90.041 | 98.190 | 93.741 | 0.1195 |
| **mingw-x86** | 60 | 89.481 | **89.499** | 89.353 | 0.1371 |

`mingw-x86` loses nearly nine points of recall against every other cell in the matrix, on identical
source. It is the only 32-bit member and the only one where recall, not precision, is the limit. The
32-bit ByteWeight set does not show this — 97.872 there — so it is not 32-bit code as such but 32-bit
code from this toolchain.

**By build variant:**

| variant | n | PPV | TPR | F1 | FP/truth |
|---|---|---|---|---|---|
| O0 | 40 | 92.431 | 99.164 | 95.517 | 0.1003 |
| O1 | 40 | 91.471 | 97.923 | 94.143 | 0.1483 |
| O2 | 40 | 91.114 | 93.031 | 91.888 | 0.1290 |
| O3 | 40 | 90.110 | 92.599 | 91.093 | 0.1560 |
| Os | 40 | 94.089 | 97.449 | 95.504 | 0.0941 |
| O2-static | 40 | 90.374 | 92.591 | 91.358 | 0.1361 |
| O2-nopie | 20 | 95.241 | 96.290 | 95.555 | 0.1057 |

Recall falls monotonically with optimization from `O0` (99.164) to `O3` (92.599), and `Os` — which
optimizes for size rather than speed, and so inlines and unrolls far less — sits back up at 97.449.
That is the inlining and tail-merging the origin evaluation predicted would be the hard case,
measured here across three compilers for the first time.

**Worst cells**, all one program:

| cell | truth | PPV | TPR |
|---|---|---|---|
| googletest_mingw-x86_O3 | 1,201 | 54.10 | 63.78 |
| googletest_mingw-x86_O2 | 1,196 | 60.16 | 64.88 |
| googletest_gcc-x64_O3 | 1,273 | 53.59 | 83.27 |
| googletest_gcc-x64_O1 | 1,113 | 52.38 | 94.88 |
| googletest_gcc-x64_Os | 1,194 | 52.06 | 99.58 |
| googletest_gcc-x64_O2-nopie | 1,281 | 58.77 | 84.23 |

googletest is a C++ template-heavy static framework linked without any tests, so most of its code is
dead and nothing inside the binary calls it. It is the hardest artefact in the corpus by a wide
margin and it is where the `endbr64` mechanism below was found.

---

## 2026-08-24 — the biggest precision mechanism in the C/C++ corpus: `endbr64` is not a function start

The worst cell in the 260-binary matrix is `googletest_gcc-x64_Os`: 1,194 truth functions, **2,284
detected**, PPV 52.06 at TPR 99.58. Nearly twice as many functions reported as exist.

Truth first, as always. `.eh_frame` in the same binary declares 842 ranges against the 843 the truth
holds in `.text`, and **none of the 1,095 false positives is FDE-declared**. The truth is right and
the over-detection is real.

Then the histogram. Of those 1,095 false positives:

| property | count |
|---|---|
| first instruction is `endbr64` | **1,085** |
| exactly two instructions long | 588 |
| ≥64 bytes past the nearest preceding declared start | 1,077 |
| carrying any symbol of any kind | 0 |

`endbr64` is a CET landing pad, and `locatePrologueCandidates` seeds every one it finds. But a
landing pad marks *every indirect-branch target*, not every function: under `-fcf-protection` gcc
emits one at each jump-table destination, so a `switch` in a hot function produces a dozen of them
inside a single function body. Seeding them all books a function at each one.

**Corpus-wide, by byte scan alone** — every `endbr64` in `.text` across the 140 ELF cells, against
what the truth declares:

| | count |
|---|---|
| `endbr64` occurrences in `.text` | 69,971 |
| at a declared function start | 54,985 |
| **not at one** | **14,986 (21.4%)** |

Split by toolchain, 12,564 of the 14,986 are gcc's and 2,422 are clang's — gcc marks jump-table
targets far more liberally. The whole C/C++ corpus holds 26,702 false positives, so this one pattern
bounds more than half of them.

**Proposed rule, not yet measured:** seed an `endbr64` only where the bytes before it end a function
or pad between functions — a `ret`, an unconditional `jmp`, `int3` padding, or `nop` padding. A
jump-table landing pad is preceded by ordinary instruction bytes and would be refused. This is the
same shape of argument as the interior-prologue rule that landed above: the pattern is real, its
*position* is what disqualifies it.

**Ceiling:** up to 14,986 false positives on the C/C++ corpus, worth roughly +5 to +7 PPV there, with
recall untouched if the rule only ever refuses. The counterfactual to run before implementing is the
one the prologue rule got: how many of those 14,986 does the proposed predicate refuse, and how many
declared starts would it refuse with them.

### Measured worse: every byte-level test for an `endbr64`'s role

The proposed rule was to seed an `endbr64` only where the bytes before it end a function or pad
between functions. Cross-tabulated against the truth over all 140 ELF cells — how many spurious pads
each variant refuses, against how many declared function starts it would refuse with them:

| variant | refuses spurious | costs declared | ratio |
|---|---|---|---|
| padding only (`int3`, `nop` forms) | 13,689 | 15,737 | 0.87 |
| 16-byte aligned | 13,319 | 14,149 | 0.94 |
| 16-aligned **and** (`ret` or padding) | 14,027 | 15,727 | 0.89 |
| `ret` or padding | 13,009 | 3,418 | 3.81 |
| 16-aligned **or** (`ret` or padding) | 12,301 | **1,840** | 6.69 |

The best variant still refuses 1,840 real function starts, and a recall drop is the reject criterion.
**All of them rejected.**

The reason is structural, not a matter of tuning the byte set. A jump-table case body commonly ends
in `jmp <shared epilogue>` and the next case's landing pad follows it, so "preceded by a terminator"
describes an interior pad as accurately as it describes a function entry. In the other direction, a
function whose predecessor ends in a call to something that does not return has no terminator before
it at all — the same shape the AArch64 boundary rule was written for. The two populations are not
separable by the bytes in front of them.

What does separate them is what the address *is used as*: a landing pad is the target of an indirect
branch from inside a function, and a function entry is the target of a call. SMDA computes jump
tables during analysis and knows their targets. So the repair belongs after analysis, as a filter on
candidates the jump-table pass has already claimed, not before it as a filter on bytes — which is the
same lesson as the interior-prologue rule from the other side: there, position among already-admitted
candidates was the discriminator; here, role among already-resolved branch targets has to be.

### Measured worse: refusing a reference-less `endbr64`

If the bytes in front cannot decide it, perhaps the references into it can. On the worst cell the
split looked decisive:

| | count | with a code reference into them |
|---|---|---|
| false positives | 1,095 | **0 (0.0%)** |
| true positives | 1,189 | 689 (57.9%) |

Not one of the 1,095 spurious pads is referenced by any code the analysis recovered, and more than
half the real functions are. The rule that suggests itself: refuse a candidate that begins with
`endbr64` and has no reference into it.

Measured over four cells chosen to span toolchains and programs:

| cell | false positives | would drop | true positives | would drop |
|---|---|---|---|---|
| googletest_gcc-x64_Os | 1,095 | 1,085 | 1,189 | **498** |
| sqlite3_gcc-x64_O2 | 9 | 0 | 1,891 | **653** |
| lua_clang-x64_O2 | 5 | 0 | 704 | 4 |
| brotli_gcc-x64_O1 | 26 | 0 | 332 | 59 |
| **total** | 1,135 | **1,085** | 4,116 | **1,214** |

It removes fewer false positives than it removes real functions. **Rejected.**

The reason the first table was so persuasive and so misleading: googletest is a static test framework
linked without any tests, so most of its code is never called from inside the binary. A real function
there is as reference-less as a spurious pad, and the rule cannot tell them apart. sqlite3 makes the
same point louder — 653 real functions with no internal caller, and no false positives to trade for
them.

Two rejected repairs on the same finding, from opposite directions, both because the discriminator
was assumed rather than measured. What is left is the one thing neither test looks at: whether the
address is the target of an indirect branch the jump-table pass resolved. SMDA computes that during
analysis and does not surface it in a report, so confirming it needs instrumentation rather than
another counterfactual over existing output.

### Blocked: an AArch64 build corpus

clang here can target `aarch64-linux-gnu` and lld links it, and a freestanding program built that way
comes out as a real ARM64 ELF with a real symbol table. Nothing beyond that works: there are no
AArch64 libc headers or sysroot installed, so every project in the C/C++ matrix fails at the first
standard header, and linking with unresolved symbols would leave the intra-project call graph intact
but the library calls pointing at zero.

So the AArch64 evidence here is the Mach-O corpus and the Go arm64 cells, and neither is a build
matrix: one platform and one linker on one side, one compiler on the other. Recorded as a block
rather than worked around, because a synthetic generated program would have been easy to produce and
would have measured the generator's idea of a function rather than a compiler's.

---

## 2026-08-24 — re-verifying every published figure

Every number in the report's tables re-derived from the result files rather than from the notes that
produced them:

```
[control] checked 33 published figures against the result files; mismatches: 0
```

The check covers the five per-family rows (PPV, TPR, F1 and truth count each), the five frozen
corpora, and the three micro figures the AArch64 argument rests on. It is worth running rather than
trusting, because every one of those numbers passed through prose at least once between the run that
produced it and the table that prints it, and a figure that is only ever compared against the
sentence it was copied into cannot disagree with anything.

### The boundary rule against every other corpus

The measurement above is on the corpus the rule was written for. Against the same tree without it,
over every other corpus in the harness:

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|---|
| ARM64 Mach-O | 11 | +0.023 | **+0.729** | +0.397 | **+28** | **0** |
| Bao byteweight msvc10-32 | 68 | 0 | 0 | 0 | 0 | 0 |
| Bao byteweight msvc10-64 | 68 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-32-d | 56 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 0 | 0 | 0 | 0 | 0 |
| Plohmann malpedia itw | 57 | 0 | 0 | 0 | 0 | 0 |
| Built Go (pclntab truth) | 45 | 0 | 0 | 0 | 0 | 0 |
| Built Rust (gnu targets) | 24 | 0 | 0 | 0 | 0 | 0 |
| Built .NET (CIL + NativeAOT) | 4 | 0 | 0 | 0 | 0 | 0 |

Eight of the nine are bit-identical, which is what an AArch64-only change should look like: seven of
them are intel and the eighth, Go on arm64, is the population where the static counterfactual said
the predicate fires zero times in 55,964 `bl` instructions. The measured run agrees with the static
count exactly.

---

## 2026-08-24 — where every corpus stands at the end of this branch

One run of the whole harness at the last commit. Filter `all`, arithmetic macro mean.

| corpus | n | PPV | TPR | F1 | truth | detected |
|---|---|---|---|---|---|---|
| Bao byteweight msvc10-32 | 68 | 92.041 | 97.872 | 94.713 | 110,195 | 115,792 |
| Bao byteweight msvc10-64 | 68 | 99.080 | 99.838 | 99.454 | 108,187 | 109,584 |
| Bao_Dumped msvc10-32-d | 56 | 91.189 | 97.510 | 94.060 | 108,486 | 114,162 |
| Bao_Dumped msvc10-64-d | 56 | 98.874 | 99.811 | 99.338 | 106,679 | 108,455 |
| Plohmann malpedia itw | 57 | 92.643 | 98.561 | 95.144 | 21,924 | 24,270 |
| Built C/C++ (gcc, clang, mingw) | 260 | 91.878 | 95.523 | 93.428 | 213,441 | 229,371 |
| Built Go (pclntab truth) | 45 | 94.843 | 99.618 | 97.118 | 162,621 | 171,768 |
| Built Rust (gnu targets) | 24 | 78.951 | 97.493 | 87.185 | 33,817 | 41,663 |
| Built .NET (CIL + NativeAOT) | 4 | 93.589 | 99.461 | 96.124 | 7,441 | 9,257 |
| ARM64 Mach-O (linker truth) | 11 | 94.008 | 96.345 | 94.778 | 2,753 | 2,775 |

875,544 truth functions, 927,097 detections, no failed sample. Five of the corpora and 420,073 of
those truth functions did not exist for this project before this branch, and no corpus lost recall at
any step of it.

---

## 2026-08-24 — not worth changing: the `endbr64`-then-prologue interior seed

A third interior seed suggested itself while separating a test fixture. A CET-enabled function opens
`endbr64; push rbp; mov rbp, rsp`, and `55 48 89 e5` is on the seeded list, so the scan books a
candidate four bytes inside every such function. The scan order hides it from the interior-prologue
rule: `DEFAULT_PROLOGUES` is walked before `ENDBR64_BYTES`, so when `55 48 89 e5` is matched the
`endbr64` in front of it is not yet a candidate and the rule has nothing to refuse it with.

The byte-level counterfactual looked emphatic. Across the C/C++ corpus there are **19,536**
`endbr64`-then-frame-prologue adjacencies; the `endbr64` is a declared function start in **all 19,536**
and the follower four bytes on is a declared start in **none**. A perfect signal, over 40 cells.

It changes nothing measurable. The first six binaries measured returned 0 of 111 false positives at
`endbr64 + 4` — and five of those six contain **zero** adjacencies, so their zeros meant nothing and
the measurement had to be redone on binaries that carry the pattern:

| cell | adjacencies present | false positives | of those at `endbr64 + 4` |
|---|---|---|---|
| googletest_gcc-x64_O0 | 2,994 | 1,317 | 0 |
| sqlite3_gcc-x64_O0 | 2,856 | 165 | 2 |
| lua_gcc-x64_O0 | 1,058 | 255 | 2 |
| brotli_gcc-x64_O0 | 579 | 111 | 0 |
| googletest_clang-x64_O2-static | 2,025 | 1,484 | 2 |
| **total** | **9,512** | 3,332 | **6** |

Six false positives, over binaries holding half the corpus' adjacencies. The recursive analysis
reaches the function at the `endbr64` first and claims those bytes as code, so the interior candidate
is discarded before it can be reported. The seed is wasteful and not inaccurate. **Not changed.**

Worth recording for the control rather than the conclusion: the first run of this measurement
returned a clean zero on a population that was not there. A zero with no positive control beside it
says nothing at all, and this one had a perfect 19,536-to-0 byte statistic in front of it making it
look like confirmation.
