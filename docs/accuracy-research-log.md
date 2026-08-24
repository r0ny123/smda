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
