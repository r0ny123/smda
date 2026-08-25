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
those two targets.

It is what the target's own first instruction looks like, and the correlation is exact:

| veneer target | opens with | veneers pointing there | found |
|---|---|---|---|
| `0x100006400` | `stp x29, x30, [sp, #-0x10]!` | 1 | yes |
| `0x100007984` | `stp x29, x30, [sp, #-0x10]!` | 1 | yes |
| `0x100007aec` | `stp x22, x21, [sp, #-0x30]!` | 2 | yes |
| `0x10000642c` | `ldp x9, x8, [x1, #0x20]` | 4 | **no** |
| `0x10000643c` | `ldr x0, [x0, #0x28]` | 4 | **no** |

All five targets are themselves declared and all five are recovered, so it is not the target being
missed that loses the veneer. The four found veneers point at addresses whose first word
`is_function_prologue` recognises; the eight missed ones point at addresses it does not. Whatever
path reaches a veneer is therefore reaching it through its target having been seeded as a prologue
first, and a target that opens mid-function-looking — as a linker-generated entry point often
does — takes its veneers down with it.

Recorded as a clue rather than a mechanism: which pass that is has not been instrumented.

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

| Malpedia57 | – | 57 | 0.819 / 0.940 | 0.849 / 0.961 | 0.976 / 0.935 | 0.986 / 0.926 |

TPR / PPV. The `O1` 64-bit Ghidra cell holds one binary the engine did not finish inside the analysis
budget; it is marked and named rather than printed, for the reasons recorded above. Every other cell
is measured, and the tool's control line reports `missing=[]`.

**This is the harness validating itself against a second engine.** Ghidra 12.1.3 lands within 0.002
to 0.013 of the figures recorded for Ghidra 9.1.2 on four of the five comparable cells — a different
tool, a different decade, and the same metric implementation reproducing the published numbers. The
earlier validation showed SMDA 4.4.1 reproducing a recorded SMDA measurement; this shows the metric
is not tuned to one engine's output shape.

It also says something about the two tools. Ghidra has moved very little on these corpora in five
years — at most +0.013 recall on a ByteWeight cell, and +0.030 on the malware corpus, which is its
one real improvement and still leaves it at 0.849 against SMDA's 0.986. SMDA has moved a great deal, and
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
corpora, and the three micro figures the AArch64 argument rests on. Run again after the fifth fix
landed, over all ten end-state rows including their detection counts, it found exactly one mismatch:
the Go and ARM64 Mach-O rows and the total detection count were still carrying the fix's *inputs*.
42 figures checked, one wrong, and it was the one a human re-reading the prose would not have caught,
because the sentence around it was still true of the run it was written from. It is worth running rather than
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
| Built Go (pclntab truth) | 45 | 95.111 | 99.618 | 97.266 | 162,621 | 171,338 |
| Built Rust (gnu targets) | 24 | 78.951 | 97.493 | 87.185 | 33,817 | 41,663 |
| Built .NET (CIL + NativeAOT) | 4 | 93.589 | 99.461 | 96.124 | 7,441 | 9,257 |
| ARM64 Mach-O (linker truth) | 11 | 94.220 | 96.711 | 95.074 | 2,753 | 2,767 |

875,544 truth functions, 926,659 detections, no failed sample. Five of the corpora and 420,073 of
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

---

## 2026-08-24 — measured worse: gating the AArch64 tailcall seeding

The AArch64 backend seeds tailcall candidates from two sites of its own, and neither consults
`SmdaConfig.RESOLVE_TAILCALLS` — which is `False` by default and which the shared engine honours on
both of its own tailcall paths. On Go arm64 that source produces 170 of 246 false positives per
binary and contributes none on any intel cell. Making the backend honour the flag is the obvious
consistency repair.

Measured on the ARM64 Mach-O corpus, n=11, with the boundary rule's cut kept and only the candidate
seeding gated:

| | PPV | TPR | F1 | TP | FP |
|---|---|---|---|---|---|
| as shipped | 94.008 | **96.345** | 94.778 | 2,512 | 263 |
| seeding gated | 94.684 | **96.314** | 95.203 | 2,517 | 230 |

Macro recall falls by 0.031, and **a recall drop on any corpus is the reject criterion**. Per sample:

| sample | ΔTP | ΔFP |
|---|---|---|
| osx.gimmick | **+12** | **−28** |
| RustyPages | **−6** | 0 |
| LockBit | 0 | −2 |
| osx.frostyferret | −1 | +1 |
| Kitty | 0 | −4 |

The seeding is net-negative on precision — 34 false positives against 7 true positives — and it is
not worthless: seven functions on two binaries are reached only through it. Micro recall actually
rises, 91.246 to 91.428, because the twelve gimmick recovers outweigh the seven lost; the macro mean
is what the reject criterion reads, and it falls. **Rejected as a blunt gate.**

### The same gate on Go

| corpus | n | PPV | TPR | F1 | TP | FP |
|---|---|---|---|---|---|---|
| as shipped | 45 | 94.843 | 99.618 | 97.118 | 162,145 | 9,623 |
| seeding gated | 45 | **95.216** | 99.618 | **97.323** | 162,145 | **8,983** |

**640 false positives removed and not one true positive lost**, with recall identical to the digit.
Split by architecture, the isolation is complete:

| architecture | FP before | FP after | ΔFP | ΔTP |
|---|---|---|---|---|
| 386 | 747 | 747 | 0 | 0 |
| amd64 | 3,065 | 3,065 | 0 | 0 |
| **arm64** | 5,811 | **5,171** | **−640** | **0** |

The intel cells are bit-identical, which is the control that the change reaches only what it was
meant to. The ceiling recorded earlier for this item — "roughly 2,907 across the six arm64 cells" —
was an over-estimate taken from the count of tailcall-sourced candidates rather than from the
functions they actually produce. The real figure is 640 on Go and 33 on the Mach-O corpus.

So the trade is **673 false positives against 7 true positives**, and the seven are the whole reason
this is not simply landed. Separating the two sites, below, splits that trade cleanly: 458 of the 673
come from the site that costs nothing, and 215 from the site that costs the seven. What the numbers argue for is the narrower rule the other two fixes took:
keep the source and refuse the cases that are provably interior, rather than switching the source
off. Characterising those seven is the next step, and this measurement is what says they exist.

---

## 2026-08-24 — the clean-checkout claim, verified rather than asserted

The harness is described as runnable from a clean checkout, which is easy to write and easy to be
wrong about after a day of working in one tree. Checked directly: a fresh clone of the pushed branch,
an empty ground-truth root, and the checkout's own `src` on `PYTHONPATH` so nothing of the working
tree can leak in.

```
git clone --branch <branch> --single-branch <fork> clean-check
SMDA_BENCH_GROUNDTRUTH=<empty dir> tools/bench/build_corpus.py --family macho-arm64 --out .../built
  [macho-arm64] ok=11 failed=1
SMDA_BENCH_GROUNDTRUTH=<empty dir> tools/bench/run.py --corpus macho-arm64 --engine smda --filter all
  ARM64 Mach-O (LC_FUNCTION_STARTS)  smda  all  11  94.008  96.345  94.778  2512  263  241
```

The same figures the report prints, from a tree that has never been worked in, with the same skip
recorded for the fixture that declares no function starts. The corpus that needs no toolchain and no
download is the one this can be shown on end to end; the others need their compilers, and their
recipes are the same code path.

---

## 2026-08-24 — the two AArch64 tailcall sites are not the same thing

Gating both sites together lost recall, and that reads as "the source is worth keeping". Gating them
separately says something quite different. ARM64 Mach-O corpus, n=11, filter `all`, arithmetic macro
mean:

| configuration | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| as shipped | 94.008 | 96.345 | 94.778 | 2,512 | 263 | 241 |
| branch-target site gated | 94.461 | **96.214** | 95.039 | 2,505 | 258 | 248 |
| **`bl` fall-through site gated** | **94.217** | **96.446** | **94.936** | **2,524** | **235** | **229** |
| both gated | 94.684 | 96.314 | 95.203 | 2,517 | 230 | 236 |

The two sites do opposite things.

**The branch-target site earns its keep.** It seeds the target of a backward branch or a short
no-frame stub, and gating it costs 7 true positives — those are the seven the combined measurement
found, and they all come from here.

**The `bl` fall-through site is strictly worse than not having it.** Gating it improves *every*
metric: 12 more functions recovered, 28 fewer false positives, recall up 0.101 and precision up
0.209. Removing a candidate source and gaining true positives is the surprising part, and the reason
is that the seeding is not what finds the function. The same code path cuts the caller at the
boundary — `_cutFunctionBeforeInstruction` runs whether or not the candidate is seeded — and once the
caller ends there, the ordinary candidate machinery finds the next entry with better extents than a
tailcall-flagged candidate does.

Gating both hid this: the branch-target site's 7 losses and the fall-through site's 12 gains partly
cancel, leaving a net that looked like a small recall drop and read as "reject the whole idea".

### The same site on Go

| corpus | n | PPV | TPR | F1 | TP | FP |
|---|---|---|---|---|---|---|
| as shipped | 45 | 94.843 | 99.618 | 97.118 | 162,145 | 9,623 |
| `bl` fall-through site gated | 45 | **95.111** | 99.618 | **97.266** | 162,145 | **9,193** |

430 false positives removed, recall identical to the digit, no true positive lost.

**Both AArch64 corpora improve on every metric**, which is what separates this from the three
proposals rejected above:

| corpus | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|
| ARM64 Mach-O, n=11 | +0.209 | **+0.101** | +0.158 | **+12** | **−28** |
| Built Go, n=45 | +0.268 | +0.000 | +0.148 | 0 | **−430** |

Landed as the narrow change: the `bl` fall-through site consults `RESOLVE_TAILCALLS` like the shared
engine does, and the branch-target site is deliberately left alone with the seven functions it
recovers as the stated reason.

---

## 2026-08-24 — Ghidra on the Go corpus

The Ghidra sweep reached the built Go family, which no published comparison covers. Filter `all`,
Ghidra 12.1.3 under the same analysis budget both engines get:

| engine | n | PPV | TPR | F1 | micro PPV | micro TPR |
|---|---|---|---|---|---|---|
| ghidra-12.1.3 | 45 | 93.501 | **86.430** | 88.537 | 98.204 | **78.313** |
| smda-4.4.7 | 45 | 94.843 | **99.618** | 97.118 | — | — |

Two samples — `netjson_darwin-arm64_default` and `netjson_linux-arm64_default` — did not finish
inside the budget and score 0, which the macro figures carry; the micro figures are dominated by the
43 that did.

By architecture, micro:

| architecture | Ghidra PPV | Ghidra TPR |
|---|---|---|
| 386 | 98.38 | **70.22** |
| amd64 | 98.77 | 91.76 |
| arm64 | 96.60 | **62.89** |

Ghidra is more precise than SMDA on this family and recovers far fewer functions — 78.3% against
99.6%, and 62.9% on arm64. That is the pclntab: SMDA reads Go's own function table, and a Go binary
without one recovered is mostly unreachable code as far as recursive traversal is concerned. It is
the clearest illustration in this work of the design trade the origin evaluation states — deliberate
over-detection buying completeness — measured on a family that evaluation never covered.

Recorded with the budget caveat attached: this is Ghidra under the timeout this harness gives both
engines, and two of its 45 samples exceeded it.

### The gate, across all ten corpora

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|---|
| ARM64 Mach-O | 11 | +0.209 | **+0.100** | +0.158 | **+12** | **−28** |
| Built Go (pclntab truth) | 45 | +0.268 | +0.000 | +0.148 | 0 | **−430** |
| Bao byteweight msvc10-32 | 68 | 0 | 0 | 0 | 0 | 0 |
| Bao byteweight msvc10-64 | 68 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-32-d | 56 | 0 | 0 | 0 | 0 | 0 |
| Bao_Dumped msvc10-64-d | 56 | 0 | 0 | 0 | 0 | 0 |
| Plohmann malpedia itw | 57 | 0 | 0 | 0 | 0 | 0 |
| Built C/C++ (gcc, clang, mingw) | 260 | 0 | 0 | 0 | 0 | 0 |
| Built Rust (gnu targets) | 24 | 0 | 0 | 0 | 0 | 0 |
| Built .NET (CIL + NativeAOT) | 4 | 0 | 0 | 0 | 0 | 0 |

Eight of ten bit-identical, the two AArch64 corpora both improving, and 458 false positives removed
for 12 functions gained. `summarize.py --compare` reports `compared=10` and no recall regression.

---

## 2026-08-24 — what the fixes cost in time

Both landed candidate rules add work per match — the interior-prologue rule compares the preceding
bytes against up to eight seeded patterns, and the AArch64 boundary rule reads four words — so the
runtime is worth measuring rather than assuming. Against the branch point, median of three runs each:

| fixture | before | after | functions |
|---|---|---|---|
| cutwail | 0.183 s | 0.185 s | 33 either way |
| dotnet_readytorun | 0.340 s | 0.341 s | 564 either way |
| **rust_pe_gnu** | **6.504 s** | **5.861 s** | 2,355 either way |

Flat on the small fixtures and **10% faster on the largest**, with the function count identical on all
three. The per-match cost is real and it is smaller than the work saved by not analysing the
candidates that are no longer seeded. A precision fix that removes candidates before analysis pays
for itself in the analysis it skips.

The identical function count on `rust_pe_gnu` is also the expected result rather than a surprise: it
is a mingw PE, and the counterfactual said the interior-prologue rule is inert on all eight mingw PE
cells of the built corpus.

---

## 2026-08-24 — what the interior-prologue rule does to the control-flow graph

The repository's own benchmark gate compares base and PR function-address sets over a 155-file
corpus and fails on any difference, which an accuracy change necessarily produces. Its report on this
branch is worth reading closely, because the shape of the difference is the argument:

- `elf.akira...unpacked`: 48 addresses gone, none gained, and **59 functions whose block count
  changed** — the ones it lists all read `base 1 → PR N`, with N from 5 to 154.

That is the fix, seen from the other side. A spurious candidate seeded four bytes inside a function
does not only add a false positive: it **truncates the real function**, which stops at the candidate
and is reported as a single block. Removing the candidate lets the real function decode.

Reproduced on a corpus that has ground truth, two Rust cells, base against PR:

| | release | debug |
|---|---|---|
| addresses dropped | 123 | 123 |
| **of those, declared functions** | **0** | **0** |
| addresses gained | 0 | 0 |
| functions that grew | 119 | 119 |
| **of those, grew from a single block** | **119** | **119** |
| functions that shrank | **0** | **0** |
| largest single-block recoveries | 1 → 327, 237, 227, 221, 202 | same |

Every dropped address is undeclared, every declared function is kept, nothing shrinks, and 119
functions per binary go from being reported as one block to being reported as up to 327. The
function-start metric this whole project measures cannot see that: it scores starts, and a function
truncated to its first block still has the right start. The gate's block-count drift, which it prints
as informational, is measuring something the accuracy tables miss.

So the branch's headline for this fix — 912 false positives removed, 0 true positives lost — understates
it. On these two cells it also repairs 119 control-flow graphs each.

---

## 2026-08-24 — the veneers, run down: a candidate snapshot taken before analysis

The correlation recorded above — a veneer is recovered when its target opens with a word
`is_function_prologue` recognises, and missed when it does not — turned out to be a proxy for
something else entirely. Instrumenting which pass admits each candidate:

| address | admitted by | detected |
|---|---|---|
| `0x100007abc` … `0x100007ac8` | never a candidate | no |
| `0x100007acc`, `0x100007ad0` | gap search | yes |
| `0x100007ad4` … `0x100007ae0` | never a candidate | no |
| `0x100007ae4`, `0x100007ae8` | gap search | yes |

So the gap sweep reaches the run and admits four of twelve. The guard that rejects the other eight is
`_gapRunFlowsIntoInterior`, which decodes the straight-line run from a gap position and, if it ends
in an unconditional `b`, suppresses it when the target is *in `code_map` but not a function-start
candidate* — the shape of a mid-function tail rather than a new function.

**`getFunctionStartCandidates()` is a snapshot taken before analysis begins.** `_buildQueue` fills it
once from the candidates the discovery passes found; after that only one AArch64 path adds to it, and
gap analysis never does. On this image it holds **211 addresses while 261 functions are recovered**,
so **50 recovered functions are invisible to it**:

| veneer target | in `code_map` | is a recovered function | in `getFunctionStartCandidates()` |
|---|---|---|---|
| `0x10000642c` | yes | **yes** | **no** |
| `0x10000643c` | yes | **yes** | **no** |
| `0x100006400` | yes | yes | yes |
| `0x100007984` | yes | yes | yes |
| `0x100007aec` | yes | yes | yes |

The three targets the found veneers point at were seeded by the prologue scan, so they are in the
snapshot. The two the missed veneers point at were discovered by gap analysis, so they are not — and
a branch to them reads to the guard as a branch into the middle of somebody else's function. The
prologue correlation was real and was a symptom: which pass found the target, not what the target
looks like.

The guard is asking "is this the interior of already-mapped code", and the right way to answer it
includes the functions recovered since the snapshot was taken. Adding `target in
disassembly.functions` as an exemption:

| | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| before | 94.217 | 96.446 | 94.936 | 2,524 | 235 | 229 |
| after | 94.220 | **96.711** | 95.074 | **2,532** | **235** | **221** |

Eight functions recovered, **the false-positive count identical**, and on `osx.frostyferret` the
veneer run goes from 5 of 13 recovered to **13 of 13**.

The gate across all ten corpora: nine bit-identical, only the ARM64 Mach-O corpus moving.

| corpus | n | ΔPPV | ΔTPR | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|---|---|
| ARM64 Mach-O | 11 | +0.002 | **+0.265** | +0.138 | **+8** | **0** |
| the other nine | 68/68/56/56/57/260/45/24/4 | 0 | 0 | 0 | 0 | 0 |

An AArch64-only change reaching only AArch64, and the one corpus it reaches gaining recall without
paying for it.

### Why this is worth more than eight functions

`getFunctionStartCandidates()` is consulted in several places as though it meant "addresses believed
to start a function". It means "addresses the discovery passes proposed before analysis started", and
on this image the two differ by 50 of 261. Any guard that reads it as the former is wrong by that
margin for every function found after `_buildQueue` ran — which is every gap-discovered function, and
on AArch64 that is a large share of what gap analysis exists to find.

This fix corrects the one site the veneer run exposed, and the set has one definition, so the rest of
its readers can be enumerated rather than guessed at. All six:

| site | shape | verdict |
|---|---|---|
| `X86Backend` jump classifier, two sites | `if dest in disassembly.functions: … elif dest in getFunctionStartCandidates():` | **benign** — the live set is tested first |
| `AArch64Backend._analyzeUncondBranch` | same `if … functions` / `elif … candidates` shape | **benign** — same reason |
| `AArch64Backend._callFallthroughFunctionStart`, two tests | `if addr in getFunctionStartCandidates(): return addr` | **sibling** — no live-set test in front of it |
| `_isLikelyInteriorBtiCandidate` | `if addr in code_map and addr not in getFunctionStartCandidates()` | **sibling** — identical to the fixed site |

Three of the six are already correct because they consult `disassembly.functions` first and fall back
to the snapshot only for addresses that are not yet functions, which is what the snapshot is good for.
Two are the same defect.

Both siblings are **inert on every corpus available here** — the ARM64 Mach-O figures are identical
with and without them, and Go's gap analysis contributes little because the pclntab names everything.
They are corrected anyway, because they are the same defect and the correction can only stop the code
suppressing at an address already recovered as a function, which cannot lose one. Recorded as a class
sweep rather than as a measured gain: the measured gain is the eight veneers, and these two are the
rest of the class.


---

## 2026-08-25 — what the benchmark's timing verdict was measuring

Three consecutive runs of the repository's malpedia benchmark, on three heads of this branch, reported
**+1.26%** (*inconclusive*), **−13.18%** (*PR is slower*, Wilcoxon p = 0.0000) and **−15.53%** (*PR is
slower*) over 155 files. The source changes between those heads are `61df8a1` and `68d4e9d`, both of
which touch `AArch64Backend`, on a corpus of x86 and x64 images.

Three figures out of the runs' own artifacts settle what happened.

**The base side of all three verdicts is literally the same data.** `evaluation.json` records base
`median_time` 0.709083, `total_time` 252.53414500000002 and `total_functions` 175973 in every one, and
the three base passes' corpus medians — 0.737365, 0.794363, 0.785123 — agree to the last digit across
all three runs. The job log says why: `Restore cached base results` hit, and every step after it
(Python, install, decrypt, benchmark) was skipped. The cache restored the first run's base
measurements into the two that followed.

**The PR side did identical work in all three.** Corpus-wide recovered functions: 175942 every time.
The same two files differing from base, the same addresses — 48 dropped on `elf.akira`, 3 dropped and
20 gained on `win.konni` — and the same 59 block-count drifts.

**The PR side got slower each time.** Sum-of-best-times **252.83 s → 282.21 s → 289.04 s**, a spread
of **14.3%** for output that never changed; per-pass corpus medians 0.798 / 0.792 / 0.753, then 0.836
/ 0.849 / 0.800, then 0.883 / 0.856 / 0.821. The `Run Malpedia Benchmark` step took 370 s and then
396 s of wall clock for the same three passes. A different runner each time, over two hours.

**The noise band cannot see any of this.** `evaluate_runtime.py` sets it to
`max(base_cv, pr_cv)`, where each `cv` is the median coefficient of variation across *one side's* own
repeated passes — passes that all run inside a single job on a single machine. It estimates
within-runner jitter and is then used to bound a between-runner offset. In all three runs it came out
at exactly 5.0324754475773545, because in all three it was set by the base side: the band that judged
the second and third runners was computed from the first one's measurements.

The spread is visible inside a single run without any of that. The first run's nine pairwise
base-vs-PR comparisons, three passes against three, span **−8.25% to +5.26%** for the same two trees.

## 2026-08-25 — what the branch costs in time, measured on one machine

The earlier entry measured three bundled fixtures and concluded the candidate rules are free. Three
fixtures is not a population, and the fixture that carried the headline is the one family where the
interior-prologue rule fires hardest, so it was the most favourable sample available rather than a
representative one. Re-measured properly: three corpora, both trees checked out into **the same
working directory** in turn, one pass at a time with nothing else running, and the side that goes
first rotated per pass so drift over the session cannot land on one of them. Per-sample time is the
report's own `execution_time`, aggregated min-of-three, and the paired statistic is the repository's
own `compute_paired_stats`.

| corpus | n | base | branch head | median speedup | 95% CI | p |
|---|---|---|---|---|---|---|
| Plohmann malpedia dumps | 57 | 34.34 s | 34.18 s | −0.19% | [−0.60%, +0.57%] | 0.962 |
| Built Rust (mingw PE) | 24 | 66.85 s | 63.88 s | **+1.46%** | [−2.65%, +6.51%] | 0.166 |
| ARM64 Mach-O | 11 | 4.46 s | 4.50 s | −2.83% | [−3.62%, +2.98%] | 0.197 |

The three corpora are chosen so that each landed rule is measured where it fires: the malware dumps
are what CI measures, the Rust corpus is where the interior-prologue rule removes most of its
candidates (42,453 → 41,663 recovered addresses), and the Mach-O corpus is the only one that reaches
the AArch64 rules at all.

**None of these is distinguishable from zero, and the controls are what say so.** Running *identical
code* twice — the same commit, checked out into two different directories, measured in two sessions on
the same idle machine — produces:

| control | n | median speedup | 95% CI | p |
|---|---|---|---|---|
| `802e627` against `802e627` | 57 | +1.37% | [+0.10%, +1.80%] | **0.008** |
| `dc2aec5` against `dc2aec5` | 57 | −0.69% | [−1.65%, +0.48%] | 0.103 |

A comparison of a commit with itself clears the 95% CI and reports p = 0.008. Every figure in the
corpus table above is smaller in magnitude than that control, so none of them is evidence of anything.
It also shows what the Wilcoxon p-value is worth here: with ~10² paired files, a systematic
session-level offset of a percent is more than enough for significance, which is exactly how CI
reached p = 0.0000.

The first attempt at this measurement fell into the same trap. Base was read from one checkout and the
branch head from another, giving a median of −1.89% with p = 0.0000 — a clean, significant, entirely
spurious 2% regression, and the number this entry would have published without the control.

Attributed per commit on the malware dumps, each row base against that commit:

| through | median speedup | 95% CI | p |
|---|---|---|---|
| `2929638` a dump's instruction set from its header | −0.38% | [−1.36%, +0.07%] | 0.123 |
| `d0a47f7` the exception table's declared address | +1.05% | [+0.01%, +1.95%] | 0.053 |
| `184e4d6` a prologue that opens where another ends | −0.11% | [−1.22%, +0.48%] | 0.787 |
| `dc2aec5` the branch head | −0.19% | [−0.60%, +0.57%] | 0.962 |

No step is separable from the session noise either. The honest statement is not that the rules are
free — it is that on three corpora spanning 92 binaries their cost is below what two runs of one
commit disagree by, and that a claim of "free" made from three fixtures was never supported.

### What the same gate says once both sides share a runner

First run of the repaired workflow, on the same head that had just been called 15.53% slower:

| | before the fix (three runs) | after |
|---|---|---|
| verdict | **PR is slower** ×2, *inconclusive* ×1 | *inconclusive — within run-to-run noise (±6.8%)* |
| median paired speedup | +1.26%, −13.18%, −15.53% | **+0.82%**, 95% CI [−0.40%, +2.06%] |
| Wilcoxon p | 0.218, 0.0000, 0.0000 | **0.242** |
| base sum-of-best-times | 252.53 s, frozen across all three | 210.82 s, measured |
| PR sum-of-best-times | 252.83 / 282.21 / 289.04 s | 207.41 s |

The base side moving at all is the first thing to check: it had been bit-identical for three runs
because it came from cache, and it is now 210.82 s on a runner faster than the one that produced the
frozen figure. Both sides sit on that runner, so the comparison is between two trees again rather than
between two machines. The correctness finding is unchanged — the same two files, the same addresses —
which is the control that only the timing arrangement moved.

The noise band is now a real one: 6.8%, taken from the PR side's own repeated passes inside the same
job. The pairwise diagnostic still spans −13.4% to +7.6% across individual passes, which is why the
headline uses the paired per-file best-of-runs statistic and not those medians.

It also agrees with the local measurement in the previous entry — CI on its corpus says +0.82%
[−0.40%, +2.06%], this machine on the malware dumps says −0.19% [−0.60%, +0.57%] — which is two
instruments on two machines reaching the same answer, where before they disagreed by 15 points.


---

## 2026-08-25 — what an `endbr64` false positive actually is

Section 13's second agenda item ends with a measurement to make: the proposed repair is a filter on
candidates the jump-table pass has claimed, and its ceiling is "the 14,986, minus however many of them
the jump-table pass does not in fact resolve". The answer is: nearly all of them.

Instrumenting `JumpTableAnalyzer.getJumpTargets` on six gcc/clang cells and intersecting its targets
with the false positives that open with `endbr64`:

| cell | false positives opening `endbr64` | of those, jump-table targets | targets the pass claimed on the whole image |
|---|---|---|---|
| `googletest_gcc-x64_Os` | 1,085 | **0** | 43 |
| `googletest_gcc-x64_O1` | 862 | **0** | 58 |
| `googletest_gcc-x64_O3` | 793 | **0** | 81 |
| `googletest_gcc-x64_O2-nopie` | 646 | **0** | 58 |
| `googletest_gcc-x64_O0` | 1,241 | **0** | 0 |
| `googletest_clang-x64_O0` | 0 | 0 | 84 |

**0 of 4,627.** The control is the last column: the pass resolves 43 to 84 targets per image, so the
instrumentation ran — it is the population that is wrong, not the probe. On the worst image the whole
jump-table pass claims 43 addresses while 1,085 spurious landing pads sit in it. A post-analysis filter
on what that pass claimed cannot reach them, and the agenda item's proposed repair is dead as stated.

### What they are instead

Every one of them sits **strictly inside a range the image's own `.eh_frame` declares**, a median of
892 to 2,067 bytes in. Over ten ELF cells: **4,690 of 4,690**.

The first attempt at that measurement said the opposite and was wrong twice over. It read function
extents from sized `FUNC` symbols, and these binaries are stripped — their truth comes from an
unstripped twin — so it found 1 sized symbol on the image with 1,085 pads and reported "0 interior"
from an empty oracle. The guard it carried, `any(declared_extents)`, passed at 1. Switching to
`.eh_frame`, which survives stripping, then produced "1,085 of 1,085 interior" from a helper that
**merged adjacent ranges** — and consecutive functions are laid out end-to-start, so merging collapses
`.text` into a handful of spans and "strictly inside a declared extent" degenerates into "anywhere but
the first byte". Unmerged, the answer is the same 100% but it now means something, and the control that
says so is the range count: 345 merged spans against 842 real FDEs on that image.

### What a rule built on it would cost

| cell | false positives it removes | true positives it touches | of those, nothing references |
|---|---|---|---|
| `googletest_gcc-x64_Os` | 1,085 | 346 | **0** |
| `googletest_gcc-x64_O1` | 862 | 356 | **0** |
| `googletest_gcc-x64_O3` | 793 | 348 | **0** |
| `googletest_gcc-x64_O2-nopie` | 646 | 360 | **0** |
| `googletest_gcc-x64_O0` | 1,241 | 437 | **0** |
| `lua_gcc-x64_O2` | 63 | 150 | **0** |
| `brotli`, `zlib`, both clang cells | 0 | 284 | **0** |
| **total** | **4,690** | **2,131** | **0** |

The rule under test is the narrow one: *decline to seed* an `endbr64` prologue match that begins
strictly inside a declared FDE range — decline to add a candidate, never remove one, which is the same
shape as the interior-prologue rule in the earlier entry. The blanket form is not usable: 2,518
recovered true positives sit strictly inside a declared FDE across the same ten cells, so refusing
every interior address would cost more than it buys.

Two things this measurement does **not** establish, and the end-to-end run is what will settle them.
The 2,131 figure counts true positives with at least one inbound *code* reference, call or jump, while
only a call reference is seeded before the prologue scan. And every one of those references was
observed in a run where the seed was present, so a reference reaching one of them could itself descend
from the seed — the same circularity that made an earlier before/after diff blind to the mechanism it
was supposed to test. Neither is answerable by counting; both are answerable by building the rule and
diffing recovered sets against truth.

Also worth recording: **clang emits none of this**. Both clang cells have zero `endbr64` false
positives against gcc's hundreds on the same source, which is why the C/C++ matrix's precision gap
between the two toolchains is as wide as it is.

---

## 2026-08-25 — the landing-pad rule, landed

Built as the previous entry described: decline to seed an `endbr64` prologue match beginning strictly
inside a declared FDE range. Decline to add, never remove.

Ten corpora in one run, against the branch head before it:

| corpus | n | dPPV | dTPR | dF1 | dTP | dFP |
|---|---|---|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | **+0.745** | +0.001 | **+0.447** | **+11** | **−3,977** |
| the other nine | — | +0.000 | +0.000 | +0.000 | +0 | +0 |

`summarize.py --compare` reports `compared=10` and no TPR regression on any corpus. The nine
bit-identical corpora are the inertness control: every PE, Mach-O and memory-dump corpus has no
readable `.eh_frame` section, and Go emits none, so the rule cannot fire there. `googletest_gcc-x64_Os`
goes from **52.058 PPV to 97.701**.

**Seven true positives are lost**, against eighteen gained, on four of the 260 cells —
`googletest_clang-x64_O2-static` (−3), `tinyxml2_gcc-x64_O2` (−2), `tinyxml2_gcc-x64_O2-nopie` (−1),
`tinyxml2_gcc-x64_O2-static` (−1). Checking each against the decoded ranges: **none of the seven is
inside a declared FDE range**, so the rule refused none of them directly. They are second-order — the
analysis that reached them descended from a pad it did refuse. Two of the three examined open with
`endbr64` followed by `push r15; push r14`; the third opens `mov rdi, rbp; call …`, which is not an
entry shape at all and is a truth start only because the symbol table names it.

### The half that was built and rejected

Applying the same test to gap analysis removes the pads the seeding half leaves behind, and it is a
catastrophe for recall:

| cell | seeding half only | with the gap half |
|---|---|---|
| `googletest_gcc-x64_Os` | 97.701 / **99.665** | 99.021 / **84.673** |
| `googletest_gcc-x64_O1` | 79.295 / **94.969** | 99.321 / **78.886** |
| `zlib_gcc-x64_O2` | 99.510 / **97.596** | 99.425 / **83.173** |

Every function it loses is a PLT stub — 179 of 179 on the first cell, 30 of 30 on the last, all in
`.plt` or `.plt.sec`. The whole PLT block sits under one FDE, so every stub after the first reads as
interior; and on a CET binary it is the **gap scan** that recovers them, not
`locateStubChainCandidates`, whose byte patterns match the classic `jmp qword ptr [rip+…]` stub and
not the `endbr64`-prefixed one. That also explains why the seeding half is free on the PLT: refusing
the seed there costs nothing because the gap scan still reaches them.

### What the fixture shows, and what it does not

No bundled sample carries the shape, so one was built: gcc `-O2 -fcf-protection=full`, a `dispatch`
routine with a computed goto, committed xored as `elf_cet_landing_pads_x64_xored`. Its `.text` holds
ten pads — four that each begin a declared range, four strictly inside `0x1180`–`0x11e6`, and two in
neither — which is the fixture's own control that both shapes are present before anything is compared.

The test asserts the pads are not **seeded**, not that they are absent from the report, because they
are not absent: the gap scan books all four, exactly as it does on `googletest_gcc-x64_O2-nopie`. The
first version of the test asserted absence and failed for that reason, which is the more useful
result — `dispatch` is recovered but decodes only three blocks, because the PIE computed-goto table
is not resolved, so its case bodies stay unclaimed and the gap scan carves them out. On this shape the
pads are a symptom and the unresolved indirect dispatch is the cause.

### The class

AArch64's BTI pad is the same construct, seeded by `locatePrologueCandidates` and guarded only by
`_isLikelyInteriorBtiCandidate`, which fires solely for addresses already in `code_map`. The shared
predicate would apply unchanged. It is not fixed here because nothing here can measure it: Go's arm64
cells carry **zero** FDE ranges, the ARM64 Mach-O corpus has no such section, and the one bundled
AArch64 ELF that has 276 readable ranges has no ground truth. Scoring a change there by counting
recovered addresses is the instrument this project has already recorded as wrong.

---

## 2026-08-25 — an AArch64 ELF corpus, and what it says about the architecture gap

The landing-pad fix was recorded with its AArch64 sibling unmeasured, and the reason was that no
corpus here could reach it: Go's arm64 cells carry zero FDE ranges, the ARM64 Mach-O corpus has no
`.eh_frame` section, and the one bundled AArch64 ELF has no ground truth. That prerequisite is now
met — `gcc-aarch64-linux-gnu` builds the same ten C and C++ programs, the same seven variants, into a
`native-arm64` corpus whose truth is the same compiler's symbol table. 72 cells of 80; the eight
failures are all `xxhash`, whose `XXHSUM_DISPATCH` is x86-specific, and the manifest says so.

It is its own corpus rather than extra cells of `native`, so the x86 matrix stays comparable to the
figures already published for it rather than silently becoming a mixed-architecture population.

### The recall gap is not architectural

Report §13 ranked AArch64 recall as "the largest architecture gap measured anywhere in this work",
from micro recall 91.246 on eleven Mach-O binaries against 99.745 on the 64-bit ByteWeight set. Those
are two different populations — real macOS images with linker truth against MSVC-built open-source
PEs — and holding source, programs, variants and compiler family constant says something else:

| 63 matched cells, same programs and variants | macro PPV | macro TPR |
|---|---|---|
| `gcc-x64` | 94.684 | 96.899 |
| `gcc-arm64` | **77.594** | 95.364 |

**Recall differs by 1.5 points; precision differs by 17.1.** Pooled over the same 63 cells, micro
recall is 97.750 on AArch64 against 96.170 on x86 — AArch64 ahead — and micro precision 81.559
against 90.464. Whatever the Mach-O corpus is measuring, it is not a recall property of the
instruction set, and the agenda's first item is ranked on the wrong axis.

The first version of this entry compared AArch64's matched-cell micro recall against the *whole* x86
matrix's 94.958 — a 63-cell figure against a 260-cell one. That is the two-differently-filtered-
populations error this harness was built to stop, made while correcting the same error in the
agenda's ranking. Matched properly the conclusion is stronger rather than weaker, which is luck and
not vindication: the check that caught it was re-deriving every figure this session published
against the result files, not noticing the prose read oddly.

### The BTI sibling, measured and rejected by the gate

The `O2-bti` cell exists because nothing else here carries the construct: 3,830 BTI landing pads
across its nine binaries against **21** in the same programs built without the flag.

The sibling rule — extend the declared-range test to `is_bti_landing_pad`, which today is guarded
only by a `code_map` check that cannot see a not-yet-decoded region — measures on those cells:
**2,068 of 2,068** false-positive pads sit strictly inside a declared FDE range, and **0** true
positives opening with a pad do. That is a cleaner split than the x86 case, where the same test
touched 2,131 real functions, all of them PLT stubs.

End to end across the whole corpus, n=72: **PPV 76.676 → 78.050**, F1 84.852 → 85.828, **2,861 false
positives removed** — and **one true positive lost**, `0xe1744` on `sqlite3_gcc-arm64_O2-bti`. TPR
95.9386 → 95.9379.

`summarize.py --compare` rejects it, and correctly: a TPR drop on any corpus is the stated criterion
and it does not have a size threshold. The change is reverted. What the loss is, for whoever revisits
this: `0xe1744` opens `paciasp`, not a BTI pad, and sits in no declared range, so the rule refused
nothing about it — it is the same second-order class as the seven the x86 rule costs, an address
whose analysis descended from a pad that is now refused. Recovering it needs the pad-to-victim chain
instrumented, not a narrower predicate.

Recorded rather than landed, and worth a maintainer's call: 2,861 false positives against one
function in 56,127 is a trade the gate as written will not take.

### The measurement that was wrong first

The first BTI run reported a clean **0 of 2,068** — the opposite answer — behind three controls that
all looked right: 3,830 pads present, 2,068 recovered as false positives, 124 to 1,777 FDE ranges
decoded per image. The script built its per-file record with two dictionary keys of the same name,
so the false-positive column was silently overwritten by the true-positive one and every "inside"
figure printed was the wrong quantity. Re-deriving the same number a second way, out of a different
script, is what caught it. A zero with three healthy controls beside it is still only as good as the
line that computed it.

---

## 2026-08-25 — what the landing-pad rule cost, and where

The repaired benchmark reported the branch inconclusive three times running, but with the median
drifting: **+0.82%**, **−0.84%**, **−2.31%**. The band absorbed all three, and a band absorbing
something is not the same as nothing being there, so the last one was measured directly instead.

The drift turned out not to be the signal, and the run after it says so. `0b5ca6c` changes only
`tools/` and `docs/` — its `src/` tree is byte-identical to `68ce20c`'s — and the same workflow scored
the two at **−2.31% (p = 0.0000)** and **+0.06% (p = 0.9865)**. That is an accidental identical-source
control on CI's own instrument, and it puts the repaired workflow's between-run spread at about 2.4
points even with both sides on one runner. So the drift was a reason to go and measure, not evidence
of anything; what follows stands on the local instrument and its own control, not on CI's trend.

Same machine, both commits checked out into one directory in turn, leading side rotated per pass,
min of three, on the malware dumps — the corpus CI measures, and one the rule fires on **not at all**
(function count 24,270 either way):

| | median speedup | 95% CI | p | sum of best times |
|---|---|---|---|---|
| the rule as landed | −1.60% | [−2.94%, −0.62%] | **0.0000** | 31.90 s → 33.11 s (**+3.8%**) |
| after the hoist below | −1.07% | [−2.42%, +0.86%] | 0.4132 | 32.80 s → 32.91 s (+0.3%) |
| **control: the same commit on both sides** | −0.14% | [−0.88%, +1.14%] | 0.962 | 32.98 s → 32.90 s |

The control is what makes the first row readable. It says the harness has no side bias, so a CI
excluding zero at p = 0.0000 on a corpus where the rule changes nothing is a real cost and not the
ordering.

### It was not the lookup

Instrumenting `declaredFdeRangeContaining` and `ehFrameFdeRanges` over the whole corpus: **zero calls
to either**. Those images are 32-bit or carry no `endbr64` at all, so the predicate never runs. What
was being paid was the *test* — `if refuse_declared_interior and self.opensInsideDeclaredFdeRange(...)`
sitting inside the per-match loop of every seeded pattern — not the work behind it.

Resolving it once before the loop (`refuse_declared_interior and bool(self.ehFrameFdeRanges())`)
collapses it to nothing on any image with no `.eh_frame`, which is every PE, Mach-O and dump here.
The recovered sets are identical on all ten C/C++ cells the rule moves, which is the control that
this is a hoist rather than a change.

Reading it back: a guard's cost is not the cost of what it guards. The measurement that would have
misled here is the obvious one — profile the predicate, find it takes no time, conclude the change
is free. It takes no time because it never runs, and the branch in front of it is the whole expense.

### What it broke, and why that is the same lesson as before

Resolving the lookup earlier reaches `getLiefBinary()` on every 64-bit image, and two test doubles
did not implement it — the same duck-type gap that made `MockBinaryInfo` gain `getExceptionDirectory`
when the exception-table fix landed. Both now return `None`, which is what a raw buffer with no
container declares. Eight tests failed and named the accessor outright, so the suite located it in
one run.

---

## 2026-08-25 — the hoist, as CI reads it

First benchmark run against the hoisted tree, both sides on one runner:

| | median | 95% CI | p | base sum | pr sum |
|---|---|---|---|---|---|
| before the hoist (`68ce20c`) | −2.31% | [−3.30%, −1.19%] | 0.0000 | 294.49 s | 298.70 s |
| its src twin (`0b5ca6c`) | +0.06% | [−0.90%, +0.55%] | 0.9865 | 246.12 s | 251.73 s |
| after the hoist (`e42e0e6`) | **−0.83%** | [−1.22%, 0.00%] | 0.0720 | 206.97 s | **205.42 s** |

The sum of best times crosses over for the first time — the PR side is 1.5 s *ahead* of base rather
than 4 s behind. That is consistent with the local finding rather than confirmation of it: the middle
row is two runs of byte-identical source disagreeing by 2.4 points, so this instrument cannot resolve
an effect of this size on its own. What it can say is that nothing large is left.

Worth recording about the runs themselves: three consecutive benchmark runs were **cancelled by the
next push** before they finished, because the workflow sets `cancel-in-progress`. Pushing every
finished piece of work means never seeing a completed run of the thing just pushed. The reading above
only exists because the branch was left alone for twenty minutes.

---

## 2026-08-25 — what is actually producing the Rust false positives

Section 13's third item names the next step rather than guessing: histogram the surviving interior
splits by the pass that booked them, the way the `41 57` seed was found. Instrumenting every
`add*Candidate` entry point and attributing each false positive to the first pass that books it,
over all 24 Rust cells:

| pass that booked it | false positives | share |
|---|---|---|
| `addGapCandidate` | **6,093** | **70.2%** |
| `addReferenceCandidate` | 2,215 | 25.5% |
| `addPrologueCandidate` | 370 | 4.3% |

**8,678 in total**, and the answer refutes the item's own framing. It reads "the class is the same and
the byte pattern is not", which assumes what remains is another seed. The prologue scan — the source
the interior-prologue fix targeted, and the only one a byte pattern can reach — now accounts for
**4.3%**. A second pattern, however well chosen, is bounded at 370 of 8,678.

Seven in ten are gap analysis, and one in four is a reference the analysis believed. Neither is a
byte-level phenomenon: the gap scan carves entries out of regions nothing claimed, and the reference
source books whatever an instruction pointed at. So the ceiling in that item — 13 points to match the
32-bit ByteWeight set — is not reachable through the seeding scan at all, and the next measurement is
what those 6,093 gap candidates look like, not which bytes they start with.

The instrument is the same one that attributed the AArch64 veneers and the nopie landing pads: patch
each `add*Candidate` method to record the first pass that books an address, then intersect with the
false-positive set. It costs one run of the corpus and it has now redirected three investigations
that reading the code had pointed the wrong way.

---

## 2026-08-25 — what the Rust gap candidates look like

The attribution put 70.2% of the surviving Rust false positives on `addGapCandidate`, so the next
question is whether the gap scan is indiscriminate there or whether its wrong answers look different
from its right ones. Describing both sides with the same four fields, over all 24 cells — 3,464
gap-booked addresses that are real functions against 6,093 that are not:

| | real | spurious |
|---|---|---|
| **16-byte aligned** | **3,116 (90.0%)** | **391 (6.4%)** |
| unaligned | 348 (10.0%) | 5,702 (93.6%) |
| single block | 2,406 (69.5%) | 3,598 (59.1%) |
| referenced by something | 23 (0.7%) | 156 (2.6%) |
| median instruction count | 5 | 8 |

**Only alignment separates them**, and it separates them almost completely. Of the aligned gap
candidates 88.9% are real; of the unaligned, 5.8% are. The other three fields are flat or point the
wrong way: block count barely moves, the spurious side is *more* often referenced than the real one,
and the opening mnemonic is `mov` on both sides (4,779 spurious against 2,454 real) so no byte test
lives here either.

**It is not usable as a filter as it stands.** Refusing unaligned gap candidates would remove 5,702
of the 6,093 spurious — 93.6% — and cost **348 real functions**, which is 10% of everything the gap
scan contributes on this corpus and far outside the reject criterion. Recorded as a bound rather than
a proposal: any usable rule here is alignment plus a second signal that recovers those 348, and the
next measurement is what they have in common, not whether alignment works.

Two cautions on the corpus. These are mingw PE Rust binaries, so the alignment property may be a
property of that linker rather than of Rust; a second corpus has to confirm it before anything is
built on it. And the gap scan contributing 3,464 real functions here is worth stating beside the
6,093 — it is not a pass that could simply be turned down.

---

## 2026-08-25 — the synthesizer's size guard measures the wrong span

`Fuzz (fuzz_synthesis)` went red with a `MemoryError` in `ElfSynthesizer._synthesizeMinimal`. It is
not this branch's: nothing here touches `src/smda/synthesis/`, and the same input reproduces on
`origin/master` at `802e627`.

`BinarySynthesizer._resolveFunctionOffsets` refuses a report whose functions are too far apart to
rebuild, and sizes that refusal as `max(extent_end) - min(offset)`. The layout it protects,
`_syntheticSpan`, sizes the image as `max(max(extent_end), max(offset) + 1) - min(offset)` — the
second term was added so that a report whose blocks sit *below* their own function offset does not
produce an inverted span. The guard never learned about it, so exactly that shape walks past a
100 MB cap into an allocation of any size.

Two functions, one at `0x1000` and one at `0x40000000`, both holding a single `ret` block at
`0x1000`:

| | guard span | image `_syntheticSpan` lays out |
|---|---|---|
| offsets far apart, blocks together | `0x1` — passes | `[0x1000, 0x40000010)` = **1024 MB** |
| offsets *and* blocks far apart | `0x3ffff001` — refused | — |

The second row is the control: the guard does fire on the shape it measures. Under a 2 GB
`RLIMIT_AS` the first row raises `MemoryError` at `synthesize:89 ← _synthesizeMinimal:576 ←
_nopFill:141`, which is the CI traceback frame for frame.

Reach across the three formats, same report:

- **ELF** — `MemoryError`, via `_synthesizeMinimal`.
- **Mach-O** — `MemoryError`, via `_synthesizeMinimal` → `_synthesizeFromSections` →
  `_prepareSections`. Same defect, different route.
- **PE** — succeeds, because `_synthesizeMinimal` there sizes `.text` from extent ends only, which
  the guard does bound. It is immune to the crash and *not* correct: it emits a 4,608-byte image
  with one `.text` at `0x1000`, no section describing `0x40000000`, and **no warning**. The declared
  function is silently gone.

The fix is one line at admission — measure what the layout will measure:

```python
extent_end = max(self._functionExtentEnd(self.report.xcfg[offset]) for offset in resolved)
span = max(extent_end, resolved[-1] + 1) - resolved[0]
```

Applied to `origin/master`, all three formats raise the guard's own `ValueError`, which the fuzz
oracle already lists as a documented malformed-input outcome; `testSynthesis`, `testFuzzRegressions`
and `testFuzzCorpus` stay green (79 passed, 193 subtests, exit 0). It covers the two `uncovered`
sub-span call sites for free, because those pass a subset of the same resolved offsets. The PE row
changes from silent omission to a stated refusal, which is the direction worth having.

Not landed here. It is a pre-existing defect in code this branch does not touch, and widening an
accuracy PR into the synthesizer is the wrong place for it — reported on the PR with the patch
instead.

---

## 2026-08-25 — the Rust gap candidates, crossed against where they sit

The last entry left alignment as the only field separating the gap scan's right answers from its
wrong ones, and 348 unaligned-but-real functions as the reason a bare alignment filter is
unaffordable. Crossing alignment with a second field — whether the candidate begins exactly where
the previous recovered function ends, or with something in front of it — over the same 24 cells and
the same 3,464 real / 6,093 spurious population:

| 16-byte aligned | begins at previous function's end | real | spurious | precision |
|---|---|---|---|---|
| yes | yes | 143 | 247 | 36.7% |
| **yes** | **no** | **2,973** | **144** | **95.4%** |
| no | yes | 322 | 4,019 | 7.4% |
| no | no | 26 | 1,683 | 1.5% |

**Alignment is not the field doing the work; the pair is.** An aligned candidate with a gap in front
of it is right 95.4% of the time and accounts for 86% of everything the gap scan legitimately
contributes. The same alignment with the previous function ending on its first byte collapses to
36.7% — worse than the corpus base rate.

That also corrects the earlier framing. The 348 unaligned-but-real are not scattered: 322 of them
(92.5%) sit immediately after a recovered function, which is what a hot/cold split or a
`.text.unlikely` tail looks like. They are not indistinguishable from the 5,702 spurious, they were
being described by the wrong field.

Read as filters:

| rule | spurious removed | real lost |
|---|---|---|
| refuse unaligned | 5,702 (93.6%) | 348 (10.05% of gap recall) |
| **refuse unaligned *and* not following a function end** | **1,683 (27.6%)** | **26 (0.75%)** |
| refuse anything following a function end | 1,827 | 2,999 (86.6%) — catastrophic |

**Not proposed as it stands, for two reasons.** 26 real functions is still a recall drop, and the
gate on this branch is that TPR does not fall on any corpus at any step. And the measurement is
circular: "follows a recovered function's end" is defined against a set that includes the 6,093
spurious functions, so removing 1,683 of them changes the very feature the rule reads. The static
table is an estimate of a rule, not a measurement of one.

The non-circular form of the same question — how much padding the *image* has in front of the
candidate — is what the next measurement asks, because that field is in the buffer rather than in
the answer.

---

## 2026-08-25 — the same question read from the image instead of from the answer

The circular feature replaced with one the buffer carries: how many padding bytes (`cc`, `90`, `00`)
immediately precede the candidate. Same 24 Rust cells, same population:

| 16-byte aligned | padding in front | real | spurious | precision |
|---|---|---|---|---|
| **yes** | **yes** | **2,995** | **79** | **97.4%** |
| yes | no | 121 | 312 | 27.9% |
| no | yes | 140 | 704 | 16.6% |
| no | no | 208 | 4,998 | 4.0% |

The pair survives the change of instrument, and the good cell is cleaner than the circular version
made it look: 97.4% against 95.4%, holding 86.5% of everything the gap scan legitimately finds.
Aligned-and-padded against unaligned-and-unpadded is a **24-fold** difference in precision, read
entirely off bytes that are in the file.

The bad cell is not as clean, and that is the finding that matters:

| rule | spurious removed | real lost |
|---|---|---|
| refuse unaligned | 5,702 | 348 |
| refuse unpadded (any alignment) | 5,310 | 329 |
| refuse unaligned *and* unpadded | 4,998 | **208** |
| refuse unaligned *and* not following a function end (circular) | 1,683 | **26** |

The circular feature is eight times more discriminating than the buffer one, and cannot be trusted
from a static table; the buffer feature can be trusted and costs 208 real functions. Neither is free,
so neither passes the gate this branch holds itself to.

The padding-run histogram says why the cheap version of this idea does not work:

| padding bytes in front | real | spurious |
|---|---|---|
| 0 | 329 | 5,310 |
| 1 | 570 | 277 |
| 2 | 382 | 340 |
| 3 | 44 | 124 |
| 4 | 190 | 16 |
| 5 | **1,557** | 10 |
| 6–7 | 47 | 7 |
| 8+ | 345 | 9 |

One padding byte already flips the balance in favour of real, and from four bytes up it is nearly
pure — 2,139 real against 42 spurious. But 329 real functions have nothing in front of them at all,
which is why "requires padding" is not a rule, and 277 spurious sit behind a single byte, which is
why "any padding at all" is not one either.

Recorded as a characterisation rather than a proposal. What it changes is the shape of the remaining
agenda: the gap scan is not uniformly imprecise, it is two populations, and the next thing worth
knowing is whether the same split holds on a corpus that is not mingw Rust.

---

## 2026-08-25 — the split holds on three corpora, and weakens with each one

The alignment-and-padding pair, measured the same way on three corpora. 260 C/C++ x86 cells and 72
AArch64 cells joined the 24 Rust ones; no cell was skipped in any of the three.

| corpus | n | aligned + padded | aligned, no padding | unaligned + padded | unaligned, no padding | gap-scan precision overall |
|---|---|---|---|---|---|---|
| Rust (gnu targets, x86) | 24 | **97.4%** (2,995 / 79) | 27.9% | 16.6% | **4.0%** (208 / 4,998) | 36.2% |
| C/C++ x86 (gcc, clang, mingw) | 260 | **89.6%** (13,889 / 1,620) | 51.6% | 16.4% | **14.2%** (2,278 / 13,747) | 46.9% |
| C/C++ AArch64 (gcc cross) | 72 | **65.2%** (980 / 524) | 36.5% | 3.1% | **29.0%** (952 / 2,335) | 39.3% |

**The direction is the same on all three and the strength is not.** Aligned-and-padded against
unaligned-and-unpadded is a 24-fold precision difference on Rust, 6.3-fold on x86 C/C++ and 2.2-fold
on AArch64. What a filter would buy follows the same collapse:

| corpus | spurious removed | real lost | ratio |
|---|---|---|---|
| Rust | 4,998 | 208 | 24 : 1 |
| C/C++ x86 | 13,747 | 2,278 | 6 : 1 |
| C/C++ AArch64 | 2,335 | 952 | 2.5 : 1 |

On AArch64 it is barely a filter at all, and the reason is structural rather than statistical: every
AArch64 instruction is 4-byte aligned, so "not 16-byte aligned" says far less there than it does
about a variable-length x86 encoding. A rule built on the Rust number and applied tree-wide would be
close to a coin toss on the corpus with the worst precision of the eleven.

**This is why the two-corpus rule exists.** The single-corpus version of this measurement pointed at
a 24-fold effect and would have justified shipping something; the third corpus prices it at 2.2.

### One correction to the earlier AArch64 run

The first AArch64 pass reported zero padding in front of every one of its 6,133 candidates, which is
not a finding — the padding set was `cc`/`90`/`00`, and AArch64 pads with the four-byte NOP
`1f 20 03 d5`. The corrected run added a control printing what actually precedes a candidate, and it
reads `1f2003d5` 1,536 times and `c0035fd6` — `ret` — 1,063 times. Every measurement here now carries
that control.

That control also named the next question. A thousand AArch64 candidates sit directly behind a `ret`
with no padding at all, and the padding-only feature files every one of them under "nothing in
front" together with the genuine noise.

---

## 2026-08-25 — master has lost precision on the malware corpus since 4.4.7

An upstream pull request merged on 2026-08-11 recorded a malpedia figure of macro F1 **95.4551** at
TPR 98.5302. Today's master measures **95.142**. Both numbers are in the same units, so the first
thing to establish was whether the two instruments agree at all.

Re-measuring that pull request's tip (`e394a45`) through **today's** harness returns F1 **95.455**,
TPR **98.530**, PPV 93.193 — the historical figure reproduced to three decimals. That is the control:
the comparison below is between two commits, not between two ways of counting.

| commit | date | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|---|
| `e394a45` | 2026-08-11 | 93.193 | 98.530 | 95.455 | 21,682 | 2,501 | 242 |
| `802e627` | 2026-08-24 | 92.639 | 98.561 | 95.142 | 21,688 | 2,583 | 236 |
| Δ | | **−0.554** | +0.031 | **−0.313** | +6 | **+82** | −6 |

Recall went *up*. A gate that watches recall alone — which is the gate this branch holds itself to —
would not have seen this at all.

### Bisected

Twenty-four commits touch `src/smda/` in that window. Six measurements over the range, n=57 and filter
`all` throughout, and the corpus is deterministic (three consecutive commits returning byte-identical
counts is the evidence for that):

| commit | pull request | PPV | TPR | F1 | FP |
|---|---|---|---|---|---|
| `e394a45` | #233 tip | 93.193 | 98.530 | 95.455 | 2,501 |
| `8f8070e` | #268 | 93.193 | 98.530 | 95.455 | 2,501 |
| `91097b6` | #273 | 93.193 | 98.530 | 95.455 | 2,501 |
| `785b148` | #282 | 93.197 | 98.530 | 95.457 | 2,500 |
| `9ab1329` | #284 | 93.180 | 98.523 | 95.443 | 2,508 |
| **`5f70672`** | **#285** | **92.639** | **98.561** | **95.142** | **2,583** |
| `802e627` | master | 92.639 | 98.561 | 95.142 | 2,583 |

**Effectively all of it is one commit.** `5f70672` — "recover the function starts four boundary
defects were hiding" — takes 7 true positives and gives back **75 false positives**, a 1 : 10.7 trade.
`9ab1329` accounts for a further −0.014 and `785b148` for +0.002; the other twenty-one commits move
nothing on this corpus.

### Why it was not caught

The commit records its own measurement, and it is a good one: 50 labelled binaries, each scored
against its own symbol table with analysis run on the stripped copy, body splits down from 712 to 316,
recall unchanged, no file regressed, every bundled fixture identical.

Those 50 binaries are gcc and clang ELF executables. The corpus that pays for the change is 57 PE
memory dumps of malware, and it was not measured. The rule this breaks is already written down here
from the other direction: a change measured neutral on the corpus you have can still cost on the
corpus that exercises the path. Here a change measured *good* on the corpus available costs on one
that was never consulted — same instrument error, opposite sign.

Not a proposal yet. `5f70672` fixes four real defects and the 396 body splits it removes are on a
population this repository can also measure, so what it is worth elsewhere has to be priced before
anything is said about it. The next measurement is the four ByteWeight PE sets either side of it,
which are the corpora closest in kind to the one paying.

---

## 2026-08-25 — the position family of gap-scan filters, closed out

The AArch64 control named a third position: a thousand candidates sit directly behind a `ret` with no
padding at all, which the padding-only feature files under "nothing in front" with the noise. Adding
that — is the candidate preceded by padding, by a decoded instruction that *ends* a function, by other
decoded code, or by nothing decoded at all — over all three corpora, 356 cells:

| corpus | padded | after a terminator | after other code | nothing decoded |
|---|---|---|---|---|
| Rust, 24 cells | 3,135 / 783 | 329 / 5,270 | 0 / 0 | 0 / 40 |
| C/C++ x86, 260 cells | 14,654 / 5,531 | 3,008 / 14,399 | 0 / 20 | 2 / 15 |
| C/C++ AArch64, 72 cells | 981 / 555 | 1,218 / 2,541 | 169 / 35 | 43 / 591 |

*(real / spurious)*

**On intel the feature is very nearly constant and therefore useless.** Every gap candidate on both
x86 corpora is either padded or sitting directly behind a terminator — "after other code" is 0 of
9,557 on Rust and 20 of 37,629 on C/C++. Refusing the residue buys 40 spurious on Rust and 35 on
C/C++, for 0 real functions in both cases. It is not a filter, it is a rounding error.

That is a real answer rather than a null one: the gap scan on intel does not book candidates in the
middle of nowhere. It books them where a function plausibly ends, and the false positives are in the
same places as the true ones.

**On AArch64 it separates, and still costs.** "Nothing decoded in front" is 43 real against 591
spurious — 6.8% precision, 13.7 spurious per real function lost, which is the best ratio any rule has
reached on this corpus and still not free. `after other code` inverts: 169 real against 35, 82.8%.

Controls printed on every row. Terminators seen immediately before a candidate: `jmp` 11,913 and `ret`
5,484 on C/C++ x86; `jmp` 3,154 and `ret` 2,445 on Rust; `b` 2,549, `ret` 1,063 and `br` 147 on
AArch64.

**This closes the family.** Alignment, padding, following-a-terminator and following-decoded-code are
the four position facts available before a candidate is analysed, measured in every combination on
three corpora and 356 cells. None of them yields a cut that removes spurious candidates without
removing real functions, on any corpus. The precision headroom in the gap scan is real — it books
6,093, 19,965 and 3,722 spurious candidates on the three — but it is not reachable from where the
candidate sits. Anything that reaches it has to use what the address is *used as*, which is the same
conclusion the landing-pad work reached by a different route.

---

## 2026-08-25 — the malware-corpus loss is one condition, and it is not the one it looked like

`5f70672` changes seven files. Two hypotheses about which part costs the malware corpus were wrong
before the third was right, and both were refuted by measurement rather than by reading.

**Attribution first.** Diffing the recovered address sets either side of the commit, per sample, with
the booking pass recorded for every address:

- gained **10 true positives** (all `addReferenceCandidate`) and **76 false positives**
  (`addGapCandidate` 54, `addReferenceCandidate` 22)
- lost 3 true positives and 1 false positive, all `addGapCandidate`
- net **+7 TP / +75 FP**, and **only 8 of 57 samples changed at all**

Two samples carry 73 of the 76: `geodo` gains 40 false positives and **zero** true ones, `feodo` gains
33 false positives and 4 true ones. On `feodo` every one of the 37 gained addresses falls inside a
single pre-existing function, in a 0x340-byte window.

**Wrong hypothesis 1: the new register-base jump-table recovery.** Logging every resolution that
returns targets, on `feodo`, either side of the commit: *five* resolutions on both sides, the same
five dispatch sites, the same target counts, the same address ranges. Identical. The jump-table half
of the commit does nothing on this sample.

**Wrong hypothesis 2: the widened backward-walk allowlist.** The diff moves
`_VALUE_PRESERVING_MNEMONICS` out of `IndirectCallAnalyzer` into `definitions.py` — with identical
membership. A pure move.

**The actual cause** is one condition added to the inferred alignment floor in
`common/FunctionCandidateManager.py`:

```python
and not candidate.is_exception_handler
and not candidate.call_ref_sources          # added by 5f70672
```

Every call-referenced candidate now skips the floor. The commit argues it well — the floor is
inferred from call-referenced candidates and tolerates a twentieth of them sitting off it, so
applying it back to that same population discards what the inference allowed for. The prologue-scan
half of the commit cannot be involved here at all: it keys on `push r15; push r14`, and these are
32-bit dumps.

Reverting that single line on top of `5f70672`, everything else in the commit left in place:

| tree | PPV | TPR | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| `9ab1329`, before the commit | 93.180 | 98.523 | 95.443 | 21,681 | 2,508 | 243 |
| `5f70672`, the commit | 92.639 | 98.561 | 95.142 | 21,688 | **2,583** | 236 |
| `5f70672` minus that one condition | 93.180 | 98.515 | 95.439 | 21,679 | **2,508** | 245 |

**The false-positive count returns to 2,508 — the pre-commit figure to the unit.** One condition owns
all 75. It buys 9 true positives on this corpus and costs 75 false positives, a 1 : 8.3 trade; the
rest of the commit is −2 true positives and no false positives here.

No proposal yet, and deliberately so. The exemption was justified on 50 labelled ELF binaries and the
question is what it is worth *there* — a condition that is right on ELF and wrong on PE dumps wants a
narrower predicate, not a revert. The ByteWeight PE sets and the 260-cell C/C++ matrix are running
either side of the same single line.

---

## 2026-08-25 — pricing the exemption on the corpus it was justified against

The 50-binary boundary corpus behind the commit's own measurement is now available here, with its
scoring harness, so the condition can be priced on both sides rather than only on the side that pays.
The truth extractor reports 11,384 labelled functions, which matches the figure recorded for it — the
control that the corpus is the same one.

All three trees are `5f70672`; the only difference is that one line.

**The 50 ELF binaries, `recall` and `body_splits`, analysis run on stripped copies:**

| variant | recall | recovered | body splits |
|---|---|---|---|
| exemption as shipped | **95.098%** | 10,826 / 11,384 | 306 |
| narrowed to more than one call reference | 95.081% | 10,824 | 308 |
| no exemption | 94.993% | 10,814 | 308 |

**The 57 malware dumps, filter `all`, macro mean:**

| variant | PPV | TPR | F1 | TP | FP |
|---|---|---|---|---|---|
| exemption as shipped | 92.639 | 98.561 | 95.142 | 21,688 | **2,583** |
| narrowed to more than one call reference | 93.038 | 98.548 | **95.373** | 21,685 | 2,540 |
| no exemption | 93.180 | 98.515 | 95.439 | 21,679 | 2,508 |

**The exemption is not a mistake.** It buys 12 real functions on the corpus it was written for and
removes two body splits. It is a predicate that is right on ELF executables and wrong on memory dumps,
which is a different thing from a defect and wants a narrower predicate rather than a revert.

### The narrower predicate the codebase already names

`FunctionCandidate.getConfidence` scores a candidate with more than one inbound call reference at
1.0 outright, on the stated grounds that *multiple* inbound call references are essentially always a
function. One is weaker evidence, and the tree already says so. Requiring the same threshold before
the alignment floor is waived:

- keeps **10 of the 12** ELF functions the exemption gains — 83% of its benefit
- removes **43 of the 75** malware-corpus false positives — 57% of its cost
- recovers **+0.231** of the 0.297 F1 the corpus lost, or 78% of it

It is a strict improvement on what is shipped, on both corpora at once, and it is still not free:
malpedia recall goes 98.561 → 98.548 and ELF recall 95.098 → 95.081. Under this branch's own rule —
no recall drop on any corpus at any step — it would not land here as it stands.

### Where the full ledger sits

Effect of the condition as shipped, both sides at `5f70672`, every corpus available here:

| corpus | n | ΔF1 | ΔTP | ΔFP |
|---|---|---|---|---|
| boundary corpus (50 ELF) | 50 | *recall +0.105 pt* | **+12** | *−2 body splits* |
| Bao byteweight msvc10-32 | 68 | +0.011 | +2 | −2 |
| Bao_Dumped msvc10-32-d | 56 | +0.013 | +2 | −2 |
| Built C/C++ (gcc, clang, mingw) | 260 | −0.001 | +34 | +26 |
| Bao byteweight msvc10-64 | 68 | −0.002 | −3 | +6 |
| Bao_Dumped msvc10-64-d | 56 | −0.036 | −3 | **+75** |
| Plohmann malpedia itw | 57 | **−0.297** | +9 | **+75** |

The two corpora that pay are both 64-bit-capable dumped sets, but "dumped" is not the discriminator:
the 32-bit dumped ByteWeight set *gains* 0.013, and the sample that gains the most false positives on
malpedia is a 32-bit dump. What separates them is not yet established, and finding it is what would
turn the narrowed predicate into a free one.

---

## 2026-08-25 — a predicate that costs nothing where the change was justified

Profiling every candidate the exemption admits — not the net effect, the candidates themselves —
across both corpora, classified the way each corpus classifies an address.

**The first version of this probe was wrong and the ELF column is what showed it.** Counting "not in
the truth set" as an error there made the exemption look 45% precise, with the *spurious* side
carrying more call references (median 7) and higher confidence (1.0) than the real side. That is the
signature of PLT stubs: the corpus labels `.symtab` FUNC symbols only, and its own metric says
unlabelled code is "neither credited nor penalised, since unlabelled code is real code". Scoring it
as a false positive turns every import stub into an error.

Re-run with that corpus' three-way classification — a labelled start, a **body split** (strictly
inside a labelled function, its unambiguous error), or unlabelled:

| 100 exempted and recovered, 50 ELF binaries | labelled start | body split | unlabelled |
|---|---|---|---|
| count | 45 | **0** | 55 |
| has a common entry shape | 39 (86.7%) | – | 55 (100%) |

**Zero body splits.** The exemption produces no errors at all on the corpus it was written for.

On the malware corpus, where the truth does include thunks so "not in truth" is a real error:

| 94 exempted and recovered, 57 dumps | real (71) | spurious (23) |
|---|---|---|
| has a common entry shape | 66 (93.0%) | 5 (21.7%) |
| exactly one call reference | 49 (69.0%) | 23 (100.0%) |
| **neither of the two** | **3 (4.2%)** | **18 (78.3%)** |

Every spurious one has exactly one call reference, and 78% have no entry shape either. So waive the
floor only for a candidate that is call-referenced **and** either entry-shaped or referenced more
than once.

### Measured end to end, four variants, both corpora

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

**It is byte-identical to the shipped exemption on the ELF corpus** — same recall, same recovered
count, same body splits — while removing **31 of the 75** false positives the exemption costs on the
malware corpus, for **2** true positives. The narrower `>1 reference` variant removes more (43) but is
no longer free on ELF: it costs 2 functions and adds 2 body splits.

That is the honest ranking. Neither is free on the malware corpus, so neither clears a
no-recall-drop gate; but one of them is free where the change was justified, which the other is not,
and that is a better answer than the revert this started from.

Not landed: this is `master`'s code and the finding is reported rather than pushed. What the two lost
true positives are is the next thing to look at, and would decide whether a third clause closes it.

### What the two cost true positives are

Diffing the recovered sets directly rather than the aggregates: the predicate is a **strict subset**
of what the shipped exemption recovers — 31 false positives dropped, 2 true positives dropped, **0
addresses gained**, so there is no churn hiding inside the net figures.

Both losses are `addReferenceCandidate` bookings: `0xb8c08e` on `feodo` and `0x1e05ae9` on `urlzone`.
Each is a real function whose entire evidence is one call reference and no recognised entry shape —
the same bucket the predicate refuses, and the same bucket that holds 18 of the 23 spurious
admissions. Separating two from eighteen on a corpus of this size is not a rule, it is a coin toss
with a good story, so no third clause is proposed. The predicate's cost is 2 functions in 21,924 and
that is where it stands.

---

## 2026-08-25 — the malware corpus' precision is mostly a truth gap, not over-detection

Two questions about the corpus itself, both answerable from what it already ships.

### Is truth landing outside an executable section a defect?

No, and it costs almost nothing. The harness flags 12 of 57 dumps as holding truth outside every
area SMDA treats as code. Measuring recall separately inside and outside those areas:

| | truth | recovered |
|---|---|---|
| inside SMDA's code areas | 6,499 | 6,469 — **99.54%** |
| outside them | 333 | 312 — **93.69%** |

`dyre`, the worst-flagged sample at 174 of 461, recovers **173 of its 174** outsiders; they sit in
`.rsrc`, which is where a packed sample keeps a payload. `heloag` is the extreme case — its `.text`
carries no executable characteristic at all and it has an `.aspack` section — and it is not flagged,
because SMDA's own loader treats it as code anyway, which is the right answer for a dump.

So the flag means "this image's section table does not describe where its code is", which is normal
for the workload, rather than "this truth is wrong". **I said earlier that it depresses precision on
those samples; that was an assumption and it is wrong** — the addresses are real, and the engine
finds 94% of them.

### What the 2,582 false positives actually are

The `.fnmap` truth maps **every instruction** to its owning function, not just the starts, so a
detection can be classified exactly the way the 50-binary ELF corpus classifies one:

| of 24,270 detections | count | share |
|---|---|---|
| a labelled function start | 21,688 | 89.4% |
| **a body split** — a labelled instruction that is not its function's start | **283** | **1.2%** |
| outside every labelled instruction | 2,299 | 9.5% |

**Only 283 of the 2,582 the harness scores as false positives — 11% — are unambiguous errors.** The
other 2,299 are addresses the labelling never covered, and the ELF corpus' stated convention for
exactly that population is that it is "neither credited nor penalised, since unlabelled code is real
code".

Counted that way, micro precision on this corpus is **98.71%** rather than the 89.36% reported.

### Where the 2,299 are

| | share of 2,299 |
|---|---|
| beyond the labelled span entirely | 62.4% |
| five or more instructions | 76.9% |
| something references them | 47.8% |

And they are concentrated, with a mechanism visible in each case:

| sample | outside detections | where |
|---|---|---|
| `corebot` | 1,281 | **1,247 in `.x64`** — a 1.4 MB section; its truth spans `0x91000-0xc6849` and `.x64` begins at `0xcc000` |
| `shujin` | 175 | 168 in `.vmp0`, a VMProtect section beyond a labelled span ending at `0x412f95` |
| `bolek` | 105 | 80 in `.data`, 25 in `.text` |

`corebot` is unambiguous: the image carries a 32-bit body and an embedded 64-bit payload, and the
truth labels only the first. That one sample is **54% of every unlabelled detection in the corpus**.

### What follows

The reported PPV understates this engine on this corpus, and the gap is bookkeeping rather than
recovery. Two things follow, and both are harness work rather than disassembler work:

1. Report body splits beside PPV wherever truth carries instruction-level coverage, so a truth gap
   cannot read as over-detection. malpedia's `.fnmap` already carries it and the harness throws it
   away, keeping only the starts.
2. `corebot`'s truth describes part of its image. It belongs in `KNOWN_TRUTH_DEFECTS` with that
   evidence, the way the ByteWeight entry already records its own.

Neither changes a published figure — a body-split column is added beside PPV, not instead of it.

---

## 2026-08-25 — why one call reference is worth more on an ELF than on a dump

The open question was what separates the corpora the alignment-floor exemption helps from the ones
it costs. It is not the corpus. It is whether the *referencing instruction* is real code.

Taking only the bucket the entry-shape predicate cannot save — a candidate with exactly one call
reference and no recognised entry shape — and asking where that one reference comes from:

| one reference, no entry shape | count | the referencing instruction is itself labelled code |
|---|---|---|
| malpedia, real | 3 | 2 (66.7%) |
| **malpedia, spurious** | **18** | **0 (0.0%)** |
| ELF, real | 5 | 5 (100%) |
| ELF, spurious | 0 | — |

**Every one of the eighteen spurious admissions is referenced from an instruction that is not real
code.** The evidence the exemption trusts was manufactured by a misdecode: something in a packed or
obfuscated region decoded as a `call`, and its operand became the only reason an address off the
alignment floor was admitted.

That explains the whole corpus split without appealing to the corpus. A lone call reference in a
compiler-built ELF comes from an instruction that is really there, so it is good evidence; in a dump
of packed malware it often does not, so it is not. The exemption is not wrong about ELF and right
about dumps — it is trusting a signal whose reliability depends on something it never checks.

**Sample size is the honest limit here**: 26 candidates across both corpora, 18 of them the spurious
side. A 18-to-0 split is clean and the mechanism is sensible, but it is not a population you fit a
rule to. What it gives is a direction, and the next measurement is the mechanism on a larger one —
every singly-referenced candidate rather than only the ones this exemption admits.

**Implementability is the second open question.** "The referencing instruction is labelled code" is
not available during analysis; the runtime proxy would be something like "the reference comes from
inside a function already recovered on stronger evidence", and whether that proxy separates the same
way has to be measured rather than assumed — it reads the recovered set, which is the circularity
that already caught this investigation once.

### The same question on the whole population

26 candidates is a direction, so the same test over **every** recovered candidate carrying exactly
one call reference — 8,836 on the dumps, 2,197 on the ELF binaries:

| malpedia, 57 dumps | count | precision |
|---|---|---|
| the reference comes from real code | 8,120 | **98.9%** |
| it does not | 716 | **6.1%** |

**A sixteen-fold separation over 8,836 candidates.** 672 of the 759 spurious singly-referenced
candidates on this corpus are admitted on a reference that is not a real instruction. The mechanism
holds far beyond the 26 it was found in.

| boundary corpus, 50 ELF | count | precision |
|---|---|---|
| the reference comes from real code | 2,137 | 95.8% |
| it does not | 60 | 83.3% |

**And it does not separate on ELF**, which is the point rather than a disappointment: only 60 of
2,197 land in the weak bucket at all, because on a compiler-built binary nearly every call site is a
real instruction. The signal exists where misdecoded regions do.

Two limits, both load-bearing:

- **The ELF "spurious" column is contaminated** in the way already recorded here — that corpus labels
  `.symtab` FUNC symbols only, so a PLT stub counts as spurious. 90 of its 100 are referenced from
  real code, which is what an unlabelled real function looks like. Read the ELF row as "no usable
  separation", not as a precision figure.
- **This is a diagnostic, not a rule.** "The referencing instruction is real code" was answered from
  ground truth. During analysis the engine cannot ask that, and the obvious proxy — "the reference
  comes from inside an already-recovered function" — reads the recovered set, which is the
  circularity that has already misled this investigation once. Whether the proxy separates the same
  way is the next measurement, and it has to be made before any of this becomes a change.

As a filter it would cost 44 real functions on the dumps to remove 672 spurious ones, a 15 : 1 trade
— better than anything else measured on this corpus, and still not free.

### The proxy the engine could compute, and why it does not work

The test above answered "is the referencing instruction real code" from ground truth. The engine
cannot. The nearest thing it can ask is "did I decode an instruction at that address", so the two
were measured side by side on the same 8,836 candidates:

| malpedia | count | truth: the reference is real code | proxy: the engine decoded it |
|---|---|---|---|
| real | 8,077 | 8,033 (99.5%) | 7,989 (98.9%) |
| **spurious** | 759 | **87 (11.5%)** | **624 (82.2%)** |

| split by | precision when yes | precision when no |
|---|---|---|
| ground truth | **98.9%** (n=8,120) | **6.1%** (n=716) |
| the proxy | 92.8% (n=8,613) | 39.5% (n=223) |

**The proxy collapses the separation from sixteen-fold to 2.3-fold**, and the reason is exact: it
answers "did I decode this", and in these cases the engine's own decoding is the thing that is
wrong. 82% of the spurious references point at an instruction SMDA decoded — it decoded the
misdecode. Asking it to check its own work catches almost nothing.

As a filter the proxy would remove 135 spurious candidates for 88 real ones, 1.5 : 1, against the
ground-truth version's 15 : 1. It is not usable.

**This closes the thread with a negative that is worth more than the rule would have been.** The
signal separating these false positives is real, large and consistent — and it is not visible from
inside the engine, because the only instrument the engine has is the one that produced the error.
Anything that reaches this class has to bring evidence from outside the disassembly: a declared
entry, an unwind record, a symbol, a relocation. Which is the same conclusion the landing-pad work
and the gap-scan position family both arrived at by different routes, now with a mechanism attached.

---

## 2026-08-25 — the endbr64 ceiling: the proposed repair cannot work, and why

Section 13's largest precision item ends with an unmeasured claim: that the repair "belongs after
analysis, as a filter on candidates the jump-table pass has claimed", with the ceiling being the
non-declared landing pads minus however many that pass does not resolve. Measuring the overlap over
the 140 ELF cells of the C/C++ corpus, no cell skipped:

| | count | of which the jump-table pass resolved |
|---|---|---|
| false positives, all | 10,389 | – |
| **false positives opening with `endbr64`** | **5,076** | **0 (0.0%)** |
| true positives opening with `endbr64` | 61,119 | 2 |

**Not one.** Against 46,411 jump-table targets resolved across the same run, so the hook is live; and
the intersection does work, because it catches two true positives. This is a zero with its controls.

**It is a zero by construction, which is the finding.** When the jump-table pass resolves an address,
that address becomes a *block of the enclosing function* — it never becomes a function of its own. So
the resolved targets and the spurious functions are disjoint sets by definition: the spurious pads are
exactly the case bodies the pass **failed** to resolve. A filter on what the pass claimed can never
reach them.

The shape confirms it. Every one of the 5,076 sits strictly between two consecutive truth starts:

| | |
|---|---|
| strictly inside a real function | **5,076 (100.0%)** |
| before the first truth start | 0 |
| distinct real functions they shatter | 1,846 |
| average pads per shattered function | 2.7 |

and 121 of those functions carry eight or more spurious pads apiece, which is a dispatch nobody
resolved rather than a scattering of bad guesses.

**So the item is re-ranked rather than closed.** The lever is not a filter at all — it is jump-table
resolution itself. Every case body the pass learns to resolve stops being a false positive *and*
stops shattering a real function, in one move, with no recall cost by construction because the
address stays in the report as a block. The 5,076 are worth roughly 5 points of precision on this
corpus and they are the *symptom*; the disease is 1,846 unresolved dispatches.

That also makes this the one item on the agenda whose fix cannot fail the no-recall-drop gate, which
moves it to the top.

---

## 2026-08-25 — the endbr64 false positives are C++ exception landing pads

Having established that the 5,076 spurious pads shatter 1,846 real functions and that the jump-table
pass resolves none of them, the obvious reading was "unresolved switch dispatches". **That is wrong**,
and the measurement that says so is the same instrument pointed one step further: of the 1,846
shattered functions, **1,757 (95.2%) contain no indirect jump at all.** A function with no indirect
branch in it cannot be hosting an unresolved jump table.

Grouping the pads by what built the binary:

| spurious `endbr64` pads | count | share | cells |
|---|---|---|---|
| C++ | **4,818** | 94.9% | 28 of 140 |
| C | 258 | 5.1% | 112 of 140 |

| carries `.gcc_except_table` | pads |
|---|---|
| C, no LSDA | **0** |
| C, with LSDA | 258 |
| C++, with LSDA | 4,818 |

**Every one of the 5,076 sits in a binary carrying an LSDA, and a binary without one contributes
exactly zero.** C++ is 20% of the cells and 95% of the pads.

These are **exception landing pads**. `-fcf-protection` emits `endbr64` at every address an indirect
branch may reach, and the personality routine transfers control to a landing pad indirectly — so gcc
marks each one, they sit inside a function body, and nothing in that function branches to them. Which
is exactly the 95.2% with no indirect jump.

**And that puts the repair on image-declared evidence**, which is where the earlier closure said
anything reaching this class would have to come from. `.gcc_except_table` is the image's own
statement of where its landing pads are: an LSDA call-site table names them explicitly. A rule that
declines to seed a prologue candidate at a declared landing pad reads a fact the compiler wrote down,
not a fact the disassembler inferred — the same shape as the `.eh_frame` FDE rule already landed, one
level more precise.

Worth up to 5,076 false positives and 1,846 repaired function boundaries on this corpus, roughly five
points of precision. **Correlation is not yet the claim**: this establishes that the pads only occur
where an LSDA exists, not that the pads *are* the addresses the LSDA declares. Decoding one and
intersecting is the next step and has to come before any of this is proposed.

### Two attempts to confirm the landing-pad reading, both flawed, and where it actually stands

The correlation above is strong but it is correlation. Two attempts to turn it into a direct claim
both failed, in ways worth recording because each looked like an answer.

**Attempt one, decoding the LSDA, was a broken probe.** It reported 0 of 4,818 spurious pads among
40,561 declared landing pads. That zero is an artifact: `LPStart` in an LSDA header defaults to the
*function start the FDE names*, and the decoder defaulted it to 0, so every "declared pad" it computed
was a section-relative offset being compared against an absolute address. The two number spaces cannot
intersect, so the zero was guaranteed before the data was read. The control that should have caught
it did, quietly — "36 real functions declared as landing pads" is a coincidence-sized number, and a
real one would have been 0.

**Attempt two, looking for the C++ runtime, was under-powered.** It asked whether each spurious
detection reaches `__cxa_begin_catch` / `_Unwind_Resume`, and found 1.9% against 1.3% for real
functions — no separation. But these detections are two or three instructions long: a landing pad
would not call the runtime *in its own first block*, it would fall into a cleanup path further on,
which the harness attributes to a different recovered function. The test could not have found what it
was looking for.

**What is solid.** Following the terminating branch of each spurious detection, over the 28 C++ cells:

| | count | share |
|---|---|---|
| jumps into a labelled function's **interior** | 3,884 | 80.6% |
| jumps to a labelled function's **entry** | 487 | 10.1% |
| carries no jump at all | 386 | 8.0% |
| indirect jump | 61 | 1.3% |

The 80.6% is the useful number, and it strengthens the interiority claim rather than the thunk one: a
standalone thunk the symbol table failed to name would jump to another function's *entry*, and only
487 do. Four in five of these detections branch into the middle of a labelled function, which is what
a block of that function does.

**Where this leaves it.** The landing-pad reading is still the leading hypothesis — the LSDA
correlation is perfect, the enclosing functions carry no indirect jump, and four in five of the
detections behave like interior blocks. It is not confirmed, and neither instrument I reached for
could confirm it. Doing so needs a correct `.eh_frame` walk that reads each FDE's augmentation for
its LSDA pointer and decodes the call-site table with `LPStart` defaulting to that FDE's function
start. That is the next step, and until it is done this is a hypothesis with strong circumstantial
support, not a finding.

The 487 that jump to a labelled entry are a separate and smaller result: those are real code the
symbol table does not name, the same completeness effect already measured on the malware corpus,
and they are not false positives at all.

### Confirmed: they are declared landing pads, and the decoder had one contract bug

The `.eh_frame` walk done properly — each FDE's augmentation read for its LSDA pointer, each LSDA's
`LPStart` defaulting to that FDE's function start:

| 28 64-bit C++ ELF cells | |
|---|---|
| landing pads decoded from the LSDAs | 25,525 |
| spurious `endbr64` detections | 4,818 |
| **spurious that are declared landing pads** | **4,757 (98.7%)** |
| **control: real functions declared as pads** | **0** |

The control is the part that makes this a result rather than a coincidence: a landing pad is interior
by construction, so a correct decode must never declare a real function start as one, and it declares
none of 23,106.

**The third bug was a contract, not a slip.** After fixing `LPStart` and the return-address-register
read, every LSDA still failed. The cause: `_read_encoded_value` in the in-tree `.eh_frame` decoder
deliberately refuses `uleb128`, and says so — *"uleb128/sleb128-encoded pointers are rare in
.eh_frame; not supported"*. True of an FDE pointer, and false of a call-site table, where uleb128 is
what gcc emits. Reusing a helper across the boundary its own comment draws returned `None` on every
record, and the empty result then read as "this binary declares no landing pads". Anyone extending
that decoder to LSDAs has to widen the reader first.

### What this is worth

The C/C++ corpus carries 10,389 false positives across its 140 ELF cells. **4,757 of them — 45.8% —
are addresses the image itself declares as exception landing pads.** A rule that declines to seed a
prologue candidate at a declared landing pad:

- reads a fact the compiler wrote down, not one the disassembler inferred, which is exactly what the
  earlier thread concluded anything reaching this class would have to do
- cannot cost a true positive by construction, and the control says so empirically: 0 of 23,106 real
  functions are declared pads
- also repairs the boundaries of the ~1,846 functions these pads were splitting

It is the same shape as the `.eh_frame` FDE-range rule already landed, one level more precise: that
one asks "is this address inside a declared function", this one asks "is this address a place the
unwinder is declared to jump to".

### Which pass books them, and why the rule already landed does not catch them

Before building anything, the obvious objection: this branch **already** refuses an `endbr64` prologue
seed that opens inside a declared FDE range, and a landing pad is inside one by definition. So why are
4,757 of them still in the report?

| the 4,757 declared-landing-pad false positives, by the pass that first books each | |
|---|---|
| `addGapCandidate` | **4,757 (100.0%)** |

**Every one comes from the gap scan.** The landed rule guards the seeding scan, and the gap scan books
these independently, afterwards, from bytes nothing else claimed. The two passes disagree about the
same addresses and only one of them was taught the FDE ranges.

That places the fix precisely: not a wider prologue rule, but a gap-scan rule — the gap scan must not
promote an address the image declares as a landing pad. It also explains the earlier finding that
these detections sit in functions with no indirect jump: the gap scan is not following a dispatch, it
is filling a hole, and a landing pad is a hole because nothing in the function branches to it.

## 2026-08-25 — the LSDA landing-pad rule, and the resume point that decides whether it costs recall

The `endbr64` work established what the spurious pads are: 98.7% of them are addresses the image's
own `.gcc_except_table` declares as exception landing pads, and all of them are booked by the gap
scan. This is the rule built on that, the sibling site it turned up in the AArch64 backend, and the
one design decision that separates a rule which costs recall from one that gains it.

### Reading the declaration

`.eh_frame` already had a decoder here; it did not read LSDAs. Each FDE whose CIE announces `L` in
its augmentation string opens its augmentation data with a pointer to its LSDA, and the LSDA's
call-site table names each landing pad as an offset from `LPStart` — which **defaults to the
function start the FDE names**, not to zero. An earlier probe that assumed zero compared section
offsets against absolute addresses and reported 0 of 4,818, a zero guaranteed by construction.

Two contract bugs in the reader had to be fixed before any of it decoded:

- `_read_encoded_value` refuses the leb128 formats by contract, on the grounds that leb128 pointers
  are rare in `.eh_frame`. That is true of FDE pointers and false of call-site tables, where
  uleb128 is exactly what gcc emits — so every table read as empty rather than as unreadable. A
  separate `_read_lsda_value` admits leb128 without widening what the FDE walk will decode.
- `_read_uleb128` signals failure through its **value**, returning `(None, pos)` where `pos` is
  always an int. A guard written as `if pos is None` after the ttype-offset read therefore never
  fired, and a corrupted cursor went on to decode the call-site table. Not dead code: on a
  constructed table the pre-fix tree returns a fabricated pad at `0x2020` where the fixed tree
  returns None.

Both are now covered by contract tests, and the decoder refuses the application modes it cannot
apply — datarel/textrel/funcrel would otherwise be read as absolute, which does not fail, it
silently yields a different address.

### One record walk, not two

The landing-pad walk began as a copy of `decodeEhFrameFdeRanges`'s record-boundary logic: the same
thirty lines of length, extended-length, record-end and CIE-pointer handling. A defect fixed in one
would have survived in the other, so both now drive off one `_walkEhFrameFdes` generator. The
refactor is output-identical over **21,798 FDE ranges across 12 sections**, four of them large
system libraries (`libstdc++.so.6`, `python3`, `bash`, `libc.so.6`), with a positive control that
8 of the 12 decode non-empty.

### The sibling: AArch64 books the same pads, through two passes

x86 books declared pads only through the gap scan — `endbr64` is not one of the prologue scan's
shapes. AArch64 is worse on both counts. `bti` **is** a recognized entry prologue there, so pads
reach `locatePrologueCandidates` as well, and on a small C++ fixture that pass books all five of
them while the gap scan books none.

Measured over the 72-cell AArch64 ELF corpus before any rule:

| | |
|---|---|
| declared landing pads | 12,585 |
| booked as functions by the current engine | 4,108 |
| of those pads, ones the compiler's symbol table calls a real start | **0** |

The `-bti` cells are the extreme: `googletest_gcc-arm64_O2-bti` books **1,219 of 1,219**. The
existing `_isLikelyInteriorBtiCandidate` shape test is what lets them through — under
`-mbranch-protection` every pad opens with a `bti`, and the test reads that as evidence of a
legitimate indirect-call target. A declaration beats a shape, so the rule has to run before it.

### The resume point is the whole decision

The first version stepped one instruction past a refused pad. On AArch64 that **cost 5 true
positives** while removing 553 false ones, and the trace says exactly why: refusing the pad at
`0x1dd60`, the scan books `0x1dd64` — one instruction *into* the pad — and that bogus function then
runs forward over two real functions the pad's own would have stopped short of. Booking the word
after the pad is a worse candidate than booking the pad.

The fix is to resume where the image says the function ends: `declaredLandingPadSkipTarget` returns
the end of the FDE that declares the pad. Everything between a landing pad and the end of its own
function is that function's body, so the skip passes over interior addresses only.

That is checkable rather than assumed. Counting true starts lying strictly between a pad and its
declaring FDE's end:

| corpus | samples with pads | declared pads | truth starts the skip would step over |
|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 44 | 25,748 | **0** |
| AArch64 ELF | 23 | 12,585 | **0** |
| Rust ELF | 8 | 2,882 | **0** |

41,215 pads, nothing at risk — which is why the skip turns a recall cost into a recall gain rather
than merely reducing it. The hazard it was checked against is real and recorded: a whole PLT block
sits under a single FDE, so a resume point landing inside one would lose every stub after the first.

### Three resume points on the AArch64 corpus, n=72, micro

| variant | TPR | PPV | recovered | detections |
|---|---|---|---|---|
| rule off | 97.923 | 79.529 | 54,961 | 69,108 |
| refuse the pad, resume one instruction on | 97.914 | 80.163 | 54,956 | 68,555 |
| refuse the pad, resume at the declaring FDE's end | **97.949** | **81.551** | **54,976** | 67,413 |

The one-instruction variant is also what cost 8 Rust true positives when this was first
measured; the FDE-end variant gains 13 there instead. Those two Rust figures come from different
runs and are not put in one table.

This supersedes the BTI sibling recorded in report section 21 as measured-and-rejected: that one
removed 2,861 false positives for **one** true positive lost, and the gate refused it. The rule
here removes more and loses none.

### End to end, six corpora, one tree, both sides back to back

`tools/bench/run.py --corpus native,native-arm64,rust,go,macho-arm64,dotnet --engine smda`,
one side per configuration. The rule shipped on as a result of this run, so reproducing the
baseline now means `--set USE_LSDA_LANDING_PADS=0` on the *before* side rather than `=1` on the
after side. Macro means, filter `all`, 0 failed samples on either side.

| corpus | n | PPV | TPR | F1 | dTP | dFP |
|---|---|---|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | 92.623 -> **94.109** | 95.525 -> **95.595** | 93.875 -> 94.718 | +193 | -7,312 |
| Built C/C++ AArch64 (gcc cross) | 72 | 76.676 -> **79.172** | 95.939 -> **95.963** | 84.852 -> 86.632 | +15 | -4,487 |
| Built Rust (gnu targets) | 24 | 78.951 -> **82.435** | 97.493 -> **97.578** | 87.185 -> 89.192 | +13 | -654 |
| Built Go (pclntab truth) | 45 | 95.111 | 99.618 | 97.266 | 0 | 0 |
| ARM64 Mach-O (LC_FUNCTION_STARTS) | 11 | 94.220 | 96.711 | 95.074 | 0 | 0 |
| Built .NET (CIL and NativeAOT) | 4 | 93.589 | 99.461 | 96.124 | 0 | 0 |

**12,453 false positives removed, 221 real functions gained, recall up on every corpus that moves
and identical on the rest.** `summarize.py --compare` reports `compared=6` and
`[ok] no TPR regression on any compared config`.

The three unchanged corpora are the reach control: Go emits no `.eh_frame` at all (21 ELF samples,
0 declaring a pad), and the Mach-O and .NET rows have no section for the rule to read. A rule that
moved them would be doing something other than what it claims.

The baseline side reproduces the published figures exactly — 92.623 / 95.525 / 93.875 on the 260
C/C++ cells and 76.676 / 95.939 / 84.852 on the AArch64 cells — and the recovered-function counts
agree to the unit with an independent scorer written for this measurement (54,961 AArch64,
32,985 Rust), which is the cross-check that the harness and the probe are counting the same thing.

### Shipped on by default

The earlier version of this rule was going to ship off, because it traded recall for precision. The
FDE-end resume point removes the trade, so the remaining question was whether it is free elsewhere:

- **Frozen fixtures.** Of the 33 bundled `tests/*_xored` samples, exactly the two added with this
  change move. No pre-existing baseline shifts.
- **Cost.** Timed with interleaved repeats and an off-vs-off control on the same machine and
  session: on the two cells carrying the most pads, analysis is **3.8% faster** with the rule on,
  because the ~1,500 candidates it refuses per cell are ones nothing then analyses. On the small
  fixtures the off-vs-off control swings -13% to +45%, so nothing is measurable there and the
  single-pass +88% readings taken first were noise — a reminder that a per-fixture A/B without a
  same-tree control measures the machine.

### Also landed: measuring an off-by-default option without editing the library

Every measurement of this kind so far meant editing `SmdaConfig` and remembering to put it back,
which is not reproducible from the repository and leaves no record in the result of which settings
produced it. `run.py --set NAME=VALUE` now overrides any config attribute for one run and records
the overrides in the result JSON, derived by diffing the instance against the class defaults so a
stock run records an empty set rather than claiming an override it does not have.

### What the decode costs on input built to make it cost

The rule reads a structure the analysed file controls, so its cost is a property of the input
distribution and every fixture here is benign. Timed directly, which nothing in the test gate does:
a 205 KB `.eh_frame` whose FDEs each name a 64 KB LSDA took **155 seconds**, scaling linearly with
the record count. Nothing stopped it — the analysis budget is polled between candidates, and this
walk happens inside one of them.

Two bounds fix it, and which quantity they count turned out to matter more than their size:

- **Decode each LSDA once.** One LSDA serves one function in a real image, but nothing stops every
  FDE naming the same one. Memoized by `(lsda address, function start)`, because the same table
  under a different function start declares different addresses.
- **Bound the call-site table bytes decoded per section**, and gate the read on the same budget —
  the reader is asked for 64 KB per LSDA, so a section naming a distinct table per record would
  copy that much per record even with each decode declining.

The first attempt charged the budget for bytes *read* rather than bytes *decoded*, and that is the
part worth recording: a reader asked for 64 KB gets 64 KB whenever the section is big enough, so
the budget was spent on bytes no loop ever touched. It bound on **four real binaries**, and
`googletest_gcc-arm64_O2-static` silently lost 197 of its 2,612 pads. The comment asserting "the
largest real section decodes under 2 MB" was written before it was measured; measured, the heaviest
real image decodes **31 KB** of call-site tables and `libstdc++.so.6` decodes 26 KB.

| shape | before | after |
|---|---|---|
| 10,000 FDEs naming one 64 KB LSDA | 155 s | 0.04 s |
| 200,000 FDEs naming distinct 64 KB LSDAs | unbounded | 2.5 s, 129 reads |
| heaviest real image (3,062 pads) | 31 KB decoded, 260x under the bound | unchanged |

Real pad counts are identical either side of the bounds: 25,748 / 12,585 / 2,882 over the three
corpora that carry any.

## 2026-08-25 — what a memory dump still declares, and two avenues closed with it

The report's section 22 established that the malware corpus' false positives are not reachable from
inside the disassembly: the separation that works reads "is the referencing instruction real code",
and the nearest question the engine can ask collapses it from sixteen-fold to 2.3-fold. Anything
that reaches this class has to bring evidence the *image* declares. This is a survey of what these
images still declare, and the two most obvious candidates measured and closed.

### What survives in 48 PE memory dumps

| directory | declared | lands inside the dump |
|---|---|---|
| Import table | 43 | 43 |
| Base relocations | 40 | 38 |
| IAT | 36 | 36 |
| Export table | 13 | 13 |
| Load configuration | 8 | 8 |
| Exception table | 3 | 3 |
| TLS | 1 | 1 |

### Control Flow Guard: the table is there and it is garbage

`GuardCFFunctionTable` is the loader's own list of every address it will accept as an indirect-call
target — image-declared function starts, exactly the shape section 22 asks for. Nothing in the tree
reads it.

All eight dumps that declare a load configuration declare an impossible one:

| sample | image size | table pointer | declared entry count |
|---|---|---|---|
| bolek | 368 KB | `0x67616d69` | 1,768,370,021 |
| corebot | 636 KB | `0x65726f63` | 7,565,407 |
| lurk | 64 KB | `0xee` | 12,320,959 |
| trickbot | 100 KB | `0x3167546a` | 2,020,890,693 |

`0x67616d69` is `"imag"` and `0x65726f63` is `"core"`. The load-config directory in an unpacked dump
points into arbitrary data, and every count exceeds the file it lives in by three orders of
magnitude. This needs no control to read as a negative: the values are not small or suspicious,
they are impossible.

The avenue is closed a second way as well. **0 of 160 well-formed PEs** across every built corpus
here declares a GuardCF table at all, so even a correct implementation could not be scored — which
is the same "no corpus exercises the path" objection that stopped the AArch64 sibling before a
corpus was built for it.

### Base relocations: readable, and too noisy in both directions

Relocations survive far better — 38 of 48 dumps carry a fully well-formed table. One thing has to be
said before any of that is usable: **LIEF exposes zero relocation entries for these images**, because
a dump carries no section table to map RVAs through. A pass written against `lief_binary.relocations`
would be silently inert on precisely the corpus it was written for. Walking the blocks by hand works.

Against the `.fnmap` truth, over 35 dumps and 59,279 relocated slots:

| where a relocated slot's value lands | count | share of in-image |
|---|---|---|
| a labelled function start | 4,269 | 7.2% |
| strictly inside a labelled body | 1,411 | 2.4% |
| an address the labelling never covers | 53,264 | 90.4% |

Relocations cover every absolute pointer, most of which name data, so as a seed source this is not
close. Narrowing to slots whose value lands in a declared executable section leaves 15,383, of which
27.6% are starts — better, and still not a candidate source.

The measurement that closes it is what the remainder would *add*. Of the relocated executable
targets, 2,668 are already recovered; what is left is:

| not yet recovered, and the target is | count |
|---|---|
| a labelled function start | **116** |
| strictly inside a labelled body | **1,285** |
| unlabelled | 5,220 |

**116 real starts against 1,285 addresses landing strictly inside a labelled body** — an eleven-to-one
trade against, and the losing side is the unambiguous kind of error rather than the arguable one.
Seeding relocated code pointers is not a gain on this corpus.

### What this leaves

Both avenues are closed on evidence rather than on judgement, and neither is worth re-attempting
without a different corpus. The surviving directories that no pass reads are the import table and the
IAT, both of which name imported APIs rather than the sample's own functions, and the export table,
present in 13 of 48 and already consumed by the symbol provider where it is.

### The check the format guarantees and the decoder was not making

Following the landing-pad rule onto the NativeAOT cell — a 2 MB ELF, the only managed sample with an
`.eh_frame` — turned up a decode producing 4,826 addresses out of an image whose landing pads should
be zero. Reading the LSDA headers it was handed says why:

| LPStart enc | ttype enc | call-site enc | count |
|---|---|---|---|
| `0x00` | `0x81` | `0x00` | 326 |
| `0x00` | `0x81` | `0x80` | 274 |
| `0x01` | `0xae` | omit | 118 |
| `0x00` | `0xd6` | `0x65` | 62 |
| `0x00` | `0x16` | `0xcf` | 60 |

Those are not LSDA headers. The FDE's LSDA pointer is leading into arbitrary bytes, most of which
the reader rejects — 4,407 of 5,344 — while 52 of them decode as a call-site table anyway and yield
93 addresses each. The rule was inert on this image only because none of the 4,826 happened to
coincide with a candidate, which is luck rather than design.

The format already guarantees the check that separates the two cases: **a landing pad is interior to
the function its own FDE names**. Measured before implementing it:

| corpus | decoded pads | inside their own FDE | outside |
|---|---|---|---|
| Built C/C++ | 25,748 | 25,748 | **0** |
| AArch64 ELF | 12,585 | 12,585 | **0** |
| Rust ELF | 2,882 | 2,882 | **0** |
| `libstdc++.so.6`, `python3`, `libc.so.6` | 2,666 | 2,666 | **0** |
| NativeAOT | 4,828 | **0** | 4,828 |

Perfect separation: 43,881 real pads, not one outside; 4,828 spurious, not one inside. Filtering on
it keeps every measured pad count identical and takes the NativeAOT image to zero.

This is the same lesson as the ttype-offset guard earlier in this entry, arriving from the other
direction. There the reader failed to reject bytes it could not read; here it read bytes it should
never have trusted. A decoder that only checks whether the bytes *parse* will accept anything that
happens to; what stops it is a property the format promises about what it decodes to.

## 2026-08-25 — the FDE-interior gap rule, and the two conditions found by measuring what it cost

Section 20 of the report left this open: the interior test the seeding scan uses was refused for
the gap scan because it "costs every CET .plt stub". Attacking the NativeAOT precision item put it
back on the table, because attributing that image's false positives by the pass that books each
says where they come from:

| bench_nativeaot, 1,376 genuine false positives, by first booking pass | |
|---|---|
| `addGapCandidate` | 763 |
| `addReferenceCandidate` | 510 |
| never booked by a tracked pass | 76 |
| `addPrologueCandidate` | 27 |

### The measurement that was wrong, and why

The first pass at it counted, post hoc, which gap-booked addresses are FDE-interior: **1,106 false
positives against 4 real losses**, none of them in a PLT. That is not what the rule does. Built and
run end to end the same rule costs **3,457 true positives** on the same corpus — three orders of
magnitude worse — because refusing a candidate changes what the scan reaches next, so the set the
rule removes is not the set a subtraction predicts. The recorded refusal in section 20 was right and
the fresh number was measuring a different question.

That is the second time in this branch that a set difference and an end-to-end run disagreed in the
same direction; the first was the landing-pad resume point, where stepping one instruction on cost 5
true positives while resuming at the FDE end gained 15.

### Condition one: a PLT is exempt

Every loss was a PLT stub, as section 20 said. The whole table sits under a single FDE, so the range
test reads every stub after the first as interior to the first. The section table declares where the
table is, so the exemption is image-declared rather than heuristic. It takes the cost from **3,457
true positives to 35**, and removes 1,869 false positives on that corpus regardless.

### Condition two: the range's own start must be a recovered function

The remaining 35 were perfectly systematic — every one on an `O2-static` cell, exactly two per cell:

| lost address | opens with | its FDE | offset into it | CIE augmentation |
|---|---|---|---|---|
| `0x47ad70` | `mov rax, 0xf; syscall` | `0x47ad6f`+10 | 1 | `zRS` — a signal frame |
| `0x477740` | `endbr64; mov rax, [rax+8]` | `0x477739`+25 | 7 | `zR` |

Neither FDE start is a symbol or a truth start: both ranges begin in the alignment padding ahead of
their function, and the real 16-byte-aligned entry sits a few bytes in. A range like that never had
a claim to be one function starting where it says, so it is not evidence about anything inside it.
Requiring the range's own start to be a function the analysis already recovered discharges both
shapes without naming either.

### Result, six corpora

| corpus | n | PPV | TPR | dTP | dFP |
|---|---|---|---|---|---|
| Built C/C++ (gcc, clang, mingw) | 260 | 94.109 -> **94.725** | 95.595 -> **95.596** | +4 | -1,551 |
| Built C/C++ AArch64 (gcc cross) | 72 | 79.172 -> **80.554** | 95.963 -> **95.964** | +3 | -1,692 |
| Built Rust (gnu targets) | 24 | 82.435 -> **83.608** | 97.578 -> **97.617** | +6 | -197 |
| Built .NET (CIL and NativeAOT) | 4 | 93.589 -> **95.332** | 99.461 -> **99.469** | +2 | -648 |
| Built Go, ARM64 Mach-O | 56 | bit-identical | | 0 | 0 |

**4,088 false positives removed, 15 real functions gained, no corpus loses recall.**
`summarize.py --compare` reports `compared=6` and `[ok] no TPR regression on any compared config`.
Timing sits inside an off-vs-off control band on the two heaviest cells.

### Why it ships off anyway

It moves two bundled fixtures, and both moves are improvements: `elf_cet_landing_pads_x64_xored`
drops four `endbr64` addresses that are jump-table case labels strictly inside the function the
symbol table names `dispatch`, and `aarch64_static_xored` drops two mid-function instructions. None
of the six carries a symbol. That is exactly the switch-under-`-fcf-protection` class section 13
ranks as the largest single precision mechanism on this corpus.

Moving a frozen fixture is a deliberate baseline update rather than a config edit, which is the
stated reason the two options beside it ship off as well. The measurement supports enabling it; the
decision is a maintainer's, and everything needed to make it is recorded here.
