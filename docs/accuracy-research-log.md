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
