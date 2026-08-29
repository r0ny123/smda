# Function-detection accuracy benchmark

Measures how well a disassembler recovers **function start addresses**, against corpora whose
ground truth comes from a compiler, a linker, or a published labelling — never from another
disassembler.

```
tools/bench/run.py --corpus bao-x86 --engine smda,ghidra --filter paper --out results/
tools/bench/summarize.py results/ --compare baseline/
```

Nothing here is vendored. The corpora are either fetched, built from source by
`tools/bench/build_corpus.py`, or supplied by the operator; the repository carries the recipes.

## Metric

A detected start counts only on an **exact address match**. Per binary:

```
TPR = |detected ∩ truth| / |truth|
PPV = |detected ∩ truth| / |detected|
F1  = 2·TPR·PPV / (TPR + PPV)
```

An engine that returns nothing for a binary scores 0, not "undefined" — otherwise a crash would
be averaged away rather than counted.

**A false positive is not one thing, and the `split` column says so.** Where a corpus labels
*instructions* rather than only starts — malpedia's `.fnmap` does — a wrong detection is either
inside a function the oracle labelled, which is an error on any reading, or outside every labelled
address, which may be code the oracle never covered. The column counts the first kind. It is
reported beside PPV and changes none of the rates: whether unlabelled code should be charged to the
engine depends on how complete each corpus' labelling is, so the harness reports the split rather
than deciding it. A corpus that cannot answer prints `-`, never `0` — zero would read as "no
function was broken apart".

On malpedia this matters more than it sounds: of 2,582 false positives, 283 are splits and 2,299 sit
where nothing is labelled, and one sample supplies 1,247 of those from a section its truth does not
cover.

Corpus figures aggregate the **per-binary rates**. All three aggregations are written to every
result file and the printed table names the one it is showing:

| `--mean` | aggregation | use it for |
|---|---|---|
| `macro` (default) | arithmetic mean of per-binary rates | comparing against this project's own accuracy tables |
| `geometric` | geometric mean | comparing against the origin paper, whose tables penalise outliers this way |
| `micro` | pooled counts | "how many mistakes in total", not "how does a typical binary score" |

Pooled and per-binary figures diverge whenever binary sizes do, so a number is only comparable
with another computed the same way.

## Ground-truth conventions

- **Thunks are functions.** Import stubs are code, are referenced by other code, and every engine
  in this comparison reports them. The ByteWeight corpus ships them in a separate list; the loader
  folds them into the truth set. ELF PLT entries are treated the same way.
- **External functions are not.** An import that exists only as an offset has no body. Ghidra and
  IDA list them behind an `external` flag; the harness discards those entries.
- **A headerless sample's bitness comes from its file name** (`x64-` or `_64_`, otherwise 32-bit).
  A dump carries no container to read the instruction set from, and this is the convention the
  corpora were labelled under.
- **Built corpora measure the stripped binary against the unstripped link's symbols.** Stripping
  moves no code, so the two describe the same addresses, and what is measured has no symbol table
  to read.
- **PLT0 is not a function.** The first entry of an ELF's `.plt` is the lazy-binding trampoline:
  it is reached by falling out of a stub, never called, and no engine in this comparison reports
  it. Every other `.plt`, `.plt.sec` and `.plt.got` entry is truth. This diverges from the origin
  evaluation's ELF convention, which took every aligned `.plt` entry including the first.

## Filters — always stated, never assumed

`--filter all` keeps every binary. `--filter paper` drops the `Os`/`Od`/`Ox` builds, which is the
population the published comparison tables use. On the 32-bit ByteWeight set that is 68 binaries
versus 34, and the two differ by more than two points of precision. Every printed row carries its
filter and its `n` for exactly this reason.

## Corpora

Set `SMDA_BENCH_GROUNDTRUTH` to the ground-truth root (default `~/groundtruth_data`).

| key | contents | truth |
|---|---|---|
| `bao-x86`, `bao-x86-64` | ByteWeight PE, MSVC, four optimization levels | compiler-derived extents plus a thunk list |
| `bao-x86-dumped`, `bao-x86-64-dumped` | the same programs with PE headers stripped | as above |
| `malpedia` | one memory dump per malware family | IDA databases plus manual labelling |
| `native` | C and C++ built by gcc, clang and MinGW | symbol table of the unstripped link |
| `go` | Go across GOOS/GOARCH and link modes | `go tool nm` over the unstripped build |
| `rust` | Rust across targets, profiles and LTO | symbol table of the unstripped link |
| `dotnet` | CIL, ReadyToRun, single-file and NativeAOT | assembly metadata; symbols for the native image |
| `native-arm64` | the same C/C++ programs and variants through the AArch64 cross compiler, plus a `-mbranch-protection=standard` cell | symbol table of the unstripped link |
| `macho-arm64` | ARM64 Mach-O, from the repository's own fixture corpus | `LC_FUNCTION_STARTS`, written by the linker |

The built families are produced by:

```
tools/bench/build_corpus.py --family native,native-arm64,go,rust,dotnet,macho-arm64 --out "$SMDA_BENCH_GROUNDTRUTH/built"
```

`native-arm64` needs `gcc-aarch64-linux-gnu` and `g++-aarch64-linux-gnu`. It is kept as its own
corpus rather than as extra cells of `native` so the x86 matrix stays comparable to the figures
already published for it instead of becoming a mixed-architecture population. Its `O2-bti` cell is
the only corpus here that carries AArch64 BTI landing pads in any density — 3,830 across its nine
binaries against 21 in the same programs built without the flag, which is the control that the cell
measures what it claims to.

`macho-arm64` needs no toolchain and no download: it decodes the ARM64 Mach-O fixtures the
repository already carries and reads each one's `LC_FUNCTION_STARTS`. It is the only AArch64
accuracy corpus here whose ground truth comes from a linker rather than from one compiler's
metadata, and the decoded binaries are written under the ground-truth root, never back into the
repository. A fixture that carries the load command with nothing in it is skipped and named in the
manifest — an empty truth set would score every detection as a false positive and read as a
catastrophic result rather than as missing truth.

**Do not measure this corpus with `SmdaConfig.USE_MACHO_FUNCTION_STARTS` enabled.** That option
makes SMDA read `LC_FUNCTION_STARTS` as a candidate source — the same table this corpus uses as
ground truth — so the engine would be scored against the answer key it was handed. It is off by
default and every figure recorded here is measured with the default.

Each family writes a `manifest.json` recording every cell it attempted, including the failures and
why — a matrix that quietly shrank must not read like one that passed.

## Engines

- `smda` — imported from the environment. Every result file records the module path it ran from,
  because putting a second checkout on `PYTHONPATH` is how another tree gets measured and nothing
  else in the output proves which one did.
- `ghidra` — driven through `support/analyzeHeadless` with `ghidra_scripts/DumpFunctionStarts.java`.
  Set `GHIDRA_INSTALL_DIR` or pass `--ghidra-dir`. A container-format binary goes through Ghidra's
  own loader; a headerless dump is imported as raw bytes at its stated base address, which is the
  same input SMDA gets. The exact Ghidra version is recorded in every result file.

## Replicating the origin evaluation

`tools/bench/paper_table.py results/` prints the origin paper's comparison table from result files
this harness wrote, applying the per-row aggregation that evaluation used — geometric mean per
optimization level for rows whose binaries carry an `O0`-`O3` label, arithmetic mean over all of
them for rows that do not. Columns for engines that cannot be re-run here are labelled `(paper)`
against `(measured)` in the header, and a corpus an engine was not run on prints `not measured`
rather than a blank. `docs/paper-replication.md` records the metric definitions and corpus
composition it is replicating.

## Withholding the bitness

`--bitness corpus` (default) hands the engine the bitness the corpus declares, which is what the
published comparisons did. `--bitness auto` withholds it, which is what a caller analysing an
unknown dump actually gets. The two answer different questions and results are written to
separate files so they cannot be mistaken for one another.

## Measuring an off-by-default option

Several accuracy options ship off because measurement showed a trade rather than a win. `--set`
turns one on for a run without editing the library, so the number can be reproduced from this
repository alone:

```
tools/bench/run.py --corpus native,native-arm64,rust --engine smda --out results/off/
tools/bench/run.py --corpus native,native-arm64,rust --engine smda --set USE_LSDA_LANDING_PADS=1 --out results/on/
tools/bench/summarize.py results/on/ --compare results/off/
```

`--set NAME=VALUE` is repeatable, names any `SmdaConfig` attribute, and applies to the `smda`
engine only. Booleans accept `1/true/yes/on` and their negations; integers accept the base they
are written in, so `0x100` and `256` are the same value. Every override lands in the result JSON
under the engine's `config_overrides`, and a run at stock settings records an empty one — a result
that does not state its settings cannot be compared with another.

## The harness asserts its own success

A sample whose engine errored, timed out, or returned nothing is counted as a failure, listed, and
— past `--max-failures` — aborts the report. Two identical sets of *errors* otherwise read as "no
difference". `summarize.py --compare` refuses a comparison whose two sides have different `n`, and
exits non-zero if TPR fell on any config. `paper_table.py` marks a cell holding an incomplete
sample with `!k` and names the samples beneath the table: an incomplete run scores 0, and the
geometric mean an optimization-level row uses carries that zero into the cell, so the figure has to
carry the reason with it.

Before printing any metric, `run.py` reports a corpus-integrity check: for every sample whose
binary has a section table, whether its ground truth lands inside an executable section, together
with how many samples the check could run on at all. A headerless dump names no sections, so the
check does not apply there and silence must not be read as a pass. Truth landing outside an
executable section is not by itself a defect on a memory dump — on the malware corpus 94% of those
addresses are recovered anyway, because a packed sample's section table does not describe where its
code is. `--exclude-known-defects` drops samples recorded in `corpora.KNOWN_TRUTH_DEFECTS` as
describing a different build or covering only part of their image, and is off by default because
every published figure for these corpora includes them.
