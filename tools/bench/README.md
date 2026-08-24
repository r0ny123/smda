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

The four built families are produced by:

```
tools/bench/build_corpus.py --family native,go,rust,dotnet --out "$SMDA_BENCH_GROUNDTRUTH/built"
```

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

## The harness asserts its own success

A sample whose engine errored, timed out, or returned nothing is counted as a failure, listed, and
— past `--max-failures` — aborts the report. Two identical sets of *errors* otherwise read as "no
difference". `summarize.py --compare` refuses a comparison whose two sides have different `n`, and
exits non-zero if TPR fell on any config.
