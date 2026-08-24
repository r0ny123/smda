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

