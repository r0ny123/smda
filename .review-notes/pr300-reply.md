Rebased onto `6240b74` and re-measured. You were right about the table — it was describing a tree that stopped existing around #304 — and right that the gap-scan ordering was the hunk worth not guessing at. There turned out to be a second one you had no way to see from the conflict text, where "keep both" would have quietly undone #311; that one is below too.

## The rebase

Dropped the pre-squash copies of #302, #306, #307, #308, #309 and #310, plus one of #311's (`test(tests): move the fixture's rationale out of comments into its docstring` — master already carries that wording). What is left is the three commits that are actually this PR's — `456b855`, the budget poll on the declared-table walk, and the `declaredArchitecture` return-type fix — plus a fourth, `test(tests): repair what the rebase onto current master broke`, which is kept separate rather than folded in so what the rebase changed stays readable next to what the PR changed.

Your table of the five files was accurate. Taking them in your order:

**`common/FunctionCandidateManager.py` — kept both.** `_pdata_ranges` / `_pdata_range_starts` / `_pdata_range_reach` from #312, then `_eh_frame_fde_ranges` / `_eh_frame_fde_starts` / `_declared_landing_pads` / `_plt_ranges`, in both the constructor and the `init()` reset. No interaction, as you said. `declaredExceptionRangeContaining` stays exactly as #312 left it and `ehFrameFdeRanges` goes in below it.

**`intel/FunctionCandidateManager.py` — the ordering.** Chosen order in the gap-scan loop: #309's `.pdata` interior refusal, then `USE_LSDA_LANDING_PADS`, then `USE_ELF_FDE_INTERIOR_GAPS`.

Two things decide it, and neither is a preference.

The `.pdata` rule and the two `.eh_frame` rules can never speak about the same address, because they can never be armed on the same image. `_pdata_ranges` has exactly two writers in the tree and both are PE-only: on intel it is `_admitExceptionRecord` under `declared=True`, reached only from a table the exception directory or a `.pdata` section named, and the memory-dump path `_carveExceptionRecords` passes `declared=False` and records no extents at all; on AArch64 it is the directory walk behind `isinstance(lief_binary, lief.PE.Binary)`, and `_carveArm64ExceptionRecords` likewise records none. `ehFrameFdeRanges()` and `declaredLandingPads()` both return early unless lief reports `ELF.Binary`. So the first test is a PE test and the other two are ELF tests, and the emptiness check on `_pdata_ranges` is the cheapest of the three, which is why it goes first.

LSDA before FDE-interior does matter, and in one direction only. `declaredLandingPadSkipTarget()` is implemented as `declaredFdeRangeContaining(addr)[1]` — literally the same resume point the interior rule would use — so the two can never disagree about *where* to resume. They differ in when they fire: the interior rule additionally requires `containing[0] in self.disassembly.functions`, i.e. that the range's own start has already been recovered. The landing-pad rule needs no such thing, because an LSDA naming an address as a pad is evidence on its own. Putting it first is therefore a strict superset with an identical skip target; putting it second would silently drop the pads whose declaring FDE has not been recovered yet.

**`intel/FunctionCandidateManager.py` — the `.pdata` seeding block.** Re-expressed against #312's shape rather than merged textually. `locateExceptionHandlerCandidates` now resolves the table address first (`getExceptionDirectory()`, falling back to a `.pdata` section only when the directory names none, and only when `is_pe`), then hands `(start, end)` to `_readExceptionTable`, which walks it and calls #309/#312's `_admitExceptionRecord` unchanged — `declared=` flag, `_isTrustworthyExceptionExtent`, chained-record handling, all of it. Your reading of it was right: I locate the table, #309 decides what each record is worth, and the two are orthogonal once the seam is in the right place.

One incidental thing I did not touch: master carries a dangling `#: (start, end, is_chained) for every RUNTIME_FUNCTION record the image declares,` in `intel/FunctionCandidateManager.__init__` with nothing under it — the attribute it documents lives in `common/` since #312. I put the new attribute *above* it rather than below so the merge does not make it look like it documents mine. Left it otherwise alone since it is yours to remove.

**`aarch64/FunctionCandidateManager.py` — kept both, #310 first, and one hunk that had to be dropped.**

The prologue predicate now runs `is_bti_landing_pad(word) and _isLikelyInteriorBtiCandidate(addr, word)` before the LSDA test, per your note: the `bti j` refusal is an integer compare against a word the loop already has, and the LSDA test decodes `.eh_frame`. Both `continue`, so it is purely cost. Inside `_isLikelyInteriorBtiCandidate` the `USE_AARCH64_BTI_TARGET_TYPE` block stays first and the three-condition `code_map` test follows it, same reason.

The gap scan gets the same three rules in the same order as the intel one, and then #310's `_endOfRefusedLandingPadRun` resume — not this branch's `+= INSTRUCTION_SIZE`, which is the bug #310 fixed.

The hunk that is not "keep both": this branch re-adds

```python
if is_conditional_branch(word):  # a function never opens with a cond branch
    self.gap_pointer += INSTRUCTION_SIZE
    continue
```

to the AArch64 gap scan, and `db5eff0` (#311) deliberately removed it — the removal is the diff hunk, and both fixtures' test comments in master name the addresses it bought. Dropped it.

Worth being precise about the evidence, because the fixtures do not show it. Re-adding the skip changes nothing at all on either bundled fixture — `USE_ELF_FDE_INTERIOR_GAPS` refuses `0x40DF30` first, and the Mach-O one is untouched either way — so a merge that kept it would have gone green. On the corpora it is not close: measured on the branch with the skip put back,

| corpus | ΔTPR | ΔPPV | ΔTP | ΔFP |
|---|---|---|---|---|
| Built C/C++ AArch64 ELF, n=72 | **−1.531** | −2.114 | **−349** | +539 |
| ARM64 Mach-O, n=11 | −0.159 | −0.165 | −4 | +4 |

349 real functions and worse precision, which is #311 measured from the other side. This is the hunk I would most have liked you to see me get wrong, so: the resolution is "drop it", and the number above is why.

**`SmdaConfig.py` and the two test files.** Config: kept all three flags, as you said. The two pinned baselines are re-pinned from an actual run on the merged tree, with the reasons rewritten — see below.

## The numbers, against `6240b74`

Both trees run back to back on the same machine, arithmetic macro mean, `--filter all`, stock config. Every result file records the `smda` module path it imported from.

| corpus | n | PPV before → after | TPR before → after | ΔFP | ΔTP |
|---|---|---|---|---|---|
| Built C/C++ AArch64 ELF (gcc cross) | 72 | 91.497 → **94.947** | 97.705 → **98.069** | −3,645 | +151 |
| Built Rust (gnu targets) | 24 | 79.659 → **87.480** | 98.237 → **98.361** | −1,641 | +19 |
| Built Go (pclntab truth) | 47 | 95.361 → **95.626** | 99.367 → 99.367 | −408 | 0 |
| ARM64 Mach-O (LC_FUNCTION_STARTS) | 11 | 94.281 → **94.499** | 96.402 → **97.207** | −27 | +38 |
| Built C/C++, MinGW PE cells | 120 | bit-identical | bit-identical | 0 | 0 |
| ByteWeight msvc10-64 | 68 | bit-identical | bit-identical | 0 | 0 |
| ByteWeight msvc10-64, headers stripped | 56 | bit-identical | bit-identical | 0 | 0 |
| Malpedia dumps (`.fnmap` truth) | 57 | 92.645 → 92.648 | 98.552 → 98.552 | −1 | 0 |

**Nothing loses recall.** That gate still holds, and it is the one thing I would not have wanted to find out the hard way after #304/#309/#310/#311 closed as much headroom as they did.

Malpedia is level to within one false positive, which is what it should be — those are packed Windows dumps and almost every rule here reads ELF unwind data. It is in the table as a control rather than as a result.

Your read on where the overlap would land was right, and the AArch64 row shows both halves of it: master's own PPV on that corpus has gone from the 76.676 this PR recorded for it to **91.497** today, so most of what the old table claimed is now yours, not this branch's. What is left on top of it is still 3.450 points and 3,645 false positives, with recall up rather than traded.

### Two rows changed character, and I would rather say so than quietly re-title them

**Go is no longer bit-identical.** It is now −408 false positives at identical TP and FN. That is not a rule firing where it should not — Go carries no `.gcc_except_table` and the ELF FDE rule needs a recovered range start it does not have here. It is section 5's tailcall gate, whose effect on Go was always in the PR body (−430 FP) and simply never made it into the headline table's Go row. Attribution below.

**The C/C++ row is not the 260-cell population any more, and I could not make it be.** The archived corpus behind these figures carries the 120 MinGW-PE cells of that matrix and not the gcc/clang ELF cells, and rebuilding those needs upstream fetches I do not have from here. So the honest statement is the one in the table: on the MinGW PE half, this branch is bit-identical to master, byte for byte. That is consistent rather than disappointing — `USE_LSDA_LANDING_PADS`, `USE_ELF_FDE_INTERIOR_GAPS` and the `endbr64` interior rule all decode nothing unless lief reports an ELF, so a PE-only C/C++ population is exactly where they should show nothing. It does mean the "260 cells, 91.878 → 94.725" line has no successor I can produce, and I have taken it out of the description rather than restate it with a number I did not measure.

The corpus property the rule rests on re-verifies unchanged, since it is a fact about the images rather than about the engine:

| corpus | samples with pads | declared pads | truth starts the FDE-end skip would step over | pads inside a PLT |
|---|---|---|---|---|
| AArch64 ELF | 23 | 12,585 | **0** | **0** |
| Rust ELF | 8 | 2,882 | **0** | **0** |

### The PE side of change 2, checked rather than assumed

Reading the exception table from the data directory instead of from a section named `.pdata` is the one engine change here that touches ordinary Windows binaries, so it is worth a control rather than an argument. On ByteWeight msvc10-64 (n=68) and its header-stripped twin (n=56) — 124 PE x64 images, 214,362 truth functions between them — this branch is **bit-identical to master on both**: same TP, same FP, same FN, to the digit.

That is what it should be. On an MSVC PE the directory and the `.pdata` section name the same table, and a header-stripped dump has no directory to read, so it still takes the carve path. The change only shows up where the two disagree, which is the ReadyToRun case below.

### The ReadyToRun figure, re-measured

`66.93% → 100.00%` was the old one. On `6240b74` the gap scan already reaches most of that image on its own, so the honest figure is smaller and still the same shape: on `tests/dotnet_readytorun_pe_xored`, **419 → 626 functions**, and 626 of the 626 starts the exception directory declares — recall 100.00%, with nothing recovered that the directory does not name. `testEveryDeclaredNativeFunctionIsRecovered` pins it.


### Sections 8 and 9, re-attributed

The old per-corpus splits between the landing-pad rule and the FDE-interior rule were on the 260-cell C/C++ matrix and on the AArch64 and Rust corpora. The first is gone for the reason above; the other two re-measure like this, everything else in the branch on, adding one rule at a time:

| corpus | variant | PPV | TPR | TP | FP |
|---|---|---|---|---|---|
| AArch64 ELF, n=72 | both rules off | 91.554 | 98.045 | 59,495 | 6,062 |
| AArch64 ELF, n=72 | + `USE_LSDA_LANDING_PADS` | 93.176 | 98.067 | 59,513 | 4,330 |
| AArch64 ELF, n=72 | + `USE_ELF_FDE_INTERIOR_GAPS` (branch default) | 94.947 | 98.069 | 59,516 | 2,484 |
| Rust, n=24 | both rules off | 82.805 | 98.237 | 33,298 | 6,573 |
| Rust, n=24 | + `USE_LSDA_LANDING_PADS` | 86.303 | 98.321 | 33,311 | 5,919 |
| Rust, n=24 | + `USE_ELF_FDE_INTERIOR_GAPS` (branch default) | 87.480 | 98.361 | 33,317 | 5,722 |

On AArch64 ELF the landing-pad rule alone is −1,732 false positives and +18 true, and the interior rule adds −1,846 and +3 on top of it. On Rust the landing-pad rule alone is −654 false positives and +13 true, and the interior rule adds −197 and +6 on top of it.

## The one decision I had to re-open: section 5's tailcall gate

This is the change that gates the AArch64 `bl` fall-through tailcall seed behind `RESOLVE_TAILCALLS`. It was measured before #307 changed what `addTailcallCandidate` does, so I re-measured it rather than carry the old numbers over. Everything else in this branch on, gate off → gate on, against `6240b74`:

| corpus | n | ΔPPV | ΔTPR | ΔFP | ΔTP |
|---|---|---|---|---|---|
| Built Go (pclntab truth) | 47 | +0.265 | 0.000 | **−408** | 0 |
| ARM64 Mach-O | 11 | +0.201 | +0.092 | **−27** | **+11** |
| Built C/C++ AArch64 ELF | 72 | +0.359 | **−0.070** | **−580** | **−53** |

Go with the gate off is byte-identical to master, which is the control that this is the only thing moving that row.

The third line is new, and it is the reason I am flagging this rather than just restating the section. The AArch64 ELF corpus was not measured for this change originally — the write-up only covers Mach-O and Go — and on it the gate is a trade: 580 false positives against 53 real functions. By the strict per-change rule the branch set itself ("a recall drop on any corpus is the reject criterion") that is a reject.

I have kept it, for three reasons, and I would rather you overrule me than have me quietly pick:

1. **F1 is up on all three**, and precision is up on all three. The 53 are the only thing pointing the other way.
2. **The branch as a whole still does not lose recall on any corpus** — the AArch64 ELF row goes 97.705 → 98.069 with the gate in it. The gate's 53 are more than repaid by the FDE and landing-pad rules on the same corpus.
3. **The gate is what makes both behaviours reachable at all.** Today the AArch64 backend seeds these regardless of `RESOLVE_TAILCALLS` while the shared engine honours it on both of its own tailcall paths, so there is no setting that turns the AArch64 seeding off. With the gate, `RESOLVE_TAILCALLS=True` gets those 53 back and then some — measured on the branch, AArch64 ELF goes to TPR **98.202** and 59,611 TP (against 98.069 / 59,516 at the default and 98.139 / 59,569 with the seed simply ungated), and ARM64 Mach-O to **97.713** / 2,579. It costs precision to do it, which is presumably why the flag defaults off, but the recall is on a switch rather than gone.

For completeness, since `RESOLVE_TAILCALLS` also turns on the shared engine's own tailcall promotion, that row is not a pure "ungate" — the ungated-seed-only column is the `nogate` line in the table above.

Dropping it is a one-line revert in `AArch64Backend._analyzeCallInstruction` if you would rather have the 53 and the 580 both. Say which and I will push it either way.

## Three things the rebase broke that were not conflicts

These all passed on the old base and fail on `6240b74`, so I am listing them rather than letting them look like noise in the diff.

**`testInteriorPrologueSuppression` stopped constructing.** Its `_BufferBinaryInfo` stub implements the parts of `BinaryInfo` the seeding scan reads, and #309 gave `locateExceptionHandlerCandidates` a `_getLiefType()` call the stub does not have. It now answers `"OTHER"`, which is what the real `BinaryInfo` answers for a buffer lief cannot parse, and is the case the PE-only branches are guarded for.

**`LsdaLandingPadArm64Test.testTheRuleIsOnByDefaultAndTurningItOffShowsWhatItDoes` became vacuous** — which is your observation, arriving as a red test. That case switches the rule off and asserts a declared pad comes back, so that the assertion above it means something. On `6240b74` it does not come back: all five pads in that fixture are `bti j`, and `USE_AARCH64_BTI_TARGET_TYPE` refuses a `bti j` on the word alone. The control now switches #310's flag off as well, and documents why. So the test asserts what it always meant to — with both rules off the pads are booked, with either one on they are not — instead of asserting a set that is now empty for a reason that has nothing to do with the rule under test.

**`aarch64_static` and the Mach-O fixture are re-pinned from an actual run**, not merged textually.

`aarch64_static` goes 278 → 276 functions (19,882 → 19,735 instructions, 3,499 → 3,476 blocks). The address in the old write-up has moved with #311: the branch refuses both `0x40DF34`, where Binary Ninja puts that routine, and `0x40DF30`, where the gap scan puts it now that #311 stopped skipping a word opening on a conditional branch. Both sit inside the FDE at `0x40DDC0`, which really is one unwind range — `0x40DF34` repeats the range's opening minus its `prfm` prefetch, so it is an alternate entry sharing one frame. Same disagreement between the unwinder and Binary Ninja as before, one instruction over. Both are asserted absent rather than dropped from the expected list.

The Mach-O fixture's primary pass goes 256 → **271**, which is 143 of `LC_FUNCTION_STARTS`' 147 entries against 128, and the total with the table pass on is unchanged at 274. That shape is the point: what the table adds shrinks by exactly what the primary pass learned to reach on its own.

## One thing already in here that overlaps #322

Item 4 of #322 — the corpus benchmark's timing verdict being dominated by between-runner spread — is the same finding as the workflow change in this PR, arrived at from the other end. This branch collapses the base/PR matrix legs back into one job on one runner because of exactly what you describe: three consecutive runs whose PR side produced byte-identical output reported +1.26%, −13.18% and −15.53%, because the PR side drew a different runner each time (sum-of-best 252.83s / 282.21s / 289.04s) while the cached base side stayed frozen at 252.53s across all three. Caching one side is what makes it a measurement from another machine and another hour.

So "pin both sides to one runner" is the option this implements. Not claiming it closes your item — the noise band still derives from within-runner CV, which is the other half of what you wrote — but the runner half is here and measured, and it may save you doing it twice.

## Gates

- full suite: `2059 passed, 2 skipped, 2593 subtests` on the rebased tree
- `ruff check .` clean, `ruff format --check .` clean
- `make typecheck`: exit 0, 0 error-level diagnostics — same as master, which is also 0
- the advisory sibling-pair check warns once, on `[backends] 1/2`: `aarch64/AArch64Backend.py` changed and `intel/X86Backend.py` did not. Intentional — the no-return boundary rule reads AArch64 frame-record encodings and has no x86 counterpart in this branch

---

The branch is `accuracy/engine-enhancements` again, force-pushed onto `6240b74`. Nothing in the diff's substance changed apart from the two AArch64 hunks above; the rest is the same code read against a different tree.
