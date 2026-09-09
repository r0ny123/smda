Rebased, in the order you asked for: #300 first onto `6240b74`, then this on top of it.

## What is in it now

Twenty-one commits — #300's three plus the test-repair commit its rebase needed, then the sixteen of this branch's own, then one more: the docstring you asked for on `test_interior_holes_match_the_covered_byte_walk`. The pre-squash copies of #302, #306, #307, #308, #309 and #310 are gone, including the two on this branch that were #310's series (`resume past a refused landing pad's block` and `stop the refused-pad walk at a trap`); master carries both as `7d01480`.

Four of the sixteen needed real resolution rather than a textual merge:

- `perf(aarch64): prefilter candidate word scans by instruction top byte` — the chunked prefilter loop now wraps the *current* bodies of the `bl` reference scan and the prologue scan, so it keeps #307's `self._call_targets.add(target)` and #310's `_isLikelyInteriorBtiCandidate(addr, word)` signature rather than the pre-#307 shapes it was written against.
- `perf(common): drop redundant ref bookkeeping and speed hot lookups` — `SmdaInstruction.from_tuple` goes in, but `getDataRefs` keeps master's typed body from #320 (`-> Iterator[int]`, direct `self._data_refs`) rather than reintroducing the `getattr` that the annotation work removed.
- `perf(aarch64): skip non-matching words and capstone data-ref decodes` — both sides of the test-file conflict were additive, kept both.
- `fix(common): restore code_map as the gap-scan coverage source` applies unchanged on top.

## The report hashes, regenerated against the tree this lands on

You are right that the old claim had gone stale, and for the reason you named rather than for a rebase reason. Regenerated:

Ten bundled fixtures, `computeReportIdentityHash` over the full serialized report, `timestamp` and `execution_time` excluded. Three trees: current master `6240b74`, #300 rebased onto it, and this branch rebased onto that.

| fixture | backend | master `6240b74` | #300 rebased | this branch |
|---|---|---|---|---|
| `asprox` | intel | `d961211b` | `d961211b` | `d961211b` |
| `cutwail` | intel | `e201853a` | `e201853a` | `e201853a` |
| `bashlite` | intel | `be88d8f5` | `be88d8f5` | `be88d8f5` |
| `blockblast` | dalvik | `767ebb8e` | `767ebb8e` | `767ebb8e` |
| `komplex` | intel | `7fce68c9` | `7fce68c9` | `7fce68c9` |
| `njrat` | cil | `cc2a2ea3` | `cc2a2ea3` | `cc2a2ea3` |
| `pe_export` | intel | `6d4b219a` | `6d4b219a` | `6d4b219a` |
| `aarch64_static` | aarch64 | `1f415f37` | `3613e186` | `3613e186` |
| `aarch64_switch_macho_O0` | aarch64 | `418c8419` | `418c8419` | `418c8419` |
| `dotnet_readytorun` | intel | `713c981f` | `9c651848` | `9c651848` |

**This branch is byte-for-byte equal to the tree it lands on, on all ten.** That is the claim the PR makes and it is now made against the right baseline rather than against v4.5.0.

The two that move do so between master and #300, not here: `aarch64_static` 278 → 276 functions and `dotnet_readytorun` 419 → 626, both #300's business and both explained over there.

And with your point taken about what this proves: it proves these sixteen commits change nothing *on these ten images*. It is not evidence about `updateFunctionGaps`, because none of the ten is gap-dominated — which is the whole reason `3ff05a8` exists. The gap-scan behaviour is pinned by `test_gaps_follow_code_map_coverage_not_recovered_function_extents`, which fails on the pre-revert source, rather than by any hash.

## `fuzz_buffer`

Noted, and thanks for re-running it rather than leaving it as an open question on the branch. Nothing here holds a lock or loops on buffer content, so I had no better explanation than "infra" either — good to have it settled by a green run rather than by argument.

## On the third defect

Taking the generalisation as a standing rule rather than a one-off, since you asked for it on the record: **a report-identity comparison is evidence about the fixtures, not about the change.** Concretely: an identity hash is a gate only for paths a fixture actually reaches. Everywhere else it reports coverage and reads as behaviour, which is exactly how the 16% gap-scan recall loss got through — none of the ten bundled fixtures is gap-dominated, so no hash could have moved whatever the change did.

I have made the corrected `test_interior_holes_match_the_covered_byte_walk` docstring say why it populates both sources, per your note.

## Gates

Full suite on the rebased branch: `2092 passed, 2 skipped, 2593 subtests`. `ruff check` and `ruff format --check` clean, `make typecheck` exit 0 with no error-level diagnostics. (#300's own tree, underneath this one, is `2059 passed, 2 skipped, 2593 subtests`.)
