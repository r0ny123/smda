# What is in here

Work for danielplohmann/smda #300 and #299, in response to Daniel's 2026-09-08 review comments.

| file | what |
|---|---|
| `pr300-reply.md` | the comment to post on #300 |
| `pr299-reply.md` | the comment to post on #299 |
| `pr300-description-patch.md` | the edits the #300 description needs, section by section |
| `collect.py` | rebuilds the before/after table from the saved benchmark result JSONs |

## Branches

Both rebases are local to this session's checkout of `r0ny123/smda`:

- `rebase/pr300` — 4 commits on `danielplohmann/smda@6240b74`: the PR's own three, plus one commit of test repairs the rebase needed
- `rebase/pr299` — those four, then this PR's own sixteen, then one docstring commit Daniel asked for

Both PR branches are pushed:

| branch | head | PR |
|---|---|---|
| `accuracy/engine-enhancements` | `68b2626` | #300 |
| `perf/analysis-hot-path-overhead` | `6cae1c5` | #299 |

`claude/smda-pr-review-7bfdeu` carries the same `6cae1c5` as a backup.

The comments could not be posted from the session — GitHub access here is scoped to `r0ny123/*`
and `danielplohmann/smda` cannot be attached — so `pr300-reply.md` and `pr299-reply.md` need
pasting by hand.

## Benchmark results

`/home/user/bench-results/` — one directory per configuration, each holding the harness's own
per-sample result JSONs:

| directory | tree / config |
|---|---|
| `master/` | `danielplohmann/smda@6240b74` |
| `pr300/` | `rebase/pr300`, stock config |
| `nogate/` | `rebase/pr300` with the AArch64 `bl` tailcall seed ungated |
| `tailcalls-on/` | `rebase/pr300` with `RESOLVE_TAILCALLS=1` |
| `elfrules-off/` | `rebase/pr300` with both new ELF rules off |
| `lsda-only/` | `rebase/pr300` with `USE_ELF_FDE_INTERIOR_GAPS=0` |
| `identity_*.json` | the ten report-identity hashes per tree |

Corpora were unpacked from `r0ny123/smda-eval-data` into `/home/user/groundtruth_data`.
