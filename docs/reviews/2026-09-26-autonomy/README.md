# Autonomous-development assessment — 2026-09-26

## Repository and preservation

The task started in `Documents/AutoQuantTrader`, a workspace container rather
than a Git root. Its `repo/` checkout is the historical `8685b56` branch. Existing
instructions and Git state identify `Documents/GitHub/AutoQuantTrader` at
`b1156ba96e6f1246a3a213ff041f17e3b15ff78b` on
`codex/personal-v1-w4-integration` as the current integration source.

The integration checkout had one preexisting architecture status edit. It was
left untouched and its updated paragraph was carried into the new isolated
`autonomous-development` worktree on `codex/autonomous-development`. The managed
worktree tool could not operate from the non-Git task directory; a normal Git
worktree was created from the explicit integration revision. No old checkout,
private runtime artifact, database or historical evidence was deleted.

[previous-agent-handoff.md](previous-agent-handoff.md) preserves the original
AGENTS bytes. Its historical relative links were written for the repository
root; use the current docs navigation for continuation. Frozen contracts and
existing evidence remain in place rather than being rewritten as current passes.

## Inspection coverage and findings

The tracked inventory contains 1,625 files: 496 tests, 412 documentation files,
376 package files, 142 app files, 70 scripts, 43 migration files, 23 native files,
18 build-support files, infrastructure/configuration, vendored crypto and lockfiles.
The audit inventoried the complete tracked tree, read current instructions,
roadmap/contracts and relevant historical evidence, traced composition roots and
financial/source/credential boundaries, and reviewed test selection, CI, package
configuration and useful Git history. Three independent audits covered product,
architecture and validation. This is not a claim that every line was executed
or every historical native path requalified. Credentials/private runtime files
were excluded from inspection.

Findings:

1. Waves 0–3 have recorded merged-revision acceptance. The current research
   product is more capable than the old fixture-only README describes.
2. Wave 4 includes substantial stateful simulation and reconciliation code but
   remains incomplete. The fixed worker only restores/checks existing HALTED
   state, and fresh genuine capture admission deliberately rejects.
3. AGENTS had become a 27 KB chronological log. Concise operating instructions,
   a small current STATUS and source-backed SPEC/PLAN/TESTING improve resumability
   without deleting previous decisions or wave requirements.
4. The current CI failure is real and newer than the last checked-in handoff.
   Read-only GitHub inspection identified exact run
   [36096804829](https://github.com/km8trix/AutoQuantTrader/actions/runs/36096804829).
5. Existing pure sharding tests were excluded from the standard runner, with a
   stale historical workflow assertion. The focused repair adds coverage and
   preserves that assertion against the actual legacy workflow.

## Latest integration failure, preserved

Run 36096804829 at `b1156ba` completed with failed required shard 7. Foundations,
installed wheels, migrations, browser and the other 15 shards passed. The failed
test is:

```
tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease
```

Required unprofiled restore failed after **60.310 seconds**. The nested cause is
`AccountLeaseOwnershipLost` at `_borrow_original_daily` ownership revalidation;
retained-index/integrity/schema wrappers propagate it. Lease release failed
separately with `OFFLINE_LEASE_RELEASE_FAILED`. The original 60-second lease is
unchanged. Shard 7 reports one failure, 279 passes and 4,243 deselections.

The separate failure-only diagnostic also failed (61.175-second instrumented
execution). Its artifact reports substantial repeated semantic serialization
and source validation work. Enclosing timings overlap and must not be added;
instrumented timing cannot certify startup acceptance or performance improvement.
Keep all original fences, provenance checks, error semantics and limits while
investigating a narrow pure-helper repair.

## Completed validation at the operating-docs checkpoint

- Standard architecture check passed using an isolated verified Python runtime.
- Original sharding workflow assertion reproduced as a failure, before repair.
- Runner + sharding tests: **32 passed**; formatting/lint of all three changed
  files passed; original sharding assertions retained.
- Documentation links/diff/source review and subsequent A2 validation are recorded
  in [STATUS](../../STATUS.md) and appended evidence below as they complete.

No live account operation, provider request, OAuth, credential read, runtime
activation, native installation, risk change or deployment occurred. GitHub CI
metadata/log/artifact reads were used only to diagnose the existing failed run.

### A0/A1 independent review

All 74 local Markdown links in the eight operating documents resolved and
`git diff --check` passed. Architecture/source review found no authority or
financial-policy weakening; its production-credential wording correction was
applied. README now names the actual legacy Compose profile and separates the
wave roadmap from the executable queue.

A safe collection-only run through the actual sanitized personal runner collected
4,537 tests from 218 targets, without collection errors (13.83 seconds). This is
the 4,523-case baseline plus 14 restored sharding cases, before A2 additions. No
test body ran during collection. Collection is inventory evidence, not a passing
full regression. A0 and A1 are complete; A2 remains open.

### A2 local candidate

A narrow exact-scalar tuple conversion removes recursive calls for immutable
leaves while preserving tuple allocation, subclass/dataclass fallback, traversal,
mutation, error/read order and canonical hashes. No cache, financial rule,
source/SQL/fence check or limit changed. Independent review found no correctness
issue. **233 focused compatibility tests** (15 new) pass, along with Ruff, full
mypy (417 files), architecture and API contract checks.

The original unprofiled signed retained-outcome test passed in **245.87 s**;
fixture setup took 196.124 s and restore completed in **46.681 s** under the
unchanged 60-second lease. Its original result/preservation/cleanup assertions
passed. [Bound source evidence](semantic-tuple-evidence.json),
[original log](retained-local.txt) and [finite benchmark](semantic-tuple-benchmark.json)
record scope. This local result does not close the previous Linux failure or
establish a before/after startup speed comparison. The microbenchmark also has
a slower scalar control; it is not a uniform speedup claim.

Automatic approval review rejected GitHub publication because explicit repository
egress authorization was required. No push occurred. Local work remains valid;
exact-revision Linux CI and Wave 4 closeout remain incomplete.

The owner subsequently explicitly approved pushing `codex/autonomous-development`
to `km8trix/AutoQuantTrader` and opening a draft PR against the Wave 4 integration
branch for Linux CI. This resolves publication permission only. Full repository
Ruff formatting (1,017 files) and lint also pass after the local candidate.

### A3.1 mechanical Tiingo selection

Added an optional in-memory matcher for the existing request, acquisition profile,
reviewed authorization and pinned calendar. It reuses the existing bounded codecs,
authorization date meanings and research-calendar convention. It returns no token
or permission and is not wired into genuine capture admission. Equal copies can
pass this content check; original identity/rights/account/clock provenance remains
unproved. A successful genuine-shaped match still reaches the unchanged capture
denial before any clock, HTTP or artifact effect.

**216 focused cases passed** (49 new), including date/window equality, reviewed
scope, nested mutation, copied-content limitations and no-effect denial. Ruff,
architecture and mypy (418 files) passed; independent review found no actionable
issue. [Evidence and source hashes](tiingo-selection-evidence.json) retain the
exact scope. Held locally while CI continues on `b6e4815`.

### A3.2a original clock conversion

The optional Chrony observation retains its original reading and measurement under
a weak original-owner registry. Legacy calls use the unchanged conversion body
without registering evidence. Verification performs no source read or local clock
sampling and deliberately makes no currentness or healthy-history claim.

**92 focused clock cases passed** (39 new), with independent review, architecture,
formatting/lint and scoped mypy passing. Review discovered copied-owner acceptance
from shared registries and an unpinned authority descriptor. Both were corrected;
the [copied-owner failure reproduction](chrony-copied-owner-reproduction.txt) and
[final source-bound evidence](chrony-observation-evidence.json) preserve that history.
Tests use only injected callbacks and synthetic parser input. Measured health
history, actual host qualification and capture admission remain unfinished.
