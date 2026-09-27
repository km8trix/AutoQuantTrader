# Autonomous-development assessment — 2026-09-26

**Current outcome:** A2 is reopened after the same-source follow-up CI failed.
The eager semantic-loop optimizations were subsequently withdrawn after a new
exception/lifetime regression was found; the correction passes local validation.
The preceding full 4,786-test pass remains preserved for its exact run. See [final acceptance](#a2a3-final-source-acceptance-and-next-handoff)
and [STATUS](../../STATUS.md) for A4's remaining blocker. The sections below
preserve the initial audit and successive checkpoints in chronological order.

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
4. At the initial audit, the CI failure was real and newer than the checked-in handoff.
   Read-only GitHub inspection identified exact run
   [36096804829](https://github.com/km8trix/AutoQuantTrader/actions/runs/36096804829).
5. Existing pure sharding tests were excluded from the standard runner, with a
   stale historical workflow assertion. The focused repair adds coverage and
   preserves that assertion against the actual legacy workflow.

## Initial integration failure, preserved

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

*Initial local checkpoint; this addition was subsequently published with the revised
candidate. See [STATUS](../../STATUS.md) for current CI and the
[implementation findings](capture-bridge-contract.md#implementation-findings-after-the-initial-proposal)
for the remaining source boundary.*

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

*Conversion-only checkpoint. Subsequent historical health ownership is recorded in
[A3.2b](#a32b-original-measured-health-history); the
[implementation findings](capture-bridge-contract.md#implementation-findings-after-the-initial-proposal)
retain the separate host-qualification and capture-admission gaps.*

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

### A3.3a Tiingo transport return boundary

Existing mock callbacks reproduced successful Tiingo returns after loader
replacement or cleanup-time binding/deadline loss. The first adverse run had
**9 failures and 2 passes**; its [original output](tiingo-transport-before.txt)
is preserved. The focused repair rechecks request/loader bindings after callbacks
and before GET, then permits success only after all cleanup and final binding
and effective-deadline checks. Earlier failure and cleanup-failure precedence,
single use, fixed endpoints and all existing resource limits remain intact.

The final six-file regression reports **297 passed, 1 skipped** in 3.62 s,
including 23 new HTTP cases. The existing skip needs disposable PostgreSQL and
is not accepted as concurrency evidence. Independent review separately passed
all 104 HTTP cases; architecture, formatting/lint, scoped mypy and diff checks
passed. [Source-bound evidence](tiingo-transport-evidence.json) and
[final output](tiingo-transport-final.txt) record the scope. No provider call or
genuine collector admission was introduced.

### A2 prior Linux failure: b6e4815

The approved PR run on `b6e4815` failed the original unprofiled retained restore
at **61.200 s** under the unchanged 60-second lease. This time expiry was detected
at the final retained-integrity account-fence recheck; lease release also failed.
Shard 7 reports **1 failed, 280 passed, 4,271 deselected**. The local 46.681-second
pass remains valid only as local evidence and does not satisfy A2.

[Bound failure record](linux-b6e4815-retained-failure.json) and
[original sanitized failure output](linux-b6e4815-retained-failure.txt) preserve
the result. At this checkpoint the other shards and failure-only diagnostic were still running.
The completed failure and the later repair are recorded below. Every original
ownership/provenance/SQL/fence check and all resource limits remain unchanged.

### A3.2b original measured health history

The optional `PersonalMeasuredClock` owns a fresh `StandardClock` and binds each
health result to its actual original Chrony conversion. It rejects changed private
history, copied owners/tokens, callback replacement and interleaved sampling. Weak
callback/registry ownership allows cleanup. Existing health/recovery semantics are
compared against a separate ordinary `StandardClock` with the same synthetic inputs.

Review reproduced an older valid source observation being substituted during a
final local callback. The [original failing regression](measured-clock-pending-reproduction.txt)
is retained; explicit pending-observation/call-count guards fix the association.
**186 focused cases passed** (94 new), along with architecture, scoped static checks
and independent review. [Source-bound evidence](personal-measured-clock-evidence.json)
records exact commands, prior type-check failure and limits. Historical ownership
is not currentness, host qualification, re-arm or genuine capture admission.

At the completed offline A3 checkpoint, full Ruff formatting/lint (1,021 files),
mypy (419 source files) and architecture checks pass. Collection through the actual
sanitized standard runner finds **4,757 cases** in 12.81 s without collection errors.
This includes all new component regressions; no test body runs in collection mode.

### A2 second local candidate: field conversion and scalar emission

The next minimal changes avoid exact-scalar recursive calls in dataclass fields
and build three canonical scalar fragments with one string allocation. They keep
JSON escaping, builtin conversion, original field-name/read order, fallback hooks,
fresh tuple allocation and all ownership/SQL/lease checks. Independent review
reproduced a temporary-object lifetime difference in the initial field loop;
explicit release before the next getter restores the original behavior.

[Field compatibility and failure evidence](semantic-field-evidence.json),
[original failure output](semantic-field-release-before-fix.txt),
[independent reproduction](semantic-field-lifetime-repro.txt), and
[scalar emission evidence](canonical-leaf-evidence.json) record the narrow scope.
The combined seven-file gate passes **262 cases** (21 new field cases, 8 new scalar
cases). Independent reviews and full static/API checks pass. Converter benchmark
ratios are candidate time divided by prior time, not startup speed: actual-contract
field fixtures measure 0.8015; non-scalar and tuple-field controls are slower.

The unchanged unprofiled retained test passes locally in **221.29 s**, with
176.562 s fixture setup and **41.963 s restore** under the original 60-second lease.
All preservation and cleanup assertions pass. [Bound evidence](retained-after-field-leaf-evidence.json)
and [original output](retained-after-field-leaf.txt) identify the exact source.
At this local checkpoint Linux acceptance remained open; the later full pass is
recorded below. No limit changed.

Final candidate collection finds **4,786 cases** in 12.98 s. The existing
Starlette/httpx deprecation warning remains; no dependency change was made.

### Prior CI closed before publishing the revised candidate

Run 36222039834 is complete: foundations/browser and 15 regression shards pass;
required shard 7 and its aggregate fail. The separate instrumented diagnostic
also fails at 60.562 s and reports a valid bounded profile. The
[profile summary](linux-b6e4815-profile-summary.json) preserves source/artifact
identity and the largest self costs. Canonical tuple emission (5.38 million calls)
and semantic conversion (3.09 million calls) remain substantial measured costs.
Inclusive timings overlap and cannot establish a startup speed claim. The revised
candidate is published only after preserving this complete failed run.

### A2/A3 final source acceptance and next handoff

[Run 36225463486](https://github.com/km8trix/AutoQuantTrader/actions/runs/36225463486)
completed successfully on `a8b92297ba0845b9038b7684ab60333d928d9c6d`. The tested
PR merge `bf7625d47f2d8a29a062d9e2310ab897a705ce82` has the identical Git tree
`1a58635e503d602085c0450a8df15b06ff2d6366`. All **4,786 selected tests passed**
across 16 disjoint Linux shards using disposable PostgreSQL, with no failures or
skips. Foundations, migrations, static/API checks, conventional wheel/installed
process, browser/Compose and the required aggregate passed. The failure-only
diagnostic correctly skipped. The existing Starlette/httpx warning remains.

[Complete bound result](linux-a8b9229-ci-pass.json),
[restore-shard evidence](linux-a8b9229-retained-pass.json) and
[original result lines](linux-a8b9229-retained-pass.txt) retain the identities and
counts. Shard 7 contains the original signed retained restore and reports 295
passes. Quiet successful output omits individual timing: the 41.963-second local
restore is not a Linux elapsed-time measurement. No lease, deadline, resource,
financial, ownership, provenance or cleanup assertion changed. Prior failures
remain preserved rather than overwritten.

A0–A3 are complete within their documented scope. The final follow-up changes
only documentation/evidence; runtime, tests and configuration remain identical
to the accepted source. [STATUS](../../STATUS.md) now names A4's first blocker:
identify the supervised Mac's measured-time source and non-secret qualification
record, then review the genuine producer/qualification proposal. The owner
question is pending. Existing provider rights/retention approvals remain scoped;
fresh session/window and initializer gates remain separate. No named independent
PLAN implementation is left unblocked. No provider effects or trading occurred.

### Resume: same-source CI repeat failed on 02a8ee6

[Run 36228369058](https://github.com/km8trix/AutoQuantTrader/actions/runs/36228369058)
completed with failures in shards 3 and 7; foundations/browser and the other 14
shards passed. Only documentation/evidence differs from the prior full passing
source. The original retained restore expired its unchanged 60-second lease at
60.412 seconds, during account-history validation, and lease cleanup also failed.
The separate diagnostic failed at 60.333 seconds. The fixed-worker restart test
failed with `probe_stalled`; its exact internal branch is not identified by CI
output. These are open investigations, not proof of a particular race.

[Failure/profile summary](linux-02a8ee6-ci-failure.json) and
[sanitized original excerpts](linux-02a8ee6-ci-failure.txt) retain both failures.
A2/A2.1 is now the highest-priority unblocked work. Earlier A2 acceptance does not
override this evidence. Preserve all lease, probe, operation and resource bounds;
measure a repair instead of repeatedly rerunning until green. A4 remains separately
blocked; resuming ordinary work supplies no recurring schedule or live authority.

### Resume: rejected shortcuts and probe repair investigation

Finite shortcut probes did not justify changes to canonical tuple emission or
daily identity traversal. Some regressed sampled contract graphs; faster variants
changed observable callback cleanup, generator `StopIteration` translation or
transient field-metadata destruction timing. [Investigation evidence](rejected-shortcut-investigation.json),
[exception reproduction](daily-identity-list-stopiteration-repro.txt) and
[finalizer reproduction](daily-identity-list-finalizer-repro.txt) preserve why
these candidates were rejected. Those production helpers remain unchanged.

A finite mocked-child schedule separately reproduces an unnecessary second
post-exit probe callback racing the supervisor's bounded final join. A narrow
terminal producer repair and adverse regressions are under validation; the CI
`probe_stalled` output still does not prove which internal stall branch fired.
The original owned-process unit run was blocked by sandbox denial of `/bin/ps`;
it is being repeated with scoped access, without changing test or process bounds.

### Resume: terminal probe repair locally validated

The terminal producer now exits after publishing its original post-exit sample.
[Pre-fix regression](probe-terminal-regression-before-fix.txt),
[controlled schedule](probe-terminal-race.json) and
[bound evidence](probe-terminal-evidence.json) preserve the reproduced defect.
The broad process unit suite passed **95 cases**, including 13 new adverse schedules.
The original fixed-worker restart and lifecycle integration suite passed **19 cases**
with unchanged financial-history, receipt, fence and cleanup assertions.
[Unit output](probe-terminal-process-unit-check.txt) and
[integration output](probe-terminal-worker-integration.txt) retain the results.
Scoped process inspection resolved the earlier sandbox denial; no code/test/limit
change was used to bypass it. Independent review passed. A2 still requires the
retained-cost repair and fresh Linux evidence; the exact CI probe stall remains
unattributed. No live, provider, initialization or trading operation occurred.

### Resume: actual retained canonical shapes and rejected SQL reuse

A bounded output-only diagnostic on the original retained fixture passed locally:
setup 193.831 s, restore 46.747 s, total 241.85 s. It captured only synthetic
canonical output strings during the original execute call, with 44-sample,
1 MiB-per-sample and 4 MiB-total caps. No original graph references were retained.
This instrumented result is diagnostic evidence, not unprofiled or Linux acceptance.

The [source-bound summary](canonical-retained-shape-summary.json) records 62,011
canonical calls and 10.861 s inclusive time. Twenty-two captured samples replayed
byte-for-byte; eight enum-containing samples were intentionally unsupported.
Another 253 outputs above the sample cap accounted for 39.65% of canonical time.
The admitted sample estimates cover only 31.05% of that time. Safe tuple variants
showed about 1.4% improvement on this limited mix, with other shapes regressing;
none was adopted. A guarded combined-fragment variant remained behaviorally
unqualified. Arbitrary-string memoization was rejected because retaining data
globally is unnecessary and could extend sensitive text lifetimes.

Operation-local SQL projection reuse was also prototyped without source changes.
Guards against mutable metadata and exposed expression mutation made it slower;
private templates with fresh deep clones were slower again. SQL queries, transfer
limits, original checks and production construction remain unchanged. The
[SQL rejection](journal-projection-rejection.json) records 10 normal and 41
adverse comparisons and candidate/original ratios of 1.56–1.60 for guarded reuse
and 2.32–2.45 for cloning. These are finite local experiments, not PostgreSQL
execution or retained acceptance.

### Resume: semantic generator correction and remaining decision

The earlier eager tuple/record loops changed generator exception behavior and
retained partial results through failing tracebacks. The initial 43-case
[regression run](semantic-stopiteration-regression-before.txt) had 29 failures.
Literal original generators are restored, retaining preexisting builtin dispatch.
Six additional lifetime cases brought the new file to 49 cases; the combined
[focused suite](semantic-stopiteration-after-all.txt) passed all 324 cases.
Independent review found no remaining issue.

The original unprofiled [retained test](semantic-generator-retained.txt) passed:
194.504 s setup, 45.425 s restore, 242.87 s total. The original
[worker/lifecycle suite](semantic-generator-worker.txt) passed 19 cases in
60.95 s. Architecture, full Ruff/format (1,023 files), mypy (419 files) and API
contracts pass. [Bound evidence](semantic-generator-evidence.json) records exact
sources and scope. These local results do not erase the latest Linux failure.

A final [inline-generator candidate](semantic-tuple-inline-assessment.json)
passed finite compatibility tests but regressed actual contract conversion by
about 1.4%; it was not adopted. Historical timings for withdrawn eager loops
must not be presented as current-source performance.

At that historical checkpoint, the [factory proof proposal](factory-verification-seal-proposal.md)
had independent review and an explicit owner question pending. It changes the contract for one
repeated in-memory fingerprint and requires proof of a restricted data profile.
Existing handoff seals do not supply that proof. No implementation, approval,
speedup, external-observation reduction or trading authority is inferred.

### Approved bounded offline proof pilot: implementation and failed baseline

The owner approved the [bounded factory-only design](factory-verification-seal-proposal.md).
This grants implementation scope, not acceptance or any provider/live authority.
The [invalid initial diagnostic](attempt-fingerprint-baseline-invalid.json) remains
incomplete: its 30-call counter exhausted. The subsequent
[retained-source measurement](factory-proof-retained-economics.json) completed the
original restore assertions and counted 72 eligible fingerprints in 24 borrows.
Their 3.169 s measured cost exceeds the optimistic 0.495 s data-only proof model;
the model excludes unfinished full ownership/behavior costs and proves no speedup.
[Pending-source measurements](factory-proof-pending-economics.json),
[prototype assessment](factory-pilot-prototype-assessment.md),
[safety review](factory-proof-safety-review.md) and
[finite behavior design inventory](factory-proof-behavior-inventory.md) retain the
preceding investigation and its limits. STATUS records current implementation.

The published `7c73cd6` baseline's
[Linux run](https://github.com/km8trix/AutoQuantTrader/actions/runs/36279615517)
finished **failed**. Fifteen financial shards plus foundations/browser passed;
shard 7's original retained restore expired the unchanged lease at **60.118 s**,
and its separate diagnostic failed at **61.393 s**. The aggregate correctly
remained failed. The uncommitted pilot was absent from this revision.
[Failure record](linux-7c73cd6-restore-failure.json),
[sanitized failure excerpt](linux-7c73cd6-restore-failure.txt),
[diagnostic profile](linux-7c73cd6-diagnostic-profile.json) and
[diagnostic exit](linux-7c73cd6-diagnostic-test-exit.json) preserve this evidence.
The diagnostic considered 4,988 profile entries; its 42 attempt fingerprints
cost 5.761 s inclusive before the failing restore ended. Calls include both
prepared and resolved paths, inclusive times overlap, and instrumentation is not
an acceptance timing. No rerun or safety-limit increase was performed.

The candidate then passed [93 focused tests](factory-proof-expanded-focused-final.txt)
(58 data, 23 behavior, eight instance-profile, four real-owned pending/genesis
controls). [Focused evidence](factory-proof-focused-test-evidence.json) retains
initial failures and repairs; this run preceded final source freezing.
The frozen [seven-case genuine lifecycle run](factory-proof-genuine-lifecycle-first.json)
also passed, including original restoration and rejected misuse with cleanup.
[Original output](factory-proof-genuine-lifecycle-first.txt) and
[source hashes](factory-proof-genuine-lifecycle-first-sources.json) bind that result.
Global profiling until first proof use affects its timings, so it is not an
unprofiled performance gate. Test observation was subsequently narrowed before CI.
The [test review](factory-proof-validation-review.md) also records the copied-case
poisoning assertion to make explicit. [Import/AST evidence](factory-proof-final-import-ast.json)
confirms unchanged public `require_resolved` and `_fingerprint` bodies and the
combined budget remaining after finite behavior/lifecycle metadata.

### Implemented pilot: original gates and full observed cost

The original [unprofiled retained test](factory-proof-original-retained-first.json)
passes with **40.246 s** restore, 179.754 s fixture and 222.75 s total. All original
lease/operation/process limits, preservation assertions and cleanup remain. The
nine [original integration/worker files](factory-proof-original-integrations-first.json)
pass **177 tests in 811.28 s**, with no skips. Production hashes are unchanged
through these gates and the combined run below.

All **100 new tests pass together in 321.91 s** in the
[combined log](factory-proof-combined-cost-first.txt), establishing genuine proof
admission after the mutation unit tests in the same interpreter. Local monitoring
replaces global call profiling in the genuine cases. The copied-proof case now
asserts the original operation is poisoned immediately, before independently
testing cleanup callback replacement. The nested mutation initially hit an earlier
historical-prefix guard; its final targeted refinement injects at the raw data
check after those original guards and requires the exact data-binding failure.
Its result is tracked separately, rather than attributing new assertions to this run.

The [cost capture](factory-proof-complete-economics.json) is valid, with no
diagnostic faults, 24 genuine borrows, 72 private checks, three original full
checks/fingerprints, and verified final retirement. Actual data, source/root
behavior and lifecycle reserve total **7,389 containers / 66,263 bindings** within
the original 16,384 / 131,072 caps. The measured issue/retire work is 0.173 s.
The model estimates **1.043 s** incremental work against **2.346 s** removed
fingerprints, or **1.303 s** savings. It includes the observed behavior and root
lifecycle spans missing from the earlier data-only estimate.

This remains an approximate model: original-prefix subtraction, monitoring
overhead and changing guard cost can bias it; a few new branch/finally instructions
are not isolated. The observed span envelope includes unchanged guards and is
not a rigorous upper bound. The 40.635 s instrumented positive restore is not an
unprofiled timing gate, and comparison to earlier local timings is not a paired
speedup experiment. These results justify submitting the bounded candidate to
Linux validation; they do not close A2 or establish startup acceptance.

[Independent final economics review](factory-proof-final-economics-review.md),
[local validation](factory-proof-local-validation.json),
[observer plan](factory-complete-cost-plan.md),
[literal observer source](factory-complete-cost-observer.py.txt),
[native layout probe](factory-proof-native-layout.json) and
[optional cache probe](factory-proof-native-optional-layout.json) preserve the
qualified CPython 3.12.13 implementation basis and diagnostic boundaries. Full
architecture, Ruff/format, mypy and API checks pass; the standard runner collects
4,948 tests. Unsupported interpreter profiles retain the original full source
validation. Exact-source Linux/PostgreSQL acceptance is still pending.

The final [targeted nested-data test](factory-proof-nested-final.json) passes in
**204.63 s** with unchanged production hashes. Its [output](factory-proof-nested-final.txt)
records exact `FACTORY_ATTEMPT_DATA_BINDING_CHANGED` rejection at the data seal
after the original prefix guards; assertions also require no permit completion,
original failure latches, and complete registry retirement. Fifteen observer
selfchecks and final scoped Ruff/format pass. This is the separate evidence for
the strengthened test; it does not retroactively change the historical 100-case run.

The [final resumability review](factory-proof-final-resume-review.md) checked the
operating documents against candidate `2a9fc2c`, separating historical evidence,
current CI, fallback-runtime skips and the remaining A4 input. Its five handoff
findings were corrected without changing code, tests or approvals.

### Candidate Linux worker failure: observation subtype missing

At `2a9fc2c`, [run 36285774497](https://github.com/km8trix/AutoQuantTrader/actions/runs/36285774497)
worker shard 3 fails one original restart test; 326 cases pass, no skips.
[Failure metadata](linux-2a9fc2c-worker-failure.json) and the
[bounded excerpt](linux-2a9fc2c-worker-failure.txt) preserve the coarse
`child_observation_failed` result. Actions tested the generated PR merge ref
recorded in the evidence, with the candidate as its run head.

Source review locates that reason at the parent's original non-reaping
`_observe_child` call. It may mean timeout before the work deadline, OS/subprocess
error, or rejected `ps` output; the log cannot distinguish them. The failure
precedes the original child-exit event and differs from the prior terminal-probe
race. The test uses signed genesis plus an initial assignment, without attempt
sources, so the nonempty fingerprint-proof path is ineligible. No observed
evidence attributes the failure to the proof or to any particular OS condition.

The final outcome also indicates owned-child cleanup completed: `_run` would
replace the result with `cleanup_incomplete` otherwise. This inference does not
identify the failing iteration or exception. The test retains its original
30-second parent/CPU bounds and 512 MiB memory limit, separate from the large
retained-outcome fixture. A test-only diagnostic is being added to preserve the
first observation exception category and bounded scalar timing through cleanup,
without printing raw exception text, outputs, commands or paths. Production
observation semantics, original assertions and all limits remain unchanged.
A passing diagnostic repeat alone cannot repair or close this failure.

The test-only [diagnostic implementation](worker-observation-diagnostic-plan.md)
passes [102 cases](worker-observation-diagnostic-validation.json) in 24.34 s:
82 original process unit cases, 19 diagnostic cases, and the genuine worker
restart integration. Scoped Ruff/format and architecture pass; the standard
runner collects 4,967 tests including the new 19. Production files are byte-for-byte
unchanged from `2a9fc2c`. This validates the instrumentation locally, not the
unknown Linux observation failure. The active published run is being preserved
before a new evidence-bearing revision is submitted.

The same candidate's [genuine positive proof case](linux-2a9fc2c-proof-positive-failure.json)
also fails at **60.265 s**, during the original borrow coordinator revalidation,
followed by expired-lease release. Shard 4 reports one failed, 338 passed and no
skips; the [bounded trace](linux-2a9fc2c-proof-positive-failure.txt) identifies the
rejection boundary, not performance causality. No proof-change error appears in
the trace. Because execution raises before the final test assertions, this log
alone does not report proof admission or completed-use counts at failure. The
original unprofiled retained test remains a separate required result. Linux
acceptance is failed; local timing/model results do not override it.

A [bounded follow-up assessment](factory-proof-linux-failure-assessment.md)
identified that missing private-entry visibility. The lifecycle test now emits
only its fixed positive case and `private_entry_seen` boolean after existing
cleanup when execution unexpectedly fails. Independent review found no blocker;
two isolated failure-plumbing checks preserve the original exception and monitor
slots. True means captured entry, not completed proof; false alone cannot prove
fallback. All original assertions and production code remain unchanged.

The [collection-only check](factory-proof-collection-baseline-health.json) replays
the 4,948 published node IDs locally without fixtures: static/source/root behavior
baselines are present and healthy after collection. Review of the ten preceding
shard-4 test bodies found no demonstrated persistent pinned-namespace mutation.
This does not reproduce Linux or those fixture executions, establish proof use
in the failed run, or support a speculative change to admission. Inspect the
exact-source Linux profile before further performance decisions.

The [original unprofiled retained gate](linux-2a9fc2c-original-restore-failure.json)
also fails on the candidate at **60.193 s** (shard 7: one failed, 302 passed,
no skips). Its [bounded trace](linux-2a9fc2c-original-restore-failure.txt) reaches
the same original borrow coordinator lease rejection and expired-lease cleanup
as the positive proof case. Neither failure is timing acceptance or a reason
to enlarge the lease. The separate exact-source diagnostic is needed to assess
proof use/cost; current production code remains frozen.

### Completed candidate financial matrix

All 16 shards finished: **4,944 passed, four failed, no skips**, covering exactly
the 4,948 selected tests. Foundations/installed-wheel and all 139 browser tests
pass; the required backend aggregate fails. The [financial summary](linux-2a9fc2c-financial-summary.json)
preserves every shard's result and raw-log hash, with the verified identical
candidate and generated-merge tree.

The fourth failure is the genuine `retired` positive case at **60.313 s**:
[record](linux-2a9fc2c-proof-retired-failure.json) and
[bounded trace](linux-2a9fc2c-proof-retired-failure.txt). It expires at the original
borrow commit-fence revalidation, before its retirement assertions can run;
expired-lease cleanup also fails. Shard 15's precise `nested_data` adverse case
passes. These separate outcomes must not be collapsed into proof acceptance.
The [complete run](linux-2a9fc2c-ci-failure.json) is failed. Its separate
[diagnostic](linux-2a9fc2c-diagnostic-profile.json) is valid with no capture faults,
but the test [exits 1](linux-2a9fc2c-diagnostic-test-exit.json) after restore lease
expiry at 63.075 s. The [trace](linux-2a9fc2c-diagnostic-failure.txt) reaches original
descriptor/reconciliation commit-fence revalidation and expired-lease cleanup.

The private proof route ran 36 times in that diagnostic. Data and behavior
verification account for 0.666 s and 0.128 s inclusive; larger preserved
canonicalization, identity and SQL construction paths dominate visible costs.
Those nested spans cannot be summed or used as unprofiled speedup evidence.
The [independent interpretation](factory-proof-linux-failure-assessment.md)
records why the pilot remains unaccepted and why no further broad profiling is
needed merely to establish route use. Local diagnostic commit `0f9b191` can now
be pushed without cancelling this completed run. Production remains unchanged.

A finite [identity-classification probe](daily-native-membership-rejection.json)
then rejected two apparent scalar-dispatch shortcuts. Frozen native membership
changes dynamic alias rebinding; a live tuple eagerly loads names that the
original chain may short-circuit. Custom metaclasses retain the original path,
but that does not repair either counterexample. Synthetic timing was mixed or
worse. The [literal probe](daily-native-membership-probe.py.txt) preserves the
original tuple/generator traversal and performs no project imports or operational
effects. No implementation or heavy follow-up was justified.

### Diagnostic follow-up and completed original-only measurement

Diagnostic/evidence revision `26631c6` was pushed to the existing draft PR #56.
Production remains identical to `2a9fc2c`. Its
[verified candidate/merge tree](linux-26631c6-source-binding.json) and current
Linux [positive proof failure](linux-26631c6-proof-positive-failure.json) preserve
a 60.278 s expiry at borrow commit-fence validation. The
[static trace](linux-26631c6-proof-positive-trace.json) records
`private_entry_seen=true`: the route was entered, not necessarily completed.
The [unchanged original retained gate](linux-26631c6-original-restore-failure.json)
also expires at 60.113 s, at initial borrow coordinator validation in its
[trace](linux-26631c6-original-restore-trace.json). The original worker passes;
its failure-only marker is silent, so the older unknown observation error is
not explained. The remaining matrix and automatic diagnostic are still running;
STATUS is the current progress source. No source repair is inferred from these
instrumentation changes or a passing repeat.

The separate A2.4 original-only local measurement is complete:
[result manifest](daily-identity-original-result.json),
[scalar observation](daily-identity-original-observation.json),
[original test output](daily-identity-original-test.txt), and
[independent interpretation](daily-identity-original-result-assessment.md).
All 24 borrows and 144 targeted public/identity calls returned, with valid capture,
unchanged hashes and no observer faults. Original pytest passed in 246.33 s;
observed execute was 44.306 s, with 2.1675 s of disjoint builder work and 2.4653 s
of inclusive public validation. These nested costs are not additive or net savings.

The [reviewed plan](daily-identity-observer-plan.md),
[readiness record](daily-identity-observer-ready-reviewed.json),
[observer source](daily-identity-observer.py.txt),
[synthetic tests](daily-identity-observer-tests.py.txt),
[29-case result](daily-identity-mechanics-final.txt) and
[independent mechanics review](daily-identity-observer-independent-review.md)
retain reproducibility. No project method, argument, SQL/object/fence read,
lease or test assertion changed. The existing original test enforces cleanup;
the observer does not separately time or infer `factory.close`.

The vector has 54,690 edges; existing simultaneous attempt-proof use leaves
64,813 binding and 8,997 container units. Neither the vector/visited sizes nor
9,923 unclassified edge types establishes a daily proof's charge or eligibility.
The [boundary assessment](daily-identity-proof-decision-assessment.md) and
[separate feasibility proposal](daily-identity-feasibility-proposal.md) explain
why no automatic production extension follows. The owner subsequently approved
the separate feasibility experiment only; A2.5 starts with shared-resource fit
and independent review before any genuine fixture. Production remains unchanged.
A further [journal projection audit](journal-columns-cost-assessment.md) found
no safe material small fix: guarded reuse already regressed and unguarded reuse
has a concrete mutable-bound counterexample. No new fixture or implementation
was justified for that hotspot. The approved pilot remains unaccepted.

### Approved feasibility: first layout rejected

The owner approved only the separate temporary experiment. Its
[concrete per-node layout](daily-identity-node-layout.md) retains one logical
record per visited non-scalar identity under the existing proof accounting. The
[resource screen](daily-identity-node-layout-resource-screen.json) needs at least
9,356 containers and 73,402 bindings in addition to the current attempt proof.
Joint totals exceed the unchanged caps by **359 containers and 8,589 bindings**
before any further schema/behavior/context/construction costs.

[Validation](daily-identity-node-screen-validation.json),
[37-case result](daily-identity-node-screen-selfchecks.txt),
[literal scalar code](daily-identity-node-screen.py.txt),
[selfchecks](daily-identity-node-screen-tests.py.txt),
[executed commands](daily-identity-node-screen-commands.md), and
[independent review](daily-identity-node-screen-independent-review.md) preserve
this bounded rejection. No new graph, authority, source import or fixture was
created. Raw eligibility, transitive behavior and timing were not implemented;
they cannot rescue this layout's lower bound. An alternative representation is
untested, not automatically impossible or an accounting exemption.

A separate [pre-lease source review](prelease-restoration-seam-assessment.md)
finds preparation/fresh-recheck precedents, but no existing qualified handoff
across writer-lease acquisition. The coherent snapshot includes lease/head rows
that acquisition changes; daily captures also carry an original fenced receipt.
Moving those owned results across acquisition would change lifecycle/error-order
and exact-snapshot contracts. No such implementation or approval is inferred.
