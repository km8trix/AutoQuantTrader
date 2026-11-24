# Linux factory proof failure assessment — 2026-09-26

Read-only assessment by spec_plan_audit. No source/test edits, provider effects,
local fixture runs or new approval assumptions.

## Verified failure and present limit

At `2a9fc2c5adda25c49e7d1c1ca78e2845b7bb64eb`, run 36285774497, shard 4 fails
`test_genuine_factory_proof_lifecycle_preserves_original_history[original]`:
338 passed, 1 failed, no reported skips. The restore reports 60.265 seconds. The
observed rejection is original coordinator lease revalidation reached through
`continuous_composition._historical_current` ->
`continuous_integrity._borrow_original_daily:1859` -> `account_coordinator.revalidate`.
Cleanup separately reports expired-lease release, preserved in the ExceptionGroup.
The unchanged lease and cleanup gates are enforcing their requirements.

This identifies where elapsed work was rejected, not the time-consuming cause or
how much work remained. A 0.265-second overshoot is not evidence that saving
0.266 seconds would complete the restore. There are still validation boundaries
after this code location. The worker observation failure in shard 3 is a separate
observed failure; neither establishes the other's cause.

The original retained test's shard 7 and ensuing bounded Linux profile were still
pending at the time of this assessment. Their eventual results must be recorded
without replacing this failed positive-case evidence.

## An actual observability gap

The positive case currently records the first private proof-method entry in its
`captured` dictionary, but emits no scalar indication of that fact on failure.
`_execute_retained_factory` raises, control performs the test's existing finally,
and the following `assert captured` and retirement assertions are never reached.
Therefore the failure log does **not** show whether the proof was active or an
initial unsupported profile retained the full path. The trace reaches a borrow
and its first daily graph check has returned, but that check has both ordinary
and private branches. The stack cannot distinguish them.

Passed adverse cases on other shards do not fill this gap: the parameterized
nodes run in separate shard processes with different preceding tests/import and
cache state. The local admitted run also cannot establish admission in this
failed Linux process.

## Smallest useful next observation within approved scope

First inspect the already-scheduled exact-source Linux profile and shard 7 result.
The existing profile covers factory.execute only. Look for actual calls/costs of
`_require_resolved_for_factory`, `_issue_daily_fingerprint`,
`_issue_factory_fingerprint`, `_try_seal_attempt_data`, both behavior `require`
paths and `_AttemptDataSeal.require`, together with the original full source
fingerprint costs. A recorded call proves that code was entered, not necessarily
that issuance or a check completed. Its selected top-N rows may omit cheap
functions, so absent rows must not be interpreted as zero calls. Its profiled
isolated original test is not the same process as failed shard 4 and adds overhead.

If that evidence does not resolve admission/use, the smallest useful additional
test observation is **failure-only scalar phase metadata** on the existing genuine
positive case, preserving the original exception and all assertions:

- Reuse the already-populated `captured` truth value as `private_entry_seen`.
  This requires no extra observation calls or retained objects.
- If that value is false or issuance distinction is needed, add one-shot local
  monitoring on the original root issue method's entry and normal return, retaining
  only `issue_entered`, `issue_returned`, and `nonnull_proof_returned`. Inspect the
  actual monitoring return value transiently, not a fabricated source record.
- Emit those booleans only after the original failure and existing cleanup, then
  re-raise the original exception. Do not print locals, objects, paths, exception
  payloads, native cache contents, record classes or arbitrary type names. The
  normal positive assertion remains mandatory.

This separates not-reached / issue-unwound / ordinary fallback / admitted-but-not-
yet-used / active-private-use without changing producer code, validation order,
permits, deadlines or retry behavior. The existing first-use observer remains a
one-shot and costs no additional traversal. Any added observer needs finite
mechanics tests and independent review, as previous diagnostics did. No such edit
is made or authorized by this assessment itself.

Only if useful costs are omitted should the existing bounded report gain a fixed
small inventory of selected function counters from already-collected stats. That
would be metadata extraction, not another heavy local run or extra validation.
A bounded same-host authentic cost observation is useful only if the upcoming
profile cannot separate the decision; avoid repeated profiling without a specific
question.

## What the current economic evidence can establish

The valid local complete-cost observation has 24 borrows/72 private checks and
models 2.345598024 seconds of removed fingerprints against 1.042580999 seconds of
added work: **1.303017025 seconds estimated saving**, candidate/original ratio
0.4444840882. It charges issuance and both root retirement calls. Shared resources
are 7,389 containers and 66,263 bindings within unchanged caps.

This is a bounded local model, not paired before/after timing. Its prefix estimate
comes from only three ordinary checks and is extrapolated across 72 private calls.
Monitoring, prefix variation and non-isolated branch instructions limit precision.
The local original restore's 40.246-second pass and instrumented approximately
40.6-second run are not portable Linux margins.

The model indicates modest benefit for this one substitution. Even idealizing
all *modeled* new bookkeeping to zero would remove only its approximately
1.043-second added cost locally; that is a thought experiment, not a rigorous
upper bound or an achievable optimization claim. No measured evidence currently
supports a second substantial improvement within the same narrow scope. The
failed Linux trace alone neither disproves the local saving nor demonstrates
that further bookkeeping tuning could close the Linux gate.

## Decision boundary

- If the failed positive case never admitted a proof, diagnose the exact initial
  unsupported condition conservatively. Preserve the original fallback; do not
  widen native/class/source admission merely to force the test onto the fast path.
  A concrete accidental test/import contamination or incorrect bounded profile
  assumption can then receive a narrowly justified repair and adverse tests.
- If the proof was active and full behavior/data/lifecycle overhead dominates the
  permitted substitution, use authentic measured costs to identify a specific
  bounded implementation defect. No such defect is established by this failure.
- If the proof was active, has the expected modest benefit, and the mandatory
  lease still expires in preserved work, this pilot is **not a sufficient restore
  fix**. Keep acceptance open and record that result; a subsequent isolated pass
  cannot erase it. Do not broaden the substitution to owner/reference/descriptor,
  SQL, object, observation or fence checks, and do not extend/renew the lease to
  make the candidate pass. Any substantially broader architecture is a separate
  decision, not implied by this pilot approval.

The honest immediate next step is the already-pending Linux evidence plus the
minimal admission/use visibility if still necessary. It is premature either to
claim acceptance or to attribute the failure to insufficient proof benefit without
knowing whether the proof ran. No new product decision is needed merely to obtain
that missing bounded diagnostic evidence.

## Cheap collection and predecessor check

At root's request, a temporary collection-only plugin inspected the already
created static/source/root behavior seals after collecting the recorded standard
file set. All **4,948 nodes collected in 13.00 seconds** on the verified local
CPython 3.12.13 interpreter; all three baselines were present and `require()`
passed. No fixture or test body ran and no baseline was changed. Artifacts:
`factory-proof-collection-health.py`,
`factory-proof-collection-baseline-health.json`, and
`factory-proof-collection-baseline-health.txt` in the same audit directory.

The saved SHA256-modulo-16 selection has ten cases before the failed positive:
one account-observation case, four applied-reconciliation cases, and five
continuous-account-store cases (including a PostgreSQL restart/rollback case).
Their selected bodies use fixture-owned SQL/object mutations; the codec function
replacement is managed by pytest's monkeypatch teardown. The copied observation
uses dataclasses.replace, not copy.copy. Read-only inspection found no demonstrated
unrestored pinned class/module mutation in those selected bodies. Fixtures and
transitive behavior were not executed, so this is not proof of zero side effects.

The local collection result does not reproduce the Linux process or preceding
fixture execution. It uses the current checkout, whose worker test has a pending
test-only diagnostic import; the new diagnostic unit file is outside the recorded
4,948-node selection. Production proof sources are unchanged. This check provides
no evidence for blaming whole-suite collection, and does not resolve actual Linux
admission. Stop chasing that hypothesis without a concrete failing inventory;
retain the minimal failure-phase observation as the next discriminating evidence
if the pending profile cannot answer it.

## Completed Linux evidence and independent interpretation

Run 36285774497 completed with 4,944 financial passes, four failures and no skips
across all 4,948 nodes. Both positive genuine proof cases, the original retained
restore and the original worker restart fail. All five genuine adverse cases
pass. Foundations/installed-wheel and browser pass. See the
[complete source-bound record](linux-2a9fc2c-ci-failure.json).

The [separate profile](linux-2a9fc2c-diagnostic-profile.json) is valid with no
diagnostic faults and considers 5,085 entries. Its execute call starts but does
not return; the original test [exits 1](linux-2a9fc2c-diagnostic-test-exit.json)
after 252.50 s, with restore elapsed 63.075 s. The selected private source method
has 36 entries, root borrow has 12 entries, raw data admission has one entry,
data-seal `require` has 39 entries and behavior-seal `require` has 150. This
establishes that the private route ran in this diagnostic; wholesale fallback
does not explain this run. It does not establish every return, retirement,
remaining work or admission in the separate failed shard processes. The counts
are consistent with one issuance and 36 uses, but are not completion events.

The data and behavior `require` families take 0.666 s and 0.128 s inclusive,
respectively. These two nonnested categories are only part of pilot cost.
The 9.166 s private-method span also contains unchanged original guards; calling
it optimization overhead would be incorrect. Visible preserved work includes
canonical byte conversion (15.681 s inclusive) and assignment identity traversal
(6.879 s inclusive, 2.979 s self). These and higher-level validation spans overlap
and must not be added. Profile overhead and a failed partial execution preclude
an unprofiled speedup or acceptance claim.

The [failure trace](linux-2a9fc2c-diagnostic-failure.txt) reaches original
descriptor/reconciliation recheck and commit-fence lease enforcement, followed
by expired-lease release. No proof-mutation rejection is reported. The independent
architecture_audit reviewer confirmed these interpretations by reading the
artifact and source; no extra execution or mutation was performed. Production
remains unchanged. No additional broad profiling is justified merely to establish
private-route use. The reviewed failure markers remain useful for unprofiled
shard failures and the separate unknown worker observation subtype.

The pilot has not satisfied Linux acceptance and is not a sufficient demonstrated
restore repair. Any further pure optimization must preserve actual behavior and
target measured work. Widening proof substitution or changing the SQL/object/fence
schedule or limits remains outside the approved pilot.
