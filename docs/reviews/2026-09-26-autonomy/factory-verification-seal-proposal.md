# Factory-only verification substitution — approved development scope

Status: **owner approved the bounded offline design on 2026-09-26**. The explicit
reply was “approve the bounded offline design.” Detailed proof/handshake review,
implementation, independent adverse tests and original acceptance gates remain
required. This approval does not establish validity or performance, expand the
pilot, change limits, or authorize live/provider effects. The proposal below
records the approved scope and remaining engineering obligations.

Current checkpoint: the candidate is implemented and independently reviewed.
Original local restore and 177 original integration/worker tests pass, as do
100 new tests together. The [complete observed cost model](factory-proof-complete-economics.json)
includes the behavior/lifecycle spans absent from the early data-only experiment;
its estimated 1.303 s benefit remains approximate. Exact-source Linux candidate
`2a9fc2c` finishes the financial matrix with 4,944 passed, four failed and no skips:
the original worker, original retained restore and both positive proof cases fail.
The separate diagnostic also expires; it confirms the private route ran but
provides no unprofiled speedup or completed-restore evidence. The pilot is not accepted.
See [Linux assessment](factory-proof-linux-failure-assessment.md),
[current local validation](factory-proof-local-validation.json) and
[final economics review](factory-proof-final-economics-review.md). The dated
proposal and early measurements below retain their original context.

## Approved decision and measurement checkpoint

Develop a pilot in which the existing HALTED factory restore uses an owner/thread/operation-bound seal
of a narrowly admitted, already authenticated source-data graph to substitute a
fresh structural/identity check for **one repeated pure fingerprint operation**,
while retaining all existing ownership checks, fresh external observations and
full entry/terminal verification. Adopt it only after the requirements below pass.

The smallest pilot is the final `_fingerprint(value)` comparison in
`SqlContinuousRuntimeAttemptSources.require_resolved` at
`packages/persistence/continuous_runtime_attempt_sources.py:2442–2454`, during
borrows of the same `ResolvedDailyRuntimeSnapshot` by the existing private
factory `_OriginalDailyEpisode`. The remaining body of `require_resolved` still
runs: `_require`, all account references, historical descriptors and outcome
readers. Ordinary `require_resolved` callers retain the existing full algorithm.

This is smaller than consolidating fresh SQL reads or caching arbitrary resolved
results. Those changes are **not proposed**. The profile recorded 29 calls to the
attempt fingerprint, about 6.003 seconds inclusive, inside a failing restore.
That method serves both prepared and resolved values; the profile does not
attribute all 29 calls to the proposed resolved path. This is a target for
measurement, not a promised saving. Its descendants account
for other time that this initial pilot deliberately does not remove.

The reviewed alternatives were:

1. **Keep the current validation contract.** Continue only changes proven to
   preserve all current reads/callbacks/errors, and leave retained acceptance
   open if no such change meets the existing limits.
2. **Authorize the bounded factory-only proof substitution above.** Develop and
   independently review this specific contract, with no assumption of success
   and no authority outside the original active factory operation.

The owner selected alternative 2. An initial original-test timing diagnostic
then completed restore in 47.151 seconds and passed the original assertions,
but exhausted its 30-call diagnostic cap. Those first 30 calls were all resolved
fingerprints, totaling 1.139 seconds. The incomplete attribution must not be
reported as the total cost, a speedup or acceptance. Source hashes were unchanged;
[invalid metadata](attempt-fingerprint-baseline-invalid.json) and the
[original output](attempt-fingerprint-baseline-invalid.txt) are preserved.
That checkpoint required measuring the proposed proof cost on authentic source
data before adding the lifecycle machinery. The permitted outcome includes rejecting this pilot
when its benefit does not justify the implementation or proof burden.

Neither alternative authorizes changing the lease/operation/process/resource
bounds, weakening tests, enabling trading, changing risk policy or adopting a
later account history. A broader SQL-snapshot verification schedule would be a
separate, more consequential proposal.

## Verified precedent and explicit gap

| Existing source | What it already permits | What it explicitly does not establish |
|---|---|---|
| `continuous_integrity.py:_original_daily_episode` (1314), `_borrow_original_daily` (1393) | Reuse of the exact original daily snapshot in one owner/thread-bound episode, bounded borrows, failure poisoning and retirement. | Each borrow still invokes the complete daily/source graph guards, original-object rechecks, SQL rechecks and actual fence observations. |
| `continuous_integrity.py:_factory_structure` (413), `_require_factory_structure` (622) | Bounded seals of explicitly admitted original field/sequence/mapping bindings; checks without rehashing or serialization at existing handoff sites. | Its docstring keeps known owners subject to full graph guards. It is a handoff seal, not authorization to bypass a source owner's fingerprint. |
| `daily_runtime_risk.py:require_same_complete_capture` (1286) and `continuous_capture_comparison.py` | Exact original capture reuse after a real fresh complete capture compares equal; explicit data and opaque-owner boundaries. | No ownership, risk validity, currentness or cross-call validity cache is created. Repeated comparison calls reread inputs. |
| `detached_journal_capture.py:DetachedJournalCapture` | Interning equal detached row copies under aggregate transfer bounds. | No SQL query is omitted and no validation/authority is cached. |
| `continuous_integrity.py:_factory_operation` (958), `_verify_factory_terminal` (923) | Original factory operation/thread registration, reentrancy denial, full final guards and cleanup/failure retirement. | It is not a generic context flag allowing arbitrary stores to skip validation. |

The present seal is insufficient for the proposed substitution. It treats exact
`datetime` values as scalar leaves without independently qualifying their tzinfo;
it records fixed dataclass field names without making a general promise about
later field-inventory, type module/qualified-name, descriptor or class-method
replacement; and configured owners remain
opaque identities whose own full guards are authoritative. A frozen dataclass,
mapping proxy, object ID or old digest alone does not supply deep immutability.
Enum member identity is also insufficient: its name/value and class behavior can
change. The existing handoff is a checked mutable graph, not a truly immutable
value representation. Reusing it unchanged would not prove fingerprint equivalence.

## Exact proposed lifecycle and boundary

1. Enter the existing original factory operation normally. The existing schema,
   account, source, journal, codec and object validation runs unchanged. Do not
   use a seal during this first authentication.
2. Only after the original attempt source owner completes its full existing
   `require_resolved`, and only inside the factory's original daily episode,
   issue a private seal for that exact `ResolvedRuntimeAttemptSources` object and
   the exact data projection already consumed by its `_fingerprint`.
3. Bind issuance to original source owner, factory reader, active operation,
   episode, daily snapshot, thread and method/dependency bindings. Use an actual
   private ownership registry; copied dataclasses, equal reconstructed content,
   object IDs alone and deserialized tokens must not be accepted.
4. At each otherwise unchanged fingerprint point in a later borrow, first run
   the unchanged preceding owner/reference/descriptor/outcome checks. Recheck
   the original seal, permitted class/schema/field/leaf profile and every mutable
   binding in its admitted data projection. Return no new source token or
   authority. Never update the seal's baseline from a changed graph.
5. Keep the existing final full `_require_daily_episode` check in
   `_validate_original` before `_recheck_final`, and the separate full factory
   terminal output verification. Preserve the actual episode context-manager
   exit's identity-only checks and cleanup; do not describe those as a full
   fingerprint check or silently add another one. Seal availability must not
   change standalone schema verification, standalone account restore, source
   publication or any future execution path. Retire it on normal exit, failure,
   cancellation and cleanup.
6. Retain existing failure latching, primary-error preservation and cleanup
   ownership. A failure cannot make the operation reusable or install a receipt.

The proof obligation is: the admitted data projection is still the exact
authenticated value the original fingerprint covered, and all behavior-bearing
dependencies that could change that projection remain the originals. It is not
merely that the top object or a tuple is unchanged.

## Unchanged checks and observations

The following remain at their original positions and with their existing inputs:

- `SqlContinuousIntegrityReader._require_graph`, original episode owner/thread/
  consumer/borrow-bound checks and all source-owner registries/bindings;
- both `daily.require_resolved_snapshot` calls in `_require_daily_graph`;
- account-reference, historical-descriptor and outcome checks in the proposed
  pilot source method;
- `coordinator.revalidate`, all original object/artifact rereads, committed
  observation rechecks, `daily.recheck_snapshot_in_transaction` and
  `revalidate_for_commit_in_transaction` in `_borrow_original_daily`;
- every journal/SQL capture and recheck, query order, row/copy/transfer limit,
  transaction boundary and rollback-only clock observation;
- later fresh daily read and complete equality comparison, all full terminal
  owner/source/object/SQL/fence verification and result/receipt/child cleanup;
- original timestamps, expiry, account history, HALTED state, trading authority
  false, schema and resource profiles.

No entry/exit-only external validation schedule is proposed. A changed SQL row,
object payload, fence/lease or clock observation at an intermediate original
boundary must still fail there.

## Narrow implementation review scope, if approved

Expected owners are `continuous_integrity.py` for episode/factory lifecycle and
`continuous_runtime_attempt_sources.py` for the one owner-issued fingerprint
proof. Add a small private shared type only if needed to avoid a dependency cycle;
do not move the existing general handoff machinery or add a framework.

Keep the public source method unchanged. A private, explicitly selected
factory-only method may share its unchanged validation body and substitute only
the final fingerprint check when presented with an authenticated original seal.
Do not use a process-global cache, a public `skip_validation` flag, a thread-local
ambient bypass, or a caller-supplied boolean asserting immutability. Exact names
and the final handshake are subject to design review before code is authorized.

Seal construction must use the fingerprint's actual projection, not a separately
invented partial object inventory. Admit only a documented exact built-in/domain
data profile; custom getters, schema/descriptor behavior, subclasses, mutable
timezone providers and unknown leaves use the unchanged full-validation path
from the start. Once issued, seal mutation/rebinding poisons the operation; it
must not reseal changed input. Original source fingerprints and constructors
remain available as independent test oracles.

For every admitted record class, the proof must cover the field inventory and
field-definition identities/names as well as the type module/qualified name and
original behavior used by conversion. Getter/descriptor and enum name/value
behavior cannot be inferred from an unchanged instance field pointer. Pinning
known implementations or admitting only a narrower representation is a required
design decision; no current helper already proves all of this.

Account for the extra retained references and overlapping seal lifetimes inside
the existing container/binding/memory limits. Reusing a handoff helper does not
authorize another independent allowance or a larger combined resource profile.
Do not retain the seal or its graph after the original episode ends.

## Acceptance and failure tests

1. Literal preceding source validation versus the new path: same accepted
   genuine owner result, nested account/descriptor/outcome calls, SQL/artifact/
   clock trace, exception precedence and no authority expansion.
2. Mutate each admitted graph category between borrows and from a preceding
   callback: dataclass fields/schema/descriptors, nested mappings/lists/aliases,
   enum value/name, raw bytes replacements, source references, opaque owner
   tokens and behavior-bearing methods. The sealed path fails before returning
   the changed value; it never adopts an equal foreign token.
3. Exact-scalar and immutable-leaf edge cases including Decimal representation,
   datetime timezone/fold and custom subclasses; unknown profiles keep the full
   old path, including its StopIteration/finalizer/error behavior.
4. Owner copy, token copy, reconstruction, wrong source/daily/reader/operation,
   foreign thread, nested entry, overlapping factory, later operation and restart
   cannot reuse the seal. No warmed result or serialized proof can be injected.
5. Mutation from external callbacks still reaches the original SQL/object/fence
   rechecks. Expired lease, replaced artifacts, changed journal rows, rollback,
   cancellation, callback errors and cleanup failures remain failures with the
   same unchanged external observation schedule.
6. No extra aggregate allowance: boundary-size graphs, aliases/cycles, failed
   issuance, partial cleanup and garbage collection stay within original limits
   and release retained owners/graphs.
7. Existing daily episode, factory handoff/scope, source ownership/comparison,
   original retained restore and fixed-worker tests pass. Relevant existing
   suites include `test_continuous_integrity_daily_episode.py`,
   `test_continuous_factory_scope_lifecycle.py`,
   `test_continuous_factory_integrity_result.py`,
   `test_continuous_factory_daily_handoff.py`,
   `test_continuous_factory_pending_handoff.py`, and source comparison suites.
8. Independent review, architecture/Ruff/mypy, the unchanged original retained
   acceptance gate and complete exact-revision Linux/PostgreSQL CI pass. Measure
   the full cost including issuance, guards, retirement and peak retention;
   reject the pilot if it does not provide useful reliable margin.

## Limits and unresolved engineering proof

The deliberate semantic delta is replacing a repeated pure computation with a
different proof that its input and behavior are unchanged. That can change which
pure callbacks run and when unsupported mutable behavior is rejected. This is
why existing handoff precedent alone does not authorize implementation as a
performance micro-optimization.

In particular, full entry/terminal checks can detect a transient mutation too late
to preserve an earlier error or callback ordering, or miss a change that was
restored before the final check. They are not a substitute for adequate proof at
each original intermediate fingerprint point. Approval must explicitly accept
the restricted, effect-free data/getter/schema profile and fail-closed handling
of newly unsupported behavior. The proposal does not promise identical callback
counts or historical error order for hooks intentionally excluded by that newly
approved profile. If those behaviors must remain fully supported at every point,
the original full computation remains required and this proposal is not viable.

The data profile, transitive method/schema binding inventory, bounded ownership
handshake and equivalence of the fingerprint projection must still be specified
and reviewed. A successful seal comparison cannot assert currentness beyond the
existing fresh checks or extend the original lease. If this limited pilot is
insufficient, any proposal to omit/coalesce SQL, artifact, clock or owner checks
returns for a separate explicit decision.

The guarded SQL projection experiment was rejected before production work:
[the rejection evidence](journal-projection-rejection.json) summarizes its finite
performance and mutation evidence. There is no pending cache patch to
approve alongside this architectural decision.
