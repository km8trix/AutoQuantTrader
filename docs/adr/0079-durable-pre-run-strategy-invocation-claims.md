# ADR 0079: durable pre-run strategy invocation claims

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0075 bounds one supervised strategy subprocess and ADR 0077 atomically
records its result, breaker transition, and critical-alert incident. They do
not close the crash window before the subprocess effect. A process can start a
child and disappear before the result is recorded; after restart, absence of a
result does not prove that the child never ran. Automatically invoking the
same immutable strategy request again would therefore duplicate an uncertain
effect.

The lifecycle must remain provider- and deployment-neutral. No production
strategy artifact, executable, environment, account assignment, or launch
policy has been approved by this decision. The existing invocation already
binds those facts, and the actual runner remains an injected port.

## Decision

1. Before calling a strategy runner, commit one immutable claim for the exact
   `StrategyInvocation` under the current account fence. The claim binds the
   canonical invocation payload and digest, exact claim-time lease revision,
   account-fence receipt, trusted claim time, lease validity bound, and a fixed
   recovery instant. Acquire the shared account serialization lock before
   sampling the trusted claim time, then revalidate the fence and authenticate
   the complete current operational-control history under that lock. Require
   the exact control head to be `RUNNING` before a previously unseen invocation
   can commit a claim. Absent, corrupt, `PAUSED`, `DRAINING`, `FLATTENING`, or
   `HALTED` control evidence fails before both the claim write and runner
   effect.
2. Require the claim-time lease receipt to remain valid strictly beyond the
   complete recovery window. The window is nine seconds: a one-second strict
   child-start interval, the existing five-second hard subprocess deadline, and
   one aggregate three-second budget shared by process-group termination,
   process wait, pipe closure, and all reader/writer thread joins. An invocation
   whose current lease cannot cover that window is not ready to start.
3. Return `new` only as a process-local winning-claim envelope created after
   the claim transaction commits. Its opaque start permit is bound to the
   issuing repository instance and process, is not recoverable from durable
   claim facts, and is consumed under a lock before any fallible authorization
   operation. A copied caller, competing repository, concurrent consumer,
   retained claim, or second use cannot obtain start authority.
4. Treat the consumed permit as eligibility for one fresh start authorization,
   not as an indefinitely usable launch capability. Reacquire account
   serialization, resample trusted time, revalidate the exact claim fence,
   reload the claim, and require `RUNNING` control. The sealed authorization
   retains a second atomic one-shot use state bound to the same issuing
   repository identity and process. Authorization must complete strictly before
   the one-second start deadline. Missing that deadline or consuming the
   authorization without completing the runner sacrifices all launch authority
   and leaves the claim pending for recovery. At or after the nine-second
   recovery instant, the authorizer atomically records the deterministic
   interruption result and returns `final`, without calling the runner.
5. Require the bounded local runner to receive the repository-issued sealed
   authorization through its configured adapter; direct construction is
   invalid. It atomically consumes the sealed authorization before batch/runtime
   validation, bounded request encoding, clock reads, or process creation; a
   concurrent or later second use fails before `Popen`. It then samples its
   process-start timestamp and re-enforces the strict authorization window
   immediately before `Popen`. At that same boundary it derives one absolute
   monotonic deadline eight seconds later: the five-second decision interval
   and three-second cleanup interval never overlap and cleanup never receives a
   fresh budget. Every normal, exceptional, and partial-launch cleanup path
   uses that same deadline. Process-started results use the pre-spawn instant.
   A slow encoder, delayed caller, equality with the strict start deadline, or
   replayed authorization therefore cannot launch a child.
6. Loading the same unfinished claim returns `pending`, never `new`. A restart,
   concurrent caller, lost response, changed fence, or exact retry therefore
   cannot authorize a second subprocess start. Look up retained claims before
   applying the new-claim `RUNNING` gate: an authenticated `PAUSED` or `HALTED`
   head must not deadlock orphan recovery, timely result finalization, or an
   exact final-result retry. Those paths still require the caller's current
   fence and never grant runner authority.
7. Invoke only an injected runner port with the already-bound invocation and
   sealed market batch. This lifecycle selects no executable, artifact,
   deployment, strategy version, configuration, or ambient environment and has
   no broker, order, risk, reservation, dispatch, re-arm, or control-command
   port.
8. Accept only an exact result for the claimed invocation whose observed start
   and completion fit within the claim window. Atomically insert the immutable
   claim-finalization link with ADR 0077's existing durable result,
   operational-control transition, and source-idempotent critical-alert
   incident. A partial result, breaker, incident, or finalization link cannot
   commit.
9. Once either lifecycle table is present, reject the legacy public
   strategy-supervision writer before any result, control, or incident
   mutation. Only the lifecycle repository's process-private authority token
   may enter the transaction-scoped writer, so every new result must have one
   exact claim and atomic finalization link.
10. Exact retries authenticate and return the retained final result. A changed
   invocation, result, claim payload, normalized column, digest, lease
   reference, result reference, or finalization link conflicts and fails
   closed.
11. Never automatically rerun an orphaned claim. Before the fixed recovery
   instant, recovery returns the same `pending` state. At or after equality, it
   revalidates the caller's current account fence and atomically classifies the
   claim with the existing `crash` outcome and deterministic detail code
   `supervisor_interrupted_after_durable_claim`.
12. Expose orphan discovery only as bounded, repeatable-snapshot pages of at
    most 256 authenticated unfinished claims. Select claims due at or before
    the caller's trusted cutoff and order them by `(recoverable_at, claim_id)`.
    Back that order with the lifecycle recovery index. The exclusive resume
    cursor binds exactly to the returned page tip.
13. The interruption result claims only what durable evidence proves:
   `process_started=false` means no process-start observation survived the
   lifecycle boundary; it does not assert that no child ever existed. The
   result carries no exit status, empty stdout/stderr digests, and no accepted
   response. Its timestamps and elapsed duration derive solely from the
   immutable claim, so every recovery caller produces the same result.
14. A recovered crash applies ADR 0077 unchanged. It requests `PAUSED`, cannot
   lower a stronger control state, cannot request `RUNNING`, creates the exact
   source-idempotent critical incident, and never authorizes automatic re-arm.
   The five existing supervision outcomes remain the complete outcome set.
15. Startup integrity verifies every claim and finalization link together with
    their lease, result, control, and critical-alert histories. Orphan results
    in the lifecycle path, finalization links without exact claims/results, and
    tampered canonical payloads block readiness. Development downgrade refuses
    nonempty lifecycle history. PostgreSQL upgrade locks the legacy result
    table across the empty-history cutover; downgrade locks results, claims, and
    finalizations across the emptiness checks and schema removal.

## Consequences

The subprocess effect now has a durable precondition. Crashes at claim,
spawn, result, and record boundaries converge either on the retained exact
result or on one deterministic fail-closed interruption result, without a
second subprocess call. Result, control, alert, and lifecycle finalization
remain one transaction. Operational control now closes the launch boundary:
only `RUNNING` can create a runner-authorizing claim, while stronger control
states continue to admit the retained lifecycle work needed to classify and
record an already-claimed effect.

The nine-second recovery instant does not prove that arbitrary hostile code
has terminated. Safety depends on ADR 0075's bounded local runner and on the
strategy child having no broker, risk, order, or control capabilities through
this lifecycle. Stronger operating-system containment and signed deployment
admission remain separate work before untrusted strategies can run.

This decision does not choose a production artifact or enable a strategy
deployment. It also does not convert an accepted child response into a target,
risk decision, reservation, order, or broker authority.
