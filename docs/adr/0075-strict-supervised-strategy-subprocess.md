# ADR 0075: strict supervised strategy subprocess

- Status: Accepted
- Date: 2026-07-28

## Context

The operational budget gives one strategy decision a two-second warning and a
five-second hard deadline per watermark-complete market batch. A strategy
callback currently runs in the caller's process. A deadlock, crash, unbounded
write, malformed return, or ambient-environment dependency could therefore
block or corrupt the loops that retain orders, apply risk, ingest broker
events, cancel exposure, and reconcile the account.

Strategy failure has a narrower safety meaning than total runtime failure. It
must block new exposure and request `PAUSED`, but it must not stop the machinery
that observes or reduces existing exposure. A recovered child also cannot
lower an existing durable control state. Phase 5A makes authenticated human
re-arm the only future path to `RUNNING`; strategy supervision must preserve
that invariant.

This slice needs a strict local process and protocol boundary before durable
supervision history, deployment management, or an authenticated runtime policy
exists. It must not present a child response as an approved target, a risk
decision, a durable control transition, or paper-trading authority.

## Decision

1. Define one immutable strategy invocation for one watermark-complete
   `MarketBatch`. Its semantic identity binds the control scope, environment,
   exact batch identity/digest/as-of time, strategy identity/version,
   configuration digest, input-state digest, request time, protocol version,
   runtime identity/version, executable-artifact digest, and exact launch-spec
   digest. Reusing a response across any changed input fails identity
   validation.
2. Use a one-request/one-response canonical UTF-8 JSON protocol over stdin and
   stdout. The request carries the complete sealed market batch, canonical
   Decimal strings, and every invocation binding. The response contains
   exactly the protocol version, invocation ID, invocation digest, and an
   opaque result. Duplicate keys, unsupported fields, floats, non-finite
   values, noncanonical whitespace, invalid UTF-8, excessive nesting or node
   count, and mismatched invocation facts are protocol failures. One final LF
   is the only tolerated framing byte.
3. Fix the local resource envelope at:

   - request: at most 1,048,576 bytes;
   - stdout: at most 262,144 bytes;
   - stderr: at most 65,536 bytes;
   - JSON: at most 32 levels and 8,192 nodes;
   - argv: at most 64 items, 4,096 UTF-8 bytes per item, and 16,384 bytes
     total.

   A request that exceeds its bound fails before process creation. Readers
   retain no more than the relevant bound plus one detection byte and terminate
   the child when stdout or stderr exceeds its limit. Raw stderr is not placed
   into domain evidence; the result retains only bounded byte counts and
   digests.
4. Start a fresh process group for each invocation with an absolute executable
   path, `shell=False`, closed inherited descriptors, and pipes for only the
   defined protocol streams. Do not inherit the parent environment. Supply
   only fixed locale, UTC, Python UTF-8, and deterministic hash-seed settings.
   Configuration and identity arrive through authenticated invocation material,
   not ambient environment variables.
5. Measure from invocation start through validated response with an injected
   monotonic clock. Two seconds, inclusive, marks the warning threshold. Five
   seconds, inclusive, is a hard failure. On deadline equality the supervisor
   kills only the invocation's new process group, closes its pipes, waits for
   process and reader cleanup, and records `timeout`. A child is never allowed
   to remain detached after the runner returns.
6. Record exactly five outcomes:

   - `completed`: exit zero and an exact validated response;
   - `timeout`: validation did not finish before the hard deadline;
   - `crash`: creation failed, the process exited nonzero, or supervision I/O
     failed;
   - `protocol_error`: exit zero produced no exact acceptable response;
   - `resource_exceeded`: the request, stdout, or stderr crossed a fixed bound.

   Results bind the exact invocation, UTC start/completion observations,
   monotonic elapsed microseconds, process-start and exit facts, bounded stream
   counts/digests, a fixed detail code, and an accepted response digest only
   for `completed`.
7. Every non-completed outcome blocks new exposure and may request only
   `PAUSED`. The result has no `RUNNING`, `HALTED`, drain, flatten, cancel, or
   re-arm command. The order, risk, broker-event, cancel, and reconciliation
   loops are an explicit protected set and are not dependencies or mutation
   ports of the subprocess runner. Killing a child therefore cannot stop those
   loops through this API.
8. A later `completed` result carries no control-state request. It never
   requests `RUNNING` and never authorizes automatic resume. Durable
   operational control remains at its current severity until the separate
   exact-head, authenticated-human re-arm boundary is implemented and
   satisfied.
9. Treat a child result as opaque, non-authorizing strategy material. Existing
   strategy-transition, `TargetPortfolio`, operational-control, batch-risk,
   reservation, and dispatch validation still must accept and bind any economic
   action. This slice does not bypass or combine those authorities.
10. Keep this slice process-local. Do not add persistence, schema, migration,
    worker registration, deployment policy, broker calls, or a control-state
    write. A later durable supervisor may retain these exact observations and
    translate a failure into an idempotent Phase 5A trip under the account
    lock; it must not reinterpret a historical success as re-arm evidence.

## Consequences

A stuck or malformed strategy can no longer monopolize unbounded protocol
memory or share the parent process's failure domain. Every invocation and
accepted result is replay-identifiable, deadlines use monotonic time, and the
failure action is fail-closed for new exposure without granting the strategy a
way to disable recovery/control work.

The sanitized environment and no-shell launch remove common ambient and command
injection paths. Process-group termination also contains ordinary descendants
of the invocation. The implementation nevertheless is process isolation, not
a complete hostile-code sandbox. It does not yet apply namespaces, containers,
seccomp, filesystem isolation, cgroups, operating-system CPU/RSS limits, signed
artifact loading, or runtime attestation. Deployment admission must add those
controls before untrusted strategy code is allowed.

The byte and JSON limits are versioned protocol facts. Raising them, changing
the warning/deadline, adding protocol fields, or changing launch environment
requires a reviewed contract version rather than an ad hoc runtime override.

No database records or control transitions are created in this slice.
Therefore restart cannot yet recover a supervision observation or prove that a
corresponding `PAUSED` request was durably applied. Paper/live startup and the
Phase 5 exit gate remain open until durable composition, deployment controls,
authoritative control application, telemetry/alerts, and fault drills are
implemented.
