# Operational control

This runbook describes the Phase 5A durable control contract and the Phase 5F
loopback-only authenticated operations boundary. The local API can append
audited control intents when its durable services are explicitly injected. It
does not execute broker cancellation, drain, flatten, reconciliation, or order
actions, and it is not a remote, paper, or live control plane.

## Severity and permissions

The fixed severity order is:

```text
RUNNING < PAUSED < DRAINING < FLATTENING < HALTED
```

Every command except re-arm preserves the higher of the requested and current
states. Missing, unreadable, or corrupt control evidence blocks new exposure and
must never be interpreted as `RUNNING`.

| State | Operator meaning |
|---|---|
| `RUNNING` | New exposure may proceed only through all other readiness, risk, and dispatch gates. |
| `PAUSED` | Block new exposure; keep cancellation, reconciliation, and separately authorized reduce-only handling available. |
| `DRAINING` | Block new exposure and drive working orders to terminal state; positions may remain. |
| `FLATTENING` | Block new exposure and use only the dedicated flatten policy while repeatedly reconciling toward zero. |
| `HALTED` | Block strategy submissions; retain cancellation, reconciliation, and separately authenticated emergency handling. |

## Local authenticated surface

The operations API is mounted under `/api/v1/operations`:

```text
GET   /api/v1/operations/accounts/{account_id}
POST  /api/v1/operations/accounts/{account_id}/control/{action}
POST  /api/v1/operations/accounts/{account_id}/advanced-risk-assignment
```

Every account read and control request requires the signed local-operator
cookie and matching CSRF header. Mutations additionally require a new
`Idempotency-Key`. The request body contains only `reason_code`; client-supplied
readiness, reconciliation, order, blocker, completion, fence, or re-arm proof
fields are rejected.

The assignment route is conditional. It is absent unless the server has an
injected approved-policy assignment service and current-fence authority.
Likewise, missing operations query/control services return a sanitized
unavailable response rather than fabricated state. Durable persistence
readiness is required before any account operation.

`GET /api/v1/operations/dashboard` is a separate, GET-only observational
snapshot. Its current adapter shows deterministic walking-thread data and marks
missing coordinator, reconciliation, alert, and control authorities
unavailable. It requires the same signed local-operator cookie, matching CSRF
header, loopback transport, and durable readiness as the other operations
reads. The snapshot itself has no control or broker action. The browser renders
a separate fail-safe command panel that consumes the authenticated account
overview and only the granular `control_pause`/`control_halt` capability flags.
Development fixture fallback cannot enable that panel.

## Issuing a control

1. Confirm the environment and exact account.
2. Choose the least ambiguous safe action. The current durable local
   composition and browser client expose only `PAUSE` and `HALT`; stale or
   unavailable display evidence does not hide an advertised fail-safe command.
3. Authenticate through the loopback local-operator session and matching CSRF
   value.
4. Supply a bounded reason and create one actor-scoped idempotency key for the
   exact account/action intent. HALT requires the stronger typed confirmation.
5. Send only `pause` or `halt` to the exact account. The browser has no drain,
   flatten, re-arm, assignment, initialization, or broker route.
6. Retain the immutable command receipt.
7. If a network, `5xx`, or malformed/mismatched success leaves the outcome
   ambiguous, retry only by explicit operator action with the exact same key
   and body. A distinct intent gets a distinct key.
8. After a confirmed result, reload the authenticated account overview. A
   retried receipt is historical and does not replace a current-head read.
9. Run the separately authorized broker-side workflow, if one exists. The
   local command route itself does not cancel, drain, flatten, reconcile, or
   submit.
10. If the durable store is unavailable, assume new exposure is blocked and use
   the independent broker dashboard/manual channel as required.

A lower-severity command cannot weaken a stronger state. A same-state or
lower-severity request may therefore be durably audited without changing the
effective head.

## Drain and flatten results

Do not infer completion from a command or elapsed time.

- Drain is complete only after all orders are terminal and two-pass
  reconciliation is clean. Report retained positions and exposure.
- Flatten is complete only with zero unresolved orders and zero residual
  positions/exposure.
- Closed, halted, or illiquid markets, deadline expiry, broker uncertainty, and
  any other incomplete outcome must retain an explicit reason and residual or
  unresolved facts.

Recording a result does not resume the account. If an incomplete or
deadline-ended drain/flatten is retried, open a new explicit operation attempt
and retain the earlier result. Unrelated no-op controls must not replace that
active attempt.

## Manual re-arm

Never re-arm from a timer, health recovery, breaker reset, process restart, or
caller assertion. Re-arm requires all of the following:

1. the exact current non-running control head;
2. an authenticated human action;
3. a current readiness result and healthy data/clock;
4. authoritative clean reconciliation;
5. disposition of every outstanding blocker;
6. zero unknown, working, and pending-cancel orders;
7. for `DRAINING`, its exact completed drain result;
8. for `FLATTENING`, its exact zero-exposure completion result.

The current Phase 4 comparisons are historical and explicitly unqualified, so
they cannot satisfy these prerequisites. The authenticated service accepts a
`rearm` intent only when an injected server-side verifier returns the exact
fresh facts above. The browser cannot construct that proof. The dedicated SQL
path reacquires the account lock, authenticates the complete history and
current head, rebinds any required drain/flatten completion, and compare-and-
set updates the head. A concurrent/stale head, expired proof, incomplete fact,
or conflicting retry fails closed.

The ordinary repository `apply` path still rejects every raw `REARM`, including
one carrying a syntactically valid digest. If no authoritative verifier is
composed, the authenticated `rearm` request is rejected without a write.
Replaying a retained receipt never substitutes for re-authorizing its current
source facts.

## Strategy-supervision failures

Treat creation of a new durable strategy-invocation claim as a strategy
submission. The claim transaction must authenticate an exact current
`RUNNING` head; `PAUSED`, `DRAINING`, `FLATTENING`, `HALTED`, absent, or corrupt
control evidence must produce neither a claim nor a child-process call. This
gate does not suppress retained lifecycle handling: a claim created while
`RUNNING` may still accept its timely exact result, recover an orphan, and
return a retained final result after the account becomes non-running. Those
paths never rerun the strategy. Cancellation, reconciliation, broker-event,
and separately authorized reduce-only loops remain outside this launch gate.

Only the caller that receives the post-commit `new` envelope may request a
start authorization. Its opaque permit is bound to that repository instance
and process, is consumed before fence, clock, SQL, or control checks, and is
never persisted or reissued. Call start authorization immediately: it
reacquires account serialization, revalidates the current claim fence, and
requires the current head still to be `RUNNING`. The sealed authorization must
reach the configured subprocess runner strictly before the claim's one-second
start deadline. A failed check, process restart, competing caller, retained
claim, or second use sacrifices start authority; do not mint a replacement or
manually call the low-level runner.

The runner measures one absolute monotonic interval from its final pre-spawn
boundary: five seconds for decision and the remainder through eight seconds
for process-group termination and pipe/thread cleanup. Cleanup never starts a
fresh three-second clock. An unfinished claim remains pending until its
nine-second recovery instant (one-second start window plus five-second
decision plus three-second cleanup), when current-fence recovery records the
deterministic interruption result without launching a child. In that result,
`process_started=false` means no start observation survived durably; it is not
proof that a child never existed.

The supervised strategy runner records one of `completed`, `timeout`, `crash`,
`protocol_error`, or `resource_exceeded`. A completed result leaves the
operational head unchanged and never resumes the account. Every non-completed
result is committed under the current account fence together with:

- a deterministic breaker command requesting `PAUSED`, while preserving any
  stronger state; and
- one source-idempotent critical-alert incident.

Those three facts commit or roll back together. The protected order, risk,
broker-event, cancel, and reconciliation loops remain outside the child
strategy process and must continue at the resulting control severity. After a
failure, investigate the retained sanitized result and use only the manual
re-arm procedure above; process restart or a later successful strategy call is
not re-arm authority.

## Critical-alert boundary

An alert incident is durable evidence, not confirmation that an operator
received a message. External delivery claims are recorded before provider I/O,
and an unresolved claim is never automatically resent after restart. Primary
and escalation are abstract route classes until deployment configuration
selects independent providers/routes and recipients.

Before relying on alerts operationally, the owner must approve the primary and
fallback providers, destinations, recipients, escalation roster, secret
references, and channel probes. The deployment must also compose and test the
separate policy that blocks new exposure after total alert-delivery failure.
Until then, use direct operator observation and the independent broker
dashboard as the fallback; do not treat the local incident table as delivery
proof.
