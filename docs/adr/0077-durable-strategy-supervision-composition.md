# ADR 0077: durable strategy-supervision composition

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0075 defines the bounded one-shot subprocess and its non-authorizing
result. A process-local result is insufficient after restart: a crash could
lose the observation, a failure could be retained without its operational
breaker, or a breaker could exist without a critical-alert incident. A
successful child also must never be interpreted as authority to lower an
existing control state.

## Decision

1. Persist each exact invocation/result pair once under the current account
   fence. The record binds the exact lease revision, pre-transition control
   head, final control transition, trusted record time, canonical invocation
   and result payloads, and a persistence-envelope digest.
2. Serialize through the shared account lease-head lock and authenticate the
   complete lease and operational-control histories on every read. Exact
   retries return the retained record; a changed result, fence, payload,
   normalized column, digest, or referenced history fails closed.
3. A `completed` result leaves the control head byte-for-byte unchanged and
   creates no critical alert. It carries no `RUNNING` or re-arm authority.
4. Every non-completed result appends the deterministic Phase 5A
   circuit-breaker command immediately after the observed pre-transition head.
   Higher-severity precedence remains intact, so a PAUSED request cannot lower
   DRAINING, FLATTENING, or HALTED.
5. The same transaction records a source-idempotent critical-alert incident
   bound to the failed result and final control transition. Its detection time
   is the subprocess completion time, its record time is the repository's
   trusted time, and its payload contains only identifiers and digests. The
   incident explicitly reports whether the one-second local durability
   milestone was met.
6. The supervision row references the exact incident for failures and forbids
   one for success. Failure of the supervision insert rolls back the breaker
   transition and alert incident together.
7. Startup readiness authenticates every supervision row in the same stable
   database snapshot used for the other immutable operational histories.
   Downgrade refuses nonempty supervision history.

## Consequences

Restart can reconstruct whether an invocation completed, which exact control
effect accompanied it, and which alert incident was durably opened. There is
no interval in which one of those failure facts commits without the others.
The protected order, risk, broker-event, cancel, and reconciliation loops are
unchanged and continue operating at the resulting control severity.

This composition still selects no strategy deployment, executable artifact,
alert provider, recipient, or escalation roster. Those deployment choices
remain separate approval-gated configuration. A critical-alert incident is
durable evidence, not proof that an external operator received it.
