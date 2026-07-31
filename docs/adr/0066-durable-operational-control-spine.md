# ADR 0066: durable operational-control spine

- Status: Accepted
- Date: 2026-07-28

## Context

The architecture defines five account control states and requires the
higher-severity state to win, but the implemented batch-risk contract recognizes
only `RUNNING`, `PAUSED`, and `HALTED`. There is no durable command history for
pause, drain, flatten, halt, breaker trips, completion reports, or manual
re-arm. Treating a missing row as running, clearing a recovered breaker
automatically, or accepting caller-asserted completion would each create a path
to new exposure without durable operational evidence.

Drain and flatten also have materially different outcomes. Drain may complete
with positions still open after every order is terminal and reconciliation is
clean. Flatten cannot promise zero exposure when a market is closed, halted, or
illiquid, so its terminal evidence must distinguish a verified zero result from
an incomplete result with explicit residual exposure.

Phase 4 does not yet produce authoritative reconciliation or canonical paper
account state. Phase 5A must therefore establish a durable, fail-closed control
foundation without presenting historical Phase 4 comparisons as re-arm
authority, invoking broker effects, or changing the existing batch-risk
decision vocabulary.

## Decision

1. Define the versioned Phase 5A operational-control contract with the strict
   severity order
   `RUNNING < PAUSED < DRAINING < FLATTENING < HALTED`. Except for re-arm, a
   command joins its requested state with the current state, so concurrent or
   stale lower-severity commands cannot weaken a stronger control. Same-state
   and lower-severity requests remain immutable audit facts even when they do
   not change the effective state.
2. Bind every command to an account, actor identity, actor-scoped idempotency
   key, action, reason/evidence material, and trusted recording time. An exact
   retry returns the original historical receipt. Reusing the same account,
   actor, and key for different request semantics is an immutable-fact
   conflict. A historical receipt describes the result of that command; callers
   reload the authenticated head when they need current state.
3. Keep absence explicit at the repository boundary. Missing or corrupt control
   evidence never means `RUNNING`; risk compatibility treats it as `HALTED`.
   The first durable account event initializes a `HALTED` state. Migration does
   not backfill existing accounts into a permissive state, and process restart
   never implies resume.
4. Record circuit-breaker trips through the same durable command boundary.
   Breakers may request only a no-new-exposure state and higher severity still
   wins. A recovery observation may be retained as evidence, but it cannot
   lower state. No timeout, health recovery, breaker reset, process restart, or
   exact retry auto-resumes an account.
5. Make manual re-arm the only operation that can lower state, and only to
   `RUNNING`. Re-arm binds the exact current head, an authenticated human actor,
   a current readiness result, clean reconciliation, dispositions for every
   outstanding blocker, and zero unknown, working, and pending-cancel orders.
   `DRAINING` additionally requires the exact terminal drain result;
   `FLATTENING` requires a terminal zero-exposure flatten result. Evidence is
   checked at the repository's trusted time and equality with an expiry never
   grants authority. Until an authoritative readiness and reconciliation
   verifier is composed, re-arm remains unavailable rather than accepting
   caller-supplied hashes or booleans.
   Revision 0025 can retain the immutable decision receipt emitted by a future
   authoritative verifier so the schema need not be replaced when that
   composition arrives. Phase 5A's public SQL repository nevertheless rejects
   every re-arm before reading the clock or writing SQL. History replay
   authenticates a stored receipt's exact human actor, target, digest, prior
   head, and state change; it never re-authorizes the unavailable source facts.
6. Retain drain and flatten results as immutable operation-scoped facts.
   Results bind their initiating state epoch, source evidence, terminal order
   counts, and canonically ordered residual positions/exposure. Drain completion
   requires terminal orders plus clean two-pass reconciliation and reports any
   retained positions. Flatten completion requires zero terminal-order
   uncertainty and zero residual position/exposure. An incomplete or deadline
   outcome requires an explicit reason and residual or unresolved facts. A
   result is observational evidence; recording one performs no cancel,
   reduce-only, reconciliation, or broker call and never resumes the account.
   Retrying an incomplete or deadline result requires a new explicit
   drain/flatten command and a distinct operation-attempt identity even though
   effective severity is unchanged. Unrelated same-state, lower-severity, or
   breaker no-op events never replace the active operation attempt. Aggregate
   residual exposure uses the pinned, ambient-context-independent decimal
   arithmetic policy and a bounded `NUMERIC(32, 10)` projection.
7. Preserve the Phase 2 batch-risk vocabulary and semantic material. The
   compatibility projection maps durable `RUNNING` to batch-risk `RUNNING`,
   `PAUSED`, `DRAINING`, and `FLATTENING` to batch-risk `PAUSED`, and `HALTED`,
   or explicit absence to batch-risk `HALTED`. Unreadable or corrupt evidence
   raises and every authorization caller must deny rather than fabricate a
   state. This local mapping does not yet compose the durable head into every
   authorization and dispatch transaction.
8. Persist a gap-free, predecessor-linked account transition history and an
   authenticated current-head cache under the existing account serialization
   lock. Completion and residual facts retain exact transition scope rather
   than mutating prior events. Reads and startup verification reconstruct
   canonical values, replay precedence, and reject gaps, forks, substitutions,
   rollback, malformed idempotency, orphaned completion facts, or a head that
   disagrees with history. Transition and head updates commit atomically; no
   database transaction spans external I/O. The durable current-head projection
   retains at most 2,048 exact open blockers. Overflow drops only the oldest
   projected member after its immutable event remains durable, sets a sticky
   overflow flag, and keeps accepting stronger controls; re-arm remains
   unavailable until an authoritative verifier disposes the complete durable
   history.
9. Revision 0025 is additive. Empty operational-control tables may be removed
   during a development downgrade; nonempty durable history refuses downgrade
   rather than silently destroying operator or breaker evidence.

## Consequences

Phase 5A provides a durable local state machine, actor-bound exact-retry
commands, fail-closed risk compatibility, explicit breaker behavior, and
typed drain/flatten outcomes. Severity races have a deterministic result and
cannot produce an accidental downgrade. Operators can distinguish a durable
halt from missing or corrupt evidence, and an incomplete flatten remains
visible instead of being reported as success.

This slice does not authenticate a browser user, expose a control API, send an
alert, supervise a strategy process, call or cancel at the broker, execute
drain/flatten, produce authoritative reconciliation, or wire control state into
every risk and dispatch boundary. The existing Phase 4 views remain
non-authorizing and cannot satisfy re-arm. All paper/live startup and Phase 5
exit gates remain open.
