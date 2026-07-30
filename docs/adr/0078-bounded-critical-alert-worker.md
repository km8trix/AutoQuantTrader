# ADR 0078: bounded provider-neutral critical-alert worker

- Status: Accepted; control-binding decisions 9-10 superseded by ADR 0085
- Date: 2026-07-28

## Context

ADR 0072 records source-idempotent incidents and claim-before-effect delivery
evidence, but it deliberately leaves provider selection and worker operation
open. A usable local orchestration boundary must find durable work without an
unbounded table walk, preserve the strict 15- and 30-second milestones, and
never turn a crash-uncertain provider call into an automatic resend.

The owner has not selected either delivery provider, any destination or
recipient, an escalation roster, or secret references. At the time of this
decision the local response to complete delivery failure was also undecided.
ADR 0085 later fixes the only local failure-control composition to
severity-preserving `PAUSED`, without activating that composition in a
deployment.

## Decision

1. Require one exact injected route plan with a plan ID/version and explicit
   primary and escalation bindings. Each binding contains a provider ID plus
   opaque destination and recipient-set digests, never raw credentials or
   recipients. Provider IDs must be distinct, but distinct IDs do not prove
   operational independence.
2. Derive each provider idempotency key from the immutable incident, exact
   route-plan digest, and route binding. Every retained attempt must reproduce
   that provider, key, and provider-request digest. A repeated route, foreign
   plan, early escalation, late primary, or non-primary-first two-route history
   fails closed.
3. Scan existing incident, attempt, and result tables in
   `(recorded_at, incident_id)` order. Each page inspects at most 256 incidents
   plus one lookahead row and returns an explicit resume cursor. Histories in
   the bounded segment are decoded and authenticated before an incident is
   returned as active. An in-budget confirmed result closes the incident for
   worker scanning; a late confirmation does not.
4. Require callers to follow `resume_after` until it is absent. This lets a
   prefix of already delivered incidents be crossed without an unbounded query
   or starvation of later active work. The existing schema is sufficient for
   correctness; an additional index would only be a measured performance
   optimization.
5. Reload and authenticate the complete incident history before reading trusted
   time or resolving an adapter. Reject clock rollback behind durable history.
   Before the strict 15-second boundary, only primary may be selected. A
   terminal primary failure or unresolved primary claim remains no-I/O `WAIT`
   evidence until that boundary. At equality, select escalation. An unresolved
   escalation remains no-I/O `WAIT` before 30 seconds and becomes total failure
   at equality; a terminal escalation failure is total failure immediately.
6. Keep the supervisor and worker single-step. One incident invocation performs
   at most one provider call and contains no polling, sleep, resend, or restart
   loop. Bind lazy ports to the approved provider IDs, but resolve only the
   route the supervisor actually selects. A missing, throwing, or malformed
   selected adapter fails with a sanitized unavailable reason. The preceding
   claim remains unresolved, so restart cannot turn adapter or provider
   uncertainty into a resend. WAIT, confirmed, and terminal retained histories
   resolve no adapter.
7. Continue to use `deliver_critical_alert`, so the durable attempt claim
   precedes provider I/O and concurrent workers converge on the winning claim.
   A route with an unresolved claim is never resolved or sent again before its
   deadline; after the deadline it is failure evidence, not resend permission.
8. Derive total-delivery-failure evidence only when neither route has an
   in-budget confirmation and both are exhausted. Its determination time is
   canonical: the later of the two immutable terminal-failure times or fixed
   route deadlines. Missing or unresolved delivery at a deadline is therefore
   explicit evidence without fabricating a provider receipt.
9. Put operational-control selection behind two injected boundaries: an
   explicit total-failure policy binder and the existing durable control
   writer. The binder must produce an exact `TRIP` command bound to the
   incident scope, stable failure idempotency key, failure digest, rule ID, and
   its own policy digest. The application accepts the domain's permitted
   `PAUSED` or `HALTED` result but selects neither. **Superseded by ADR 0085:**
   the split binder/writer seam is retired and always fails unavailable when
   total failure is reached.
10. Validate the pure policy command before calling the control writer, then
   authenticate the returned transition against that exact command. Missing or
   invalid policy and missing or failing writer are unavailable states. With
   no explicitly injected approved policy, no operational-control write is
   attempted. The existing operational-control transition is the atomic durable
   binding of failure, policy, actor, and target-state digests; no second alert
   receipt or schema migration is needed. Every worker projection remains
   non-authorizing for broker action. **Superseded by ADR 0085 and migration
   0032:** only the same-store atomic repository may append the fixed local
   `PAUSED` transition and its source receipt in one transaction.

## Consequences

The repository supports deterministic bounded active scans, and the local
worker layers around the strict route-plan supervisor instead of redefining
it. Deterministic tests cover bounded pagination,
selected-route-only adapter resolution, primary failure waiting until the
fixed escalation boundary, both deadline equalities, unresolved-claim restart,
stable total-failure identity, durable provider failure, absent-policy
no-control behavior, and explicit historical test policy bindings. ADR 0085
supplies the later atomic fixed-`PAUSED` composition and disables this ADR's
legacy split control path.

This is still not a deployed alert service. The following external choices
remain approval-gated:

- primary provider adapter, stable provider ID, destination, recipients, and
  credential or secret references;
- independent escalation provider adapter, destination, recipients,
  escalation roster, and credential or secret references;
- approval to activate the fixed local `PAUSED` total-failure policy, including
  its exact policy digest, circuit-breaker actor, and deployment authority;
- deployment worker ownership, cadence, availability supervision, route-health
  monitoring, and production drill evidence for the one-, 15-, and 30-second
  milestones.

Until those are supplied at the composition root, delivery or control paths
that need them remain unavailable and do not invent effects.
