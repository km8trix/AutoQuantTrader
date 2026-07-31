# ADR 0072: durable provider-neutral critical-alert delivery

- Status: Accepted
- Date: 2026-07-28

## Context

The operational baseline requires a critical event to be durably enqueued
within one second, primary delivery to be confirmed within 15 seconds, and an
independent fallback to be confirmed within 30 seconds. A process-local send
does not prove any of those milestones. Retrying an uncertain send can also
duplicate an operator notification, while treating a transport return as
durable can lose the only evidence after a crash.

The concrete primary and fallback providers, route identifiers, recipients,
escalation roster, and secret references are deployment decisions that the
owner has not supplied. This slice therefore needs to preserve the timing and
durability contract without inventing a production route or claiming that
alert failure already changes account control state.

## Decision

1. Represent each critical incident as an immutable, source-idempotent fact
   bound to scope, source, idempotency key, alert code, evidence digest,
   detection time, repository recording time, and tracing correlation digest.
   Raw evidence, provider responses, message bodies, credentials, and recipient
   data are not accepted by the durable contract.
2. Measure the initial operational baseline exactly. Local durability is met
   when recording occurs no later than one second after detection. Primary and
   escalation confirmation must occur strictly before 15- and 30-second
   deadlines respectively; equality misses. Delivery success must satisfy both
   the UTC deadline and the corresponding monotonic elapsed-time bound.
3. Keep `PRIMARY` and `ESCALATION` as abstract route classes. A provider adapter
   receives only bounded identifiers and digests plus a provider-scoped
   idempotency key. Selecting an actual provider, destination, recipient,
   fallback channel, or escalation roster remains approval-gated deployment
   configuration.
4. Persist a delivery-attempt claim before external I/O. Attempts form a
   gap-free predecessor-authenticated incident-local chain, and each attempt
   can have at most one immutable terminal result: confirmed with only a
   receipt digest, or timeout/error with only a sanitized failure code. No
   database transaction spans provider I/O.
5. Treat the provider request identity, not the caller's race-dependent time
   sample, as the same-key retry boundary. Concurrent callers using the same
   incident, provider, route, key, and request digest converge on the winning
   attempt; a changed route or request digest conflicts. The winner's requested
   and claimed times remain the immutable audit times.
6. Never resend a claimed attempt whose terminal result is absent. An exact
   restart retry returns the unresolved claim. A new attempt requires a new
   explicit provider key. Escalation becomes eligible after a primary failure
   or the primary deadline, while any already confirmed in-budget route blocks
   a new automatic send.
7. Store incidents, claims, and results in the central operational schema under
   revision 0027. Startup readiness decodes every canonical payload, verifies
   source idempotency, predecessor order, command and semantic digests, terminal
   result linkage, and orphan absence. Empty tables may be removed during a
   development downgrade; nonempty alert history refuses downgrade.
8. Keep every incident, attempt, result, and delivery-run projection
   non-authorizing. This slice requests no control state and grants no broker
   action. In particular, missing both deadlines does not itself write the
   operational-control transition required by the baseline; that later
   composition must bind the exact alert evidence and durable control head.

## Consequences

Critical-alert delivery now has restart-safe local evidence, bounded sanitized
provider inputs, explicit timing semantics, concurrency-safe same-key claims,
and readiness-integrated corruption detection. Provider exceptions and raw
receipts cannot enter durable state, and an uncertain crash cannot silently
become a resend.

The implementation is not a deployed alerting system. It does not choose or
authenticate a primary/fallback provider, define recipients, render message
content, resolve secrets, operate a worker, probe channel health, write a
control transition after a 30-second failure, or prove a timed production
drill. Those items and the actual route/escalation configuration remain open
Phase 5 approval and deployment work.
