# ADR 0085: atomic local critical-alert worker composition

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0078 added a bounded provider-neutral critical-alert worker with an
explicitly injected control-policy and control-writer seam. Migration 0032's
Phase 5D failure-control persistence subsequently made the local response
stricter: one repository reauthenticates the complete alert history,
severity-joins a fixed `PAUSED` trip with the operational-control head, and
appends the source receipt in the same transaction.

Leaving a new runtime composition on the older split policy/writer seam would
permit a control transition without its failure receipt. Composing the two SQL
repositories without proving they share one store would also permit the scan
and control transaction to observe different durable histories. Finally, raw
supervisor observations are not stable retry identities because their
`observed_at` value advances with the process clock.

## Decision

Add the local, deliberately unwired
`phase5d-atomic-critical-alert-worker-v1` composition.

Before reading a clock, scanning incidents, resolving an adapter, calling a
provider, or binding control, it requires:

1. one exact injected primary/escalation route plan;
2. one complete bounded active-incident repository;
3. one credential-owning route resolver with no defaults;
4. the fixed-policy atomic failure-control binder; and
5. positive, identical process-local store identities for the alert repository
   and failure-control binder.

The binder also exposes only its route-plan and fixed-policy digests so a
different plan or policy fails before any effect.

Each active incident is reloaded and authenticated before the existing strict
single-step supervisor runs. Confirmed, waiting, and primary-failed outcomes
never call failure control. A provider-called terminal outcome also never
binds control in the same invocation: its durable result must first be replayed
with `provider_called=false`.

A replay-derived terminal escalation failure becomes eligible immediately at
the latest authenticated incident, claim, or result time. An unresolved
escalation claim becomes eligible only at or after the escalation deadline.
The binding observation is canonicalized to that earliest durable eligible
instant, so later process-clock samples produce the same evidence and exact
retries converge on one 0032 receipt. Deadline equality is terminal: a
confirmation completed exactly at or after the exclusive delivery deadline
does not suppress total-failure control.

Adapter discovery and boundary failures expose allowlisted unavailable reason
codes without raw exception text. Authenticated-history and returned-receipt
identity corruption remains an explicit conflict. The public composition has
no split policy/writer arguments.

Operational-control persistence reserves the fixed alert-failure actor,
reason, rule, policy digest, and idempotency namespace. Public repository
append, the raw transaction helper, and authenticated re-arm reject any full
or partial claim on that namespace. Only the atomic binder can issue a sealed
append capability, and that capability is bound by object identity to the
exact active connection transaction, validated receipt and digest, command
digest, decision time, and durable predecessor head. A fake, stale,
cross-transaction, changed-command, or changed-head capability writes nothing.

The older ADR 0078 worker remains available for bounded delivery and evidence
replay, but its split control-policy/control-writer path is retired. When that
worker derives total failure it now fails with the allowlisted
`atomic_failure_control_required` state before reading either legacy control
port. Only the atomic composition may bind failure control.

## Consequences

The local worker can scan a bounded page, perform at most one provider action
per incident through the existing supervisor, and atomically bind only
replay-authenticated total failures to the fixed local `PAUSED` policy. SQL
concurrency and restart retries converge on one receipt and one associated
control command. Alternate operational-control writers cannot claim the
reserved failure-control namespace or leave an unreceipted command prefix.

This decision adds no provider, route, recipient, credential, deployment, or
schedule defaults. It does not wire a production worker and grants no broker,
fence, re-arm, automatic-resume, flatten, or trading authority. Selecting and
operating real delivery adapters and recipients remains an explicit deployment
approval.

This decision adds no schema or migration.
