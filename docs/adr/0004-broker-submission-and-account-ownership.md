# ADR 0004: broker submission and account ownership

- Status: Accepted
- Date: 2026-07-15

## Context

A PostgreSQL transaction and broker HTTP call cannot commit atomically. Network
timeouts can leave broker acceptance unknown, and overlapping trader processes
can create split-brain submissions.

## Decision

One account coordinator owns a renewable lease and monotonically increasing
fencing generation. It revalidates ownership before each broker side effect.
Because the broker cannot enforce the fence, automatic failover is disabled;
manual takeover requires lease expiry, an in-flight safety interval, prior
process stop confirmation where possible, reconciliation, and human re-arm.

Each logical order has a deterministic client ID, immutable payload hash,
single-use reservation, and immutable submission attempts. An ambiguous call
enters `UNKNOWN`; recovery queries by the same client ID and never blindly
resubmits. Provider events pass through a deduplicating inbox. Startup and
reconnect require a convergent stream/snapshot reconciliation barrier.

## Consequences

Adapters must prove lookup, pagination, lifecycle mapping, rate-budget, and
reconciliation behavior before live eligibility. The v1 broker account is
application-exclusive; unexplained manual activity halts new exposure.
