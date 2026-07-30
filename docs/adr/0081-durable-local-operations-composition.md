# ADR 0081: durable local operations composition

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0073 defined an authenticated local operations transport but left its query
and command services injectable. The normal API composition therefore reported
those capabilities as unavailable even when the durable schema was ready.
Wiring arbitrary table serialization would expose authority material, while
turning every Phase 5A command on would imply drain, flatten, and re-arm
capabilities that the process does not possess.

## Decision

When and only when the durable schema verifies and local authentication is
loopback-scoped, the API composes:

1. A bounded `SqlLocalOperationsSnapshotReader`. It authenticates coordinator
   history, the operational-control head and retained history, the current
   advanced-risk assignment and latest assessment, and active critical-alert
   delivery histories inside one repeatable-read transaction. Source counts
   are bounded and overflow fails closed. Facts later than the exact UTC
   snapshot time, malformed canonical facts, cross-account identities, and
   inconsistent heads fail the whole view.
2. An allowlisted HTTP projection. It returns only fields in
   `OperationsOverviewResponse`; canonical payloads, lease IDs, authority and
   evidence digests outside that contract, provider receipts, raw payloads, and
   secrets are never serialized.
3. A database-only authenticated command service over the exact same SQL
   engine. It accepts only `PAUSE` and `HALT`, preserves actor-scoped
   idempotency and the severity join, and never creates initial account control.
   `DRAIN`, `FLATTEN`, and `REARM` remain unavailable because no operation
   executor or authoritative re-arm verifier is composed. No command invokes a
   broker.
4. Granular bootstrap flags for the operations query and each command.
   `control_pause` and `control_halt` are true for this composition;
   `control_drain`, `control_flatten`, and `control_rearm` are false. The legacy
   generic `controls` flag remains false because the complete control surface is
   not available.

The overview never fabricates trading readiness. Even with healthy retained
facts, authoritative reconciliation readiness is not composed, so readiness
remains `NOT_READY` (or `HALTED` when the durable control head is halted) and
states that reconciliation readiness is unavailable.

## Consequences

The default durable local API now exposes a production-safe observational
snapshot plus audited PAUSE/HALT commands without gaining broker, executor,
initialization, or downgrade authority. Ephemeral, unmigrated, remotely scoped,
or unauthenticated startup composes neither service. Adding drain/flatten
execution or re-arm remains a separate explicit capability decision with its
own authoritative adapters and tests.

This decision adds no schema or migration.
