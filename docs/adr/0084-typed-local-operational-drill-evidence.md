# ADR 0084: typed local operational-drill evidence

- Status: Accepted
- Date: 2026-07-28

## Context

The Phase 5 fault-drill catalog identifies the deterministic tests that cover
the repository's safety properties and separately lists deployment drills that
have not run. That catalog prevents a local regression suite from being
presented as external provider, broker, telemetry, or game-day evidence.

Future local drill runners also need a small immutable value contract for one
observed response and a complete six-scenario matrix. Without one, callers
could silently weaken the expected control state, omit a required fault class,
treat unavailable evidence as a failed response, accept a late response, or
describe automatic re-arm as success.

## Decision

Add the pure `phase5h-local-operational-drill-evidence-v1` contract.

One `LocalOperationalDrillCase` binds:

- an exact campaign and account scope;
- one of kill-state, strategy-failure, total-alert-failure, data-gap,
  broker-disconnect, or risk-trip;
- an inclusive, bounded response deadline;
- the minimum expected durable control state; and
- the digest of the local fixture specification.

Every non-kill scenario must expect at least `PAUSED`. Kill-state may retain a
`RUNNING` control head only because exact fencing can independently withhold
new-exposure authority.

One `LocalOperationalDrillObservation` records exact UTC start/observation
times, the final control state, whether new exposure or automatic re-arm was
observed, and exactly one response digest or unavailable reason. Its
disposition is derived rather than supplied:

- `UNAVAILABLE` when response evidence is absent;
- `PASSED` only at or before the deadline, at the expected or stronger control
  state, with new exposure withheld and no automatic re-arm; or
- `FAILED` otherwise.

One `LocalOperationalDrillMatrix` requires all six scenarios exactly once in
canonical order under the same campaign and scope. Stable IDs, canonical
payloads, and semantic digests make cases, observations, and matrices
content-authenticatable.

The contract is intentionally pure and local. Every value reports false for
broker authority and Phase 5 exit-gate qualification. It does not execute a
fault, choose a provider or broker, persist evidence, authenticate deployment
authority, or authorize re-arm.

## Consequences

Local harnesses can exchange typed, deterministic drill observations without
weakening safety expectations or overstating missing evidence. The checked-in
JSON catalog remains the source of exact pytest-node coverage; the typed
contract complements it rather than treating test references as runtime facts.

Deployment game days still require owner-approved providers, routes,
recipients, telemetry, paper-account and strategy composition, authoritative
data/reconciliation, wall-clock measurements, residual-exposure evidence, and
manual re-arm proof. A complete green local matrix cannot satisfy those gates.

This decision adds no schema, worker, provider I/O, broker I/O, or trading
authority.
