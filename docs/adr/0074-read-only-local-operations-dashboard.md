# ADR 0074: Read-only local operations dashboard

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 5 requires one operator view spanning environment identity, freshness,
coordinator ownership, strategy/deployment state, orders, fills,
account/ledger positions, risk reservations and decisions, reconciliation
differences, critical alerts, and audited operational-control transitions.
These facts have different authorities and freshness budgets. Combining them
visually must not turn an incomplete summary, old observation, or synthetic
fixture into trading authority.

The same browser application also exposes separately authenticated command
workflows. A dashboard that shared mutation affordances or broker transport
authority with its observational queries would make it too easy to confuse a
display action with a durable operational command.

## Decision

Introduce `phase5-operations-dashboard-v1` as a whole-snapshot, GET-only
projection at `/api/v1/operations/dashboard`.

The response:

- declares `read_only: true`;
- carries one server observation time;
- includes every required operational section, using an explicit
  `unavailable` state when an authority is absent;
- carries source-specific observation times and maximum-age budgets;
- keeps coordinator lease and fence identity observational;
- presents retained order, fill, position, ledger, risk, reconciliation,
  alert-delivery, and control-receipt facts without deriving new authority;
- never contains credentials, broker request payloads, session tokens, or an
  executable command description; and
- is served with `Cache-Control: no-store` and `Pragma: no-cache`.

The router registers only `GET`. Projection absence, integrity failure, or an
invalid non-read-only result returns a sanitized `503`; partial success is not
silently recast as a complete snapshot.
Because the route is inside `/api/v1/operations`, it also requires the same
signed local-operator cookie, matching CSRF header, loopback-scoped transport,
and durable-persistence readiness as every other operation read. Read-only
means non-authorizing; it does not mean unauthenticated.

The React dashboard polls this endpoint as an observational client. It:

- keeps the environment banner visible;
- warns when the snapshot or any named source is stale or unavailable;
- displays all required sections in one operational route;
- labels deterministic development fixtures as fixtures;
- exposes refresh as its only button; and
- explicitly states that controls require the separately authenticated
  operations API and that this surface cannot call a broker.

The first local query adapter projects the deterministic walking thread. It
reports missing coordinator, reconciliation, alert, and operational-control
authority as unavailable instead of inventing those facts. Durable Phase 5
composition may replace that adapter while preserving the response contract
and the GET-only boundary.

## Consequences

- Operators get one coherent status surface without creating a second command
  path.
- Missing or stale evidence is visible and cannot be mistaken for readiness.
- UI tests can prove that all required evidence regions render and that no
  pause, drain, flatten, halt, or re-arm buttons exist on this route.
- API tests can prove the route has no mutation method, disables caching,
  requires the local session and CSRF pair, preserves exact decimal
  serialization, sanitizes failures, and remains usable with a deterministic
  local projection.
- Registering a durable query adapter still requires a composition-root choice;
  this ADR does not claim that the local walking-thread projection is a
  broker-authoritative paper-account snapshot.
