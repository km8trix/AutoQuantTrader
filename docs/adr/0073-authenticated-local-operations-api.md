# ADR 0073: authenticated local operations API

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 5A established durable `PAUSE`, `DRAIN`, `FLATTEN`, `HALT`, breaker-trip,
and guarded `REARM` semantics, but deliberately exposed no operator transport.
Accepting a browser's claim that readiness is healthy, reconciliation is clean,
orders are terminal, blockers are resolved, or drain/flatten is complete would
turn transport input into downgrade authority. Likewise, a browser control
that invoked a broker adapter directly could bypass the durable command,
fencing, risk, and audit boundaries.

The existing local research API already issues a short-lived signed,
HTTP-only, same-site cookie and a separate CSRF value only when the configured
transport is loopback-scoped. Reusing that capability gives the local operator
surface one authentication model without creating a second session or exposing
credentials to JavaScript.

The operations UI also needs a small read surface. Returning persistence rows,
canonical payloads, source evidence, provider receipts, credentials, or raw
broker/reconciliation documents would unnecessarily expose implementation and
secret-bearing data. Read models must therefore be explicit projections rather
than serialization of repository objects.

## Decision

1. Mount operations routes only beneath `/api/v1/operations` in the existing
   local-only application. Every operation read and mutation requires the
   signed local-operator cookie and matching CSRF header. Mutations additionally
   require the existing bounded `Idempotency-Key` header. Responses are marked
   `no-store`; domain and persistence failures are translated into stable,
   sanitized HTTP errors.
2. Expose an allowlisted overview containing only environment identity and
   loopback status, readiness status/reason codes, coordinator owner/generation
   and lease expiry, the current control projection and bounded history,
   current advanced-risk assignment and assessment summaries, and active-alert
   delivery summaries. The response does not contain canonical payloads,
   evidence or authority digests, lease IDs, provider payloads/receipts,
   credentials, or raw source documents.
3. Accept only a bounded `reason_code` in control mutation bodies. Unknown body
   fields are rejected, so a browser cannot submit readiness flags, evidence
   digests, reconciliation results, order lists, blocker dispositions,
   operation completions, or raw payloads. `PAUSE`, `DRAIN`, `FLATTEN`, and
   `HALT` create authenticated human Phase 5A commands and append them through
   the durable operational-control repository. They never invoke a broker,
   cancel, order, reconciliation, or execution adapter.
4. Preserve Phase 5A severity precedence. Every non-rearm operator command uses
   the existing severity join, so a stale or lower-severity request cannot
   weaken `DRAINING`, `FLATTENING`, or `HALTED`. Actor-scoped exact retries
   return their authenticated historical transition, while reuse of the key
   for another action or reason is a conflict.
5. Make `REARM` a separate server-authoritative workflow. After authentication,
   the service loads the authenticated exact current head and invokes an
   injected verifier at trusted UTC time. That verifier—not the client—must
   return exact-head-bound, unexpired readiness, reconciliation, incident
   register, order-state, blocker disposition, and optional operation
   completion facts. The application proof-constructs
   `OperationalControlRearmEvidence`; the client has no constructor or
   evidence fields.
6. Add an explicit SQL `apply_authenticated_rearm` method. It reacquires the
   shared account serialization lock, authenticates history, checks the
   actor-scoped retry, re-binds the proof to the current head, authenticates any
   referenced drain/flatten completion in the same transaction, applies the
   pure Phase 5A transition, and compare-and-set updates the durable head. A
   stale/concurrent head or an expired, incomplete, or conflicting proof fails
   closed. The public `apply` method and public transactional append continue
   to reject every raw `REARM`, including one carrying a syntactically valid
   digest.
7. Register the advanced-risk assignment endpoint only when a server-side
   assignment service with an injected current-fence authority is supplied.
   The client selects neither a fence nor arbitrary policy material. The
   service obtains the current exact account fence, uses only the
   server-approved paper-policy binding, constructs an expected-head command,
   and calls the existing fenced `SqlAdvancedRiskRepository.assign` boundary.
   No route is registered when that authority is absent, and no account is
   fabricated or auto-assigned.
8. Keep composition explicit. The generic API composition root accepts injected
   operations query/control/assignment services. Without authoritative read,
   control, and rearm dependencies, operations fail unavailable and the
   assignment route is absent. This slice does not enable non-loopback
   transport, create a paper/live credential path, or infer readiness from
   Phase 4's non-authorizing comparison artifacts.

## Consequences

The local browser can observe a bounded operations view and can request audited
control commands without gaining broker or proof authority. CSRF, session,
idempotency, stale-head, and proof failures are fail-closed. Exact REARM
evidence is assembled only from injected server facts and committed only
through the dedicated authenticated repository path, while the original raw
repository behavior remains closed.

Deployment-specific authoritative readiness/reconciliation composition,
drain/flatten executors, live or remote access, and UI implementation remain
separate work. Merely mounting the routes does not make unavailable
authorities ready and does not close the remaining Phase 4 or Phase 5 runtime
and drill exit gates.
