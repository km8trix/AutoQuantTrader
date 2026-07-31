# ADR 0082: safe browser PAUSE and HALT controls

- Status: Accepted
- Date: 2026-07-28

## Context

ADR 0074 made the operations dashboard explicitly read-only because no durable
command service was composed at that time. ADR 0081 now composes a
database-only local command service that advertises only `PAUSE` and `HALT`.
The browser must preserve that narrow authority. In particular, a generic
`controls` flag, stale readiness evidence, an automatic HTTP retry, or a
development fixture must not accidentally widen or suppress the fail-safe
surface.

## Decision

The React operations pages expose a shared control panel with the following
contract:

1. The panel renders only `PAUSE` and `HALT`. It has no client route or button
   for drain, flatten, re-arm, policy assignment, broker action, or account
   initialization.
2. Each action requires the local environment, the
   `operations_control` flag, its granular `control_pause` or `control_halt`
   flag, an exact enabled bootstrap credential capability, a signed-session
   CSRF token, and the supported CSRF and idempotency header names. A
   contradictory disabled capability carrying a token remains disabled. The
   session cookie is sent implicitly with `credentials: same-origin`.
3. Bootstrap readiness and dashboard freshness do not disable an advertised
   `PAUSE` or `HALT`. These commands reduce or stop authority and remain
   available when observational evidence is stale or not ready. The durable
   server may still reject a command.
4. The operator supplies trimmed visible text of 1–128 characters. Both
   actions show a confirmation dialog; the stronger `HALT` action additionally
   requires typing `HALT`.
5. One random idempotency key is created only when the operator confirms an
   intent. The intent binds the exact account, action, and reason shown in its
   confirmation. An account change requires a new confirmation; an ambiguous
   retained intent is available for retry only when that original account is
   current. Browser automatic retries are disabled. A network failure, 5xx
   response, malformed 2xx response, or mismatched 2xx action/state is
   ambiguous, so the exact account, action, reason, and key are retained behind
   an explicit retry. A confirmed success clears that account's retained intent
   and refreshes its authoritative overview. A later intent receives a
   distinct key.
6. The development bootstrap fixture advertises neither operations mutations
   nor either granular action. Mutation requests have no fixture fallback.

The client consumes generated request and response types from the checked-in
OpenAPI contract and performs a minimal runtime confirmation check before
treating a 2xx mutation as successful.

## Consequences

The local browser can apply the two fail-safe controls already composed by the
backend without gaining execution, downgrade, initialization, assignment, or
broker authority. Ambiguous outcomes converge through server-side idempotency
instead of issuing a new command. This decision does not enable remote access,
add a broker call, or close the deployment and operational-drill exit gates.

This decision adds no backend schema or migration.
