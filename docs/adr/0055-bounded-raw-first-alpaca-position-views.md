# ADR 0055: bounded raw-first Alpaca position views

- Status: Accepted
- Date: 2026-07-28

## Context

The startup and reconnect barrier needs an account position view as well as the
bounded order traversal introduced in Phase 4M. Alpaca exposes the account's
currently open positions through `GET /v2/positions`, but the values are live
mark-to-market observations: a closed position disappears, market-value fields
can change while the response is handled, and the endpoint supplies neither
snapshot isolation nor a provider revision for the array.

Treating an empty or successfully decoded array as the canonical account
position state would therefore be unsafe. The system must retain the exact
response before interpretation, reject profile drift and ambiguous identities,
bound local work, and keep the result historical and non-authorizing.

Reviewed provider references:

- [All Open Positions](https://docs.alpaca.markets/us/v1.1/reference/getallopenpositions)
- [Trading API OpenAPI contract](https://docs.alpaca.markets/us/openapi/trading-api.json)

## Decision

1. Define Phase 4R as a local, non-I/O Alpaca paper position-view contract. It
   introduces no credential resolver, request transport, schedule, worker, SQL
   table, startup composition, or broker authority.
2. Freeze one request description:
   `GET https://paper-api.alpaca.markets/v2/positions`, with no query
   parameters, scoped to one account and one account-local capture
   idempotency key.
3. Route every representable response through the Phase 4C broker-ingress
   recorder before decoding. The durable receipt binds the exact account,
   adapter version, paper environment, operation, request correlation, status,
   provider request ID when present, trusted receive/record times, and exact
   bytes. A missing request ID or decoder failure is reported only after the
   raw receipt has been committed.
4. Accept only a bounded HTTP 200 JSON array. The response must fit the
   one-mebibyte Phase 4C body limit and contain at most 512 position objects;
   an overflow is rejected after retention and is never silently truncated.
5. Freeze the reviewed USD U.S.-equity wire profile. Every position requires a
   canonical provider asset UUID, bounded symbol, supported non-crypto equity
   exchange, `us_equity` asset class, exact marginable flag, side, and all
   required decimal-string economics. `qty_available` is the sole optional
   field. Local-currency-only fields, unknown keys, missing required keys,
   duplicate JSON keys, non-standard constants, malformed decimals, and
   additive profile drift fail closed.
6. Preserve each decimal's exact provider lexeme alongside its canonical
   finite decimal value. Detect both long and short observations rather than
   treating the v1 long-only policy as proof that no unexpected short position
   can exist.
7. Reject duplicate provider asset UUIDs and duplicate
   `(asset_class, symbol)` identities within one decoded array. The local
   capture identity and raw-delivery identity prove exact retry/source
   equality only; neither is a provider revision or cross-channel
   deduplication identity.
8. Bind the typed observation back to the exact raw receipt, description,
   request metadata, trusted receive time, bytes, and digest. An empty array is
   a valid historical response but does not prove that the provider account is
   durably flat.
9. Keep every authority false. Phase 4R cannot establish a complete or isolated
   snapshot, a canonical position/cash/ledger fact, convergence, provider
   revision identity, lifecycle or reconciliation application, UNKNOWN
   resolution, readiness, a broker call, or a trading effect.

## Consequences

The repository can now describe, retain, strictly decode, and replay one
bounded historical open-position response without losing malformed evidence or
promoting a live mark-to-market view into account truth. Duplicate identities
and provider profile drift fail closed with the raw bytes still available for
diagnosis.

Authenticated request execution, durable typed position-source persistence,
two-view comparison, account/order/position cross-source reconciliation,
activity and fill pagination, stream buffering, provider-qualified event and
correction identities, authoritative application, convergence, and the Phase 4
paper exit gate remain open.
