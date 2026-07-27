# ADR 0039: offline Alpaca client-order lookup observations

- Status: Accepted
- Date: 2026-07-26

## Context

ADR 0038 freezes the first non-authorizing Alpaca paper capability and request
translation contract. Phase 2 already preserves deterministic client order IDs
and freezes ambiguous dispatches in `UNKNOWN`, but neither contract defines
what evidence a later `GET /v2/orders:by_client_order_id` response supplies.

The recovery boundary is easy to overstate. A temporary 404 can reflect delayed
read visibility and is not proof that a submission never reached the broker. A
REST Order object reports cumulative quantity and average price, but does not
supply the execution identity, per-fill price/quantity, correction chain, or
fee evidence required by the canonical execution and ledger reducers. The
existing `BrokerOrderEvent` also assumes a stable event identity and a
contiguous local sequence; assigning those values from REST arrival order would
invent provider facts.

A durable broker inbox should therefore follow, not precede, a bounded
source-specific observation contract. Its uniqueness and sequencing rules
cannot safely be designed from unvalidated status strings or guessed snapshot
identity.

## Decision

1. Define Phase 4B as a pure, offline client-order lookup observation boundary.
   A lookup description can be created only from the exact
   `AlpacaPaperSubmissionDescription` produced by ADR 0038 and a bounded local
   account identifier. It binds the original intent, immutable submission
   request, deterministic client order ID, capability digest, paper base URL,
   and `GET /v2/orders:by_client_order_id` query. It carries no credentials and
   grants no transport or trading authority.
2. Decode only retained HTTP 200 and 404 response bytes. The response must be a
   non-empty UTF-8 JSON object no larger than 256 KiB. The Order decoder is a
   versioned **local accepted wire profile**, not a claim to implement every
   representation accepted by Alpaca's SDK. It requires the reviewed legacy
   response fields, permits the deprecated `order_type`, newer `expires_at`,
   `position_intent`, and `ratio_qty`, plus example-only `source` and `subtag`
   fields to be absent or present with exact local types, and rejects
   unreviewed fields. It accepts bounded non-negative plain decimal strings,
   including trailing-zero spellings, but not SDK-normalized numeric JSON
   values or a null `filled_qty`. Nullable `updated_at` and `submitted_at` are
   retained intentionally. Duplicate object keys, non-standard JSON constants,
   missing required local fields, malformed UUIDs, wrong exact types,
   unsupported statuses, and malformed timestamps fail closed. The exact
   response byte count and SHA-256 digest are preserved with the provider
   `X-Request-ID` and explicit UTC receipt time.
3. Preserve provider timestamps without silently truncating nanoseconds.
   Accepted timestamps have an explicit `Z` or numeric offset and at most nine
   fractional digits. The observation retains the exact provider text and an
   exact nanosecond-preserving normalized UTC identity.
4. Interpret HTTP 200 through three distinct layers:
   the returned `client_order_id` must exactly equal the requested deterministic
   ID; the Order object must pass the local wire profile; and its request
   economics are compared with the original Phase 4A request. Matching symbol,
   U.S. equity class, quantity, side, canonical `type=market`, `DAY`, simple
   class, absent price or replacement fields, and `extended_hours=false`
   produces `FOUND_MATCHED`. A missing, empty, or matching deprecated
   `order_type` alias is compatible; a conflicting non-empty alias is a
   mismatch. A supported object with the same client ID but different economics
   is retained as `FOUND_MISMATCH`, including filled notional collisions. It is
   never normalized into the requested order. `FOUND_MATCHED` means only that
   the reviewed request economics match; it does not validate `asset_id`,
   security identity, current tradability, or broker eligibility.
5. Interpret HTTP 404 only as `NOT_VISIBLE_INCONCLUSIVE`. The frozen error
   profile retains an exact positive 32-bit integer code and bounded message,
   but neither value is interpreted because the cited client-order endpoint
   does not qualify a stable error body. HTTP status 404 supplies the meaning.
   Repeated 404 responses remain inconclusive; no code, message, count, or
   elapsed interval in this pure contract can produce `NOT_SUBMITTED`,
   `RESOLVED`, or permission to resubmit.
6. Supersede ADR 0038 Decision 5 only for the reviewed status vocabulary by
   extending its closed classifier with the current official SDK's
   `pending_review` value. A recognized status and its conservative disposition
   are observation data. `pending_review`, rare, held, replacement, suspended,
   or otherwise special status requires reconciliation and does not become an
   optimistic local lifecycle transition. Because Alpaca treats additive enum
   values as compatible, an unreviewed value fails decoding until a contract
   review adds it.
7. Treat cumulative REST fill fields only as order-observation data. This
   boundary cannot construct `BrokerOrderEvent`, an execution ID, a fee, a
   broker sequence, ledger evidence, or `UnknownSubmissionResolution`. Even
   `FOUND_MATCHED` requires a later durable inbox and reconciliation workflow
   before it can affect submission or order state.
8. Check in a manifest and exact found/not-found fixtures for deterministic
   contract tests. The found response is `documentation_derived_synthetic`; the
   not-found code/message pair is an
   `unqualified_synthetic_error_example`. Neither is an authenticated Alpaca
   paper-account capture. Their byte digests are pinned, they contain no
   credential or account evidence, and the reviewed SDK source is pinned to
   commit `bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f` with source-file
   digests. The mutable Trading OpenAPI download is bound to its reviewed date
   and digest. An authenticated, secret-safe provider capture remains future
   qualification work.
9. Keep every ADR 0038 runtime-readiness flag false. This slice resolves no
   credential, performs no network request, enforces no request budget, writes
   no inbox, consumes no stream, paginates no snapshot, runs no reconciliation
   barrier, mutates no submission, and enables no paper or live startup.
10. Defer SQL persistence to Phase 4C. Alpaca explicitly considers additive
    response fields and enum members backward-compatible. This decoder
    deliberately rejects unreviewed additions, but an offline exception is not
    yet a durable quarantine fact. The durable design must persist raw ingress
    before decoding and separate raw delivery receipts from source-neutral
    provider facts and later application receipts; retain foreign/manual
    activity without a mandatory local-order foreign key; allocate an
    independent account-local ingress sequence under the account transition
    lock; and never reuse either the risk-observation sequence or canonical
    per-order broker sequence.

## Consequences

The codebase can now deterministically evaluate supported recorded client-order
lookup bytes and distinguish a request-economics match, an economic mismatch,
and temporary non-visibility without granting recovery authority. Unsupported
shape or enum drift raises a typed decode failure. It is not durably quarantined
until Phase 4C persists raw ingress before decoding. Provider timestamps retain
their full precision.

Phase 4B does not perform a lookup or resolve an `UNKNOWN` attempt. The next
broker slice must define the stream/snapshot observation identities and durable
inbox before provider facts can be applied atomically to submissions, orders,
reservations, executions, and ledger entries. Request-budget enforcement,
credential resolution, real transport, authenticated fixtures, pagination,
reconciliation, dispatch, and paper startup remain open.

## Reviewed Alpaca sources

- Client-order lookup endpoint:
  <https://docs.alpaca.markets/us/v1.4.2/reference/getorderbyclientorderid>
- Trading API request-ID header:
  <https://docs.alpaca.markets/us/docs/getting-started-with-trading-api>
- Order lifecycle and client-order lookup semantics:
  <https://docs.alpaca.markets/us/docs/orders-at-alpaca>
- June 2026 order-schema additions (`expires_at`, `ratio_qty`, and `held`):
  <https://docs.alpaca.markets/us/v1.1/changelog/2026-06-24-trading-api-00bf221>
- Trading OpenAPI schema and response examples:
  <https://docs.alpaca.markets/us/openapi/trading-api.json>
- Alpaca's additive-field and additive-enum compatibility policy:
  <https://docs.alpaca.markets/us/docs/alpaca-api-platform>
- Pinned official SDK Order model:
  <https://github.com/alpacahq/alpaca-py/blob/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/models.py>
- Pinned official SDK order-status enum:
  <https://github.com/alpacahq/alpaca-py/blob/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/enums.py>
- Documented Order fields and asynchronous submission timestamp behavior:
  <https://github.com/alpacahq/alpaca-docs/blob/master/content/api-references/broker-api/trading/orders.md>
