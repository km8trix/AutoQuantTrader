# ADR 0038: offline Alpaca paper contract boundary

- Status: Accepted
- Date: 2026-07-26

## Context

Phase 2 already records immutable submission attempts, deterministic client
order IDs, `UNKNOWN` submission outcomes, account reservations, and coordinator
fences for the deterministic simulator. Those facts do not define what an
external broker accepts, how provider lifecycle states are interpreted, or
which read paths a future reconciliation service must exhaust.

Phase 4 begins with a deliberately non-authorizing boundary. The repository
needs a reviewed, versioned Alpaca paper capability contract and a deterministic
translation from the existing canonical `OrderIntent` into the first supported
request shape. It is not yet safe to resolve credentials, make an HTTP request,
submit or cancel a paper order, consume a broker stream, or claim
reconciliation. The Phase 3 captured-tape, reconnect, shadow, economic
evaluation, and reporting gates also remain open.

## Decision

1. Define Phase 4A as an offline Alpaca paper contract. The contract freezes the
   paper environment, endpoint and path metadata, authentication header names,
   provider capability breadth, local v1 subset, lifecycle classification,
   pagination limits, client-order-ID limit, and documented account request
   ceiling. The contract has a semantic digest so a future transport, fixture,
   or readiness check can bind the exact reviewed version.
2. The only local v1 request shape is a simple U.S.-equity market order with
   `time_in_force=day`, an integer share quantity, and
   `extended_hours=false`. The candidate translation mapping is fixed to
   `US-ETF-DIA -> DIA`, `US-ETF-IWM -> IWM`, `US-ETF-QQQ -> QQQ`, and
   `US-ETF-SPY -> SPY`. It is not a trade-enabled security master: the compiler
   does not prove current asset identity/tradability or broker eligibility.
   Instrument/symbol mismatches and every mapping outside that candidate set
   fail locally.
3. Record Alpaca's broader documented order types and time-in-force values as
   provider metadata, not local permission. Limit, stop, stop-limit,
   trailing-stop, GTC, OPG, CLS, IOC, FOK, fractional/notional, extended-hours,
   replacement, and advanced order-class requests remain unsupported. Both buy
   and sell shapes can be described, but the compiler has no position context:
   an exact risk authorization and position reservation must prove a sell is
   reduce-only before dispatch, and short exposure is never authorized here. No
   market-data feed is selected by this contract.
4. Deterministically translate an eligible canonical intent into an immutable
   paper request description containing `POST /v2/orders`, the exact paper base
   URL, the existing deterministic client order ID, `symbol`, integer `qty`,
   `side`, `type=market`, `time_in_force=day`, and
   `extended_hours=false`. The description stores the exact `OrderIntent` and
   rejects a request whose otherwise-valid quantity, side, or mapped security
   does not match it. `exchange_regular_session` is a future dispatch
   requirement, not compiler evidence: an exact pinned exchange calendar,
   including shortened sessions, must supply a `BatchRiskSession` whose
   `contains(now)` check is revalidated under the current fence. Constructing
   and hashing the description grants no dispatch capability and performs no
   I/O.
5. Use a closed provider-order-status classifier:
   `accepted` and `pending_new` are acknowledged and `new` is working;
   `partially_filled`, `filled`, `pending_cancel`, `canceled`, `expired`, and
   `rejected` retain their explicit economic meaning. Rare/special
   `accepted_for_bidding`, `held`, `stopped`, `done_for_day`, `calculated`,
   `pending_replace`, `replaced`, and `suspended` require reconciliation rather
   than an optimistic interpretation. An unknown or malformed provider status
   fails closed. This slice does not freeze a stream-event schema; cancel
   rejection, late fill, bust/correction, and other trade-event handling remain
   Phase 4 inbox/reducer work.
6. Freeze the reviewed provider metadata as of 2026-07-26:
   the paper trading base URL is `https://paper-api.alpaca.markets`; a client
   order ID may contain at most 128 characters; order-list requests expose a
   maximum page limit of 500, `open|closed|all` filters, `asc|desc` direction,
   `after`/`until` time filters, and mutually exclusive `after_order_id` or
   `before_order_id` cursors; either order-ID cursor family is also mutually
   exclusive with the time filters. Account-activity requests expose
   `asc|desc`, a `page_token` carrying the last activity ID, and page size from
   1 through 100; and the currently documented Trading API ceiling is 200
   requests per minute per account. These are contract inputs, not evidence
   that request-budget reservation, pagination exhaustion, delayed visibility,
   or reconciliation has been implemented.
7. Keep every runtime-readiness flag false in this slice. Phase 4A resolves no
   credential reference, imports no network client, reads no environment
   secret, validates no exchange calendar/session, security mapping, broker
   asset tradability, or reduce-only sell, makes no broker request, consumes no
   account/order/activity snapshot or stream, writes no inbox event, enforces no
   request budget, runs no reconciliation barrier, and enables no coordinator
   dispatch, paper startup, or live startup.
8. Provider documentation is temporally mutable. Changing any frozen endpoint,
   field, status, limit, or enabled subset requires an explicit contract-version
   review and updated tests. Provider breadth must never silently expand local
   trading authority.
9. A future transport must accept a durable `SubmissionAttemptPreparation`,
   revalidate its intent-bound request, and require a fresh dispatch fence. The
   request description alone is never a send capability and cannot bypass the
   `PENDING -> IN_FLIGHT` durability boundary.

## Consequences

The repository can now reject unsupported Alpaca request combinations before a
future risk-approved dispatch and can bind later recorded fixtures and transport
work to one exact reviewed capability contract. Exceptional and replacement
states cannot silently release reservations or enable new exposure.

Phase 4A's local contract slice is complete, but Phase 4 and its exit gate remain
open. The next broker work must add credential resolution, request-budget
enforcement, a network transport, deterministic client-ID lookup, paginated
snapshots, an idempotent inbox, stream recovery, and the convergent
reconciliation barrier before the first paper submission can be enabled.
Phase 3's external captured-tape, reconnect, shadow, economic-evaluation, and
reporting gates also remain open. Alpaca paper simulation does not establish
live execution quality.

## Reviewed Alpaca sources

- Paper endpoint and authentication headers:
  <https://docs.alpaca.markets/us/v1.1/docs/authentication-1>
- Create-order fields, supported order types/time-in-force values, and the
  client-order-ID limit:
  <https://docs.alpaca.markets/us/reference/postorder>
- Equity order behavior, extended-hours constraints, and order lifecycle:
  <https://docs.alpaca.markets/us/docs/orders-at-alpaca>
- June 2026 order-schema update adding the `held` status:
  <https://docs.alpaca.markets/us/v1.1/changelog/2026-06-24-trading-api-00bf221>
- Order-list filters and pagination:
  <https://docs.alpaca.markets/us/reference/getallorders-1>
- Account-activity page token and page-size bounds:
  <https://docs.alpaca.markets/us/reference/getaccountactivities-2>
- Current Trading API request ceiling:
  <https://alpaca.markets/support/usage-limit-api-calls>
- Paper-trading simulation limitations:
  <https://docs.alpaca.markets/us/docs/paper-trading>
