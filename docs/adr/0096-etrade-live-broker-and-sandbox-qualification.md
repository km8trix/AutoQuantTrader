# ADR 0096: E\*TRADE live broker and sandbox qualification boundary

- Status: Accepted
- Date: 2026-08-05
- Amends: [ADR 0004](0004-broker-submission-and-account-ownership.md) and
  [ADR 0038](0038-offline-alpaca-paper-contract-boundary.md)

## Context

AutoQuantTrader needs one explicit live-broker target before broker-specific
execution, reconciliation, credential, and promotion work can be completed.
The existing Phase 4A-4AI Alpaca paper chain is valuable historical,
non-authorizing evidence, but its endpoint shapes, client-order lookup,
pagination, request budgets, account identity, and lifecycle assumptions are
provider-specific. Those artifacts cannot be renamed or treated as evidence
for another broker.

E\*TRADE provides separate sandbox and production API keys and endpoints. Its
sandbox is intended for request/response development and returns stored sample
data; it does not execute real transactions and a response may not correspond
to the request. Sandbox success therefore cannot establish paper-trading
economics, stateful lifecycle behavior, production account identity, order
visibility timing, or reconciliation convergence.

E\*TRADE order placement also differs materially from ADR 0004's original
recovery assumption. An order is previewed and then placed with the returned
preview identifier. The provider client order identifier is limited to twenty
alphanumeric characters, must be unique within an account, is not returned in
order API responses, and has no documented lookup endpoint. The current
canonical AutoQuantTrader client ID is longer and contains punctuation. A
timeout during Place therefore cannot be recovered by automatically querying
the same client ID.

The operator reports that sandbox and production API keys exist in a local
owner-controlled environment file. This decision neither reads nor validates
that file. Reported key presence is configuration intent, not credential,
account, sandbox, production, or live-admission evidence.

## Decision

1. Select E\*TRADE production as AutoQuantTrader's intended v1 live execution
   venue and use the provider identifier `etrade`. This is an architecture
   selection only. No current runtime, secret reference, account, strategy,
   order path, or deployment is live-authorized by this ADR.
2. Preserve the entire Alpaca Phase 4A-4AI contract and evidence chain as
   immutable historical paper-provider work. It may support broker-neutral
   operational testing after its own gates pass, but it is neither E\*TRADE
   qualification nor live-broker evidence. New E\*TRADE schemas, adapters,
   fixtures, migrations, and evidence are additive and must not reinterpret
   existing Alpaca rows or digests.
3. Hard-pin and separately allowlist the official data/order REST origins:
   `https://apisb.etrade.com/v1` for sandbox and
   `https://api.etrade.com/v1` for production. Environment selection is typed
   and cannot be supplied as an arbitrary URL. Sandbox and production use
   disjoint credential references, account bindings, request budgets,
   databases or schemas, audit identities, and visual banners. Redirects,
   ambient proxy inheritance, cross-environment credentials, and response
   provenance that names the other REST origin fail closed.
4. Treat E\*TRADE OAuth 1.0a as a supervised session boundary. A reviewed OAuth
   implementation must use HMAC-SHA1 signatures, unique nonces, and trusted
   timestamps; obtain and authorize access tokens through the documented
   request-token flow; renew them only through the documented renewal path;
   and handle inactivity and daily expiry without silently retrying an order
   effect. Tokens, consumer secrets, verifiers, signatures, and authorization
   headers are resolved ephemerally from the dedicated secret scope and never
   persisted to application databases, evidence artifacts, or logs. Only
   secret-reference versions and sanitized request/evidence digests may enter
   application durable state. Shutdown and rotation procedures revoke tokens
   where supported.
   Sandbox and production keys use the same exact authorization service:
   token operations are allowlisted only beneath
   `https://api.etrade.com/oauth/`, and interactive authorization is allowlisted
   only at `https://us.etrade.com/e/t/etws/authorize`. This shared OAuth origin
   does not weaken the disjoint REST, credential, token, or account scopes. The
   authorization URL is secret-bearing and must not be logged or retained.
   Browser redirection is allowed only for that authorization page and an exact
   pre-registered callback origin/path, or the documented out-of-band verifier
   flow; dynamic callbacks, open redirects, and verifier replay fail closed.
5. Bind one local account alias to both the provider's numeric account ID and
   opaque `accountIdKey` through authenticated, raw-first production evidence.
   Order, portfolio, balance, and transaction paths use only that exact current
   binding. Account-list position or display text is not identity. The v1 live
   account remains application-exclusive; unexplained manual or foreign
   activity blocks new exposure until explicitly adopted or resolved.
6. Keep AutoQuantTrader's canonical internal order ID unchanged. Add a separate
   durable E\*TRADE client-order identifier that is deterministic, collision-
   checked before any provider call, account-scoped, at most twenty characters,
   and strictly alphanumeric. Persist its versioned derivation and immutable
   one-to-one mapping to the internal order, attempt, payload digest, account,
   and fencing generation. Because E\*TRADE does not return or support lookup by
   this identifier, the mapping is audit and duplicate-prevention evidence; it
   is not an automatic ambiguous-submission recovery key.
7. Model submission as two bounded external calls, Preview then Place. Before
   Preview, durably prepare the exact request and reauthenticate the account
   lease/fence, risk reservation, control state, trading session, quote and
   price collar, trusted time, OAuth session, account binding, instrument, and
   request budget. Persist the raw Preview response before decoding, then bind
   its preview ID, response digest, provider messages, estimated charges, and
   exact normalized order digest to the immutable attempt.
   HTTP status is never business success. A versioned closed classifier must
   recognize every Preview message/disclosure code and type. Unknown, review,
   restriction, timeout, unable-to-process, or confirmation-required messages
   block Place and require a new reviewed policy or human disposition; v1 never
   acknowledges a warning implicitly.
8. A preview grants no placement authority. The adapter uses a versioned local
   TTL strictly shorter than E\*TRADE's documented three-minute preview window.
   Immediately before Place it reauthenticates every Preview gate, consumes
   reserved Place capacity, and proves that all economic and provider fields
   match the previewed request. A stale preview, changed input, expired or
   renewed OAuth session, fence change, stronger control state, stale quote,
   or unavailable trusted time requires a new attempt and preview; it cannot
   reuse the prior preview ID.
9. Call Place at most once for an attempt. Persist every response raw-first.
   A definitive acceptance requires the exact expected account identity, a
   provider order-confirmation identity, an exact request/preview match, and
   every message code/type admitted by the closed versioned classifier. A
   definitive rejection likewise comes from a reviewed business-message
   classification, not HTTP status. An unrecognized or contradictory HTTP 2xx,
   timeout, disconnect, malformed response after possible send, or other
   ambiguous completion becomes durable `UNKNOWN`. For E\*TRADE,
   `UNKNOWN` permanently blocks replacement and automatic retry/resubmission,
   places the account in `HALTED` for new exposure, and retains all
   reservations until disposition. Absence from a read response never proves
   the request was unsent.
10. Reconcile an ambiguous Place with bounded, paginated production Orders and
    Transactions reads plus Balance/Portfolio evidence and the independent
    broker dashboard. Candidate matches remain non-applying until a human
    adopts the exact provider order or records a separately authenticated
    terminal disposition. A clean reconciliation and explicit human re-arm are
    required before new exposure. This provider-specific policy amends ADR
    0004's assumption that every live broker must recover uncertainty through
    lookup by the same client ID; its never-resubmit invariant remains
    unchanged.
    An ambiguous Cancel retains the order and reservation in a pending-cancel
    uncertainty state, blocks new exposure, and is not automatically reissued.
    Orders/Transactions/Portfolio evidence and late fills must be reconciled
    before a human disposition; the independent dashboard remains the emergency
    control channel. A Cancel HTTP 2xx or provider message that says only that
    cancellation is being processed remains pending-cancel; only a separately
    observed reviewed terminal state is canceled. Unknown Cancel codes fail
    closed under the same versioned message policy.
11. Start with bounded REST polling. Account, balance, portfolio, order, and
    transaction responses enter the provider-neutral raw journal before strict
    decoding, preserve pagination and source identity, and feed one idempotent
    reconciliation path. The documented Comet streaming capability remains
    unqualified and disabled until a separate contract freezes authentication,
    ordering, replay/resume, gap detection, correction, and request-budget
    behavior. Cumulative order fields are not canonical fills; reviewed
    transaction identities and detail records must support execution,
    correction, and fee application.
12. Do not inherit Alpaca's request ceiling. Until measured and contract-
    reviewed E\*TRADE limits exist, use conservative account-local and operation-
    local budgets with capacity reserved for cancellation, token/session
    control, and reconciliation. Throttling or an undocumented response shape
    fails closed and cannot expand capacity automatically.
13. Qualify the broker through this ordered ladder:

    1. deterministic offline recorded contracts and fault injection;
    2. E\*TRADE sandbox OAuth, endpoint-isolation, request shape, raw-first
       retention, decoder checks, and pagination field/request/response shape
       only;
    3. E\*TRADE production read-only Accounts, Balance, Portfolio, Orders, and
       Transactions checks plus preview-only qualification;
    4. local shadow and submission-boundary fault soak with no Place call;
    5. a separately approved, directly supervised, minimum-size production
       canary.

    Sandbox observations never count as paper sessions, fills, rejects,
    reconnects, reconciliation convergence, or execution-quality evidence.
    No ladder stage implies the next one.
14. Production credentials must move to a live-scoped deployed secret store
    before activation. A developer `.env`, CI secret, browser storage, local
    image, or reported key presence cannot satisfy this boundary. Credential
    inspection, account discovery, production read-only calls, preview, and
    Place each require their own scoped implementation and operator approval.
15. E\*TRADE selection does not reorder or satisfy any Phase 3, Phase 5, or
    Phase 6 gate. In particular, it does not alter the approved trusted-time
    policy upgrade, proof-resume, runtime-admission, first-enrollment, watchdog,
    alert, readiness, or human re-arm sequence.

## Consequences

The live path has a named provider and a fail-closed rollout sequence, while
all current trading authority remains disabled. Implementation requires a new
provider contract, OAuth/session supervisor, exact account binding, separate
provider client-ID mapping, Preview/Place persistence, production read-only
and preview-only qualification, reviewed lifecycle and transaction models,
bounded polling/reconciliation, and new fault evidence.

E\*TRADE's lack of client-order-ID lookup makes ambiguous Place materially more
conservative than the historical Alpaca design: the system may require manual
broker-dashboard reconciliation and remain halted indefinitely, but it will
not risk a duplicate order by guessing or resubmitting. The sandbox is useful
for protocol development but cannot replace a genuine paper or shadow soak.

## Reviewed E\*TRADE sources

- Authentication, token lifecycle, environments, and sandbox limitations:
  <https://developer.etrade.com/getting-started/developer-guides>
- Exact shared OAuth token and browser-authorization endpoints:
  <https://apisb.etrade.com/docs/api/authorization/request_token.html>,
  <https://apisb.etrade.com/docs/api/authorization/authorize.html>,
  <https://apisb.etrade.com/docs/api/authorization/get_access_token.html>,
  <https://apisb.etrade.com/docs/api/authorization/renew_access_token.html>, and
  <https://apisb.etrade.com/docs/api/authorization/revoke_access_token.html>
- Separate sandbox and production keys and production-access workflow:
  <https://developer.etrade.com/getting-started>
- Preview/Place order contract, client-order-ID constraint, preview validity,
  order lists, and order lifecycle fields:
  <https://apisb.etrade.com/docs/api/order/api-order-v1.html>
- Account list and balance contracts:
  <https://apisb.etrade.com/docs/api/account/api-account-v1.html>
- Portfolio contract:
  <https://apisb.etrade.com/docs/api/account/api-portfolio-v1.html>
- Transaction list/detail contracts:
  <https://apisb.etrade.com/docs/api/account/api-transaction-v1.html>
- REST and Comet API availability:
  <https://developer.etrade.com/support/frequently-asked-questions>
