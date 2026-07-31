# ADR 0044: authenticated Alpaca paper account binding

- Status: Accepted
- Date: 2026-07-27

## Context

Phases 4A through 4F define an offline Alpaca paper request contract, strict
account/asset response profiles, raw-first durable ingress, durable
request-budget admission, and a non-authorizing dispatch-preflight assessment.
They intentionally cannot resolve a credential, make an authenticated request,
or bind a local account alias to the provider account UUID returned by Alpaca.

The next runtime slice must prove one narrow prerequisite without accidentally
creating order authority. Trust-on-first-use is not acceptable: a validly
authenticated response for the wrong paper account would otherwise become a
new local identity. A request also cannot bypass the durable request budget or
survive a coordinator-fence change merely because it is read-only. Credential
values and authentication headers must remain transient, while unsuccessful or
unqualified HTTP responses must still cross the raw-first boundary before
decoding fails.

The repository is not yet ready to configure a deployed secret-store resolver,
observe assets, reconcile broker state, or start the paper trader. This decision
therefore admits exactly one authenticated `GET /v2/account` operation and
preserves every other runtime gate.

## Decision

1. Define Phase 4G as one authenticated, read-only Alpaca paper account
   observation. The only network target is the fixed
   `https://paper-api.alpaca.markets/v2/account` `GET` with no query, body,
   pagination, redirect, retry, proxy inheritance, order operation, or
   caller-selected URL. The concrete HTTPX transport verifies TLS, does not
   follow redirects, ignores ambient proxy settings, requests identity content
   coding, applies a fixed two-second timeout independently to HTTPX connect,
   pool, read, and write waits, and bounds the raw entity body at the existing
   1 MiB ingress limit. This inactivity timeout is not an end-to-end request
   deadline; a peer that continues producing chunks can take longer.
2. Require a nonsecret `AlpacaPaperCredentialReference` containing the local
   account alias, an operator-pinned canonical lowercase provider account UUID,
   a canonical `secret://paper/...` reference, and an immutable safe-text
   secret version. The reference is content-authenticated and grants no
   transport or trading authority. The observed provider UUID must exactly
   equal the configured pin; this slice never learns or rotates the pin from a
   response.
3. Resolve credentials only through an injected trusted resolver port.
   Possession of that port is secret-read authority and belongs only in the
   exact account-observation composition boundary. The public factory returns
   an opaque envelope; material, session, header, resolution, and concrete
   transport operations remain module-internal. API-key and secret values live
   in an explicitly closable, non-copyable, non-serializable, redacted byte
   buffer. All resolver interactions and transport errors are replaced with
   bounded diagnostics, and the buffer is zeroed on every success or failure
   path. A secret-free resolution receipt binds the exact reference, resolver
   identity/version, and a fixed 30-second session window. Neither the
   reference URI nor its version is a credential value, but both remain
   operational metadata and must not contain a secret.
4. Derive an exact `observe_account` request demand from the credential
   reference and Phase 4E account description. Map it to the existing protected
   reconciliation purpose; callers cannot select a lower-protection purpose or
   arbitrary correlation digest. The durable Phase 4D repository must issue
   a newly debited permit and then authenticate it under its SQL serialization
   boundary, producing a proof-constructed freshness receipt bound to the exact
   policy, demand, permit, check instant, and expiry. An already admitted exact
   demand is rejected before transport rather than using one debit for two
   provider requests; after an ambiguous crash, retry uses a new demand identity
   and consumes another slot.
5. Validate the same stable account fence immediately before the request, then
   validate that exact fence again after the raw response has been retained and
   decoded. The credential session, durable permit, and pre-request fence must
   all be current when transport starts and remain current when the response
   completes. A changed fence, regressed trusted time, stale permit, mismatched
   freshness receipt, or cross-account input fails closed. A response that
   outlives one of those pre-send windows can still be retained as raw evidence
   but cannot create a binding.
6. Construct authentication headers only from the open credential session at
   the final transport boundary. Their mapping exposes exactly Alpaca's two
   reviewed authentication-header names and redacts its representation. No
   header or credential value is included in canonical evidence, exceptions,
   logs, settings, SQL rows, or raw ingress metadata.
7. Once the exact transport completes an entity body within 1 MiB and trusted
   receive/record times are available, persist the status, representable
   allowlisted metadata, exact raw bytes exposed by HTTPX `iter_raw()`, digest,
   receive time, and record time through the Phase 4C journal before invoking
   the strict Phase 4E decoder. HTTP framing is not retained and content coding
   is not decoded. Invalid optional request-ID or media-type metadata is stored
   as absent and cannot qualify. Consequently, a `401`, malformed JSON, missing
   or over-bound `X-Request-ID`, unexpected media type or content coding, schema
   drift, blocked account, or pinned-UUID mismatch cannot create a binding but
   bounded bytes remain retained. A body-limit, pre-response, trusted-clock, or
   ingress-recorder failure cannot claim a durable raw receipt and never
   refunds the consumed permit.
8. Accept a binding only for HTTP `200`, JSON media type, a present provider
   request ID, the exact restricted transport profile, a Phase 4E
   `OBSERVED_USABLE_CANDIDATE` account, and an observed provider UUID equal to
   the operator pin. Preserve the account's economic fields only in the raw
   body; balances, buying power, equity, and status do not become canonical
   ledger, capacity, risk, or reconciliation facts.
9. Content-authenticate the successful transient evidence across credential
   reference and resolution receipt, account description, budget
   policy/demand/permit/freshness receipt, both fence receipts, transport
   request/response, raw ingress receipt, decoded observation, and trusted-time
   order. A binding is valid for at most five seconds and never beyond the
   persisted post-request fence expiry; domain readback and SQL constraints
   reject longer windows.
10. Persist each successful binding in
    `phase4_alpaca_paper_account_bindings` with an account-local contiguous
    sequence and predecessor digest. Advance
    `phase4_alpaca_paper_account_binding_heads` in the same transaction under
    the shared account-capacity serialization lock. Foreign keys bind the exact
    durable request permit and raw ingress receipt; exact SQL readback,
    full-history verification, and startup readiness authenticate the scalar
    payload, terminal head, source journals, provider UUID pin, and chain.
    Replaying identical evidence returns the existing fact, while conflicting
    content, orphaned facts, rolled-back heads, missing sources, digest drift,
    or any later provider UUID change fails closed.
11. Persist only secret-free scalar evidence. The nonsecret secret reference
    and immutable version are retained so an operator can identify which
    configured credential version produced a binding; credential values and
    authentication headers are structurally absent. Configuration loads the
    local alias, provider UUID pin, reference, and version only. It neither
    accepts direct Alpaca credential values nor selects a configurable base
    URL.
12. Keep the global `ALPACA_PAPER_CAPABILITIES` runtime-readiness flags false.
    The repository defines a resolver port and an injectable orchestrator, but
    it does not deploy a secret-manager resolver or wire this path into API,
    worker, trader, or startup composition. A particular short-lived durable
    binding proves only credential resolution and authenticated account
    identity for its exact receipt window.
13. Keep account economics, asset/security identity and tradability, current
    quote/collar, exchange-calendar/session, reduce-only sell proof, positions,
    order submission/cancel/lookup, stream processing, normalized broker facts,
    reconciliation, `mark_in_flight`, coordinator dispatch, and paper startup
    false. The binding exposes no submission request, lifecycle transition, or
    trading-effect authority and cannot satisfy Phase 4F's remaining gates by
    itself.
14. The public orchestrator constructs the exact concrete restricted transport;
    callers cannot substitute a self-described transport object before it
    receives authentication headers. The pure broker-contract aggregator
    exports none of the network runtime, credential material, header, session,
    standalone resolution, or concrete transport APIs. Keep private trusted
    seams only for deterministic contract tests. Do not perform a real
    credential-backed capture in tests or repository fixtures. Unit and SQL
    integration tests use those seams with a deterministic resolver and
    transport, assert raw-first failure behavior and secret erasure, exercise
    durable budget/fence/source binding, reject silent provider-account
    rotation and corruption, and prove that every trading-authority property
    remains false.
15. The owner-operated enrollment command remains generation-one-only by
    default. A separate recovery mode may authorize exactly one second account
    `GET` only when explicit CLI authority accompanies distinct old and new
    operation UUIDs and the same database contains exactly one released
    generation-one attempt, one matching reconciliation permit, one retained
    successful JSON response that now decodes to the exact pinned usable
    account, no binding, no alias conflict, a clear lease head, unchanged
    control, and no other account-local state. Recovery preserves that history,
    acquires generation two, and invokes the unchanged Phase 4G observer at
    most once. It cannot accept another checkpoint or authorize generation
    three. The retained response cannot be promoted directly into a binding:
    the original credential-resolution, permit-freshness, request, and fence
    receipts were transient and cannot be faithfully reconstructed after the
    failed decode.

## Consequences

Phase 4G establishes the first authenticated broker read boundary and a durable,
freshness-bounded local-alias-to-provider-account proof. A successful request
has durable capacity evidence, survives raw-first inspection, and cannot silently
bind another provider account. Received failures remain diagnosable without
granting readiness, and credential values remain outside durable evidence.
The bounded owner recovery path preserves an exact failed raw-first attempt and
requires fresh authority and fresh authenticated evidence instead of deleting
history or manufacturing a binding from an incomplete transcript.

This is not a paper-trading runtime. No concrete secret-store deployment,
authenticated asset observation, current security master, quote/session check,
position or reduce-only proof, reconciliation barrier, order transport, or
startup composition exists. Those prerequisites must be implemented as later
bounded phases, and the Phase 4 exit gate remains open.
