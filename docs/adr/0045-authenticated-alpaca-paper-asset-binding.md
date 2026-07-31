# ADR 0045: authenticated Alpaca paper asset binding

- Status: Accepted
- Date: 2026-07-27

## Context

Phase 4E defines a strict offline description and decoder for one exact
DIA/IWM/QQQ/SPY asset lookup, but its retained bytes are neither authenticated
nor current. Phase 4G can authenticate the configured paper account for a
short receipt window, yet it deliberately stops before security identity and
tradability. The next bounded runtime slice must close only that gap.

An authenticated response is not sufficient by itself to establish the local
instrument mapping. Learning the provider asset UUID from the first response
would make a transient or misdirected observation a trust-on-first-use security
master. The mapping therefore needs an independent nonsecret pin. The read must
also remain inside the existing durable request budget and stable account fence,
and it must prove that the exact Phase 4G account binding is still the current
durable terminal fact before and after transport.

This decision does not define effective-dated identifier changes, corporate
actions, a general market-data security master, quotes, sessions, positions,
reconciliation, or order authority.

## Decision

1. Define Phase 4H as one authenticated, read-only Alpaca paper
   `GET /v2/assets/{symbol}` for one exact candidate in the frozen
   DIA/IWM/QQQ/SPY map. The request has no query, body, pagination, redirect,
   retry, proxy inheritance, caller-selected URL, or order side effect.
2. Require a secret-free security reference that binds the exact Phase 4G
   credential reference, local instrument ID, fixed symbol, operator/review-
   pinned canonical provider asset UUID, and current capability digest. The
   observed UUID must equal the pin. A later legitimate identifier transition
   requires an explicit reviewed lifecycle contract rather than silent rotation.
3. Require the supplied Phase 4G account binding to match the local account,
   provider account UUID, credential reference/version, and capability digest.
   The SQL account-binding repository must reauthenticate that exact binding as
   the terminal head, including all of its durable sources, both immediately
   before transport and again after the raw response and post-request fence
   check. Both proof receipts are content-authenticated and half-open in time.
4. Reuse the Phase 4G ephemeral credential boundary. The asset resolver returns
   only the same opaque, closable envelope. Credential material and exact
   authentication headers remain redacted, non-copyable, non-serializable, and
   internal; every exit path zeros the byte buffers. Resolver and transport
   failures expose only sanitized bounded diagnostics.
5. Add the closed `observe_asset` budget operation and map it to protected
   reconciliation capacity without changing policy ceilings or the three-second
   permit window. Derive its correlation from the exact security reference,
   source account binding, and asset description. The runtime uses new-only
   durable issuance and reauthenticates the exact permit before transport, so
   replay cannot send twice under one debit.
6. Revalidate the same stable account fence before and after transport. At
   request start, the credential session, new durable permit, pre-request fence,
   and source account binding must all be current. At response completion the
   same windows must still be current. A late response may remain raw evidence
   but cannot create an asset binding.
7. The public orchestrator constructs the exact restricted HTTPX transport.
   It verifies TLS, follows no redirects, ignores ambient proxy configuration,
   requests identity content coding, and applies the fixed two-second timeout
   independently to connect, pool, read, and write inactivity waits. It retains
   the completed raw entity exposed through `iter_raw()` within the existing
   1 MiB bound; the timeout is not an end-to-end deadline.
8. Once the bounded entity and trusted receive/record times are available,
   persist representable allowlisted metadata and exact raw bytes through the
   Phase 4C journal before strict Phase 4E decoding. A missing or malformed
   request ID, unexpected media type or content coding, HTTP error or 404,
   malformed or drifted body, ineligible asset, and UUID mismatch therefore
   create no binding while leaving the completed bounded response inspectable.
9. Qualify only an HTTP 200 JSON observation with a request ID and exact
   `OBSERVED_USABLE_CANDIDATE` outcome: the fixed symbol, `us_equity`, a reviewed
   listed-U.S. exchange, `active`, `tradable`, and no PTP/review attribute.
   Preserve the provider asset UUID, class, exchange, status, and tradability.
   Marginability, shortability, borrowing, fractionality, and other raw fields
   remain non-authorizing.
10. Content-authenticate the successful transient evidence across the security
    and credential references, both account-binding freshness receipts,
    credential resolution, description, budget policy/demand/permit/freshness,
    both fence receipts, transport request/response, raw ingress receipt,
    decoded observation, and trusted-time order. A resulting binding is valid
    for at most five seconds and no later than either the source account binding
    or post-request fence.
11. Persist successful facts in a predecessor-linked chain per
    `(account_id, instrument_id)` and keep a terminal head for each chain.
    Advance them under the existing shared account-capacity lock. Exact foreign
    keys bind the canonical instrument, Phase 4G account binding, Phase 4D
    permit, and Phase 4C ingress receipt. Head-level uniqueness prevents one
    provider UUID or symbol from aliasing two local instruments for an account.
    Before inserting a new fact, reauthenticate under that lock that its exact
    Phase 4G source is still the current terminal account binding. If the source
    advanced after the runtime's post-request check, retain the raw observation
    but create no new asset binding.
12. Exact replay of evidence returns the existing fact. Conflicting content,
    source reuse, an orphan or rolled-back head, a missing successor, chain
    discontinuity, source corruption, clock regression, provider account
    change, provider asset UUID rotation, symbol change, or cross-instrument
    alias fails closed. Point reads, history reads, and startup verification
    reauthenticate the complete chain and durable sources. These are historical,
    non-authorizing reads: a binding's timestamp window alone does not prove
    that either its account source or its own head is still current. Any future
    active consumer must use a dedicated reauthentication boundary that proves
    the current asset head, current account head, fence, and time together.
13. A receipt-scoped Phase 4H binding may report authenticated security
    identity and current provider tradability for its exact window. It is not
    published into the general market-data security master and does not alter
    the global capability matrix. Quote/collar, calendar/session, positions,
    reduce-only validation, normalized broker facts, reconciliation,
    submission/cancel/lookup, `mark_in_flight`, coordinator dispatch, paper
    startup, and every trading-effect authority remain false.
14. Keep the concrete resolver deployment and API, worker, trader, and startup
    composition out of this slice. Tests use deterministic internal seams and
    synthetic inputs only; they do not perform a credential-backed provider
    capture.

## Consequences

Phase 4H can establish a short-lived, durable, account-scoped proof that one
operator-pinned candidate security currently has the exact reviewed Alpaca
identity and tradability state. The proof is raw-first, capacity-accounted,
stable-fence-bound, and rooted in the current authenticated account binding.

The binding is intentionally narrower than a production security master and
cannot authorize an order. Runtime calendar, quote, position, reduce-only,
reconciliation, lifecycle, and dispatch contracts remain future Phase 4 work,
and the Phase 4 exit gate remains open.
