# ADR 0046: authenticated Alpaca paper client-order lookup

- Status: Accepted
- Date: 2026-07-27

## Context

Phase 4B defines a strict offline observation for one exact
`GET /v2/orders:by_client_order_id` response, Phase 4C retains its bytes before
decoding, and Phase 4D reserves protected request capacity for UNKNOWN
recovery. Phase 4G can authenticate the configured paper account, while Phase
4H independently pins one candidate symbol to its expected provider asset
UUID. None of those slices performs the lookup for a durable submission
attempt or proves that the attempt is still the exact unresolved UNKNOWN head
when a request leaves the process.

An authenticated lookup is recovery evidence, not a recovery decision. A
matching Order object does not contain per-fill identities, fees, corrections,
or the converged account view required to resolve an UNKNOWN submission. A
404 remains vulnerable to delayed provider visibility and cannot authorize a
resubmission. Requiring current asset tradability would also be incorrect:
historical order recovery must remain possible when the asset is presently
inactive or non-tradable. The returned asset UUID can instead be checked
against the independently configured security reference without treating that
pin as current tradability evidence.

The next bounded slice must therefore authenticate and retain one exact
client-order lookup while preserving every lifecycle and reconciliation gate.

## Decision

1. Define Phase 4I as one authenticated, read-only Alpaca paper client-order
   lookup for an exact durable submission attempt. The only network target is
   the Phase 4B description's fixed
   `GET /v2/orders:by_client_order_id?client_order_id={deterministic-id}`.
   Callers cannot select another method, path, query field, client order ID,
   base URL, body, redirect, retry, proxy, pagination mode, or order operation.
2. Require the supplied attempt to reconstruct from its immutable durable
   preparation and complete event chain, with its exact current terminal event
   in `UNKNOWN`. The preparation, Alpaca submission description, request,
   account, intent, logical order, deterministic client order ID, instrument,
   symbol, and capability digest must agree. Authenticate that exact UNKNOWN
   head immediately before transport and again after the raw response, under
   the durable commit boundary. If the attempt head changes, retain any
   completed raw response but publish no typed attempt-bound lookup receipt.
3. Use the current recovery owner's account fence independently of the
   submission's original dispatch fence. The recovery fence must name the same
   account and remain the exact same stable fence when revalidated immediately
   before and after transport. A legitimate takeover may therefore investigate
   a prior generation's UNKNOWN attempt, but only under its own current,
   database-authenticated recovery fence. Fence change, loss, or expiry leaves
   any completed raw response non-qualifying.
4. Require the exact terminal Phase 4G account binding as the durable provider
   account identity anchor before transport and reauthenticate that same
   terminal binding after the raw response. Its local account, pinned provider
   account UUID, credential reference and version, capability digest, and
   durable sources must agree. Each check produces an account
   identity-continuity receipt; the complete lookup evidence binds both
   receipts alongside the same recovery fence and trusted time order. These
   receipts do not require the Phase 4G status-eligibility window to remain
   fresh and do not claim that the earlier account status or blocker flags are
   current.
5. Bind an independent Phase 4H security reference to the attempt's exact local
   instrument and fixed symbol. For HTTP 200 only, the returned Order
   `asset_id` must equal the reference's operator/review-pinned provider asset
   UUID. A decoded 200 whose Order `asset_id` is null or a different canonical
   UUID produces a typed authenticated `SECURITY_IDENTITY_MISMATCH` outcome
   that blocks later reconciliation; it is not discarded as raw-only evidence.
   A malformed provider asset UUID, missing required wire-profile field, or
   wrong client order ID still fails the strict decoder and therefore leaves
   raw evidence only. An HTTP 404 contains no asset identity and remains
   admissible only as an inconclusive not-visible observation.
6. Do not require a current Phase 4H asset binding, current asset head, or
   current provider tradability to perform or retain this historical recovery
   observation. The independent UUID pin proves only the expected identity of
   a supported HTTP 200 Order object. It does not publish a security master,
   validate symbol lifecycle, or establish present eligibility for a new
   order.
7. Resolve credentials only through the same injected trusted resolver and
   opaque, closable envelope used by Phases 4G and 4H. Credential bytes and
   authentication headers remain internal and absent from canonical evidence,
   SQL, logs, settings, and diagnostics. The owned envelope is redacted,
   non-copyable, non-serializable, and explicitly zeros its mutable credential
   buffers on success and failure paths. This contract does not claim that
   immutable or library-managed transient copies can be zeroed.
8. Derive the exact lookup demand from the attempt-bound description, terminal
   account identity anchor, security reference, and UNKNOWN-head evidence. Fix
   the operation to `lookup_unknown_by_client_order_id` and its purpose to the
   Phase 4D protected `unknown_lookup` tier. Use new-only durable issuance and
   reauthenticate the exact permit and freshness receipt before transport.
   Replaying an admitted demand cannot send twice under one debit; a later
   lookup uses a new demand identity and consumes another slot. The credential
   session and permit must remain fresh when the response completes; a late raw
   response remains non-qualifying.
9. Preserve the restricted transport profile from Phases 4G and 4H: verified
   TLS, no redirects, no ambient proxies, identity content coding, exact raw
   entity bytes from `iter_raw()`, a 1 MiB transport/ingress bound, and fixed
   two-second connect, pool, read, and write inactivity waits. These per-I/O
   bounds are not an end-to-end request deadline.
10. Once a bounded response and trusted receive/record times exist, persist
    representable allowlisted metadata and the exact raw bytes through Phase
    4C before Phase 4B decoding or any post-request source check. A decoder
    failure, unsupported HTTP status, malformed or absent request ID,
    unexpected media type or content coding, schema drift, a wrong client order
    ID, changed UNKNOWN head, failed account identity continuity, or lost fence
    can therefore leave raw evidence without creating a typed attempt-bound
    receipt. A decoded 200 with a null or different canonical asset UUID instead
    retains the typed reconciliation-blocking security mismatch. A
    pre-response, body-limit, trusted-clock, or ingress-recorder failure cannot
    claim a durable raw response and never refunds the permit.
11. Admit typed historical observations only through Phase 4B's exact local
    256 KiB wire-profile bound. HTTP 200 retains either `FOUND_MATCHED` or
    `FOUND_MISMATCH` after exact client-ID and request-economics evaluation when
    the provider asset UUID matches the independent pin. A null or different
    canonical asset UUID changes the authenticated result to
    `SECURITY_IDENTITY_MISMATCH`. HTTP 404 retains only
    `NOT_VISIBLE_INCONCLUSIVE`. Recognized special statuses, request-economics
    mismatches, security-identity mismatches, and cumulative REST fill fields
    remain observation data requiring reconciliation.
12. Content-authenticate the successful secret-free receipt across the exact
    attempt and UNKNOWN terminal event, submission and lookup descriptions,
    security and credential references, account binding and both identity
    continuity receipts, credential resolution, budget
    policy/demand/permit/freshness, both fence receipts, transport
    request/response, raw ingress receipt, decoded observation, and trusted
    time order. Persist immutable, predecessor-linked lookup history under the
    shared account serialization boundary. Exact replay is idempotent; changed
    content, source reuse,
    missing or corrupt sources, a rolled-back head, chain discontinuity, clock
    regression, or conflicting provider identity fails closed on write, read,
    and startup verification.
13. The committed typed receipt is historical and non-authorizing. The
    UNKNOWN-at-send evidence and post-response recheck establish the state in
    which that lookup occurred; they do not promise that the attempt will
    remain UNKNOWN afterward. Every later consumer must reauthenticate current
    lifecycle and reconciliation state rather than interpreting the receipt as
    a mutable projection. The shared account lock is the authoritative live
    ordering boundary across lease, attempt, account-binding, and lookup
    writes. Historical verification can reject a source transition whose
    trusted timestamp is strictly earlier than the lookup commit; equal
    timestamps across those separate append-only streams do not encode their
    transaction order and therefore cannot create current-state authority.
14. Neither `FOUND_MATCHED`, `FOUND_MISMATCH`,
    `SECURITY_IDENTITY_MISMATCH`, nor any number or elapsed duration of 404
    observations can construct an
    `UnknownSubmissionResolution`, authorize resubmission, create a canonical
    broker event or execution, infer a fee or correction, release a
    reservation, or mutate submission, order, ledger, or account state.
15. Add no retry scheduler, delayed-visibility threshold, pagination,
    normalized provider fact, quarantine/application receipt, reconciliation
    reducer, cancellation, submission transport, API/worker/trader/startup
    composition, or real credential-backed capture in this slice. Unit and SQL
    integration tests use deterministic trusted seams and the existing
    synthetic Phase 4B fixtures.
16. Keep every global `ALPACA_PAPER_CAPABILITIES` runtime-readiness flag false.
    A particular receipt can prove that one protected authenticated lookup
    occurred for an exact UNKNOWN attempt, but `client_order_id_lookup_ready`,
    `inbox_deduplication_ready`, `reconciliation_ready`,
    `transport_submission_ready`, `paper_startup_ready`, and every
    trading-effect authority remain false.

## Consequences

Phase 4I can retain an authenticated, capacity-accounted, raw-first historical
answer to one exact UNKNOWN client-order lookup. The observation is bound to
the current recovery owner, the configured provider account, the exact
UNKNOWN head at the request boundary, and, for a 200 response, the independent
provider asset identity comparison. A null or different canonical UUID remains
typed, authenticated, reconciliation-blocking evidence. Recovery reads depend
on provider-account identity continuity, not a fresh account-status window or
present asset tradability.

This slice still cannot decide whether the original request reached the broker,
apply an order state, reconstruct fills, resolve UNKNOWN, or permit a
resubmission. Bounded delayed lookup scheduling, normalized inbox facts,
paginated snapshots, stream overlap, executions and corrections, convergent
reconciliation, current position and reduce-only proof, calendar and quote
checks, dispatch, and paper startup remain later Phase 4 work. Phase 4 and its
exit gate remain open.
