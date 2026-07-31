# ADR 0057: authenticated single-use Alpaca position views

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4R can retain and strictly decode one supplied open-position response,
and Phase 4S can compare two supplied responses without promoting them to
canonical account state. Neither slice can safely execute the provider request.
A normal idempotent retry is unsafe for `GET /v2/positions`: Alpaca supplies no
snapshot revision or as-of time for the array, so a restart could silently
associate two different live mark-to-market views with one capture identity.

The existing Phase 4G terminal provider-account binding, Phase 4D request
budget, account fence, and Phase 4C raw journal provide the surrounding
evidence. A narrower runtime still needs an explicit durable single-use claim
before any credential or request capacity is touched.

## Decision

1. Define Phase 4T as the
   `phase4t-authenticated-single-use-position-snapshot-v1` runtime contract.
   One public call may claim, request, retain, decode, commit, and exactly
   reload one Phase 4R position capture. It has no retry or traversal loop.
2. Bind the immutable runtime plan to the exact Phase 4R request description,
   secret-free credential reference, and terminal Phase 4G account binding.
   The local account, paper environment, pinned provider-account UUID, secret
   reference/version, and their semantic digests must agree.
3. Require the durable repository to create a fresh single-use preparation as
   the first external mutation. An unresolved, completed, concurrent, or
   restarted use of the same capture must fail at preparation, before secret
   resolution, permit issuance, or transport. A separate read-only load can
   recover an already committed receipt but cannot authorize another request.
4. Consume exactly one new Phase 4D reconciliation-purpose permit derived from
   the plan and capture idempotency key. Authenticate the fixed policy, demand,
   permit, and freshness receipt before transport, and require the permit to
   remain fresh through response completion; retry admission is not an
   execution path.
5. Reauthenticate the same exact account fence lease and terminal Phase 4G
   provider-account identity around the request and again before commit. The
   durable recorder must independently revalidate the same fence, policy,
   lease digest, and expiry inside its commit transaction at or after the
   runtime authentication instant and strictly before lease expiry.
6. Restrict transport to exactly
   `GET https://paper-api.alpaca.markets/v2/positions` with no query. Use the
   `strict-httpx-alpaca-paper-position-snapshot` version `1.0.0` profile: TLS
   verification enabled; redirects, ambient proxies, and compression disabled;
   JSON accepted; connect, pool, read, and write inactivity bounded to two
   seconds each; and at most one mebibyte retained.
7. Resolve credentials only inside this operation. Persist only a secret-free
   resolution receipt, expose authentication headers only to the restricted
   transport, sanitize transport failures, and close and zero owned mutable
   credential buffers on every exit path.
8. Route each representable response through Phase 4C before media-type,
   status, request-ID, credential/permit completion-time freshness, JSON, or
   Phase 4R profile qualification. A retained malformed or late response can
   leave the preparation permanently stalled but cannot create authenticated
   typed evidence or be resent.
9. Cross-bind the committed receipt to the exact plan and preparation,
   credential resolution, pre/post account-identity proofs, demand, permit and
   freshness receipt, pre/post/final fences, strict transport request and
   response, Phase 4C receipt, Phase 4R typed capture, authentication instant,
   and transaction-internal commit fence. Reload must equal the exact committed
   receipt.
10. Allow only narrow evidence properties to become true: a fresh single-use
    claim existed, the request budget was enforced, the provider-account source
    was authenticated, the raw response was persisted, and the exact typed
    position capture was durably committed. Current runtime state, monotonic
    timing, snapshot isolation/completeness, provider revision or
    deduplication identity, canonical positions/cash/ledger, lifecycle or
    reconciliation application, convergence/completion, readiness, UNKNOWN
    resolution, reservation release, resubmission, and every trading authority
    remain false.
11. Add only the runtime contract and injected fake-port tests in this slice.
    A concrete SQL repository, deployed secret resolver, API/worker/trader
    composition, automatic retry, startup-readiness change, and real provider
    request remain outside Phase 4T.

## Consequences

The codebase now has a bounded authenticated execution envelope for one
position view and an explicit conservative crash rule. Any failure after
durable preparation sacrifices that capture's liveness instead of risking a
duplicate request or mixing two provider views under one identity.

Concrete persistence, durable two-view comparison, restart-safe pair
supervision, account/order/position composition, activity and fill views,
stream overlap, provider-qualified event identities, authoritative
application, convergence, and the Phase 4 exit gate remain open.
