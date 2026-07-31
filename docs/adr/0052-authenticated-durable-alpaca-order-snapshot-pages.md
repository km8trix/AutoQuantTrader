# ADR 0052: authenticated durable Alpaca order-snapshot pages

- Status: Accepted
- Date: 2026-07-28

## Context

Phase 4M defines a bounded raw-first order-page chain, and Phase 4N can compare
two supplied chains without claiming convergence. Neither slice can safely make
a provider request or resume a partially observed traversal after a crash.
Executing a whole pagination loop in one process would create an unsafe
recovery ambiguity: after a permit is issued or response bytes are retained,
restarting the same page could duplicate a provider call or mix two different
broker views under one capture identity.

The existing Phase 4G account identity, Phase 4D request permits, account fence,
and Phase 4C raw journal provide the source evidence needed for a narrower
runtime. They do not by themselves retain the prepared traversal prefix or
prove which exact page may be requested next.

## Decision

1. Define Phase 4O as the
   `phase4o-authenticated-durable-order-snapshot-page-v2` boundary. One public
   call can prepare, request, retain, decode, and commit exactly one Phase 4M
   page. It never runs an automatic pagination loop.
2. Persist an immutable plan and head before credential resolution or permit
   issuance. Preparation authenticates the exact next Phase 4M description,
   page number, predecessor digest, and cursor. Request and delivery identities
   are derived from the plan and page; callers cannot choose them.
3. Require the exact terminal Phase 4G provider-account identity binding and
   the same current account fence before and after transport. Account identity
   continuity is required; the earlier five-second account-status window is
   not treated as current balance or account-state evidence.
4. Consume a new Phase 4D reconciliation-purpose permit for every page and
   durably reauthenticate its demand, policy, freshness, and source position
   before the broker call. Exact retry of an already issued demand cannot send.
5. Restrict transport to one exact Phase 4M `GET /v2/orders` page using
   `strict-httpx-alpaca-paper-order-snapshot-page` version `1.0.0`. Enable TLS
   verification; disable redirects, ambient proxy configuration, and content
   compression; use JSON media type; bound connect, pool, read, and write
   inactivity to two seconds each; and retain at most one MiB.
6. Resolve paper credentials only inside this operation. Retain a secret-free
   resolution receipt, expose authentication headers only to the restricted
   transport, and close and zero owned mutable credential buffers on every
   success or failure path.
7. Commit representable response metadata and exact bytes through Phase 4C
   before request-ID, media-type, status, or Phase 4M decoding qualification.
   An HTTP error, missing request ID, malformed JSON, duplicate key, or profile
   drift can leave a raw receipt but cannot create a typed page.
8. Record typed runtime evidence under the SQL account lock with a
   transaction-internal fence recheck. Every page cross-binds its exact plan,
   preparation, account binding and pre/post continuity receipts, credential
   receipt, demand, permit and freshness receipt, stable fence evidence,
   transport request/response, Phase 4C raw receipt, Phase 4M observation,
   predecessor, and commit time.
9. Store plans, pages, and heads in three additive Phase 4 tables. Page numbers
   are contiguous; later pages bind the exact preceding runtime receipt,
   persisted Phase 4M page digest, and derived cursor. Each permit and raw
   receipt can belong to only one page. Exact retry returns the original
   committed receipt; gaps, forks, substitutions, rollback, truncation, and
   orphans fail closed.
10. Head states distinguish active prefixes, non-isolated cursor exhaustion,
    bounded truncation, and stalled preparation. Cursor exhaustion is never
    named provider snapshot completion. No page can be appended after an
    exhausted or truncated head.
11. Make restart behavior conservative:
    - the transaction that first persists a preparation is its only
      single-use claimant; every later prepare call for that stalled head fails
      before credentials, permit issuance, or transport;
    - therefore a crash after preparation, including before permit issuance,
      stalls the capture rather than risking an overlapping resend;
    - a crash after permit issuance but before typed commit cannot resend;
    - a crash after raw persistence retains those bytes but cannot resend;
    - a crash after typed commit reconstructs the exact prefix and derives only
      its next page.
    A stalled capture requires a new capture identity until a separate recovery
    policy can prove another action safe.
12. Allow only scoped evidence properties to become true: the page used a
    durably enforced request budget, its raw response was persisted, its
    provider-account page source was authenticated, and its committed prefix
    was established. Snapshot completeness/isolation, convergence and monotonic
    convergence timing, provider revision/deduplication identity, lifecycle or
    execution application, `UNKNOWN` resolution, reservation release,
    reconciliation completion, readiness transition, transport reuse, and
    every trading authority remain false.
13. Add no API, worker, trader composition, secret-manager deployment, startup
    readiness change, or external provider call in this local slice.

## Consequences

The repository gains a restart-safe committed prefix for authenticated order
pagination and can prove the exact next allowable page after a completed
commit. It loses liveness conservatively after any crash following durable
preparation, even before permit issuance, because preventing duplicate or
mixed-view requests and overlapping supervisor calls is more important than
automatically finishing that capture.

Automatic traversal supervision, explicit stalled-capture recovery, repeated
durable view comparison, account/position/activity snapshots, stream
buffering/resume, qualified provider revision/execution/correction identities,
authoritative inbox application, whole-account convergence, paper startup, and
the Phase 4 exit gate remain open.
