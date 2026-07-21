# ADR 0033: durable fixture-only research workflow

- Status: Accepted
- Date: 2026-07-21

## Context

The Phase 2 domain contracts can produce deterministic reports and run
manifests, but researchers also need a durable path to select approved inputs,
launch work idempotently, recover an abandoned worker claim, and inspect the
result in the browser. An unrestricted strategy runner or arbitrary dataset
launcher would exceed the evidence and security boundaries implemented in this
phase.

## Decision

1. Store immutable, content-bound strategy versions, parameter schemas,
   validated configurations, and fixture definitions in a dedicated research
   catalog. A fixture pins its dataset manifest and source tape, sealed replay,
   strategy version and configuration, benchmark, cost model, fill model, and
   metric conventions. Registration is idempotent for exact facts and rejects a
   conflicting reuse of an identity.
2. Accept a launch only when every supplied input exactly matches a registered
   catalog tuple. The current catalog contains one repository-owned synthetic
   golden fixture: a raw-price buy, stock split, dividend, and exit lifecycle.
   Arbitrary code, parameters, uploads, datasets, replays, symbols, date ranges,
   and model substitutions are outside this workflow.
3. Derive a job identity from the local operator and bounded idempotency key.
   Retrying the same key and exact input returns the existing job; changing the
   input is a conflict. Persist the request, an append-only queued/running/
   terminal event chain, and one launch audit fact. A lockable head is only a
   compare-and-swap projection of that reconstructable history.
4. Give workers bounded SQL claims. A current worker may renew its claim and is
   the only actor allowed to complete or fail that attempt before expiry. After
   expiry, another claim increments the attempt number; the stale worker cannot
   publish a terminal result. PostgreSQL claim selection uses row locking with
   skip-locked semantics, while SQLite uses its serialized write transaction.
5. The local fixture worker idempotently installs the golden catalog, claims at
   most one job, executes the deterministic golden runner, and commits either a
   verified success or a bounded failure classification. Raw exception text is
   not persisted. The continuously running worker polls for additional jobs;
   `--once` processes at most one.
6. On success, atomically bind the terminal job event to one immutable run
   manifest and report. The manifest must reproduce every immutable job input
   and reference the report's semantic and artifact digests. The report retains
   separately hashed semantic, artifact, and browser-query payloads containing
   metrics, equity, trades, positions, ledger trace, measurement conventions,
   and provenance. Reads authenticate those digests and fail closed on malformed
   or conflicting payloads.
7. Expose durable catalog, job, and completed-report queries through the local
   API. Enable launch only when durable persistence and a validated loopback
   transport boundary are available. Bootstrap issues an eight-hour,
   process-bound, signed `HttpOnly`, `SameSite=Strict` capability cookie and a
   CSRF token; launch also requires a bounded `Idempotency-Key`. Local-auth CORS
   origins must be literal loopback HTTP origins. The API either binds directly
   to loopback or uses explicit trusted-loopback-proxy mode; the checked-in
   Compose model publishes that container listener only on `127.0.0.1`.
   Capabilities intentionally expire on process restart.
8. Provide browser Strategies and Backtests pages that display immutable
   versions, configurations, and pins; submit only catalog-provided launch
   inputs; poll queued or running jobs; show append-only history; and render the
   verified report metrics, equity curve, trades, positions, ledger trace, and
   provenance. Development fixtures remain explicit fallbacks, not durable
   production data.

## Consequences

The browser now drives a reproducible, auditable local research loop from an
immutable selection through a recoverable worker job to retained result
evidence. Exact launch retries are safe, concurrent workers cannot complete the
same active claim, and report corruption makes the workflow unavailable rather
than silently changing a result.

This is not a general backtesting service or a deployment/promotion path. It is
limited to the built-in synthetic golden fixture, a loopback-scoped signed
launch capability plus CSRF, SQLite or PostgreSQL persistence, and the
implemented deterministic worker. The local capability is not user identity
authentication.
There is no arbitrary strategy execution, user-authored parameter search,
licensed historical-data launch, remote multi-user authorization, paper/live
execution, or promotion authority.
