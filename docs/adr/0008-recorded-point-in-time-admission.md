# ADR 0008: recorded point-in-time admission slice

- Status: Accepted
- Date: 2026-07-15

## Context

ADR 0002 establishes immutable, availability-time market data, but a licensed
vendor, authoritative identifier mapping, and production calendar have not yet
been selected. Phase 1 still needs an executable slice that can prove temporal,
storage, quarantine, manifest, API, and browser contracts without pretending a
synthetic source is vendor-qualified.

## Decision

Phase 1A uses a strict recorded JSONL historical-source adapter containing only
repository-owned synthetic facts. Its source and entitlement records always
identify it as `synthetic_fixture`, `fixture_only`, and unlicensed. API startup
never ingests; the worker is the only composition root for publication.

Bars use half-open intervals and raw prices. Event time is interval end. Vendor
publication, receipt, causal availability, and operational ingestion remain
separate fields. Replay visibility is controlled only by `available_at`.
`REVISED_AS_OF` selects the greatest revision available to the simulated clock;
`FIRST_SEEN` retains the first revision. There is no implicit latest-data read:
historical reads require both an immutable manifest ID and an explicit `as_of`.

The local fixture issues opaque stable security IDs and stores effective-dated,
knowledge-time ticker, venue, tradability, universe, symbol-change, and
delisting facts. Explicit XNYS sessions cover pre/post-DST behavior, a half day,
and an absent holiday session. These contracts are suitable for admission
testing but are not an authoritative security master or production calendar.

Rows are canonically ordered before Parquet serialization. Every object has a
semantic SHA-256 and byte SHA-256 and is sealed by atomic rename before its
catalog transaction begins. A manifest hashes its ordered normalized
partitions, schema, calendar, universe, corporate-action set, raw price basis,
and revision policy. A failed catalog transaction may leave an invisible orphan
object, but it cannot expose an unfinished object through a manifest.

Blocking record-level findings are written to a separate raw quarantine
partition. Valid records may be published in a normalized manifest; blocking
dataset-level findings quarantine the normalized partition and prevent manifest
creation. No check silently repairs, forward-fills, adjusts, or drops a fact.

Corporate-action variants are strictly typed and append-only. Adjusted research
views are a separate future boundary and cannot construct the execution-facing
raw-bar type. Split and dividend effects on the ledger remain a Phase 2
accounting responsibility; Phase 1A proves their data and knowledge-time facts.

## Consequences

The system now exercises the full local data publication and browser path and
can admit a real vendor through the same contracts. Phase 1 is not complete
until a licensed source, entitlement, identifier authority, ETF universe, and
production calendar pass that admission suite. No Phase 1A result authorizes
paper or live trading.
