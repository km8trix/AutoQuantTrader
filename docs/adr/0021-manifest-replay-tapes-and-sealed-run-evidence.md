# ADR 0021: manifest replay tapes and sealed run evidence

- Status: Accepted
- Date: 2026-07-18

## Context

ADR 0020 defined deterministic availability-time replay over domain events, but
it intentionally did not connect that reducer to the Phase 1 immutable data
plane or persist a run. The existing `bars_as_of` reader is a causal snapshot:
it applies one cutoff and collapses each observation to one revision. Reusing
it as a tape would erase correction-chain and late-arrival evidence.

A replay schedule also cannot be inferred from rows. The reference fixture has
a quarantined 13:34 record, so row-derived coverage would silently omit that
decision slice rather than prove it incomplete. Likewise, deriving a watermark
from the latest observed revision would let future facts rewrite earlier
decision clocks.

Phase 1 remains open for licensed vendor admission. This slice must support
repository-owned fixture development without creating vendor, broker, paper,
live, API, worker-launch, or browser authority.

## Decision

1. Keep `ManifestBarReader.bars_as_of` snapshot-only. Add a separate
   `ManifestReplayTapeReader` that loads every in-scope `RawBar` revision and
   maps its event identity, observation identity, source sequence, supersession,
   event time, availability time, instrument, symbol, and close exactly into
   `MarketEvent`.
2. Resolve a rich manifest descriptor before reading bytes. Reproduce the
   content-addressed manifest and partition identities; require ordered,
   contiguous, normalized, published, non-quarantined members; and bind source,
   schema, raw price basis, revision policy, calendar, universe,
   corporate-action, tzdata, object byte/semantic hashes, sizes, row counts, and
   time ranges. Reference hashes and object/partition semantic checksums carry
   explicit contract versions. New `raw-bar-v2` objects use post-Arrow
   `arrow-v2` semantics and persisted-row `persisted-v2` references; migrated
   `raw-bar-v1` facts remain explicitly `input-v1` and retain their legacy
   identity formulas. Read limits bound partitions, compressed bytes, rows,
   reference rows, and watermarks. Parquet bytes, exact Arrow schema, checksum
   marker, decoded row counts, ranges, currency, source, interval, schema, and
   price basis fail closed.
3. Restrict this Phase 2A path to unlicensed `synthetic_fixture` or
   `recorded_fixture` sources with fixture-only entitlement. Vendor manifests
   are categorically rejected even if catalog fields are forged.
4. Build the inclusive replay plan only from the pinned calendar and effective,
   causally available universe. Coverage endpoints must align to calendar bar
   completions. The decision lag is an explicit immutable input; `closed_at` is
   `event_time + decision_lag`, never a function of observed rows. Revision
   policy comes from the dataset manifest; missing data remains SKIP and late
   data remains HALT.
5. Retain two provenance layers. `source_tape_sha256` binds the full selected
   RawBar semantics and ordered partition proofs. The existing replay tape and
   result hashes bind the projected events, watermarks, and reducer output. A
   close-only result therefore cannot be presented as full input provenance.
6. Persist only a completed, content-addressed `ReplayRunManifest`. Its input
   identity pins dataset/reference proofs; each ordered partition's identities,
   canonical object key, Parquet format, byte size, row count, byte/semantic
   digests and semantic contract version, event-time extent, and
   availability-time extent; each reference digest and its independent contract
   version; the exact plan; adapter/watermark/replay/batch/arithmetic contract
   versions; source revision, dirty-patch digest, dependency lock, schema
   revision, and Python/PyArrow runtime. Strategy, benchmark, cost, fill, and RNG
   fields are explicitly `not_applicable`; this is replay evidence, not an
   economic backtest. Wall-clock insertion time, credentials, payload bytes, and
   mutable status are excluded.
7. Compute and validate the complete tape and `ReplayResult` in memory, then
   lock and rederive the catalog descriptor, authenticate the referenced object
   snapshot from that descriptor inside the sealing transaction, and atomically
   insert one sealed-success row. The successful authenticated read is the
   storage-evidence linearization point. Identical retries are no-ops. The
   same input identity with different output, changed catalog pins, malformed
   canonical payload, or lossy SQL read-back conflicts. Failures create no run
   row. Repository reads and readiness strictly decode every retained payload,
   verify its duplicated indexed columns, and compare every durable partition
   and object pin against the same immutable catalog facts accepted by the tape
   reader. SQL and external object-store availability cannot be committed
   atomically: the local content-addressed adapter therefore requires immutable
   retention, and a future cloud adapter must pin object versions and enforce
   versioning plus deletion-resistant retention such as Object Lock.
8. Do not add a replay route, command, worker lifecycle, browser view, feature
   capability, strategy execution, benchmark, or performance report. Mutable
   queued/running/failed/canceled job history belongs to Phase 2C.
9. Version integrity algorithms instead of reinterpreting old catalog rows.
   Migration 0006 labels existing object and partition semantic checksums
   `input-v1` and existing reference content hashes `input-v1`. Those values
   retain their original meaning: pre-Arrow caller values and ingestion-order
   reference values, respectively. New `raw-bar-v2` publications use
   domain-separated `arrow-v2` checksums over schema-coerced persisted values
   and `persisted-v2` hashes over the exact retained reference rows. The v2
   Parquet checksum marker is part of the content-addressed object bytes, and
   checksum/hash contract versions are retained in partition, manifest, tape,
   and run evidence. Legacy replay verifies exact bytes and strict decoded
   domain facts without falsely claiming its input checksum is reproducible;
   a legacy reference receipt that cannot be reconstructed from retained rows
   fails explicitly rather than being silently reinterpreted.
10. Preserve exact retries across the integrity-contract upgrade. If the current
    v2 ingestion identity does not exist but the exact pre-0006 identity does,
    require the legacy job identity, source checksum, and strict manifest proof
    to agree, then reconstruct the complete v1 publication through the normal
    immutable publication transaction. This reproduces the old normalization,
    checksum, reference-order, partition-identity, and manifest-identity
    formulas and verifies every object, quality, admission, and catalog fact.
    It does not treat job existence as sufficient proof, convert old facts to
    v2, or downgrade a changed source snapshot to the legacy contract.

## Consequences

The fixture's quarantined 13:34 bar produces a retained incomplete/skipped
batch because its slice comes from the calendar, not rows. A one-minute decision
lag includes the 13:31 correction available exactly at 13:32; a five-second lag
deterministically raises `LateMarketEvent` and persists nothing. Neither case
changes the immutable clock after facts are observed.

The Phase 1 object plane now feeds the Phase 2 reducer through a verified,
all-revision boundary, and successful reducer evidence is reproducible and
tamper-evident. This still is not a usable backtest product. Versioned strategy
state and clock callbacks remain Phase 2A; execution/ledger reducers remain
Phase 2B; durable job orchestration, query APIs, and the browser Backtests
workspace remain Phase 2C.

An upgraded local worker can therefore retry its exact legacy fixture without
colliding with the new reference hash contract. Fresh ingestion remains v2;
unverifiable legacy receipts and changed inputs fail closed rather than using
the compatibility path.
