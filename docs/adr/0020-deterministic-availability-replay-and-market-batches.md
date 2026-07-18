# ADR 0020: deterministic availability-time replay and watermark-complete market batches

- Status: Accepted
- Date: 2026-07-18

## Context

The point-in-time data plane can normalize immutable facts and answer explicit
causal as-of queries, but an as-of state view is not an event tape. The
repository had no advancing simulated clock, no total order for simultaneous
facts, no explicit watermark closure, and no complete cross-sectional strategy
batch. The Phase 0 strategy received one event and its frozen context still
wrapped caller-owned mutable state.

Phase 1 remains open on licensed provider, identity, calendar, corporate-action,
and independent admission evidence. That external gate must not prevent the
pure canonical engine from being developed against repository-owned synthetic
facts, and synthetic replay must not imply vendor or trading authority.

## Decision

Implement the first Phase 2 engine slice in the synchronous, standard-library
domain core. It is synthetic-only and has no provider request, persistence,
broker, paper, live, API, or browser-launch effect.

1. Replay time is UTC and advances only by a nondecreasing SimulatedClock.
   Event/effective time never grants knowledge; visibility is controlled by
   available_at.
2. The canonical total-order key is:

       (
         available_at,
         phase,
         source_id,
         source_sequence_is_missing,
         source_sequence_or_zero,
         event_kind,
         event_time,
         instrument_id,
         observation_id,
         revision,
         event_revision_id,
       )

   FACT=0 and WATERMARK_CLOSE=1. A missing source sequence is represented by
   the (is_missing, value) pair rather than a numeric sentinel. Therefore all
   facts available at time T reduce before a watermark closing at T, and caller
   input order cannot break ties. Watermarks are then validated in canonical
   closed order: event_time_through must be nondecreasing, so availability-time
   replay cannot close an older event-time slice after a newer one.
3. MarketWatermark keeps the exact event-time frontier separate from
   availability-time closed_at. Its expected instruments are a sorted, unique,
   externally pinned set; arrivals never expand that set.
4. Replay proof-constructs every sealed MarketBatch from a validated watermark
   and its causally selected revision chains; callers cannot directly
   instantiate a complete batch. A batch contains at most one selected event
   per expected instrument, records received and missing sets exactly, and is
   complete only when the two sets cover the expected set without overlap. Its
   as_of is the watermark's closed_at.
5. The initial missing-data policy is SKIP: an incomplete batch is retained as
   explicit evidence and never invokes the strategy. The initial late-event
   policy is HALT: a fact with availability after its watermark fails the run
   and never reopens or mutates a sealed batch.
6. Exact duplicate deliveries collapse idempotently. Reusing an event or
   watermark identity for unequal semantics fails closed. Correction chains
   must start at revision 1, remain contiguous, name the immediately superseded
   revision, keep one source, preserve source-sequence presence, never move
   availability backwards, and use increasing source sequences when present.
   Across the whole tape, a (source, observation identity) pair is bound to one
   instrument and event-time revision chain; reusing it for another chain fails
   closed. FIRST_SEEN and REVISED_AS_OF are explicit replay policies.
7. Batch and replay semantic digests use canonical JSON with explicit field
   types and UTC serialization. Finite decimals use compact,
   context-independent canonical text, including one canonical zero. Phase 2
   deterministic identifiers use typed, length-safe canonical material rather
   than delimiter-joined stringification. Identity-bearing portfolio and risk
   arithmetic uses the explicit `decimal64-e63-exact-v1` policy: 64 significant
   digits with fixed exponent bounds and rounding or inexact results trapped,
   independent of the ambient process context. Its version is bound into the
   intent payload hash. SQL-bound decimals must be exactly representable by
   `NUMERIC(28,10)`; construction rejects values outside that contract and
   transactional read-back verification fails closed on lossy dialect storage.
   Wall-clock telemetry is excluded.
   These first digests cover the local replay result; a later durable run
   manifest must also pin dataset, calendar, universe, corporate-action,
   strategy, runtime, and cost-model versions.
8. The strategy callback is the existing canonical strategy seam, changed from
   a single event to MarketBatch. Its context copies positions into an
   immutable, sorted snapshot and binds the exact batch identity and semantic
   digest, not merely a shared causal as_of. A TargetPortfolio is bound to that
   exact decision batch and carries its position targets as an immutable,
   canonically sorted, unique tuple. The deterministic walking thread now
   traverses this same batch boundary.
9. Complete-batch callbacks receive a read-only clock snapshot. Replay validates
   identity, scope, and late-event constraints before invoking them. Durable or
   external side effects remain outside this pure callback contract.
   ReplayResult records every strategy-eligible proof in `complete_batch_ids`,
   whether or not a callback was installed; `skipped_batch_ids` records
   incomplete batches.

The first implementation accepts domain MarketEvent facts. A separate next
slice must build a manifest-pinned all-revision tape adapter from canonical
RawBar facts; the existing bars_as_of snapshot reader must not be repurposed as
an availability-ordered tape. That later boundary is defined by
[ADR 0021](0021-manifest-replay-tapes-and-sealed-run-evidence.md).

## Consequences

Cross-sectional decisions no longer depend on symbol arrival or input order,
facts exactly on the watermark boundary are handled inclusively, incomplete
coverage cannot silently reach a strategy, regressing watermarks and cross-chain
observation reuse fail closed, and later facts cannot rewrite an earlier
decision batch. Complete batches, strategy contexts, and immutable targets share
one exact decision identity. The walking thread remains deterministic and
retains its next-event fill and mandatory risk boundaries.

This is a core contract, not a usable backtest product. The Backtests browser
route remains reserved, the API exposes no replay command or result, no
benchmark claim is made, and no backtest capability is advertised. Durable run
orchestration, strategy state and clock callbacks, ledger/reducer expansion,
reports, and browser workflows remain Phase 2 work. ADR 0021 subsequently adds
the fixture-only manifest adapter and sealed replay evidence without widening
those product capabilities.
