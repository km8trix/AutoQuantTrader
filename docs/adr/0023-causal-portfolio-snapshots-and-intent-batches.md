# ADR 0023: causal portfolio snapshots and canonical intent batches

- Status: Accepted
- Date: 2026-07-19

## Context

ADR 0022 completed the strategy callback boundary and allowed market- or
clock-triggered targets, but the Phase 0 converter accepted one current quantity
and one complete market batch. It could not convert a portfolio atomically,
could not price a clock-triggered target, and did not carry the strategy
configuration digest into risk's execution payload.

This first Phase 2B slice must establish the evidence boundary before adding
order lifecycle, fills, or expanded accounting. It remains an in-memory pure
domain capability and grants no broker, paper, or live authority.

## Decision

1. Add an immutable `PortfolioSnapshot` containing canonically ordered current
   positions and causal prices at one exact UTC `as_of`. Every price binds the
   complete source `MarketEvent` digest and must have been available by the
   snapshot time. Duplicate instruments, mutable collections, non-whole
   positions, and future-available prices fail closed.
2. Add a pure target-to-`OrderIntentBatch` reducer. It accepts both market- and
   clock-triggered targets because pricing is supplied by the explicit snapshot,
   not inferred from the trigger. Target and snapshot times must match exactly.
3. A full-snapshot target converts the union of desired and current instruments,
   so omitted holdings become sell intents to zero. A partial target changes
   only named instruments. Zero deltas remain represented by an evidence-bearing
   empty batch rather than a fabricated order.
4. Order intents are unique and sorted by instrument. Every intent carries its
   enclosing batch ID, complete target digest, strategy identity/version,
   strategy configuration digest, exact decision trigger, and causal reference
   price event. Intent and batch digests cover this evidence; the mandatory risk
   payload hash covers it as well.
5. `TargetPortfolio` now carries the exact strategy configuration digest and its
   semantic contract advances to v2. Strategy replay verifies that digest
   against the captured runtime pin before returning a result.
6. Preserve `target_to_order_intent` as the Phase 0 one-position compatibility
   adapter. It builds the same canonical snapshot and batch internally, then
   returns zero or one intent. The walking-thread HTTP contract and persistence
   schema remain unchanged.

## Consequences

Caller iteration order cannot alter snapshots, batches, intents, or digests.
Clock callbacks can now produce execution candidates without pretending that a
clock is a market batch, while future or missing prices halt conversion. Full
portfolio semantics and strategy configuration remain traceable through risk.

This is not yet an economic backtest or complete Phase 2B execution model. It
adds no durable intent batch, ledger expansion, simulated broker lifecycle,
atomic batch risk reservation, account lease/fencing, worker job, API route, or
browser workflow. Those Phase 2B and Phase 2C slices remain gated.
