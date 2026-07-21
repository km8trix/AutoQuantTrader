# ADR 0029: conservative source-bound simulated broker

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0024 defines the canonical order and execution lifecycle, and ADR 0025
through ADR 0028 define the financial projections that can consume that
transcript. The remaining Phase 2B simulation boundary must turn an authorized
intent into canonical broker facts without bypassing mandatory risk or using
market information that was unavailable when the order became active.

The retained `MarketEvent` contract has a close price but no quote, observed
spread, high/low path, or volume. A simulator therefore cannot honestly infer
queue position, participation, partial fills, or limit-order eligibility from
the current evidence. Session boundaries, price costs, and fees must also be
explicit inputs rather than ambient calendar or hidden model assumptions.

## Decision

1. Add a narrow provider-neutral submission `BrokerPort` and a separate
   conservative simulated implementation for explicit regular-hours sessions,
   including shortened half-days, and whole-share DAY market orders. Leave the
   Phase 0 compatibility broker unchanged, and grant neither paper nor live
   broker authority through this port. Cancellation, recovery, reconciliation,
   and update streams remain separate future capabilities.
2. Require exact regular-session evidence containing the exchange session and
   pinned calendar identity, version, and digest. Intent creation, decision,
   submission, activation, and eligible market facts must fit that explicit
   session; the simulator never consults an ambient clock or calendar.
3. Make submission structurally dependent on consuming a persisted, current,
   exact-payload, single-use risk approval. Preflight the approval window and all
   derivable tape/model failures before consumption. Missing, expired,
   mismatched, or already-consumed approval fails before an order submission or
   simulated broker event can be produced. The later atomic risk boundary must
   still transact reservation, consumption, and submission against unexpected
   adapter/process failure. ADR 0030 refines this rule for its explicit
   authorization caps: static cap/session/currency defects remain preflight
   failures, while a later source-price or cash-cap breach is an auditable
   post-acceptance working outcome rather than a retroactive submission failure.
   For that capped path, the first relevant future slice being incomplete, or
   its exact event producing invalid execution arithmetic, is likewise retained
   as an accepted, working deferred-source block with exact evidence; neither
   condition can undo authorization consumption or acceptance.
4. Canonicalize and validate the supplied session tape independently of caller
   ordering. Collapse exact duplicate batches; reject cross-batch event,
   observation, and watermark identity conflicts, conflicting same-frontier
   slices, and availability-order watermark regressions; and bind the canonical
   tape into the simulation result.
5. Accept the order immediately at the approval-consumption time, apply the
   model's explicit non-negative activation latency, and consider only the first
   sealed `MarketBatch` frontier whose event time is strictly later than
   activation. Its exact submitted-instrument event is the sole price source
   only when the batch is complete. A same-time event, an older event delivered
   later, or an incomplete first relevant future batch cannot establish a fill;
   the incomplete batch is never skipped for a later complete slice.
6. Fill the complete approved quantity once or not at all. Use the source
   event's close price and a versioned fixed adverse price model: add explicit
   per-share half-spread and slippage amounts for buys and subtract them for
   sells. Charge an explicit fixed fee plus a per-share fee, and reject
   non-positive prices or arithmetic that cannot fit the exact persisted decimal
   contract.
7. Produce deterministic canonical broker acceptance and execution events and
   pass them through the ADR 0024 lifecycle reducer. Record execution occurrence
   at the source event time and receipt at the sealed batch's availability time;
   deterministic identities and semantic digests cannot depend on caller order
   or ambient decimal context.
8. Preserve separate fill evidence binding the accepted working-order state,
   exact source batch and event identities and digests, session digest, model
   digest, reference price, every adverse-cost component, and every fee
   component. The simulation result binds that evidence, the canonical broker
   transcript, and the reducer-produced order state.
9. When no strictly later eligible event exists in the exact supplied tape,
   return an accepted working order with an explicit no-eligible-event outcome
   and a deterministic observation horizon covering activation and that tape.
   This is a prefix result, not proof of end-of-session expiry. DAY scope limits
   what this simulator accepts; it does not justify fabricating an expiry,
   cancellation, rejection, or fill that is absent from the canonical broker-
   event contract.
10. Fail closed outside this deliberately narrow model. Limit and stop orders,
    observed-spread or OHLC path inference, volume participation, liquidity and
    queue modeling, partial fills, broker expiry, order replacement, paper/live
    submission, ambient calendars, and provider reconciliation remain
    unsupported.

## Consequences

Backtests can now obtain a deterministic, source-bound order transcript from an
exactly authorized intent. Strictly later event selection prevents same-event
lookahead, explicit session/model evidence makes assumptions auditable, and the
canonical lifecycle and ledger reducers can consume simulated executions
without a simulation-specific accounting path.

The model is conservative about knowledge and fail-closed boundaries, not a
claim of realistic liquidity or fill probability. Full fills and fixed costs are
declared assumptions necessitated by the current close-only evidence. ADR 0030
implements the process-local atomic intent-batch risk boundary described above.
The next implementation step is the account-scoped coordinator lease/fencing
contract and data model. Durable batch/order persistence, recovery,
reconciliation, richer execution models, and paper/live trading authority
remain gated.
