# ADR 0022: deterministic clock callbacks and versioned strategy state

- Status: Accepted
- Date: 2026-07-18

## Context

ADR 0020 created a deterministic availability-time market reducer and an exact
complete-batch strategy seam. ADR 0021 connected repository-owned fixture data
to that reducer and sealed callback-free replay evidence. Neither decision
specified how scheduled strategy callbacks interleave with complete batches or
how mutable strategy history can be reproduced without trusting hidden Python
object state.

The existing strategy context and target were also market-batch-only. Reusing a
batch ID for a scheduled callback would forge causality, while adding strategy
output to the existing `ReplayRunManifest` would reinterpret evidence whose
runtime pins explicitly say that strategy, RNG, benchmark, costs, and fills are
not applicable.

This slice must remain a pure synthetic domain capability. It cannot create a
backtest job, worker command, HTTP route, browser result, broker action, or
paper/live authority.

## Decision

1. Preserve `ReplayResult`, `REPLAY_CONTRACT_VERSION`, and the ADR 0021 sealed
   manifest contract unchanged. Add a separate in-memory strategy-replay layer
   that accepts a completed `ReplayResult` from the market reducer, an explicit
   clock schedule, a strategy reducer, and an immutable initial position
   snapshot. Because `ReplayResult` is publicly constructible, the strategy
   layer revalidates exact, unique, canonically ordered, in-interval batches and
   the complete/skipped indexes before invoking a callback; it does not claim
   that the value is a durable ADR 0021 manifest.
2. Represent every schedule entry as a UTC-only `ClockEvent` with a trimmed
   event identity, schedule identity, non-negative sequence, scheduled instant,
   and versioned semantic digest. Exact duplicate event delivery collapses.
   Reusing an event identity with different semantics or assigning two events
   to one schedule/sequence slot fails closed. Sequence order within a schedule
   cannot move backwards in time, and this slice restricts events to the sealed
   market replay interval.
3. The strategy callback order is canonical and independent of caller order.
   The underlying market reducer still orders equal-time facts before their
   watermark. The strategy layer orders every complete batch at an instant
   before clock events at that instant, then orders clocks by schedule,
   sequence, and event identity. Incomplete batches remain sealed evidence but
   do not invoke `on_market`; an independently scheduled clock at that instant
   still invokes `on_clock`.
4. Bind every callback through a typed `DecisionTrigger` containing the kind
   (`market_batch` or `clock`), exact trigger identity, exact trigger digest,
   and UTC `as_of`. `ReadOnlyStrategyContext` contains that trigger, an immutable
   position snapshot, the exact input state, a canonical context digest, and a
   read-only `FixedClock` snapshot. It has no repository, filesystem, network,
   random, or ambient-time escape hatch.
5. Give initialization a separate `StrategyInitializationContext` containing
   only replay start and copied initial positions. It deliberately exposes no
   future batch or schedule contents. A strategy returns generation-zero state
   from `initialize` and an exact `StrategyTransition` from every market or
   clock callback.
6. Carry state externally as `VersionedStrategyState`. It pins strategy ID,
   strategy version, exact configuration digest, state-schema version,
   generation, UTC `as_of`, bounded canonical scalar values, predecessor
   digest, and callback trigger contract digest. Values
   may only be null, bool, bounded int/string, finite exact `Decimal`, or UTC
   datetime. Every callback advances generation exactly once, chains the exact
   predecessor digest, preserves all version pins, and binds the exact trigger.
   Schema changes require an explicit future migration; they cannot be decoded
   implicitly.
7. Generalize `TargetPortfolio` to carry the typed decision trigger and add a
   semantic digest covering every target field, including expiry, target
   symbols/quantities, full-snapshot mode, and rebalance generation. A clock
   callback may therefore express a causal desired portfolio. The current
   Phase 0 target-to-intent converter still requires a complete market trigger
   with an exact reference event and rejects clock-driven targets. Supplying
   causal price/valuation state and execution conversion remains Phase 2B.
8. Capture one immutable runtime pin before initialization: strategy identity,
   version, exact configuration digest, and state-schema version. Initialization,
   every successor, every target, and the final result validate against that
   pin; callback-time metadata drift fails closed. Return a
   `StrategyReplayResult` containing that pin, the market replay digest, clock
   schedule digest, initialization-context digest, initial/final states, and an
   ordered decision transcript. Each decision binds sequence, trigger, context,
   input state, successor state, and the complete target digest or its absence.
   Callback failure returns no result. This slice persists no strategy state or
   transcript; durable jobs, restart checkpoints, and query models remain
   Phase 2C.
9. Extend the architecture check for the new pure reducer files. Imports that
   grant ambient filesystem, process, thread, network, randomness, or wall-clock
   authority are forbidden even when they come from the Python standard
   library.

## Consequences

For deterministic reducer implementations, repeated runs and input permutations
produce identical callback transcripts, state chains, targets, and semantic
digests. Extending a tape or schedule in the future preserves the prior decision
prefix. Position snapshots, strategy configuration, and every target field are
now part of the enclosing transcript evidence rather than implicit callback
inputs.

The Phase 0 walking thread uses this strategy-replay seam and demonstrates one
explicit initialized state and one chained market transition. The reference
strategy also handles clock events without retaining hidden authoritative state.

This completes the planned synthetic Phase 2A callback/state boundary, but it is
not an economic backtest. It adds no database migration, strategy run record,
benchmark, costs, fills, ledger expansion, worker lifecycle, API/browser
capability, provider request, broker connection, or paper/live readiness. Phase
2B execution reducers and Phase 2C durable research workflows remain next, and
the external Phase 1 vendor-admission gate remains open.

Strategy implementations are trusted in-process code at this stage. The import
guard constrains the repository-owned reducer modules, not arbitrary third-party
callback objects; process isolation and a broader conformance boundary remain
future hardening. This unreleased `0.1.0` slice intentionally replaces the prior
internal Python strategy/context constructors with the explicit reducer API.
Phase 2B must retain the enclosing decision/configuration evidence when
converting targets, or carry the configuration digest forward explicitly.
