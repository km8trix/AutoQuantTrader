# ADR 0024: canonical order and execution lifecycle reducer

- Status: Accepted
- Date: 2026-07-19

## Context

ADR 0023 converts a causal portfolio target into an immutable intent batch, but
the only order model remains the Phase 0 walking-thread shortcut with `working`
and `filled` states. That model cannot represent submission evidence, broker
acceptance or rejection, partial fills, cancel acknowledgement, late fills, or
execution corrections without mutable hidden state.

The next Phase 2B boundary must define these facts before a simulated broker,
expanded ledger, or durable order store can depend on them. It must remain pure
and deterministic, and it must not grant submission authority merely because an
order value can be reduced.

## Decision

1. Add a separate pure lifecycle reducer and leave the Phase 0 `Order`, `Fill`,
   and `SimulatedBroker` compatibility path unchanged.
2. Begin with immutable `OrderSubmission` evidence that binds the exact intent
   and risk payload digest, risk-decision ID, submission-attempt ID, deterministic
   order/client IDs, and explicit UTC submission time. Construction does not
   consume or prove a risk approval; the effectful submission boundary remains
   responsible for that authority.
3. Accept exact immutable broker events with one normalized, positive,
   contiguous per-order sequence. Event and sequence reuse with conflicting
   semantics fails closed. Exact duplicate delivery collapses, and event and
   receipt times cannot regress with sequence.
4. Model broker acceptance, rejection, cancellation, execution, and execution
   correction explicitly. One broker-order identity is immutable for the local
   order. Rejection cannot follow acceptance or execution. Cancellation requires
   a local cancel request bound to the exact prior reducer-produced non-terminal
   state.
5. Treat executions as revision chains. An initial execution is revision one;
   every correction names the exact current predecessor and advances one
   revision. The projection selects only each chain head while the transcript
   retains every superseded report.
6. Derive cumulative fill quantity, remaining quantity, fees, and status from
   current execution heads using the versioned exact decimal policy. Cumulative
   quantity can never exceed the order. A correction may reopen a filled order,
   and a late fill after cancellation remains conserved; a full late fill
   produces `filled`, while a partial late fill retains `canceled`.
7. Hash the complete submission, cancel request, broker transcript, selected
   executions, quantities, fees, status, and reducer time into a semantic order
   state. Caller ordering and ambient decimal context cannot change the result.
8. Extend the architecture guard so this reducer cannot acquire filesystem,
   process, network, thread, randomness, or ambient wall-clock authority.

## Consequences

Simulation and future broker adapters can share one order state machine, and
ledger work can consume corrected execution heads without losing the append-only
history. Duplicate delivery, overfills, sequence gaps, identity drift, forged
cancel state, and broken correction chains halt deterministically.

This slice is in-memory and does not create a `BrokerPort`, durable order/event
tables, atomic intent-batch risk, ledger postings, settlement, coordinator
lease/fencing, worker job, API/browser capability, or paper/live authority.
Those remaining Phase 2B boundaries stay gated.
