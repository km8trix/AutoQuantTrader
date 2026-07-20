# ADR 0025: append-only execution ledger reducer

- Status: Accepted
- Date: 2026-07-19

## Context

ADR 0024 provides an immutable order and execution transcript with exact
predecessor-linked corrections, but the Phase 0 ledger accepts only one mutable
walking-thread buy fill. It cannot consume partial fills, sell executions, late
fills, or trade busts without either overwriting prior financial history or
double-posting corrected economics.

The next Phase 2B boundary must convert the canonical execution transcript into
balanced append-only financial postings. It must establish cash, security-unit,
fee, and external cash-flow conservation before durable storage or a simulated
broker depends on accounting state. The existing evidence does not yet define
tax lots, cost-basis policy, realized P&L, settlement, or corporate actions, so
this slice must not invent those semantics.

## Decision

1. Add a separate pure Phase 2 execution-ledger reducer and leave the Phase 0
   `Ledger`, `Fill`, and walking-thread compatibility path unchanged.
2. Accept only exact reducer-produced `CanonicalOrderState` values. Re-reduce
   every order before posting, collapse exact duplicate snapshots, and reject
   conflicting snapshots for one order identity.
3. Convert every initial execution report into one balanced append-only entry.
   Buys debit execution trade-value clearing and execution fees while crediting
   cash; sells reverse trade-value and units, debit cash net of fees, and debit
   fees. Every entry binds the complete source-event semantic digest.
4. Convert each execution correction into the exact economic delta between the
   new report and its current predecessor. Quantity, price, fee, cash, and
   trade-value changes can debit or credit their accounts. A zero-quantity
   correction therefore reverses the original fill without removing it.
5. Record explicit contribution and withdrawal facts as balanced cash/equity
   entries with separate effective and recorded UTC times. Identity reuse with
   conflicting semantics fails closed; exact duplicate delivery collapses.
6. Derive cash, security units, execution trade value, and fee expense solely by
   folding canonical entries. Caller ordering and ambient decimal context cannot
   change entries, balances, or the semantic state digest.
7. Use a clearly named `clearing:executions:<instrument>` account for execution
   notional. It is not a securities cost-basis asset or a realized-P&L account.
   This keeps cash and unit conservation exact without silently selecting FIFO,
   average-cost, settlement, tax, or mark policy.
8. Extend the architecture guard so the reducer cannot acquire filesystem,
   process, network, thread, randomness, or ambient wall-clock authority.

## Consequences

Order replay can now produce stable balanced financial history for partial
fills, sells, late fills, fees, corrections, and busts. Financial facts remain
append-only, and current cash and unit balances are rebuildable rather than
mutable sources of truth.

Trade-value clearing may retain an amount after a position returns to zero; that
amount is deliberately not labeled realized P&L. A later ledger slice must add
explicit account policy, lots/cost basis, realized and unrealized P&L, marks,
settlement, dividends, splits, and position transfers before the expanded ledger
is complete. This slice creates no durable ledger table, broker effect, atomic
batch risk authority, coordinator fencing, API/browser capability, or paper/live
trading authority.
