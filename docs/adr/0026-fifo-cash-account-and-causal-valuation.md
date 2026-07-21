# ADR 0026: FIFO cash account and causal valuation

- Status: Accepted
- Date: 2026-07-20

## Context

ADR 0025 establishes balanced append-only cash-flow and execution postings, but
its execution trade-value clearing balance is deliberately not securities cost
basis or realized P&L. The implementation plan requires an explicit account,
lot, fee, and valuation policy before portfolio state can drive later risk and
simulated-broker work.

The first vertical slice is long-only, whole-share US ETF trading in a cash
account. The account projection must remain deterministic under duplicate input,
late execution corrections, and ambient decimal-context changes. It must not
pretend that unrecorded marks, settlement, tax elections, margin, shorting, or
corporate actions are already supported.

## Decision

1. Add a separate pure, account-bound projector that consumes a required stable
   account identity plus the same exact cash-flow and canonical order facts as
   the execution ledger. Bind both the account identity and resulting ledger
   semantic digest into the projection.
2. Adopt versioned FIFO trade-date cost basis for the initial cash-account
   policy. Each current buy execution head creates one lot at execution price;
   current sell heads consume the oldest open lots first. Execution fees are
   expensed immediately and are not capitalized into lot basis.
3. Rebuild the complete lot book from current execution-chain heads on every
   projection. Corrections therefore replace prior execution economics without
   mutating ledger history. A corrected history that would sell more shares than
   the FIFO book owns fails closed as an unsupported short position.
4. Preserve the initial execution occurrence and receipt times as a corrected
   execution's FIFO ordering key. The later correction report changes economics,
   not the original trade's place in the account history.
5. Require explicit immutable position marks for every open instrument. Marks
   carry effective and recorded UTC times; no mark recorded after the caller's
   explicit valuation time may enter the projection. Exact duplicate facts
   collapse, while mark/source identity reuse with changed semantics halts.
6. Project open lots, quantity, cost basis, market value, gross realized P&L,
   execution fees, net realized P&L, unrealized P&L, cash, exposure, and equity
   with versioned context-independent decimal arithmetic.
7. Reconcile projected position quantities and execution fees exactly to the
   append-only ledger. A broker execution identity cannot name lots in multiple
   orders. Caller order and exact duplicate order/cash/mark delivery cannot
   change the projection or semantic digest.
8. Make the canonical account state proof-constructed by the projector rather
   than publicly instantiable. The projector derives the ledger, current
   execution heads, FIFO lots, positions, balances, P&L, exposure, and equity
   from source facts. Revalidation checks canonical nested evidence and
   independently re-derives aggregate account totals; a caller cannot inject a
   forged aggregate or use `dataclasses.replace` to create one.
9. Extend the architecture guard so this projector cannot acquire filesystem,
   process, network, thread, randomness, or ambient wall-clock authority.

## Consequences

The Phase 2B account state now has explicit, testable economics rather than an
ambiguous trade-value balance. Corrected fills deterministically rebuild FIFO
lots and both realized and unrealized P&L. Closed positions retain their realized
trace without requiring a current mark, while every open position requires
causally available valuation evidence.

This is trade-date cash-account accounting, not a tax-lot election service or a
broker statement model. Settlement cash states, receivables/payables, position
transfers, dividends, splits, mark corrections, margin, shorting, multi-currency
translation, durable projections, atomic batch risk, coordinator fencing,
broker effects, and trading authority remain gated.
