# ADR 0003: ledger accounting and mandatory risk

- Status: Accepted
- Date: 2026-07-15

## Context

Mutable position rows cannot reliably explain fees, cash movement, late fills,
corporate actions, or corrections. Sequential per-order checks can also reserve
the same cash twice.

## Decision

Balanced append-only ledger entries are the financial source of truth. Cash,
positions, lots, and P&L are rebuildable projections.

Strategies emit target portfolios. Portfolio construction creates an atomic
intent batch. Risk evaluates the complete batch against one versioned snapshot
and atomically persists a single-use decision plus cash/share/notional/exposure
reservations. Execution is structurally unreachable without a current approval.
Reservations include approved-unsent, unknown, working, partially filled, and
pending-cancel exposure.

## Consequences

Accounting conservation and risk-reservation conservation are property-tested.
Cancel requests do not release exposure until confirmed economically complete.
