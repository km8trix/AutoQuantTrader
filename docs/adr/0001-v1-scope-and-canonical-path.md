# ADR 0001: v1 scope and canonical decision path

- Status: Accepted
- Date: 2026-07-15

## Context

Trading correctness and operational safety become substantially harder as asset
classes, sessions, order types, and concurrently active strategies expand.

## Decision

V1 supports one operator, one trade-enabled strategy per brokerage account, a
small fixed universe of liquid U.S. ETFs, regular market hours, long-only whole
shares, one-minute-or-slower data, and DAY market orders with next-event
activation. Research may evaluate multiple strategies.

The promotion backtest, replay, shadow, paper, and live paths share the same
strategy, portfolio, accounting, order, and risk domain code. Vectorized
notebooks may generate hypotheses but cannot supply promotion evidence.

## Consequences

Options, futures, crypto, shorting, fractional shares, extended hours, order
replacement, shared-account strategy sleeves, and sub-second trading require a
new ADR before implementation.
