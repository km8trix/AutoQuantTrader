# ADR 0006: canonical engine boundary and build strategy

- Status: Accepted
- Date: 2026-07-15

## Context

A third-party backtesting engine could accelerate research features, but allowing
one engine for backtests and another for shadow or trading would create two
decision paths with different clocks, ordering, fill, accounting, and risk
semantics.

## Decision

Build the small canonical event-driven engine described by the architecture as
part of the modular monolith. Its synchronous domain core owns simulated time,
availability-time ordering, strategy callbacks, target conversion, accounting,
risk, order reduction, and deterministic replay. Market-data, storage, broker,
and wall-clock behavior enter through ports.

DuckDB, Polars, and vectorized notebooks may accelerate data preparation and
hypothesis exploration. A mature third-party library may be adopted behind a
port for calendars, analytics, optimization, or broker connectivity, but it may
not become a second promotion or execution path. Replacing the canonical engine
requires differential replay evidence and a superseding ADR.

## Consequences

The first engine supports only the locked v1 slice and grows through verified
reducers and event contracts. This trades breadth for exact replay, explicit
causality, and backtest-to-shadow parity.
