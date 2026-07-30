# ADR 0071: OpenTelemetry trading-chain correlation

- Status: Accepted
- Date: 2026-07-28

## Context

The Phase 5 exit gate requires one causal trace from market evidence through
target production, risk reservation, submission, broker evidence, fill,
accounting, and reconciliation. Existing domain objects already have immutable
identities and semantic digests. Tracing must correlate those facts without
becoming a second source of truth, carrying credentials, exposing economic
payloads, or granting execution authority.

OpenTelemetry Python traces are stable, and the default Python propagation
format includes W3C Trace Context plus baggage. This system does not need
baggage for trading correlation, and accepting arbitrary baggage would create
an unnecessary secret and personal-data propagation surface.

## Decision

1. Use the official OpenTelemetry Python API and SDK with a version range
   starting at 1.44 and below the next major version.
2. Define a closed, ordered set of trading stages:
   `market_batch`, `target`, `reservation`, `submission_attempt`,
   `broker_event`, `fill`, `ledger_posting`, and `reconciliation`.
3. Correlation consists only of account/environment scope plus, for each
   present stage, an opaque immutable fact ID and its SHA-256 semantic digest.
   The bounded canonical correlation has its own digest. It contains no symbol,
   quantity, price, cash value, broker payload, credential, error body, operator
   text, or strategy output.
4. Each span states its current stage and carries the exact correlation digest
   plus all supplied stage ID/digest pairs. A stage may not be claimed unless
   its exact reference is present. The domain facts remain authoritative;
   telemetry loss or exporter behavior cannot alter trading state.
5. Cross-process propagation uses an explicit W3C Trace Context propagator.
   The carrier must contain `traceparent` and may contain `tracestate`; no other
   key is accepted. In particular, baggage is neither injected nor extracted.
   Keys are lowercase, values are bounded ASCII, and invalid remote contexts
   fail before a consumer span begins.
6. Libraries obtain a tracer through the OpenTelemetry API. Composition roots
   own SDK provider, processor, exporter, sampling, shutdown, and deployment
   configuration. The helper does not mutate the global provider at import
   time and remains safe when the API is backed by its no-op provider. The
   supplied asynchronous provider fixes a 2,048-span queue, 256-span export
   batch, one-second schedule delay, and five-second export timeout so exporter
   backpressure is bounded and cannot become an unbounded trading-path buffer.
7. Trace and span IDs are observability identifiers, not idempotency keys,
   authorization capabilities, durable fact identities, or evidence of
   delivery. Retries may create new spans while retaining the same immutable
   trading references.
8. Runtime composition uses exact domain types and validates their causal
   bindings before adapting them. The current local composer can correlate a
   complete market batch, target, batch reservation, immutable submission
   preparation, canonical broker event, and reducer-derived ledger entry. It
   intentionally leaves `fill` and `reconciliation` absent: the transient
   advanced-risk fill input is not a durable correction-safe fill fact, and the
   existing Phase 4 reconciliation fact is historical non-applying lookup
   evidence rather than an authoritative reconciliation result. Neither may be
   relabeled to make an eight-stage trace appear complete.

## Consequences

Supplied stages can be queried in one trace while every reference remains
checkable against its immutable domain fact. The local composer reports missing
stages explicitly and produces no export receipt or trading authority. W3C
propagation works across worker/process boundaries, and an untrusted carrier
cannot inject baggage or arbitrary metadata.

The supplied provider uses a 2,048-span queue, 256-span export batch, one-second
schedule delay, and five-second export timeout. The application composer runs
only after its immutable facts exist, catches instrumentation failures into a
sanitized non-authorizing result, and never claims exporter delivery.

This local slice supplies instrumentation, exact-type causal composition, and
in-memory/integration conformance tests. A deployment must still produce and
persist an authoritative applied fill with correction-safe identity, an
authoritative reconciliation result bound to that execution/account state,
wire the composer into the deployed trader and reconciliation services, select
and secure an exporter, set retention and access policy, and test exporter
outage behavior. Exporter failure is an alertable observability failure, not
permission to mutate control or broker state.
