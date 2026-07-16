# ADR 0002: point-in-time data and storage

- Status: Accepted
- Date: 2026-07-15

## Context

Mutable latest-value datasets introduce look-ahead, correction, and
reproducibility errors. Bulk research scans can also contend with the operational
order ledger.

## Decision

Market events retain event/interval time, vendor publication, receipt,
availability, ingestion, source sequence, schema, and revision identity.
Backtests replay `available_at`. Corrections append new facts.

Raw, normalized, and feature datasets are immutable content-addressed Parquet
partitions with ordered manifests. PostgreSQL stores manifests, metadata, jobs,
and operational state. DuckDB/Polars scan historical partitions. Adjusted series
are restricted to research; execution and accounting use raw prices plus
explicit corporate-action events.

## Consequences

Every run pins partition, calendar, universe, feature, code, runtime, and cost
model versions. A correction cannot alter a previously published run manifest.
