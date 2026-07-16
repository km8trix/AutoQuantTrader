# ADR 0012: Tiingo EOD offline-first qualification

## Status

Accepted and implemented as a bounded Phase 1 qualification slice. This decision does
not authorize a Tiingo capture, create a production `HistoricalBarSource`, admit
a vendor, or enable paper or live trading.

## Context

ADR 0011 identifies Tiingo EOD as the next candidate for genuinely unadjusted
daily OHLCV. Tiingo's official end-of-day documentation distinguishes the
unprefixed `open`, `high`, `low`, `close`, and `volume` fields from separately
adjusted fields and exposes cash-dividend and split-factor fields. That field
contract is promising, but names and adjustment labels alone do not establish
that the unprefixed row is execution-safe, point-in-time data.

The reviewed public documentation does not establish a complete per-row
publication timestamp or an immutable sequence of historical vendor vintages.
A trading date identifies the market session, not when AutoQuantTrader could
have known the row. A later API response therefore cannot be backdated to the
session date or assigned a fabricated publication time. Causal knowledge begins
at the receipt time of the first authorized immutable capture, and later changed
deliveries must become explicit local revisions.

Several other boundaries remain unresolved. The exact EOD product and venue or
market provenance must be frozen independently from Tiingo's separate IEX
single-venue feed. A ticker in a provider response is an alias, not an immutable
internal security ID. Calendar, lifecycle, and corporate-action authorities
must be pinned. Finally, API access does not prove that the applicable contract
permits local retention, normalization, derived artifacts, or backtesting.

No retained live Tiingo payload is evaluated by this ADR. The earlier
secret-safe probe establishes candidate connectivity only.

## Decision

1. Implement an **offline synthetic qualification slice first**. It uses
   repository-owned fixtures that model the documented EOD field contract and
   cannot be mistaken for licensed vendor evidence.
2. Make the offline parser and contract tests fail closed on duplicate or
   unknown JSON keys, malformed dates or numbers, inconsistent raw/adjusted
   fields, invalid split/dividend values, duplicate symbol/session keys,
   out-of-scope symbols or dates, missing symbol/session coverage, and
   non-deterministic ordering or digests.
3. Treat the unprefixed OHLCV fields only as **raw candidates** until exact
   authorized bytes pass qualification. Adjusted fields remain research-only.
   Cash dividends and split factors remain explicit corporate-action candidates;
   they are not silently baked into execution prices or used to reconstruct a
   raw bar without separately validated rules.
4. Preserve the session date as event identity while using actual receipt time
   as the earliest knowledge time for a future real capture. Do not infer a
   publication timestamp from the session date, response order, or another
   provider's metadata. Synthetic fixture timestamps are test inputs, not vendor
   evidence.
5. Before any exact Tiingo response is requested for retention, freeze the exact
   endpoint/product, source ID, adapter version, allow-list, coverage, venue or
   market provenance, identifier authority, exchange calendar, lifecycle and
   corporate-action authorities, and correction policy. A reviewed,
   date-effective Tiingo-specific authorization must permit the intended local
   storage and research use and bind the applicable terms digest.
6. Only after authorized capture may exact response bytes be used to validate
   the observed schema, adjustment semantics, coverage, identity mappings,
   receipt-time revision behavior, and deterministic replay. Only after those
   checks pass may the Tiingo implementation expose the production
   `HistoricalBarSource` contract.
7. Keep source lanes isolated. Tiingo EOD cannot satisfy the one-minute Massive
   contract, Tiingo IEX cannot silently substitute for SIP, and a disagreement
   with Sharadar is a quality finding rather than an automatic fallback.
8. Keep admission and all trading authority blocked. Synthetic qualification,
   credential presence, an access probe, capture authorization, and a successful
   capture each have admission and trading effects of `none`.

## Consequences

The implemented code slice hardens schema, numeric, adjustment-basis, temporal,
coverage, and determinism rules without retaining paid data or making claims
about a live payload. It marks every result `synthetic_contract_only`, uses a
Tiingo-specific documented-raw-candidate basis instead of the canonical
execution-safe raw basis, and refuses canonical-bar or admission-evidence
conversion. It deliberately stops short of network capture and production-
source integration.

This ordering exposes semantic mistakes cheaply and gives a future capture a
precise acceptance contract. It also means Phase 1 remains open until licensing,
capture authorization, exact-byte qualification, identity/calendar/action
authority, implementation of `HistoricalBarSource`, admission evidence, and
independent approval are complete.

Receipt-time-only knowledge cannot reproduce vendor states from before the
first capture. That limitation must remain visible in manifests, backtests, and
admission evidence rather than being filled with assumed historical timestamps.

## References

- [Tiingo end-of-day API](https://www.tiingo.com/documentation/end-of-day)
- [ADR 0010](0010-market-data-provider-qualification-routing.md)
- [ADR 0011](0011-daily-first-capture-and-raw-lane-separation.md)
