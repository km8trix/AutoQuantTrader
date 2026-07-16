# ADR 0010: market-data provider qualification routing

## Status

Accepted as a qualification order. No vendor product is admitted.

## Context

The first trading slice consumes one-minute U.S. ETF data, while the available
vendor credentials span products with materially different semantics. Massive
offers SIP aggregates, trades, and quotes; Sharadar SFP is an end-of-day fund
table with active and delisted instruments; Tiingo offers end-of-day data and a
separate IEX single-venue feed. An API key proves neither the subscribed product
nor the right to store, normalize, display, or use its data in a hosted
application.

No public contract reviewed for these products promises a complete immutable
history of every prior correction, identifier revision, and corporate-action
revision. AutoQuantTrader therefore cannot equate a historically dated row with
a fact known at that historical instant.

## Decision

Use explicit, non-fallback lanes:

1. **Massive is the primary Phase 1 one-minute candidate.** Qualify the entitled
   us_stocks_sip/trades_v1 files as the causal raw input and deterministically
   build one-minute bars from accepted trade conditions. Qualify
   quotes_v1 separately for spread and execution evidence. Treat
   minute_aggs_v1 as a reconciliation dataset, not as proof of the intraminute
   correction timeline. Stocks Advanced or a matching business order form is
   required for the intended full-history trade-and-quote lane.
2. **Sharadar is the daily reference candidate.** If SFP, TICKERS, and ACTIONS
   are actually licensed, use them for unadjusted daily cross-checks, ETF
   lifecycle research, and corporate-action reconciliation. Sharadar
   permaticker remains a provider alias; it is not the canonical internal
   security ID. SFP cannot satisfy the one-minute source contract.
3. **Tiingo is an independent validation/fallback candidate.** Raw EOD prices,
   splits, and dividends may be used for reconciliation when licensed. Tiingo
   IEX data is labeled single-venue and cannot silently replace a consolidated
   SIP series.

The initial qualification allow-list is the sorted set DIA, IWM, QQQ, and SPY.
A separate non-trade-enabled lifecycle corpus must include a ticker change and
a delisted ETF before admission. Every dataset manifest pins exactly one price
source, one source ID, one security-master version, one calendar version, and
one corporate-action version. Cross-vendor disagreement is a quality finding;
the system never substitutes one source automatically.

All acquired payloads are archived immutably with request and receipt times,
object metadata, byte count, and SHA-256. Later acquisitions are diffed against
earlier snapshots to create explicit local revisions. This provides causal
reproducibility from the first captured delivery forward; it does not fabricate
vendor vintages from before acquisition began. A separately versioned U.S.
exchange calendar remains mandatory.

Credential presence never selects a lane, establishes entitlement, changes an
admission result, or enables broker connectivity. Provider probes are read-only
and return only sanitized access facts. E*TRADE remains sandbox-only until its
production approval and OAuth state are separately promoted. Alpaca paper
remains the first broker candidate; its production credentials are dormant
until the later live-authority gates pass.

## Consequences

The next Phase 1 work is an entitlement/access probe, followed by immutable
sample capture, schema freezing, raw-trade condition and correction tests,
identifier/calendar/corporate-action qualification, and independent review.
Successful HTTP access remains candidate evidence and cannot produce an
admitted result by itself.

Using more than one vendor adds reconciliation and identifier-mapping work, but
keeps execution truth, daily reference data, and independent validation from
being conflated. If the Massive entitlement does not include the required
history or permitted use, the one-minute slice remains blocked; Sharadar or
Tiingo EOD access does not silently weaken the frequency contract.

## References

- [Massive stock flat files](https://massive.com/docs/flat-files/stocks/overview)
- [Massive REST authentication](https://massive.com/docs/rest)
- [Sharadar Fund Prices](https://data.nasdaq.com/databases/SFP)
- [Nasdaq Tables API](https://docs.data.nasdaq.com/docs/api-and-analysis-tools-for-tables-data)
- [Tiingo end-of-day API](https://www.tiingo.com/documentation/end-of-day)
