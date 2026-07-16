# ADR 0011: daily-first capture and raw-lane separation

## Status

Accepted. This supersedes ADR 0010 only for the first-adapter implementation
order. It does not admit a vendor or authorize paper or live trading.

## Context

The secret-safe access run on 2026-07-16 confirmed Sharadar SFP and Tiingo EOD
rows for DIA, IWM, QQQ, and SPY. Massive raw historical trades and quotes both
returned HTTP 403, so the entitlement required by ADR 0010's one-minute lane is
not available.

Sharadar's official SFP documentation also establishes a stricter semantic
boundary than column names alone suggest. Its open, high, low, close, and volume
are adjusted for splits and stock dividends. `closeadj` is additionally
backward-adjusted for cash dividends and spinoffs. Only `closeunadj` is directly
unadjusted. SFP therefore cannot be mapped to the canonical raw OHLCV execution
contract without mixing price bases or reconstructing fields that the product
does not directly supply.

SFP's `lastupdated` is a date on the current row, not a publication timestamp or
a retained sequence of historical vendor vintages. A backfilled row proves what
was observed at acquisition time, not what was knowable on its trading date.

## Decision

1. Add `1d` as a session-defined canonical interval. A daily bar spans the exact
   open and close of one session in the pinned calendar; it is never a generic
   24-hour bucket. Regular days, half-days, holidays, and DST remain explicit.
2. Implement Sharadar SFP as the first external, immutable **research capture**
   adapter. Network acquisition is bounded and separate from deterministic
   offline loading. Before the first exact page is requested or retained, a
   separate reviewed authorization artifact must permit local snapshot storage
   and research use for the requested dates and identify the digest of the
   applicable terms. Capture output has one fixed root under the ignored
   `.local/vendor-snapshots/sharadar-sfp` tree; callers cannot select an
   arbitrary destination.
3. Preserve all SFP fields with explicit bases. The adapter must refuse to emit
   canonical `PriceBasis.RAW` bar records because raw open, high, low, and volume
   are absent. `closeunadj` may be compared as a raw-close candidate but cannot
   make the mixed row execution-safe.
4. Use actual receipt time as `observed_at`. Never convert `lastupdated` or a
   historical trading date into fabricated knowledge time. Point-in-time replay
   begins with the first immutable capture; pre-capture vendor vintages remain
   unknown.
5. Keep the initial allow-list fixed to DIA, IWM, QQQ, and SPY. Sharadar ticker
   and permaticker values remain aliases; identity, lifecycle, calendar, and
   corporate actions require separately frozen authorities.
6. Keep Tiingo EOD as independent validation and as a candidate to qualify for
   the raw daily lane. Keep Massive raw trades/quotes as the later intraday lane
   once the exact entitlement exists. No automatic vendor fallback is allowed.
7. Keep vendor admission, broker connectivity, paper orders, and live orders
   blocked. An accessible API key and a valid research capture have no trading
   effect.
8. Bind each manifest to the reviewed authorization digest, terms digest, exact
   response bytes and cursor lineage, and the observed response-column schema
   digest. Do not infer or hard-code an unobserved vendor schema version.
9. During offline loading, bind the capture digest to the pinned calendar ID,
   version, timezone, and exact session bounds. Derived daily timestamps are
   therefore part of the semantic dataset identity, and required coverage is
   checked for every allow-listed symbol/session pair.

## Consequences

The application can now represent daily bars correctly and, after explicit
storage authorization, archive SFP evidence without corrupting raw execution
truth. A bounded SFP capture can support schema, coverage, lifecycle, and
cross-vendor research after licensing is confirmed, but adjusted SFP OHLCV never
enters canonical raw bars and cannot satisfy `HistoricalBarSource` for
execution-safe raw bars. Neither an authorization artifact nor a successful
capture changes admission or trading authority.

The next raw-data qualification must either prove a vendor supplies genuinely
unadjusted daily OHLCV or independently validate a corporate-action
reconstruction against SFP/TICKERS/ACTIONS. Repeated SFP captures must later be
diffed by `(ticker, date)` so unchanged rows retain their first observation and
changed economics create explicit local revisions.

## References

- [Sharadar SFP documentation](https://data.nasdaq.com/databases/SFP/documentation)
- [Sharadar SFP metadata](https://data.nasdaq.com/api/v3/datatables/SHARADAR/SFP/metadata.json)
- [Nasdaq Tables API usage and pagination](https://docs.data.nasdaq.com/docs/in-depth-usage-1)
- [ADR 0010](0010-market-data-provider-qualification-routing.md)
