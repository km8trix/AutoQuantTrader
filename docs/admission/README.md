# Market-data admission

The admission framework and provider qualification order are implemented, but
no external market-data product is licensed or admitted. A synthetic report or
successful access probe may prove reusable software and connectivity contracts;
neither can satisfy the Phase 1 vendor gate.

## Current candidate routing

- Sharadar SFP is the first immutable daily research-capture adapter. Its OHLCV
  is split/stock-dividend adjusted and only `closeunadj` is directly raw, so it
  is structurally blocked from the canonical raw execution lane.
- Tiingo EOD is independent validation and the next raw-daily qualification
  candidate. Its implemented current slice is offline and synthetic only; exact
  capture and a production source remain blocked. Its IEX history is single-
  venue and is never substituted for SIP.
- Massive raw SIP trades and quotes remain the deferred intraday and execution-
  evidence candidates; vendor minute aggregates are reconciliation input only.

The qualification allow-list is DIA, IWM, QQQ, and SPY, plus a separate
non-trade-enabled ticker-change/delisting corpus. See
[ADR 0010](../adr/0010-market-data-provider-qualification-routing.md),
[ADR 0011](../adr/0011-daily-first-capture-and-raw-lane-separation.md), and
[ADR 0012](../adr/0012-tiingo-eod-offline-first-qualification.md).

## Secret-safe access probe

Run one bounded authenticated read per candidate with:

    make market-data-probe DATE=2026-07-14 SYMBOL=SPY

The probe reads TIINGO_TOKEN, NASDAQ_DATA_LINK_API_KEY, and MASSIVE_API_KEY from
an owner-only gitignored .env using non-interpolating dotenv parsing. It rejects
symlinks and group/other-readable files and never invokes a shell. It never
prints a credential, response body, or credential-bearing URL. Its JSON contains
only the provider, configured flag, access classification, HTTP status, row
count, sample, and an explicit admission effect of none.

Massive REST access uses MASSIVE_API_KEY. Flat-file S3 access is a distinct
credential pair: MASSIVE_ACCESS_KEY_ID and MASSIVE_S3_SECRET_ACCESS_KEY. Never
infer that an ambiguously named MASSIVE_API_SECRET is the S3 secret.

## Current access evidence

The secret-free probe run on 2026-07-16 used the completed 2026-07-14 session:

| Candidate product | Sample | Result | Admission effect |
|---|---|---|---|
| Massive minute aggregates | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row | None; aggregate access does not preserve the raw correction timeline |
| Massive raw trades | SPY | HTTP 403, not entitled | Blocks the one-minute primary lane |
| Massive historical quotes | SPY | HTTP 403, not entitled | Blocks the quote/execution-evidence lane |
| Sharadar SFP | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row for each | None; product access and daily coverage only |
| Tiingo EOD | DIA, IWM, QQQ, SPY | HTTP 200 with a sample row for each | None; product access and daily coverage only |

No response body, credential, or credential-bearing URL was retained by the
probe. ADR 0011 selected the daily-first implementation while retaining the
one-minute lane for later entitlement. Daily access must not be relabeled as
one-minute readiness, and adjusted SFP OHLCV must not be relabeled as raw.

## Immutable Sharadar research capture

Exact provider pages may be retained only after a designated reviewer confirms
that the applicable terms permit both local snapshot storage and research use.
Start from the
[fail-closed authorization template](sharadar-sfp-capture-authorization.template.json),
replace the placeholder authorization/reviewer IDs and zero terms digest, set
the effective dates, and change both permission flags to `true` only when that
review is complete. The `terms_sha256` value is the SHA-256 digest of the exact
terms that were reviewed; the terms text and all credentials remain outside the
artifact.

Capture a completed bounded range (maximum 366 inclusive dates) with the
reviewed artifact:

    make sharadar-sfp-capture START_DATE=2026-07-14 AUTHORIZATION=path/to/reviewed-authorization.json

The command reads only `NASDAQ_DATA_LINK_API_KEY` from the owner-only `.env`,
validates the authorization before requesting or retaining an exact page,
follows a bounded cursor chain, and writes exact response pages plus a
secret-free manifest only under the fixed, ignored
`.local/vendor-snapshots/sharadar-sfp` root. The command has no arbitrary output
destination. Objects are created exclusively with owner-only read permissions.

The manifest binds the reviewed authorization and terms digests, exact response
bytes, cursor lineage, and the observed response-column schema digest. The
offline reader verifies paths, permissions, sizes, hashes, cursor completeness,
schema, allow-list, duplicate primary keys, and every required symbol/session.
It then binds the capture digest to the pinned calendar ID, version, timezone,
and exact session bounds so a change in derived daily timestamps changes the
semantic dataset digest. SFP's adjusted OHLCV is preserved only as explicit
research fields and never enters canonical raw bars. Capture output is
research-only and has admission and trading effects of `none`.

## Tiingo offline qualification boundary

Tiingo's official EOD contract distinguishes unprefixed OHLCV from adjusted
fields and exposes split and cash-dividend fields. The implemented offline
qualifier models that contract using repository-owned synthetic fixtures only.
It proves local parser behavior, raw-candidate basis separation, coverage rules,
causal receipt-time handling, and deterministic output. Its results are
permanently `synthetic_contract_only` and cannot emit admission evidence or
canonical execution bars. It cannot prove a live schema, entitlement,
provenance, historical revision behavior, or licensed use.

The reviewed public documentation does not supply the full publication and
historical-vintage timeline needed to treat a historical row as known on its
session date. A future authorized capture therefore uses its actual receipt time
as the earliest knowledge time and creates explicit local revisions when later
captures differ. It never invents pre-capture vintages.

No Tiingo payload may be retained until a provider-specific authorization
confirms local storage and research rights for the requested scope and binds the
reviewed terms digest. Before a production `HistoricalBarSource` is implemented,
the exact endpoint/product, venue or market provenance, identifier mapping,
calendar, lifecycle, corporate-action authority, and correction policy must be
frozen and validated against authorized bytes. The existing Sharadar
authorization template does not authorize Tiingo capture.

See the official
[Tiingo end-of-day API](https://www.tiingo.com/documentation/end-of-day) and
[ADR 0012](../adr/0012-tiingo-eod-offline-first-qualification.md). Offline
synthetic qualification, future capture authorization, and future capture each
have admission and trading effects of `none`.

## Required workflow

1. Select the exact historical product and confirm that its contract permits the
   intended local storage, normalization, backtesting, and derived artifacts.
2. Freeze the source ID, adapter version, exact ETF allow-list, coverage interval,
   identifier authority, exchange calendar, universe, and corporate-action set.
3. Qualify the provider contract offline with synthetic fixtures before any
   exact response is retained. This proves software behavior only.
4. After provider-specific capture authorization, validate legally obtained
   exact bytes and implement `HistoricalBarSource`. Keep API credentials in the
   configured secret provider; never put them in an admission document, browser
   response, log, or catalog row.
5. Run the adapter contract suite against the licensed payloads and record one
   SHA-256 digest per required check. Failed checks remain evidence; do not erase
   or relabel them.
6. Evaluate the frozen specification and evidence. The command exits nonzero for
   `blocked`, `review_pending`, or `rejected` unless explicitly run in inspection
   mode:

   ```bash
   uv run python scripts/evaluate_market_data_admission.py \
     --specification vendor-specification.json \
     --evidence vendor-evidence.json
   ```

7. A reviewer other than the evidence executor must approve the exact bundle.
   Re-evaluate it, then ingest through the vendor adapter so the same profile,
   report, checks, and manifest are published atomically.

Use `--allow-not-admitted` only to inspect a non-admitted report in CI or local
development. It does not change the report status and must never be used as a
trading-readiness signal. The standalone evaluator prints a report; it does not
mutate the catalog or grant trading authority.

## Input rules

- Start from [the specification template](vendor-specification.template.json)
  and [the evidence template](vendor-evidence.template.json). For SFP exact-page
  retention, separately start from the
  [capture-authorization template](sharadar-sfp-capture-authorization.template.json).
- JSON keys are strict and duplicate keys are rejected.
- All timestamps must be UTC and causally ordered.
- Digests are lowercase SHA-256 values. Store only the digest of entitlement
  terms, not the contract text.
- The source ID in the evidence must match the frozen specification and the
  adapter profile.
- Missing, duplicate, or unknown technical checks invalidate the bundle.
- An approved report is still not deployment authority; paper and live modes
  retain their independent promotion, risk, broker, and reconciliation gates.

## Recommended technical checks

At minimum, preserve evidence for deterministic re-ingestion, causal revisions,
source identity, effective-dated identifiers and delistings, DST and half-day
calendar behavior, corporate actions, raw-versus-adjusted separation, schema and
quality quarantine, manifest reproduction, and full required-symbol coverage.
The exact required list is frozen in the specification and may be stricter for a
particular vendor product.
