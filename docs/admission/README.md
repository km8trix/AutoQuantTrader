# Market-data admission

The admission framework is implemented, but no external market-data product is
selected, licensed, or admitted. A synthetic report may prove reusable software
contracts; it cannot satisfy the Phase 1 vendor gate.

## Required workflow

1. Select the exact historical product and confirm that its contract permits the
   intended local storage, normalization, backtesting, and derived artifacts.
2. Freeze the source ID, adapter version, exact ETF allow-list, coverage interval,
   identifier authority, exchange calendar, universe, and corporate-action set.
3. Implement `HistoricalBarSource` for a legally obtained recorded export. Keep
   API credentials in the configured secret provider; never put them in an
   admission document, browser response, log, or catalog row.
4. Run the adapter contract suite against the licensed payloads and record one
   SHA-256 digest per required check. Failed checks remain evidence; do not erase
   or relabel them.
5. Evaluate the frozen specification and evidence. The command exits nonzero for
   `blocked`, `review_pending`, or `rejected` unless explicitly run in inspection
   mode:

   ```bash
   uv run python scripts/evaluate_market_data_admission.py \
     --specification vendor-specification.json \
     --evidence vendor-evidence.json
   ```

6. A reviewer other than the evidence executor must approve the exact bundle.
   Re-evaluate it, then ingest through the vendor adapter so the same profile,
   report, checks, and manifest are published atomically.

Use `--allow-not-admitted` only to inspect a non-admitted report in CI or local
development. It does not change the report status and must never be used as a
trading-readiness signal. The standalone evaluator prints a report; it does not
mutate the catalog or grant trading authority.

## Input rules

- Start from [the specification template](vendor-specification.template.json)
  and [the evidence template](vendor-evidence.template.json).
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
