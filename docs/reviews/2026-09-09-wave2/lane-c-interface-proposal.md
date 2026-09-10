# Wave 2 lane C: derived reporting interface proposal

Status: proposal only; root must freeze shared interfaces before implementation.
Base: `ec63ca793ed4fe8a68397dc752000e102741da59` (merged W1 PR 52).
Worktree: `personal-v1-w2-reporting`, branch `codex/personal-v1-w2-reporting`.
Authority: active canonical plan section 17 and the active Wave 2 kickoff README, which supersede this checkout's historical W1-pending handoff. No W0 contract bytes or source code changed for this proposal.

## 1. Scope and inspected seams

Lane C computes reports from immutable accepted engine output. It does not choose targets, simulate fills, mutate orders/accounts, rebuild a FIFO book, apply corporate actions, or acquire data. Analytical benchmark units are mathematical report units only.

Sources inspected:

- `docs/contracts/personal-v1/core-engine.md` sections 4–7: economics, v2 row requirements, exact flow-neutral returns, availability, scoring and undefined results.
- `docs/contracts/personal-v1/economics-cases.json`: independent E1–E8 expected values; E4/E5 instantiated below.
- `packages/domain/backtest_report.py`: keep v1 immutable validation and its existing semantic/artifact separation. Its strictly increasing wall times, period-end flow subtraction, closed-trade turnover/start-NAV denominator, currency-valued exposure averages and mandatory-null annualized statistics are incompatible with the new general report semantics. Add v2; do not silently change v1 identities.
- `packages/backtest/golden_runner.py` `_report`: fixed equity/return/trade rows are a small regression oracle, not a general report builder.
- `packages/domain/{ledger_reducer,account_projection,settlement_ledger,order_reducer}.py`: accepted journal, corrected execution state, FIFO basis excluding fees, dividend receivables and settlement buckets are authoritative inputs. `CanonicalAccountProjection` requires a causal mark for an open holding and does not itself express authoritative-null/stale-estimate reporting. Root/B must expose this state without inventing a current mark.
- `packages/domain/decimal_math.py`: existing exact money arithmetic and 64-digit division are reusable, but multiplying already rounded 64-digit ratios through an exact-multiply operation can overflow its exactness policy. Derived statistical arithmetic needs its own explicit convention below.

## 2. Root-owned additive DTOs

Proposed files: `packages/domain/engine_contract.py` for engine outputs and `packages/domain/report_contract.py` for reporting outputs. Names are proposed, not permission to edit. Root can select other module names before freezing imports. Every DTO is a frozen, slotted dataclass; collections are ordered tuples, enums are explicit, all timestamps are aware UTC, and amounts are finite `Decimal`. Never use `dict[str, Any]`, mutable reducer instances, hidden clocks, or provider clients at this boundary.

All rows carry a schema/version and canonical semantic hash. Engine-assigned `(frontier_sequence, reduction_sequence, row_sequence)` orders rows; equal economic/knowledge times are allowed and do not merge distinct pre/post-flow states. Consumers reject conflicting row IDs, out-of-order rows and broken references. Exact duplicates should already have collapsed in the engine; a report cannot count them twice.

| DTO | Required fields |
|---|---|
| `EngineResult` | `run_id`, `run_spec_sha256`, `input_sha256`, `result_status` (`completed`, `cancelled`, `failed`, `rejected`), terminal reason codes; `trace_sha256`, final account/strategy snapshot hashes; immutable `valuation_rows`, `external_flow_rows`, effective `execution_rows`, execution correction lineage, `fifo_match_rows`, terminal order rows, `journal_rows`, benchmark valuation inputs; dataset evidence/limitation pins and scoring specification; derived `result_sha256`. No attempt ID or wall-clock duration in the semantic result. |
| `ScoredInterval` | `interval_id`, `fold_id`, half-open start/end boundary keys, baseline valuation ID, final endpoint valuation ID, ordered expected regular-session IDs, calendar/version, reset/carry mode, warmup boundary and count. A shared endpoint is one value, not a twice-scored return. |
| `PositionValuationRow` | stable instrument/symbol/currency; quantity, total FIFO basis and open-lot references; current `mark_price`, market value and unrealized P&L nullable with quality/reasons; mark ID/source fact hash, raw/adjusted role, economic/knowledge times, expected/actual mark session and age; separately named last-known price/value/unrealized estimate and age; gross realized P&L, all execution fees and dividend income from accounting. |
| `ValuationRow` | row ID and sequence key, account/run and snapshot/ledger/order hashes; `economic_at`, `knowledge_at`, regular-session ID; roles (`baseline`, `daily_close`, `pre_flow`, `post_flow`, `terminal`), scored/fold/interval identity; current authoritative NAV/market value/gross and net exposure/unrealized P&L, each nullable with reason; trade-date cash, settled cash, available cash, settlement receivables/payables, buy reserve, dividend receivable, gross realized P&L, expensed execution fees, net realized P&L, dividend income, cumulative signed external flow; positions; overall mark quality and separate last-known NAV estimate; optional applied flow ID and paired valuation ID. |
| `ExternalFlowRow` | applied flow ID and journal reference/hash, contribution/withdrawal, positive amount and signed amount, currency, economic/knowledge times and reduction sequence; `pre_valuation_id`, `post_valuation_id`, origin (`initial_capital` or `external_flow`), correction lineage. Rejected withdrawals are trace outcomes, not applied flow rows. Initial capital establishes the baseline and is excluded from subsequent net contributions. |
| `ExecutionRow` | effective execution ID/revision/fact ID and fact hash; order/intent IDs, optional broker order ID with honest null reason, instrument, side, source/environment/model labels, quantity/price/notional/fee, economic/knowledge times and engine sequence; predecessor/correction/bust references, journal hashes, action/settlement references. Retain all historical fact lineage separately; turnover does not sum original plus replacement as two executions. |
| `FifoMatchRow` | B-issued match ID, opening and closing effective execution IDs/revisions, opening lot ID, instrument, matched whole-share quantity at the matched action basis, acquisition/disposal times, released fee-exclusive basis, proceeds, attributed opening and closing fees, action/conversion lineage, source account revision/hash, `trade_group_id`, and group completion status. B owns FIFO matching and split-aware fee allocation. C sums and verifies these rows only. |
| `BenchmarkValuationInput` | benchmark/series and policy hashes, boundary key and corresponding strategy valuation ID/flow ID, instrument/currency, causal total-return unit price or null/reason, economic/knowledge times, mark/source hashes and quality, source class and action/availability assumptions. Root's dataset conversion supplies one declared total-return representation; raw actions cannot be credited again on an adjusted index. |
| `ReportConventions` | version/hash; USD, exact event-timed TWR, annualization 252, minimum 252 valid scored daily sessions, sample volatility `ddof=1`, risk-free convention/value or source series, Sortino target/downside formula, one-way executed turnover, mean daily exposure ratio, FIFO trade grouping/fee policy, Decimal derived-math/serialization pins, mark policy and benchmark assumptions. Every semantic alternative changes RunSpec. |
| `MetricCoverage` | exact interval/fold IDs, expected scored sessions, observed closes, valid closes, expected/valid daily return counts, valid subperiods and flow pairs, excluded boundaries with reasons, ordered contributing row hashes and input-window hash. Include the minimum required count and denominator sample count where applicable. |
| `MetricValue` | `name`, version, value (`Decimal` or null), unit, status (`defined`, `undefined`, `approximate`), stable reason codes, coverage, convention hash and assumption IDs. Undefined means null; approximate requires a named opt-in model, never a silent repair. Counts can be separate typed integer fields in report statistics. |
| `DerivedReturnRow` | interval/session and source boundary IDs/hashes, growth/period return, cumulative linked wealth and drawdown as nullable metrics, pre/post-flow pair references, coverage/reasons. A baseline has wealth 1; it is not a daily return observation. |
| `BenchmarkReport` | ID, analytical model/series/source class/assumption hashes, matched external-flow IDs and exact boundary keys, analytical valuation/return rows, cash comparator rows, metrics and exclusions. Comparison metrics bind the exact common scored window. |
| `RunReport` | schema/version, run/input/result/convention hashes; completed or incomplete status and reason; source class/evidence/limitations, scored/warmup intervals; source valuation/flow/order/execution/match/terminal-holding/journal references, derived returns/trade statistics/metrics/benchmark, excluded intervals and optional bound stress-report references; derived `report_sha256`. |
| `ReportArtifact` | `RunReport`, `attempt_id`, `generated_at`, optional restatement provenance, `artifact_sha256`. Serialization bytes are deterministic for equal semantic report and artifact metadata. |

Cash/NAV values come from A/B's accepted transition outputs. C checks `trade_date_cash + securities + dividend_receivable = settled_cash + settlement_receivables - settlement_payables + securities + dividend_receivable` where authoritative valuation is defined; reserves affect available cash, not economic NAV. It does not repair inconsistencies by rerunning account reducers.

For flow pairs, A freezes identical causal marks/positions across an individual applied flow and emits `NAV_after = NAV_before + signed_flow` at successive reduction sequences. C verifies the pair and journal binding. Other economic events at the same wall time require their own ordered boundaries. Unknown pre-flow valuation is explicit and cannot be reconstructed from a later mark.

Root should supply canonical expected sessions and session assignments. C must not infer market calendars from weekdays, timestamps or row count. Scoring and retained warmup identities are required even for short samples.

## 3. Exact proposed public APIs

`packages/domain/metrics.py` — pure functions, no I/O, clocks, engines or account reducers:

```python
def derive_return_path(
    *, valuations: tuple[ValuationRow, ...],
    flows: tuple[ExternalFlowRow, ...],
    interval: ScoredInterval, conventions: ReportConventions,
) -> tuple[DerivedReturnRow, ...]: ...

def derive_benchmark(
    *, inputs: tuple[BenchmarkValuationInput, ...],
    flows: tuple[ExternalFlowRow, ...], initial_capital: Decimal,
    interval: ScoredInterval, conventions: ReportConventions,
) -> BenchmarkReport: ...

def derive_metrics(
    *, valuations: tuple[ValuationRow, ...],
    flows: tuple[ExternalFlowRow, ...],
    executions: tuple[ExecutionRow, ...],
    fifo_matches: tuple[FifoMatchRow, ...],
    returns: tuple[DerivedReturnRow, ...],
    interval: ScoredInterval, conventions: ReportConventions,
) -> tuple[MetricValue, ...]: ...
```

`packages/application/run_report.py` — pure artifact assembly from one accepted output:

```python
def build_run_report(
    *, result: EngineResult, conventions: ReportConventions,
    attempt_id: str, generated_at: datetime,
) -> ReportArtifact: ...
```

The builder checks that conventions match RunSpec, dispatches the pure calculators per scored interval, verifies accounting/row lineage, and retains source rows or their bound immutable payloads. Callers cannot supply precomputed metrics or substitute unbound benchmark rows. It returns an incomplete artifact for failed/cancelled runs with partial coverage; it never publishes that as completed performance. Root owns any separate serializer/storage/CLI call and the old API compatibility bridge.

Malformed identities, mismatched flow pairs, impossible arithmetic and contradictory source rows raise a specific `ReportInputError`. Expected missing data, insufficient samples and nonpositive statistical denominators yield explicit undefined metrics. Incomplete history is not malformed input.

## 4. Metric definitions and availability

1. For each complete valued interval between flows, `g = V_end_before_flow / V_start_after_previous_flow`. Link all such factors, including the final no-flow segment: `TWR = product(g) - 1`. A flow-only pre/post pair contributes growth 1, regardless of its size. Daily returns link all subperiods within that expected scored session. Cumulative wealth starts at 1 and compounds valid daily factors.
2. Unknown boundary valuation or missing expected current-session mark makes the affected return undefined. Never bridge a gap into an exact daily return. Full-window TWR/drawdown/annualized results remain undefined after an unresolved gap; a later complete subwindow can have separately named results with its own baseline and coverage. Endpoint P&L can still be defined when both endpoints and every external flow are known, even if the return path is incomplete.
3. Net dollar P&L is `ending_NAV - starting_NAV - net_flows_after_baseline`. Portfolio gross realized P&L, fees, net realized P&L, unrealized P&L and dividend income are differences/projections from accepted accounting rows. Settlement transfer and dividend payment do not create profit. Do not subtract fees or add dividend income again to NAV-derived P&L.
4. Drawdown is `1 - linked_wealth / running_peak` at the declared valued boundaries. Maximum drawdown uses the complete flow-neutral path, including known within-session flow boundaries; annualized daily statistics use only one return per eligible scored session. Root must use the same wealth convention for daily risk.
5. One-way turnover is all effective absolute executed notionals within the scored interval, including buys that remain open, divided by mean valid positive scored daily NAV. Buy/sell notionals both enter once; fees and a separate slippage expense are excluded. Slippage is already in execution price; any reported reference-price cost needs a pinned causal reference. Corrected execution and bust effects come from the engine's effective execution selection, not C's own revision reducer.
6. Average gross/net exposure is the arithmetic mean of the corresponding daily securities exposure/NAV ratios. Coverage shows excluded invalid closes. Turnover/exposure may be defined on their explicitly disclosed valid-NAV subset under this convention; they do not imply a complete return path. No valid positive denominator yields null. Flow rows and duplicate terminal/close roles never overweight daily means.
7. Total return is allowed for a complete short interval. Annualized return requires a complete consecutive regular-session sample with at least 252 valid scored daily returns/session endpoints and the causal initial baseline: `linked_growth ** (252 / scored_session_count) - 1`. Warmup rows are excluded. Calendar years elapsed do not replace session coverage.
8. Annualized volatility is `sample_stdev(daily_returns, ddof=1) * sqrt(252)`, with the same 252-session eligibility floor. Known zero variance yields volatility 0 only after this floor. Sharpe is `sqrt(252) * mean(daily_excess_returns) / sample_stdev(daily_excess_returns, ddof=1)`. Default daily risk-free return is exactly 0 under `assumed-zero-v1`, not observed. A nonzero annual effective rate converts via `(1 + rate) ** (1/252) - 1`; missing risk-free values exclude the affected metric.
9. Proposed Sortino pin: `sqrt(252) * mean(daily_excess_returns) / sqrt(mean(min(daily_excess_return, 0) ** 2))`, with all eligible observations in the downside second-moment denominator, zero target above the declared risk-free rate, and the 252-session floor. Zero downside denominator is undefined. To satisfy E8 literally, both Sharpe and Sortino remain undefined for zero return variance, including a constant negative series; root must freeze this conservative eligibility rule because core section 6 alone otherwise leaves that constant-negative Sortino edge ambiguous.
10. Nonpositive NAV at a required statistical boundary yields undefined affected returns/ratios with `nonpositive_nav`; do not emit infinity or a zero to imply good performance. Positive-NAV samples may still report known dollar accounting amounts. Profit factor with no gross losing trade amount is undefined; hit rate with no completed trade groups is undefined. Capacity and confidence intervals stay undefined (`method_not_qualified`).
11. Derived non-terminating arithmetic uses an explicitly pinned 64-significant-digit, half-even Decimal context independent of ambient context; noninteger power/sqrt operations use that context and a declared version. Monetary source rows keep their existing persisted exact limits; do not quantize intermediates to cents or ten decimal places. Rational flow expectations below are independent test oracles, converted only for comparison under the pinned derived tolerance. Root must approve either a shared derived-math helper or a private calculator helper and add its version to RunSpec.

Reason codes include `missing_current_session_mark`, `stale_mark`, `missing_pre_flow_valuation`, `missing_post_flow_valuation`, `missing_expected_session`, `incomplete_return_path`, `nonpositive_nav`, `insufficient_scored_sessions`, `zero_variance`, `zero_downside_deviation`, `missing_risk_free_input`, `no_completed_trades`, `zero_loss_denominator`, `missing_benchmark_mark`, `benchmark_withdrawal_exceeds_value`, `incomplete_attempt`, and `method_not_qualified`. Record all applicable reasons in stable order rather than hiding a data problem behind only a sample-count warning.

## 5. Independent E4/E5 and benchmark acceptance cases

Use fixture-owned explicit causal marks at flow boundaries. The intraperiod price rows below are synthetic available facts, not invented intraday observations from a daily OHLC source. Give each pair the same timestamp but distinct engine sequences to exercise ordering.

| Case/boundary | Cash | Position and price | NAV | Signed flow |
|---|---:|---|---:|---:|
| E4 baseline | 200 | 8 × 100 | 1000 | — |
| E4 immediately pre-flow | 200 | 8 × 112.5 | 1100 | — |
| E4 immediately post-flow | 700 | 8 × 112.5 | 1600 | +500 |
| E4 terminal | 700 | 8 × 132.5 | 1760 | — |
| E5 baseline | 200 | 8 × 100 | 1000 | — |
| E5 immediately pre-flow | 200 | 8 × 112.5 | 1100 | — |
| E5 immediately post-flow | 0 | 8 × 112.5 | 900 | −200 |
| E5 terminal | 0 | 8 × 123.75 | 990 | — |

E4: factors `1100/1000 = 11/10` and `1760/1600 = 11/10`; TWR `21/100`, dollar P&L `1760 - 1000 - 500 = 260`. Reject `26%` as exact TWR: that is `(1760-500)/1000-1`. No fill is needed to apply this reporting oracle; A/B's separately named oracle account policy supplies the valid starting state.

E5: factors `1100/1000 = 11/10` and `990/900 = 11/10`; TWR `21/100`, dollar P&L `990 - 1000 - (-200) = 190`. Reject `19%` as exact TWR. Flow-neutral wealth is `1, 1.1, 1.1, 1.21`; both cases have drawdown 0. The raw E5 NAV decrease from 1100 to 900 is a withdrawal, not an 18.18% drawdown.

SPY analytical comparator uses its own causal total-return unit prices `100 → 110 → 121` at precisely the strategy's baseline/pre-flow/terminal boundary keys. Default analytical fees are 0 and fractional units are permitted, explicitly disclosed; this differs from the strategy's share/cash constraints. No execution adapter is involved.

- E4: initial units `1000/100 = 10`; add `500/110 = 50/11`; total units `160/11`; terminal value `(160/11)*121 = 1760`; TWR 21%.
- E5: initial units 10; redeem `200/110 = 20/11`; remaining units `90/11`; terminal value `(90/11)*121 = 990`; TWR 21%.
- Idle cash comparator: E4 `1000 → 1500 → 1500`, E5 `1000 → 800 → 800`; both TWR 0 with the same flow IDs/times. The initial contribution is not applied a second time.
- Multiple flows sharing a wall timestamp remain distinct paired sequence boundaries. A +500/−200 pair may algebraically net to +300 but cannot be silently netted before an intervening mark/economic event. Applying a benchmark flow at a later close is a test failure even if terminal cash happens to match.
- Missing benchmark boundary mark makes the affected benchmark/comparison metric undefined while a fully valued strategy metric remains defined. Conversely, a valid benchmark does not repair strategy marks. An analytical withdrawal exceeding available benchmark value is undefined under this long-only comparator; never create negative units or silently borrow.
- Synthetic raw-price dividend/split inputs and a qualified adjusted comparator representing the same total return must agree under separately pinned modes. Crediting a dividend on the adjusted mode again must reject conflicting semantics. Root supplies action semantics; C consumes their accepted unit-price series.

## 6. FIFO fee attribution and open holdings

B emits completed quantity matches, and root pins trade grouping before C implements statistics. Proposed grouping is one closing order's matched quantities across all its partial fills and FIFO lots; completion requires that closing order be terminal with positive executed quantity. A cancelled remainder can complete the filled group. An unresolved closing order's realized matches remain visible but excluded from completed-group hit rate until terminal. This avoids one partial fill becoming one winning trade. If root chooses another grouping, its policy ID and independent expectations must change together.

E1 cross-check: buy 4 at 100 with fee 1; sell 2 at 110 with fee 1. B supplies matched basis 200, proceeds 220, attributed buy fee `1*(2/4)=0.5`, attributed exit fee 1. Closed trade-analysis net P&L is `20-0.5-1=18.5`. Portfolio net realized P&L remains `20-2=18` because the other 0.5 opening fee was expensed already; open quantity 2, basis 200, mark 110, unrealized P&L 20. Total portfolio P&L is 38. Trade attribution does not repost 1.5 fees or overwrite portfolio realized P&L. Retain the 0.5 unallocated-to-closed-matches entry fee as attribution coverage.

Fee conservation per effective execution: attributed closed-match fee plus fee attributed to still-open/uncompleted quantities equals that execution's fee. Root/B must provide split-adjusted attribution ancestry; C must not infer the original fractional fee weight from post-split share counts. Corrections/busts produce a newly bound result; previous as-known report rows and decision trace stay immutable.

Open holdings remain in terminal positions and NAV; lack of closed trades does not imply zero turnover/cost/P&L. A missing current-session mark sets authoritative terminal NAV/unrealized/exposure and affected performance metrics to null; a prior mark can supply only separate last-known estimates with source time and age. Known cash, fees, quantities, basis and realized amounts remain displayable. A stale mark must not acquire the final session date to pass validation.

## 7. Proposed focused tests and file ownership

After root freezes DTOs, lane C's exact source allowlist is:

- NEW `packages/domain/metrics.py`
- NEW `packages/application/run_report.py`
- NEW `tests/unit/test_personal_metrics.py`
- NEW `tests/unit/test_personal_run_report.py`
- This proposal file; later evidence file only if root explicitly allocates it.

No edits to `backtest_report.py`, `golden_runner.py`, account/ledger/order reducers, shared models/DTOs, strategies, migrations, application worker, API/CLI, manifests, fixture datasets, canonical docs, CI or dependency/build files. No native or non-stdlib numerical dependency is needed. Existing golden/report tests remain regressions; root owns any golden-to-general comparison and suite selection changes.

Focused acceptance matrix:

1. E4 and E5 exact 21% independently asserted from the stated Decimal amounts/fractions; the old 26% and 19% formulas fail. Matching benchmark/idle-cash flows and equal-wall-time pair ordering are asserted separately from the production calculator.
2. Same-timestamp ordered multiple flows and intervening valuation; missing pre/post mark; no period-end substitution, no flow counted twice, no warmup flow included in scored net contributions.
3. Open-only buy: filled notional enters turnover, paid fee appears once, marked holding enters NAV; zero completed trades gives undefined hit rate/profit factor. E1 partial closure validates 18.5 trade analysis versus 18 portfolio realized and 38 total P&L.
4. Multiple partial fills and multiple FIFO lots grouped once; terminal cancellation versus unresolved group; pro rata fee conservation and split-adjusted match ancestry. C tests supplied matches; integration validates B actually emits them.
5. Current-session missing/stale terminal and interior marks preserve labelled last-known estimates and invalidate affected return paths. Missing benchmark marks affect only comparator-dependent outputs. Nonpositive NAV/mean NAV and absent risk-free input give explicit reasoned nulls.
6. 251 valid scored sessions remain annualized-undefined; 252 complete eligible sessions qualify. A 252-row series with one missing expected session, a duplicate close, or a baseline counted as a return fails qualification. Five real sessions remain at most five eligible sessions, with actual available return count disclosed, never 252. Synthetic long-history fixtures retain synthetic labels.
7. Constant zero returns over 252 complete sessions: total/annualized return and volatility 0; Sharpe/Sortino null. Varying all-positive returns: Sortino null for zero downside; mixed signed returns validate independently specified sample standard deviation and downside second moment. Constant negative returns exercise the root-frozen E8 eligibility decision.
8. Daily means count one close per session, excluding flow/baseline/duplicate terminal roles; turnover includes every effective execution including open positions. Corrected/busted facts do not create double notional or fee counts; settlement/dividend payment does not create return.
9. Generated-at/attempt changes affect only artifact identity. Source class/availability/model/config/scoring/convention and accepted result changes affect semantic identity. Tuple order, hash binding, invalid flow arithmetic and contradictory input are rejected. Ambient Decimal precision/rounding changes do not alter semantic values/hashes.
10. Cancelled/failed output retains partial trace and explicit incomplete status; cannot serialize a completed report. Independent fold intervals do not concatenate account NAV, and a shared endpoint is not twice scored.

Integration acceptance owned by root: engine-issued E1–E8 accounting/flow rows feed these calculators; two reference strategies across two sufficiently long labelled datasets yield actual derived reports; all-fill costs/holdings reconcile; real five-session sample remains a limitations case; golden facts match before product cutover. Lane-local manually instantiated immutable DTO tests alone do not demonstrate the general engine exit.

## 8. Decisions root must freeze

1. Exact additive DTO module names/fields and hashing/serialization convention; no v1 report behavior changes.
2. A's explicit pre/post-flow issuance, expected scored sessions, mark quality/last-known fields and stable equal-frontier ordering; B's effective execution selection, FIFO match/fee lineage and terminal trade-group definition.
3. Benchmark total-return unit-price producer, zero-fee analytical model, same-boundary flow matching and action treatment; both SPY and idle cash are required.
4. Derived Decimal math/version/tolerance and annualization policy; confirm conservative zero-variance Sortino eligibility and the specific downside second-moment formula.
5. Report restatement policy: default as-known engine outputs; a restated view must pin correction cutoff/coverage and change semantic result/report identity as well as artifact metadata. Merely generating the identical report later changes only artifact identity.
6. Approve the four-file future source/test allowlist and root-owned shared/integration fixtures. Until then, this document is the complete lane C deliverable and no consumer code is authorized.
