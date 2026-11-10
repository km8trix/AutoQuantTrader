# Wave 0 reusable core and economic engine contract

Contract: `personal-v1-core-contract-w0-v1`, frozen for implementation by Waves 1–5.
Reviewed code: `107fa791bb52e9fa42cbce65992ea1ce9168834e`; no runtime behavior is implemented by this specification.
This is a supporting contract, subordinate to the sole [architecture](../../ARCHITECTURE.md) and [implementation plan](../../IMPLEMENTATION_PLAN.md).
The baseline record identifies the exact uncommitted consolidated documentation reviewed with this code.
The [source map](core-source-map.json) gives 90 exact Python files, source hashes, direct callers, test importers, dispositions and ownership; 689 tracked Python files parsed with zero parse errors.
The [economics cases](economics-cases.json) contain independent hand calculations, not claimed implementation passes.

## 1. Frozen scope and defaults

One USD cash account; one active strategy; long-only whole shares; DIA/IWM/QQQ/SPY, with fixed-universe selection bias disclosed.
Regular-session DAY market orders only. No shorting, leverage, fractional broker orders, extended hours, replacement or second broker.
E*TRADE remains the live target; execution stays disabled. Synthetic balances below authorize no live financial amount.

| Input | Frozen engineering default; explicit alternative changes run identity |
|---|---|
| Research capital | USD 10,000 synthetic initial settled cash; no open holdings or orders |
| Daily decision | Attempt at 20:00 America/New_York after each regular session; retry only missing required input until 09:00 next regular session, then skip |
| Actual execution schedule | 09:35 inclusive to 09:40 exclusive next regular session; fresh execution observations and session health required; no backlog |
| Historical execution | Explicit `next-regular-open-proxy-v1` is allowed for exploratory EOD runs; it is a separate model from actual 09:35–09:40 execution |
| Reference strategies | Buy/hold with configured periodic rebalance, and close strictly above trailing 200-session mean; equality means flat; otherwise cash |
| Default allocation | One symbol at most 25% NAV; a four-symbol equal basket targets 23.75% each; remaining capital stays cash |
| Daily simulation risk | 25% per-symbol/per-order NAV; 95% gross/per-batch; 1% adverse-price reserve plus model fees; 1,000 shares/order; 4 outstanding/1 per symbol; 8 new intents/session |
| Loss controls | Flow-neutral daily TWR loss at or below −3%, or drawdown at or above 15%, blocks new exposure under the account contract; separately authorized reduce-only recovery must retain its other mandatory checks |
| Study | 2010–2025 when licensed coverage supports it; train 2010–2018, validation 2019–2022, final holdout 2023–2025 |
| Evaluation | Fresh strategy/account for each independent fold; 252 eligible earlier sessions of warmup; disjoint scored intervals; fitted parameters frozen before validation/test |
| Compute | One research job, at most 2 CPU cores, 4 GiB resident-memory budget, 30-minute wall deadline and 1 GiB output budget; reject oversized work before start |
| Costs | Base exploratory adverse slippage 5 basis points/side and $0.01/share fee; stress 20 basis points/side and $0.02/share; assumptions, not measured broker costs |
| Simulated settlement | Dated standard-settlement model: T+3 before 2017-09-05; T+2 from 2017-09-05 through 2024-05-27; T+1 from 2024-05-28. Pin a settlement-business-day calendar distinct from the exchange-session calendar. Modeled availability is 09:30 ET on settlement date; this release time is an assumption, not an observed broker fact |
| Benchmark | SPY buy-and-hold analytical total-return comparator, plus idle cash at assumed 0% interest; same flow timestamps and dataset action semantics |

Source delivery, licensed rights, execution quotes, account eligibility and actual broker fees remain W1/W6 qualification inputs; they do not prevent freezing these contracts.
The standard-cycle dates are supported by the [SEC 2017 T+2 announcement](https://www.sec.gov/newsroom/press-releases/2017-163) and [SEC T+1 investor bulletin, including ETFs](https://www.investor.gov/introduction-investing/general-resources/news-alerts/alerts-bulletins/investor-bulletins/new-t1-settlement-cycle-what-investors-need-know-investor-bulletin). Actual account availability requires qualified settlement facts; exceptions are not inferred from this historical default. Constant T+1 may be a separately named exploratory sensitivity, never a silent historical substitution.
The study dates are reproducible engineering defaults, not proof that historical holdout results were never seen. Record prior access honestly; freeze criteria before new scoring and choose a new untouched or prospective holdout when needed.
Model costs, strategy lookback, allocations and research limits are configuration pins. Changing them produces a new run/trial, never a silent update.

## 2. Data, availability and immutable identity

All durable timestamps are aware UTC; local schedules also pin `America/New_York`, exchange calendar and tzdata versions.
Durations/deadlines use the clock contract; equality at expiry fails. Time ordering never uses a wall-clock string or input file order.

| Contract record | Required fields and invariant |
|---|---|
| Instrument | stable `instrument_id`, currency, venue, symbol-validity intervals, calendar ID/version, quantity/price precision, action support |
| Dataset | schema/version; source/rights reference; source class; instrument universe; coverage; raw object hashes; parser/transform versions; calendar/action versions; quality/exclusions report; admission decision and reviewer identity |
| Market fact | `event_id`, source/environment, instrument, kind, economic event time/session, optional factual vendor publication time, factual first observed time when captured, revision ID/predecessor, source sequence if proved, raw/normalized hashes |
| Availability | factual `observed_available_at`; optional factual `vendor_published_at`; separate `simulated_available_at_policy_id` and evaluated model time; availability mode and evidence reference |
| Engine event envelope | event ID/type, economic/effective time, effective knowledge time, source namespace/sequence scope, predecessor IDs, observation provenance, event payload hash, engine-assigned reduction sequence |
| Watermark | expected symbols/session, availability cutoff, selected revision policy, missing members/reasons, closed frontier identity; complete or skipped outcome |

Factual unknown fields are null with a reason. Never put a session date into factual publication/receipt fields to satisfy old constructors.
Current `RawBar` requires `vendor_published_at` and `available_at`; W1 must introduce a versioned representation and adapt its consumers, preserving old manifests byte-for-byte.
Classes stay separate: synthetic fixture; validated current-vintage history; recorded-as-observed; qualified historical PIT. The most restrictive class/assumption used survives report, export and comparison.
For observed replay, a fact is usable only once actually received and validated; provider publication alone is insufficient for the local consumer.
For qualified PIT replay, availability uses documented vintage/publication coverage plus the pinned consumer latency assumption; do not claim historical local receipts.
For current-vintage exploration, the assumed policy may make an old session available for simulation while actual capture stays current. This permits economics, not a factual PIT claim.
Assumed 20:00 delivery is explicitly modeled; data arriving after 09:00 cutoff cannot generate that session's missed order. Subsequent sessions may use it only under the declared revision/history policy.
Keep raw executable OHLC distinct from adjusted feature/benchmark series. Reconstruct total return from raw prices/actions once, or use an explicitly qualified adjusted comparator; never double-credit actions.
Daily OHLC cannot supply intraday spreads, liquidity paths or a 09:35 price. In the next-open proxy, the simulator privately reads the next session's open as a modeled execution outcome; it exposes neither that day's high/low/close nor a fabricated observed quote to the strategy.
An open-only synthetic execution event is labeled modeled, even though its price came from a later-delivered daily row. Its economics does not promote the row's factual availability.
Duplicate identical IDs collapse; conflicting same-ID payloads reject. Revision lineage is contiguous or explicitly provider-qualified; late corrections append new knowledge and never silently reopen an old decision watermark.
Future row changes must leave earlier decisions unchanged in both factual and assumed modes; updating a prior current-vintage value creates a distinct dataset/run.

## 3. One causal loop, including simultaneous timestamps

W2 introduces one application service at `packages/application/causal_engine.py`; it composes existing reducers. Historical, stateful forward and eventual live drivers use this service with distinct ports.
`packages/domain/strategy_replay.py` remains a pure callback transcript helper or delegates to the new service; it must not become a second independently evolving portfolio engine.
`packages/backtest/golden_runner.py` stays a regression oracle. Its fixture identities, fixed report and hardcoded runtime metadata cannot label a general run.

The deterministic queue is a stable topological order, with primary key effective knowledge time, then proven dependency edges, then the stage/namespace/sequence/ID keys below.
Dependencies may not point into future knowledge or form cycles. Source sequences order facts only inside their documented source/account stream; sequences from unrelated sources are incomparable.
All external events known at the frontier are frozen before reducing it. New local output gets a later engine sequence and cannot be injected retroactively into the input frontier.

| Stage at one knowledge frontier | Reduction and tie rule |
|---|---|
| 0 — validate/admit | Validate identity, availability, revision chain, calendar and completeness; reject ambiguous required facts; apply control/owner fence before any dispatch claim |
| 1 — market knowledge | Publish only available market revisions; close the complete or skipped watermark after all admitted equal-frontier market facts |
| 2 — economic facts | Apply authoritative execution/order corrections, known effective actions, cash flows and settlements in their proven economic dependency order; independent ties use source namespace, sequence-presence, sequence, event ID |
| 3 — existing simulated orders | For modeled execution observations, determine fills only for previously activated eligible orders; apply resulting order/ledger/settlement events immediately |
| 4 — account projection | Rebuild positions/FIFO basis, cash buckets, receivables/payables, pending commitments, marks and risk inputs from the new ledger revision |
| 5 — decisions | Invoke complete-market trigger then scheduled timer triggers, each by stable schedule ID/sequence/trigger ID; each callback receives the current projection and immediately completes stage 6 before the next callback |
| 6 — intent/risk | For that callback, convert targets against filled and outstanding quantities; run pure daily policy; atomically install batch/reservations in durable execution mode; record rejection or rebuild the committed snapshot before returning to stage 5 for another trigger |
| 7 — outbound scheduling | Activate eligible intents only after the creating decision; revalidate required execution-time inputs; newly activated orders cannot consume the current triggering observation |
| 8 — valuation/output | Publish frontier trace/checkpoint and scheduled marked report rows; explicit pre/post-flow valuations are taken around each flow during stage 2 |

A generic stage or lexical tie is not proof of economic precedence. Splits/dividends/fills sharing an effective time require explicit pre/post-action units and source/model dependency evidence; otherwise reject the affected scope.
Stages 5→6 are a serialized microcycle per callback, including at identical timestamps. A later trigger sees earlier approved-unsent commitments and strategy state from the same frontier. Stage 7 begins after the trigger microcycles; new intents still cannot fill from the current input observation.
In particular, derive dividend entitlement from holdings before the ex-date entitlement boundary; never from post-payment holdings or an ex-date purchase. A same-time split needs explicit pre/post-split dividend basis; no default ordering guesses it.
Preserve the existing rejection of ambiguous simultaneous entitlement/position changes until versioned replacement tests prove any newly supported case.
At a flow boundary, marks and economic facts proved to precede the flow must be reduced before `NAV_before`; apply the flow once; record `NAV_after = NAV_before + flow`; later facts cannot value the earlier boundary.
DAY expiration and cancel requests do not erase uncertain fills. Broker facts received after close still update accounting; unavailable execution events leave accepted orders unresolved until authoritative terminal evidence or the simulation model's explicit expiry event.
Incomplete daily data skips the decision; it does not freeze broker observation, controls or recovery. A feature gap clears affected warmup/window state unless a separately versioned imputation policy exists.
Close-derived targets never fill on that close. Even an equal timestamp from another event needs later causal sequence and the model's strict activation rule; current broker simulator's strictly-later-source-time guarantee remains the conservative default.

## 4. Account state, targets and accounting

Every callback receives an immutable `AccountSnapshot` containing account/run IDs, frontier sequence, ledger/order/control/risk versions, cash buckets, FIFO positions, causal marks, pending commitments, freshness/reconciliation state and strategy state.
The snapshot changes after every applied fill/action/cash event. No callback reuses start-of-run quantities as its live portfolio.
Targets contain target ID, strategy/config hash, trigger ID, whole-share desired quantities, validity/execution window and explanation; no provider order ID or transport permission.
Allocation targets are converted by floor to whole shares using causal reference prices and the frozen policy/cost buffer. Pending commitments and notional caps can reduce/reject quantities; no silent leverage.
For each instrument, effective committed quantity is filled quantity + open buy remainder − open sell remainder. Approved-unsent, UNKNOWN, working, partial and pending-cancel remainders count until authoritative release.
A repeated target at the same effective quantity emits no order. An opposing target cannot net away an unresolved commitment: cancel/reconcile first, then decide on a fresh snapshot.
Reference target marks are for sizing; execution-time quotes and risk revalidation remain separate mandatory inputs.

| Accounting convention | Frozen behavior |
|---|---|
| Numeric representation | Decimal arithmetic; preserve exact persisted `NUMERIC(28,10)` range/scale and 64-digit deterministic derived division; never ambient float arithmetic or implicit rounding |
| Journal | Balanced, immutable, append-only entries; source execution/activity identity controls idempotency; corrections/busts post deltas/reversals with ancestry |
| FIFO | Long-only whole-share lots; total basis excludes fees, matching current reducer; sell realizes proceeds minus released FIFO basis |
| Fees | Expense once when the execution fact applies; net realized P&L includes execution fees, including fees on still-open purchases; separately expose gross realized P&L and fees |
| Cash | Trade-date cash includes fills; settled cash differs by settlement obligations; available cash subtracts unsettled purchase payables and pending buy reserves without crediting unsettled/pending sales |
| Settlement | Use the dated standard-cycle and distinct settlement-business-day calendar pinned in section 1; actual settlement uses qualified facts. A simplified sensitivity is separately labelled and changes run identity |
| Dividends | Recognize income and receivable at known effective entitlement; payment moves receivable to cash once; receivable contributes to NAV |
| Splits | Change units and per-share basis while preserving total basis; require a causal post-split mark; fractional aggregate or individual FIFO lots require explicit cash-in-lieu support or visible scope rejection |
| External flows | Contributions/withdrawals change capital, not strategy P&L; withdrawals also require available cash and commitments checks |
| Corporate-action gaps | Missing entitlement/pay date, merger/delisting terms, fractional handling or ambiguous action ordering excludes affected period/instrument visibly; never synthesize payment or drop the row silently |

Economic NAV may use either trade-date cash + securities + dividend receivables, or settled cash + settlement receivables − payables + securities + dividend receivables; the two must reconcile.
A filled portion's original order reserve becomes its settlement payable rather than a second cash charge; release/transfer it atomically while keeping the unfilled remainder reserved. Each obligation is counted exactly once.
Net P&L over an interval is ending NAV − starting NAV − net external flows. Settlement is a classification change, not return.
Corrections preserve what was known at prior decisions. A restated economic report is a new artifact with correction coverage/version; it cannot overwrite the causal decision trace or claim that earlier risk knew the correction.
Fractional analytical benchmark units are report math only; they are never broker orders or account lot holdings.

## 5. Frozen run, event and report schema

The names below are declarative contract fields for a new version; W0 does not add Python models, SQL columns or migrations.

| Record | Mandatory fields |
|---|---|
| `RunSpec` | schema/version; account namespace/mode; dataset manifest/class/availability policy; universe/calendar/actions; strategy code/version/config hash; engine/reducer/risk versions; source revision and dirty patch hash; dependency/Python/numeric/tzdata pins; initial account/strategy state; schedule; fill/cost/settlement models; seed/RNG algorithm or explicit none; benchmark; evaluation/fold/scored/warmup specification; budgets; declared limitations |
| `RunIdentity` | hash of canonical `RunSpec` excluding transient job/attempt/wall-generation time; any semantic input change produces a new ID |
| `RunAttempt` | durable job/run ID, attempt ID, claim/fence, started/completed time, status/reason, progress/frontier/checkpoint, cancellation/failure evidence; one terminal publication per current attempt |
| `EngineTraceRow` | run ID, frontier/reduction sequence, event/trigger ID, predecessor IDs, visible dataset revision IDs, prior/result snapshot hashes, strategy state hashes, target/intent/risk/reservation/order IDs, reason codes and event provenance |
| `ValuationRow` | economic/knowledge time, sequence, scored flag/fold, NAV and mark quality, trade-date/settled/available cash, receivable/payable/reserved cash, quantity/basis/price/source/age per position, pre/post-flow identity, dividend income, realized/unrealized P&L, fees, exposure |
| `ExecutionRow` | order/intent/internal and broker fact IDs, source/environment, timestamps, quantity/price/fees, correction lineage, action/settlement links; closed FIFO trade rows derived separately from fills |
| `MetricValue` | name/version, value or null, unit, defined/undefined/approximate status, reason, sample count, exact input-window/valuation hashes, conventions and assumption IDs |
| `Report` | run/input/result hashes, separate attempt/generated-at artifact identity, status, data class and limitations, scored intervals, daily/flow equity rows, orders/fills/trades/terminal holdings, journal lineage, metrics/benchmark/stress comparisons and excluded intervals |

Cancelled/failed attempts retain pinned inputs and partial trace clearly labeled incomplete; they do not publish a completed performance report.
Same inputs/replay/seed reproduce semantic trace, ledger and report hashes; differing generation times may change only artifact identity.
Persist features at their own availability times; strategy state includes only prior state and visible inputs. Fit state and decision state have separate lineage.
Containers are optional local-runtime pins; use explicit not-applicable, not fixture digests or forged image hashes.

## 6. Valuation and return definitions

Value at each scored regular-session close using that session's raw closing mark once its declared availability is reached, and at every external-flow boundary where causal marks support exact valuation.
A valuation row distinguishes economic time from when it became computable. Data never becomes strategy-visible just because a report labels the economic close.
Terminal open holdings remain marked and included. A missing required current-session mark yields undefined authoritative NAV/affected metrics; retain a separately labeled last-known estimate, source time and age.
Do not bridge a missing mark interval and call its daily return exact. Close-to-close returns spanning an unknown flow valuation remain undefined for exact TWR.
Let `F` be an external flow (positive contribution) at a boundary. Record `V_before`, then `V_after=V_before+F` without artificial profit.
For each fully valued subperiod, growth is `V_end_before_next_flow / V_start_after_previous_flow`; linked TWR is the product of growth factors minus one.
Daily and cumulative returns use those linked factors. Simple profit-on-initial-capital, money-weighted returns and Modified Dietz, if added, are distinct named metrics with assumptions; no period-end adjustment is mislabeled exact TWR.
Exact flow timing uses immediately pre-flow causal marks; if only daily marks exist, either constrain synthetic flows to the valued boundary or report exact TWR undefined. An approximate method requires an explicit model/run pin.
Benchmark receives identical contributions/withdrawals at identical event boundaries, valued at its own causal marks. Report analytical benchmark assumptions, fees, cash treatment and any difference from constrained strategy exposure.
Drawdown uses the flow-neutral linked wealth index: `1 − wealth / running_peak`, not raw contributed NAV.
Default turnover is sum of absolute executed notionals divided by mean valid scored daily NAV; state this one-way convention. Average gross/net exposure is mean valid scored daily marked securities exposure/NAV, with sample coverage disclosed.
Daily return volatility uses sample standard deviation (`ddof=1`) and √252; excess-return Sharpe uses pinned risk-free convention (default assumed 0%, explicitly not a fetched rate).
Total return may be defined from complete short intervals. Annualized return/volatility/Sharpe/Sortino require at least 252 valid scored sessions by default; no calendar-year gaps may masquerade as contiguous sessions.
Zero variance/downside denominator makes the relevant ratio undefined; known zero volatility can be 0. Missing marks, nonpositive NAV, insufficient samples and absent risk-free inputs yield explicit reasons, never infinity or flattering zeros.
Annualized return uses linked growth raised to `252 / scored_session_count` only on a complete regular-session sample under this convention; pin another convention if required.
Trade statistics use completed matched FIFO quantities with proportional exit/buy fee attribution for trade analysis; portfolio fees remain expensed once. Do not count every partial fill as an independent winning trade.
Statistical confidence intervals and capacity claims are undefined until an explicit validated method exists; simple OHLC volume is not proof of executable capacity.

## 7. Evaluation warmup, reset and carry

Each fold contains ordered train, validation and test intervals, feature lookback, label horizon, purging/embargo policy, fit artifact, warmup interval, reset/carry mode and scored interval IDs.
Default independent-fold evaluation initializes the strategy and synthetic account afresh at the scored boundary; earlier eligible bars warm feature state only. No warmup orders, portfolio P&L or metrics are scored.
Training alone fits parameters/preprocessing. Validation chooses among recorded trials. Test/holdout never fits or selects a candidate; a changed choice is a new trial with new holdout requirements.
A 200-session feature must have 200 consecutive eligible completed sessions; insufficient history or a gap yields no target until re-warmed. Calendar holidays are not gaps; missing expected sessions are.
The default warmup budget is 252 earlier sessions; declared larger strategy history increases the requirement/budget before admission, not silently during a run.
In continuous-carry mode, carry account cash/lots/orders/reservations, strategy/feature state and their exact checkpoints across adjacent partitions. Do not reset indicators or cash while retaining favorable holdings.
Pending orders crossing a scored boundary are carried with original lineage in carry mode; independent reset mode begins without orders and does not fabricate liquidation proceeds from an earlier fold.
Each output interval is half-open `[start, end)` using pinned boundary sequences. Record the final endpoint mark once; adjacent folds may share that baseline value, but cannot score the same return/flow twice.
Fold statistics can be compared. Concatenation is allowed only for disjoint intervals with an explicit reset-normalized wealth convention or a continuous account; do not sum reset account NAV as one investable history.
Perturbing validation/test rows must not change training fits or earlier decision prefixes; later cash flows/corrections cannot affect earlier targets. Check both factual and assumed-availability modes.
Every attempted configuration, cancellation, failure and stress run joins the trial registry. Record any previously seen holdout material; calendar dates alone do not prove untouched evidence.

## 8. Keep/refactor/retire map and exclusive owners

`O` means orchestrator, which serializes shared schemas, migration IDs, generated API contracts and composition roots. Lane labels refer to the sole canonical plan, not additional roadmaps.
Exact per-file direct callers/test importers are in `core-source-map.json`; the table records grouped invariant/cutover tests, including indirect consumers and browser callers.
The JSON map is exhaustive for the 90 mapped core/data/research Python files at this revision. Its static-import scope does not assert completeness for dynamic/non-Python loading; UI callers and shared runtime boundaries below require cutover review.

| Existing source boundary | Actual callers / invariant tests | Disposition and wave owner |
|---|---|---|
| `packages/market_data/{models,source,normalization,temporal,calendar,security,quality,admission}.py` and package facade | adapters, ingestion, dataset reader; `test_market_data_models`, `test_market_data_admission`, `test_historical_market_data_source`, integration `test_market_data_ingestion` | Keep quality/calendar/identity; version availability/admission without recasting old facts. W1-A; O owns shared schema |
| `packages/adapters/market_data/tiingo_eod*.py` | capture/snapshot/identity/market-semantics CLI scripts and ingestion conversion; `test_tiingo_eod*` | Keep parser/lineage/raw/adjusted/action checks; replace deliberately unavailable historical conversion with honest class. W1-A |
| `packages/adapters/market_data/{recorded,reference_admission,reference_fixture}.py` | ingestion and provider fixtures; historical-source/ingestion tests | Keep offline oracle and explicit fixture class. W1-A |
| `packages/adapters/market_data/{sharadar_sfp,sharadar_sfp_capture,provider_probe}.py` | probe/capture scripts; `test_sharadar_sfp`, `test_market_data_provider_probe` | Retain dormant; no parallel provider expansion or qualification transfer. W1-A inventories consumers only |
| `packages/datasets/{parquet,reader,replay_tape,feature_artifact}.py` | ingestion, manifest replay, feature worker; `test_parquet_store`, `test_replay_manifest`, integration `test_manifest_replay_tape` | Keep content hashes and bounded readers; adapt v2 class/availability. W1-A, then W3-A |
| `packages/application/{market_data_ingestion,market_data_admission,production_market_data_admission,captured_tape_research_validity,manifest_replay}.py` | worker and admission/replay scripts; `test_market_data_admission_io`, captured/production validity unit/integration gates | Keep historic stronger claims; add positive owner-reviewed exploratory admission. W1-A; W3-A consumer |
| `packages/domain/{canonical,decimal_math,identifiers}.py` | all financial/data consumers; `test_canonical`, `test_identifiers`, reducer ambient-context/permutation tests | Keep exact numeric/hash contracts; O approves any version change |
| `packages/domain/{models,decision,market_batch,strategy,strategy_state,portfolio}.py` | replay, feature targets, golden runner, account risk; `test_portfolio_intent_batches`, `test_replay`, `test_strategy_replay` | Extend snapshot/commitments/target windows; O shared contract, W2-A converter; no duplicate working target |
| `packages/domain/{replay,replay_manifest,strategy_replay,clock}.py` | golden runner, feature replay, manifest replay, walking thread; temporal permutation/prefix tests | Retain causal batch/time invariants; remove fixed-position snapshot from product path. W2-A; clock owned W1-C through O |
| `packages/domain/{order_reducer,ledger_reducer,account_projection,corporate_action_ledger,settlement_ledger}.py` | golden runner, phase2 ledger persistence, simulation/account risk; corresponding unit tests and accounting cases E1–E8 | Keep balanced immutable/fill-correction/FIFO/settlement/action rules; integrate in one loop. W2-B; W4-A/B consumers |
| `packages/backtest/{simulated_broker,simulation_horizon}.py` | golden runner, horizon persistence; `test_simulated_broker`, `test_simulation_horizon` | Keep strict later-source fill/consumed approval/horizon invariants; add named daily model. W2-B; W4-C reuses economics |
| `packages/backtest/golden_runner.py` | `packages/application/backtest_worker.py`; `test_golden_runner`, `test_backtest_report` | Keep small accounting oracle; retire fixed product dispatch/report values only after general engine reproduces facts. W2-O cutover |
| `packages/domain/{accounting,execution,walking_thread}.py`, `packages/persistence/walking_thread.py` | runtime stub/API walking fixture; `test_accounting`, `test_walking_thread`, `test_risk_and_execution` | Retire early buy-only/simple simulator as product economics; retain isolated useful fixtures. W2-O; W5-B removes fixture ops read models |
| `packages/domain/fixture_segment_economics.py`, `packages/application/{fixture_segment_economics,_fixture_segment_economic_child}.py` | fixture worker/API; `test_fixture_segment_economics`, `test_fixture_segment_worker` | Freeze immediate-close/zero-cost economics as test-only; migrate product consumers to shared engine. W2-A then W3-A |
| `packages/domain/backtest_report.py` | golden runner, API backtest views, workflow; `test_backtest_report`, `test_phase2_backtest_api` | Preserve self-validation/undefined conventions; add event-flow/report schema and derived calculators. W2-C; O schema/API |
| `packages/domain/backtest_job.py`, `packages/application/backtest_worker.py`, `packages/persistence/backtest_workflow.py` | worker, API; `test_backtest_job`, `test_phase2_backtest_{worker,workflow,api}` | Keep claims/cancel/terminal publication; generalize selected dataset/config route. W3-A; O composition |
| `packages/domain/{feature,feature_replay,feature_target,feature_target_replay}.py`, `packages/datasets/feature_artifact.py` | fixture/evaluation worker; `test_feature_replay`, `test_feature_target_replay` | Keep availability/parity/gap reset; connect to canonical account/evaluation path. W3-B |
| `packages/domain/{experiment_governance,experiment_registry,fixture_segment_worker}.py`, `packages/persistence/{experiment_governance,fixture_segment_worker}.py`, `packages/application/fixture_segment_worker.py` | API experiment/fixture views; experiment/fixture unit and persistence tests | Keep attempts/fits/holdout lineage; replace fixture-only qualification consumers. W3-B semantics, W3-A job integration sequentially |
| `packages/persistence/{market_data,replay,phase2_ledger,simulation_horizon,immutable}.py` | ingestion, workflow, fixture tests; corresponding integration tests | Keep transactions/history/idempotency; O schema/migrations; W1-A data, W2-B ledger, W3-A runs |
| `apps/api/{backtest_views,data_views,experiment_views,fixture_segment_views,contracts,main}.py`, `apps/worker/main.py` | API tests and React research routes | General actual outputs; O owns main/contracts/worker composition; W3-A views; W3-C browser |
| `apps/web/src/features/research/*`, `apps/web/src/api/{client,queries,researchFixtures,schema.generated,types}.ts` | Backtests/Experiments/Strategies UI tests, generated API contract checks | W3-C consumes actual general report/job APIs; O serializes generated schema; fixture presentation never implies qualification |

Risk, OMS, process/time/build and broker dependency ownership belongs to the companion account/runtime map; no core worker edits those shared seams independently.
W1 schema request: new data class/nullable factual timestamp/assumption references, preserving old immutable IDs. W2 schema request: engine event/snapshot/commitment/report v2 pins. W3 schema request: general run/evaluation/attempt associations. O chooses additive migration IDs after checking current heads; W0 allocates no guessed migration number.
W4–5 consumers use the W2 engine/accounting contract; any reconciliation or broker correction extension gets an explicit version and retained old-event decoder. Do not drop historical tables or rewrite old rows.

## 9. Replacement evidence and W0 assessment

The orchestration baseline records actual pass/fail/skip counts; test names here identify requirements, not passing results.
W2 must independently instantiate E1–E8 against the engine and reports, preserving exact balances and explicit undefined/rejected outcomes. Oracle policy fixtures are separately named and cannot bypass default product risk caps.
E6 explicitly specifies fee correction/refund in its synthetic facts. Actual broker corrections or busts do not imply a fee refund unless qualified facts say so.
Also require: two datasets/two configurable strategies; fills change next cash/positions/orders; repeated target with commitment emits zero; future-row perturbation preserves prefixes; permutations/duplicates preserve semantics; partial/cancel/UNKNOWN capacity persists; close signal cannot use same-close fill.
W3 must prove flow-neutral benchmark/TWR, open/stale mark behavior, fit/test isolation, reset/carry boundaries and nonduplicated scored windows through actual API/worker/browser outputs.
No existing financial, temporal, identity or state-transition invariant is retired solely because its filename refers to an old phase. Rehome it before removing its product caller.
W0 core exit is contract readiness: one canonical engine seam, specified data/account/report/evaluation semantics, independently checkable cases and exact caller ownership. It is not implementation, source qualification, strategy profitability or order authority.
