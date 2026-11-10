# Personal-v1 scope and default contract

Contract `personal-v1-scope/1`, frozen for implementation at Wave 0 on 2026-09-08. This supporting specification implements the decisions in [the sole architecture](../../ARCHITECTURE.md); [the sole plan](../../IMPLEMENTATION_PLAN.md) controls sequencing. These are engineering defaults for reproducible development and simulation. No provider access, deployment, live financial amount, or order permission follows from them.

## Scope and schedule

| Input | Frozen value | Qualification / change rule |
|---|---|---|
| Owner and account | One owner, one application-exclusive USD cash account, one active strategy | Actual account identity/eligibility and exclusivity require W1 evidence; no margin or shorting |
| Instruments | DIA, IWM, QQQ, SPY, declared subset allowed | Fixed-universe selection bias disclosed; instrument/calendar identity is versioned |
| Order subset | Long-only whole-share DAY market orders in regular hours; cancel supported; replacement unsupported | Live endpoint behavior remains unqualified |
| Daily decision | Attempt at 20:00 America/New_York after the regular-session bar is complete and available; a missing bar may be awaited until 09:00 on the next regular session | At cutoff equality, skip and report. A decision is admitted once per strategy/session; waiting is not repeated order generation. Do not substitute incomplete bars or replay an expired backlog |
| Forward execution | Next regular session, 09:35 inclusive to 09:40 exclusive America/New_York, with fresh observations | Exchange calendar handles holidays/half-days/DST. Stale session authorization, risk, quote or reconciliation blocks dispatch; missed window expires the intent |
| Daily-only exploratory fill | Explicit separate `next-open-proxy` model at the next eligible regular-session open | Only the modeled open observation becomes available then; full daily OHLC arrives later. It is not execution-time quote, spread, liquidity, forward or live evidence |
| Source candidate | Tiingo EOD; licensed owner-imported frozen snapshot fallback through the same canonical port | W1 qualifies rights, raw/adjusted/action semantics, delivery timing and scope. No subscription/capture is authorized by this contract |
| Execution observations | Source-stamped, environment/account-appropriate quote with receipt time, instrument, bid/ask or documented price semantics, entitlement/source identity and revision | W1 records actual feed and delay semantics; no assumed SIP/NBBO. Unsupported/stale quote means no new exposure |
| Missing fractional action treatment | Reject affected scope with an explicit validation reason until checked cash-in-lieu accounting exists | Never silently round positions or invent cash |

## Research and evaluation defaults

| Input | Frozen development default |
|---|---|
| Capital | Synthetic USD 10,000 opening settled cash; a fixture may declare another explicit opening balance |
| Reference strategies | Buy/hold or periodic rebalance baseline and a transparent daily trend rule; both obey the same daily risk policy |
| Default sizing | At most 25% NAV per symbol; at most 95% total gross, retaining cash. Single-symbol references remain at most 25% invested |
| Benchmark | SPY total-return buy/hold with matching external-flow timing and the same cost assumptions; additionally show cash. Benchmark attribution is descriptive, not an instruction to buy SPY |
| Study interval | Requested 2010-01-01 through 2025-12-31, contingent on licensed complete coverage; never fabricate missing history |
| Chronological partition | Train 2010–2018; validation 2019–2022; holdout 2023–2025. Actual scored bounds use eligible exchange sessions and are recorded in each run |
| Settlement model | Dated standard cycle and distinct settlement-business-day calendar as specified/cited in the core contract; 09:30 ET availability is a simulation assumption, actual release requires facts |
| Warmup | 252 eligible prior sessions by default; no scored returns or strategy trades during warmup; insufficient history rejects the required lookback or narrows the explicitly declared scored interval |
| Reset/carry | Reset account, strategy and fitted state at each independent fold; fitting uses training only. Continuous carry is a different explicit protocol preserving ledger/orders/cash and causal state across folds; never combine reset and carried returns |
| Holdout honesty | These dates are a prospective protocol default for new runs, not evidence the owner has never seen those periods. Record prior inspection/selection; if touched, label retrospective validation and reserve new untouched/forward evidence |
| Acceptance | Freeze hypothesis, candidate, costs, policy, attempted configurations and suitability criteria before scoring the holdout or forward window. Software acceptance is deterministic economics/correct isolation; no profitability threshold is invented as owner intent |
| Cost model | Raw executable-price basis; base 5 basis points adverse slippage per side plus USD 0.01/share fee; 20 basis points plus USD 0.02/share adverse scenario; also 1x/2x/3x base-cost stresses. All are model assumptions, not actual broker fees; zero-cost fixtures are explicitly tests |

The analytical benchmark may use fractional report-only units for exact cash-flow matching; it is identified as an analytical total-return comparator with its own allocation/exposure, not a deployable whole-share strategy or an exception to account risk. A deployable whole-share benchmark must separately report residual cash and its model identity.

Pure daily risk and metric details are normative in [account/runtime](account-runtime.md) and [core/engine](core-engine.md). Oracle arithmetic uses explicitly stated test policy/balances; it does not secretly relax the default strategy profile.

## Resource defaults

One research job at a time, at most two CPU cores and 4 GiB memory, 30-minute wall deadline, 1 GiB per-run result/artifact cap, and 10 GiB per imported dataset. Strategy subprocess deadlines remain 2-second warning, 5-second output rejection and 8-second cleanup from one monotonic origin. Import or report exhaustion ends with a visible bounded failure; it never publishes a truncated successful result. These caps require measurement in W1/W3; process-level enforcement is not implemented by this document.

Stop new research if free disk is below the greater of 10 GiB or 15%; reserve coordinator/ledger/alert capacity. Retain manifests, trial records, ledger/event journals and published reports; temporary intermediates may expire after seven days if not needed by an active/recovering run. No automatic deletion of source observations or financial history is approved. Review research storage at 50 GiB and stop new imports until an owner storage decision. External spend default is zero new commitments; actual monthly budget is an owner input before purchases/deployment.

## Qualification inputs, not Wave 0 blockers

W1 must record actual rights/retention terms, selected dataset dates/action coverage and factual delivery timing; E*TRADE API access and allowed environment, OAuth daily workflow, actual account binding/type, complete read/activity/fill identity fields, pagination and quote source/entitlement; host UTC synchronization/drift producer and observed suspend/restart behavior. Offline fixture development can proceed only within its stated evidence class. Missing provider/account evidence blocks the connected lane, not this completed contract work.

W5–W8 additionally need a dedicated awake host for unattended windows, private authenticated owner access, approved alert destination, backup/restore/storage service and measured budget. Live capital, order/batch/account notional, share and loss limits remain unset until the separately authorized live dossier/canary. `live_enabled=false` and halted startup persist; no inherited paper limit or historical approval supplies these inputs.
