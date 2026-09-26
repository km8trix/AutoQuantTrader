# AutoQuantTrader specification

Verified against source revision `b1156ba` on 2026-09-26. This is a current product summary, not new trading authority. Read [STATUS](STATUS.md) for the latest validation result, [PLAN](PLAN.md) for the next work, and the frozen [personal-v1 contracts](contracts/personal-v1/README.md) with the [account eligibility amendment](contracts/personal-v1/account-eligibility-amendment.md) for detailed requirements. Historical evidence remains valid only for its bound revision and stated scope.

## Product and confirmed scope

AutoQuantTrader is a personal, event-driven quantitative research and trading system. It moves versioned strategies through reproducible research, deterministic economic backtests, stateful forward simulation, and eventually an explicitly authorized live canary. Correct accounting, causal data use, durable recovery and explicit operator control take priority over low latency.

The accepted personal-v1 scope is:

- One operator, one explicitly selected application-exclusive USD brokerage account, and one active strategy.
- DIA, IWM, QQQ and SPY, or a declared subset; long-only whole-share regular-session `DAY` market orders. Cancel is in scope; replacement, shorting, derivatives, leverage and extended-hours execution are outside v1.
- E*TRADE is the selected eventual live broker. Account privileges may be CASH or explicitly selected MARGIN under the amendment. The strategy remains cash-funded and must not borrow. Margin buying power is not usable strategy cash.
- Tiingo EOD or a licensed owner-imported frozen snapshot supplies daily research data through the canonical historical port. Historical assumptions, current-vintage observations, genuine captures and synthetic fixtures remain distinct evidence classes.
- Production order submission, live activation, fund transfers, live financial limits and automatic re-arm are not authorized by successful builds, tests, reads, source merges or this specification.

These requirements come from [scope/defaults](contracts/personal-v1/scope-defaults.md), [account/runtime](contracts/personal-v1/account-runtime.md), and the dated account amendment. The amendment supersedes the original pack's cash-only account eligibility; it does not relax strategy financing or risk.

## Implemented product behavior

| Capability | Current implementation and limits |
|---|---|
| Historical import | Explicit Tiingo files and versioned declarations/calendars become private immutable research archives. Raw prices, adjusted fields, actions, receipt times, source rights and availability assumptions are retained. Invalid or unsupported scope rejects. A small real sample was qualified; complete study-period coverage and historical publication vintages have not been established. |
| Canonical economics | `packages/application/causal_engine.py` advances causal market, strategy, order and account state; the pure daily risk policy authorizes target-derived intents. Simulated fills, fees, settlement, supported actions and external flows feed exact-decimal accounting and derived reports. Buy/hold and a transparent trend rule are reference strategies, not claims of investment suitability. |
| Research workflow | Explicit dataset/fixture registration, durable job claims, bounded child execution, cancellation/recovery, atomic report publication, descriptive experiments, comparisons and exports. FastAPI and React expose the actual personal research path. The older fixture catalog/golden demonstration remains separately preserved. |
| Research provenance | Dataset, strategy/configuration, code/build, calendars, cost model, prior access, evaluation windows and outputs are bound to identities. Holdout labels cannot manufacture a never-seen period. |
| Conventional runtime | The personal simulation CLI starts HALTED, holds an exclusive local lock and checks conventional clock/process state. It is not an active strategy launcher. The optional Chrony bridge is locally tested; its existence is not actual host-clock qualification. |
| Continuous simulation | Wave 4 contains durable account checkpoints, daily risk/attempt history, source bindings, independent stateful venue records, applied reconciliation, captured-fixture replay, and a bounded HALTED restore/integrity worker. Integration acceptance remains incomplete. |
| Provider reads | E*TRADE OAuth, account and quote parsers/read adapters plus Tiingo capture tooling exist. Prior bounded read/sample evidence does not qualify present sessions, current entitlement, financing semantics, genuine integrated forward capture or broker execution. |

Wave 1 foundations, Wave 2 canonical offline economics and Wave 3 research workflow have recorded merged-revision acceptance. Wave 4 is current; the historical Phase/Wave 7 native narrative preserved in README is not the current product status. See [implementation history](IMPLEMENTATION_PLAN.md) and the [Wave 4 checkpoint](reviews/2026-09-24-wave4-integration/README.md).

Fresh production-class publication remains explicitly blocked in `capture_forward` by `CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED`; its calendar consistency helper establishes matching content only. The continuous factory accepts restore/integrity operations and requires persisted HALTED control. These guards must not be removed simply to make an end-to-end demonstration pass.

## Required causal and financial behavior

- Replay observes facts only at their factual or explicitly modeled availability time. Future rows cannot change earlier decisions. Immutable manifests preserve data class and assumptions through reports and exports.
- A daily decision is attempted at 20:00 America/New_York after the completed bar is available. Missing data may be awaited until 09:00 the next regular session; equality at the cutoff skips. One admitted decision per strategy/source session; no expired backlog replay.
- Intended forward execution is the next eligible regular session from 09:35 inclusive to 09:40 exclusive with fresh source-stamped observations. Calendar/DST/half-day rules apply. A missed window expires the intent. Daily-only `next-open-proxy` fills remain an explicitly different exploratory model.
- Strategies produce targets, not broker commands. Independent risk sees actual positions plus all outstanding commitments. Pending sells and unsettled sale proceeds do not fund buys or reduce conservative exposure.
- Exact Decimal ledger postings, fees, cash, shares and settlement obligations remain balanced and replayable. Fills are applied even when they expose a limit breach; the response is halt/reconciliation, never discarding real facts.
- Missing risk inputs fail closed. Unknown financial values remain unavailable, not zero. Fractional action scope without checked cash-in-lieu accounting rejects visibly.
- One fenced account writer serializes policy/control/risk/reservations and durable send claims. Broker I/O occurs outside database transactions. Stale ownership or unresolved reconciliation prevents new exposure.
- Ambiguous dispatch remains `UNKNOWN` with capacity held. Do not retry Place automatically, infer nonacceptance from empty/equal views, or borrow an Alpaca client-ID guarantee for E*TRADE. Recovery requires authoritative evidence and the applicable owner disposition.
- Restart, restore, lease expiry, session renewal and CI cannot re-arm. Pause/halt, cancel, flatten and process stop have distinct meanings; stopping a process does not establish flat broker positions.
- Credential and account namespaces remain environment-specific. Research children and browser bundles receive no production broker credentials. Secret material and licensed/private payloads remain outside Git and ordinary logs.

## Accepted engineering defaults and assumptions

These defaults are reproducible simulation inputs, not approved live amounts or factual broker fees:

| Default or assumption | Required qualification/label |
|---|---|
| USD 10,000 synthetic opening settled cash; at most 25% NAV per symbol and 95% gross | Explicit fixture overrides remain separate oracle policies; none creates a live assignment. Detailed quantity, loss, drawdown and request ceilings stay in the frozen daily policy. |
| Base adverse slippage 5 bps/side plus USD 0.01/share; adverse 20 bps plus USD 0.02/share; 1x/2x/3x stresses | Modeled costs, not actual E*TRADE fees or execution quality. |
| Requested history 2010–2025; train 2010–2018, validation 2019–2022, holdout 2023–2025; 252-session warmup | Contingent on licensed coverage. Record actual scored bounds, prior inspection and exclusions. Never invent missing history or claim untouched holdout without evidence. |
| SPY analytical total-return comparator and cash with matched external-flow timing | Descriptive benchmark; fractional report-only comparator units do not permit fractional strategy orders. |
| Reset account/strategy/fitted state for independent folds; fit only on training | Continuous carry is a separate declared protocol; do not combine carried and reset returns. |
| Daily historical availability at the declared modeled time; modeled next-open execution and settlement-release timing | Real receipt time does not establish original publication/revision time. Synthetic operational health is not measured production readiness. |
| One research job, at most two CPU cores, 4 GiB memory, 30-minute deadline, 1 GiB output, 10 GiB imported dataset | Existing implementation-specific smaller input/record bounds also apply. Do not enlarge limits to get a failing validation to pass. |

Software acceptance requires deterministic economics, isolation, recovery, causal correctness and accurate reporting. No profitability threshold has been inferred from owner intent. Backtest performance does not imply future profitability.

## Intended outcomes still requiring qualification

1. Complete Wave 4 on its exact revision: stateful-session acceptance; actual authorized captured-session decision parity; scoped account/source qualification; approved initializer work; review and merged-revision verification. The revised retained-history startup passed Linux CI within existing bounds; see STATUS for the accepted revision.
2. After Wave 4, complete live-disabled restricted E*TRADE protocol code, durable operational controls, supervised recovery, backup/restore, alerts and fault drills (Wave 5).
3. Freeze the strategy/risk/runtime candidate and gather separately labeled actual-observation simulation and authorized broker protocol/read/preview evidence. The established forward plan requires at least four calendar weeks and 20 intended market sessions plus fault quotas (Wave 6).
4. Only after the dossier and new explicit owner authorization, perform a minimum-size live canary in a specified account/window/financial envelope (Wave 7). Unattended personal operation needs a separate approved operating envelope, host and recovery evidence (Wave 8).

## Unresolved inputs and product questions

| Input | Current boundary |
|---|---|
| Initializer approval and exact local simulation initialization scope | Existing records preserve a separate owner gate. Ordinary offline tests on newly created fixtures can continue; do not mutate the retained account or reinterpret this request as initializer approval. |
| Fresh E*TRADE OAuth and a current reviewed quote window | Earlier read/retention authorization remains scoped; expired sessions/windows supply no access. Provider interaction is not necessary for routine development validation. |
| Account currency, settled cash/restrictions, liabilities, discrepancies and recovery/correction identity | Production read traversal is partial evidence. Missing or contradictory account semantics block connected execution. |
| Genuine forward-source ownership and complete actual-session replay | Current fresh non-fixture publication denies admission. Establish the source/clock/calendar/rights/account boundary before changing the guard. |
| Full historical coverage, action truth, vintage availability and current quota/feed quality | Small current-vintage samples do not settle these. Preserve honest data classification and unsupported-scope rejection. |
| Strategy suitability criteria and prior-access declarations before forward qualification | Reference strategies and default dates do not decide owner acceptance criteria. A finding that no strategy qualifies is valid. |
| Exact live capital, loss/notional limits, account and order canary scope | Unspecified and disabled until separate owner approval. |
| Always-on host, backup destination, alert route/recipient, operating budget and unattended envelope | Local supervised development first. No purchase, deployment or service activation is implied. |

No unresolved live or provider input should prevent an independent, credential-free engineering task. Record blockers precisely, preserve working behavior, and continue the next eligible task from PLAN.
