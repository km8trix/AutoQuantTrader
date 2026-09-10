# Wave 3 research UI proposal

Historical lane design record. The integrated behavior and acceptance status are recorded in [the canonical plan](../IMPLEMENTATION_PLAN.md#18-current-wave-3-handoff), [the research runbook](../runbooks/personal-v1-research.md) and [the Wave 3 evidence index](../reviews/2026-09-09-wave3/README.md). Proposal-era permissions, names and open questions below are retained as design history.

Implementation authorized after the orchestrator's API freeze. Base: merged Wave 2 `6ea218addaa38d1c36c69b6a7ffbe564d701f834`, branch `codex/personal-v1-w3-ui`. The Wave 3 dispatch supersedes the checkout's historical Wave 2 pending-merge handoff. This proposal implements lane C of [the canonical plan, section 7](../IMPLEMENTATION_PLAN.md#7-wave-3--usable-research-and-evidence-quality), using the [core reporting/evaluation contract](../contracts/personal-v1/core-engine.md) and existing `personal-report/2` records.

The accepted seam is `/api/v1/research/personal`: catalog GET; runs GET/POST; runs/{job_id} GET; runs/{job_id}/cancel POST; runs/{job_id}/report GET; runs/{job_id}/rows GET with `kind`, `report_sha256`, `offset`, and `limit<=200`; comparison POST with 2–8 job IDs (read-only); experiments GET/POST and experiments/{id} GET. States are queued/running/completed/incomplete/failed/cancelled with a separate `cancel_requested`; attempt history includes abandoned. Generated central types are authoritative. Root additionally delegated the new `apps/api/personal_research_contracts.py` projection-only models, `apps/web/src/features/research/researchTestFixtures.ts` test-only response helper, and `apps/web/src/app/{AppRoutes.tsx,AppRoutes.test.tsx,navigation.tsx}` to C. Root owns transport exports and schema generation. Experiments are descriptive-only, with prior access required, ordered train/validation/test boundaries and four fixed cost scenarios; suitability remains not assessed. There are no learned-parameter, untouched-data or automatic qualification claims. This accepted seam supersedes provisional operation/criteria suggestions below.

## Current state and proposed cutover

The existing `/research/strategies`, `/research/backtests` and `/research/experiments` screens consume fixture-specific strategy/run contracts and governance snapshots. `api/client.ts` can substitute development fixtures after API errors. The old report panel describes simple cash-flow-adjusted returns; its chart requires every equity point to be a finite number. These are historical diagnostic views, not consumers of the Wave 2 event-valued report.

Add actual-run pages using the current MUI layout, React Query and SVG chart approach, without a new dependency. C wires them into the existing default research routes under the follow-up delegation. Retain the old pages under an explicit `/research/history/...` route group with diagnostic/history labels and links. Default research requests never fall back to fixture results, including in development. Component-test response fixtures remain ordinary test inputs. Existing operational, trading, data-quality and settings routes remain intact.

Dataset selection lives at the start of the runs page, avoiding a second disconnected dataset catalog. The existing `/data/datasets` screen can remain available for its current purpose. No dataset upload, provider acquisition or private filesystem browser is required by this UI slice.

## Minimal user flow

1. **Select data.** The runs page lists server-registered immutable datasets, dates, symbols, session coverage, data class, availability assumptions and limitations. It distinguishes synthetic engineering data from real current-vintage exploratory history. A known prior-access declaration is visible. The five-session real sample is selectable only for server-supported runs; missing warmup and annualized coverage remain explicit. Selection alone neither qualifies historical PIT nor proves untouched holdout.
2. **Select strategy and configuration.** Show the two reference strategies and their server-supported parameter fields, defaults and constraints. The owner can change allowed values, initial cash, selected scored interval and approved cost scenario. The server validates and freezes configuration/model/dataset pins; the browser neither computes a semantic hash nor estimates admissibility using its own economics. Display field errors and server admission reasons beside the controls. A strategy link preselects the strategy while preserving deliberate dataset selection.
3. **Launch and follow a durable run.** Submit the exact selected inputs with a stable idempotency key and existing same-origin/CSRF conventions. An ambiguous response retains the key and request body for retry. Show the server's run/job identity, state, progress if measured, attempt/recovery history and publication identity. Refresh/deep links recover the selected run from the API. Cancel sends a separate idempotent command; a request acknowledgment means cancellation is pending until authoritative state changes. Launch and cancel availability come from explicit research capabilities.
4. **Inspect the report.** Show ending NAV, net P&L, event-timed TWR, maximum drawdown, execution costs and coverage first. Provide account NAV and flow-neutral wealth views with benchmark/cash comparators, execution and completed FIFO trade tables, open positions, journal rows, and assumptions/provenance. Incomplete runs and missing marks retain available account facts with clear status. They never appear as completed performance results. Download the immutable server artifact rather than rebuilding a report in JavaScript.
5. **Compare two runs.** Select two retained results, preserving selection in the URL. Display side-by-side metrics, benchmark and base/adverse-cost results with dataset/configuration differences, scored periods, coverage and assumptions. The server supplies compatibility and any differences; the UI does not join return streams, normalize mismatched intervals or rank an undefined result. Noncomparable results can remain inspectable side by side with the reason visible.
6. **Inspect/create an experiment.** Show ordered training/validation/test and warmup intervals, fit lineage, reset/carry policy, trial history and criteria. Record prior access and criteria before requesting new evaluation. Show frozen versus draft state and server admission reasons. Previously viewed or unknown-access periods remain honestly labeled; sealing a record cannot restore untouched status. Every attempted configuration, cancellation, failure and cost stress appears in the registry. Display server-produced base/adverse-cost and benchmark results, candidate disposition and limitations. “No candidate meets the criteria” is a normal outcome. Withheld results must be absent from the projection until server-authorized release, not merely hidden by CSS.

## Exact lane C frontend allowlist

All paths below are relative to the repository root. No edits outside this list without a separate ownership handoff.

New actual-run components and helpers:

- `apps/web/src/features/research/ResearchRunsPage.tsx`
- `apps/web/src/features/research/ResearchStrategiesPage.tsx`
- `apps/web/src/features/research/ResearchExperimentsPage.tsx`
- `apps/web/src/features/research/ResearchRunForm.tsx`
- `apps/web/src/features/research/ResearchRunReport.tsx`
- `apps/web/src/features/research/ResearchEquityChart.tsx`
- `apps/web/src/features/research/ResearchComparisonPanel.tsx`
- `apps/web/src/features/research/researchApi.ts`
- `apps/web/src/features/research/researchQueries.ts`

New focused tests:

- `apps/web/src/features/research/ResearchRunsPage.test.tsx`
- `apps/web/src/features/research/ResearchStrategiesPage.test.tsx`
- `apps/web/src/features/research/ResearchExperimentsPage.test.tsx`
- `apps/web/src/features/research/ResearchRunReport.test.tsx`
- `apps/web/src/features/research/ResearchEquityChart.test.tsx`
- `apps/web/src/features/research/ResearchComparisonPanel.test.tsx`
- `apps/web/src/features/research/researchApi.test.ts`

Existing files, limited to explicit diagnostic/history titles, descriptions and corresponding assertions:

- `apps/web/src/features/research/StrategiesPage.tsx`
- `apps/web/src/features/research/StrategiesPage.test.tsx`
- `apps/web/src/features/research/BacktestsPage.tsx`
- `apps/web/src/features/research/BacktestsPage.test.tsx`
- `apps/web/src/features/research/ExperimentsPage.tsx`
- `apps/web/src/features/research/ExperimentsPage.test.tsx`

Proposal artifact: `docs/proposals/wave3-ui.md`.

Reuse `ResearchPageComponents.tsx`, shared load states, page headers and formatting helpers without changing them. Keep the old `BacktestReportPanel.tsx` and `EquityCurveChart.tsx` for historical reports; their economics and legacy contract remain unchanged. New page exports are `ResearchRunsPage`, `ResearchStrategiesPage` and `ResearchExperimentsPage`; route selection/query parameters provide dataset/strategy/run/experiment identity. The runs and experiments pages may accept the existing `bootstrap: UiBootstrap` prop if the frozen capability seam remains there.

The orchestrator owns `apps/web/src/api/{schema.generated.ts,types.ts,client.ts,queries.ts}`, backend routes, shared domain contracts, generated artifacts, database migrations and composition. Its shared client exports the existing no-fallback `requestJson`; lane C's `researchApi.ts` contains endpoint wrappers typed from generated contracts. C additionally owns the delegated `apps/web/src/app/{AppRoutes.tsx,AppRoutes.test.tsx,navigation.tsx}` cutover and the exact three-route addition to `apps/web/config/production-bundle-policy.json`. The final delegation includes only the exact 11-to-14 route-count update in `apps/web/scripts/verify-production-bundle.mjs`, `apps/web/scripts/verify-production-bundle.node.mjs`, and `apps/web/scripts/test-fixtures/production-bundle.json`, preserving integrity checks and byte budgets. `WorkspaceApp.tsx` needs no change. Do not create parallel handwritten API interfaces. Package/lock/CI files remain root-owned.

## Required API freeze

Suggested additive namespace: `/api/v1/research/personal`. Names are a proposal; root freezes the actual paths, generated record names and state enums with A/B before implementation. Existing fixture/governance routes stay available to explicit history pages.

| Operation | Minimum authoritative projection or request |
| --- | --- |
| `GET /catalog` | Dataset ID/manifest hash, display name, symbols/calendar, date and eligible-session coverage, class, availability policy, limitations, access-history summary; strategy ID/version, allowed typed parameter definitions/defaults/bounds, required warmup; available cost/benchmark/evaluation configurations; research launch/cancel/evaluation capabilities and reasons. Only registered import IDs, no private source paths. |
| `POST /runs` | Dataset identity/hash, strategy/version and allowed configuration values, initial cash, scored/warmup selection, cost/benchmark/evaluation references and optional experiment/trial binding. Server returns canonical spec/config hashes, run/job identity and authoritative admission/state. Invalid requests return structured field/reason codes. |
| `GET /runs`, `GET /runs/{id}` | Bounded list/detail; run/spec identity, dataset/strategy/config and class summary, state, created/updated times, measured progress or null, attempts/recovery events, cancel state/capability, error reasons, result/report hashes and artifact availability. Cancellation/failure preserve attempted inputs. |
| `POST /runs/{id}/cancel` | Idempotent command acknowledgment plus current state/version; conflict/already-terminal is explicit. The client does not manufacture a terminal state or a report. |
| `GET /runs/{id}/report` | A projection of the accepted Wave 2 report: run/result/report hashes, separate artifact attempt/generated time, report/run status, currency, scored/warmup/fold boundaries, class, limitations, conventions, metrics and coverage, benchmark/cash metrics, terminal snapshot summary, retained assumptions and immutable export link. |
| `GET /runs/{id}/rows?kind=...&cursor=...` | Stable pages for equity/wealth, effective executions, FIFO trades, journal and terminal positions. Each response is bound to one result/report hash, with next cursor and total/coverage when known. Filters and ordering cannot silently substitute newer artifacts. Small bounded artifacts may inline these same projections in the report. |
| `GET /comparisons?run_id=...&run_id=...` | Two immutable report references, comparison identity, comparable/not-comparable with reasons, pinned dimensions that differ, server-calculated deltas if supported, matched base/stress/benchmark results, coverage/class/limitations for each. No implicit concatenation of independent folds. |
| `GET /experiments`, `GET /experiments/{id}` | Criteria and prior-access declarations with recorded/frozen times; train/validation/test/warmup intervals, fold IDs, fit input/parameter hashes and allowed fitting boundary, reset/carry mode, attempted trial registry including failures/cancellations, scored coverage, result visibility, candidate disposition, base/stress comparison references, limitations and export link. |
| `POST /experiments`, `POST /experiments/{id}/trials` | Server-supported criteria and prior-access declaration, frozen split/configuration references, then a run/evaluation request referencing that immutable declaration. Server decides freeze/admission, trial identity and holdout visibility. Exact B workflow may collapse these into one atomic declaration-and-launch operation; no client-only frozen state. |

Mutation request identity and authentication transport must be frozen alongside these records. GET requests are abortable. Poll only nonterminal jobs while the page is active; retrying a GET never launches work. A stale/refetch error may retain the last snapshot but must label it stale and defer commands to current server capabilities. Empty catalog, no artifacts, pending evaluation, rejected admission, missing data and failed worker states have distinct messages.

### Wave 2 projection details the UI must retain

- **Metrics:** project each `MetricValue` as its existing name, decimal-string/null value, unit, status, reasons, assumptions and convention hash. Retain `MetricCoverage` expected/observed/valid sessions, valid returns, sample count, source hash and accessible contributing/excluded row IDs. Summary cards can collapse detailed lineage behind an expandable section or server detail link, never erase it from exports.
- **Series:** retain valuation ID, reduction sequence, economic time, computable/knowledge time, session, roles, scored interval, flow/pair identities, current NAV, separately labeled last-known NAV and its source/age where available, wealth, drawdown, signed external flow and reasons. Preserve same-time pre/post-flow rows by sequence. Benchmark/cash rows align by valuation ID and retain their own reasons. Account NAV and wealth are separately labeled; a contribution is not a return.
- **Executions/trades/journal:** project effective execution identity/revision, order/intent/symbol/side, quantity/price/fee/time; completed closing-order FIFO groups with match/fee/split lineage; incomplete groups and open holdings remain separate. The server supplies any grouped trade values. Journal pages expose exact amounts, cash components and source identities. The UI never re-expenses fees, derives FIFO matches or rolls up an independent ledger.
- **Identity:** semantic run/result/report hashes remain distinct from job attempt, recovery attempt and generated artifact identity. Labels and exports include actual data class, input/configuration/model/convention pins, availability assumptions and scored coverage. Do not send the entire `EngineResult` trace into every list/report response.

For display, decimal strings remain authoritative. Converting a known finite value to a JavaScript number is permitted only for chart geometry or formatting; source tables/export values and metrics are not recomputed. Null or invalid chart points break the line, never become zero or join a gap. After the report's latched wealth gap, the browser cannot resume an invented growth path. Exact tooltips include row identity and reasons. Annualized metrics use the server's availability result: a five-session sample cannot render a Sharpe ratio or annualized-return estimate through a UI fallback. Known zero volatility remains zero; undefined Sharpe/Sortino and unavailable capacity/confidence intervals remain reasoned undefined values.

## Component and integration checks

| Area | Focused lane C checks |
| --- | --- |
| Catalog/form | Loading/error/empty/real and synthetic classes; dataset selection carried into exact request; strategy constraints and server field errors; short-history limitations; launch unavailable reason; no imported runtime fixtures. |
| Launch/recovery/cancel | One stable request/key across ambiguous retries; inputs cannot drift within a retry; detail survives route refresh; pending/claimed/running/recovered/terminal states match the frozen enum; measured progress is not fabricated; cancel acknowledgment remains pending; terminal/conflict/error handling does not duplicate a launch. |
| Report | Actual API response values, incomplete financial facts, open holdings, fees/FIFO/journal lineage, metric units/coverage/undefined reasons, artifact versus semantic identity, stale/error state, bounded pagination and immutable export URLs. |
| Chart | Missing/stale NAV and latched wealth gaps; no null-to-zero coercion or gap bridging; same-time flow pair sequencing; independent benchmark gaps; distinct NAV/wealth labels; accessible exact-value/reason list. |
| Comparison | Actual selected report IDs; mismatched dataset/window/conventions visible; not-comparable reason; no frontend return arithmetic or ranking undefined values; base/stress and benchmark results retain assumptions and class. |
| Experiment | Prior access and criteria precede the launch request; unknown/previously seen data cannot be relabeled untouched; frozen declaration and fit boundary visible; trial failures/cancellations retained; withheld metrics absent; no-candidate result; insufficient-data and pending cost analysis distinct from zero-cost/zero-performance. |
| History and operations | Old golden/governance screens explicitly diagnostic/history; default research uses the new endpoints; shared route tests verify cutover; retained operations tests continue unchanged. |

Run focused Vitest tests, TypeScript check, ESLint and production build/bundle checks using existing tooling; root runs route/API-generation and the complete retained suite. Root's acceptance must also drive a clean local browser through registered real dataset selection, actual worker completion, report and comparison, plus cancellation/restart recovery and visible benchmark/adverse-cost results. Component mocks do not prove that end-to-end gate or economic correctness; independent sampled metric checks remain root/B work.

## Decisions needed to start implementation

Root should freeze generated projection/operation names, run state and cancellation semantics, capability/transport ownership, the bounded report row pagination seam, and B's atomic declaration/trial/holdout-visibility flow. The smallest initial delivery is the catalog/run/report flow followed by comparison/experiment consumers on the same contracts. If licensed history cannot support a requested fold, expose the admission or availability reason and retain an exploratory result where permitted; never manufacture adequate history, PIT status or an untouched holdout.
