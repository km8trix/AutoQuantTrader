# Personal-use design review — 2026-09-08

This is a historical comparison and evidence record, not an alternative plan. The sole current design is [ARCHITECTURE.md](../ARCHITECTURE.md); the sole roadmap is [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md).

## Scope and method

The owner requested an independent architecture/plan before inspecting the GPT-5.6 Sol work, followed by a code and design comparison and a consolidated wave plan. “Sol work” here means the project attributed to that model by the owner; Git metadata was not used to infer model authorship.

An independent baseline was written before reading the existing architecture, plan or implementation contents. A second reviewer independently proposed a design without reading the repository. Subsequent read-only reviews covered research/data/accounting, execution/risk/operations, and existing planning decisions. Draft consolidation received a second review for causal/accounting errors, migration gaps and concurrency.

The active repository is `/Users/spencer.karrat/Documents/GitHub/AutoQuantTrader`, identified by its continuation notes and Git worktree inventory. Reviewed main was clean at `107fa79`; the workspace's `repo/` checkout was at `8685b56`, with 161 main commits beyond it and a modified plan. Recent integration and development worktrees were inventoried; unmerged branches were not assumed to be accepted implementation. No remote fetch/CI confirmation was performed.

The old workspace plan diff is preserved exactly as [prior-workspace-plan.patch](2026-09-08-prior-workspace-plan.patch). Its 45 additions and 15 deletions clarified old gate status; newer main already incorporated and advanced that status. The patch is historical, not a current plan. Full previous committed plans remain in Git history, especially `107fa79:docs/ARCHITECTURE.md` and `107fa79:docs/IMPLEMENTATION_PLAN.md`.

No code, tests, dependencies, runtime configuration, credentials, provider data, services, infrastructure or trading state were changed or exercised in this review. No profitability, coverage percentage, operational readiness or new passing test count is claimed. Findings below are static source/design observations; citations identify the reviewed revision's files/line starts.

## Independent baseline, captured before repository review

The original independent proposal was a personal-use modular monolith with separate research and single-account execution processes, a thin local UI, immutable Parquet research data and one transactional operational database. It provisionally allowed SQLite for a strictly local single-writer application or PostgreSQL where concurrent transactions warranted it.

Its central contracts were causal data/feature availability, target-producing strategies without broker access, realistic event-driven simulation sharing financial logic with live, an auditable Decimal ledger, account-wide atomic risk reservations, durable intent/outbound work, explicit UNKNOWN submissions, broker reconciliation before restart, and distinct pause/cancel/flatten controls. It prioritized credible research, one broker, practical fault recovery, backup/restore and staged human-controlled promotion.

The baseline's delivery order was scope/contracts → data/domain/persistence → economic research → OMS/risk/recovery → one complete forward/paper slice → operations/qualification → separately approved live. It required one orchestrator with 2–3 disjoint workers, stable interfaces and measurable integration gates. This sequence is retained here solely to document the independent comparison; the revised waves in the current plan replace it.

## Architecture and plan comparison

| Topic | Independent baseline | Existing Sol design/plan | Final decision after review |
|---|---|---|---|
| Product scope | One owner/account/broker, low-frequency first; avoid product-platform features | Already one owner/account/active strategy, liquid ETFs, cash-account restrictions | Preserve; narrow implementation to daily first and supported actions |
| Core architecture | Modular monolith, pure targets, one account writer | Same broad principles; explicit shared decision path and fencing | Preserve useful contracts; make their integration the priority |
| Storage | SQLite if truly single writer; PostgreSQL otherwise | PostgreSQL/Alembic/SQLAlchemy, immutable Parquet, planned DuckDB | Keep PostgreSQL; migration to SQLite would waste sound transactional work |
| Broker | Select one; generic stable client-ID recovery where supported | E*TRADE production selected after extensive historical Alpaca work | Preserve E*TRADE; remove second-broker completion from critical path |
| Provider uncertainty | Durable UNKNOWN; reconcile before retry | Correctly notes E*TRADE client IDs are not returned and do not provide lookup | Adopt stricter provider-specific manual UNKNOWN handling, no automatic resubmission |
| Non-live evidence | Genuine paper/simulation before live | Already distinguishes E*TRADE sandbox from stateful paper and live | Explicit local stateful forward simulation; separate production-read/preview qualification |
| Data | Versioned snapshots, factual availability, no leakage | Extensive provenance/admission machinery; non-fixture positive path incomplete | Add usable owner-reviewed research classes; keep factual provenance separate from historical assumptions |
| Economics | One evolving account engine and derived reports | Good intended design, but several narrow fixture engines and report restrictions | Replace fixture product path; reuse ledger/reducers; golden cases become regression oracles |
| Risk | Mandatory account/cash/order/freshness/loss controls | Strong atomic reservations; later paper profile requires intraday/SIP producers | Preserve atomicity; implement supported daily rules early, with explicit policy cutover |
| Accounting | Auditable fill-based journal, cash flows, actions | Rich balanced postings, FIFO, settlement, actions and corrections | Retain; integrate and explicitly handle/exclude unsupported cash-in-lieu |
| Time/security | Standard host control, time health and process isolation | Native lifecycle/signers/anchors, extensive attestation and sealed build machinery | Defer native trust program; replace runtime dependency with ordinary measured controls and tests |
| Operator access | Local thin authenticated UI | Local controls exist, architecture also points toward Auth0/cloud; smoke profile differs | Local/private authenticated control first; dedicated host for unattended windows |
| Research governance | Record all trials, frozen evaluation/holdout | Strong governance metadata, but narrow target/fixture economics | Keep reproducibility; connect to real evaluation and reduce external authority ceremony |
| Retry semantics | Effect-specific recovery | Many narrowly single-use reads/alerts stall after uncertainty | Permit bounded read/alert retries; retain strict broker-effect uncertainty handling |
| Delivery | Usable vertical outcomes and integration gates | Stated vertical intent, but thousands of chronological subphase paragraphs and dormant slices | Nine replacement outcome waves, explicit dependencies/owners and global worker cap |

The key disagreement is therefore **implementation order, excessive operational machinery and incomplete composition**, more than the original high-level financial principles. A blanket rewrite would discard useful accounting/risk work. The final plan prioritizes selective replacement and integration, even when this retires substantial existing work.

## Implementation review and disposition

Paths below are relative to the active repository. Line starts refer to reviewed code at `107fa79`, unchanged by this planning pass.

| Priority / area | What exists and its practical limit | Evidence | Disposition / wave |
|---|---|---|---|
| P0 — data-to-research | Worker is local-only, ingests recorded fixture and registers golden catalog; catalog data is not the golden run's input | `apps/worker/main.py:29`, `:46`; README at reviewed revision explicitly distinguishes the two fixtures | Keep ingestion/catalog; connect real selected datasets in W1–3 |
| P0 — historical adapter | Tiingo `raw_bar_records()` deliberately raises; production historical-source conversion is not available | `packages/adapters/market_data/tiingo_eod.py:1006`, `:1014` | Preserve capture/parser/lineage; new honest data-class path W1 |
| P0 — job generality | Backtest worker binds one immutable strategy/config/data tuple and rejects other digests before golden execution | `packages/application/backtest_worker.py:61`, `:125`, `:143` | Replace fixed product path; retain deterministic oracle W2–3 |
| P0 — evolving portfolio | Generic strategy replay copies positions once and passes that snapshot to later callbacks; golden runner explicitly uses a separate causal loop | `packages/domain/strategy_replay.py:405`, `:437`; `packages/backtest/golden_runner.py:1` | One causal account-state loop W2; this is a generalization gap, not a claim the narrow fixture violates its contract |
| P0 — report economics | Golden runner constructs fixed report values; report schema deliberately leaves annualized/uncertainty/capacity metrics undefined | `packages/backtest/golden_runner.py:945`; `packages/domain/backtest_report.py:991` | Compute metrics from general run events; retain validation and truthful undefined values W2 |
| P0 — alternative economics | Phase 3H is fixed reference economics, immediate-close zero-cost, without a general application/report path | `packages/domain/fixture_segment_economics.py:1`, `:45`; prior plan Phase 3H | Test-only; do not extend it as another strategy-validation engine W2 |
| P0 — research eligibility | Captured-tape gate denies both absent and supplied provenance; no constructible accepted producer in that contract; external review required | `packages/application/captured_tape_research_validity.py:1109` | New positive exploratory path, while preserving stricter claims/permissions W1–3 |
| Retain — accounting | Balanced immutable entries, FIFO long-only projections, settlement, actions/corrections | `packages/domain/ledger_reducer.py:194`, `:503`; `packages/domain/account_projection.py:706` | Integrate existing mathematics and independent invariants W2 |
| Scope gap — actions | Whole shares required; fractional split/cash-in-lieu outcomes reject | `packages/domain/account_projection.py:212`; `packages/domain/corporate_action_ledger.py:116` | Implement deterministic treatment or explicitly exclude affected scope W1–2 |
| Retain — simulated broker | Later-source full-fill model with latency/spread/slippage/fixed/per-share fees; not a general next-open or liquidity model | `packages/backtest/simulated_broker.py:451`, `:1293` | Keep named model, add supported causal daily/forward semantics W2/W4 |
| Retain/refactor — research governance | Feature parity, experiment attempts, holdout commitments and fixture worker claims exist; much is target/provenance-only | `packages/domain/feature_replay.py:26`; `packages/application/fixture_segment_worker.py:45` | Connect to canonical economics and real UI; no parallel proof-only roadmap W3 |
| P0 — running trader | Main is a one-shot readiness check, explicitly refuses live and exits non-ready | `apps/trader/main.py:156`, `:171`, `:203` | Keep startup gate; build long-running coordinator W4–5 |
| Retain — transactional risk | Real session/cash/exposure checks and all-or-none SQL reservations/fence validation | `packages/domain/batch_risk.py:1822`; `packages/persistence/batch_risk.py:2591` | One supported daily entry point with versioned cutover W2/W4 |
| P0 — UNKNOWN application | Durable UNKNOWN freezes commitments; `resolve_unknown` always rejects because authoritative producer is absent | `packages/persistence/submission_attempt.py:1983`, `:2004` | Complete reconciler/owner disposition before connected order authority W4–5 |
| P0 — reconciliation | Historical broker observations do not apply lifecycle, accounting or release reservations | `packages/domain/broker_reconciliation.py:1` | Add full account application/barrier with coverage, identity and differences W4 |
| P1 — E*TRADE | Recorded request/endpoint foundation and injected OAuth transport, not a complete credential/account/order runtime | `packages/adapters/broker/etrade.py:1`; `packages/application/etrade_oauth_token_runtime.py:1` | Practical feasibility/read path W1; restricted transport W5 |
| Preserve history — Alpaca | Concrete bounded read infrastructure exists, but capabilities are non-authorizing and are not E*TRADE qualification | `packages/adapters/broker/alpaca_paper_account_runtime.py:914`; `packages/adapters/broker/alpaca_paper.py:259` | Freeze second-provider feature work; retain useful provider-bound fixtures |
| P1 — operations | Dashboard uses walking-thread fixture; durable PAUSE/HALT is database-only; no broker control loop | `apps/api/main.py:425`; `apps/api/operations_dashboard_views.py:325`; `packages/application/local_operations.py:164` | Durable actual account views and acknowledged effects W4–5 |
| P1 — readiness | Local API persistence readiness can be true while trader remains unavailable | `apps/api/main.py:202`; trader evidence above | Explicit separate readiness dimensions W5 |
| P1 — deployment drift | Preflight hardcodes local/Supabase/Alpaca/Sentry historical smoke choices | `packages/application/paper_deployment.py:377` | One configuration-driven daily personal profile W1/W5 |
| P1 — native lifecycle | Evidence-only time supervisor; native milestone candidates uninstalled; trusted-time stop target remains blocked | `apps/trusted_time_supervisor/main.py:1`; ADR 0126; `Makefile:488` | Defer custom lifecycle dependency after replacement time/stop tests W1/W5 |

These findings do not say every bounded contract is defective. Many limitations are expressly acknowledged in the old plan and source docstrings. The problem is treating accumulation of narrow contracts as progress toward an integrated personal platform while that platform's essential paths remain absent.

## Scale and verification limits

A tracked-file count on `107fa79` found 357 Python source files under `apps/packages/scripts/build_support`, totaling 381,371 lines. Of those, 102 files with `trusted_time`/`trusted-time` in their path totaled 164,312 lines, roughly 43% of that source count. This filename-based measure includes comments and omits generically named supporting/native code; it is a scope indicator, not a complexity or quality score. There were also 292 Python test files, 126 ADRs, and 38 migration Python files. The previous architecture and plan totaled 11,237 lines.

Existing tests cover worthwhile financial and concurrency behavior, including `tests/integration/test_phase2_submission_attempt_persistence.py` and `tests/integration/test_postgres_risk_concurrency.py`. They should survive simplification as behavior coverage. Test presence and prior narrative passes were not reverified by running the suite; CI qualification belongs to implementation Wave 0 and subsequent integration gates.

No runtime/private capture artifacts or secrets were opened. No provider access was exercised. Public documentation was checked for E*TRADE's sandbox, session and order semantics. The architecture cites those sources directly; API/account/market-data eligibility remains a future scoped qualification task.

## How the review changed the independent proposal

1. PostgreSQL is now definite because the repository already has meaningful transaction/lease/reservation behavior worth keeping.
2. The broker is E*TRADE, preserving established owner intent. Generic client-ID lookup recovery was replaced with E*TRADE-specific uncertainty rules and manual disposition.
3. The first cadence/universe/account are daily ETF, one strategy, long-only FIFO cash, rather than leaving asset and cadence open.
4. Stateful local forward simulation replaces a required second-broker paper implementation; sandbox, production reads/previews and actual live evidence are kept separate.
5. The existing financial reducers and golden accounting expectations are retained, while the fixed economic product path is replaced.
6. Useful current-vintage historical research becomes possible with explicit assumptions; observed capture time, assumed simulation timing, stronger PIT claims and trading authority remain distinct.
7. Clock/process handling is a planned targeted replacement of disproportionate native/remote trust infrastructure, with specific dependency and regression gates.
8. Pure daily risk enters the economic engine before the research MVP, and later runtime policy cutover preserves existing reservations/history.
9. Forward data acquisition, evaluation-state boundaries, event-timed cash flows and command/dispatch ordering are explicit deliverables after draft review found potential gaps.
10. Future work is nine concrete waves, with a global three-worker maximum, disjoint ownership, shared-file/migration coordination and exact integrated exit evidence. Old phase completion does not pre-complete a new wave.

## Consolidation policy

Only the current architecture and implementation plan govern future design and sequencing. Historical ADRs/runbooks retain implementation evidence, with index notices making their status clear. The operational budget file is a supporting specification rather than another roadmap. Continuation notes link to the canonical documents instead of carrying a stale phase checkpoint.

Older worktree plan/architecture files are historical branch snapshots; the workspace checkout's document entry points redirect to the active canonical files. No development worktree was deleted or code synchronized. The original uncommitted plan correction was preserved before replacing that obsolete entry point.
