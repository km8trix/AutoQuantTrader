# AutoQuantTrader implementation plan

Continuation entry point: [PLAN.md](PLAN.md) is the executable task breakdown of
this preserved wave roadmap; [STATUS.md](STATUS.md) holds current results and
blockers. Dated handoffs below remain historical evidence, not a substitute for
checking the current revision. No wave requirements or approval gates are removed.

Status: sole authoritative delivery plan. Waves 0/1 closed through [PR #52](https://github.com/km8trix/AutoQuantTrader/pull/52), Wave 2 through [PR #53](https://github.com/km8trix/AutoQuantTrader/pull/53), and Wave 3 through [PR #54](https://github.com/km8trix/AutoQuantTrader/pull/54), merged as `e1bcea18eaa18ad144bc3b03a4891d11ecdd9b06` with verified PR and post-merge checks. Wave 4 implementation and acceptance are in progress. Broker connected-execution qualification remains blocked; trading and deployment stay disabled.

Implement the [architecture](ARCHITECTURE.md) using the evidence-backed priorities in the [design review](reviews/2026-09-08-design-review.md). The new waves replace the previous Phase 0–8/subphase/Wave 1–7 roadmaps. Existing local passes remain historical evidence; they do not mark any new wave passed.

## 1. Starting point and priorities

Reviewed main revision: `107fa79` in `/Users/spencer.karrat/Documents/GitHub/AutoQuantTrader`. The workspace checkout at `8685b56` is older and has a pre-existing status-only plan edit; its exact diff is preserved in the review materials. Do not start implementation from that old branch or merge all development worktrees indiscriminately. No remote CI, running service, vendor entitlement or live account was requalified during this planning review.

| Priority | Change | Why it precedes more feature work |
|---|---|---|
| P0 | One causal data→strategy→order→ledger→report path | The running golden backtest is fixed; general replay does not advance positions between callbacks |
| P0 | Usable, honestly classified historical data | Capture/qualification code exists but the product has no wired non-fixture historical source |
| P0 | Applied reconciliation and durable uncertainty recovery | UNKNOWN resolution currently rejects every call; stored observations cannot yet authorize account recovery |
| P0 | Daily-v1 runtime and risk profile | The trader is a preflight and existing deployment/risk assumptions mix old Alpaca, local smoke and intraday requirements |
| P1 | Standard clock/process/secret/backup operations | Native signing/anchor/lifecycle work has become a major dependency without completing the product |
| P1 | General experiments, derived metrics and operational UI | Fixture screens and provenance-only results do not meet research or trading needs |
| P1 | E*TRADE feasibility, session handling and controlled qualification | Preserve the selected broker while discovering operational constraints early |
| Deferred | Second broker, intraday expansion, public SaaS, native lifecycle hardening, ML infrastructure | Reconsider only after the personal-v1 path works and a measured need exists |

The first useful product milestone is **Wave 3: run and compare reproducible economic backtests on a selected real historical dataset**. The second is **Wave 5: operate the same engine continuously in stateful simulation with complete recovery and controls**. Connected live execution remains disabled through Wave 6.

## 2. Orchestration contract

One orchestration task owns the plan, architecture, integration branch, shared contracts, schema sequencing, acceptance evidence and readiness summary. It may run **at most three additional tasks concurrently**; two is the default when ownership is tightly coupled. The maximum is global, including worker-created subtasks. Workers may not create more workers without releasing an existing slot through the orchestrator. The orchestrator plus workers is at most four active tasks.

Each implementation task is a bounded work package in one isolated worktree based on the same reviewed integration commit. Wave 0 contract lanes may instead use non-writing reviews of the same code revision with exclusive temporary specification outputs. Historical wave worktrees are reference material, not implicit sources of accepted changes. Never launch one task per old subphase or use every slot for speculative work.

Before dispatch, the orchestrator:

1. Selects a wave whose stated dependencies have passed and inspects current code/uncommitted changes.
2. Freezes public interfaces, invariants, expected evidence and file/module ownership. Assigns exact files once inspected; directories in the wave tables are intended boundaries, not permission for overlapping edits.
3. Assigns each shared domain contract, schema definition and migration to one owner. The orchestrator allocates migration IDs and serializes changes to `packages/persistence/schema.py`, migration heads, API schema generation, composition roots and shared fixtures where applicable.
4. Gives each worker a task brief using the template below and a fixed resource limit. Test authors receive expected behavior independently of implementation details.
5. Keeps financial/network effects disabled unless the owner has authorized that precise later operational stage. Earlier read authorization does not authorize Place, live credentials, new subscriptions or capital.

During a wave, workers implement and check only their assigned boundaries. They return commit/diff, behavior changes, tests, limitations and required integration steps. Contract changes go back to the orchestrator before consumers proceed. UI/report workers can use frozen test contracts during development; acceptance requires the actual integrated data path.

At the integration barrier, the orchestrator reviews and incorporates work sequentially, resolves conflicts, runs relevant combined tests and demonstrates the wave's user-visible path on the exact resulting revision. It updates only this plan's status/evidence table, the architecture when a decision changed, and concise runbooks. Passing unit tests or merging worker branches is not an exit gate by itself. Deployment remains halted through migrations and restarts.

The owner has authorized this standing closeout sequence for every wave: once its exit gates pass, commit the reviewed in-scope changes, push the feature branch to `origin` (`km8trix/AutoQuantTrader`), open a GitHub PR with the concrete behavior and validation, satisfy required CI/review checks, merge through GitHub, and verify the resulting default-branch revision. Record the PR URL and merged commit in the status/evidence table. Then this same orchestration task starts the next eligible wave from the merged revision under the global worker cap. This instruction supplies ongoing authorization for commits, pushes, PRs, merges and dependency-qualified continuation; no repeated permission request is needed. Preserve unrelated work and existing worktrees, do not bypass branch protection or force-push, and do not close a wave with unresolved acceptance gates. Trading, capital, deployment, subscriptions and other operational actions retain their separate scope gates.

Do not begin dependent work until its prerequisite passes. A provider/account blocker need not stop independent offline research: the dependency table permits Waves 2–3 after the data/runtime parts of Wave 1, while broker work is explicitly blocked. Those dependencies describe technical eligibility. Under the owner’s requested sequential closeout cadence, finish the current wave and its GitHub merge before starting the next wave. Waves 0–3 have passed GitHub closeout; Wave 4 is current. The same three-worker global cap applies. There is no automatic retry of an external action simply to fill a task slot.

### Worker brief template

```text
Wave / lane / intended outcome:
Base revision and exclusive file ownership:
Frozen contracts and invariants:
Inputs and dependencies already passed:
Required behavior and explicit exclusions:
Tests and concrete evidence to return:
Resource limits and allowed effects:
Migration/shared-file requests for orchestrator:
Completion criterion and unresolved blockers:
```

## 3. Wave map

| Wave | Outcome | Entry dependency | Worker limit | Exit evidence |
|---|---|---|---:|---|
| 0 | Freeze scope, migration seams and honest baseline | This planning review | 2 | Contract pack, retention map, exact-revision baseline and decisions |
| 1 | Usable data import, standard runtime foundation, broker feasibility | W0 | 3 | Validated dataset, clock/process profile, session/account read demonstration |
| 2 | One general causal economic engine | W1 data/runtime lanes | 3 | Configurable multi-session runs with independent ledger expectations |
| 3 | Complete research workflow and validation | W2 | 3 | Dataset selection→run→derived report→comparison→held-out evaluation |
| 4 | Reconciled coordinator and stateful simulation | W2 and W1 broker/runtime lanes | 3 | Applied account reconciliation, atomic risk and continuous simulation |
| 5 | Operationally complete execution/controls/recovery | W4 | 3 | Restricted adapter code, durable controls and fault/restore demonstrations |
| 6 | Forward qualification and live-readiness dossier | W3 + W5 | 2 | Frozen-candidate soak and separate E*TRADE protocol/read/preview evidence |
| 7 | Directly supervised minimum-size live canary | W6 + explicit owner live authorization | 2 | Actual orders reconciled against broker records within approved scope |
| 8 | Personal automated operation and measured maintenance | W7 + owner operating-envelope approval | 2 | Stable session operations, restart/restore/alert evidence and measured costs |

No calendar estimate certifies completion. Waves 0–5 are sized by bounded outcomes and dependency risk. Wave 6 has a minimum observation window plus event quotas; strategy suitability and broker onboarding cannot be promised on a schedule.

## 4. Wave 0 — baseline, contracts and simplification decisions

Objective: make later work implement the same product and preserve sound financial invariants while removing unnecessary dependencies.

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — reusable core and engine contract | Read data/domain/backtest/accounting boundaries; specify event ordering, state updates, run/report schema and small independent economics cases | One engine contract and keep/refactor/retire map with callers/tests to migrate |
| B — account, broker and operations contract | Read risk/OMS/reconciliation/clock/deployment boundaries; specify daily policy, credential/session boundaries, owner actions and effect-specific retries | One account/runtime contract, E*TRADE capability matrix and dependency-removal map |

The orchestrator owns scope decisions and the baseline check record. Preserve the chosen ETF scope, E*TRADE live target, one-strategy cash-funded brokerage account under the current account eligibility amendment and existing code until replacements pass. Map every dependency of native trusted-time/build/signing machinery before removing anything from active paths. Record historic approvals as scoped evidence, not reusable authority.

Freeze: daily decision/execution schedule; factual versus simulated historical availability; maximum job resources; study period/benchmark; fold warmup/reset/carry and scored windows; valuation and event-timed cash-flow handling; pure daily risk rules and live-disabled policy shape; quote source requirements; command/dispatch ordering; reconciliation coverage/tolerances; standard clock API. Concrete financial amounts remain required owner inputs before live activation.

Exit: agreed contracts and migration ownership; baseline tests recorded with skips/failures, not repaired through unrelated feature work; no unresolved ambiguity about which engine/risk path is canonical; old worktrees and uncommitted changes inventoried. Clock simplification and research-admission version changes have replacement requirements, not just deleted checks.

**Completed contract gate:** [frozen personal-v1 pack](contracts/personal-v1/README.md), [migration/file ownership](contracts/personal-v1/migration-ownership.md), [baseline](reviews/2026-09-08-wave0/baseline.md) and [stale native closeout](reviews/2026-09-08-wave0/stale-task-closeout.md). The pack freezes the daily schedule, synthetic-only risk/capital defaults, historical assumptions, evaluation/flow semantics and replacement interfaces. Baseline: 741 Python tests and 100 browser/bundle tests passed; 7 PostgreSQL tests skipped; architecture checker reports 6 inherited exact-document obligations against the consolidated docs. Other selected lint/type/API/Compose checks passed. This is contract completion, not application feature, native-release or live-readiness acceptance. Exact inputs, commands, arithmetic and final artifact hashes are recorded with the baseline.

## 5. Wave 1 — practical foundations and early broker feasibility

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — historical source | `packages/adapters/market_data`, ingestion application layer and data validation; orchestrator owns common manifest/schema changes | One frozen licensed Tiingo or owner-imported dataset reaching the canonical historical port with raw/adjusted/action/calendar coverage and explicit data class |
| B — E*TRADE session/account feasibility | E*TRADE adapter/session boundary and secret-store integration; no order transport activation | Realistic OAuth lifecycle, environment isolation, account selection/binding and authorized read-only balance/portfolio/order/activity captures; sanitized evidence |
| C — conventional runtime foundation | Clock adapter, process lifecycle, runtime configuration and packaging; coordinate shared Make/Compose edits through orchestrator | Standard time-health/process supervision, halted startup, session/suspend detection and isolated simulation/production configuration |

Lane A supplies a positive usable research path, including intentional failure outcomes for unavailable semantics. It never assigns an old event date as a fabricated historical availability time. Keep provider rights references and secret-free hashes. Missing action cash-in-lieu support is either implemented with checked examples or causes explicit scope exclusion. Do not begin multiple vendor builds.

Lane B starts with recorded fixtures; any provider request requires the owner's later scope-appropriate authorization. Confirm E*TRADE's session renewal/daily reauthorization behavior, actual account eligibility, quote entitlement and usable order/activity identity fields. Preview/Place remain outside this wave. Unsupported facts are captured as feasibility blockers. Lack of a usable broker recovery contract stops connected execution planning progression; it does not justify arbitrary matching.

Recheck current primary provider documentation, production API access and account eligibility under the [margin-privilege amendment](contracts/personal-v1/account-eligibility-amendment.md), retention/use rights, daily delivery timing, and execution-time quote coverage against the actual selected scope. An old probe or plan is not current provider qualification.

Lane C replaces active dependencies only after behavior tests prove freshness, UTC/monotonic regressions, sleep/wake, duplicate-start exclusion and normal stop. Standard stop can stop a process with unhealthy clock/data while clearly reporting remaining brokerage exposure. Existing remote anchors, native lifecycle candidates and historical migrations remain untouched until their mapped consumers can be retired safely; do not drop tables or erase evidence.

Exit: A imports and replays a real multi-session dataset; C runs and stops the standard local simulation profile; B has a concrete authorized session/account-read result or an explicit external blocker. A and C may pass independently for W2. The overall wave is not declared complete while B is blocked. No source label, successful read or key presence grants order permission.

## 6. Wave 2 — the canonical economic engine

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — event/strategy/risk orchestration | Canonical engine application service, strategy callbacks and pure daily risk policy | Actual market/ledger/order state advances before each decision; configurable inputs and historical producers for supported daily risk rules |
| B — execution/accounting integration | Simulated broker and accounting projection adapters; preserve core journal invariants | Later-event execution, session/cash constraints, fees/slippage, partial/cancel outcomes and action/settlement integration |
| C — derived reporting | Metric calculators and report artifact builder | Event-derived NAV/P&L/returns/costs/exposure/turnover/drawdown/benchmark with frozen valuation and cash-flow timing, explicit assumptions and undefined-value handling |

The orchestrator replaces the fixed golden job as the product path only after the general path reproduces the golden accounting facts. Keep a small golden case as an oracle, and use independently specified cases to avoid copying its implementation. Retire competing fixture economic paths from qualification; preserve them only where they test useful isolated behavior.

Exit demonstrations:

- Two configurable reference strategies run on at least two multi-session datasets; changing data/configuration changes appropriate outputs and creates a new run identity.
- A fill changes the next strategy-visible position, cash and pending-order state; targets cannot duplicate an existing commitment.
- Close-derived signals never fill on that close; shortened sessions, missing eligible events and delayed publication produce specified results.
- Hand-calculated buy/sell/fee/settlement/dividend/split/cash-flow examples match the ledger and derived report. Unsupported corporate actions are rejected visibly.
- An intraperiod contribution changes capital without creating performance; benchmark flows use the same event timing. Daily risk rules run here already, before live runtime integration in W4.
- Retries/replay reproduce semantic results; stochastic models reproduce with the same seed. Future-row changes cannot alter earlier decisions.
- Open holdings, stale marks, zero variance and insufficient sample size do not produce misleading return or risk statistics.

No new independent general engine is permitted in this wave. Real provider data and fixture results remain distinguishable in every report.

## 7. Wave 3 — usable research and evidence quality

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — research jobs and artifacts | Run registration/claims, cancellation/recovery and result publication; orchestrator owns shared migration/API contracts | General durable jobs linked to real dataset/strategy/configuration manifests |
| B — evaluation protocol | Chronological splits, training-only fitting, trial registry, cost/parameter stress and benchmark comparisons | Reproducible descriptive evaluation with recorded prior access and attempted configurations; untouched holdout claims require separate evidence |
| C — research UI | Dataset/run/experiment views and comparison screens using frozen generated contracts | Select dataset/strategy/configuration, launch/cancel, inspect equity/trade/ledger/provenance and compare runs |

Prefer minimal transparent strategies and an interpretable report over large feature/optimizer libraries. The owner records criteria before looking at holdout results. Store exploratory history limitations and forward-data start dates alongside every result. Unavailable historical vintages do not prevent exploratory economics, but do prevent unsupported PIT claims.

Exit: from a clean local start, complete dataset selection→run→report→comparison with actual worker outputs. Kill/restart a research job and recover without duplicate terminal publication. Recompute metrics independently for a sampled run. Verify training/validation/test separation, fold warmup/reset/carry, nonduplicated scored windows, feature fit boundaries and trial recording; changing validation/test inputs must leave training-fitted parameters and earlier decisions unchanged. A benchmark and adverse-cost analysis are visible. Historical data classes and economic assumptions survive exports and comparison.

Milestone: useful personal research MVP. A result may say “no candidate meets the declared criteria.” That is a valid research outcome, not permission to relax criteria or declare live strategy readiness.

## 8. Wave 4 — applied reconciliation and continuous simulation

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — broker facts and reconciliation | Raw read adapters, normalization, identity/deduplication, broker fact application and reconciliation service | Explainable account differences, correction/manual-activity handling and startup/reconnect barrier |
| B — coordinator and account risk | Coordinator application service, canonical risk entry point and reservations/attempt integration | One active deployment, fenced ownership, durable command consumption and runtime producers/atomic integration for W2's daily policy |
| C — stateful simulation and forward data | Stateful simulated venue, bounded EOD/quote acquisition, immutable forward observations, gap/watermark recovery and replay/fault harness | Persistent venue records reusing W2 fill/cost/accounting contracts; actual authorized source capture with identity/entitlement/freshness evidence |

The orchestrator controls shared ledger/order schemas and integrates reconciliation with the existing durable attempt resolver. Remove its unconditional rejection only when accepted provider facts and owner recovery decisions actually support a safe resolution. E*TRADE ambiguous Place remains manual; the simulated venue may prove a stronger lookup contract only for its own environment.

Freeze quote freshness, account limits, pending commitments, cancel reserve capacity and daily signal expiration. Do not apply the historical SIP/one-minute risk policy to unavailable data or migrate its paper numbers into live. Use a new policy version with a complete producer map and disabled live assignment.

Risk-policy cutover pauses/quiesces the account, reconciles all existing obligations, preserves their original bindings/reservations and switches only new decisions. Lane C's independent venue records test reconciliation, not a second economic model. Reuse W2 semantics and explicitly version any new forward-only behavior.

Exit: coordinator runs across a session in stateful simulation; positions, cash, fees, actions, fills and commitments agree with independent simulated venue records. Two coordinators cannot jointly reserve or submit account capacity. Restarts, duplicate/late facts, partial-fill/cancel races, external trades and missing pages cannot produce unexplained account changes or premature readiness. Repeated empty/equal views alone cannot clear an UNKNOWN. A missing or stale mandatory source blocks new exposure while observation/recovery continues.

Replay at least one actual authorized captured session into identical decision outputs, proving the forward-data producer rather than only its synthetic harness. E*TRADE read-only account reconciliation is demonstrated separately where authorized; simulation observations never masquerade as provider qualification. No production Place is enabled.

## 9. Wave 5 — execution, controls and recovery completeness

| Lane | Work and ownership | Deliverable |
|---|---|---|
| A — restricted execution adapter | Preview/Place/Cancel protocol code, payload/client-ID mapping, request classification and UNKNOWN handling | Integrated but live-disabled E*TRADE order transport, validated with fixtures/sandbox and fault transports |
| B — operator experience | Operations API/read models/React controls with command acknowledgements | Accurate readiness, session state, orders/fills/cash/positions, pause/cancel/flatten/halt/re-arm and residual exposure |
| C — reliability and deployment | Clock/heartbeat/alert integrations, backup/restore, packaging/runbooks and independent fault harness | Reproducible supervised deployment, off-host recovery proof and measured safety/control outcomes |

The orchestrator integrates worker changes into the actual running coordinator and tests the exact release image with real PostgreSQL. Resource/time limits must preserve risk/observation/control progress if strategy work stalls. Avoid adding public hosting or external identity services to complete a local UI.

Mandatory drill matrix:

| Scenario | Required evidence |
|---|---|
| Crash before/after send claim or network acceptance | No automatic duplicate Place; UNKNOWN retained where uncertainty exists; reservations preserved |
| Duplicate, late, partial and corrected execution facts | Exactly one economic posting per qualified fact/correction; late fills accounted for |
| Cancel/fill race, rejected cancel, closed market flatten | Pending commitments retained; correct final order/position state; visible incomplete result |
| Stale data/quote, missing session, sleep/wake, clock step | New exposure denied; missed decisions not bulk-submitted; explicit re-arm after recovery |
| Lease loss, second process, database/network outage | No automatic takeover or stale-coordinator restart into trading; reconciliation required |
| OAuth inactivity/expiry during preview or dispatch | Session repair separated from order retry; expired/mismatched preview discarded safely |
| Read `429`/timeout/schema drift | Bounded backoff and protected recovery capacity; no truncation or invented economic facts |
| Process stop with clock or database unhealthy | Process can be stopped; existing brokerage exposure remains explicitly unresolved |
| Alert provider failure and host loss | Observed owner warning/fallback or visible delivery failure; external heartbeat catches host loss |
| Database restore and release rollback | Restored process starts halted; broker history reconciles gap; no erased orders or replayed sends |
| Manual broker trade or cash movement | Classified difference, explicit adoption or halt, cash-flow-neutral performance |

Exit: all required scenarios pass in the appropriate local/stateful environment, timed targets are measured, UI uses durable operational state and a restored installation is usable. Provider-specific uncertainty remains explicit. Native trust machinery is no longer a prerequisite only after replacement tests pass. Live mode remains disabled; no real-capital canary has occurred.

## 10. Wave 6 — forward qualification and readiness dossier

Use two workers: A owns frozen-candidate research/forward evidence and daily comparisons; B owns E*TRADE qualification, operational drill evidence and the readiness dossier. The orchestrator owns deployment revision, incident triage and the gate. These are development/review tasks, not authority to trade.

Run two distinct evidence lanes:

1. Stateful forward simulation/shadow over actual captured observations, with the exact approved strategy/risk/runtime versions, tests operations and decision parity.
2. E*TRADE sandbox protocol tests plus separately authorized production read-only and preview-only qualification test the selected broker's session, account, response and preview behavior. Place stays disabled. Sandbox samples do not count as real sessions, fills or execution quality.

Minimum planned observation: four calendar weeks and at least 20 completed intended market sessions, extending for holidays, incidents or insufficient coverage. This is an operational minimum, not statistical validation or a guarantee of a profitable strategy. Natural strategy activity and injected faults are counted separately. Predeclare quotas before starting: every critical Wave 5 fault exercised at least once; at least three restart/reconnect drills on distinct sessions; one restore; one primary-alert failure/host-heartbeat drill; every supported order transition covered. Inject rarely occurring cases in simulation, not live just to meet a quota.

Each session records data completeness, authorization coverage, target/risk differences, orders/fills/cash/positions, costs and unexplained residuals. Material engine, broker, policy or strategy changes invalidate affected evidence and restart the relevant observation window; the orchestrator records the scope explicitly.

Exit dossier:

- Separate research, simulation, sandbox and production-read/preview evidence inventories with exact revisions/configurations and source class.
- Zero unresolved economic, order or reconciliation discrepancies; incidents have causes, corrections and regression coverage.
- Strategy acceptance criteria and holdout results, search history, cost/capacity sensitivity and limits of statistical inference.
- Verified credential/account separation, daily auth procedure, budgets, clock health, controls, alerts, broker-native intervention and restored-state reconciliation.
- Proposed exact live account, symbols, maximum shares/notional/capital, loss/exposure limits, operator session window and abort conditions.

If strategy criteria fail, report operational completion separately and continue research. Do not mark the live gate passed or conduct live trials to compensate for failed research.

## 11. Wave 7 — owner-authorized live canary

Entry is a **new explicit owner authorization** of the exact account, strategy/configuration, runtime revision, session window, financial limits and canary actions. This plan is not that authorization. The orchestrator presents the completed W6 dossier before requesting it. No automatic live promotion is allowed.

Use two workers: A reviews the restricted execution/reconciliation session and incident evidence; B independently reviews accounting, risk and execution quality. A single authorized operational owner/coordinator performs effects; development workers must not independently issue orders.

Begin with production read/shadow and preview requalification, then the smallest sensible whole-share order in the authorized one-symbol/session scope. Revalidate all gates immediately before Place. Observe actual execution, cancel outcomes where applicable, positions, charges and settlement against the API and independent broker records. Any ambiguous Place blocks new exposure and requires manual disposition. A stopped process does not make positions flat.

Exit: the predefined canary scope is complete and reconciled, real execution deviations are understood, no unresolved UNKNOWN or accounting differences remain, and the owner has reviewed the evidence. No automatic capital increase follows. A failed canary remains halted and returns only the affected work to remediation/qualification.

## 12. Wave 8 — personal automated operation

Use at most two workers: A owns measured reliability/incident/upgrade improvements; B owns execution-quality and research monitoring. The orchestrator controls releases and the single roadmap.

A dedicated awake host, private operator access, proven database backup/restore, external heartbeat and usable owner alert route are prerequisites for unattended execution windows. Keep E*TRADE session authorization and manual re-arm explicit. Schedule daily preflight, expected-data checks, bounded strategy execution, continuous risk/order observation, periodic reconciliation and end-of-session reconciliation/export. Retain broker-native/manual access.

Freeze a production operating envelope and strategy change procedure. Detect data, signal, cost and execution drift; alerts pause/review according to policy, never auto-tune or auto-promote a replacement strategy. Track monthly hosting/data/API/alert costs and storage growth; set an owner budget before purchases. Capital, universe, order types, strategies and brokers expand only through separate evidence and owner approval.

Exit for initial delivery: a documented, owner-approved observation window of stable operation; successful restart/restore/alert drills on the deployed profile; reconciled statements; measured operating costs; and a maintainable daily/incident/release runbook. Later enhancements join this same roadmap rather than creating a parallel plan.

## 13. Verification, migration and completion rules

- Baseline status from the previous plan is historical. Re-run proportionate tests on the selected implementation revision; include actual PostgreSQL concurrency/migrations when changing financial persistence, not just SQLite fixtures.
- Preserve independent accounting and temporal invariants while simplifying code. Retire old tests only when their required behavior is covered by the replacement; mechanical AST/seal churn is not a substitute for behavior tests.
- API/schema/Compose/type checks and relevant browser tests run when those boundaries change. Full release checks run at integration/release gates, not after every documentation edit.
- Snapshot/export before applicable migrations. Preserve historical ledger/events/digests; use a versioned new path and compatible schema changes. Never reinterpret old Alpaca or trusted-time evidence as new broker/runtime approval.
- Dormant code cleanup follows caller mapping and passing replacements. Delete no worktree, secret, database, cloud resource or historical artifact merely because the target architecture defers it.
- A lane blocked on rights, provider access, account eligibility or owner decisions reports the exact missing input; independent lanes continue within the global concurrency cap.
- “Complete” means the stated user-visible outcome and evidence passed. Contract-only, fixture-only, implemented-but-disabled, operationally qualified and owner-authorized are different statuses.

## 14. Status and decision registers

The orchestrator updates this compact table as work occurs; detailed results belong in versioned evidence/runbooks, not thousands of chronological paragraphs.

| Wave | Current status | Accepted revision/evidence | Blocker / next gate |
|---|---|---|---|
| W0 | **Complete — contract/baseline only** | Code `107fa791`; [pack](contracts/personal-v1/README.md), [baseline](reviews/2026-09-08-wave0/baseline.md), [artifact manifest](reviews/2026-09-08-wave0/final-artifact-manifest.json) | None for W0; recorded checker failures/environment gaps remain later gates |
| W1 | **Complete within bounded foundation/read-feasibility scope** | [PR #52](https://github.com/km8trix/AutoQuantTrader/pull/52), merged `ec63ca793ed4fe8a68397dc752000e102741da59`; CI passed 1,271 Python tests including PostgreSQL, browser regressions, migrations and packaging; merged tree and 140 artifact hashes verified; post-merge CI passed | [Closeout verification](reviews/2026-09-09-wave2/wave1-merged-verification.json); financing, quotes, quotas, recovery and reconciliation remain connected-execution blockers under the [acceptance rationale](reviews/2026-09-08-wave1/wave1-acceptance.md) |
| W2 | **Complete — canonical offline economics** | [PR #53](https://github.com/km8trix/AutoQuantTrader/pull/53), merged `6ea218addaa38d1c36c69b6a7ffbe564d701f834`; PR CI passed 1,640 Python tests including PostgreSQL, browser/migrations/installed packaging; post-merge CI passed | [Merged verification](reviews/2026-09-09-wave3/wave2-merged-verification.json); 83 bound artifacts and exact tested/merged tree verified |
| W3 | **Complete — research workspace and descriptive evaluation** | [PR #54](https://github.com/km8trix/AutoQuantTrader/pull/54), merged `e1bcea18eaa18ad144bc3b03a4891d11ecdd9b06`; PR CI passed 1,999 Python tests, 139 browser/33 bundle cases, migrations and installed-worker checks; exact tested/merged tree and 147 bindings verified | [Merged verification](reviews/2026-09-10-wave4/wave3-merged-verification.json); post-merge CI passed |
| W4 | **In progress — shared interfaces and offline implementation** | Base verified W3 merge; [current handoff](reviews/2026-09-10-wave4/README.md) | Canonical continuation, atomic account integration, independent venue/session replay, actual provider/data qualification and CI/merge |
| W5 | Not started | None | W4 |
| W6 | Not started | None | W3 + W5; candidate and external qualification scope |
| W7 | Not started; live disabled | None | W6 and exact owner live approval |
| W8 | Not started | None | W7 and operating-envelope approval |

| Decision/input | Planning position | Needed by |
|---|---|---|
| Personal scope and E*TRADE broker | Preserve established selection; daily-first implementation | W0 |
| Historical rights/provider/scope | Owner selected recommended Tiingo API using existing `TIINGO_TOKEN` reference; bounded personal research capture authorized, no new spend or redistribution | W1 A |
| Execution schedule and quote source | W0 frozen: decision 20:00 ET, missing-bar cutoff next session 09:00, forward execution 09:35–09:40; daily-only next-open proxy is separately labelled. Actual quote identity/coverage still required | Contract passed; W1 qualification |
| E*TRADE session feasibility | Daily owner participation accepted as design constraint; validate actual workflow before execution build | W1 B |
| Research strategy/benchmark and acceptance criteria | Transparent reference rules first; predeclare criteria before holdout/soak | W3, before W6 |
| Daily simulation policy and source map | W0 daily-v1 defaults/producers frozen; all synthetic limits only, prior SIP/intraday policy historical | W2 pure implementation; W4 durable cutover |
| Account type, funds, loss and notional limits | Unspecified for live; default live-disabled | W6 dossier / W7 approval |
| Always-on host, database backup, alert recipient and monthly cost | Local supervised first; select and qualify before unattended operation; no infrastructure purchase implied | W5 design, W8 activation |

The architecture's personal-use simplifications take precedence over conflicting old future requirements. Keep factual implementation limits visible until changed and verified. Wave 0 ends with reviewed contracts and an offline baseline; Wave 1 data/runtime and authorized production read foundations are accepted within their evidence limits. Connected execution qualification remains blocked; W1–W3 GitHub closeout passed; W4 account/reconciliation/continuous-simulation work is current.


## 15. Wave 0 handoff (historical snapshot)

The following records the W0 boundary before W1 authorization. Section 16 and the status table now govern current work.

Wave 0 used one orchestrator and exactly two bounded collaboration workers, with no nested workers or implementation app tasks. Both lanes and independent economics review are complete. Read the [pack index](contracts/personal-v1/README.md), [file ownership](contracts/personal-v1/migration-ownership.md), [baseline/limits](reviews/2026-09-08-wave0/baseline.md) and [preserved old-task closeout](reviews/2026-09-08-wave0/stale-task-closeout.md), then verify HEAD, branch, uncommitted status and final manifest before dispatch. No commit/push/PR/merge was requested or performed. No successor orchestrator was needed.

The next authorized wave is W1, not the old native Wave 8. Use the current active checkout and preserve all uncommitted documentation. Allocate A data, B E*TRADE feasibility and C standard runtime under the global three-worker cap; serialize shared schemas/migrations/composition/build/CI through the orchestrator. The current `.venv` launcher is broken; temporary locked test setup and exact commands are recorded in the baseline. Six inherited architecture document constraints require a reviewed W1 checker migration, not invented W0 passes or obsolete prose. PostgreSQL locking/migration evidence requires an explicitly disposable local test database before financial persistence changes.

A starts with the frozen manifest/availability contract and a licensed source/import; C proves clock/suspend/ownership/halted startup/normal stop before removing mapped native prerequisites. B starts offline with fixtures; actual credentials, account reads, rights and quotes require separately scoped qualification inputs and permission. Missing B evidence may block W1 B while A/C progress; W1 overall cannot be marked complete while B is blocked. No source/account call, Preview/Place/Cancel, native activation, deployment, live amount, or follow-on wave is authorized by this handoff.

## 16. Wave 1 accepted boundary

Wave 1 A, B and C passed their bounded foundation/read-feasibility gates. Root integrated exact worker allowlists sequentially from base `107fa791`; the original 39 worktrees and frozen W0 contracts remain preserved. The [acceptance rationale](reviews/2026-09-08-wave1/wave1-acceptance.md) maps each retained provider limitation to its connected/execution gate. The owner-authorized closeout completed through PR #52; section 17 governs current work.

The integrated gate passed 1,264 Python tests and all selected formatting/lint/type/API/standard architecture/Compose checks. Seven PostgreSQL tests were skipped locally; CI configures a disposable PostgreSQL service. Two conventional wheel builds were byte-identical. The installed CLI outside the checkout starts HALTED, rejects duplicate ownership, stops on SIGTERM and restarts HALTED. Physical host suspension, external clock-offset measurement, remote CI and native/container activation are not claimed by these local results.

A imported and reloaded four Tiingo symbols over five sessions (20 real bars). This is exploratory current-vintage history with unknown vendor publication and explicit modeled 20:00 ET availability. It is not PIT or full-study-period qualification; the sample dates are no longer untouched holdout. Raw licensed payloads remain outside Git.

The owner authorized both E*TRADE environment read scopes, completed OAuth, selected the accounts and declared them dedicated to AutoQuantTrader. Initial sandbox balance identity failed; production CASH discovery/MARGIN balance evidence originally stopped a cash-only capture. The owner confirmed margin privileges and requested the [versioned eligibility amendment](contracts/personal-v1/account-eligibility-amendment.md). It permits an explicit CASH/MARGIN read profile while retaining cash-funded long-only financing, no borrowing and all-false order authority. The original W0 bytes and prior failed results remain preserved.

The revised production capture completed fresh discovery and balance, portfolio, current-order, bounded order-history and activity reads on 2026-09-09 at 22:18 UTC. Identity matched; discovery CASH and balance MARGIN remain distinct. Initial empty 204 responses are query observations, not reconciled absence. [Production metadata](reviews/2026-09-08-wave1/live-broker-production-cash-funded.json) records receipts, hashes, scope and all retained blockers. Across the recorded attempts there were 22 account GETs and six OAuth token requests. Supervised renewals preserve issuance and daily expiry. Sandbox still has mismatched stored balance examples; no other account was silently substituted.

USD, settled-cash/liability/restriction semantics, quotes, actual provider quotas, retention, usable execution/correction identities and reconciliation remain unqualified. The frozen quota obligation is explicitly unresolved: the ten-reads-per-minute/one-attempt/three-second limits are local bounds only. These prevent connected execution admission. They do not turn a complete authorized W1 read traversal into a failed transport result or authorize fabricated financial facts.

See [integrated evidence](reviews/2026-09-08-wave1/README.md), the [foundation runbook](runbooks/personal-v1-foundations.md) and [read-only runbook](runbooks/personal-v1-etrade-readonly.md). Preview/Place/Cancel, trading and deployment remain outside the owner-authorized read scope.

## 17. Wave 2 handoff (historical local-gate snapshot)

The same orchestration task completed local W2 acceptance from merged W1 revision `ec63ca793ed4fe8a68397dc752000e102741da59`, on `codex/personal-v1-w2-integration`. The [shared interfaces](contracts/personal-v1/wave2-interfaces.md) are implemented; the [current evidence index](reviews/2026-09-09-wave2/README.md) records local exit acceptance and remaining GitHub closeout. The [preservation inventory](reviews/2026-09-09-wave2/initial-preservation.json) records retained worktrees.

Root owns shared definitions, input conversion, reference strategy, CLI/composition, independent acceptance, golden product cutover and CI. A owns the single causal queue, daily target conversion and risk; B owns one-command accounting and financial oracle integration; C owns pure metrics/reporting. There are at most three workers, with no nested tasks. No new financial persistence migration is required in W2.

The five-session real Tiingo sample remains an insufficient-history case for default strategy/annualized metrics. Sufficiently long labelled fixtures and independent action/flow cases supply engineering acceptance; no factual publication time, provider action or untouched holdout is invented. W2 needs no provider requests, credentials, orders, subscriptions or deployment. Close all W2 gates and the authorized commit/PR/check/merge/verification workflow before beginning W3.

## 18. Wave 3 handoff (historical pre-merge snapshot)

Wave 2 is closed through PR #53 and its verified merged tree; the preceding section and Wave 2 accepted artifacts retain their original local-gate snapshot. This orchestration task started `codex/personal-v1-w3-integration` directly from the verified merge. The owner authorized continued waves and delegated routine recommendations; the standing commit/PR/CI/review/merge/verification workflow remains mandatory before each wave closes.

Root owns integration, codecs, catalog/evaluation persistence, migration 0039, API/composition, the shared process boundary and independent acceptance. A implements delegated new job DTOs, five additive job tables, artifact storage, lifecycle/workflow and orchestration. B implements new pure evaluation DTOs/input preparation and actual-engine tests. C implements delegated HTTP projection models and research UI; root owns generated API types and route cutover. At most three workers; no nested workers.

W3 uses 60-second database leases, ten-second heartbeats and at most three attempts with automatic recovery only after abandonment. Owner cancellation is durable and terminal; graceful worker shutdown is recoverable abandonment. Inputs are capped at 32 MiB and reports at 64 MiB, below W2's ceiling. Completed and incomplete publications remain distinct. Every candidate/fold/window/cost trial is registered before execution. The four fixed cost scenarios and explicit no-fit reference artifacts support descriptive comparisons; neither untouched historical data nor profitability eligibility is inferred. Existing data sufficiency and connected-execution gates remain visible.

### W3 integration decisions and observed limits

The retained Tiingo sample remains the selected real-data workflow check. It has five registered sessions, four scored sessions with the final session reserved as a calendar horizon, and no annualized or untouched-holdout claim. Longer labelled synthetic histories supply engine, chronological-isolation and cost-stress engineering checks. This follows the owner's delegated recommendation preference without choosing investment suitability criteria. Actual predeclared candidate eligibility and frozen forward qualification remain W6 gates.

Root's clean browser check exercised dataset selection, base/adverse runs, a terminal queued cancellation, actual report execution/journal views, and a comparable-cost report pair. A 520-session synthetic job survived parent SIGKILL, retained orphan ownership until child exit, waited for real lease expiry and completed on its second attempt with one publication. Independent rational/80-digit checks verified all three completed reports. No provider request or credential inspection was needed.

Integration caught and corrected the imported default execution horizon, concurrent idempotent launch recovery, research-owner configuration validation, whole-report work escaping the supervised child, explicit wheel payload exclusions, and the narrow-window shell/banner. SQLite experiment/readiness contention required coherent snapshots with bounded batch reads, dependency loading before transactions, and explicit research WAL/FULL operation on a patched SQLite runtime. The stronger retained-history probe passed all five simultaneous lanes across three rounds with unchanged timeout/lease settings. Earlier smaller passing probes and stronger failures remain labelled separately in the evidence index.

Three earlier experiment registries and all 36 owner-cancelled unexecuted trials remain retained; no attempt or accepted source pin is rewritten. Root declared a fresh 12-trial experiment through the actual browser against the frozen corrected source. All 12 completed in 48.944 seconds with one attempt/publication each; independent arithmetic, exact modeled costs, chronological resets, export bytes and source/report bindings passed. The final installed wheel separately passed actual execution and idempotent restart with WAL/FULL verified. That original local snapshot passed 1,974 Python tests, eight PostgreSQL skips and one retained dependency deprecation warning. Browser checks passed 139 Vitest and 33 bundle cases; Python lint/types, generated API contracts and architecture passed. Complete GitHub PR/CI/review/merge and exact content verification before beginning Wave 4.

PR #54 exposed browser fixture typing timeouts, PostgreSQL insert-result ambiguity and Linux inherited peak-memory accounting. The scoped corrections preserve production UI and risk/process limits, use actual returned inserts for idempotent transactional launch, and bind Linux post-exec peak measurement to resource profile `/2`. Independent reviews accepted the runtime changes. On corrected source `efe9fcc2a30fa66da4a8fc5ef372a7ce859b4792bd0dec9944ac0d2583f1531b`, 1,990 Python tests passed with eight PostgreSQL and one Linux-only skip; all static checks passed. A fresh synthetic 12-trial ASGI/CLI acceptance completed in 29.115 seconds with one attempt/publication per trial, independent arithmetic and unchanged restart. Two corrected wheels were byte-identical (`df8fd8799515410f992e10106027fea66434c51a8ca2503a0e9e0a3ac7765bc3`) and the new installation passed actual worker execution, economics and restart, with source/dependency bindings unchanged. Earlier evidence remains preserved under its actual source pins. See the [corrected-source evidence](reviews/2026-09-09-wave3/README.md#corrected-source-acceptance). Actual Linux/PostgreSQL CI and exact GitHub closeout remain required before W4.

## 19. Current Wave 4 handoff

This orchestration task verified PR #54 merge `e1bcea18eaa18ad144bc3b03a4891d11ecdd9b06` against tested tree `b90bf91f6b710cf7f2aa722de6eb15623c31adca` and all 147 W3 manifest bindings. PR CI passed 1,999 Python tests with actual PostgreSQL/Linux, browser and installed-package gates. Post-merge CI also passed all gates with 1,999 Python tests. Work starts on `codex/personal-v1-w4-integration`; original main/worktrees, W0 contracts and all earlier accepted source pins remain preserved.

Root owns the continuous spec/frontier and internal action APIs inside the existing causal engine, shared accounting/schema integration, composition, independent acceptance and GitHub closeout. Three bounded workers, no nested workers. A owns actual fact application, retained venue-source authentication and paired account/reconciliation publication. B owns account risk, durable admission/hold/attempt history and dispatch provenance. C owns independent stateful venue/forward captures and the continuous checkpoint store/composer; C is also implementing the concrete runtime source producer. Shared edits are assigned at exact interface boundaries. The three [preflight](proposals/wave4-reconciliation-preflight.md) [interface](proposals/wave4-coordinator-preflight.md) [proposals](proposals/wave4-simulation-preflight.md) are supporting designs, not acceptance claims or competing roadmaps.

Current implementation evidence is provisional and remains in the isolated integration staging directory. The existing engine now continues from retained checkpoints, applies actual reconciliation batches through the shared fact planner, and preserves original decision, source, wealth and request histories. An independent SQLite venue/capture test applies ordered cash facts through that engine without duplicating initial capital; it also retains the external-activity barrier. Continuous internal activation/release actions have an explicit separate request type and cannot enter through external source tapes. The request-budget callback receives original modeled request times; it does not establish actual provider quotas.

The common bounded journal, detached source readers, daily admission/hold/attempt store, continuous account store/composer, applied reconciliation store, and revision `0040_personal_continuous` are implemented in staging. Focused SQLite checks cover atomic admission/hold publication, first-send preparation, durable uncertain outcomes, explicit expired-unsent release, retained-source replay and rollback after deferred foreign-key commit failure. Codecs, source replay and canonical accounting run outside account write transactions. These component results do not yet establish a complete running coordinator. New PostgreSQL concurrency cases remain an actual CI/runtime gate.

The same concrete runtime producer now connects engine risk callbacks with historical admission/attempt restoration. Canonical checkpoints, observed hold revisions and applied reconciliation provenance publish inside one transaction, with original source, fence and deadline checks again immediately before the outer commit. Component checks cover first-send ownership, operational-schema integrity and the bounded HALTED restore/integrity process lifecycle. Full session/fault/resource acceptance remains open. No fixture source or caller-created evidence DTO supplies provider identity, entitlement, host-clock or provider-quota authority.

The September 12 continuation now has concrete finite session routing for daily/quote publication, pending attempts, activation and immediate one-use simulation sends, actual venue outcome observation, UNKNOWN recovery, expired-unsent release, and financial reconciliation. The original source, account, daily-risk, applied-reconciliation and independent venue owners remain authoritative. A cooperative exact-Event scope checks again after original publication/fence readbacks immediately before COMMIT; a sampled stop permanently denies further writes on that account instance. Its final sample and COMMIT are not atomic across processes. Command-rejected acknowledgments and lost acknowledgments preserve uncertainty; only the separately captured original registered order can establish a definitive attempt outcome. The fixed supervised worker still performs HALTED restore/integrity; it is not an active session launcher.

Focused session tests passed eight cases, and account stop/regression checks passed 99 with three PostgreSQL-only skips. The full partial/completed-fill, restart and repeated-reconciliation flow plus the signed-owner daily check passed two cases in 1,841.52 seconds. A separate interrupted-send case reconstructed all account/risk/source owners under a new lease and preserved UNKNOWN until independently captured acceptance, with exactly one submission and unchanged balances and holds; it passed in 841.77 seconds. These are modeled sources and in-process reconstruction, not active-worker or OS-crash qualification. External cancellation without a local request correctly remains blocked; its separate regression passed. Actual PostgreSQL competition, elapsed-time qualification and the complete final-source suite remain open.

After preserving those baseline bindings, a reviewed pure hashing change removed one redundant normalization pass without changing canonical bytes or per-call mutation detection. The broad unit check passed 2,488 cases with one expected Linux-only skip after a fixture-only account identity/order correction; that run preceded capture integration. A single bounded unprofiled comparison measured a warm-owner C9 restore at 58.065 seconds before and 51.689 seconds after the hashing change. This is not full-session, cold-owner or worker qualification. Both original resolution guards remain.

The reviewed capture publisher now retains the earliest original proof/window expiry through the final bounded field check and actual SQL readback immediately before COMMIT. UTF-8 bytes are charged before effects. Encoding and raw storage finish outside SQL, historical retries preserve their original bytes and samples, and fresh provider captures remain blocked until genuine source ownership exists. Independent review and integrated capture/downstream checks passed 331 cases with four PostgreSQL-only skips. The final check and physical COMMIT remain non-atomic with time.

The CI runner retains the personal profile and uses 16 deterministic test shards with at most four concurrent jobs, separate foundations/browser jobs and a required aggregate that rejects any failed or skipped dependency. This changes CI scheduling only; worker limits remain unchanged. Full static checks passed (980 files formatted, mypy over 415 source files), as did 139 browser and 33 bundle cases. The latest integration collection contains 1,231 cases, including 23 PostgreSQL cases; collection is not execution. Two conventional offline wheels were byte-identical, and installed research/process and HALTED-genesis restore/restart checks passed on the pre-factory baseline. An official PostgreSQL 16.15 source build in a temporary private prefix passed actual migrations and schema checks through revision 0040_personal_continuous; the Unix-only test server then shut down cleanly. The initial 23-case PostgreSQL run exposed a Boolean-to-BIGINT projection error, a default-isolation mismatch in capture publication and a shared fixture collision. The reviewed corrections preserve integer ranges, original SQL/readback/deadline guards and all financial assertions; capture test instrumentation now tracks each actual connection. All 23 PostgreSQL cases passed in 157.34 seconds on the corrected five-file candidate with zero skips, unchanged source and complete server cleanup. Those five files are adopted in staging, and full static checks pass (981 formatted files and 415 typed source files). The complete final-source and Linux gates remain pending. Component manifests and prior accepted hashes remain immutable. Read the [dated offline progress record](reviews/2026-09-10-wave4/offline-progress-2026-09-12.md) for exact evidence and pending owner inputs.

The new runtime environment is `stateful_simulation`, with a separate versioned daily producer map and all-false live authority. Provider source environments remain separately identified. Preserve actual CASH/MARGIN privileges under cash-funded long-only/no-borrowing policy. The new coordinator must reuse the sole engine frontier and accounting reducers; repeatedly starting historical runs is not continuous operation. Restart retains strategy/trigger/request/wealth/account state. A modeled terminal commitment never supplies authority to release durable broker UNKNOWN/pending-cancel holds. External activity and missing provider sequence/settlement/correction semantics require explicit mappings or blockers; no invented risk approval or projection overwrite.

A separate factory candidate binds the original delivery, independent read-only venue and outcome owners needed for retained history; it remains unadopted. Fourteen focused checks passed, but the genuine signed C12 restore failed after 61.95 seconds and lease-release cleanup masked the primary execute exception. One bounded diagnostic on the preserved history stopped at acquisition because its expired active lease requires durable takeover, which current APIs do not implement. It did not locate the earlier failure. A genuine clean-release C12 fixture was subsequently prepared in 296.78 seconds and its 149 files verified and archived before any measured factory acquisition. Its original 60-second lease and source/configuration bindings remain; no expired head is repaired or guard relaxed. Repeated full B validation inside both retained C guards is being addressed in a separate integrity/composer candidate, with scoped ownership and mutation checks under review. No factory or reuse correction is adopted yet. One subsequent clean-snapshot diagnostic identified the primary failure after60.327seconds: initial integrity reconstruction exhausts the unchanged 60-second lease in composer.prepare_capture through a repeated daily.read_snapshot. Factory's later account.restore was not reached. The original history remained unchanged, primary and cleanup failures were recorded separately, both engines were disposed and the child was reaped. The scoped reuse candidate then passed37 focused cases, including actual PENDING source ownership, prospective observed ownership with explicit rejection from historical reuse, and both foreign-slot catch/repair failure-latching regressions. Independent review verified1,119 unchanged inputs. These checks do not qualify nonempty retained activation/outcome/observed history. A separate combined candidate preserves the adopted PostgreSQL fixes and original factory baseline, with1,580 exact source hashes and full static checks passing (983 formatted files,415 typed source files); its original-limit C12 diagnostic subsequently failed after 60.049 seconds at the final borrowed-B fence check during initial integrity. Both engines were disposed, the child was reaped, and original history and source pins stayed unchanged. No historical sequence was recorded, so the two failed timings do not establish improvement. One reviewed eight-span diagnostic produced valid timing data but failed at lease expiry after 60.525 seconds during initial integrity, before the failed B recheck's table/source readbacks. Its 66 full daily-graph checks used 24.974 seconds of selected exclusive time; C reference checks used 2.952 seconds. These are instrumented enclosing costs, not isolated fingerprint costs or a performance improvement. All wrappers were restored and original source/history checks passed; lease release failed separately, while both engines and the child/group were cleaned up. The subsequent 13-span diagnostic was also valid but failed at initial integrity's final fence after 63.811 seconds, following its original row checks. All 24 scoped borrows and 37 B rechecks returned; the later factory restore remained unreached. Selected exclusive time was 9.125 seconds for attempt-source validation, 7.110 for descriptor checks and 4.633 for B identity scans; these are enclosing method costs, not isolated fingerprint timings. Original source/history and resource cleanup checks passed, with lease release failing separately. The narrow resolved-attempt fingerprint change passed 22 pure/PENDING compatibility checks in 14.54 seconds and independent review; its three files are adopted in staging. It removes only a redundant semantic traversal after unchanged complete detachment. Exact byte/hash/error/read-order proof and all 1,582 run pins passed; the child was reaped with no timeout or cleanup fault. This does not qualify retained history, full startup or performance. The separate factory candidate now returns the same original account result after fixed full-schema verification, final original source/object/SQL/fence checks and successful cleanup. The second factory restore is removed through an explicit contract change: intervening later state is rejected rather than adopted. Both underlying index guards remain. All 37 distinct focused cases have passing evidence across three controlled runs:16 A and3 B cases before test-only failures, then the 18 corrected or unreached cases passed in 25.13 seconds. Independent AST/dependency review binds the unchanged 19 cases to final source. The failures were a slotted-instance test patch and an invalid equality between separately sampled receipt/head timestamps; both are preserved. All 1,585 source pins and child cleanup checks passed on every run. The handoff has explicit narrower object-count limits and is not yet adopted. The next retained C12 run failed after 62.340 seconds with FACTORY_HANDOFF_UNKNOWN_MUTABLE_VALUE while sealing the restored graph, before the final integrity readbacks. Lease release failed separately after expiry. All source, financial-state, venue and artifact postchecks passed; both engines and the child/group were cleaned up. Source review identified an unsupported reachable SQLAlchemy Case expression in the original retained hold-revision selector, without establishing that it was the first rejected leaf in that run. A separate correction supports that exact bounded expression, removes a redundant venue fingerprint traversal and avoids descending exact immutable scalar leaves during B identity scans. The combined candidate passed 95 checks in 47.53 seconds: 92 pure compatibility cases and three actual PENDING/retained-venue fixtures. All 1,591 source pins remained unchanged and child/group cleanup passed. Those checks qualify the original CASE-bearing restored graph and finite byte/hash/field-read compatibility. Full static checks passed (994 formatted files and 415 typed source files). The subsequent unchanged-limit C12 run passed graph sealing and reached initial integrity's final lease check, then failed after 60.424 seconds at expiry; the later post-schema handoff remains unreached. Original financial/source/venue/artifact checks and process cleanup passed, with lease release failing separately. Root independently verified all 55 failed-run evidence bindings. Full retained-history startup and the unchanged 60-second lease gate remain open; the corrections remain unadopted. A further isolated correction removes the redundant semantic traversal at both fully detached account-reference fingerprint sites and moves the unchanged exact-tuple encoder branch earlier. Both index guards and all owner/source/object/SQL/fence checks remain. The combined candidate passed 290 checks in 50.23 seconds: 267 pure cases and 23 actual fixtures, including the original reference creation, heartbeat/restart, alias, mutation and final SQL boundaries. All 1,594 source pins and child/group cleanup checks passed. Full static checks also passed (997 formatted files and 415 typed source files). Independent review verified the exact seven source/test changes from the previous candidate; no retained startup or performance success is inferred. The separate two-line CI selection correction passed all 18 existing runner cases and is adopted in staging so the existing attempt fingerprint regression runs in CI. The subsequent original-limit retained C12 attempt reached the final factory lease check and failed after 61.984 seconds. The unchanged source path establishes that full schema verification, the original integrity handoff, the later fresh daily read and signed-assignment/HALTED/Stop checks returned; result encoding was not reached. Original financial/source/venue/artifact checks and child/group cleanup passed, while expired-lease release failed separately. Root independently verified all 119 failed-run audit bindings. The production corrections remain isolated and unadopted. This later failure boundary does not establish a performance improvement or successful startup. The final fresh daily read serves a separate currentness window and remains unchanged; a bounded pure type-lookup experiment is next, with no further history run released.

A separate worker Stop Event seam now exposes the original cancellation Event and latches a deadline observed by stop_requested into that same Event. It preserves all existing signals, parent-death handling, limits and HALTED launcher/lifecycle behavior. All 31 process tests passed in 11.35 seconds with 859 input hashes unchanged after scoped permission for the existing own-child RSS check; the initial sandbox denial and corrected child-execution proof are preserved. Root adopted only the source, fixture and new test file. Full staging static checks passed with 985 unchanged code/configuration inputs (982 formatted files and 415 typed source files). These checks qualify the Event seam, not an active worker or elapsed-time deadline.

W4 remains incomplete until the section 8 exit demonstrations pass, including actual authorized captured-session replay and separately scoped E*TRADE read reconciliation. The owner subsequently reported purchasing Tiingo Power on September 20; the updated EOD retention basis and E*TRADE rights next steps are recorded in the recovery record. Actual captured-session qualification remains unreleased. The previous OAuth expiry is past; fresh supervised session access will be needed when provider qualification is ready. Missing quote rights, identity, delay, freshness, quotas or financial semantics remain explicit gates. No Preview/Place/Cancel, subscriptions, deployment or trading activation is authorized by continued implementation. The standing commit/PR/CI/review/merge/exact-verification workflow applies before W5.

### September 20 recovery

Exact isolated integration, R9 and R10-R1/R2 source trees were recovered into persistent storage and archived. The complete original R2 source-manifest hash matches; the Python runtime was reverified. This recovers implementation, not a successful retained-history startup: the last recorded attempt failed and its detailed output is missing. Continue from the [recovery record](reviews/2026-09-10-wave4/recovery-2026-09-20.md), preserving the unchanged lease and resource limits. Wave 4 and its GitHub closeout remain incomplete.


### Latest recovered qualification status

The isolated R13d personal-profile regression completed all 4,292 cases across 16 serial groups: 4,281 passed, ten failed and one Linux-only case skipped. All 23 PostgreSQL cases passed every phase; source/runtime checks and process cleanup passed. The original failed result remains unchanged. The six stale-schema failures and four fixture setup errors are addressed by five test-only changes in R13f; all 43 affected/guard cases passed across 129 phases in the required order. Its static check exposed one formatting-only assertion change; R13g preserves the same complete test AST and all other files. The R13g format/lint checks now both pass. PostgreSQL shut down cleanly through its original owner, with independent terminal verification. Checkpoints 23 and 24 are archived and independently verified; completed regression and correction records are retained in the persistent recovery directory. The latest candidate remains isolated and unadopted. Linux, active-session/captured-replay and provider acceptance, specific initializer approval, Tiingo capture eligibility and GitHub closeout remain open; trading remains disabled.

The owner confirms Tiingo Power, current E*TRADE paperwork, permitted retention and approved technical quote qualification. The support quote reader passed all 60 offline cases and the Sunday zero-request guard. Actual production qualification awaits fresh supervised OAuth and the reviewed September 21, 09:35–09:40 Eastern window. See the newest recovery-record decision; the separate initializer approval remains pending.

The bounded Tiingo EOD technical qualification passed on September 20: four HTTP 200 requests for DIA/IWM/QQQ/SPY over September 14–18, twenty rows and all thirteen fields. A separate offline process reloaded the same retained capture with matching manifest/semantic/qualification hashes and zero network calls. All 44 wrapper cases passed after one fixture-only correction; source/runtime checks and owned cleanup passed. This is current-vintage receipt-time sample qualification, not PIT, ongoing quota, broker semantics or integrated Wave 4 captured-session/replay acceptance. The new recovery-record entry binds the sanitized evidence. Monday E*TRADE qualification and the separate initializer gate remain open.


### September 24 integration checkpoint

The reviewed R13g implementation has now been adopted into the Wave 4 feature branch: 249 exact source, migration, test and CI files over the verified Wave 3 merge. The existing canonical documents and historical evidence were preserved. See [the integration checkpoint](reviews/2026-09-24-wave4-integration/README.md) for the source bindings and validation scope. The next GitHub PR is a draft to qualify this exact revision with the 16-shard Linux/PostgreSQL workflow, foundations, installed-wheel checks and browser regressions. No new full local regression or wheel build was needed solely for the accepted test corrections. Wave 4 remains incomplete: actual captured-session decision parity, scoped provider/account qualification, the separately approved initializer work and final review/merge verification are still required. The September 21 quote window has expired; a separately reviewed September 24 window requires fresh same-day production OAuth. Prior failed results remain failed and trading stays disabled.


### September 24 offline adapters and Linux CI finding

Draft PR [#55](https://github.com/km8trix/AutoQuantTrader/pull/55) is open at the integrated baseline `47fab9c32108151e1d98a5e636579a22cb86813c`. The optional Chrony-to-StandardClock conversion passed 53 offline cases, format/lint/types and the architecture boundary check. Local original-binding checks for both capture HTTP adapters passed 85 cases, including four unchanged no-effect publication/source guards. [Adapter evidence](reviews/2026-09-24-wave4-integration/offline-adapters.json) binds the exact source and independent review. These additions do not qualify a host clock or admit genuine captures.

The first Linux CI run exposed a retained-history startup failure: integrity verification exceeded the original 60-second lease at 60.190 seconds, followed by a separate lease-release cleanup failure. The failed result remains failed; source performance work is isolated and the lease limit is unchanged. Foundations, migrations, installed-wheel and browser jobs passed, while the full regression gate remains unresolved. The September 24 quote window expired without fresh OAuth or a provider request. Initializer approval, actual source ownership/captured-session replay and provider/account qualification remain open. Wave 4 is incomplete and no merge or Wave 5 start is authorized by these component passes.


### September 24 retained conversion correction

The baseline Linux run completed with 4,291 passed, one failed and zero skipped tests. The single retained-factory failure exceeded the unchanged 60-second lease; the failed run remains recorded. Two narrow conversion changes now dispatch exact built-in tuples and scalars before redundant dataclass reflection, preserving bytes hashing, mapping precedence, subclass behavior and all existing source, SQL and lease checks. The focused qualification passed 284 cases (76 new and 208 existing), plus formatting, lint and type checks.

A finite synthetic benchmark verified all 768 outputs and measured lower converter costs on that fixture only. One fresh copy of the existing synthetic C12 history then restored successfully in 43.601 seconds with the original 60-second lease, 120-second operation and 150-second parent limits. Financial records, source artifacts and independent venue data were preserved, and owned cleanup passed. This is a local restore result, not a startup performance comparison or Linux acceptance. Bounded static code locations were added to the existing CI failure reporter without changing its test, lease or timing logic.

The correction is ready for a new exact-head CI run on draft PR #55. The updated suite is expected to contain 4,416 cases. Actual captured-session replay, scoped provider/account qualification, the separate initializer approval and final CI/review/merge remain open. No provider request, initialization, order or deployment occurred.

[Correction evidence](reviews/2026-09-24-wave4-integration/pure-dispatch.json) binds the source and independently reviewed results.


### September 24 imported-calendar consistency prerequisite

A new opt-in helper compares a capture request with the exact imported research-calendar pin and session open/close values. It uses the existing Tiingo projection, including string session kinds and the personal America/New_York calendar constraint. The caller must explicitly choose that digest convention. Equal copied content can pass this check and does not confer source authority. The genuine-source admission guard and all existing capture behavior remain unchanged.

All 106 focused cases passed: 44 new calendar cases and 62 existing capture/import/publication guard cases. Formatting, lint, types and the architecture boundary also passed, with source/runtime and owned cleanup checks. Synthetic cases cover winter/summer offsets, half days, missing sessions and nested mutation. This completes a mechanical prerequisite; it does not qualify a real calendar, clock, provider or captured session. The implementation is held locally while the already-running correction CI finishes, so that run continues to test its original exact commit.

[Calendar qualification evidence](reviews/2026-09-24-wave4-integration/capture-calendar.json) records the exact scope and bindings.


### September 25 canonical fragment assembly correction

The latest Linux run completed with 4,415 passed and one retained-restore failure at the unchanged 60-second lease. The failed run and separate cleanup failure remain recorded. A bounded local diagnostic identified repeated typed-JSON assembly as a material cost; its instrumented restore also failed and is not performance acceptance.

The correction records fallback positions, preserves conversion and deferred serialization order, and joins completed string fragments directly. All 296 compatibility cases passed, including 12 new ordering, mutation and error-precedence cases, with format/lint/types. Two finite synthetic workloads verified 768 timed outputs and measured candidate/old median ratios of 0.732 for primitive tuples and 0.935 for mixed fallbacks. These are serializer measurements only.

One fresh copy of existing synthetic C12 history restored in 41.345 seconds under the original 60/120/150/8/1 limits, with financial/source/artifact/venue preservation and complete cleanup. The calendar helper and serializer correction are ready for exact-revision Linux CI, expected to contain 4,472 cases. This local pass does not close the prior Linux failure. Actual captured-session replay, scoped provider/account qualification, specific initializer approval and final review/merge remain open. Wave 4 is incomplete.

[Correction evidence](reviews/2026-09-24-wave4-integration/canonical-fragment-join.json) binds the exact source and independently reviewed results.


### September 25 tuple validation cost correction

Linux CI on `5e6595c` completed with 4,471 passed and one retained-restore failure at 60.186 seconds; the unchanged 60-second lease and separate expired-lease cleanup failure remain recorded. The new correction assembles scalar tuple children without recursive helper calls and dispatches exact tuples earlier in identity traversal. Canonical bytes, ordered identities, mutation/read/error order and all source, SQL and lease checks remain unchanged.

All 335 focused checks passed: 309 existing unit cases, 25 new identity cases and one original PENDING publication/restore fixture, plus format/lint/types. The first proposal's two mypy errors are preserved; its unit/PENDING phases never ran. The corrected exact-type predicate needs no runtime cast.

Finite benchmarks verified 1,536 serializer outputs and 512 identity outputs. Serializer candidate/prior median ratios were 0.921 for primitive tuples and 0.981 for mixed fallbacks, but scalar string and None controls were slower at 1.283 and 1.668 (about 84 ns and 127 ns extra per call). Identity ratios were 0.774 and 0.845. These measurements do not establish a uniform speedup or predict startup performance.

One unprofiled fresh copy of existing synthetic C12 history restored in 40.821 seconds under the original 60/120/150/8/1 limits, with financial/source/artifact/venue preservation and complete cleanup. This local pass does not close the Linux failure. Together with 26 separately qualified diagnostic-helper cases, the next required CI suite is expected to contain 4,523 cases across 16 shards. Actual captured-session replay, provider/account qualification, specific initializer approval and final CI/review/merge remain open. Wave 4 is incomplete and Wave 5 has not started.

[Correction evidence](reviews/2026-09-24-wave4-integration/validation-cost.json) binds the exact source and independently reviewed results.


The optional Linux diagnostic profiles only the original factory execution and runs after a required backend regression failure. Required tests remain unprofiled, original limits and failures remain authoritative, and diagnostic artifacts contain bounded static code metadata and timings only. All 26 finite reporter and fake-lifecycle checks passed, along with architecture/format/lint. The earlier assertion-message test failure is preserved and its test-only correction was rechecked. No actual retained history was rerun for instrumentation. [Diagnostic evidence](reviews/2026-09-24-wave4-integration/linux-retained-profile.json) records the exact scope.
