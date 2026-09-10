# AutoQuantTrader implementation plan

Status: sole authoritative delivery plan. Waves 0/1 closed through [PR #52](https://github.com/km8trix/AutoQuantTrader/pull/52); Wave 2 closed through [PR #53](https://github.com/km8trix/AutoQuantTrader/pull/53), merged as `6ea218addaa38d1c36c69b6a7ffbe564d701f834` with successful PR and post-merge checks. Wave 3 local exit gates passed; GitHub PR/CI/merge verification remains open. Broker connected-execution qualification remains blocked; trading and deployment stay disabled.

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

Do not begin dependent work until its prerequisite passes. A provider/account blocker need not stop independent offline research: the dependency table permits Waves 2–3 after the data/runtime parts of Wave 1, while broker work is explicitly blocked. Those dependencies describe technical eligibility. Under the owner’s requested sequential closeout cadence, finish the current wave and its GitHub merge before starting the next wave; Wave 1 GitHub closeout has passed; Wave 2 is current. The same three-worker global cap applies. There is no automatic retry of an external action simply to fill a task slot.

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
| W3 | **Local gates passed — GitHub closeout pending** | Base `6ea218addaa38d1c36c69b6a7ffbe564d701f834`; original browser/recovery and corrected-source API/worker/evaluation, 1,990 Python tests, 139 browser unit cases, installed package; [evidence index](reviews/2026-09-09-wave3/README.md) | PR #54 CI including eight PostgreSQL cases and the Linux fork/exec regression, review, merge and exact merged-tree verification |
| W4 | Not started | None | W1 broker/runtime + W2 |
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

The architecture's personal-use simplifications take precedence over conflicting old future requirements. Keep factual implementation limits visible until changed and verified. Wave 0 ends with reviewed contracts and an offline baseline; Wave 1 data/runtime and authorized production read foundations are accepted within their evidence limits. Connected execution qualification remains blocked; W1/W2 GitHub closeout passed; W3 corrected-source local gates passed and PR #54 closeout is current.


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

## 18. Current Wave 3 handoff

Wave 2 is closed through PR #53 and its verified merged tree; the preceding section and Wave 2 accepted artifacts retain their original local-gate snapshot. This orchestration task started `codex/personal-v1-w3-integration` directly from the verified merge. The owner authorized continued waves and delegated routine recommendations; the standing commit/PR/CI/review/merge/verification workflow remains mandatory before each wave closes.

Root owns integration, codecs, catalog/evaluation persistence, migration 0039, API/composition, the shared process boundary and independent acceptance. A implements delegated new job DTOs, five additive job tables, artifact storage, lifecycle/workflow and orchestration. B implements new pure evaluation DTOs/input preparation and actual-engine tests. C implements delegated HTTP projection models and research UI; root owns generated API types and route cutover. At most three workers; no nested workers.

W3 uses 60-second database leases, ten-second heartbeats and at most three attempts with automatic recovery only after abandonment. Owner cancellation is durable and terminal; graceful worker shutdown is recoverable abandonment. Inputs are capped at 32 MiB and reports at 64 MiB, below W2's ceiling. Completed and incomplete publications remain distinct. Every candidate/fold/window/cost trial is registered before execution. The four fixed cost scenarios and explicit no-fit reference artifacts support descriptive comparisons; neither untouched historical data nor profitability eligibility is inferred. Existing data sufficiency and connected-execution gates remain visible.

### W3 integration decisions and observed limits

The retained Tiingo sample remains the selected real-data workflow check. It has five registered sessions, four scored sessions with the final session reserved as a calendar horizon, and no annualized or untouched-holdout claim. Longer labelled synthetic histories supply engine, chronological-isolation and cost-stress engineering checks. This follows the owner's delegated recommendation preference without choosing investment suitability criteria. Actual predeclared candidate eligibility and frozen forward qualification remain W6 gates.

Root's clean browser check exercised dataset selection, base/adverse runs, a terminal queued cancellation, actual report execution/journal views, and a comparable-cost report pair. A 520-session synthetic job survived parent SIGKILL, retained orphan ownership until child exit, waited for real lease expiry and completed on its second attempt with one publication. Independent rational/80-digit checks verified all three completed reports. No provider request or credential inspection was needed.

Integration caught and corrected the imported default execution horizon, concurrent idempotent launch recovery, research-owner configuration validation, whole-report work escaping the supervised child, explicit wheel payload exclusions, and the narrow-window shell/banner. SQLite experiment/readiness contention required coherent snapshots with bounded batch reads, dependency loading before transactions, and explicit research WAL/FULL operation on a patched SQLite runtime. The stronger retained-history probe passed all five simultaneous lanes across three rounds with unchanged timeout/lease settings. Earlier smaller passing probes and stronger failures remain labelled separately in the evidence index.

Three earlier experiment registries and all 36 owner-cancelled unexecuted trials remain retained; no attempt or accepted source pin is rewritten. Root declared a fresh 12-trial experiment through the actual browser against the frozen corrected source. All 12 completed in 48.944 seconds with one attempt/publication each; independent arithmetic, exact modeled costs, chronological resets, export bytes and source/report bindings passed. The final installed wheel separately passed actual execution and idempotent restart with WAL/FULL verified. That original local snapshot passed 1,974 Python tests, eight PostgreSQL skips and one retained dependency deprecation warning. Browser checks passed 139 Vitest and 33 bundle cases; Python lint/types, generated API contracts and architecture passed. Complete GitHub PR/CI/review/merge and exact content verification before beginning Wave 4.

PR #54 exposed browser fixture typing timeouts, PostgreSQL insert-result ambiguity and Linux inherited peak-memory accounting. The scoped corrections preserve production UI and risk/process limits, use actual returned inserts for idempotent transactional launch, and bind Linux post-exec peak measurement to resource profile `/2`. Independent reviews accepted the runtime changes. On corrected source `efe9fcc2a30fa66da4a8fc5ef372a7ce859b4792bd0dec9944ac0d2583f1531b`, 1,990 Python tests passed with eight PostgreSQL and one Linux-only skip; all static checks passed. A fresh synthetic 12-trial ASGI/CLI acceptance completed in 29.115 seconds with one attempt/publication per trial, independent arithmetic and unchanged restart. Two corrected wheels were byte-identical (`df8fd8799515410f992e10106027fea66434c51a8ca2503a0e9e0a3ac7765bc3`) and the new installation passed actual worker execution, economics and restart, with source/dependency bindings unchanged. Earlier evidence remains preserved under its actual source pins. See the [corrected-source evidence](reviews/2026-09-09-wave3/README.md#corrected-source-acceptance). Actual Linux/PostgreSQL CI and exact GitHub closeout remain required before W4.
