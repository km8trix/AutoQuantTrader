# Executable plan

Updated 2026-09-26 from source `b1156ba` and its actual CI. This is the small-task
breakdown of [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md), not a replacement
product direction. [SPEC.md](SPEC.md) defines scope, [STATUS.md](STATUS.md) tells
where to resume, and [TESTING.md](TESTING.md) defines command prerequisites. Frozen
contracts, dated amendments, approval gates and wave exit requirements remain.

Read spec/status/plan → choose the first unblocked task → implement → validate →
inspect/fix/retest → update status/decisions → commit focused work → continue.
A known failed gate remains failed until its applicable acceptance passes; do
not proceed to dependent work. Independent offline work can continue.

`AQT_PYTHON` below is an explicitly selected verified Python 3.12 interpreter.
Focused pytest commands use TESTING's clean environment. No commands here source
credentials, start live services or authorize provider traffic.

| Milestone | State | Dependency |
|---|---|---|
| A0 — concise operating documents | Complete | Source/history audit |
| A1 — standard runner covers sharding controls | Complete | A0 audit |
| A2 — retained restore within original limits | Linux b6e4815 failed; revised local candidate ready | Existing W4 integration |
| A3 — genuine capture bridge contract and offline guards | Offline scope locally complete; publication/CI pending | Existing capture/clock/calendar boundaries |
| A4 — actual W4 source/account/session acceptance | Blocked | A2/A3, scoped access and initializer approval |
| A5 — Wave 4 GitHub closeout | Blocked | All W4 acceptance including A4 |
| B1 — restricted protocol implementation | Blocked | W4 merged and verified |
| B2 — operational controls and recovery | Blocked | B1 and W5 integration |
| C1 — forward qualification/readiness dossier | Blocked | W3 and W5 closed, source/provider evidence |
| C2 — canary and eventual unattended operation | Blocked | C1 plus explicit owner approvals |

## A0 — concise operating documents

- **Objective:** a fresh task can resume from repository facts without chat history.
- **Scope:** AGENTS, SPEC, ARCHITECTURE, PLAN, STATUS, DECISIONS, TESTING and README
  navigation. Archive useful previous handoff; retain existing roadmap/contracts.
- **Dependencies:** inventory tracked code, tests, config, scripts, history and
  existing dirty changes; identify current versus historical checkouts.
- **Acceptance criteria:** requirements separated from assumptions; actual
  composition and capital/credential boundaries documented; exact commands and
  known failures visible; no conflicting current handoff; existing edit preserved.
- **Validation commands:** `git diff --check`; `$AQT_PYTHON -I -B
  scripts/check_personal_architecture.py`; resolve local Markdown links in current
  docs and check commands against Makefile/CI. See dated assessment for results.
- **Completion criteria:** all seven requested files exist, source-backed review
  and link/diff checks pass, status names the next task and evidence limitations.

## A1 — standard runner covers sharding controls

- **Objective:** continuously test the infrastructure that selects financial tests.
- **Scope:** include existing pure sharding tests in `run_personal_tests.py` and
  correct their historical workflow reference. Preserve existing assertions.
- **Dependencies:** identify standard versus manually dispatched legacy workflow.
- **Acceptance criteria:** default runner selects every sharding test; stable,
  disjoint, complete assignment and explicit PostgreSQL option behavior pass;
  legacy workflow contract is still tested against its actual file.
- **Validation commands:** `$AQT_PYTHON -B -m pytest -q -p no:cacheprovider
  tests/unit/test_personal_ci_runner.py tests/unit/test_pytest_sharding.py`;
  `$AQT_PYTHON -m ruff format --check scripts/run_personal_tests.py
  tests/unit/test_personal_ci_runner.py tests/unit/test_pytest_sharding.py`;
  `$AQT_PYTHON -m ruff check` on those same paths; `git diff --check`.
- **Completion criteria:** reproduce stale assertion failure, repair root cause,
  all 32 focused cases and static checks pass; include 14 added cases in future CI.
  This does not close the unrelated retained-history failure.

## A2 — retained restore within original limits

- **Objective:** repair the actual signed retained-outcome restore failure.
- **Scope:** bounded diagnosis and minimal behavior-preserving cost reduction;
  retain every original source/object/SQL/history/fence validation. Preserve
  required unprofiled gate and separate diagnostic result.
- **Dependencies:** exact `b1156ba` CI run 36096804829 and its bounded profile;
  source-owned synthetic retained-history fixture and isolated runtime.
- **Acceptance criteria:** byte/hash/error/read-order and subclass/mutation
  compatibility; unchanged ledger, venue, artifacts and controls; original
  60-second lease, 120-second operation, 150-second parent and existing resource
  limits; successful owned child/group/engine/lease cleanup. All Linux shards pass.
- **Validation commands:** clean focused tests for each modified pure helper;
  `$AQT_PYTHON -B -m pytest -q -p no:cacheprovider
  tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease`;
  architecture, Ruff and mypy commands from TESTING; full runner with explicit
  disposable PostgreSQL across all 16 CI shards; inspect `gh run view <run-id>`.
- **Completion criteria:** independent review of the narrow change, local retained
  preservation/cleanup evidence and successful exact-revision Linux/PostgreSQL CI.
  A synthetic microbenchmark or a local restore alone is insufficient. If only a
  change to ownership/lease semantics could help, stop for the consequential decision.

## A3 — genuine capture bridge contract and offline guards

The [concrete contract investigation](reviews/2026-09-26-autonomy/capture-bridge-contract.md)
identifies source selection, retained measured-clock ownership and original
transport/source ownership as separate offline slices. Start with A3.1 mechanical
selection validation using existing records; keep genuine publication denied.

- **Objective:** specify the missing source-admission boundary before implementation.
- **Scope:** map clock, calendar, HTTP identity, rights, raw capture/publication,
  expiry and SQL fence owners; describe positive/negative evidence for a genuine
  captured session. Keep `CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED` until its
  replacement is fully specified, reviewed and qualified.
- **Dependencies:** existing capture contracts and current offline helpers; owner
  decision if new authority/ownership design lacks an established precedent.
- **Acceptance criteria:** no copied object/hash alone confers source authority;
  timestamps/expiry cannot be rebased; no provider request or initializer effect;
  proposed interface and adverse tests are concrete and source-referenced.
- **Validation commands:** clean pytest on
  `tests/unit/test_forward_capture_http.py`,
  `tests/unit/test_personal_capture_calendar_binding.py`, and existing
  `test_personal_forward_capture*` files, including
  `tests/integration/test_personal_forward_capture_publication.py`, found with
  `rg --files tests`; architecture/Ruff/types if implementation changes.
- **Completion criteria:** reviewed contract and offline regression evidence, or
  an explicit narrowly stated consequential choice recorded as a blocker. This
  milestone does not grant provider access or source qualification.

### A3.2a — retain the original clock conversion (locally validated)

- **Objective:** retain the exact reading that produced a standard measurement.
- **Scope:** optional `ChronyStandardObservation` and original-owner verification;
  preserve the legacy conversion call, error codes, deadlines and health policy.
- **Dependencies:** existing bounded Chrony source and mechanical standard bridge.
- **Acceptance criteria:** one source read; exact reading/measurement association;
  copies, foreign owners, mutations and changed callbacks fail without new reads;
  weak ownership cleanup; no currentness, host qualification or capture authority.
- **Validation commands:** clean pytest on `tests/unit/test_personal_standard_clock_chrony.py`
  and `tests/unit/test_standard_clock.py`; architecture, Ruff, mypy, diff checks.
- **Completion criteria:** independent review and all 92 focused cases pass,
  original behavior preserved, discovered ownership defects and corrections recorded.
  Linux acceptance of the pending commit is still required before integration.

### A3.2b — retain measured health history (locally validated)

- **Objective:** bind a health result to its actual measured observations from startup.
- **Scope:** inspect and implement the smallest opt-in owner consistent with existing
  `StandardClock`; retain original source/clock/epoch bindings and health history.
  Keep capture admission denied and runtime profiles unchanged.
- **Dependencies:** A3.2a; source-backed interface review before implementation.
- **Acceptance criteria:** arbitrary or simulated healthy snapshots cannot qualify;
  60-second startup/recovery and 30-second age/cadence policies remain unchanged;
  historical verification invokes no clock/source callback and makes no currentness claim;
  copies, field/callback replacement, regression, suspend and epoch faults reject.
- **Validation commands:** existing clock tests above and new selected `test_personal_*`
  cases; architecture, Ruff and mypy. All time and source callbacks are synthetic.
- **Completion criteria:** reviewed ownership and unchanged reducer-policy evidence,
  with 186 focused cases (94 new) passing; preserve the original pending-observation
  substitution failure and its correction.
  This component alone cannot satisfy actual host qualification or A3.4 admission.

### A3.3a — preserve Tiingo binding and deadline through cleanup (locally validated)

- **Objective:** prevent successful HTTP results after original binding or deadline loss.
- **Scope:** the existing Tiingo concrete transport; check original loader identity
  after dependency callbacks and defer success until all cleanup and final checks.
- **Dependencies:** reproduced mock-only loader replacement, cleanup mutation and
  deadline-equality failures in the existing transport; no qualified source needed.
- **Acceptance criteria:** changed loader cannot dispatch; request/loader changes
  and effective deadline expiry during cleanup cannot return success; preserve
  one-use ownership, fixed endpoint, resource cleanup and static failure precedence.
- **Validation commands:** clean pytest on `tests/unit/test_forward_capture_http.py`
  and affected personal capture tests; architecture, Ruff, mypy and diff checks.
- **Completion criteria:** preserve failed reproductions, pass new adverse cases
  and existing regressions, independently review the focused change. This repairs
  an existing transport boundary; it grants no provenance or genuine capture admission.

## A4 — actual Wave 4 source/account/session acceptance

- **Objective:** establish actual-observation replay and independent reconciliation.
- **Scope:** scoped provider/account/quote semantics, fresh authorized OAuth and
  reviewed capture window, genuine clock/calendar/source ownership, permitted
  capture retention, separately approved initializer and actual-session parity.
- **Dependencies:** A2/A3; owner/access prerequisites recorded in STATUS. Expired
  historical windows and previous credentials cannot be reused by assumption.
- **Acceptance criteria:** W4 session/financial/fault/process gates in the existing
  roadmap; actual captured decisions reproduce under the original observations;
  independent venue/account reconciliation and complete cleanup; no live orders.
- **Validation commands:** offline `test_continuous_session*`,
  `test_continuous_capture*`, `test_continuous_reconciliation*` and relevant account
  fixture tests via the sanitized runner. Provider commands are deliberately not
  executable defaults: use `docs/runbooks/personal-v1-etrade-readonly.md` only
  with its specific access/scope prerequisites and a reviewed current window.
- **Completion criteria:** separate evidence for genuine source, account semantics,
  replay, initializer approval and operational behavior. Missing inputs stay blocked.

## A5 — Wave 4 GitHub closeout

- **Objective:** integrate only accepted W4 work and verify the actual merged tree.
- **Scope:** existing draft PR #55, focused reviewed commits, required CI/reviews,
  merge through GitHub and post-merge verification; preserve evidence revisions.
- **Dependencies:** A2/A4 and every W4 exit criterion, not just passing source tests.
- **Acceptance criteria:** full architecture/format/lint/types/API/browser/migration/
  wheel/installed-process/Linux/PostgreSQL gates pass; no unresolved safety review;
  bound artifacts correspond to tested and merged source.
- **Validation commands:** prepared-environment `make check`; migration/wheel/
  installed-process commands in TESTING and `.github/workflows/ci.yml`;
  `gh pr checks 55`; `gh run view <exact-revision-run-id>`; compare merged tree.
- **Completion criteria:** protected GitHub merge and verified post-merge results;
  update STATUS before starting W5. Never force-push or bypass required checks.

## B1 — restricted protocol implementation (Wave 5)

- **Objective:** implement the established E*TRADE request/recovery subset safely.
- **Scope:** live-disabled preview/place/cancel contracts and effect-specific retry
  semantics with injected transports; durable outbound/UNKNOWN recovery evidence.
- **Dependencies:** verified W4 merge and qualified provider contracts; no real effects.
- **Acceptance criteria:** v1 order subset only, durable claims before effects,
  no blind Place retry or synthetic inference of cancellation/nonacceptance;
  environment/account boundaries and independent adverse oracles pass.
- **Validation commands:** existing E*TRADE/attempt/recovery fixture families via
  sanitized pytest; standard runner, architecture, Ruff/types; new protocol tests
  must be included in the runner before acceptance.
- **Completion criteria:** reviewed disabled code and all established W5 protocol
  acceptance tests; no live transport activation inferred from implementation.

## B2 — operational controls and recovery (Wave 5)

- **Objective:** make command consumption, restart and recovery reliable.
- **Scope:** durable pause/halt/kill/cancel/flatten/re-arm semantics, auth/audit/read
  models, supervised ownership and backup/restore/alerts as scoped in W5.
- **Dependencies:** B1, W4 closure; route/host/access decisions before external effects.
- **Acceptance criteria:** lost acknowledgements, duplicate commands, stale roles,
  crash/restart, disk/DB failure, operator absence and clock/session loss fail
  safely; restoration preserves balances/UNKNOWN and never auto-rearms.
- **Validation commands:** selected operational-control, runtime-owner, persistence,
  process and simulated fault tests plus standard CI; no provider-facing drill
  until its scope is explicitly authorized.
- **Completion criteria:** recorded W5 fault/restore evidence, all exit gates and
  GitHub closeout; decompose these future lanes into small tasks at W5 entry.

## C1 — forward qualification and readiness dossier (Wave 6)

- **Objective:** measure a frozen candidate under actual observations and failures.
- **Scope:** separately labeled forward simulation and scoped protocol/read/preview
  qualification, measured resources/costs and owner readiness dossier.
- **Dependencies:** W3/W5 closed, qualified sources/accounts, owner suitability
  criteria, host/access/retention and alert/backup decisions.
- **Acceptance criteria:** at least four calendar weeks and 20 intended sessions
  plus required event/fault quotas from the existing roadmap; reproducible reports,
  honest prior-access/cost/data limits; no promised profitability.
- **Validation commands:** full standard and relevant process/fault regression;
  approved qualification runbook commands for the frozen revision only.
- **Completion criteria:** independently reviewed dossier and all W6 exit gates.
  Calendar duration alone cannot qualify the candidate.

## C2 — canary then personal operation (Waves 7–8)

- **Objective:** validate minimum-size execution and later an approved operating envelope.
- **Scope:** preserve the existing separate supervised canary and unattended-operation
  milestones; no implementation pass here can authorize orders or capital changes.
- **Dependencies:** C1 and explicit owner-approved account, instruments, window,
  amounts/risk/stop rules; a separate operating-envelope approval after the canary.
- **Acceptance criteria:** actual orders/fills/cancels reconcile to authoritative
  records within approved limits; stop/recovery/alert/backup behavior and measured
  maintenance costs meet the established wave requirements.
- **Validation commands:** offline regression and dossier verification first;
  exact operational commands must be reviewed with the owner-approved runbook.
- **Completion criteria:** canary evidence and separate W7 closeout, then W8
  acceptance under the explicitly approved envelope. Never infer either approval.
