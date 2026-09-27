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
| A2 — retained restore within original limits | Open: 2a9fc2c Linux worker and positive-proof gates fail | Existing W4 integration |
| A3 — genuine capture bridge contract and offline guards | Complete offline scope; genuine admission stays denied | Existing capture/clock/calendar boundaries |
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
  The a8b9229 full pass is preserved, but the same-source 02a8ee6 repeat failure
  reopens acceptance. Diagnose both restore cost and worker probe lifecycle before
  another exact-revision gate; a rerun alone is not a root-cause repair.
  A synthetic microbenchmark or a local restore alone is insufficient. If only a
  change to ownership/lease semantics could help, stop for the consequential decision.

### A2.1 — recurring restore and worker probe failures

- **Objective:** repair failures seen after the first full Linux pass.
- **Scope:** original retained restore cost and fixed-worker observation/probe
  failures; distinguish concrete reproduced defects from unproven CI hypotheses.
  The bounded diagnostic on `071dd5c` now identifies `TimeoutExpired` in the
  original `/bin/ps` observation at its 0.1-second bound. This is deliberate
  fail-closed handling, not an unhandled reap race. Inspect a bounded Linux-native
  observation path against the existing state/RSS, deadline and cleanup contract
  before implementation; do not increase the timeout or retry a failed observation.
- **Dependencies:** preserved run 36228369058 logs/profile and unchanged source.
- **Acceptance criteria:** original restore, restart/history and cleanup assertions
  pass under unchanged lease, operation, probe and process bounds. New adverse tests
  cover any lifecycle change; retain all original probes and ownership checks.
- **Validation commands:** TESTING's clean pytest command on the original retained
  outcome and fixed worker integration tests; focused new regressions, full static
  checks and exact-revision Linux/PostgreSQL CI. Coordinate expensive fixtures.
- **Completion criteria:** measured/reproduced root-cause repair, independent review
  and passing applicable gates; record previous pass and repeat failure separately.

### A2.2 — preserve semantic conversion exceptions and temporary lifetimes

- **Objective:** repair the earlier loop optimization's changed generator semantics.
- **Scope:** restore original recursive generator boundaries in `semantic_value`
  and add independent-oracle regressions; retain safe exact-builtin dispatch.
- **Dependencies:** reproduced getter, field-name and nested-reflection
  `StopIteration` mismatch against the literal original implementation.
- **Acceptance criteria:** original error type/cause/context, field/read order,
  temporary release and canonical bytes remain; top-level reflection errors
  remain outside the generator boundary. No failure is swallowed or converted
  into successful output.
- **Validation commands:** TESTING's clean pytest on `test_personal_semantic*`,
  `test_personal_contract_semantics.py` and `test_personal_canonical*`; original
  retained outcome, architecture/Ruff/mypy/API checks and exact-revision CI.
- **Completion criteria:** independently reviewed correction and applicable
  checks pass. Record any timing regression honestly; this correction does not
  itself repair the separate retained-restore performance failure.
  Source `6c0cdea` has 324 focused passes (49 new), an original local retained
  pass at 45.425 s, 19 worker/lifecycle passes and full static/API checks. The
  standard runner collected 4,848 cases. Published `7c73cd6` Linux restore failed
  at 60.118 s; worker shard 3 passed. The proof candidate is a separate A2.3 task.

### A2.3 — bounded factory proof pilot (approved; local gates pass, Linux acceptance fails)

- **Objective:** determine whether one repeated source fingerprint can be replaced
  by an equally bounded proof for a narrowly admitted, unchanged data projection.
- **Scope:** only the factory's original daily episode and the final resolved
  attempt-source fingerprint. See the [reviewed proposal](reviews/2026-09-26-autonomy/factory-verification-seal-proposal.md).
  All preceding owner/reference/outcome checks and fresh SQL/object/fence checks remain.
- **Dependencies:** explicit owner decision on the restricted effect-free data
  contract, then detailed proof/handshake review. The owner explicitly approved
  the bounded offline design on 2026-09-26. Current seals remain insufficient;
  the approval grants development scope, not proof validity or acceptance.
- **Acceptance criteria:** original owner/thread/operation boundaries; no copied,
  mutated, foreign or retired proof accepted; unsupported input follows original
  validation; no larger aggregate resource allowance; fresh observations and full
  final verification remain. A complete measured benefit must justify the change.
- **Validation commands:** TESTING's clean pytest on integration files
  `test_continuous_integrity_daily_episode.py`,
  `test_continuous_factory_scope_lifecycle.py`,
  `test_continuous_factory_integrity_result.py`,
  `test_continuous_factory_daily_handoff.py`,
  `test_continuous_factory_pending_handoff.py`,
  `test_continuous_runtime_attempt_sources.py`, and
  `test_continuous_attempt_fingerprint.py`; new independent adverse oracles;
  original retained/worker gates, full static checks and exact-revision CI.
- **Completion criteria:** reviewed approved contract and passing original gates
  under unchanged limits, or a documented rejection of the pilot. Neither design
  approval nor a passing microbenchmark closes A2 or authorizes live activity.
  The implemented candidate passes 100 new cases together and 177 original
  integration/worker cases; original unprofiled restore is 40.246 s locally.
  The complete observed spans model a 1.303 s saving with explicitly approximate
  prefix subtraction; they do not establish paired speedup or Linux acceptance.
  The final targeted mutation-boundary assertion passes separately in 204.63 s.
  [Source-bound evidence](reviews/2026-09-26-autonomy/factory-proof-local-validation.json)
  preserves the original caps, previous failures and measurement limits.
  Candidate `2a9fc2c` Linux finishes with 4,944 passed/four failed/no skips;
  both positive proof cases, original restore and worker restart fail. Its
  separate valid profile confirms private-route use and substantial preserved
  work, but itself expires. The pilot remains unaccepted; investigate only
  behavior-preserving pure costs before proposing any broader proof boundary.

### A2.4 — measure original daily identity traversal (offline; complete)

- **Objective:** measure actual work and shape at the two daily snapshot checks
  inside authenticated original factory borrows before any further proof decision.
- **Scope:** one opt-in original retained-outcome operation with bounded test-only
  observation; preserve every call, argument, guard, limit and assertion. The
  [decision assessment](reviews/2026-09-26-autonomy/daily-identity-proof-decision-assessment.md)
  specifies the seam and explicitly unapproved substitution proposal.
- **Dependencies:** completed failed Linux pilot evidence, reviewed temporary
  observer and passing finite mechanics tests before the genuine fixture run.
- **Acceptance criteria:** exact operation/thread/owner/episode/current/call-site
  attribution; completed versus failed spans; provisional tuple/seen-size metadata
  qualified only after original public validation returns; fixed bounded output
  with no object contents or retained graph; original cleanup and test exit visible.
  Existing proof usage and vector size are not a new proof's total resource charge.
- **Validation commands:** architecture first; finite observer selfchecks; then
  TESTING's clean pytest environment, with the reviewed temporary module directory
  on `PYTHONPATH`, `-p aqt_daily_identity_cost`, and the original
  `tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease`.
  Record the exact module hash, output environment, complete command and source hashes
  before releasing that one run. No repeat without a specific unresolved question.
- **Completion criteria:** reviewed valid source-bound measurement, or an explicit
  incomplete/failing result and its bounded next investigation. A viable broader
  daily proof still requires a separate owner decision before production substitution;
  a diagnostic pass does not close A2 or any failed Linux gate.
  The original test passed in 246.33 s with valid complete capture: 24 borrows,
  144 target checks, 2.1675 s builder work within 44.306 s execute. Independent
  review verifies hashes/counts/bounds. [Result assessment](reviews/2026-09-26-autonomy/daily-identity-original-result-assessment.md).
  No repeat or production extension is justified by this measurement alone. The
  [separate feasibility proposal](reviews/2026-09-26-autonomy/daily-identity-feasibility-proposal.md)
  has explicit separate owner approval for temporary feasibility work only.
  Continue it under A2.5 and preserve existing CI diagnosis.


### A2.5 — separate daily identity feasibility (first layout rejected)

- **Objective:** determine whether a faithful all-field daily identity proof can
  fit alongside the attempt proof and save enough complete work to justify a
  later production proposal; rejection is a valid result.
- **Scope:** temporary source-owned synthetic data/behavior prototype, literal
  original identity oracle and finite adverse comparisons. Start with the joint
  resource screen; no production wiring or larger framework.
- **Dependencies:** completed A2.4 and explicit owner approval of the
  [feasibility proposal](reviews/2026-09-26-autonomy/daily-identity-feasibility-proposal.md).
  Independent mechanics review precedes every released genuine fixture.
- **Acceptance criteria:** model every daily field and original identity traversal
  role; distinguish unsupported shapes, aliases/cycles and opaque leaves. Charge
  all added data/behavior/context/construction state jointly under the original
  caps. No mutation authority, extra original validations, source effects or
  changed public methods. Preserve failure and uncertain results honestly.
- **Validation commands:** architecture first; the reviewed temporary mechanics
  suite; one explicitly selected existing source-owned fixture only after its
  command, plugin hash and output bounds are recorded. No parallel heavy runs.
  If the resource screen rejects, no complete-cost fixture is warranted.
- **Completion criteria:** source-bound independently reviewed feasibility or
  documented bounded rejection. Only a fitting faithful prototype proceeds to
  full construction/use/retirement cost comparisons and adverse tests. This
  cannot close A2 or authorize production daily-proof substitution.
  **Outcome:** the established per-node layout has a source-bound joint lower
  bound of 16,743 containers/139,661 bindings, exceeding the original caps by
  359/8,589 before overhead. [Independent verdict](reviews/2026-09-26-autonomy/daily-identity-node-screen-independent-review.md).
  All 37 scalar mechanics checks pass; no further fixture, graph/behavior proof
  or timing work is warranted for this layout. Other representations remain
  untested, not proved impossible. The completed follow-up CI has 4,964 passed,
  three failed and no skips; the diagnostic also fails. Preserve these A2 failures.
  A2.6 has separate owner approval for bounded offline design and feasibility only.

### A2.6 — bounded pre-lease handoff study (complete; CLOCK candidate rejected)

- **Objective:** determine whether bounded provisional historical preparation can
  reduce lease-held work without changing the original complete validation or limits.
- **Scope:** the [concrete proposed study](reviews/2026-09-26-autonomy/prelease-restoration-decision-proposal.md),
  restricted to an existing HALTED account/inactive head. No production implementation
  or reuse of old receipts under a new fence.
- **Dependencies:** failed original Linux gates, rejected A2.5 layout and the
  separate 2026-09-27 owner approval for this study. Production adoption requires
  a further decision; earlier attempt/daily approvals are not expanded.
- **Acceptance criteria:** first specify a finite useful pure-work subset and exact
  acquisition-owned delta; preserve every other captured row/object dependency,
  fresh SQL/object/fence/control/terminal observation and original timer/resource cap.
  Resolve original before/after transition ownership and race/ABA questions before
  any prototype can issue qualified results. Record changed failure ordering.
- **Validation commands:** architecture and finite mechanics first; a reviewed,
  original-only observation may measure the proposed subset before qualification.
  A reuse prototype or candidate experiment requires the ownership/resource/cost
  model to survive first. Record literal commands/source hashes for either path.
  Existing retained/worker acceptance
  remains required for any later separately approved production adoption.
- **Completion criteria:** independently reviewed finite feasibility or documented
  rejection. Do not run a heavy fixture before a concrete plan, add broad lease-table
  exclusions, move timers to hide work, or treat faster execute time as total benefit.
  **Checkpoint:** the [acquisition study](reviews/2026-09-26-autonomy/prelease-acquisition-witness-study.md)
  identifies finite transition facts but no implemented post-commit cleanup protocol.
  The [pure-work study](reviews/2026-09-26-autonomy/prelease-pure-work-study.md)
  narrows investigation to discarded typed clock-journal validation. Same codec
  identity or one cached hint dictionary cannot prove its behavior unchanged.
  The source-inventory checkpoint and one reviewed original-only observation
  are complete. Cold-path qualification and total binding accounting remain
  intentionally unfinished after the candidate's economic rejection.
  The unchanged original test passed in 242.12 s with
  all 61 CLOCK validators returning. Direct codec work totals 8.607 ms; only
  8.204 ms is repeated successful work across three observational digest groups,
  0.0186% of the 44.155 s execute. [Bound result](reviews/2026-09-26-autonomy/prelease-clock-original-result.json).
  Reject this specific candidate as immaterial before adding acquisition,
  behavior, comparison and retirement costs. No substitution, witness prototype,
  net speedup, full resource fit or Linux acceptance is established. Other designs
  remain untested; missing data alone was not the reason for rejection.
  Do not repeat this observation or expand to other schemas without a concrete
  new source-backed question. A2/A2.1 remain open; no safe material repair is established.


### A2.7 — exact primitive contract validation (local gates pass; Linux pending)

- **Objective:** remove unnecessary typing introspection for already matching
  exact primitive fields without changing contract admission or constructors.
- **Scope:** only the existing `_check_type` helper's exact `str`, `int`, `bool`
  and `NoneType` success path. Preserve the 65,536-character text bound and
  original mismatch, alias, union, literal, tuple, subclass and other-type paths.
  No cache, new proof, skipped constructor, lease or resource change.
- **Dependencies:** source-bound 52-case literal-original prototype, independent
  source review, and existing codec primitive-dispatch precedent. This ordinary
  implementation change does not expand the rejected A2.5/A2.6 designs.
- **Acceptance criteria:** exact types and errors, string-bound/name formatting,
  compound recursion, custom annotation/metaclass observations and constructor
  order match the original oracle. Financial/codec/factory behavior remains.
- **Validation commands:** TESTING's clean pytest on
  `tests/unit/test_personal_contract_type_dispatch.py`, contract/semantic/canonical/
  codec families and affected factory proof/worker regressions; architecture,
  Ruff/format, mypy and API drift checks. Record one original retained restore
  after focused gates; inspect exact-revision Linux acceptance separately.
- **Completion criteria:** independent review and applicable compatibility/static/
  integration gates pass. Finite primitive timings justify this small change,
  not a full-restore speedup or closure of A2's failed Linux acceptance.
  [Local checkpoint](reviews/2026-09-26-autonomy/contract-primitive-local-validation.json):
  83 new oracle cases, 744 existing unit cases, unchanged retained restore/cleanup
  and 19 worker/lifecycle cases pass. The initial integration selection's two
  class-cache pollution failures are preserved and repaired at three test-only
  copy sites; five focused unit and five ordered integration cases pass afterward.


### A2.8 — bounded native Linux child observations (local gates pass; Linux pending)

- **Objective:** remove the per-observation subprocess identified by the concrete
  Linux worker timeout while preserving current state/RSS and failure policy.
- **Scope:** a bounded Linux `/proc/<owned-pid>/status` reader behind the existing
  observer; retain the original ps helper on other platforms. No retries,
  fallback after Linux failure, background observer, reaping or larger timeout.
- **Dependencies:** source-bound `071dd5c` worker failure, reviewed procps/kernel
  field semantics, existing bounded procfs precedent and independent design review.
  A2.7's local source checkpoint is committed as `9f9cd72` before this change.
- **Acceptance criteria:** original accepted state codes, exact current RSS and
  explicit no-memory representation; strict PID/field/size checks; original
  deadline including successful parsing/close; primary failure precedence and
  complete descriptor cleanup. Sole-waiter/group/receipt rules remain unchanged.
- **Validation commands:** TESTING's clean pytest on new
  `test_continuous_linux_observation.py`, existing process/terminal/diagnostic
  tests, original fixed-worker restart and lifecycle integration; architecture,
  Ruff/format, mypy and exact-revision Linux CI, including actual procfs cases.
- **Completion criteria:** independent code/test review and applicable gates pass.
  Mocked or Darwin passes cannot qualify Linux procfs. This repair does not close
  the separate retained-history lease failure or establish deadline immunity.
  [Local checkpoint](reviews/2026-09-26-autonomy/linux-native-local-validation.json):
  188 new cases pass with three actual-Linux skips, 114 existing process cases
  and 19 original worker/lifecycle cases pass, as do static/API checks.

## A3 — genuine capture bridge contract and offline guards

The [concrete contract investigation](reviews/2026-09-26-autonomy/capture-bridge-contract.md)
identifies source selection, retained measured-clock ownership and original
transport/source ownership as separate offline slices. A3.1 now validates mechanical
selection using existing records. The implemented offline components are described
below; genuine publication remains denied and further source integration belongs to A4.

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

### A3.1 — match existing Tiingo selection records (validated offline and in CI)

- **Objective:** reject a daily capture request inconsistent with the selected
  acquisition profile, authorization or pinned calendar before any effects.
- **Scope:** optional pure `require_tiingo_capture_selection` matcher using existing
  bounded records and calendar conventions. It returns `None`, creates no source
  token and leaves genuine capture admission unchanged.
- **Dependencies:** existing `ForwardCaptureRequest`, Tiingo acquisition/authorization
  and pinned-calendar records, bounded codecs and research-calendar binding helper.
- **Acceptance criteria:** revalidate nested content, review chronology, symbol/data
  scope and request-window boundaries; preserve authorization effective dates as
  data coverage. Equal reconstructed content can match but proves no original
  ownership or rights provenance. A genuine-shaped match still reaches the existing
  collector denial with zero clock, transport or artifact effects.
- **Validation commands:** TESTING's clean environment with `$AQT_PYTHON -B -m pytest
  -q -p no:cacheprovider tests/unit/test_personal_tiingo_capture_selection.py
  tests/unit/test_personal_capture_calendar_binding.py tests/unit/test_tiingo_eod_capture.py
  tests/unit/test_personal_forward_capture.py`; architecture, Ruff, mypy and diff checks.
- **Completion criteria:** 216 focused cases pass (49 new), static checks and
  independent review pass, and the [source-bound evidence](reviews/2026-09-26-autonomy/tiingo-selection-evidence.json)
  records the mechanical limits. Local completion and the full a8b9229 Linux/PostgreSQL CI pass are recorded;
  source qualification remains separate.

### A3.2a — retain the original clock conversion (validated offline and in CI)

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
  Full a8b9229 Linux/PostgreSQL CI also passed; host qualification remains separate.

### A3.2b — retain measured health history (validated offline and in CI)

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
  This component alone cannot satisfy actual host qualification or A4 admission.

### A3.3a — preserve Tiingo binding and deadline through cleanup (validated offline and in CI)

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
  The next missing input is the supervised Mac's measured-time source and a
  non-secret qualification record; then review the genuine producer contract in
  [the source boundary](reviews/2026-09-26-autonomy/capture-bridge-contract.md).
  Preserve [existing rights/retention approvals](reviews/2026-09-10-wave4/recovery-2026-09-20.md).
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
  The current repair PR #56 targets `codex/personal-v1-w4-integration`; PR #55
  carries that W4 branch to `main`. Inspect each applicable exact revision and
  its own checks; a #56 pass cannot close missing W4 gates or authorize either merge.
- **Dependencies:** A2/A4 and every W4 exit criterion, not just passing source tests.
- **Acceptance criteria:** full architecture/format/lint/types/API/browser/migration/
  wheel/installed-process/Linux/PostgreSQL gates pass; no unresolved safety review;
  bound artifacts correspond to tested and merged source.
- **Validation commands:** prepared-environment `make check`; migration/wheel/
  installed-process commands in TESTING and `.github/workflows/ci.yml`;
  `gh pr checks 56`; `gh pr checks 55`; `gh run view <exact-revision-run-id>`;
  compare merged tree only after authorized closeout.
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
