# Wave 3 evaluation proposal

Historical lane design record. The integrated behavior and acceptance status are recorded in [the canonical plan](../IMPLEMENTATION_PLAN.md#18-current-wave-3-handoff), [the research runbook](../runbooks/personal-v1-research.md) and [the Wave 3 evidence index](../reviews/2026-09-09-wave3/README.md). Proposal-era permissions, names and open questions below are retained as design history.

Status: interface proposal only, written against merged W2 `6ea218addaa38d1c36c69b6a7ffbe564d701f834`. The orchestrator's W3 authorization supersedes this checkout's older W2-closeout handoff. No execution, data acquisition, persistence activation or implementation change is implied by this document.

## Recommended boundary

Add a pure, bounded evaluation protocol around the existing W2 `EngineInputs`, `run_causal_engine`, `PersonalAccounting`, `ReferenceStrategy` and `RunReport`. B prepares one exact trial and derives comparison/admission facts. A/root execute it through the canonical supervised runner and retain its attempts/artifacts. B does not own another queue, worker, subprocess runner, engine, ledger or report calculator.

Use the existing `buy_hold` and `trend_sma` configurations. Their lookback/allocation/rebalance parameters are declared inputs, not learned parameters. An explicit `identity-no-fit/1` artifact binds the scoped training rows, reference configuration and transform version, with empty fitted parameters. Do not add an unused diagnostic scaler to claim learned-model qualification. Learned transformations remain unsupported until an actual consumer and train-only fitting tests exist.

No profitability threshold is a software default. A descriptive comparison with `eligibility=not_assessed`, no selected candidate, or `no_eligible_candidate` is a successful protocol result. Completed economic calculations, owner suitability, historical-vintage quality and trading authorization remain separate fields.

## Existing contracts and gaps

| Existing source | Reusable behavior | Boundary to preserve |
|---|---|---|
| [`experiment_registry.py`](../../packages/domain/experiment_registry.py), `EvaluationSegment`/`ExperimentEvaluationPlan`, lines 510–611 | Immutable configuration/schema identities; chronological train/validation/test declarations and explicit purge/embargo values | Its plan pins one replay digest; it is an older fixture declaration, not a W2 daily-session evaluator |
| Same module, `FrozenPromotionCriteria`, line 653 | Predeclared criteria, selection rule, multiple-testing disclosure and attempt budget | It requires nonempty numeric criteria. Do not invent a criterion merely to construct this historical type |
| [`experiment_governance.py`](../../packages/domain/experiment_governance.py), `ExperimentGovernanceFamily`, line 621; `ExperimentAttempt`, line 800; snapshot, line 1731 | Distinct scoped train/validation/test commitments; stable budget-counted attempts; append-only queued/running/completed/failed/canceled/abandoned history and exact configuration validation | Completion is specifically a certified rolling-close target transcript, not an economic `RunReport` |
| [`feature.py`](../../packages/domain/feature.py), `FeatureArtifact`, lines 375–391 | Explicit lineage and immutable no-fit state | Constructor intentionally rejects nonempty fitted parameters and training-window pins for the historical feature. Preserve this contract |
| [`feature_replay.py`](../../packages/domain/feature_replay.py), batch/incremental certification; [`feature_target_replay.py`](../../packages/domain/feature_target_replay.py), availability-prefix selection | Independent parity examples; missing/incomplete input resets; delayed availability cannot select future source observations | Fixed two-close reference and older authenticated replay vocabulary are not the W2 daily engine's feature implementation |
| [`SqlExperimentGovernance`](../../packages/persistence/experiment_governance.py), line 1319 | Atomic registration, immutable lifecycle/audit and idempotent mutation patterns | A/root own durable W3 jobs and the root owns migrations/codecs; do not reinterpret old terminal evidence or activate the old schema from B |
| [ADR 0037](../adr/0037-configuration-bound-governed-segment-evaluation.md) | Exact attempted configuration must affect its target transcript; declared parameters cannot be ignored | Explicitly does not claim a backtest, P&L, worker scheduler or criteria adjudication |

The additive W3 records should use root-owned `ContractRecord` DTOs and version pins. Historical pure proofs, SQL rows and semantic hashes remain unchanged. Root can reuse stable configuration validation helpers where the accepted reference vocabulary fits; new daily-reference identity must not claim the older feature-target runtime.

## Shared artifact proposal for root freeze

Names below are proposed shared DTOs, not permission for B to edit the shared contracts.

| Artifact | Required immutable content |
|---|---|
| `EvaluationProtocol` | Version, hypothesis/description, creator and recorded time, dataset/archive identity and data class/availability assumptions, instrument/calendar identities, explicit folds, allowed reference configurations, complete cost matrix, trial budget, reset/warmup policy, prior-access declaration, descriptive-only or owner-criteria policy, source/numeric/report pins |
| `EvaluationFold` | ID; sorted exact eligible training, validation and final-test session sets; per-segment warmup session sets; independent reset mode; explicit fit knowledge cutoff; declared purge/embargo policy; actual requested/scored bounds and coverage limitations |
| `PriorAccessDeclaration` | Recorded time/actor, affected periods/dataset revisions, `known_accessed`/`unknown`/prospective-forward description and evidence references. Records an assertion and local access history; never turns a flag or digest into proof of an untouched historical period |
| `TrainingSlice` | Fold ID, training sessions, allowed instruments, exact selected daily-row/event IDs and causal content hashes, modeled/observed knowledge cutoff, missingness and training-only content digest. No validation/test row collection is supplied to the fit constructor |
| `ReferenceFitArtifact` | `identity-no-fit/1`, exact `ReferenceConfiguration`, training-slice digest/cutoff, source/transform version, empty fitted-parameter tuple, immutable parameter/configuration digest and explicit `learned_transform_supported=false` |
| `EvaluationTrial` | Protocol/fold/configuration/fit/cost/segment IDs and hashes, registered sequence/time, attempt budget identity, expected scored/warmup sessions and report convention pins. A separate durable admission record binds its prepared engine-input/run identity before dispatch; do not create a circular trial/run hash |
| `TrialAttemptFact` | Stable logical trial ID, new attempt ID/number, predecessor lifecycle event, queued/running/terminal event, owner worker claim generation, actual recorded times, failure/cancellation reason, optional exact result/artifact hash; A owns durable storage/claim checks |
| `TrialOutcome` | Trial/attempt/result/report hashes, exact observed status and metric coverage, data/availability/access limitations, cost-model labels, current source pins and reasons; never manufacture a report for an attempt that produced none |
| `EvaluationComparison` | Protocol ID and the full declared trial inventory joined to all attempts/outcomes; aligned folds/segments/cost profiles, benchmark identity, comparable/noncomparable reasons, missing/failed/canceled rows, optional explicit owner-criteria evaluation, no automatic promotion |

Keep the whole archive/run identity separate from the training-only content/configuration digest. Mutating validation/test content legitimately changes the enclosing archive/run hash; it must not change fitted parameters, training-slice content identity or earlier causal decisions. Tests compare the causal fields, not unrelated enclosing artifact IDs.

## Proposed B API

```python
validate_protocol(protocol, *, calendar, available_sessions) -> ValidatedEvaluation

training_slice(protocol, fold_id, *, daily_events) -> TrainingSlice
freeze_reference_fit(training: TrainingSlice, configuration: ReferenceConfiguration)
    -> ReferenceFitArtifact

expand_trials(protocol, *, fits) -> tuple[EvaluationTrial, ...]

prepare_trial_inputs(
    *, protocol, trial, fit, source: EngineInputs
) -> EngineInputs

compare_trials(protocol, *, trial_inventory, attempts, outcomes)
    -> EvaluationComparison
```

`prepare_trial_inputs` is a pure adapter. It verifies exact trial/fit/plan membership and installs additive protocol/fold/trial/fit/cost/access pins; it does not register, run or publish a trial. A/root register the planned input identity before execution. The trial identity derives from the declared protocol/configuration/fold/cost/fit, while the prepared RunSpec subsequently binds that trial. A's separate job/admission record binds both; neither semantic record recursively hashes the other. The same reference configuration actually reaches the W2 engine; no ignored fit/configuration fields distinguish otherwise identical runs.

The source is the existing root-owned W2 research input producer's immutable output, after A has loaded an explicit registered dataset. Retain original event IDs, economic/knowledge timestamps, revision lineage, raw/source hashes and price bases. Select the fold's allowed warmup/scored sessions; keep required causal predecessors or reject an unsupported dependency boundary. Do not renumber source facts or silently admit out-of-scope accounting/actions. Initial W3 daily-price/benchmark/open-proxy input scope is explicit; qualified action facts continue through W2's existing path, and unsupported imported action candidates retain their current rejection.

Every independent trial starts with empty `AccountingState`, fresh strategy state, no orders/positions/fitted state carried from another segment, and the protocol's declared initial funding. Use the supplied settlement-business calendar unchanged. Engine calendars/scheduling, journal/fees/reserves and report calculations remain W2-owned.

## Chronology, warmup and scoring

Defaults remain train 2010–2018, validation 2019–2022, final historical window 2023–2025, selected from actual eligible exchange sessions. These requested dates do not create absent licensed data or establish prior non-access. A dataset with insufficient coverage produces an explicit unavailable/rejected plan or a separately preregistered narrowed study; the five-session W1 sample cannot demonstrate the default long study.

Use 252 eligible prior sessions of warmup by default. Warmup may reuse a prior segment's price history, but it contributes no scored returns, orders, account carry or refitting. The supplied input grid governs holidays; missing expected sessions are not omitted to manufacture continuity. Explicit short synthetic test protocols may use smaller warmup/lookback and must retain their engineering-only labels.

Within each trial chain, training ends before validation starts and validation ends before the final window. Across independent folds, scored windows used in one aggregate must be disjoint; training windows may overlap or expand and a prior scored observation may legitimately enter a later fold's training window if the protocol declared that progression. Do not concatenate different candidate/cost scenarios as if they were one disjoint performance series. No continuous-carry protocol or automatic fold generator is required initially.

Fit access is restricted to declared training events known by the fit cutoff. A price dated in training but becoming available after that cutoff is unavailable to the fit. Final-window data may be excluded from the train/fitting view even when physically present in a local archive. That boundary controls computation; it does not establish the owner's previous knowledge of the archive.

Purge/embargo fields must describe an actually applied boundary. Fixed W2 reference features have no forward label/training target, so an explicit zero purge/embargo is appropriate; unsupported nonzero or learned-label protocols must reject rather than advertise protection that is not applied.

## Frozen costs and comparison

| Cost trial | Adverse slippage per side | Fee per share |
|---|---:|---:|
| base / 1x | 5 bps | USD 0.01 |
| 2x base | 10 bps | USD 0.02 |
| 3x base | 15 bps | USD 0.03 |
| adverse | 20 bps | USD 0.02 |

`base` and `1x` are two labels for one identical scenario, not duplicated independent evidence. Each of these four distinct scenarios is a separately preregistered trial for every declared candidate/segment/fold. Costs are execution-model assumptions, not actual broker pricing. Keep exact Decimal values; copy the trial's fee into the actual reference strategy's fee-aware sizing, execution policy and relevant risk configuration through the canonical runner. Preserve adverse price rounding and all W2 capacity/rejection behavior; do not require monotonic P&L across stresses because changed sizing, execution rejection or risk halts can change the path.

Compare like-for-like scored sessions, reset mode, data vintage, currency, metrics conventions and flow clock. Missing/undefined metrics retain reasons; no dropping failed trials, filling missing values with zero or sorting null metrics as losses. Every attempt contributes to the disclosed search history/budget, including cancellation, failure and abandoned-worker recovery. A retry is a new attempt attached to the same logical trial, not a replacement history row. Changed configurations or study boundaries require a new immutable registration and updated prior-access disclosure.

Preserve W2's explicitly analytical SPY total-return-unit comparator (fractional units, zero analytical fees) and idle cash. Do not add raw dividends again or describe that series as cost-matched execution. To display a cost-matched executable control, use the actual W2 `buy_hold` reference as another declared candidate under each of the same four cost policies, with the same risk/allocation constraints. Show its allocation distinction from the analytical comparator. Root should freeze this labeling so the older scope-default benchmark phrase is not misrepresented by a free analytical series.

## Independent tests and actual-run acceptance

1. Reject unsorted/duplicated/out-of-calendar sessions, train/validation/test overlap, duplicated aggregate scored sessions, future fit knowledge, unsupported carry and unapplied purge/embargo. Verify year boundaries and supplied-calendar holidays without fetching a new calendar.
2. Exact no-fit artifact has empty parameters and the actual W2 reference configuration. Alter validation/test prices, revisions, timestamps and data availability: training-slice/configuration digests and earlier causal engine decisions stay unchanged. Alter an eligible training row: training lineage changes. Do not claim a learned transform was fitted.
3. Run actual W2 engine trials independently with the same declared funding. Prove fresh ledger/strategy/order state; warmup emits no scored orders/returns; missing required feature history resets; no decisions or marks from a later segment enter an earlier segment.
4. Use deterministic fixed candidate/configuration grids; ensure a configuration change either affects its intended decisions or is explicitly an equivalent/no-effect trial, never silently ignored. Compare cost profiles using actual execution rows/fees and model pins, with independent Decimal/rational arithmetic for sampled fills.
5. For both `buy_hold` and `trend_sma`, execute all four distinct cost profiles and retain report hashes/outcomes. Base and 1x identity is exact. Test an adverse gap/risk rejection without asserting that higher costs must produce a lower terminal NAV.
6. Verify protocol/fold/configuration/fit/cost/trial hash mismatch rejection, exact idempotence and conflicting duplicate rejection. Pure comparison tests retain queued, canceled, failed and abandoned attempts, retry lineage and absent-artifact reasons. A/root test the durable preregistration/claim/terminal-publication transactions and restart boundaries.
7. Known accessed and unknown historical periods cannot become `untouched` from a new run, archive copy, hash or family name. A changed post-access protocol remains retrospective. Without owner suitability criteria, return descriptive comparisons and no qualified candidate even if every economic metric is positive.
8. Compare exact report metrics and metric coverage rather than recomputing a second ledger. Missing benchmark boundaries remain undefined; cost-matched buy/hold and analytical SPY remain separate. Sample one result with independent arithmetic and preserve all disclosures through A/root exports/UI.

## Exclusive file request and root decisions

Requested B implementation allowlist after shared interfaces freeze:

- New `packages/domain/personal_evaluation.py`: pure chronology, identity/no-fit, cost matrix, trial inventory and comparison/admission rules.
- New `packages/application/evaluation_inputs.py`: pure one-trial `EngineInputs` preparation; no runner or persistence.
- New `tests/unit/test_personal_evaluation.py`.
- New `tests/integration/test_personal_evaluation_engine.py`: actual W2 engine boundary/cost trials using repository-owned fixtures.
- This proposal only under `docs/proposals/`.

Root retains shared DTOs/version contracts, schemas/migrations, API/composition, input serialization, canonical plan and UI contract. A retains jobs/catalog/artifact persistence, supervisor and the single execution path. Existing governance/registry/feature reducers, W0 bytes, W2 engine/accounting/report modules and fixtures are read-only to B unless a separately reviewed concrete defect requires ownership transfer.

Decisions to freeze: the shared DTO names and A preregistration→prepared-input handoff; exact archive/fold row-slicing contract and unsupported action boundary; explicit retrospective/unknown access defaults; cost-matched reference versus analytical benchmark labeling; the bounded declared candidate/fold grid and trial budget. Owner suitability thresholds remain absent until the owner supplies them. No data purchase, provider call, claimed acquired holdout, learned-model support, promotion or trading authority follows from W3 software acceptance.
