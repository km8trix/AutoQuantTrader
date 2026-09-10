# Wave 2 lane A — causal engine and daily risk interface proposal

Status: proposal for root review; no interface is frozen and no code is implemented by this artifact. Base: `ec63ca793ed4fe8a68397dc752000e102741da59`, branch `codex/personal-v1-w2-engine`. The active root plan section 17 and Wave 2 kickoff authorize this bounded work; the checkout's older W1-pending handoff is historical. W0 contract bytes remain unchanged. Apply `personal-v1/account-eligibility/2` and `cash-funded-long-only/1`: permitted account privileges never supply financing or order authority.

## 1. Existing seams and proposed ownership

| Existing seam inspected | Reuse and compatibility boundary |
|---|---|
| `packages/domain/strategy_replay.py:363` | `replay_strategy_callbacks` copies initialization positions once. Preserve it as a pure legacy transcript helper; the product must invoke callbacks from the new application loop with a new snapshot each time. Do not import the application engine from domain. Reuse the strategy identity/successor checks after root approves their additive shared form. |
| `packages/domain/strategy.py` and `strategy_state.py` | Preserve exact legacy `ReadOnlyStrategyContext`, `StrategyTransition`, trigger binding, state generation and predecessor validation. Add a versioned daily protocol because the legacy context has no cash, commitments or account revision. Keep mutable account state inaccessible to strategies. |
| `packages/domain/portfolio.py:70` | Existing target conversion only subtracts filled holdings. Add a daily conversion function bound to the complete account/commitment snapshot; preserve the legacy function and its digest contract. Reuse `PositionTarget`'s whole-share/Decimal checks. |
| `packages/domain/batch_risk.py:1626` | Reuse exact capacity/reserve mathematics and all-or-none semantics. Its same-session/five-minute-price checks, absolute limits, common per-share buffer and attested legacy snapshot cannot be used wholesale at 20:00. Do not fake an intraday price/session, extend its TTL or weaken existing validators. |
| `packages/domain/risk.py` | Preserve legacy authorization/consumption and its callers. The new policy returns simulation decision evidence, not legacy executable broker authorizations. |
| `packages/domain/research_dataset.py`, `packages/application/research_dataset.py` | Preserve W1 classes, content IDs, nullable factual times, raw/adjusted distinction and exclusions. Root converts admitted data to event inputs; no conversion through `RawBar`/`MarketEvent` with invented publication times. W1 replay selects input rows and is not an economic loop. |
| `packages/domain/feature.py`, `feature_target.py` | Existing feature contract explicitly describes raw PIT closes and a legacy replay manifest. Reuse pure arithmetic where suitable, but do not relabel W1 current-vintage adjusted closes as that feature contract. Daily feature basis and version need their own pin. |
| `packages/backtest/simulated_broker.py:843` | Existing simulator requires intraday intent creation and strictly later source times. B adapts useful execution/reducer behavior to the daily port; A never supplies an entire future market tape to a broker call. Preserve legacy tests. |

Proposed implementation allowlist after freeze: A owns new `packages/application/causal_engine.py`, new `packages/domain/daily_risk.py`, an additive daily converter in `packages/domain/portfolio.py`, and focused `tests/unit/test_causal_engine.py`, `tests/unit/test_daily_risk.py`, `tests/unit/test_daily_target_conversion.py`. Changes to `batch_risk.py` would be limited to extracting shared exact arithmetic with legacy-output equivalence tests, only if needed; copying its full evaluator is not proposed. No change to `strategy_replay.py` is necessary for the initial implementation.

Root owns new shared definitions, proposed in `packages/domain/engine_contracts.py` and `packages/domain/daily_strategy.py`, plus source conversion, strategy implementations, shared fixtures, output/report DTOs, composition, golden cutover and any changes to existing `models.py`, `decision.py`, `strategy.py`, `strategy_state.py`, `research_dataset.py` or calendars. B owns the accounting/execution implementation behind the transition port. C supplies one shared pure flow-neutral wealth/risk producer used by reporting and risk evidence; A does not duplicate NAV, FIFO, return or report calculations. These filenames are proposals, not extra write authority.

## 2. Typed identity and run input

All definitions below are frozen dataclasses or closed enums/unions. Collections are immutable, sorted tuples; IDs are bounded text; hashes are lowercase SHA-256; timestamps are aware UTC; prices/amounts are exact `Decimal`, never floats. Canonical serialization uses the existing canonical and Decimal policy. Unsupported enum/version values reject at admission. `...` below denotes a body to implement, not unspecified fields.

```python
@dataclass(frozen=True, slots=True)
class VersionPin:
    name: str
    version: str
    sha256: str

@dataclass(frozen=True, slots=True)
class DatasetPin:
    dataset_id: str
    manifest_sha256: str
    data_class: ResearchDataClass
    availability_mode: Literal["simulated_policy", "recorded_observation"]
    availability_policy: VersionPin
    revision_policy: VersionPin
    feature_price_basis: Literal["raw_close", "adjusted_close"]
    instruments: tuple[tuple[str, str], ...]  # instrument_id, current symbol
    calendar: VersionPin
    actions: VersionPin
    exclusions: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class DailySchedule:
    timezone: str
    decision_local: time                 # 20:00
    missing_cutoff_local: time           # 09:00 next regular session
    execution_start_local: time          # 09:35 for forward policy
    execution_end_local: time            # 09:40, exclusive
    policy: VersionPin

@dataclass(frozen=True, slots=True)
class EvaluationSpec:
    fold_id: str
    warmup_sessions: tuple[date, ...]
    scored_sessions: tuple[date, ...]
    reset_mode: Literal["independent"]    # carry unsupported in initial W2
    fitted_state_sha256: str             # explicit no-fit identity allowed
    partition_manifest_sha256: str
    prior_access_label: str

@dataclass(frozen=True, slots=True)
class RunSpec:
    schema_version: Literal["personal-run/1"]
    account_namespace: str               # synthetic logical account, no broker ID
    environment: Literal["historical_simulation"]
    account_privileges: Literal["CASH", "MARGIN"]
    eligibility_amendment: str
    financing_policy: str
    dataset: DatasetPin
    strategy: VersionPin
    strategy_configuration_json: bytes   # validated canonical bounded JSON
    strategy_configuration_sha256: str
    engine: VersionPin
    reducers: tuple[VersionPin, ...]
    daily_risk: DailyRiskPolicy
    initial_account: InitialAccountSpec  # root/B: exact cash/lots/events pin
    initial_strategy_state_sha256: str
    schedule: DailySchedule
    execution_model: VersionPin
    cost_model: VersionPin
    settlement_model: VersionPin
    settlement_calendar: VersionPin      # distinct from exchange calendar
    benchmark: VersionPin
    evaluation: EvaluationSpec
    source_revision: str
    dirty_patch_sha256: str | None
    python_version: str
    dependency_lock_sha256: str
    numeric_policy: VersionPin
    tzdata: VersionPin
    rng_algorithm: str | None
    seed: int | None
    max_events: int
    max_output_bytes: int
    max_wall_seconds: int
    max_memory_bytes: int
    max_cpu_cores: int
    limitations: tuple[str, ...]

def run_identity(spec: RunSpec) -> str: ...
```

Model pins bind canonical parameter content as well as code/version; a name alone is insufficient. Root's initial-account definition must distinguish synthetic opening capital from later external contributions and bind any starting lots/commitments. Recommend initial W2 admission support the frozen empty synthetic account and reject carry/nonempty initial orders until explicitly tested. Pin initialization state via a deterministic initialization result or a separately named no-prior-state sentinel, without a circular dependency on run ID.

`run_identity = "run-" + SHA256(canonical RunSpec)`. Changing any semantic input, source revision/dirty patch, cost, dataset, seed, allocation, schedule, action/settlement calendar, fold or limitation produces a new identity. Attempt/job IDs, machine paths, receipt-of-running time and completion time are outside it. RNG fields must both be null for deterministic models; a seed without a supported algorithm rejects. W2 supports historical simulation only; the shape does not enable forward/live drivers.

Root supplies `EngineInputs(spec, exchange_calendar, admitted_events)`; their actual immutable contents must match all pins before the loop starts. No credentials, network client or provider account object belongs in these inputs. Budgets are checked before work where counts/sizes are known; a stop/budget failure retains an incomplete trace and never publishes a successful report.

## 3. Event and frontier contract

```python
@dataclass(frozen=True, slots=True)
class ObservationProvenance:
    data_class: ResearchDataClass
    source_namespace: str
    normalized_payload_sha256: str
    raw_object_sha256: str | None
    vendor_published_at: datetime | None
    observed_available_at: datetime | None
    simulated_policy: VersionPin | None
    simulated_available_at: datetime | None
    unknown_reasons: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class SourceSequence:
    scope: str
    sequence: int

@dataclass(frozen=True, slots=True)
class EngineEvent:
    event_id: str
    kind: EventKind
    economic_at: datetime
    knowledge_at: datetime
    source_namespace: str
    source_sequence: SourceSequence | None
    predecessor_ids: tuple[str, ...]
    revision_id: str | None
    replaces_revision_id: str | None
    provenance: ObservationProvenance
    payload: EnginePayload
    payload_sha256: str

@dataclass(frozen=True, slots=True)
class ReductionPoint:
    frontier_sequence: int
    reduction_sequence: int
    knowledge_at: datetime
    stage: int
    callback_sequence: int | None

EnginePayload = (
    DailyMarketRevision | SessionScheduleEvent | ExecutionObservation
    | CanonicalEconomicInput | LocalCommitmentCommand | ControlObservation
)
```

Root freezes the closed payload union with B. `DailyMarketRevision` binds instrument/session and the complete `DailyResearchBar` without exposing it until knowledge admission. `SessionScheduleEvent` has exact schedule ID, sequence, source session, intended execution session and kind (`decision_due`, `missing_cutoff`, `activation_due`, `session_close`, `valuation_due`). `ExecutionObservation` has only observation ID, instrument, execution session, source/economic time, knowledge time, price, price basis, model ID, source-row hash and provenance; next-open observations contain no high/low/close/adjusted feature values. A type tagged as market revision cannot be passed as an execution observation.

`CanonicalEconomicInput` reuses exact existing facts where their semantics fit: `BrokerOrderEvent`, `LedgerCashFlow`, `ExecutionSettlementInstruction`, `ExecutionSettlementConfirmation`, `StockSplitAction`, `CashDividendAccrual`, `CashDividendPayment`. B/root must identify any additive command wrapper needed for current marks and reservation/order transitions; no free-form economic dictionary is admitted. Effective-time action boundaries, units and entitlement dependencies remain explicit. A known future-effective action announcement may inform admission/exclusions but does not change holdings before its effective boundary; its local due event runs at `max(known_at, effective_at)`. A late correction applies at receipt while retaining its older economic time.

A freezes every external event at knowledge frontier `t`, deduplicates identical IDs, rejects conflicting same-ID payload/provenance, validates revision ancestry, and topologically orders admitted dependencies. Dependencies cannot point into future knowledge or form cycles. Source sequences compare only within their declared stream; reject conflicting stream/sequence reuse. Among independent ready nodes, use stage, namespace, sequence scope, sequence-presence, sequence and ID. Never use input file order. A missing predecessor is a failure or explicit blocked frontier, not a lexical-order substitute.

Stages are explicit orchestration phases, not one sort over every generated event:

1. **0:** identity/availability/calendar/control admission. A halt prevents new commitments/dispatch but does not suppress accounting facts.
2. **1:** admit all equal-frontier market revisions, update the visible history, then close eligible complete/skipped watermarks. A scheduled 20:00 decision cannot precede a bar admitted at the same frontier.
3. **2:** apply ordered economic facts through B. At each external flow, issue a pre-flow valuation checkpoint, apply the flow once, then issue its post-flow checkpoint before unrelated later facts. B supplies current projection amounts; C consumes these exact pairs.
4. **3:** pass each execution observation only to orders already activated before that observation. Apply returned execution/accounting facts immediately, with later local reduction sequences and explicit parent observation/order dependencies. They do not re-enter the frozen external input set.
5. **4:** obtain the current projection, commitment snapshot and mark-quality state; advance C's shared causal wealth/risk state from engine-issued valuations. No NAV/TWR/FIFO calculation is implemented in A.
6. **5→6:** complete-market triggers first, then timers ordered by schedule ID/sequence/trigger ID. For each callback: build current immutable context, validate its successor, convert its target, evaluate daily risk, install accepted commitments atomically in the in-memory transition, rebuild the snapshot, then run the next callback. A rejected target can still advance valid strategy state; an invalid transition fails the attempt before publication.
7. **7:** schedule/activate newly accepted modeled requests after all callback microcycles. Revalidate activation requirements against the current snapshot. A newly activated request cannot consume any observation in the current frozen frontier.
8. **8:** emit immutable trace/checkpoints/valuation requests. Due events from B join A's queue exactly once; events due now must be a supported later local substage, otherwise reject rather than reopen an earlier phase.

Proof of economic precedence overrides arbitrary tie-breaking. Unproven simultaneous split/dividend/fill units or ex-date entitlement changes remain rejected. DAY expiry is an explicit model event; cancel requests and expiry timestamps alone never discard uncertain fills. The account transition, not A's queue housekeeping, decides whether a commitment can be released.

Run-wide and prefix identity must be distinguished: changing a future row changes dataset and run IDs. Earlier causal decisions must retain quantities, visible inputs, state transitions and a **causal content digest** that excludes run-wide IDs and aggregate raw-file hashes. The enclosing trace still records those full provenance pins. Event content identity uses normalized fact content/session/revision/source, not a whole-file hash containing future rows. Test prefix equivalence on this documented projection; do not incorrectly demand equal run-scoped trace IDs after changing the run's dataset.

## 4. Current account, commitments and callback inputs

```python
@dataclass(frozen=True, slots=True)
class PendingCommitment:
    commitment_id: str
    intent_id: str
    instrument_id: str
    side: Side
    state: CommitmentState
    original_quantity: Decimal
    filled_quantity: Decimal
    remaining_quantity: Decimal
    reserved_cash: Decimal
    reserved_sell_quantity: Decimal
    remaining_buy_exposure: Decimal
    accepted_for_session: date
    created_sequence: int
    activated_at: datetime | None
    activation_sequence: int | None
    execution_session: date
    not_before: datetime
    expires_at: datetime
    policy_sha256: str
    source_snapshot_sha256: str

@dataclass(frozen=True, slots=True)
class PositionState:
    instrument_id: str
    symbol: str
    quantity: Decimal
    fifo_lots: tuple[OpenTaxLot, ...]
    cost_basis: Decimal

@dataclass(frozen=True, slots=True)
class AccountSnapshot:
    run_id: str
    account_namespace: str
    point: ReductionPoint
    ledger_revision: str
    order_revision: str
    control_revision: str
    risk_revision: str
    positions: tuple[PositionState, ...]
    account_projection: CanonicalAccountProjection | None
    settlement_projection: CanonicalSettlementLedgerState
    commitments: tuple[PendingCommitment, ...]
    available_cash_after_commitments: Decimal
    accepted_intent_ids_by_session: tuple[tuple[date, tuple[str, ...]], ...]
    marks: tuple[CausalMark, ...]
    valuation_status: ValuationStatus
    operational_evidence: OperationalEvidence
    causal_sha256: str
    snapshot_sha256: str

@dataclass(frozen=True, slots=True)
class DailyInitializationContext:
    started_at: datetime                 # scored boundary
    account: AccountSnapshot
    warmup_history: tuple[VisibleDailySlice, ...]
    feature_state_sha256: str
    configuration_sha256: str

@dataclass(frozen=True, slots=True)
class DailyStrategyContext:
    trigger: DailyTrigger
    account: AccountSnapshot
    state: VersionedStrategyState
    visible_history: tuple[VisibleDailySlice, ...]
    phase: Literal["warmup", "scored"]
    context_sha256: str

class DailyStrategy(Protocol):
    def initialize(self, context: DailyInitializationContext) -> VersionedStrategyState: ...
    def on_market(self, context: DailyStrategyContext,
                  batch: CompleteDailyBatch) -> DailyStrategyTransition: ...
    def on_clock(self, context: DailyStrategyContext,
                 event: SessionScheduleEvent) -> DailyStrategyTransition: ...

@dataclass(frozen=True, slots=True)
class DailyStrategyTransition:
    state: VersionedStrategyState
    target: DailyTarget | None

@dataclass(frozen=True, slots=True)
class DailyTarget:
    target_id: str
    strategy_configuration_sha256: str
    trigger_id: str
    source_session: date
    targets: tuple[PositionTarget, ...]
    full_snapshot: bool
    execution_session: date
    not_before: datetime
    expires_at: datetime
    reduce_only_scope: bool
    explanation: str
```

`CommitmentState` includes approved-unsent, activated/send-claimed, UNKNOWN, working, partial and pending-cancel. Final states belong in history; remaining live capacity is not dropped by a caller-supplied timestamp. Exact conservation checks bind filled/remaining quantities and holds to B's order ledger. Snapshot construction is producer-only, validated against the underlying ledger/settlement/order revisions; strategies cannot instantiate a financial proof. Causal marks name instrument, raw price, economic/session/knowledge time, revision and quality. Missing current marks produce an explicit unavailable valuation, never a fabricated zero or silently authoritative last-known mark.

`PositionState` is B's current FIFO quantity/basis projection independent of authoritative marking, not another reducer in A. The existing account projector rejects a holding with no causal mark; B/root must preserve the applied ledger/lots and return `account_projection=None` in that case, with unavailable valuation. A valid old mark may produce a separately labelled last-known estimate, but `valuation_status` still prevents treating its equity as current NAV. A missing mark must not discard a received fill or stop later settlement/control processing. An unsupported ambiguous post-split mark remains an explicit affected-scope failure.

Independent-fold warmup updates pure feature history only. At the scored boundary initialize a fresh account and generation-zero strategy state from `DailyInitializationContext`, whose warmup view is already causally admitted. No warmup orders, timer decisions, portfolio P&L or score rows are carried into that account. A missing/delayed warmup prefix can fail admission or postpone eligibility under the declared gap policy; initialization cannot preload future-known rows. The `warmup` callback phase is reserved for a separately tested compatibility implementation, not permission to trade during warmup.

Root should wrap the legacy `DecisionTrigger` only if its identities can bind a daily batch without fabricated `MarketEvent` semantics. Otherwise add `DailyTrigger` with kind, trigger ID, content hash, schedule ID/sequence, source session, `as_of` and predecessor IDs; add a versioned state-successor adapter. Do not silently change old strategy context/state digests.

The converter has one new entry:

```python
def daily_target_to_intents(target: DailyTarget, snapshot: AccountSnapshot,
                            policy: DailyRiskPolicy) -> DailyIntentBatch: ...
```

For each instrument, `effective_quantity = filled + remaining_buys - remaining_sells`; identical desired quantity emits nothing. Approved-unsent and pending-cancel/UNKNOWN remainders count. If any live commitment exists and the requested target differs, emit `COMMITMENT_REQUIRES_CANCEL_OR_RECONCILIATION`, not another order or a synthetic net/release. This conservative one-intent-per-symbol rule also blocks same-direction top-ups while one is active. A full snapshot only implies zero for omitted instruments when there is a valid explicit complete target; it never means an absent callback liquidates holdings.

`DailyIntentBatch` binds account, trigger, target hash, exact snapshot hash, source/execution sessions, per-intent desired delta/reference-mark hash/window and sorted intent IDs. IDs derive from the account/trigger/target/instrument/side/quantity/window content. Replaying a target against its already-installed commitments creates no second acceptance. A different payload under the same target/intent ID rejects. One daily allocation decision per strategy/source session is consumed whether risk accepts, rejects or records no action; a missing-input wait has not consumed it yet. Additional same-frontier timer callbacks may update state but cannot mint a second daily exposure decision.

Reference strategies perform sizing with a shared root-approved helper: for a buy allocation budget `a * causal_NAV`, floor whole shares using `reference_price * 1.01 + per_share_fee` after any fixed fee. No future open enters sizing. The same risk policy independently checks the result; existing holdings, reservations, fees and caps can only reduce/reject capacity. Do not silently resize an already-approved intent inside the execution port.

## 5. Pure daily risk and the transition ports

```python
@dataclass(frozen=True, slots=True)
class DailyRiskPolicy:
    policy_id: str
    version: str
    allowed_instrument_ids: tuple[str, ...]
    max_order_quantity: Decimal
    max_order_nav_fraction: Decimal
    max_batch_nav_fraction: Decimal
    max_symbol_nav_fraction: Decimal
    max_gross_nav_fraction: Decimal
    adverse_reserve_fraction: Decimal
    fixed_fee: Decimal
    fee_per_share: Decimal
    max_open_intents: int
    max_per_symbol_intents: int
    max_new_intents_per_session: int
    daily_loss_boundary: Decimal
    drawdown_boundary: Decimal
    operational_model: VersionPin
    freshness_model: VersionPin

@dataclass(frozen=True, slots=True)
class EvidenceValue[T]:
    value: T | None
    unavailable_reason: str | None
    producer: VersionPin
    produced_at: datetime
    valid_until: datetime | None
    data_class: ResearchDataClass

@dataclass(frozen=True, slots=True)
class DailyRiskEvidence:
    phase: Literal["decision", "activation"]
    snapshot_sha256: str
    source_session: date
    execution_session: date
    watermark_sha256: str
    daily_trigger_registry_sha256: str
    account_eligible: EvidenceValue[bool]
    required_data_complete: EvidenceValue[bool]
    execution_inputs_eligible: EvidenceValue[bool]
    settled_cash_semantics: EvidenceValue[bool]
    reconciliation_current: EvidenceValue[bool]
    controls_allow: EvidenceValue[bool]
    ownership_current: EvidenceValue[bool]
    clock_healthy: EvidenceValue[bool]
    request_capacity: EvidenceValue[int]
    daily_return: EvidenceValue[Decimal]
    drawdown: EvidenceValue[Decimal]

def evaluate_daily_risk(
    policy: DailyRiskPolicy,
    snapshot: AccountSnapshot,
    target_batch: DailyIntentBatch,
    evidence: DailyRiskEvidence,
    evaluated_at: datetime,
) -> DailyRiskDecision: ...

class AccountingExecutionPort(Protocol):
    def initialize(self, spec: RunSpec) -> EconomicTransition: ...
    def transition(self, state: EconomicState, event: AccountInput,
                   point: ReductionPoint,
                   marks: tuple[CausalMark, ...]) -> EconomicTransition: ...

@dataclass(frozen=True, slots=True)
class EconomicTransition:
    state: EconomicState
    snapshot: AccountSnapshot
    applied_facts: tuple[AppliedEconomicFact, ...]
    due_events: tuple[EngineEvent, ...]
    fifo_matches: tuple[FifoMatch, ...]

def run_causal_engine(inputs: EngineInputs, strategy: DailyStrategy,
                      economic_port: AccountingExecutionPort,
                      performance_port: CausalPerformancePort) -> EngineOutput: ...
```

This is B's proposed one-step immutable transition shape. Root/B freeze `EconomicState` as the retained order/execution ledger, settlement and corporate-action facts plus their revisions; no second event loop, future input tape, strategy callback, report calculator or clock/network I/O is inside this port. `AccountInput` is a closed union: an admitted canonical economic fact, a mark/projection update, an approved-batch commitment command, an activation command, one current execution observation, or an explicit model terminal/cancel event. Each command names the expected snapshot revision/hash. State and current snapshot return together; a failed expected-version check has no partial commitment mutation.

An approved decision carries **reservation proposals**, never external execution permissions. `DailyRiskDecision` fields: decision ID; policy/target/snapshot/evidence hashes; evaluated time and validity; status (`APPROVED`, `REJECTED`, `NO_ACTION`, `UNAVAILABLE`); sorted `RuleObservation` values with rule ID, status, observed value, limit, producer/version/time/class and reasons; and sorted reservation proposals. Proposals include intent ID, buy cash reserve, sell-share reserve, remaining buy exposure and execution window. Rejection/unavailable installs none. Every simulated accepted intent ID is counted once for its intended execution session; active IDs are not added again to an already-counted daily total.

`DailyRiskPolicy` freezes all W0 defaults: positive causal NAV; allowed universe/order subset; 1,000 shares/order; 25% reference notional/order and conservative symbol exposure; 95% batch absolute reference notional/account gross; 1% adverse cash reserve plus model fees; four live intents, one per symbol, eight distinct new intents/session; daily loss boundary −3%, drawdown boundary 15%; and named simulated request/control/freshness policy. Buy reserves do not imply a maximum legal fill price. Fees on sells also require available cash when applicable; sell proceeds never finance same-batch buys. A shared capacity helper can accept per-intent Decimal reservation inputs; do not force a single per-share buffer across differently priced instruments.

`DailyRiskEvidence` contains producer-bound facts for the expected completed source session/watermark, intended execution session/model, current valuation status, settled/restricted cash status, simulated reconciliation, controls/ownership/time health, request capacity, daily accepted-ID registry and C's flow-neutral daily-return/drawdown state. Missing mandatory values use typed unavailable values/reasons, not `None -> 0`. Decision-stage bar freshness checks the required daily session and cutoff; activation-stage model/quote checks are separately identified. C supplies the same wealth-state reducer to engine risk production and reporting; risk only evaluates its policy thresholds.

Pure risk must not label historical simulation as broker-ready. A MARGIN privilege label adds no cash or leverage: unknown/nonzero real financing, currency or restrictions could never pass a future connected producer merely because a historical producer is supported. Initial W2 rejects connected environments entirely. Loss/cap breaches block new exposure; explicit reduce-only handling verifies no buy, no increased exposure and no oversell, and does not auto-flatten. Invalid/future evidence rejects even a reduce-only request.

`EngineOutput` is root-owned: run/spec ID, completion status/reasons, chronological trace, engine valuation checkpoints (including same-frontier pre/post-flow pairs), applied execution/action/flow/settlement facts, FIFO matches, order/commitment transitions, final snapshots/state pins and full limitations. C derives the report from these facts. A writes no P&L, return, benchmark, fee-allocation or trade-statistics formulas. B's FIFO match lineage must identify opening execution/lot, closing execution, matched quantity, basis, gross proceeds and fee-allocation inputs for C, without expensing portfolio fees again.

## 6. Schedule, activation and data limits

- Decision begins at 20:00 local after a session. Earlier arrival can warm knowledge but cannot trigger early trading. At or after 20:00 and strictly before the next-session 09:00 cutoff, the first complete expected-symbol set permits one decision. At cutoff equality, skip even if all missing data arrives at that exact frontier. A later revision can affect later windows under the pinned revision policy; it cannot reopen the closed session.
- Missing required input never blocks account/control/settlement processing. A missing expected feature session resets affected contiguous lookback state; calendar holidays/weekends do not. Unchanged already-observed revisions are not appended a second time. Default daily revision policy is latest available revision at each new trigger, with prior traces immutable; unsupported action-adjusted revision lineage rejects affected scope.
- Root should represent delayed/missing synthetic deliveries as versioned event-source fixture manifests. W1 `DailyResearchBar` retains its exact modeled-20:00 constructor contract; do not edit it to smuggle arbitrary availability into existing archives. Recorded mode uses actual validated receipt time; a current receipt cannot backfill a historical overnight decision. Synthetic receipt fixtures remain explicitly synthetic.
- The recommended next-open proxy arms a **modeled** request after the previous decision, retains an explicit next-session eligibility boundary, and only consumes that next session's open-only observation. Activation is causally later than the decision and its source time is strictly before the later open. This modeled overnight arming is not a broker submission or 09:35 execution. The model must never activate using a future open and fill from that same observation.
- Fill eligibility requires matching session/instrument/model, `observation.source_time > activation_time`, and a later reduction sequence; equality rejects even when sequence differs. Forward policy additionally requires `[09:35, 09:40)` and qualified inputs, but no connected driver is implemented. Next-open proxy accepts only the explicitly named open observation, not a later close or next day's first available tick.
- At a closed expected-open frontier with no eligible observation, record `MISSING_ELIGIBLE_OPEN`; do not skip ahead. Recommend an explicit model terminal event release at the intended session's close for the initial DAY model. Any UNKNOWN/cancel ambiguity retains its hold unless the model supplies authoritative terminal resolution. Root/B must freeze this exact expiry behavior before code.
- Calendar data controls open/close and the next regular session, including half-days/holidays/DST. Actual local 20:00/09:00/09:35–09:40 times are converted with pinned timezone data; do not derive them by adding fixed UTC hours. On a 13:00 half-day, DAY expiration is 13:00, not 16:00; the decision remains 20:00. Never select a weekend/holiday as the next execution day.
- Raw executable price and adjusted feature series remain distinct. The W1 action policy cannot supply missing dividend payable facts or unsupported splits; action economics tests use separate explicitly synthetic B fixtures. Any admitted run with unsupported held-instrument action scope must stop/reject or narrow its declared universe/interval visibly, never silently omit the action.

## 7. Independently specified acceptance inputs

All examples are synthetic fixtures with explicit zero costs where stated; they grant no live amounts. Expected values are hand-specified, not computed by the implementation under test. B owns ledger arithmetic checks and C owns metric checks; A verifies the observable callback/trace/decision consequences.

| Case | Inputs | Required assertions |
|---|---|---|
| A1 — equal-frontier microcycles | USD 10,000 settled, no holdings, raw mark 100, zero fees, 1% reserve; a market callback targets 10 shares and a same-frontier timer repeats 10 | First acceptance holds 1,010; second context has zero filled, +10 committed and 8,990 available. No second intent/reservation. Strategy state generation advances in callback order. Even a deliberately hostile repeating timer cannot bypass the once-per-source-session exposure registry. |
| A2 — filled and unsettled state reaches callback | A1 order fills 4 at 100 before the next decision, zero fees; six remain, all facts causally before callback | Next callback sees filled 4, remaining buy 6, effective 10, trade cash 9,600, unsettled buy payable 400, reserve 606, available 8,994. Target 10 emits none. After 400 settles, settled cash 9,600/payable 0 leave available 8,994. No double debit of the filled reserve. |
| A3 — opposing/ambiguous commitment | Filled 4, pending/UNKNOWN buy remainder 6; desired 3 or 12 | Both targets require cancel/reconciliation; no synthetic sell or second buy, no release of the original hold. Pending-cancel alone has the same result. A later proven cancel can release only its remaining portion before a fresh callback. |
| A4 — strict causal fills | Activated at `t`, an observation has source time `t` and larger local sequence; another eligible observation has source time `t+1s` | Equal-source-time observation cannot fill. The later event may fill within the exact window. The creating close and any observation already frozen in the activation frontier cannot fill the new request. Changing future high/low/close cannot alter an open-only fill. |
| A5 — missing and cutoff | Two-symbol session, second bar arrives at 20:00, 08:59:59.999999 next session, exactly 09:00, or later | Equal-20:00 permutations produce one complete market callback; just-before cutoff permits one late decision. Equality/after produces skipped watermark and no session target. Later arrival remains visible only to later eligible decisions. No stale backlog. |
| A6 — shortened calendar/DST | Labelled calendar has Friday regular close 13:00, a Monday next session, and a separate US DST weekend example | Friday valuation names 13:00 economic time but is only usable at declared publication. Decision 20:00; next cutoff Monday 09:00. DAY terminal uses 13:00. Local times cross DST with changed UTC offset, not fixed 24-hour additions. Missing Monday open never fills Tuesday. |
| A7 — feature gap | 200-session mean, 199 consecutive eligible closes then a gap; later 200 consecutive eligible closes | No target from 199 or a gap-spanning window. Rewarmed 200th close is eligible. Flat prices satisfy equality and therefore the trend target is flat. Holidays do not reset the window. |
| A8 — ordering/lineage | Permuted independent same-frontier facts, identical duplicate, conflicting duplicate, cycle, future predecessor, same-time ambiguous split/dividend units | Permutations and identical duplicates yield equal full semantic outputs for the same run. Each ambiguity rejects before a successful output; no lexical tie fabricates entitlement/units. Explicit valid economic predecessors override arrival order. |
| A9 — risk boundaries | Complete evidence; exact cap values and one smallest admitted Decimal above each cap; loss −0.03 and drawdown 0.15; missing/future input | Inclusive maximum caps pass if all other rules pass. Both loss boundaries block new exposure. Missing/future values produce explicit unavailable/rejected rules, not zeros. Nonpositive NAV blocks. Two accepted IDs already active are counted once, and the ninth distinct session acceptance rejects. Pending sales do not fund buys or lower conservative concentration. |
| A10 — future prefix | Modify only bars/actions/flows strictly after frontier F, holding visible prefix/config/initial state constant | New dataset/run identity; equal earlier causal decision projection, quantities and state-content digests through F. Permuting the same input set keeps complete trace/ledger/output hashes equal. Later corrections never overwrite original callback rows. |
| A11 — flow/checkpoint handoff | B's independently valued pre-flow NAV 10,000, contribution 2,000, post-flow NAV 12,000 at one frontier; no intervening price fact | A emits adjacent ordered pre/post checkpoints with one flow ID and the same mark set. The next callback sees 12,000 capital; C's wealth producer reports no gain from the contribution. Repeated flow ID applies once; a later mark cannot value the earlier boundary. |

Required long dataset matrix: two separately hashed, public **synthetic fixtures**, each with 520 consecutive declared regular sessions for SPY, 252 warmup sessions and 268 scored sessions (enough for at least 252 complete scored close-to-close intervals). The exact toy grid is the first 520 Monday–Friday dates starting 2021-01-04, each 09:30–16:00 America/New_York, with no holiday exclusions. This deliberately synthetic calendar includes dates that may be actual market holidays; it is not historical exchange evidence. Grid and timezone contents are pinned. Raw/adjusted values are equal, split factor 1, dividend cash 0, volume 1,000,000. Open equals the previous close, high is `max(open, close)+1`, low is `min(open, close)-1`; first open is 100. All daily rows are modeled available at 20:00.

- **Dataset F-flat/1:** every close is 100. Buy/hold with 25% single-symbol allocation, no periodic rebalance, base 5 bps/$0.01 costs buys 24 shares at the next open, at 100.05 plus 0.24 fee, and repeats no orders. Its post-fill cash is 7,598.56 and unchanged-price NAV is 9,998.56. The 200-session strict-above-mean strategy remains flat with zero orders. The 1% reserve is 2,424.24 before fill; it is not charged in addition to execution economics.
- **Dataset R-regimes/1:** warmup closes are 100; for scored index `j=0..267`, close is `100+0.1*j` for `j<90`, `108.9-0.2*(j-89)` for `90<=j<180`, then 90.9. Buy/hold remains governed by the same caps and cash rules; trend becomes invested on the rising regime and returns to cash after the strict mean crossover in the falling regime. Expect different causal target/execution transcripts from F-flat and between strategies; do not assert profitability. Verify the crossover predicate directly from the 200 literal eligible closes, separately from engine feature code.

Run both configurable strategies on both datasets. Also change buy/hold rebalance interval from none to 21 eligible sessions, trend lookback from 200 to a declared alternative, allocation, and costs individually; each changes identity, and a behavior-affecting change must change the relevant transcript. Zero-variance/short-sample metrics remain C's explicit cases. Neither synthetic dataset is a holdout or provider evidence.

Root must supply these long fixtures through an explicitly versioned fixture source to the same admitted engine input port. The W1 owner-import CLI's bounded date/size limits are not to be relaxed implicitly; its short archive path is not a general synthetic test-data generator. A direct valid `ResearchDataset` fixture or a pinned fixture event manifest is acceptable only after root freezes serialization/admission and provenance. Do not duplicate the economic engine in a fixture runner.

The actual W1 Tiingo sample has five sessions/20 bars and cannot meet 200 consecutive feature sessions, 252 earlier warmup sessions or 252 scored metric sessions. Keep default-run admission visibly `INSUFFICIENT_WARMUP`; an explicit short configuration may demonstrate plumbing with all statistical limitations retained, never default-strategy/full-study acceptance. This lane does not read that private sample, call a provider or invent publication/payable dates.

## 8. Root freeze decisions required

1. Approve exact shared module/type names and the additive daily strategy/trigger/state compatibility plan. Keep old serializers and financial proof constructors unchanged.
2. Freeze B's `EconomicState`/`AccountInput`/`EconomicTransition` expansion and snapshot builder, including reserve transfer, due-event identity/ordering, model arming, missing-open/DAY expiry and partial/cancel/UNKNOWN behavior. A must have a projection after every transition, not only after a full run.
3. Freeze C's engine valuation/checkpoint/FIFO DTOs and one reusable flow-neutral wealth-state producer for risk/reporting. State how first-scored baseline and valid return-interval counts map to annualization, avoiding an off-by-one warmup/close boundary.
4. Freeze identity serialization, causal-prefix comparison and normalized event IDs separately from dataset-wide provenance/run IDs; decide no-fit initial-state sentinel and source/dirty-build pins.
5. Approve two-phase daily admission versus activation risk, conservative no-top-up while committed, once-per-source-session decision consumption and intended-execution-session intent counts. Normal strategy risk reductions require explicit reduce-only scope, not a blanket loss-control exemption.
6. Freeze feature basis, revision/gap behavior, availability-mode validation, action exclusions and the 520-session fixture source. Preserve W1 factual-time and archive semantics. Default independent folds only; unsupported carry fails visibly.
7. Approve the exact A implementation allowlist above and confirm root-owned reference strategies, dataset conversion, result DTOs and product/CLI/golden cutover. No consumer code starts before this freeze.

Validation of this proposal is limited to source/contract inspection, branch/base verification, file scope and document checks. No provider, credential, private data, order, deployment or Git mutation occurred. The only new artifact from this assignment is this file.
