"""Versioned inputs and pure strategy/risk boundaries for the one causal engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Literal, Protocol

from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingState,
    AccountSnapshot,
    ExecutionObservation,
    ExecutionPolicy,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.models import OrderIntent, PositionTarget
from packages.domain.personal_contracts import (
    ContractRecord,
    ReductionPoint,
    VersionPin,
    content_digest,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.research_dataset import ResearchCalendar, ResearchDataClass


@dataclass(frozen=True, slots=True)
class DailyRiskPolicy(ContractRecord):
    policy_id: str = "personal-daily-simulation/1"
    max_order_quantity: Decimal = Decimal("1000")
    max_order_nav_fraction: Decimal = Decimal("0.25")
    max_batch_nav_fraction: Decimal = Decimal("0.95")
    max_symbol_nav_fraction: Decimal = Decimal("0.25")
    max_gross_nav_fraction: Decimal = Decimal("0.95")
    adverse_reserve_fraction: Decimal = Decimal("0.01")
    fee_per_share: Decimal = Decimal("0.01")
    max_open_intents: int = 4
    max_per_symbol_intents: int = 1
    max_new_intents_per_session: int = 8
    daily_loss_boundary: Decimal = Decimal("-0.03")
    drawdown_boundary: Decimal = Decimal("0.15")
    policy_scope: Literal["product", "synthetic_oracle"] = "product"

    def __post_init__(self) -> None:
        super(DailyRiskPolicy, self).__post_init__()
        require_text(self.policy_id, "risk policy")
        require_amount(self.max_order_quantity, "maximum order quantity", positive=True, whole=True)
        for name in (
            "max_order_nav_fraction",
            "max_batch_nav_fraction",
            "max_symbol_nav_fraction",
            "max_gross_nav_fraction",
            "drawdown_boundary",
        ):
            value = getattr(self, name)
            require_amount(value, name, positive=True)
            if value > 1:
                raise ValueError("cash-funded maximum fraction exceeds one")
        for name in ("adverse_reserve_fraction", "fee_per_share"):
            require_amount(getattr(self, name), name, nonnegative=True)
        if not Decimal("-1") <= self.daily_loss_boundary < 0:
            raise ValueError("daily loss boundary must be negative")
        if (
            min(
                self.max_open_intents, self.max_per_symbol_intents, self.max_new_intents_per_session
            )
            < 1
        ):
            raise ValueError("risk count limits must be positive")
        if self.policy_scope == "product" and (
            self.max_order_nav_fraction > Decimal("0.25")
            or self.max_symbol_nav_fraction > Decimal("0.25")
            or self.max_gross_nav_fraction > Decimal("0.95")
            or self.max_batch_nav_fraction > Decimal("0.95")
            or self.max_order_quantity > 1000
            or self.adverse_reserve_fraction < Decimal("0.01")
            or self.max_open_intents > 4
            or self.max_per_symbol_intents > 1
            or self.max_new_intents_per_session > 8
        ):
            raise ValueError("product policy may not exceed the frozen simulation envelope")


@dataclass(frozen=True, slots=True)
class EvaluationSpec(ContractRecord):
    fold_id: str
    warmup_sessions: tuple[date, ...]
    scored_sessions: tuple[date, ...]
    prior_access_label: str
    reset_mode: Literal["independent"] = "independent"

    def __post_init__(self) -> None:
        super(EvaluationSpec, self).__post_init__()
        for name in ("fold_id", "prior_access_label"):
            require_text(getattr(self, name), name)
        for values in (self.warmup_sessions, self.scored_sessions):
            if values != tuple(sorted(set(values))):
                raise ValueError("evaluation sessions must be sorted and unique")
        if not self.scored_sessions or (
            self.warmup_sessions and self.warmup_sessions[-1] >= self.scored_sessions[0]
        ):
            raise ValueError("warmup and scored sessions must be ordered and disjoint")


@dataclass(frozen=True, slots=True)
class RunSpec(ContractRecord):
    account_id: str
    dataset_id: str
    dataset_sha256: str
    events_sha256: str
    data_class: ResearchDataClass
    availability_mode: Literal["modeled", "recorded"]
    instruments: tuple[tuple[str, str], ...]
    calendar: ResearchCalendar
    strategy: VersionPin
    strategy_configuration: ReferenceConfiguration
    evaluation: EvaluationSpec
    execution_policy: ExecutionPolicy
    risk_policy: DailyRiskPolicy
    pins: tuple[VersionPin, ...]
    initial_state_sha256: str
    initial_cash: Decimal = Decimal("10000")
    environment: Literal["historical_simulation"] = "historical_simulation"
    account_privileges: Literal["CASH", "MARGIN"] = "CASH"
    financing_policy: Literal["cash-funded-long-only/1"] = "cash-funded-long-only/1"
    eligibility_policy: Literal["personal-v1/account-eligibility/2"] = (
        "personal-v1/account-eligibility/2"
    )
    feature_price_basis: Literal["adjusted_close", "raw_close"] = "adjusted_close"
    revision_policy: Literal["latest-known-contiguous-v1"] = "latest-known-contiguous-v1"
    max_events: int = 100000
    max_output_bytes: int = 1073741824
    max_wall_seconds: int = 1800
    max_memory_bytes: int = 4294967296
    max_cpu_cores: int = 2
    seed: int | None = None
    rng_algorithm: Literal["none"] = "none"
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(RunSpec, self).__post_init__()
        for name in ("account_id", "dataset_id"):
            require_text(getattr(self, name), name)
        for name in ("dataset_sha256", "events_sha256", "initial_state_sha256"):
            require_digest(getattr(self, name), name)
        require_amount(self.initial_cash, "synthetic initial cash", nonnegative=True)
        if self.initial_cash == 0 and self.risk_policy.policy_scope != "synthetic_oracle":
            raise ValueError("zero initial cash requires an explicit funded synthetic oracle")
        ids = tuple(i for i, _ in self.instruments)
        if not ids or ids != tuple(sorted(set(ids))) or len(self.instruments) > 4:
            raise ValueError("configured instruments must be sorted unique scope")
        if any(s not in ("DIA", "IWM", "QQQ", "SPY") for _, s in self.instruments):
            raise ValueError("unsupported personal-v1 instrument")
        labels = tuple(s.session_label for s in self.calendar.sessions)
        required = self.evaluation.warmup_sessions + self.evaluation.scored_sessions
        if any(s not in labels for s in required):
            raise ValueError("evaluation exceeds pinned session calendar")
        names = tuple(p.name for p in self.pins)
        required_pins = {
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        }
        if names != tuple(sorted(set(names))) or not required_pins.issubset(names):
            raise ValueError("run requires unique sorted complete model/source pins")
        if self.seed is not None:
            raise ValueError("initial execution model is deterministic; seed unsupported")
        if not 1 <= self.max_events <= 100000 or not 1 <= self.max_output_bytes <= 1073741824:
            raise ValueError("run exceeds event/output resource envelope")
        if (
            not 1 <= self.max_wall_seconds <= 1800
            or not 1 <= self.max_memory_bytes <= 4294967296
            or not 1 <= self.max_cpu_cores <= 2
        ):
            raise ValueError("run exceeds compute resource envelope")

    @property
    def run_id(self) -> str:
        return "run-" + self.semantic_sha256


@dataclass(frozen=True, slots=True)
class ObservationProvenance(ContractRecord):
    data_class: ResearchDataClass
    source_namespace: str
    normalized_sha256: str
    observed_at: datetime | None = None
    vendor_published_at: datetime | None = None
    simulated_available_at: datetime | None = None
    assumption_id: str | None = None
    raw_sha256: str | None = None
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(ObservationProvenance, self).__post_init__()
        require_text(self.source_namespace, "source namespace")
        require_digest(self.normalized_sha256, "normalized content")
        if self.raw_sha256 is not None:
            require_digest(self.raw_sha256, "raw object")
        if (self.simulated_available_at is None) != (self.assumption_id is None):
            raise ValueError("modeled availability requires its named assumption")
        if self.observed_at is None and self.simulated_available_at is None:
            raise ValueError("event needs observed or explicitly modeled availability")


@dataclass(frozen=True, slots=True)
class DailyPrice(ContractRecord):
    instrument_id: str
    symbol: str
    session: date
    open_price: Decimal
    close_price: Decimal
    adjusted_close: Decimal
    revision: int = 1
    predecessor_revision_id: str | None = None

    def __post_init__(self) -> None:
        super(DailyPrice, self).__post_init__()
        for name in ("open_price", "close_price", "adjusted_close"):
            require_amount(getattr(self, name), name, positive=True)
        if self.revision < 1 or (self.revision == 1) != (self.predecessor_revision_id is None):
            raise ValueError("daily price requires contiguous revision ancestry")


@dataclass(frozen=True, slots=True)
class BenchmarkPrice(ContractRecord):
    series_id: str
    unit_price: Decimal
    representation: Literal["adjusted_total_return_units", "synthetic_total_return_units"]

    def __post_init__(self) -> None:
        super(BenchmarkPrice, self).__post_init__()
        require_text(self.series_id, "benchmark series")
        require_amount(self.unit_price, "benchmark unit price", positive=True)


@dataclass(frozen=True, slots=True)
class ScheduleSignal(ContractRecord):
    schedule_id: str
    source_session: date
    kind: Literal[
        "decision_due",
        "missing_cutoff",
        "session_open",
        "session_close",
        "valuation_due",
        "timer",
        "baseline",
        "terminal",
    ]
    sequence: int = 0


type EnginePayload = (
    DailyPrice | BenchmarkPrice | ScheduleSignal | AccountingCommand | ExecutionObservation
)


@dataclass(frozen=True, slots=True)
class EngineEvent(ContractRecord):
    event_id: str
    economic_at: datetime
    knowledge_at: datetime
    payload: EnginePayload
    provenance: ObservationProvenance
    predecessor_ids: tuple[str, ...] = ()
    sequence_scope: str | None = None
    source_sequence: int | None = None

    def __post_init__(self) -> None:
        super(EngineEvent, self).__post_init__()
        require_text(self.event_id, "event ID")
        if self.economic_at > self.knowledge_at:
            raise ValueError("economic application cannot precede its effective time")
        if self.event_id in self.predecessor_ids or len(set(self.predecessor_ids)) != len(
            self.predecessor_ids
        ):
            raise ValueError("event has invalid predecessor IDs")
        if (self.sequence_scope is None) != (self.source_sequence is None):
            raise ValueError("source sequence requires a stream scope")
        if self.source_sequence is not None and self.source_sequence < 0:
            raise ValueError("source sequence cannot be negative")
        if self.provenance.normalized_sha256 != content_digest(self.payload):
            raise ValueError("event payload and normalized provenance differ")

    @property
    def causal_sha256(self) -> str:
        # Full run/raw-object hashes remain in enclosing provenance, not causal prefix content.
        return content_digest(
            (
                self.event_id,
                self.economic_at,
                self.knowledge_at,
                self.payload,
                self.predecessor_ids,
                self.sequence_scope,
                self.source_sequence,
                self.provenance.data_class,
                self.provenance.source_namespace,
                self.provenance.assumption_id,
            )
        )


@dataclass(frozen=True, slots=True)
class EngineInputs(ContractRecord):
    spec: RunSpec
    events: tuple[EngineEvent, ...]
    initial_state: AccountingState


@dataclass(frozen=True, slots=True)
class DailyStrategyState(ContractRecord):
    generation: int = 0
    predecessor_sha256: str | None = None
    previously_allocated: bool = False
    values: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class DailyTrigger(ContractRecord):
    trigger_id: str
    source_session: date
    execution_session: date
    as_of: datetime
    kind: Literal["complete_market", "timer"]
    source_sha256: str
    sequence: int


@dataclass(frozen=True, slots=True)
class DailyStrategyContext(ContractRecord):
    trigger: DailyTrigger
    account: AccountSnapshot
    state: DailyStrategyState
    configuration: ReferenceConfiguration
    instrument_symbols: tuple[tuple[str, str], ...]
    history: tuple[tuple[date, tuple[tuple[str, Decimal | None], ...]], ...]
    expected_sessions: tuple[date, ...]
    scored_session_index: int
    not_before: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class DailyTarget(ContractRecord):
    target_id: str
    trigger: DailyTrigger
    configuration_sha256: str
    targets: tuple[PositionTarget, ...]
    not_before: datetime
    expires_at: datetime
    full_snapshot: bool = True
    reduce_only_scope: bool = False
    explanation: str = "reference strategy target"


@dataclass(frozen=True, slots=True)
class DailyStrategyTransition(ContractRecord):
    state: DailyStrategyState
    target: DailyTarget | None
    reasons: tuple[str, ...] = ()


class DailyStrategy(Protocol):
    def initialize(
        self, *, configuration: ReferenceConfiguration, initial_snapshot: AccountSnapshot
    ) -> DailyStrategyState: ...
    def on_decision(self, context: DailyStrategyContext) -> DailyStrategyTransition: ...


@dataclass(frozen=True, slots=True)
class DailyIntentBatch(ContractRecord):
    batch_id: str
    target: DailyTarget
    snapshot_sha256: str
    intents: tuple[OrderIntent, ...]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DailyRiskEvidence(ContractRecord):
    snapshot_sha256: str
    phase: Literal["decision", "activation"]
    produced_at: datetime
    source_session: date
    execution_session: date
    producer: VersionPin
    daily_return: Decimal | None
    drawdown: Decimal | None
    accepted_intent_ids: tuple[str, ...]
    complete_daily_inputs: bool
    controls_healthy: bool
    session_healthy: bool
    time_healthy: bool
    cash_semantics_known: bool
    request_capacity_available: bool
    simulation_reconciled: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DailyRiskDecision(ContractRecord):
    approved: bool
    batch: DailyIntentBatch
    policy_sha256: str
    evidence_sha256: str
    reserved_cash_by_intent: tuple[tuple[str, Decimal], ...]
    reserved_shares_by_intent: tuple[tuple[str, Decimal], ...]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EngineTraceRow(ContractRecord):
    event_id: str
    point: ReductionPoint
    kind: str
    causal_input_sha256: str
    prior_snapshot_sha256: str
    next_snapshot_sha256: str
    state_sha256: str
    intent_ids: tuple[str, ...] = ()
    target_quantities: tuple[tuple[str, Decimal], ...] = ()
    reasons: tuple[str, ...] = ()
    causal_content_sha256: str = ""
