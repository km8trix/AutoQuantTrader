"""Stateful-simulation configuration and incoming closed-frontier values.

These are inputs to the existing causal engine. Unlike a research RunSpec, their
identity binds the declared stream configuration rather than future market rows.
They confer no provider, account-owner, risk or dispatch authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import ClassVar, Literal, Protocol

from packages.domain.accounting_contracts import (
    AccountingContext,
    AccountingState,
    AccountSnapshot,
    Commitment,
    ExecutionPolicy,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.daily_runtime_contracts import DailyRuntimeRiskEvidence
from packages.domain.engine_contracts import (
    DailyIntentBatch,
    DailyRiskDecision,
    DailyRiskPolicy,
    EngineEvent,
    EvaluationSpec,
)
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    content_digest,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.research_dataset import ResearchCalendar, ResearchDataClass


class ContinuousEngineRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-continuous-engine/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousEngineSpec(ContinuousEngineRecord):
    account_id: str
    deployment_id: str
    account_binding_sha256: str
    calendar: ResearchCalendar
    instruments: tuple[tuple[str, str], ...]
    strategy: VersionPin
    strategy_configuration: ReferenceConfiguration
    window: EvaluationSpec
    execution_policy: ExecutionPolicy
    risk_policy: DailyRiskPolicy
    pins: tuple[VersionPin, ...]
    initial_state_sha256: str
    bootstrap_events_sha256: str
    initialized_at: datetime
    initial_cash: Decimal = Decimal("10000")
    environment: Literal["stateful_simulation"] = "stateful_simulation"
    source_mode: Literal["synthetic_observed", "recorded_as_observed"] = "synthetic_observed"
    account_privileges: Literal["CASH", "MARGIN"] = "CASH"
    financing_policy: Literal["cash-funded-long-only/1"] = "cash-funded-long-only/1"
    feature_price_basis: Literal["adjusted_close", "raw_close"] = "adjusted_close"
    revision_policy: Literal["latest-known-contiguous-v1"] = "latest-known-contiguous-v1"
    max_events: int = 100000
    max_output_bytes: int = 33554432
    max_wall_seconds: int = 30
    max_memory_bytes: int = 4294967296
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(ContinuousEngineSpec, self).__post_init__()
        for name in ("account_id", "deployment_id"):
            require_text(getattr(self, name), name)
        for name in ("account_binding_sha256", "initial_state_sha256", "bootstrap_events_sha256"):
            require_digest(getattr(self, name), name)
        require_amount(self.initial_cash, "synthetic starting cash", positive=True)
        if self.risk_policy.policy_id != "personal-daily-stateful-simulation/1":
            raise ValueError("continuous engine requires the runtime policy version")
        if self.risk_policy.policy_scope != "product":
            raise ValueError("continuous engine cannot use a relaxed oracle policy")
        if self.execution_policy.model_id != "observed-facts-v1":
            raise ValueError("continuous coordinator requires observed-facts accounting")
        identities = tuple(key for key, _ in self.instruments)
        if not identities or identities != tuple(sorted(set(identities))) or len(identities) > 4:
            raise ValueError("continuous instrument identities must be sorted unique and bounded")
        symbols = tuple(symbol for _, symbol in self.instruments)
        if len(set(symbols)) != len(symbols) or any(
            symbol not in ("DIA", "IWM", "QQQ", "SPY") for symbol in symbols
        ):
            raise ValueError("continuous instruments exceed the personal universe")
        labels = tuple(session.session_label for session in self.calendar.sessions)
        expected = self.window.warmup_sessions + self.window.scored_sessions
        if (
            any(label not in labels for label in expected)
            or labels[-1] <= self.window.scored_sessions[-1]
        ):
            raise ValueError("continuous window requires a following execution horizon")
        first = next(
            s for s in self.calendar.sessions if s.session_label == self.window.scored_sessions[0]
        )
        if self.initialized_at >= first.closes_at:
            raise ValueError("continuous startup must precede the first operating close")
        if self.window.reset_mode != "independent":
            raise ValueError("initial stream config must explicitly begin a new account")
        names = tuple(pin.name for pin in self.pins)
        if names != tuple(sorted(set(names))) or not {
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
        } <= set(names):
            raise ValueError("continuous stream requires complete sorted build/model pins")
        if not 1 <= self.max_events <= 100000 or not 1 <= self.max_output_bytes <= 33554432:
            raise ValueError("continuous event/checkpoint resource limit exceeded")
        if not 1 <= self.max_wall_seconds <= 30 or not 1 <= self.max_memory_bytes <= 4294967296:
            raise ValueError("continuous step compute limit exceeded")

    @property
    def run_id(self) -> str:
        return "stream-" + self.semantic_sha256

    @property
    def evaluation(self) -> EvaluationSpec:
        """Reuse the existing engine's warmup/window indexing without a new loop."""
        return self.window

    @property
    def data_class(self) -> ResearchDataClass | Literal["recorded_as_observed"]:
        return (
            "recorded_as_observed"
            if self.source_mode == "recorded_as_observed"
            else ResearchDataClass.SYNTHETIC_FIXTURE
        )

    @property
    def availability_mode(self) -> Literal["modeled", "recorded"]:
        return "recorded" if self.source_mode == "recorded_as_observed" else "modeled"


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousEngineInputs(ContinuousEngineRecord):
    spec: ContinuousEngineSpec
    initial_state: AccountingState
    bootstrap_events: tuple[EngineEvent, ...]

    def __post_init__(self) -> None:
        super(ContinuousEngineInputs, self).__post_init__()
        if self.initial_state != AccountingState(self.spec.account_id):
            raise ValueError("new simulation stream starts with an explicitly empty account")
        if self.initial_state.semantic_sha256 != self.spec.initial_state_sha256:
            raise ValueError("continuous initial state differs from declared identity")
        ids = tuple(event.event_id for event in self.bootstrap_events)
        if ids != tuple(sorted(set(ids))) or len(ids) > self.spec.max_events:
            raise ValueError("bootstrap events must be sorted unique and bounded")
        if content_digest(self.bootstrap_events) != self.spec.bootstrap_events_sha256:
            raise ValueError("bootstrap events differ from their declared identity")
        if any(event.knowledge_at > self.spec.initialized_at for event in self.bootstrap_events):
            raise ValueError("bootstrap cannot read observations from future knowledge")


@dataclass(frozen=True, slots=True, kw_only=True)
class ClosedEngineFrontier(ContinuousEngineRecord):
    frontier_id: str
    stream_id: str
    previous_checkpoint_sha256: str
    source_frontier_sha256: str
    knowledge_at: datetime
    events: tuple[EngineEvent, ...]

    def __post_init__(self) -> None:
        super(ClosedEngineFrontier, self).__post_init__()
        for name in ("frontier_id", "stream_id"):
            require_text(getattr(self, name), name)
        for name in ("previous_checkpoint_sha256", "source_frontier_sha256"):
            require_digest(getattr(self, name), name)
        identities = tuple(event.event_id for event in self.events)
        if identities != tuple(sorted(set(identities))) or len(identities) > 4096:
            raise ValueError("closed frontier requires sorted unique bounded events")
        if any(event.knowledge_at > self.knowledge_at for event in self.events):
            raise ValueError("closed frontier cannot contain future knowledge")


class ContinuousRiskEvidencePort(Protocol):
    """Pure preparation seam; the durable transaction authenticates its inputs."""

    def build(
        self,
        *,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        accepted_intent_ids: tuple[str, ...],
        daily_return: Decimal | None,
        drawdown: Decimal | None,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> DailyRuntimeRiskEvidence: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousDecision(ContinuousEngineRecord):
    source_state: AccountingState
    source_context: AccountingContext
    snapshot: AccountSnapshot
    batch: DailyIntentBatch
    evidence: DailyRuntimeRiskEvidence
    decision: DailyRiskDecision
    installed_commitments: tuple[Commitment, ...]
    disposition: Literal["rejected", "no_intents", "installed", "rolled_back"]

    def __post_init__(self) -> None:
        super(ContinuousDecision, self).__post_init__()
        if self.batch.snapshot_sha256 != self.snapshot.semantic_sha256:
            raise ValueError("continuous decision snapshot differs")
        if (
            self.source_state.semantic_sha256 != self.snapshot.state_sha256
            or self.source_state.account_id != self.snapshot.account_id
            or self.snapshot.point.stage != 5
            or self.source_context.point.stage != 6
            or self.source_context.point.frontier_sequence != self.snapshot.point.frontier_sequence
            or self.source_context.point.reduction_sequence
            != self.snapshot.point.reduction_sequence + 1
            or self.source_context.point.knowledge_at != self.snapshot.point.knowledge_at
            or self.source_context.approved_snapshot != self.snapshot
            or self.source_context.risk_policy_sha256
            != self.evidence.assignment.policy.semantic_sha256
        ):
            raise ValueError("continuous decision canonical preparation source differs")
        if (self.disposition == "installed") != bool(self.installed_commitments):
            raise ValueError("continuous decision installation inventory differs")
        if self.disposition == "installed" and (
            not self.decision.approved
            or tuple(item.intent_id for item in self.installed_commitments)
            != tuple(item.intent_id for item in self.batch.intents)
        ):
            raise ValueError("continuous accepted decision must bind its complete batch")
