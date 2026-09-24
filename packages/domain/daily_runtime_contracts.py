"""Versioned stateful-simulation risk inputs; records confer no effect authority.

Source references are verified against retained producer records by the caller's
account transaction. Their hashes and constructors are not broker attestations.
Legacy commitments arrive only from the reviewed, authenticated projection bridge;
this module never guesses a Commitment from legacy reservation columns.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar, Literal

from packages.domain.accounting_contracts import Commitment
from packages.domain.engine_contracts import DailyRiskDecision, DailyRiskPolicy
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    content_digest,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.reconciliation_contracts import ReconciliationHeads, ReconciliationResult

RUNTIME_POLICY_ID = "personal-daily-stateful-simulation/1"
RuntimeRole = Literal[
    "account",
    "cash",
    "clock",
    "commitments",
    "controls",
    "daily_inputs",
    "intent_registry",
    "ledger",
    "loss",
    "quotes",
    "reconciliation",
    "request_budget",
    "session",
]
RUNTIME_ROLES: tuple[RuntimeRole, ...] = (
    "account",
    "cash",
    "clock",
    "commitments",
    "controls",
    "daily_inputs",
    "intent_registry",
    "ledger",
    "loss",
    "quotes",
    "reconciliation",
    "request_budget",
    "session",
)


class RuntimeRiskRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-daily-runtime-risk/1"


def _strings(values: tuple[str, ...], name: str) -> None:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{name} must be sorted and unique")
    for value in values:
        require_text(value, name)


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeProducerSpec(RuntimeRiskRecord):
    role: RuntimeRole
    producer: VersionPin
    provider_id: str
    source_environment: str
    account_scope: str

    def __post_init__(self) -> None:
        super(RuntimeProducerSpec, self).__post_init__()
        for name in ("provider_id", "source_environment", "account_scope"):
            require_text(getattr(self, name), name)


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeProducerMap(RuntimeRiskRecord):
    producers: tuple[RuntimeProducerSpec, ...]
    version: Literal["personal-daily-runtime-producers/1"] = "personal-daily-runtime-producers/1"

    def __post_init__(self) -> None:
        super(RuntimeProducerMap, self).__post_init__()
        if tuple(item.role for item in self.producers) != RUNTIME_ROLES:
            raise ValueError("producer map must contain every exact runtime role in order")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeRiskAssignment(RuntimeRiskRecord):
    account_id: str
    account_binding_sha256: str
    generation: int
    policy: DailyRiskPolicy
    strategy: VersionPin
    configuration_sha256: str
    instrument_symbols: tuple[tuple[str, str], ...]
    producer_map_sha256: str
    effective_at: datetime
    previous_assignment_sha256: str | None = None
    enabled_for_new_exposure: bool = False
    environment: Literal["stateful_simulation"] = "stateful_simulation"
    financing_policy: Literal["cash-funded-long-only/1"] = "cash-funded-long-only/1"
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(RuntimeRiskAssignment, self).__post_init__()
        require_text(self.account_id, "account")
        for value in (
            self.account_binding_sha256,
            self.producer_map_sha256,
            self.configuration_sha256,
        ):
            require_digest(value, "assignment binding")
        _strings(tuple(item[0] for item in self.instrument_symbols), "assigned instruments")
        symbols = tuple(item[1] for item in self.instrument_symbols)
        if (
            not 1 <= len(symbols) <= 4
            or len(set(symbols)) != len(symbols)
            or any(symbol not in ("DIA", "IWM", "QQQ", "SPY") for symbol in symbols)
        ):
            raise ValueError("assignment requires the explicit supported instrument universe")
        if self.previous_assignment_sha256 is not None:
            require_digest(self.previous_assignment_sha256, "previous assignment")
        if self.generation < 1 or (self.generation == 1) != (
            self.previous_assignment_sha256 is None
        ):
            raise ValueError("assignment generation must retain its predecessor")
        if self.policy.policy_id != RUNTIME_POLICY_ID or self.policy.policy_scope != "product":
            raise ValueError("runtime assignment requires the explicit simulation daily policy")
        if self.policy.daily_loss_boundary < Decimal(
            "-0.03"
        ) or self.policy.drawdown_boundary > Decimal("0.15"):
            raise ValueError("runtime assignment may not loosen the frozen loss boundaries")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeRiskSource(RuntimeRiskRecord):
    spec: RuntimeProducerSpec
    account_id: str
    account_binding_sha256: str
    source_id: str
    source_sha256: str
    value_sha256: str
    revision: int
    source_at: datetime
    received_at: datetime
    valid_until: datetime
    status: Literal["available", "blocked", "unavailable"]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(RuntimeRiskSource, self).__post_init__()
        require_text(self.account_id, "source account")
        require_text(self.source_id, "source identity")
        require_digest(self.account_binding_sha256, "source account binding")
        require_digest(self.source_sha256, "source content")
        require_digest(self.value_sha256, "normalized source values")
        _strings(self.reasons, "source reasons")
        if not 0 <= self.revision < 2**63 or self.source_at > self.received_at:
            raise ValueError("invalid source revision or receipt chronology")
        if self.status == "available" and self.reasons:
            raise ValueError("available source cannot hide blocking reasons")
        if self.status != "available" and not self.reasons:
            raise ValueError("unavailable source must retain its reason")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeCommitmentBinding(RuntimeRiskRecord):
    account_id: str
    commitment: Commitment
    origin: Literal["legacy_phase2", "daily_runtime"]
    source_id: str
    source_sha256: str
    original_policy_sha256: str
    projection: VersionPin

    def __post_init__(self) -> None:
        super(RuntimeCommitmentBinding, self).__post_init__()
        require_text(self.account_id, "commitment account")
        require_text(self.source_id, "commitment source")
        require_digest(self.source_sha256, "commitment source content")
        require_digest(self.original_policy_sha256, "original commitment policy")
        if self.commitment.policy_sha256 != self.original_policy_sha256:
            raise ValueError("commitment projection must preserve its original policy")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeObligationInventory(RuntimeRiskRecord):
    bindings: tuple[RuntimeCommitmentBinding, ...]
    legacy_universe_sha256: str
    daily_universe_sha256: str

    def __post_init__(self) -> None:
        super(RuntimeObligationInventory, self).__post_init__()
        identifiers = tuple(item.commitment.commitment_id for item in self.bindings)
        if len(identifiers) > 4096:
            raise ValueError("obligation inventory exceeds its bound")
        _strings(identifiers, "commitment identities")
        if len({(item.origin, item.source_id) for item in self.bindings}) != len(self.bindings):
            raise ValueError("commitment source identities must be unique")
        for origin, supplied in (
            ("legacy_phase2", self.legacy_universe_sha256),
            ("daily_runtime", self.daily_universe_sha256),
        ):
            require_digest(supplied, "obligation universe")
            expected = content_digest(
                tuple(item for item in self.bindings if item.origin == origin)
            )
            if supplied != expected:
                raise ValueError("complete obligation inventory differs from its retained universe")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeRiskInputRefs(RuntimeRiskRecord):
    snapshot_sha256: str
    assignment_sha256: str
    heads: ReconciliationHeads
    phase: Literal["decision", "activation"]
    source_session: date
    execution_session: date
    sources: tuple[RuntimeRiskSource, ...]
    obligations: RuntimeObligationInventory
    reconciliation: ReconciliationResult | None
    accepted_intent_ids: tuple[str, ...]
    daily_return: Decimal | None
    drawdown: Decimal | None
    cash_restrictions: Decimal | None

    def __post_init__(self) -> None:
        super(RuntimeRiskInputRefs, self).__post_init__()
        require_digest(self.snapshot_sha256, "runtime snapshot")
        require_digest(self.assignment_sha256, "runtime assignment")
        _strings(tuple(item.spec.role for item in self.sources), "source roles")
        _strings(self.accepted_intent_ids, "accepted intent identities")
        if self.source_session >= self.execution_session:
            raise ValueError("execution must follow its source session")
        if self.cash_restrictions is not None:
            require_amount(self.cash_restrictions, "cash restrictions", nonnegative=True)


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeRiskCheck(RuntimeRiskRecord):
    rule: str
    status: Literal["pass", "fail", "unavailable"]
    sources: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(RuntimeRiskCheck, self).__post_init__()
        require_text(self.rule, "runtime rule")
        _strings(self.sources, "rule source digests")
        for value in self.sources:
            require_digest(value, "rule source")
        _strings(self.reasons, "rule reasons")
        if (self.status == "pass") != (not self.reasons):
            raise ValueError("runtime rule status must retain its exact reasons")


@dataclass(frozen=True, slots=True, kw_only=True)
class DailyRuntimeRiskEvidence(RuntimeRiskRecord):
    assignment: RuntimeRiskAssignment
    producer_map: RuntimeProducerMap
    inputs: RuntimeRiskInputRefs
    batch_sha256: str
    produced_at: datetime
    checks: tuple[RuntimeRiskCheck, ...]

    def __post_init__(self) -> None:
        super(DailyRuntimeRiskEvidence, self).__post_init__()
        require_digest(self.batch_sha256, "runtime batch")
        _strings(tuple(item.rule for item in self.checks), "runtime check identities")
        if not self.checks:
            raise ValueError("runtime evidence requires explicit validation checks")

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(sorted({reason for check in self.checks for reason in check.reasons}))

    @property
    def snapshot_sha256(self) -> str:
        return self.inputs.snapshot_sha256

    @property
    def phase(self) -> Literal["decision", "activation"]:
        return self.inputs.phase

    @property
    def source_session(self) -> date:
        return self.inputs.source_session

    @property
    def execution_session(self) -> date:
        return self.inputs.execution_session

    @property
    def accepted_intent_ids(self) -> tuple[str, ...]:
        return self.inputs.accepted_intent_ids

    @property
    def daily_return(self) -> Decimal | None:
        return self.inputs.daily_return

    @property
    def drawdown(self) -> Decimal | None:
        return self.inputs.drawdown


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeRiskAdmission(RuntimeRiskRecord):
    evidence: DailyRuntimeRiskEvidence
    decision: DailyRiskDecision
    recorded_at: datetime
    expires_at: datetime
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(RuntimeRiskAdmission, self).__post_init__()
        if (
            self.decision.policy_sha256 != self.evidence.assignment.policy.semantic_sha256
            or self.decision.evidence_sha256 != self.evidence.semantic_sha256
            or self.decision.batch.semantic_sha256 != self.evidence.batch_sha256
            or self.recorded_at < self.evidence.produced_at
            or self.expires_at > self.decision.batch.target.expires_at
        ):
            raise ValueError("runtime admission must bind exact decision, evidence and validity")
        if self.decision.approved and (
            self.evidence.reasons
            or not self.evidence.assignment.enabled_for_new_exposure
            or self.expires_at <= self.recorded_at
        ):
            raise ValueError("runtime admission cannot approve unavailable or disabled evidence")
