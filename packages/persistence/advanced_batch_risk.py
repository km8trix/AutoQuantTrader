"""Atomic Phase 5B cutover, enforcement, BatchRisk, and dispatch sidecars."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, TypeVar, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.advanced_risk_admission import (
    AdvancedBatchRiskOutcome,
    AdvancedRiskAdmissionError,
    AdvancedRiskAssessmentReference,
    AdvancedRiskBatchAdmission,
    AdvancedRiskCutoverQuiescenceFacts,
    AdvancedRiskEnforcementHead,
    AdvancedRiskEvidenceWatermark,
)
from packages.domain.advanced_risk_enforcement import (
    AdvancedRiskEnforcementError,
    advanced_risk_trip_command,
)
from packages.domain.advanced_risk_policy import (
    MODERATE_ADVANCED_RISK_INSTRUMENTS,
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
    AdvancedRiskPolicyAssessment,
    AdvancedRiskPolicyError,
    AdvancedRiskPolicyObservation,
    ModerateAdvancedRiskRuleId,
    assess_moderate_advanced_risk,
)
from packages.domain.advanced_risk_sources import (
    AdvancedRiskExposureEvidence,
    AdvancedRiskExposureSourceError,
    ProposedBatchBuyExposureSet,
    derive_advanced_risk_exposure_evidence,
    proposed_batch_buy_exposure_from_phase2,
)
from packages.domain.batch_risk import (
    ActiveCapacityUniverse,
    BatchRiskAuthority,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskError,
    VersionedBatchRiskSnapshot,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.models import OrderIntentBatch, TargetPortfolio, require_utc
from packages.domain.operational_control import (
    OperationalControlError,
    OperationalControlState,
    OperationalControlTransition,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.advanced_risk import (
    AdvancedRiskPersistenceError,
    AdvancedRiskSourceSet,
    AuthenticatedAdvancedRiskAssignment,
    SqlAdvancedRiskRepository,
    _validate_source_set_for_observation,
    load_advanced_risk_assessment_reference_in_transaction,
    load_advanced_risk_control_bindings_in_transaction,
    load_authenticated_advanced_risk_assignment_in_transaction,
    load_current_advanced_risk_assignment_in_transaction,
)
from packages.persistence.batch_risk import (
    advanced_risk_enforcement_exists_in_transaction,
    load_active_capacity_in_transaction,
    load_batch_risk_decision,
    load_batch_risk_decision_for_batch_in_transaction,
    next_account_observation_sequence_in_transaction,
    persist_batch_risk_decision_in_transaction,
)
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.operational_control import (
    apply_operational_control_command_in_transaction,
    load_operational_control_transition_in_transaction,
)
from packages.persistence.schema import (
    phase2_authorization_consumptions,
    phase2_batch_authorizations,
    phase2_submission_attempt_events,
    phase2_submission_attempts,
    phase5_advanced_risk_batch_admissions,
    phase5_advanced_risk_batch_outcomes,
    phase5_advanced_risk_enforcement_heads,
    phase5_operational_control_transitions,
)

ADVANCED_BATCH_RISK_PERSISTENCE_VERSION = "phase5b-atomic-advanced-batch-risk-v1"
ResultT = TypeVar("ResultT")


class AdvancedBatchRiskPersistenceError(RuntimeError):
    """Atomic advanced-risk composition is unavailable, corrupt, or unsafe."""


class AdvancedBatchRiskPersistenceConflict(AdvancedBatchRiskPersistenceError):
    """An immutable cutover or admission identity has conflicting semantics."""


class SqlAccountFenceValidator(Protocol):
    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


class AdvancedRiskCutoverQuiescenceVerifier(Protocol):
    """Trusted adapter proving reconciliation and strategy quiescence."""

    def verify_in_transaction(
        self,
        connection: Connection,
        *,
        receipt: AccountFenceReceipt,
        assignment: AuthenticatedAdvancedRiskAssignment,
        control: OperationalControlTransition,
        checked_at: datetime,
    ) -> AdvancedRiskCutoverQuiescenceFacts | None: ...


@dataclass(frozen=True, slots=True)
class AdvancedRiskTransactionalEvidenceContext:
    """Exact transaction heads and economic inputs presented to one producer."""

    account_id: str
    snapshot_version: str
    snapshot_sha256: str
    active_capacity_sha256: str
    intent_batch_id: str | None
    intent_batch_sha256: str | None
    target_id: str | None
    target_sha256: str | None
    proposed_exposure_sha256: str | None
    fencing_generation: int
    fence_sha256: str
    assignment_id: str
    assignment_sequence_number: int
    assignment_sha256: str
    operational_transition_id: str
    operational_transition_sha256: str
    runtime_instrument_ids: tuple[str, ...]
    pretrade_instrument_ids: tuple[str, ...]
    evaluated_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.account_id, "transactional evidence account ID"),
            (self.snapshot_version, "transactional evidence snapshot version"),
            (self.assignment_id, "transactional evidence assignment ID"),
            (
                self.operational_transition_id,
                "transactional evidence operational transition ID",
            ),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.snapshot_sha256, "transactional evidence snapshot SHA-256"),
            (
                self.active_capacity_sha256,
                "transactional evidence active-capacity SHA-256",
            ),
            (self.fence_sha256, "transactional evidence fence SHA-256"),
            (self.assignment_sha256, "transactional evidence assignment SHA-256"),
            (
                self.operational_transition_sha256,
                "transactional evidence operational transition SHA-256",
            ),
        ):
            _require_sha256(value, field_name)
        batch_values = (
            self.intent_batch_id,
            self.intent_batch_sha256,
            self.target_id,
            self.target_sha256,
        )
        if any(value is None for value in batch_values) != all(
            value is None for value in batch_values
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "transactional evidence batch and target bindings must be all-or-none"
            )
        if self.intent_batch_id is not None:
            _require_text(self.intent_batch_id, "transactional evidence batch ID")
            _require_text(self.target_id, "transactional evidence target ID")
            _require_sha256(
                self.intent_batch_sha256,
                "transactional evidence batch SHA-256",
            )
            _require_sha256(
                self.target_sha256,
                "transactional evidence target SHA-256",
            )
        if (self.proposed_exposure_sha256 is not None) != bool(self.pretrade_instrument_ids):
            raise AdvancedBatchRiskPersistenceConflict(
                "transactional proposed exposure and pretrade scope must agree"
            )
        if self.proposed_exposure_sha256 is not None:
            if self.intent_batch_id is None:
                raise AdvancedBatchRiskPersistenceConflict(
                    "transactional proposed exposure requires a nonempty batch scope"
                )
            _require_sha256(
                self.proposed_exposure_sha256,
                "transactional evidence proposed-exposure SHA-256",
            )
        if (
            type(self.fencing_generation) is not int
            or self.fencing_generation <= 0
            or type(self.assignment_sequence_number) is not int
            or self.assignment_sequence_number <= 0
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "transactional evidence fence and assignment sequences must be positive"
            )
        for instrument_ids, field_name in (
            (self.runtime_instrument_ids, "transactional runtime instrument IDs"),
            (self.pretrade_instrument_ids, "transactional pretrade instrument IDs"),
        ):
            if (
                type(instrument_ids) is not tuple
                or any(
                    type(item) is not str or item not in MODERATE_ADVANCED_RISK_INSTRUMENTS
                    for item in instrument_ids
                )
                or instrument_ids != tuple(sorted(instrument_ids))
                or len(instrument_ids) != len(set(instrument_ids))
            ):
                raise AdvancedBatchRiskPersistenceConflict(
                    f"{field_name} must be canonical policy instruments"
                )
        try:
            require_utc(
                self.evaluated_at,
                "transactional evidence evaluated_at",
            )
        except ValueError as error:
            raise AdvancedBatchRiskPersistenceConflict(str(error)) from error

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                ADVANCED_BATCH_RISK_PERSISTENCE_VERSION,
                "transactional_evidence_context",
                self.account_id,
                self.snapshot_version,
                self.snapshot_sha256,
                self.active_capacity_sha256,
                self.intent_batch_id,
                self.intent_batch_sha256,
                self.target_id,
                self.target_sha256,
                self.proposed_exposure_sha256,
                self.fencing_generation,
                self.fence_sha256,
                self.assignment_id,
                self.assignment_sequence_number,
                self.assignment_sha256,
                self.operational_transition_id,
                self.operational_transition_sha256,
                self.runtime_instrument_ids,
                self.pretrade_instrument_ids,
                self.evaluated_at,
            )
        )


@dataclass(frozen=True, slots=True)
class AdvancedRiskTransactionalEvidence:
    """Full assessments returned by the injected transactional producer."""

    context: AdvancedRiskTransactionalEvidenceContext
    runtime: AdvancedRiskAssessmentEvidence
    pretrade: AdvancedRiskAssessmentEvidence | None

    def __post_init__(self) -> None:
        if type(self.context) is not AdvancedRiskTransactionalEvidenceContext:
            raise AdvancedBatchRiskPersistenceError(
                "transactional advanced-risk evidence requires an exact context"
            )
        self.context.__post_init__()
        if type(self.runtime) is not AdvancedRiskAssessmentEvidence:
            raise AdvancedBatchRiskPersistenceError(
                "transactional advanced-risk evidence requires exact runtime evidence"
            )
        self.runtime.__post_init__()
        if self.pretrade is not None:
            if type(self.pretrade) is not AdvancedRiskAssessmentEvidence:
                raise AdvancedBatchRiskPersistenceError(
                    "transactional advanced-risk pretrade evidence must be exact"
                )
            self.pretrade.__post_init__()


class AdvancedRiskTransactionalEvidenceProducer(Protocol):
    """Trusted adapter collecting full policy evidence under the account lock."""

    def derive_in_transaction(
        self,
        reader: AdvancedRiskTransactionalReader,
        *,
        context: AdvancedRiskTransactionalEvidenceContext,
        snapshot: VersionedBatchRiskSnapshot,
        active_capacity: ActiveCapacityUniverse,
        batch: OrderIntentBatch | None,
        target: TargetPortfolio | None,
        proposed: ProposedBatchBuyExposureSet | None,
    ) -> AdvancedRiskTransactionalEvidence: ...


@dataclass(frozen=True, slots=True)
class AdvancedRiskTransactionalReader:
    """Materialized, context-bound facts read inside the caller transaction.

    This is deliberately a domain reader rather than a general SQL facade.
    Producers receive no connection, result, SQL execution, locking, or
    transaction-control capability.
    """

    context: AdvancedRiskTransactionalEvidenceContext
    assignment: AuthenticatedAdvancedRiskAssignment
    control: OperationalControlTransition
    batch: OrderIntentBatch | None
    target: TargetPortfolio | None

    def __post_init__(self) -> None:
        if type(self.context) is not AdvancedRiskTransactionalEvidenceContext:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk transactional reader requires an exact context"
            )
        self.context.__post_init__()
        if type(self.assignment) is not AuthenticatedAdvancedRiskAssignment:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk transactional reader requires an exact assignment"
            )
        if type(self.control) is not OperationalControlTransition:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk transactional reader requires an exact control"
            )
        self.control.__post_init__()
        if (
            self.assignment.assignment.account_id != self.context.account_id
            or self.assignment.assignment.assignment_id != self.context.assignment_id
            or self.assignment.assignment.sequence_number != self.context.assignment_sequence_number
            or self.assignment.envelope_sha256 != self.context.assignment_sha256
            or self.control.scope_id != self.context.account_id
            or self.control.transition_id != self.context.operational_transition_id
            or self.control.semantic_sha256 != self.context.operational_transition_sha256
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk transactional reader facts conflict with its exact context"
            )
        if (self.batch is None) != (self.target is None):
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk transactional reader batch and target must be all-or-none"
            )
        if (
            self.batch is not None
            and self.target is not None
            and (
                type(self.batch) is not OrderIntentBatch
                or type(self.target) is not TargetPortfolio
                or self.batch.intent_batch_id != self.context.intent_batch_id
                or self.batch.semantic_sha256 != self.context.intent_batch_sha256
                or self.target.target_id != self.context.target_id
                or self.target.semantic_sha256 != self.context.target_sha256
            )
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk transactional reader batch or target conflicts "
                "with its exact context"
            )

    def read_current_heads(
        self,
        *,
        context: AdvancedRiskTransactionalEvidenceContext,
    ) -> tuple[AuthenticatedAdvancedRiskAssignment, OperationalControlTransition]:
        """Return only the heads bound to the exact producer invocation."""

        self._require_exact_context(context)
        return self.assignment, self.control

    def read_batch_target(
        self,
        *,
        context: AdvancedRiskTransactionalEvidenceContext,
    ) -> tuple[OrderIntentBatch, TargetPortfolio] | None:
        """Return the exact batch/target pair, or no pair for runtime cutover."""

        self._require_exact_context(context)
        if self.batch is None or self.target is None:
            return None
        return self.batch, self.target

    def _require_exact_context(
        self,
        context: AdvancedRiskTransactionalEvidenceContext,
    ) -> None:
        if type(context) is not AdvancedRiskTransactionalEvidenceContext or context != self.context:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk transactional reader rejects substituted context"
            )


class _SnapshotTransactions(Protocol):
    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], ResultT],
    ) -> ResultT: ...


@dataclass(frozen=True, slots=True)
class AdvancedRiskAssessmentEvidence:
    """One exact assessment plus all source membership needed to reproduce it."""

    assessment: AdvancedRiskPolicyAssessment
    observations: tuple[AdvancedRiskPolicyObservation, ...]
    source_sets: tuple[AdvancedRiskSourceSet, ...]
    required_instrument_ids: tuple[str, ...]
    valid_through: datetime

    def __post_init__(self) -> None:
        if type(self.assessment) is not AdvancedRiskPolicyAssessment:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk evidence requires an exact assessment"
            )
        self.assessment.__post_init__()
        if type(self.observations) is not tuple or any(
            type(item) is not AdvancedRiskPolicyObservation for item in self.observations
        ):
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk evidence observations must be an exact tuple"
            )
        if (
            type(self.source_sets) is not tuple
            or len(self.source_sets) != len(self.observations)
            or any(type(item) is not AdvancedRiskSourceSet for item in self.source_sets)
        ):
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk evidence source sets must exactly align"
            )
        if (
            type(self.required_instrument_ids) is not tuple
            or any(type(item) is not str for item in self.required_instrument_ids)
            or self.required_instrument_ids != tuple(sorted(self.required_instrument_ids))
            or len(self.required_instrument_ids) != len(set(self.required_instrument_ids))
        ):
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk evidence instrument IDs must be sorted and unique"
            )
        try:
            require_utc(self.valid_through, "advanced-risk evidence valid_through")
        except ValueError as error:
            raise AdvancedBatchRiskPersistenceError(str(error)) from error
        if self.valid_through <= self.assessment.assessed_at:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk evidence validity must follow assessment time"
            )


def _require_text(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            f"persisted {field_name} must be non-empty trimmed text"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _optional_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_int(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise AdvancedBatchRiskPersistenceConflict(
            f"persisted {field_name} must be an exact integer"
        )
    return value


def _optional_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_int(value, field_name)


def _require_bool(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise AdvancedBatchRiskPersistenceConflict(f"persisted {field_name} must be an exact bool")
    return value


def _require_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise AdvancedBatchRiskPersistenceConflict(f"persisted {field_name} must be a datetime")
    return as_aware_utc(value)


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _instrument_ids_payload(value: tuple[str, ...]) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def _instrument_ids_from_payload(value: object, field_name: str) -> tuple[str, ...]:
    if type(value) is not str:
        raise AdvancedBatchRiskPersistenceConflict(f"persisted {field_name} must be text")
    try:
        decoded: object = json.loads(value)
    except json.JSONDecodeError as error:
        raise AdvancedBatchRiskPersistenceConflict(
            f"persisted {field_name} is not valid JSON"
        ) from error
    if type(decoded) is not list or any(type(item) is not str for item in decoded):
        raise AdvancedBatchRiskPersistenceConflict(f"persisted {field_name} must be a string array")
    result = tuple(cast(list[str], decoded))
    if (
        result != tuple(sorted(result))
        or len(result) != len(set(result))
        or _instrument_ids_payload(result) != value
    ):
        raise AdvancedBatchRiskPersistenceConflict(f"persisted {field_name} is not canonical")
    return result


def _validate_receipt(
    receipt: AccountFenceReceipt,
    *,
    fence: AccountFence,
    checked_at: datetime,
) -> None:
    if type(receipt) is not AccountFenceReceipt:
        raise AdvancedBatchRiskPersistenceError(
            "advanced batch-risk fence validator returned a non-canonical receipt"
        )
    receipt._validate()
    if receipt.fence != fence or receipt.validated_at != checked_at:
        raise AdvancedBatchRiskPersistenceConflict(
            "advanced batch-risk receipt does not bind the exact fence and instant"
        )


def _authenticate_cutover_quiescence_facts(
    facts: AdvancedRiskCutoverQuiescenceFacts | None,
    *,
    receipt: AccountFenceReceipt,
    assignment: AuthenticatedAdvancedRiskAssignment,
    control: OperationalControlTransition,
    checked_at: datetime,
) -> AdvancedRiskCutoverQuiescenceFacts:
    if type(facts) is not AdvancedRiskCutoverQuiescenceFacts:
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk cutover requires authoritative quiescence facts"
        )
    facts.__post_init__()
    if (
        facts.account_id != receipt.fence.account_id
        or facts.fencing_generation != receipt.fence.fencing_generation
        or facts.fence_sha256 != receipt.fence.semantic_sha256
        or facts.assignment_id != assignment.assignment.assignment_id
        or facts.assignment_sequence_number != assignment.assignment.sequence_number
        or facts.assignment_sha256 != assignment.envelope_sha256
        or facts.operational_transition_id != control.transition_id
        or facts.operational_transition_sha256 != control.semantic_sha256
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "authoritative cutover facts do not bind the exact current heads"
        )
    if facts.checked_at != checked_at or checked_at >= facts.expires_at:
        raise AdvancedBatchRiskPersistenceError("authoritative cutover facts are stale")
    if (
        not facts.reconciliation_clean
        or facts.working_order_ids
        or facts.unknown_order_ids
        or facts.pending_cancel_order_ids
        or facts.active_strategy_invocation_ids
    ):
        raise AdvancedBatchRiskPersistenceError(
            "authoritative reconciliation or strategy activity is not quiescent"
        )
    return facts


def _assignment_matches(
    left: AuthenticatedAdvancedRiskAssignment,
    right: AuthenticatedAdvancedRiskAssignment,
) -> bool:
    return left.assignment == right.assignment and left.envelope_sha256 == right.envelope_sha256


def _transition_for_binding(
    connection: Connection,
    *,
    account_id: str,
    transition_id: str,
    transition_sha256: str,
    bindings: Mapping[str, str],
) -> OperationalControlState:
    if bindings.get(transition_id) != transition_sha256:
        raise AdvancedBatchRiskPersistenceConflict(
            "advanced-risk control transition is not authenticated"
        )
    state = connection.scalar(
        sa.select(phase5_operational_control_transitions.c.effective_state).where(
            phase5_operational_control_transitions.c.account_id == account_id,
            phase5_operational_control_transitions.c.transition_id == transition_id,
            phase5_operational_control_transitions.c.semantic_sha256 == transition_sha256,
        )
    )
    try:
        return OperationalControlState(_require_text(state, "operational control state"))
    except ValueError as error:
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted operational control state is unsupported"
        ) from error


def _enforcement_values(head: AdvancedRiskEnforcementHead) -> dict[str, object]:
    assessment = head.assessment
    return {
        "account_id": head.account_id,
        "cutover_sequence_number": head.cutover_sequence_number,
        "assignment_id": head.assignment_id,
        "assignment_sequence_number": head.assignment_sequence_number,
        "assignment_sha256": head.assignment_sha256,
        "policy_sha256": head.policy_sha256,
        "assessment_id": assessment.assessment_id,
        "assessment_sha256": assessment.assessment_sha256,
        "cutover_observation_sequence": assessment.observation_watermark_sequence,
        "cutover_evidence_id": assessment.watermark_evidence_id,
        "cutover_evidence_sha256": assessment.watermark_evidence_sha256,
        "operational_transition_id": head.operational_transition_id,
        "operational_transition_sha256": head.operational_transition_sha256,
        "fencing_generation": head.fencing_generation,
        "lease_sha256": head.lease_sha256,
        "fence_sha256": head.fence_sha256,
        "enforcement_enabled": head.enforcement_enabled,
        "assessment_disposition": assessment.disposition.value,
        "cutover_at": head.cutover_at,
        "assessment_valid_through": assessment.valid_through,
        "updated_at": head.updated_at,
        "canonical_payload": head.canonical_json,
        "semantic_sha256": head.semantic_sha256,
    }


def load_advanced_risk_enforcement_head_in_transaction(
    connection: Connection,
    account_id: str,
) -> AdvancedRiskEnforcementHead | None:
    """Authenticate and load the one-way enforcement cutover head."""

    if not isinstance(connection, Connection):
        raise AdvancedBatchRiskPersistenceError(
            "transactional enforcement load requires a Connection"
        )
    row = (
        connection.execute(
            sa.select(phase5_advanced_risk_enforcement_heads).where(
                phase5_advanced_risk_enforcement_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    assessment = load_advanced_risk_assessment_reference_in_transaction(
        connection,
        _require_text(row["assessment_id"], "enforcement assessment ID"),
    )
    if assessment is None:
        raise AdvancedBatchRiskPersistenceConflict(
            "enforcement head lacks an authenticated assessment"
        )
    _current, control_bindings = load_advanced_risk_control_bindings_in_transaction(
        connection,
        account_id,
    )
    transition_id = _require_text(
        row["operational_transition_id"],
        "enforcement operational transition ID",
    )
    transition_sha256 = _require_text(
        row["operational_transition_sha256"],
        "enforcement operational transition SHA-256",
    )
    transition_state = _transition_for_binding(
        connection,
        account_id=account_id,
        transition_id=transition_id,
        transition_sha256=transition_sha256,
        bindings=control_bindings,
    )
    if transition_state is OperationalControlState.RUNNING:
        raise AdvancedBatchRiskPersistenceConflict(
            "enforcement cutover control binding is not non-running"
        )
    head = AdvancedRiskEnforcementHead(
        account_id=account_id,
        cutover_sequence_number=_require_int(
            row["cutover_sequence_number"],
            "enforcement cutover sequence",
        ),
        assignment_id=_require_text(row["assignment_id"], "enforcement assignment ID"),
        assignment_sequence_number=_require_int(
            row["assignment_sequence_number"],
            "enforcement assignment sequence",
        ),
        assignment_sha256=_require_text(
            row["assignment_sha256"],
            "enforcement assignment SHA-256",
        ),
        policy_sha256=_require_text(
            row["policy_sha256"],
            "enforcement policy SHA-256",
        ),
        assessment=assessment,
        operational_transition_id=transition_id,
        operational_transition_sha256=transition_sha256,
        fencing_generation=_require_int(
            row["fencing_generation"],
            "enforcement fencing generation",
        ),
        lease_sha256=_require_text(row["lease_sha256"], "enforcement lease SHA-256"),
        fence_sha256=_require_text(row["fence_sha256"], "enforcement fence SHA-256"),
        enforcement_enabled=_require_bool(
            row["enforcement_enabled"],
            "enforcement enabled",
        ),
        cutover_at=_require_datetime(row["cutover_at"], "enforcement cutover_at"),
        updated_at=_require_datetime(row["updated_at"], "enforcement updated_at"),
    )
    expected = _enforcement_values(head)
    assert_immutable(
        phase5_advanced_risk_enforcement_heads,
        account_id,
        row,
        expected,
    )
    return head


def _admission_values(admission: AdvancedRiskBatchAdmission) -> dict[str, object]:
    assessment = admission.assessment
    return {
        "admission_id": admission.admission_id,
        "account_id": admission.account_id,
        "phase2_decision_id": admission.phase2_decision_id,
        "phase2_decision_sha256": admission.phase2_decision_sha256,
        "phase2_decision_status": admission.phase2_decision_status.value,
        "fencing_generation": admission.fencing_generation,
        "lease_sha256": admission.lease_sha256,
        "fence_sha256": admission.fence_sha256,
        "assessment_id": None if assessment is None else assessment.assessment_id,
        "assessment_sha256": (None if assessment is None else assessment.assessment_sha256),
        "assignment_id": None if assessment is None else assessment.assignment_id,
        "assignment_sequence_number": (
            None if assessment is None else assessment.assignment_sequence_number
        ),
        "assignment_sha256": (None if assessment is None else assessment.assignment_sha256),
        "policy_sha256": None if assessment is None else assessment.policy_sha256,
        "observation_watermark_sequence": (
            None if assessment is None else assessment.observation_watermark_sequence
        ),
        "watermark_evidence_id": (None if assessment is None else assessment.watermark_evidence_id),
        "watermark_evidence_sha256": (
            None if assessment is None else assessment.watermark_evidence_sha256
        ),
        "operational_transition_id": admission.operational_transition_id,
        "operational_transition_sha256": admission.operational_transition_sha256,
        "assessment_mode": None if assessment is None else assessment.mode.value,
        "assessment_disposition": (None if assessment is None else assessment.disposition.value),
        "admitted": admission.admitted,
        "bound_at": admission.bound_at,
        "expires_at": admission.expires_at,
        "canonical_payload": admission.canonical_json,
        "semantic_sha256": admission.semantic_sha256,
    }


def load_advanced_risk_admission_in_transaction(
    connection: Connection,
    decision: BatchRiskDecision,
) -> AdvancedRiskBatchAdmission | None:
    """Authenticate one exact additive admission sidecar."""

    if not isinstance(connection, Connection):
        raise AdvancedBatchRiskPersistenceError(
            "transactional admission load requires a Connection"
        )
    if type(decision) is not BatchRiskDecision:
        raise AdvancedBatchRiskPersistenceError(
            "transactional admission load requires an exact Phase 2 decision"
        )
    decision.__post_init__()
    row = (
        connection.execute(
            sa.select(phase5_advanced_risk_batch_admissions).where(
                phase5_advanced_risk_batch_admissions.c.phase2_decision_id == decision.decision_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    assessment_id = _optional_text(row["assessment_id"], "admission assessment ID")
    assessment = (
        None
        if assessment_id is None
        else load_advanced_risk_assessment_reference_in_transaction(
            connection,
            assessment_id,
        )
    )
    if assessment_id is not None and assessment is None:
        raise AdvancedBatchRiskPersistenceConflict("admission lacks its authenticated assessment")
    current_control, control_bindings = load_advanced_risk_control_bindings_in_transaction(
        connection,
        decision.account_id,
    )
    transition_id = _require_text(
        row["operational_transition_id"],
        "admission operational transition ID",
    )
    transition_sha256 = _require_text(
        row["operational_transition_sha256"],
        "admission operational transition SHA-256",
    )
    state = _transition_for_binding(
        connection,
        account_id=decision.account_id,
        transition_id=transition_id,
        transition_sha256=transition_sha256,
        bindings=control_bindings,
    )
    admission = AdvancedRiskBatchAdmission(
        account_id=_require_text(row["account_id"], "admission account ID"),
        phase2_decision_id=_require_text(
            row["phase2_decision_id"],
            "admission Phase 2 decision ID",
        ),
        phase2_decision_sha256=_require_text(
            row["phase2_decision_sha256"],
            "admission Phase 2 decision SHA-256",
        ),
        phase2_decision_status=BatchRiskDecisionStatus(
            _require_text(
                row["phase2_decision_status"],
                "admission Phase 2 status",
            )
        ),
        fencing_generation=_require_int(
            row["fencing_generation"],
            "admission fencing generation",
        ),
        lease_sha256=_require_text(row["lease_sha256"], "admission lease SHA-256"),
        fence_sha256=_require_text(row["fence_sha256"], "admission fence SHA-256"),
        assessment=assessment,
        operational_transition_id=transition_id,
        operational_transition_sha256=transition_sha256,
        operational_state=state,
        admitted=_require_bool(row["admitted"], "admission admitted"),
        bound_at=_require_datetime(row["bound_at"], "admission bound_at"),
        expires_at=_require_datetime(row["expires_at"], "admission expires_at"),
    )
    if (
        admission.phase2_decision_id != decision.decision_id
        or admission.phase2_decision_sha256 != decision.semantic_sha256
        or admission.phase2_decision_status is not decision.status
        or admission.account_id != decision.account_id
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "admission conflicts with its exact Phase 2 decision"
        )
    if (
        _optional_text(row["assessment_sha256"], "admission assessment SHA-256")
        != (None if assessment is None else assessment.assessment_sha256)
        or _optional_text(row["assignment_id"], "admission assignment ID")
        != (None if assessment is None else assessment.assignment_id)
        or _optional_int(
            row["assignment_sequence_number"],
            "admission assignment sequence",
        )
        != (None if assessment is None else assessment.assignment_sequence_number)
        or _optional_text(
            row["assignment_sha256"],
            "admission assignment SHA-256",
        )
        != (None if assessment is None else assessment.assignment_sha256)
        or _optional_text(row["policy_sha256"], "admission policy SHA-256")
        != (None if assessment is None else assessment.policy_sha256)
        or _optional_int(
            row["observation_watermark_sequence"],
            "admission observation watermark sequence",
        )
        != (None if assessment is None else assessment.observation_watermark_sequence)
        or _optional_text(
            row["watermark_evidence_id"],
            "admission watermark evidence ID",
        )
        != (None if assessment is None else assessment.watermark_evidence_id)
        or _optional_text(
            row["watermark_evidence_sha256"],
            "admission watermark evidence SHA-256",
        )
        != (None if assessment is None else assessment.watermark_evidence_sha256)
        or _optional_text(row["assessment_mode"], "admission assessment mode")
        != (None if assessment is None else assessment.mode.value)
        or _optional_text(
            row["assessment_disposition"],
            "admission assessment disposition",
        )
        != (None if assessment is None else assessment.disposition.value)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "admission denormalized assessment bindings conflict"
        )
    expected = _admission_values(admission)
    assert_immutable(
        phase5_advanced_risk_batch_admissions,
        admission.admission_id,
        row,
        expected,
    )
    if current_control is None:
        raise AdvancedBatchRiskPersistenceConflict(
            "admission account lacks current operational control"
        )
    return admission


def _outcome_material(
    outcome: AdvancedBatchRiskOutcome,
    *,
    lease_sha256: str,
) -> tuple[object, ...]:
    return (
        ADVANCED_BATCH_RISK_PERSISTENCE_VERSION,
        "advanced_batch_risk_outcome_envelope",
        outcome.canonical_json,
        outcome.semantic_sha256,
        lease_sha256,
        outcome.watermark.fence_sha256,
    )


def _outcome_values(
    outcome: AdvancedBatchRiskOutcome,
    *,
    lease_sha256: str,
) -> dict[str, object]:
    watermark = outcome.watermark
    pretrade = outcome.pretrade_assessment
    decision = outcome.phase2_decision
    admission = outcome.admission
    material = _outcome_material(outcome, lease_sha256=lease_sha256)
    return {
        "outcome_id": outcome.outcome_id,
        "account_id": watermark.account_id,
        "intent_batch_id": watermark.intent_batch_id,
        "intent_batch_sha256": watermark.intent_batch_sha256,
        "watermark_id": watermark.watermark_id,
        "watermark_sha256": watermark.semantic_sha256,
        "target_id": watermark.target_id,
        "target_sha256": watermark.target_sha256,
        "snapshot_version": watermark.snapshot_version,
        "snapshot_sha256": watermark.snapshot_sha256,
        "active_capacity_sha256": watermark.active_capacity_sha256,
        "phase2_policy_sha256": watermark.phase2_policy_sha256,
        "advanced_risk_policy_sha256": outcome.runtime_assessment.policy_sha256,
        "fencing_generation": watermark.fencing_generation,
        "lease_sha256": lease_sha256,
        "fence_sha256": watermark.fence_sha256,
        "runtime_instrument_ids_payload": _instrument_ids_payload(watermark.runtime_instrument_ids),
        "pretrade_instrument_ids_payload": _instrument_ids_payload(
            watermark.pretrade_instrument_ids
        ),
        "evaluated_at": watermark.evaluated_at,
        "assignment_id": outcome.assignment_id,
        "assignment_sequence_number": outcome.assignment_sequence_number,
        "assignment_sha256": outcome.assignment_sha256,
        "runtime_assessment_id": outcome.runtime_assessment.assessment_id,
        "runtime_assessment_sha256": outcome.runtime_assessment.assessment_sha256,
        "pretrade_assessment_id": (None if pretrade is None else pretrade.assessment_id),
        "pretrade_assessment_sha256": (None if pretrade is None else pretrade.assessment_sha256),
        "pre_control_transition_id": outcome.pre_control_transition_id,
        "pre_control_transition_sha256": outcome.pre_control_transition_sha256,
        "final_control_transition_id": outcome.final_control_transition_id,
        "final_control_transition_sha256": outcome.final_control_transition_sha256,
        "final_control_state": outcome.final_control_state.value,
        "phase2_decision_id": None if decision is None else decision.decision_id,
        "phase2_decision_sha256": (None if decision is None else decision.semantic_sha256),
        "admission_id": None if admission is None else admission.admission_id,
        "admission_sha256": (None if admission is None else admission.semantic_sha256),
        "outcome_sha256": outcome.semantic_sha256,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": _sha256(material),
    }


def load_advanced_batch_risk_outcome_in_transaction(
    connection: Connection,
    intent_batch_id: str,
) -> AdvancedBatchRiskOutcome | None:
    """Authenticate one complete atomic outcome by its batch identity."""

    if not isinstance(connection, Connection):
        raise AdvancedBatchRiskPersistenceError("transactional outcome load requires a Connection")
    _require_text(intent_batch_id, "advanced-risk outcome intent batch ID")
    row = (
        connection.execute(
            sa.select(phase5_advanced_risk_batch_outcomes).where(
                phase5_advanced_risk_batch_outcomes.c.intent_batch_id == intent_batch_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    account_id = _require_text(row["account_id"], "outcome account ID")
    watermark = AdvancedRiskEvidenceWatermark(
        account_id=account_id,
        intent_batch_id=_require_text(
            row["intent_batch_id"],
            "outcome intent batch ID",
        ),
        intent_batch_sha256=_require_text(
            row["intent_batch_sha256"],
            "outcome intent batch SHA-256",
        ),
        target_id=_require_text(row["target_id"], "outcome target ID"),
        target_sha256=_require_text(
            row["target_sha256"],
            "outcome target SHA-256",
        ),
        snapshot_version=_require_text(
            row["snapshot_version"],
            "outcome snapshot version",
        ),
        snapshot_sha256=_require_text(
            row["snapshot_sha256"],
            "outcome snapshot SHA-256",
        ),
        active_capacity_sha256=_require_text(
            row["active_capacity_sha256"],
            "outcome active-capacity SHA-256",
        ),
        phase2_policy_sha256=_require_text(
            row["phase2_policy_sha256"],
            "outcome Phase 2 policy SHA-256",
        ),
        fencing_generation=_require_int(
            row["fencing_generation"],
            "outcome fencing generation",
        ),
        fence_sha256=_require_text(
            row["fence_sha256"],
            "outcome fence SHA-256",
        ),
        runtime_instrument_ids=_instrument_ids_from_payload(
            row["runtime_instrument_ids_payload"],
            "outcome runtime instrument IDs",
        ),
        pretrade_instrument_ids=_instrument_ids_from_payload(
            row["pretrade_instrument_ids_payload"],
            "outcome pretrade instrument IDs",
        ),
        evaluated_at=_require_datetime(
            row["evaluated_at"],
            "outcome evaluated_at",
        ),
    )
    if (
        _require_text(row["watermark_id"], "outcome watermark ID") != watermark.watermark_id
        or _require_text(
            row["watermark_sha256"],
            "outcome watermark SHA-256",
        )
        != watermark.semantic_sha256
    ):
        raise AdvancedBatchRiskPersistenceConflict("persisted outcome watermark identity conflicts")
    assignment = load_authenticated_advanced_risk_assignment_in_transaction(
        connection,
        _require_text(row["assignment_id"], "outcome assignment ID"),
    )
    if assignment is None:
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome lacks an authenticated assignment"
        )
    assignment_sequence_number = _require_int(
        row["assignment_sequence_number"],
        "outcome assignment sequence",
    )
    assignment_sha256 = _require_text(
        row["assignment_sha256"],
        "outcome assignment SHA-256",
    )
    if (
        assignment.assignment.account_id != account_id
        or assignment.assignment.sequence_number != assignment_sequence_number
        or assignment.envelope_sha256 != assignment_sha256
        or assignment.assignment.policy_sha256
        != _require_text(
            row["advanced_risk_policy_sha256"],
            "outcome advanced-risk policy SHA-256",
        )
    ):
        raise AdvancedBatchRiskPersistenceConflict("persisted outcome assignment bindings conflict")
    runtime = load_advanced_risk_assessment_reference_in_transaction(
        connection,
        _require_text(
            row["runtime_assessment_id"],
            "outcome runtime assessment ID",
        ),
    )
    if runtime is None or runtime.assessment_sha256 != _require_text(
        row["runtime_assessment_sha256"],
        "outcome runtime assessment SHA-256",
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome runtime assessment is not authenticated"
        )
    pretrade_id = _optional_text(
        row["pretrade_assessment_id"],
        "outcome pretrade assessment ID",
    )
    pretrade = (
        None
        if pretrade_id is None
        else load_advanced_risk_assessment_reference_in_transaction(
            connection,
            pretrade_id,
        )
    )
    if (
        (pretrade_id is None)
        != (
            _optional_text(
                row["pretrade_assessment_sha256"],
                "outcome pretrade assessment SHA-256",
            )
            is None
        )
        or (
            pretrade is not None
            and pretrade.assessment_sha256
            != _require_text(
                row["pretrade_assessment_sha256"],
                "outcome pretrade assessment SHA-256",
            )
        )
        or (pretrade_id is not None and pretrade is None)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome pretrade assessment is not authenticated"
        )
    _current_control, control_bindings = load_advanced_risk_control_bindings_in_transaction(
        connection,
        account_id,
    )
    pre_control_id = _require_text(
        row["pre_control_transition_id"],
        "outcome pre-control transition ID",
    )
    pre_control_sha256 = _require_text(
        row["pre_control_transition_sha256"],
        "outcome pre-control transition SHA-256",
    )
    final_control_id = _require_text(
        row["final_control_transition_id"],
        "outcome final-control transition ID",
    )
    final_control_sha256 = _require_text(
        row["final_control_transition_sha256"],
        "outcome final-control transition SHA-256",
    )
    pre_state = _transition_for_binding(
        connection,
        account_id=account_id,
        transition_id=pre_control_id,
        transition_sha256=pre_control_sha256,
        bindings=control_bindings,
    )
    final_state = _transition_for_binding(
        connection,
        account_id=account_id,
        transition_id=final_control_id,
        transition_sha256=final_control_sha256,
        bindings=control_bindings,
    )
    if pre_state is not OperationalControlState.RUNNING or final_state.value != _require_text(
        row["final_control_state"], "outcome final state"
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome operational-control bindings conflict"
        )
    final_transition = load_operational_control_transition_in_transaction(
        connection,
        account_id,
        final_control_id,
    )
    if final_transition is None or final_transition.semantic_sha256 != final_control_sha256:
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome final control transition is not authenticated"
        )
    if runtime.disposition in {
        AdvancedRiskDisposition.PAUSE,
        AdvancedRiskDisposition.HALT,
    }:
        final_row = (
            connection.execute(
                sa.select(phase5_operational_control_transitions).where(
                    phase5_operational_control_transitions.c.account_id == account_id,
                    phase5_operational_control_transitions.c.transition_id == final_control_id,
                )
            )
            .mappings()
            .one()
        )
        if (
            _require_text(
                final_row["reason_evidence_sha256"],
                "outcome trip assessment evidence SHA-256",
            )
            != runtime.assessment_sha256
            or _require_text(
                final_row["command_kind"],
                "outcome trip command kind",
            )
            != "trip"
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "persisted outcome trip does not bind the runtime assessment"
            )
    decision_id = _optional_text(
        row["phase2_decision_id"],
        "outcome Phase 2 decision ID",
    )
    decision = None if decision_id is None else load_batch_risk_decision(connection, decision_id)
    if (
        (decision_id is None)
        != (
            _optional_text(
                row["phase2_decision_sha256"],
                "outcome Phase 2 decision SHA-256",
            )
            is None
        )
        or (
            decision is not None
            and decision.semantic_sha256
            != _require_text(
                row["phase2_decision_sha256"],
                "outcome Phase 2 decision SHA-256",
            )
        )
        or (decision_id is not None and decision is None)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome Phase 2 decision is not authenticated"
        )
    admission = (
        None
        if decision is None
        else load_advanced_risk_admission_in_transaction(
            connection,
            decision,
        )
    )
    if (admission is None) != (
        _optional_text(row["admission_id"], "outcome admission ID") is None
        and _optional_text(
            row["admission_sha256"],
            "outcome admission SHA-256",
        )
        is None
    ) or (
        admission is not None
        and (
            admission.admission_id != _require_text(row["admission_id"], "outcome admission ID")
            or admission.semantic_sha256
            != _require_text(
                row["admission_sha256"],
                "outcome admission SHA-256",
            )
        )
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted outcome admission is not authenticated"
        )
    outcome = AdvancedBatchRiskOutcome(
        watermark=watermark,
        assignment_id=assignment.assignment.assignment_id,
        assignment_sequence_number=assignment_sequence_number,
        assignment_sha256=assignment_sha256,
        runtime_assessment=runtime,
        pretrade_assessment=pretrade,
        pre_control_transition_id=pre_control_id,
        pre_control_transition_sha256=pre_control_sha256,
        final_control_transition_id=final_control_id,
        final_control_transition_sha256=final_control_sha256,
        final_control_state=final_state,
        phase2_decision=decision,
        admission=admission,
    )
    expected = _outcome_values(
        outcome,
        lease_sha256=_require_text(
            row["lease_sha256"],
            "outcome lease SHA-256",
        ),
    )
    try:
        assert_immutable(
            phase5_advanced_risk_batch_outcomes,
            outcome.outcome_id,
            row,
            expected,
        )
    except ImmutableFactConflict as error:
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted advanced-risk outcome conflicts"
        ) from error
    return outcome


def _verify_advanced_batch_risk_integrity(connection: Connection) -> None:
    """Authenticate every cutover head and complete atomic outcome at startup."""

    if not isinstance(connection, Connection):
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk integrity verification requires a Connection"
        )
    try:
        account_ids = tuple(
            connection.execute(
                sa.select(phase5_advanced_risk_enforcement_heads.c.account_id).order_by(
                    phase5_advanced_risk_enforcement_heads.c.account_id
                )
            ).scalars()
        )
        for account_id in account_ids:
            if (
                load_advanced_risk_enforcement_head_in_transaction(
                    connection,
                    _require_text(account_id, "enforcement account ID"),
                )
                is None
            ):  # pragma: no cover - selected from the same transaction
                raise AdvancedBatchRiskPersistenceConflict(
                    "persisted enforcement head disappeared during verification"
                )

        intent_batch_ids = tuple(
            connection.execute(
                sa.select(phase5_advanced_risk_batch_outcomes.c.intent_batch_id).order_by(
                    phase5_advanced_risk_batch_outcomes.c.intent_batch_id
                )
            ).scalars()
        )
        for intent_batch_id in intent_batch_ids:
            if (
                load_advanced_batch_risk_outcome_in_transaction(
                    connection,
                    _require_text(intent_batch_id, "outcome intent batch ID"),
                )
                is None
            ):  # pragma: no cover - selected from the same transaction
                raise AdvancedBatchRiskPersistenceConflict(
                    "persisted advanced-risk outcome disappeared during verification"
                )

        orphan_admission_id = connection.execute(
            sa.select(phase5_advanced_risk_batch_admissions.c.admission_id)
            .select_from(
                phase5_advanced_risk_batch_admissions.outerjoin(
                    phase5_advanced_risk_batch_outcomes,
                    phase5_advanced_risk_batch_outcomes.c.admission_id
                    == phase5_advanced_risk_batch_admissions.c.admission_id,
                )
            )
            .where(phase5_advanced_risk_batch_outcomes.c.outcome_id.is_(None))
            .limit(1)
        ).scalar_one_or_none()
        if orphan_admission_id is not None:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk admission lacks its atomic outcome"
            )
    except AdvancedBatchRiskPersistenceError:
        raise
    except (
        AccountCoordinatorError,
        AdvancedRiskAdmissionError,
        AdvancedRiskEnforcementError,
        AdvancedRiskPersistenceError,
        BatchRiskError,
        ImmutableFactConflict,
        OperationalControlError,
    ) as error:
        raise AdvancedBatchRiskPersistenceConflict(
            "persisted advanced-risk cutover or outcome failed authentication"
        ) from error


def authenticate_advanced_risk_admission_for_dispatch_in_transaction(
    connection: Connection,
    *,
    decision: BatchRiskDecision,
    receipt: AccountFenceReceipt,
    checked_at: datetime,
) -> AdvancedRiskBatchAdmission | None:
    """Require a fresh exact sidecar when an enforcement head exists."""

    if not advanced_risk_enforcement_exists_in_transaction(
        connection,
        decision.account_id,
    ):
        return None
    head = load_advanced_risk_enforcement_head_in_transaction(
        connection,
        decision.account_id,
    )
    if head is None:  # pragma: no cover - presence checked immediately above
        raise AdvancedBatchRiskPersistenceConflict("advanced-risk enforcement head disappeared")
    admission = load_advanced_risk_admission_in_transaction(connection, decision)
    if admission is None:
        raise AdvancedBatchRiskPersistenceError(
            "post-cutover dispatch requires an advanced-risk admission sidecar"
        )
    outcome = load_advanced_batch_risk_outcome_in_transaction(
        connection,
        decision.intent_batch_id,
    )
    if outcome is None or outcome.phase2_decision != decision or outcome.admission != admission:
        raise AdvancedBatchRiskPersistenceError(
            "post-cutover dispatch requires the exact atomic advanced-risk outcome"
        )
    assignment = load_current_advanced_risk_assignment_in_transaction(
        connection,
        decision.account_id,
    )
    control, _bindings = load_advanced_risk_control_bindings_in_transaction(
        connection,
        decision.account_id,
    )
    if (
        not admission.admitted
        or admission.assessment is None
        or checked_at >= admission.expires_at
        or receipt.validated_at != checked_at
        or admission.fencing_generation != receipt.fence.fencing_generation
        or admission.lease_sha256 != receipt.lease_sha256
        or admission.fence_sha256 != receipt.fence.semantic_sha256
        or assignment is None
        or admission.assessment.assignment_id != assignment.assignment.assignment_id
        or admission.assessment.assignment_sequence_number != assignment.assignment.sequence_number
        or admission.assessment.assignment_sha256 != assignment.envelope_sha256
        or control is None
        or control.effective_state is not OperationalControlState.RUNNING
        or admission.operational_transition_id != control.transition_id
        or admission.operational_transition_sha256 != control.semantic_sha256
    ):
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk admission is stale, non-admitted, or no longer exact"
        )
    return admission


def _assert_cutover_quiescent(
    connection: Connection,
    *,
    account_id: str,
    checked_at: datetime,
) -> None:
    observation_sequence = next_account_observation_sequence_in_transaction(
        connection,
        account_id,
    )
    capacity = load_active_capacity_in_transaction(
        connection,
        account_id,
        as_of=checked_at,
        observation_sequence=observation_sequence,
    )
    if capacity.reservations:
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk cutover requires no active reservations"
        )
    current_event = (
        sa.select(
            phase2_submission_attempt_events.c.attempt_id,
            sa.func.max(phase2_submission_attempt_events.c.sequence_number).label(
                "sequence_number"
            ),
        )
        .select_from(
            phase2_submission_attempt_events.join(
                phase2_submission_attempts,
                phase2_submission_attempts.c.attempt_id
                == phase2_submission_attempt_events.c.attempt_id,
            )
        )
        .where(phase2_submission_attempts.c.account_id == account_id)
        .group_by(phase2_submission_attempt_events.c.attempt_id)
        .subquery()
    )
    unknown = connection.scalar(
        sa.select(sa.func.count())
        .select_from(phase2_submission_attempt_events)
        .join(
            current_event,
            sa.and_(
                current_event.c.attempt_id == phase2_submission_attempt_events.c.attempt_id,
                current_event.c.sequence_number
                == phase2_submission_attempt_events.c.sequence_number,
            ),
        )
        .where(phase2_submission_attempt_events.c.state == "unknown")
    )
    if unknown != 0:
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk cutover requires no unresolved UNKNOWN submissions"
        )
    unconsumed = connection.scalar(
        sa.select(sa.func.count())
        .select_from(
            phase2_batch_authorizations.outerjoin(
                phase2_authorization_consumptions,
                phase2_authorization_consumptions.c.authorization_id
                == phase2_batch_authorizations.c.authorization_id,
            )
        )
        .where(
            phase2_batch_authorizations.c.account_id == account_id,
            phase2_batch_authorizations.c.expires_at > checked_at,
            phase2_authorization_consumptions.c.authorization_id.is_(None),
        )
    )
    if unconsumed != 0:
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk cutover requires no unconsumed unexpired approvals"
        )
    if connection.scalar(
        sa.select(sa.func.count())
        .select_from(phase5_advanced_risk_batch_admissions)
        .where(phase5_advanced_risk_batch_admissions.c.account_id == account_id)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "advanced-risk admissions cannot predate enforcement cutover"
        )
    if connection.scalar(
        sa.select(sa.func.count())
        .select_from(phase5_advanced_risk_batch_outcomes)
        .where(phase5_advanced_risk_batch_outcomes.c.account_id == account_id)
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "advanced-risk outcomes cannot predate enforcement cutover"
        )


def _required_runtime_instruments(
    snapshot: VersionedBatchRiskSnapshot,
    active_capacity: ActiveCapacityUniverse,
    batch: OrderIntentBatch,
) -> tuple[str, ...]:
    instruments = {
        position.instrument_id
        for position in snapshot.portfolio_snapshot.positions
        if position.quantity > 0
    }
    instruments.update(
        authorization.instrument_id for authorization in active_capacity.authorizations
    )
    instruments.update(intent.instrument_id for intent in batch.intents)
    return tuple(sorted(instruments))


def _required_pretrade_instruments(batch: OrderIntentBatch) -> tuple[str, ...]:
    return tuple(sorted({intent.instrument_id for intent in batch.intents}))


def _build_watermark(
    *,
    snapshot: VersionedBatchRiskSnapshot,
    active_capacity_sha256: str,
    batch: OrderIntentBatch,
    target: TargetPortfolio,
    authority: BatchRiskAuthority,
    receipt: AccountFenceReceipt,
    runtime_instrument_ids: tuple[str, ...],
    pretrade_instrument_ids: tuple[str, ...],
    evaluated_at: datetime,
) -> AdvancedRiskEvidenceWatermark:
    return AdvancedRiskEvidenceWatermark(
        account_id=snapshot.account_id,
        intent_batch_id=batch.intent_batch_id,
        intent_batch_sha256=batch.semantic_sha256,
        target_id=target.target_id,
        target_sha256=target.semantic_sha256,
        snapshot_version=snapshot.version,
        snapshot_sha256=snapshot.semantic_sha256,
        active_capacity_sha256=active_capacity_sha256,
        phase2_policy_sha256=authority.limits.semantic_sha256,
        fencing_generation=receipt.fence.fencing_generation,
        fence_sha256=receipt.fence.semantic_sha256,
        runtime_instrument_ids=runtime_instrument_ids,
        pretrade_instrument_ids=pretrade_instrument_ids,
        evaluated_at=evaluated_at,
    )


_EXPOSURE_RULE_IDS = frozenset(
    {
        ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO,
        ModerateAdvancedRiskRuleId.GROSS_LEVERAGE_MULTIPLE,
        ModerateAdvancedRiskRuleId.ABS_NET_LEVERAGE_MULTIPLE,
        ModerateAdvancedRiskRuleId.CASH_ACCOUNT_INTEGRITY_UNHEALTHY,
    }
)


def _transactional_evidence_context(
    *,
    snapshot: VersionedBatchRiskSnapshot,
    active_capacity: ActiveCapacityUniverse,
    batch: OrderIntentBatch | None,
    target: TargetPortfolio | None,
    proposed: ProposedBatchBuyExposureSet | None,
    receipt: AccountFenceReceipt,
    assignment: AuthenticatedAdvancedRiskAssignment,
    control: OperationalControlTransition,
    runtime_instrument_ids: tuple[str, ...],
    pretrade_instrument_ids: tuple[str, ...],
    evaluated_at: datetime,
) -> AdvancedRiskTransactionalEvidenceContext:
    if (batch is None) != (target is None):
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional evidence batch and target must be supplied together"
        )
    return AdvancedRiskTransactionalEvidenceContext(
        account_id=snapshot.account_id,
        snapshot_version=snapshot.version,
        snapshot_sha256=snapshot.semantic_sha256,
        active_capacity_sha256=active_capacity.semantic_sha256,
        intent_batch_id=None if batch is None else batch.intent_batch_id,
        intent_batch_sha256=None if batch is None else batch.semantic_sha256,
        target_id=None if target is None else target.target_id,
        target_sha256=None if target is None else target.semantic_sha256,
        proposed_exposure_sha256=None if proposed is None else proposed.semantic_sha256,
        fencing_generation=receipt.fence.fencing_generation,
        fence_sha256=receipt.fence.semantic_sha256,
        assignment_id=assignment.assignment.assignment_id,
        assignment_sequence_number=assignment.assignment.sequence_number,
        assignment_sha256=assignment.envelope_sha256,
        operational_transition_id=control.transition_id,
        operational_transition_sha256=control.semantic_sha256,
        runtime_instrument_ids=runtime_instrument_ids,
        pretrade_instrument_ids=pretrade_instrument_ids,
        evaluated_at=evaluated_at,
    )


def _expected_exposure_observations(
    exposure: AdvancedRiskExposureEvidence,
    *,
    required_instrument_ids: tuple[str, ...],
) -> tuple[AdvancedRiskPolicyObservation, ...]:
    required = frozenset(required_instrument_ids)
    return tuple(
        observation
        for observation in exposure.observations
        if (
            observation.rule_id is not ModerateAdvancedRiskRuleId.INSTRUMENT_CONCENTRATION_RATIO
            or observation.subject_id in required
        )
    )


def _authenticate_produced_assessment(
    evidence: AdvancedRiskAssessmentEvidence,
    *,
    exposure: AdvancedRiskExposureEvidence,
    mode: AdvancedRiskEvaluationMode,
    required_instrument_ids: tuple[str, ...],
    context: AdvancedRiskTransactionalEvidenceContext,
) -> None:
    evidence.__post_init__()
    if (
        evidence.assessment.account_id != context.account_id
        or evidence.assessment.mode is not mode
        or evidence.assessment.assessed_at != context.evaluated_at
        or evidence.required_instrument_ids != required_instrument_ids
    ):
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional producer assessment scope conflicts with exact inputs"
        )
    for observation, source_set in zip(
        evidence.observations,
        evidence.source_sets,
        strict=True,
    ):
        try:
            _validate_source_set_for_observation(observation, source_set)
        except AdvancedRiskPersistenceError as error:
            raise AdvancedBatchRiskPersistenceConflict(
                "transactional producer source membership does not authenticate"
            ) from error
    expected_observations = _expected_exposure_observations(
        exposure,
        required_instrument_ids=required_instrument_ids,
    )
    actual_pairs = tuple(
        (observation, source_set)
        for observation, source_set in zip(
            evidence.observations,
            evidence.source_sets,
            strict=True,
        )
        if observation.rule_id in _EXPOSURE_RULE_IDS
    )
    expected_source_set = AdvancedRiskSourceSet(
        members=exposure.source_members,
        source_count=len(exposure.source_members),
    )
    expected_pairs = tuple(
        (observation, expected_source_set) for observation in expected_observations
    )
    if actual_pairs != expected_pairs:
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional producer exposure evidence does not derive from the "
            "exact snapshot, capacity, proposed batch, and fence"
        )
    try:
        expected_assessment = assess_moderate_advanced_risk(
            evidence.observations,
            mode=mode,
            required_instrument_ids=required_instrument_ids,
            assessed_at=context.evaluated_at,
        )
    except AdvancedRiskPolicyError as error:
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional producer does not provide exact full-policy coverage"
        ) from error
    if expected_assessment != evidence.assessment:
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional producer assessment conflicts with its exact evidence"
        )


def _authenticate_transactional_evidence(
    produced: AdvancedRiskTransactionalEvidence,
    *,
    expected_context: AdvancedRiskTransactionalEvidenceContext,
    snapshot: VersionedBatchRiskSnapshot,
    active_capacity: ActiveCapacityUniverse,
    proposed: ProposedBatchBuyExposureSet | None,
) -> tuple[AdvancedRiskAssessmentEvidence, AdvancedRiskAssessmentEvidence | None]:
    if type(produced) is not AdvancedRiskTransactionalEvidence:
        raise AdvancedBatchRiskPersistenceError(
            "advanced-risk producer returned non-canonical transactional evidence"
        )
    produced.__post_init__()
    if produced.context != expected_context:
        raise AdvancedBatchRiskPersistenceConflict(
            "advanced-risk producer replayed a different transaction context"
        )
    try:
        runtime_exposure = derive_advanced_risk_exposure_evidence(
            snapshot=snapshot,
            active_capacity=active_capacity,
            proposed=None,
            fence_token=expected_context.fencing_generation,
            fence_sha256=expected_context.fence_sha256,
            observed_at=expected_context.evaluated_at,
            recorded_at=expected_context.evaluated_at,
        )
        pretrade_exposure = (
            None
            if proposed is None
            else derive_advanced_risk_exposure_evidence(
                snapshot=snapshot,
                active_capacity=active_capacity,
                proposed=proposed,
                fence_token=expected_context.fencing_generation,
                fence_sha256=expected_context.fence_sha256,
                observed_at=expected_context.evaluated_at,
                recorded_at=expected_context.evaluated_at,
            )
        )
    except AdvancedRiskExposureSourceError as error:
        raise AdvancedBatchRiskPersistenceError(
            "exact transactional exposure derivation is unavailable"
        ) from error
    _authenticate_produced_assessment(
        produced.runtime,
        exposure=runtime_exposure,
        mode=AdvancedRiskEvaluationMode.RUNTIME,
        required_instrument_ids=expected_context.runtime_instrument_ids,
        context=expected_context,
    )
    if expected_context.pretrade_instrument_ids:
        if produced.pretrade is None or pretrade_exposure is None:
            raise AdvancedBatchRiskPersistenceConflict(
                "transactional producer omitted required pretrade evidence"
            )
        _authenticate_produced_assessment(
            produced.pretrade,
            exposure=pretrade_exposure,
            mode=AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE,
            required_instrument_ids=expected_context.pretrade_instrument_ids,
            context=expected_context,
        )
    elif produced.pretrade is not None:
        raise AdvancedBatchRiskPersistenceConflict(
            "transactional producer fabricated pretrade evidence without exposure"
        )
    return produced.runtime, produced.pretrade


class SqlAdvancedBatchRiskRepository:
    """Own the one atomic post-cutover advanced-risk authorization path."""

    __slots__ = (
        "_advanced",
        "_authority",
        "_clock",
        "_coordinator",
        "_cutover_verifier",
        "_engine",
        "_evidence_producer",
    )

    def __init__(
        self,
        *,
        engine: Engine,
        authority: BatchRiskAuthority,
        coordinator: SqlAccountFenceValidator,
        clock: Clock,
        cutover_verifier: AdvancedRiskCutoverQuiescenceVerifier | None = None,
        evidence_producer: AdvancedRiskTransactionalEvidenceProducer | None = None,
    ) -> None:
        if not isinstance(engine, Engine):
            raise AdvancedBatchRiskPersistenceError(
                "advanced batch-risk repository requires an Engine"
            )
        if type(authority) is not BatchRiskAuthority:
            raise AdvancedBatchRiskPersistenceError(
                "advanced batch-risk repository requires exact Phase 2 authority"
            )
        if not callable(getattr(authority.snapshots, "transact", None)):
            raise AdvancedBatchRiskPersistenceError(
                "advanced batch-risk requires transactional snapshots"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise AdvancedBatchRiskPersistenceError(
                "advanced batch-risk requires a SQL fence validator"
            )
        if not callable(getattr(clock, "now", None)):
            raise AdvancedBatchRiskPersistenceError("advanced batch-risk requires a trusted clock")
        if cutover_verifier is not None and not callable(
            getattr(cutover_verifier, "verify_in_transaction", None)
        ):
            raise AdvancedBatchRiskPersistenceError("advanced-risk cutover verifier is unsupported")
        if evidence_producer is not None and not callable(
            getattr(evidence_producer, "derive_in_transaction", None)
        ):
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk transactional evidence producer is unsupported"
            )
        self._engine = engine
        self._authority = authority
        self._coordinator = coordinator
        self._clock = clock
        self._cutover_verifier = cutover_verifier
        self._evidence_producer = evidence_producer
        self._advanced = SqlAdvancedRiskRepository(
            engine=engine,
            coordinator=coordinator,
            clock=clock,
        )

    def _now(self) -> datetime:
        value = self._clock.now()
        try:
            require_utc(value, "advanced batch-risk trusted time")
        except ValueError as error:
            raise AdvancedBatchRiskPersistenceError(str(error)) from error
        return value

    def enable_enforcement(
        self,
        *,
        fence: AccountFence,
    ) -> AdvancedRiskEnforcementHead:
        """Commit the one-way cutover only while the account is fully quiesced."""

        if type(fence) is not AccountFence:
            raise AdvancedBatchRiskPersistenceError("advanced-risk cutover requires an exact fence")
        verifier = self._cutover_verifier
        if verifier is None:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk cutover requires an authoritative quiescence verifier"
            )
        producer = self._evidence_producer
        if producer is None:
            raise AdvancedBatchRiskPersistenceError(
                "advanced-risk cutover requires a transactional evidence producer"
            )
        snapshots = cast(_SnapshotTransactions, self._authority.snapshots)

        def operation(snapshot: VersionedBatchRiskSnapshot) -> AdvancedRiskEnforcementHead:
            if type(snapshot) is not VersionedBatchRiskSnapshot:
                raise AdvancedBatchRiskPersistenceError(
                    "advanced-risk cutover snapshot is non-canonical"
                )
            snapshot._validate()
            cutover_at = self._now()
            if snapshot.account_id != fence.account_id:
                raise AdvancedBatchRiskPersistenceConflict(
                    "advanced-risk cutover snapshot account conflicts with its fence"
                )
            with _write_transaction(self._engine) as connection:
                receipt = self._coordinator.revalidate_in_transaction(
                    connection,
                    fence,
                    checked_at=cutover_at,
                )
                _validate_receipt(receipt, fence=fence, checked_at=cutover_at)
                control, _bindings = load_advanced_risk_control_bindings_in_transaction(
                    connection,
                    fence.account_id,
                )
                assignment = load_current_advanced_risk_assignment_in_transaction(
                    connection,
                    fence.account_id,
                )
                if control is None or control.effective_state is OperationalControlState.RUNNING:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced-risk cutover requires an exact non-RUNNING control head"
                    )
                if assignment is None:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced-risk cutover requires a current assignment"
                    )
                quiescence_facts = _authenticate_cutover_quiescence_facts(
                    verifier.verify_in_transaction(
                        connection,
                        receipt=receipt,
                        assignment=assignment,
                        control=control,
                        checked_at=cutover_at,
                    ),
                    receipt=receipt,
                    assignment=assignment,
                    control=control,
                    checked_at=cutover_at,
                )
                existing = load_advanced_risk_enforcement_head_in_transaction(
                    connection,
                    fence.account_id,
                )
                if existing is None:
                    _assert_cutover_quiescent(
                        connection,
                        account_id=fence.account_id,
                        checked_at=cutover_at,
                    )
                observation_sequence = next_account_observation_sequence_in_transaction(
                    connection,
                    fence.account_id,
                )
                active_capacity = load_active_capacity_in_transaction(
                    connection,
                    fence.account_id,
                    as_of=cutover_at,
                    observation_sequence=observation_sequence,
                )
                context = _transactional_evidence_context(
                    snapshot=snapshot,
                    active_capacity=active_capacity,
                    batch=None,
                    target=None,
                    proposed=None,
                    receipt=receipt,
                    assignment=assignment,
                    control=control,
                    runtime_instrument_ids=MODERATE_ADVANCED_RISK_INSTRUMENTS,
                    pretrade_instrument_ids=(),
                    evaluated_at=cutover_at,
                )
                runtime, pretrade = _authenticate_transactional_evidence(
                    producer.derive_in_transaction(
                        AdvancedRiskTransactionalReader(
                            context=context,
                            assignment=assignment,
                            control=control,
                            batch=None,
                            target=None,
                        ),
                        context=context,
                        snapshot=snapshot,
                        active_capacity=active_capacity,
                        batch=None,
                        target=None,
                        proposed=None,
                    ),
                    expected_context=context,
                    snapshot=snapshot,
                    active_capacity=active_capacity,
                    proposed=None,
                )
                if (
                    pretrade is not None
                    or runtime.assessment.disposition is not AdvancedRiskDisposition.NONE
                    or runtime.required_instrument_ids != MODERATE_ADVANCED_RISK_INSTRUMENTS
                ):
                    raise AdvancedBatchRiskPersistenceError(
                        "cutover requires transaction-derived full-policy RUNTIME NONE evidence"
                    )
                reference = self._advanced.record_assessment_in_transaction(
                    connection,
                    runtime.assessment,
                    observations=runtime.observations,
                    source_sets=runtime.source_sets,
                    required_instrument_ids=runtime.required_instrument_ids,
                    fence=fence,
                    receipt=receipt,
                    committed_at=cutover_at,
                    valid_through=runtime.valid_through,
                    evidence_context_sha256=quiescence_facts.semantic_sha256,
                    expected_assignment=assignment,
                    expected_control=control,
                )
                if existing is not None:
                    if (
                        existing.assessment != reference
                        or existing.assignment_id != assignment.assignment.assignment_id
                        or existing.assignment_sequence_number
                        != assignment.assignment.sequence_number
                        or existing.assignment_sha256 != assignment.envelope_sha256
                        or existing.operational_transition_id != control.transition_id
                        or existing.operational_transition_sha256 != control.semantic_sha256
                        or existing.fencing_generation != fence.fencing_generation
                        or existing.fence_sha256 != fence.semantic_sha256
                        or existing.quiescence_facts_sha256 != quiescence_facts.semantic_sha256
                    ):
                        raise AdvancedBatchRiskPersistenceConflict(
                            "advanced-risk cutover retry conflicts"
                        )
                    return existing
                head = AdvancedRiskEnforcementHead(
                    account_id=fence.account_id,
                    cutover_sequence_number=1,
                    assignment_id=assignment.assignment.assignment_id,
                    assignment_sequence_number=assignment.assignment.sequence_number,
                    assignment_sha256=assignment.envelope_sha256,
                    policy_sha256=assignment.assignment.policy_sha256,
                    assessment=reference,
                    operational_transition_id=control.transition_id,
                    operational_transition_sha256=control.semantic_sha256,
                    fencing_generation=fence.fencing_generation,
                    lease_sha256=receipt.lease_sha256,
                    fence_sha256=fence.semantic_sha256,
                    enforcement_enabled=True,
                    cutover_at=cutover_at,
                    updated_at=cutover_at,
                )
                try:
                    connection.execute(
                        sa.insert(phase5_advanced_risk_enforcement_heads).values(
                            **_enforcement_values(head)
                        )
                    )
                except IntegrityError as error:
                    raise AdvancedBatchRiskPersistenceConflict(
                        "advanced-risk cutover conflicts with existing facts"
                    ) from error
                persisted = load_advanced_risk_enforcement_head_in_transaction(
                    connection,
                    fence.account_id,
                )
                if persisted != head:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced-risk enforcement cutover failed exact readback"
                    )
                final_control, _ = load_advanced_risk_control_bindings_in_transaction(
                    connection,
                    fence.account_id,
                )
                final_assignment = load_current_advanced_risk_assignment_in_transaction(
                    connection,
                    fence.account_id,
                )
                if (
                    final_control != control
                    or final_assignment is None
                    or not _assignment_matches(final_assignment, assignment)
                ):
                    raise AdvancedBatchRiskPersistenceConflict(
                        "cutover control or assignment changed before commit"
                    )
                return head

        try:
            return snapshots.transact(operation)
        except AdvancedBatchRiskPersistenceError:
            raise
        except (
            AccountCoordinatorError,
            AdvancedRiskAdmissionError,
            AdvancedRiskPersistenceError,
            BatchRiskError,
            ImmutableFactConflict,
            OperationalControlError,
        ) as error:
            raise AdvancedBatchRiskPersistenceError(str(error)) from error

    def authorize(
        self,
        batch: OrderIntentBatch,
        target: TargetPortfolio,
        fence: AccountFence,
    ) -> AdvancedBatchRiskOutcome:
        """Evaluate advanced risk and unchanged Phase 2 risk in one transaction."""

        if type(batch) is not OrderIntentBatch or type(target) is not TargetPortfolio:
            raise AdvancedBatchRiskPersistenceError(
                "advanced authorization requires an exact batch and target"
            )
        if type(fence) is not AccountFence:
            raise AdvancedBatchRiskPersistenceError(
                "advanced authorization requires an exact fence"
            )
        producer = self._evidence_producer
        if producer is None:
            raise AdvancedBatchRiskPersistenceError(
                "advanced authorization requires a transactional evidence producer"
            )
        if batch.target_id != target.target_id or batch.target_sha256 != target.semantic_sha256:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced authorization batch and target bindings differ"
            )
        snapshots = cast(_SnapshotTransactions, self._authority.snapshots)

        def operation(snapshot: VersionedBatchRiskSnapshot) -> AdvancedBatchRiskOutcome:
            if type(snapshot) is not VersionedBatchRiskSnapshot:
                raise AdvancedBatchRiskPersistenceError(
                    "advanced authorization snapshot is non-canonical"
                )
            snapshot._validate()
            evaluated_at = self._now()
            if snapshot.account_id != fence.account_id:
                raise AdvancedBatchRiskPersistenceConflict(
                    "advanced authorization snapshot and fence accounts conflict"
                )
            with _write_transaction(self._engine) as connection:
                receipt = self._coordinator.revalidate_in_transaction(
                    connection,
                    fence,
                    checked_at=evaluated_at,
                )
                _validate_receipt(receipt, fence=fence, checked_at=evaluated_at)
                enforcement = load_advanced_risk_enforcement_head_in_transaction(
                    connection,
                    fence.account_id,
                )
                if enforcement is None:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced authorization requires completed enforcement cutover"
                    )
                existing_outcome = load_advanced_batch_risk_outcome_in_transaction(
                    connection,
                    batch.intent_batch_id,
                )
                if existing_outcome is not None:
                    return self._retry_outcome(
                        batch=batch,
                        target=target,
                        snapshot=snapshot,
                        fence=fence,
                        receipt=receipt,
                        outcome=existing_outcome,
                    )
                pre_control, _bindings = load_advanced_risk_control_bindings_in_transaction(
                    connection,
                    fence.account_id,
                )
                assignment = load_current_advanced_risk_assignment_in_transaction(
                    connection,
                    fence.account_id,
                )
                if pre_control is None or assignment is None:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced authorization requires a current assignment "
                        "and operational control"
                    )
                if pre_control.effective_state is not OperationalControlState.RUNNING:
                    raise AdvancedBatchRiskPersistenceError(
                        "new advanced authorization requires RUNNING control"
                    )
                prior = load_batch_risk_decision_for_batch_in_transaction(
                    connection,
                    batch,
                )
                if prior is not None:
                    raise AdvancedBatchRiskPersistenceConflict(
                        "post-cutover Phase 2 decision lacks its atomic advanced-risk outcome"
                    )
                observation_sequence = next_account_observation_sequence_in_transaction(
                    connection,
                    fence.account_id,
                )
                active_capacity = load_active_capacity_in_transaction(
                    connection,
                    fence.account_id,
                    as_of=evaluated_at,
                    observation_sequence=observation_sequence,
                )
                runtime_instruments = _required_runtime_instruments(
                    snapshot,
                    active_capacity,
                    batch,
                )
                pretrade_instruments = _required_pretrade_instruments(batch)
                try:
                    proposed = (
                        None
                        if not pretrade_instruments
                        else proposed_batch_buy_exposure_from_phase2(
                            batch=batch,
                            target=target,
                            snapshot=snapshot,
                            limits=self._authority.limits,
                            evaluated_at=evaluated_at,
                        )
                    )
                except AdvancedRiskExposureSourceError as error:
                    raise AdvancedBatchRiskPersistenceError(
                        "exact proposed exposure derivation is unavailable"
                    ) from error
                context = _transactional_evidence_context(
                    snapshot=snapshot,
                    active_capacity=active_capacity,
                    batch=batch,
                    target=target,
                    proposed=proposed,
                    receipt=receipt,
                    assignment=assignment,
                    control=pre_control,
                    runtime_instrument_ids=runtime_instruments,
                    pretrade_instrument_ids=pretrade_instruments,
                    evaluated_at=evaluated_at,
                )
                runtime, pretrade = _authenticate_transactional_evidence(
                    producer.derive_in_transaction(
                        AdvancedRiskTransactionalReader(
                            context=context,
                            assignment=assignment,
                            control=pre_control,
                            batch=batch,
                            target=target,
                        ),
                        context=context,
                        snapshot=snapshot,
                        active_capacity=active_capacity,
                        batch=batch,
                        target=target,
                        proposed=proposed,
                    ),
                    expected_context=context,
                    snapshot=snapshot,
                    active_capacity=active_capacity,
                    proposed=proposed,
                )
                watermark = _build_watermark(
                    snapshot=snapshot,
                    active_capacity_sha256=active_capacity.semantic_sha256,
                    batch=batch,
                    target=target,
                    authority=self._authority,
                    receipt=receipt,
                    runtime_instrument_ids=runtime_instruments,
                    pretrade_instrument_ids=pretrade_instruments,
                    evaluated_at=evaluated_at,
                )
                runtime_reference = self._advanced.record_assessment_in_transaction(
                    connection,
                    runtime.assessment,
                    observations=runtime.observations,
                    source_sets=runtime.source_sets,
                    required_instrument_ids=runtime.required_instrument_ids,
                    fence=fence,
                    receipt=receipt,
                    committed_at=evaluated_at,
                    valid_through=runtime.valid_through,
                    evidence_context_sha256=watermark.semantic_sha256,
                    expected_assignment=assignment,
                    expected_control=pre_control,
                )
                pretrade_reference = (
                    None
                    if pretrade is None
                    else self._advanced.record_assessment_in_transaction(
                        connection,
                        pretrade.assessment,
                        observations=pretrade.observations,
                        source_sets=pretrade.source_sets,
                        required_instrument_ids=pretrade.required_instrument_ids,
                        fence=fence,
                        receipt=receipt,
                        committed_at=evaluated_at,
                        valid_through=pretrade.valid_through,
                        evidence_context_sha256=watermark.semantic_sha256,
                        expected_assignment=assignment,
                        expected_control=pre_control,
                    )
                )
                final_control = pre_control
                if runtime.assessment.requires_control_trip:
                    final_control = apply_operational_control_command_in_transaction(
                        connection,
                        advanced_risk_trip_command(
                            runtime.assessment,
                            assessment_evidence_sha256=(runtime_reference.assessment_sha256),
                        ),
                        decided_at=evaluated_at,
                    )
                if runtime.assessment.requires_control_trip or (
                    pretrade is not None
                    and pretrade.assessment.disposition is AdvancedRiskDisposition.REJECT
                ):
                    outcome = AdvancedBatchRiskOutcome(
                        watermark=watermark,
                        assignment_id=assignment.assignment.assignment_id,
                        assignment_sequence_number=assignment.assignment.sequence_number,
                        assignment_sha256=assignment.envelope_sha256,
                        runtime_assessment=runtime_reference,
                        pretrade_assessment=pretrade_reference,
                        pre_control_transition_id=pre_control.transition_id,
                        pre_control_transition_sha256=pre_control.semantic_sha256,
                        final_control_transition_id=final_control.transition_id,
                        final_control_transition_sha256=final_control.semantic_sha256,
                        final_control_state=final_control.effective_state,
                        phase2_decision=None,
                        admission=None,
                    )
                    return self._persist_outcome(
                        connection,
                        outcome=outcome,
                        receipt=receipt,
                    )
                if final_control.effective_state is not OperationalControlState.RUNNING:
                    raise AdvancedBatchRiskPersistenceError(
                        "advanced authorization final control head is not RUNNING"
                    )
                decision = persist_batch_risk_decision_in_transaction(
                    connection,
                    batch=batch,
                    target=target,
                    snapshot=snapshot,
                    limits=self._authority.limits,
                    receipt=receipt,
                    active_capacity=active_capacity,
                    account_observation_sequence=observation_sequence,
                    evaluated_at=evaluated_at,
                )
                admission = self._persist_admission(
                    connection,
                    decision=decision,
                    receipt=receipt,
                    assessment=pretrade_reference,
                    final_control=final_control,
                    bound_at=evaluated_at,
                )
                rechecked_control, _ = load_advanced_risk_control_bindings_in_transaction(
                    connection,
                    fence.account_id,
                )
                rechecked_assignment = load_current_advanced_risk_assignment_in_transaction(
                    connection,
                    fence.account_id,
                )
                if (
                    rechecked_control != final_control
                    or rechecked_assignment is None
                    or not _assignment_matches(rechecked_assignment, assignment)
                ):
                    raise AdvancedBatchRiskPersistenceConflict(
                        "control or assignment changed before advanced admission commit"
                    )
                outcome = AdvancedBatchRiskOutcome(
                    watermark=watermark,
                    assignment_id=assignment.assignment.assignment_id,
                    assignment_sequence_number=assignment.assignment.sequence_number,
                    assignment_sha256=assignment.envelope_sha256,
                    runtime_assessment=runtime_reference,
                    pretrade_assessment=pretrade_reference,
                    pre_control_transition_id=pre_control.transition_id,
                    pre_control_transition_sha256=pre_control.semantic_sha256,
                    final_control_transition_id=final_control.transition_id,
                    final_control_transition_sha256=final_control.semantic_sha256,
                    final_control_state=final_control.effective_state,
                    phase2_decision=decision,
                    admission=admission,
                )
                return self._persist_outcome(
                    connection,
                    outcome=outcome,
                    receipt=receipt,
                )

        try:
            return snapshots.transact(operation)
        except AdvancedBatchRiskPersistenceError:
            raise
        except (
            AccountCoordinatorError,
            AdvancedRiskAdmissionError,
            AdvancedRiskEnforcementError,
            AdvancedRiskPersistenceError,
            BatchRiskError,
            ImmutableFactConflict,
            OperationalControlError,
        ) as error:
            raise AdvancedBatchRiskPersistenceError(str(error)) from error

    def _persist_outcome(
        self,
        connection: Connection,
        *,
        outcome: AdvancedBatchRiskOutcome,
        receipt: AccountFenceReceipt,
    ) -> AdvancedBatchRiskOutcome:
        existing = load_advanced_batch_risk_outcome_in_transaction(
            connection,
            outcome.watermark.intent_batch_id,
        )
        if existing is not None:
            if existing != outcome:
                raise AdvancedBatchRiskPersistenceConflict(
                    "advanced batch-risk outcome retry conflicts"
                )
            return existing
        if (
            outcome.watermark.fencing_generation != receipt.fence.fencing_generation
            or outcome.watermark.fence_sha256 != receipt.fence.semantic_sha256
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced batch-risk outcome and receipt fence differ"
            )
        try:
            connection.execute(
                sa.insert(phase5_advanced_risk_batch_outcomes).values(
                    **_outcome_values(
                        outcome,
                        lease_sha256=receipt.lease_sha256,
                    )
                )
            )
        except IntegrityError as error:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced batch-risk outcome conflicts with immutable facts"
            ) from error
        persisted = load_advanced_batch_risk_outcome_in_transaction(
            connection,
            outcome.watermark.intent_batch_id,
        )
        if persisted != outcome:
            raise AdvancedBatchRiskPersistenceError(
                "advanced batch-risk outcome failed exact readback"
            )
        return outcome

    def _persist_admission(
        self,
        connection: Connection,
        *,
        decision: BatchRiskDecision,
        receipt: AccountFenceReceipt,
        assessment: AdvancedRiskAssessmentReference | None,
        final_control: OperationalControlTransition,
        bound_at: datetime,
    ) -> AdvancedRiskBatchAdmission:
        if decision.status is BatchRiskDecisionStatus.NO_ACTION:
            if assessment is not None:
                raise AdvancedBatchRiskPersistenceConflict(
                    "NO_ACTION sidecar cannot bind a pretrade assessment"
                )
            expires_at = min(decision.expires_at, receipt.valid_until)
        else:
            if assessment is None:
                raise AdvancedBatchRiskPersistenceError(
                    "nonempty Phase 2 decision requires a pretrade assessment"
                )
            expires_at = min(
                decision.expires_at,
                receipt.valid_until,
                assessment.valid_through,
            )
        admission = AdvancedRiskBatchAdmission(
            account_id=decision.account_id,
            phase2_decision_id=decision.decision_id,
            phase2_decision_sha256=decision.semantic_sha256,
            phase2_decision_status=decision.status,
            fencing_generation=receipt.fence.fencing_generation,
            lease_sha256=receipt.lease_sha256,
            fence_sha256=receipt.fence.semantic_sha256,
            assessment=assessment,
            operational_transition_id=final_control.transition_id,
            operational_transition_sha256=final_control.semantic_sha256,
            operational_state=final_control.effective_state,
            admitted=(
                decision.status is BatchRiskDecisionStatus.APPROVED
                and assessment is not None
                and assessment.disposition is AdvancedRiskDisposition.NONE
                and final_control.effective_state is OperationalControlState.RUNNING
            ),
            bound_at=bound_at,
            expires_at=expires_at,
        )
        existing = load_advanced_risk_admission_in_transaction(
            connection,
            decision,
        )
        if existing is not None:
            if existing != admission:
                raise AdvancedBatchRiskPersistenceConflict(
                    "advanced-risk admission retry conflicts"
                )
            return existing
        try:
            connection.execute(
                sa.insert(phase5_advanced_risk_batch_admissions).values(
                    **_admission_values(admission)
                )
            )
        except IntegrityError as error:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced-risk admission conflicts with immutable facts"
            ) from error
        persisted = load_advanced_risk_admission_in_transaction(
            connection,
            decision,
        )
        if persisted != admission:
            raise AdvancedBatchRiskPersistenceError("advanced-risk admission failed exact readback")
        return admission

    def _retry_outcome(
        self,
        *,
        batch: OrderIntentBatch,
        target: TargetPortfolio,
        snapshot: VersionedBatchRiskSnapshot,
        fence: AccountFence,
        receipt: AccountFenceReceipt,
        outcome: AdvancedBatchRiskOutcome,
    ) -> AdvancedBatchRiskOutcome:
        pretrade_instruments = _required_pretrade_instruments(batch)
        if (
            outcome.watermark.intent_batch_id != batch.intent_batch_id
            or outcome.watermark.intent_batch_sha256 != batch.semantic_sha256
            or outcome.watermark.target_id != target.target_id
            or outcome.watermark.target_sha256 != target.semantic_sha256
            or outcome.watermark.snapshot_version != snapshot.version
            or outcome.watermark.snapshot_sha256 != snapshot.semantic_sha256
            or outcome.watermark.phase2_policy_sha256 != self._authority.limits.semantic_sha256
            or outcome.watermark.fencing_generation != fence.fencing_generation
            or outcome.watermark.fence_sha256 != fence.semantic_sha256
            or pretrade_instruments != outcome.watermark.pretrade_instrument_ids
            or bool(pretrade_instruments) != (outcome.pretrade_assessment is not None)
            or (
                outcome.phase2_decision is not None
                and outcome.phase2_decision.active_capacity_sha256
                != outcome.watermark.active_capacity_sha256
            )
        ):
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced authorization retry uses different atomic evidence"
            )
        expected_watermark = _build_watermark(
            snapshot=snapshot,
            active_capacity_sha256=outcome.watermark.active_capacity_sha256,
            batch=batch,
            target=target,
            authority=self._authority,
            receipt=receipt,
            runtime_instrument_ids=outcome.watermark.runtime_instrument_ids,
            pretrade_instrument_ids=pretrade_instruments,
            evaluated_at=outcome.watermark.evaluated_at,
        )
        if expected_watermark != outcome.watermark:
            raise AdvancedBatchRiskPersistenceConflict(
                "advanced authorization retry watermark conflicts"
            )
        return outcome
