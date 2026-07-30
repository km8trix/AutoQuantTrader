"""Pure bindings for Phase 5B cutover, assessment, and batch admission.

The Phase 2 decision remains unchanged.  These contracts bind its exact
snapshot/capacity inputs to authenticated advanced-risk assessment envelopes,
the account fence, and the operational-control heads observed before and after
enforcement.  They grant no authority unless an exact admitted sidecar exists.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.domain.advanced_risk_policy import (
    AdvancedRiskDisposition,
    AdvancedRiskEvaluationMode,
)
from packages.domain.batch_risk import BatchRiskDecision, BatchRiskDecisionStatus
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import OperationalControlState

ADVANCED_RISK_ADMISSION_CONTRACT_VERSION = "phase5b-advanced-risk-admission-v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdvancedRiskAdmissionError(ValueError):
    """An advanced-risk cutover or admission binding is malformed."""


class AdvancedRiskAdmissionConflict(AdvancedRiskAdmissionError):
    """Supposedly identical advanced-risk admission facts disagree."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(
    value: str,
    field_name: str,
    *,
    maximum: int = 128,
) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskAdmissionError(f"{field_name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskAdmissionError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskAdmissionError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise AdvancedRiskAdmissionError(f"{field_name} must be UTC")


def _require_instrument_scope(
    value: tuple[str, ...],
    field_name: str,
    *,
    allow_empty: bool,
) -> None:
    if type(value) is not tuple or any(type(item) is not str for item in value):
        raise AdvancedRiskAdmissionError(f"{field_name} must be an exact string tuple")
    if not allow_empty and not value:
        raise AdvancedRiskAdmissionError(f"{field_name} cannot be empty")
    if value != tuple(sorted(value)) or len(value) != len(set(value)):
        raise AdvancedRiskAdmissionError(f"{field_name} must be sorted and unique")
    for item in value:
        _require_text(item, field_name, maximum=128)


@dataclass(frozen=True, slots=True)
class AdvancedRiskEvidenceWatermark:
    """Exact exposure inputs authenticated by one atomic risk transaction."""

    account_id: str
    intent_batch_id: str
    intent_batch_sha256: str
    target_id: str
    target_sha256: str
    snapshot_version: str
    snapshot_sha256: str
    active_capacity_sha256: str
    phase2_policy_sha256: str
    fencing_generation: int
    fence_sha256: str
    runtime_instrument_ids: tuple[str, ...]
    pretrade_instrument_ids: tuple[str, ...]
    evaluated_at: datetime

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "watermark account ID", 64),
            (self.intent_batch_id, "watermark intent batch ID", 64),
            (self.target_id, "watermark target ID", 64),
            (self.snapshot_version, "watermark snapshot version", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        for value, field_name in (
            (self.intent_batch_sha256, "watermark intent_batch_sha256"),
            (self.target_sha256, "watermark target_sha256"),
            (self.snapshot_sha256, "watermark snapshot_sha256"),
            (self.active_capacity_sha256, "watermark active_capacity_sha256"),
            (self.phase2_policy_sha256, "watermark phase2_policy_sha256"),
            (self.fence_sha256, "watermark fence_sha256"),
        ):
            _require_sha256(value, field_name)
        if type(self.fencing_generation) is not int or self.fencing_generation <= 0:
            raise AdvancedRiskAdmissionError("watermark fencing_generation must be positive")
        _require_instrument_scope(
            self.runtime_instrument_ids,
            "watermark runtime instrument IDs",
            allow_empty=True,
        )
        _require_instrument_scope(
            self.pretrade_instrument_ids,
            "watermark pretrade instrument IDs",
            allow_empty=True,
        )
        _require_utc(self.evaluated_at, "watermark evaluated_at")

    @property
    def watermark_id(self) -> str:
        return canonical_id(
            "advanced-risk-evidence-watermark",
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            self.account_id,
            self.intent_batch_id,
            self.intent_batch_sha256,
            self.snapshot_sha256,
            self.active_capacity_sha256,
            self.fence_sha256,
            self.evaluated_at,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "evidence_watermark",
            self.watermark_id,
            self.account_id,
            self.intent_batch_id,
            self.intent_batch_sha256,
            self.target_id,
            self.target_sha256,
            self.snapshot_version,
            self.snapshot_sha256,
            self.active_capacity_sha256,
            self.phase2_policy_sha256,
            self.fencing_generation,
            self.fence_sha256,
            self.runtime_instrument_ids,
            self.pretrade_instrument_ids,
            self.evaluated_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskAssessmentReference:
    """Authenticated persistence envelope for one full policy assessment."""

    account_id: str
    assessment_id: str
    assessment_sha256: str
    policy_sha256: str
    mode: AdvancedRiskEvaluationMode
    disposition: AdvancedRiskDisposition
    assignment_id: str
    assignment_sequence_number: int
    assignment_sha256: str
    observation_watermark_sequence: int
    watermark_evidence_id: str
    watermark_evidence_sha256: str
    operational_transition_id: str
    operational_transition_sha256: str
    evidence_context_sha256: str | None
    assessed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "assessment reference account ID", 64),
            (self.assessment_id, "assessment reference ID", 36),
            (self.assignment_id, "assessment reference assignment ID", 36),
            (
                self.watermark_evidence_id,
                "assessment reference watermark evidence ID",
                36,
            ),
            (
                self.operational_transition_id,
                "assessment reference operational transition ID",
                36,
            ),
        ):
            _require_text(value, field_name, maximum=maximum)
        for value, field_name in (
            (self.assessment_sha256, "assessment reference assessment_sha256"),
            (self.policy_sha256, "assessment reference policy_sha256"),
            (self.assignment_sha256, "assessment reference assignment_sha256"),
            (
                self.watermark_evidence_sha256,
                "assessment reference watermark_evidence_sha256",
            ),
            (
                self.operational_transition_sha256,
                "assessment reference operational_transition_sha256",
            ),
        ):
            _require_sha256(value, field_name)
        if self.evidence_context_sha256 is not None:
            _require_sha256(
                self.evidence_context_sha256,
                "assessment reference evidence_context_sha256",
            )
        if type(self.mode) is not AdvancedRiskEvaluationMode:
            raise AdvancedRiskAdmissionError("assessment reference mode is unsupported")
        if type(self.disposition) is not AdvancedRiskDisposition:
            raise AdvancedRiskAdmissionError("assessment reference disposition is unsupported")
        if (
            type(self.assignment_sequence_number) is not int
            or self.assignment_sequence_number <= 0
            or type(self.observation_watermark_sequence) is not int
            or self.observation_watermark_sequence <= 0
        ):
            raise AdvancedRiskAdmissionError(
                "assessment reference sequence numbers must be positive"
            )
        _require_utc(self.assessed_at, "assessment reference assessed_at")
        _require_utc(self.valid_through, "assessment reference valid_through")
        if self.valid_through <= self.assessed_at:
            raise AdvancedRiskAdmissionError(
                "assessment reference validity must follow assessment time"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "assessment_reference",
            self.account_id,
            self.assessment_id,
            self.assessment_sha256,
            self.policy_sha256,
            self.mode,
            self.disposition,
            self.assignment_id,
            self.assignment_sequence_number,
            self.assignment_sha256,
            self.observation_watermark_sequence,
            self.watermark_evidence_id,
            self.watermark_evidence_sha256,
            self.operational_transition_id,
            self.operational_transition_sha256,
            self.evidence_context_sha256,
            self.assessed_at,
            self.valid_through,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskCutoverQuiescenceFacts:
    """Exact facts returned by the injected authoritative cutover verifier."""

    account_id: str
    fencing_generation: int
    fence_sha256: str
    assignment_id: str
    assignment_sequence_number: int
    assignment_sha256: str
    operational_transition_id: str
    operational_transition_sha256: str
    checked_at: datetime
    expires_at: datetime
    reconciliation_source_id: str
    reconciliation_sha256: str
    reconciliation_clean: bool
    working_order_ids: tuple[str, ...]
    unknown_order_ids: tuple[str, ...]
    pending_cancel_order_ids: tuple[str, ...]
    strategy_activity_source_id: str
    strategy_activity_sha256: str
    active_strategy_invocation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "cutover facts account ID", 64),
            (self.assignment_id, "cutover facts assignment ID", 36),
            (
                self.operational_transition_id,
                "cutover facts operational transition ID",
                36,
            ),
            (
                self.reconciliation_source_id,
                "cutover facts reconciliation source ID",
                128,
            ),
            (
                self.strategy_activity_source_id,
                "cutover facts strategy activity source ID",
                128,
            ),
        ):
            _require_text(value, field_name, maximum=maximum)
        for value, field_name in (
            (self.fence_sha256, "cutover facts fence_sha256"),
            (self.assignment_sha256, "cutover facts assignment_sha256"),
            (
                self.operational_transition_sha256,
                "cutover facts operational_transition_sha256",
            ),
            (
                self.reconciliation_sha256,
                "cutover facts reconciliation_sha256",
            ),
            (
                self.strategy_activity_sha256,
                "cutover facts strategy_activity_sha256",
            ),
        ):
            _require_sha256(value, field_name)
        if (
            type(self.fencing_generation) is not int
            or self.fencing_generation <= 0
            or type(self.assignment_sequence_number) is not int
            or self.assignment_sequence_number <= 0
        ):
            raise AdvancedRiskAdmissionError(
                "cutover facts assignment and fence sequences must be positive"
            )
        if type(self.reconciliation_clean) is not bool:
            raise AdvancedRiskAdmissionError("cutover facts reconciliation_clean must be exact")
        for identifiers, field_name in (
            (self.working_order_ids, "cutover facts working order IDs"),
            (self.unknown_order_ids, "cutover facts UNKNOWN order IDs"),
            (
                self.pending_cancel_order_ids,
                "cutover facts pending-cancel order IDs",
            ),
            (
                self.active_strategy_invocation_ids,
                "cutover facts active strategy invocation IDs",
            ),
        ):
            _require_instrument_scope(
                identifiers,
                field_name,
                allow_empty=True,
            )
        _require_utc(self.checked_at, "cutover facts checked_at")
        _require_utc(self.expires_at, "cutover facts expires_at")
        if self.expires_at <= self.checked_at:
            raise AdvancedRiskAdmissionError(
                "cutover facts expiry must follow its authoritative check"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "cutover_quiescence_facts",
            self.account_id,
            self.fencing_generation,
            self.fence_sha256,
            self.assignment_id,
            self.assignment_sequence_number,
            self.assignment_sha256,
            self.operational_transition_id,
            self.operational_transition_sha256,
            self.checked_at,
            self.expires_at,
            self.reconciliation_source_id,
            self.reconciliation_sha256,
            self.reconciliation_clean,
            self.working_order_ids,
            self.unknown_order_ids,
            self.pending_cancel_order_ids,
            self.strategy_activity_source_id,
            self.strategy_activity_sha256,
            self.active_strategy_invocation_ids,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskEnforcementHead:
    """One-way authenticated account cutover into advanced-risk enforcement."""

    account_id: str
    cutover_sequence_number: int
    assignment_id: str
    assignment_sequence_number: int
    assignment_sha256: str
    policy_sha256: str
    assessment: AdvancedRiskAssessmentReference
    operational_transition_id: str
    operational_transition_sha256: str
    fencing_generation: int
    lease_sha256: str
    fence_sha256: str
    enforcement_enabled: bool
    cutover_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "enforcement account ID", maximum=64)
        for value, field_name in (
            (self.assignment_id, "enforcement assignment ID"),
            (self.operational_transition_id, "enforcement operational transition ID"),
        ):
            _require_text(value, field_name, maximum=36)
        for value, field_name in (
            (self.assignment_sha256, "enforcement assignment_sha256"),
            (self.policy_sha256, "enforcement policy_sha256"),
            (
                self.operational_transition_sha256,
                "enforcement operational_transition_sha256",
            ),
            (self.lease_sha256, "enforcement lease_sha256"),
            (self.fence_sha256, "enforcement fence_sha256"),
        ):
            _require_sha256(value, field_name)
        if (
            self.cutover_sequence_number != 1
            or type(self.assignment_sequence_number) is not int
            or self.assignment_sequence_number <= 0
            or type(self.fencing_generation) is not int
            or self.fencing_generation <= 0
        ):
            raise AdvancedRiskAdmissionError(
                "enforcement cutover and assignment/fence sequences are invalid"
            )
        if type(self.assessment) is not AdvancedRiskAssessmentReference:
            raise AdvancedRiskAdmissionError("enforcement requires an exact assessment reference")
        self.assessment.__post_init__()
        if (
            self.assessment.account_id != self.account_id
            or self.assessment.assignment_id != self.assignment_id
            or self.assessment.assignment_sequence_number != self.assignment_sequence_number
            or self.assessment.assignment_sha256 != self.assignment_sha256
            or self.assessment.policy_sha256 != self.policy_sha256
            or self.assessment.mode is not AdvancedRiskEvaluationMode.RUNTIME
            or self.assessment.disposition is not AdvancedRiskDisposition.NONE
            or self.assessment.operational_transition_id != self.operational_transition_id
            or self.assessment.operational_transition_sha256 != self.operational_transition_sha256
            or self.assessment.evidence_context_sha256 is None
        ):
            raise AdvancedRiskAdmissionConflict("enforcement cutover assessment bindings conflict")
        if self.enforcement_enabled is not True:
            raise AdvancedRiskAdmissionError(
                "advanced-risk enforcement head can only represent enabled cutover"
            )
        _require_utc(self.cutover_at, "enforcement cutover_at")
        _require_utc(self.updated_at, "enforcement updated_at")
        if (
            self.assessment.assessed_at > self.cutover_at
            or self.cutover_at >= self.assessment.valid_through
            or self.updated_at < self.cutover_at
        ):
            raise AdvancedRiskAdmissionError(
                "enforcement cutover assessment is stale or chronologically invalid"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "enforcement_head",
            self.account_id,
            self.cutover_sequence_number,
            self.assignment_id,
            self.assignment_sequence_number,
            self.assignment_sha256,
            self.policy_sha256,
            self.assessment.semantic_sha256,
            self.operational_transition_id,
            self.operational_transition_sha256,
            self.fencing_generation,
            self.lease_sha256,
            self.fence_sha256,
            self.enforcement_enabled,
            self.cutover_at,
            self.updated_at,
            "one_way_no_backfill",
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def quiescence_facts_sha256(self) -> str:
        """Return the exact authoritative quiescence facts bound at cutover."""

        value = self.assessment.evidence_context_sha256
        if value is None:  # pragma: no cover - guarded by __post_init__
            raise AdvancedRiskAdmissionConflict("enforcement cutover lacks quiescence facts")
        return value

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskBatchAdmission:
    """Additive sidecar controlling whether one unchanged v2 decision may dispatch."""

    account_id: str
    phase2_decision_id: str
    phase2_decision_sha256: str
    phase2_decision_status: BatchRiskDecisionStatus
    fencing_generation: int
    lease_sha256: str
    fence_sha256: str
    assessment: AdvancedRiskAssessmentReference | None
    operational_transition_id: str
    operational_transition_sha256: str
    operational_state: OperationalControlState
    admitted: bool
    bound_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.account_id, "admission account ID", maximum=64)
        _require_text(self.phase2_decision_id, "admission Phase 2 decision ID", maximum=64)
        _require_text(
            self.operational_transition_id,
            "admission operational transition ID",
            maximum=36,
        )
        for value, field_name in (
            (self.phase2_decision_sha256, "admission Phase 2 decision_sha256"),
            (self.lease_sha256, "admission lease_sha256"),
            (self.fence_sha256, "admission fence_sha256"),
            (
                self.operational_transition_sha256,
                "admission operational_transition_sha256",
            ),
        ):
            _require_sha256(value, field_name)
        if type(self.phase2_decision_status) is not BatchRiskDecisionStatus:
            raise AdvancedRiskAdmissionError("admission Phase 2 decision status is unsupported")
        if type(self.fencing_generation) is not int or self.fencing_generation <= 0:
            raise AdvancedRiskAdmissionError("admission fencing_generation must be positive")
        if type(self.operational_state) is not OperationalControlState:
            raise AdvancedRiskAdmissionError("admission operational state is unsupported")
        if type(self.admitted) is not bool:
            raise AdvancedRiskAdmissionError("admission admitted flag must be exact")
        _require_utc(self.bound_at, "admission bound_at")
        _require_utc(self.expires_at, "admission expires_at")
        if self.expires_at <= self.bound_at:
            raise AdvancedRiskAdmissionError("admission expiry must follow binding time")
        no_action = self.phase2_decision_status is BatchRiskDecisionStatus.NO_ACTION
        if no_action:
            if self.assessment is not None or self.admitted:
                raise AdvancedRiskAdmissionConflict(
                    "NO_ACTION admission must use the exact assessment-null non-admitted shape"
                )
        else:
            if type(self.assessment) is not AdvancedRiskAssessmentReference:
                raise AdvancedRiskAdmissionError(
                    "nonempty decision admission requires an assessment reference"
                )
            self.assessment.__post_init__()
            if (
                self.assessment.account_id != self.account_id
                or self.assessment.mode is not AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE
                or self.assessment.operational_transition_id != self.operational_transition_id
                or self.assessment.operational_transition_sha256
                != self.operational_transition_sha256
            ):
                raise AdvancedRiskAdmissionConflict(
                    "admission assessment scope or control binding conflicts"
                )
            if self.expires_at > self.assessment.valid_through:
                raise AdvancedRiskAdmissionConflict(
                    "admission cannot outlive its advanced-risk assessment"
                )
        expected_admitted = (
            self.phase2_decision_status is BatchRiskDecisionStatus.APPROVED
            and self.assessment is not None
            and self.assessment.disposition is AdvancedRiskDisposition.NONE
            and self.operational_state is OperationalControlState.RUNNING
        )
        if self.admitted != expected_admitted:
            raise AdvancedRiskAdmissionConflict(
                "admission flag conflicts with Phase 2, advanced-risk, or control outcome"
            )

    @property
    def admission_id(self) -> str:
        return canonical_id(
            "advanced-risk-batch-admission",
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            self.account_id,
            self.phase2_decision_id,
            self.phase2_decision_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "batch_admission",
            self.admission_id,
            self.account_id,
            self.phase2_decision_id,
            self.phase2_decision_sha256,
            self.phase2_decision_status,
            self.fencing_generation,
            self.lease_sha256,
            self.fence_sha256,
            None if self.assessment is None else self.assessment.semantic_sha256,
            self.operational_transition_id,
            self.operational_transition_sha256,
            self.operational_state,
            self.admitted,
            self.bound_at,
            self.expires_at,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedBatchRiskOutcome:
    """Exact result of one atomic advanced-risk and unchanged Phase 2 evaluation."""

    watermark: AdvancedRiskEvidenceWatermark
    assignment_id: str
    assignment_sequence_number: int
    assignment_sha256: str
    runtime_assessment: AdvancedRiskAssessmentReference
    pretrade_assessment: AdvancedRiskAssessmentReference | None
    pre_control_transition_id: str
    pre_control_transition_sha256: str
    final_control_transition_id: str
    final_control_transition_sha256: str
    final_control_state: OperationalControlState
    phase2_decision: BatchRiskDecision | None
    admission: AdvancedRiskBatchAdmission | None

    def __post_init__(self) -> None:
        if type(self.watermark) is not AdvancedRiskEvidenceWatermark:
            raise AdvancedRiskAdmissionError("outcome watermark must be exact")
        self.watermark.__post_init__()
        _require_text(self.assignment_id, "outcome assignment ID", maximum=36)
        for value, field_name in (
            (self.assignment_sha256, "outcome assignment_sha256"),
            (self.pre_control_transition_sha256, "outcome pre-control SHA-256"),
            (self.final_control_transition_sha256, "outcome final-control SHA-256"),
        ):
            _require_sha256(value, field_name)
        for value, field_name in (
            (self.pre_control_transition_id, "outcome pre-control transition ID"),
            (self.final_control_transition_id, "outcome final-control transition ID"),
        ):
            _require_text(value, field_name, maximum=36)
        if type(self.assignment_sequence_number) is not int or self.assignment_sequence_number <= 0:
            raise AdvancedRiskAdmissionError("outcome assignment sequence must be positive")
        if type(self.runtime_assessment) is not AdvancedRiskAssessmentReference:
            raise AdvancedRiskAdmissionError("outcome runtime assessment must be exact")
        self.runtime_assessment.__post_init__()
        if (
            self.runtime_assessment.mode is not AdvancedRiskEvaluationMode.RUNTIME
            or self.runtime_assessment.disposition is AdvancedRiskDisposition.REJECT
        ):
            raise AdvancedRiskAdmissionConflict(
                "outcome runtime assessment uses the wrong mode or disposition"
            )
        if self.pretrade_assessment is not None:
            if type(self.pretrade_assessment) is not AdvancedRiskAssessmentReference:
                raise AdvancedRiskAdmissionError("outcome pretrade assessment must be exact")
            self.pretrade_assessment.__post_init__()
            if (
                self.pretrade_assessment.mode
                is not AdvancedRiskEvaluationMode.PRETRADE_NEW_EXPOSURE
                or self.pretrade_assessment.disposition
                in {AdvancedRiskDisposition.PAUSE, AdvancedRiskDisposition.HALT}
            ):
                raise AdvancedRiskAdmissionConflict(
                    "outcome pretrade assessment uses the wrong mode or disposition"
                )
        for assessment in (
            self.runtime_assessment,
            *(() if self.pretrade_assessment is None else (self.pretrade_assessment,)),
        ):
            if (
                assessment.account_id != self.watermark.account_id
                or assessment.assignment_id != self.assignment_id
                or assessment.assignment_sequence_number != self.assignment_sequence_number
                or assessment.assignment_sha256 != self.assignment_sha256
                or assessment.evidence_context_sha256 != self.watermark.semantic_sha256
                or assessment.operational_transition_id != self.pre_control_transition_id
                or assessment.operational_transition_sha256 != self.pre_control_transition_sha256
            ):
                raise AdvancedRiskAdmissionConflict(
                    "outcome assessment bindings conflict with its atomic inputs"
                )
        if type(self.final_control_state) is not OperationalControlState:
            raise AdvancedRiskAdmissionError("outcome final control state is unsupported")
        if self.runtime_assessment.disposition is AdvancedRiskDisposition.PAUSE:
            if self.final_control_state is not OperationalControlState.PAUSED:
                raise AdvancedRiskAdmissionConflict(
                    "runtime PAUSE outcome must retain the PAUSED final head"
                )
        elif self.runtime_assessment.disposition is AdvancedRiskDisposition.HALT:
            if self.final_control_state is not OperationalControlState.HALTED:
                raise AdvancedRiskAdmissionConflict(
                    "runtime HALT outcome must retain the HALTED final head"
                )
        elif (
            self.final_control_transition_id != self.pre_control_transition_id
            or self.final_control_transition_sha256 != self.pre_control_transition_sha256
            or self.final_control_state is not OperationalControlState.RUNNING
        ):
            raise AdvancedRiskAdmissionConflict(
                "non-trip outcome must retain the unchanged RUNNING control head"
            )
        if self.phase2_decision is None:
            if self.admission is not None:
                raise AdvancedRiskAdmissionConflict(
                    "outcome cannot retain an admission without a Phase 2 decision"
                )
        else:
            if type(self.phase2_decision) is not BatchRiskDecision:
                raise AdvancedRiskAdmissionError("outcome Phase 2 decision must be exact")
            self.phase2_decision.__post_init__()
            if (
                self.phase2_decision.account_id != self.watermark.account_id
                or self.phase2_decision.intent_batch_id != self.watermark.intent_batch_id
                or self.phase2_decision.intent_batch_sha256 != self.watermark.intent_batch_sha256
                or self.phase2_decision.snapshot_version != self.watermark.snapshot_version
                or self.phase2_decision.snapshot_sha256 != self.watermark.snapshot_sha256
                or self.phase2_decision.active_capacity_sha256
                != self.watermark.active_capacity_sha256
                or self.phase2_decision.policy_sha256 != self.watermark.phase2_policy_sha256
                or type(self.admission) is not AdvancedRiskBatchAdmission
                or self.admission.phase2_decision_id != self.phase2_decision.decision_id
                or self.admission.phase2_decision_sha256 != self.phase2_decision.semantic_sha256
                or self.admission.operational_transition_id != self.final_control_transition_id
                or self.admission.operational_transition_sha256
                != self.final_control_transition_sha256
            ):
                raise AdvancedRiskAdmissionConflict(
                    "outcome Phase 2 decision or sidecar binding conflicts"
                )
        if (
            self.runtime_assessment.disposition
            in {AdvancedRiskDisposition.PAUSE, AdvancedRiskDisposition.HALT}
            and self.phase2_decision is not None
        ):
            raise AdvancedRiskAdmissionConflict(
                "runtime trip outcome cannot retain a Phase 2 decision"
            )
        if (
            self.pretrade_assessment is not None
            and self.pretrade_assessment.disposition is AdvancedRiskDisposition.REJECT
            and self.phase2_decision is not None
        ):
            raise AdvancedRiskAdmissionConflict(
                "pretrade rejection cannot retain a Phase 2 decision"
            )

    @property
    def outcome_id(self) -> str:
        return canonical_id(
            "advanced-risk-batch-outcome",
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            self.watermark.account_id,
            self.watermark.intent_batch_id,
            self.watermark.intent_batch_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ADMISSION_CONTRACT_VERSION,
            "advanced_batch_risk_outcome",
            self.outcome_id,
            self.watermark.semantic_sha256,
            self.assignment_id,
            self.assignment_sequence_number,
            self.assignment_sha256,
            self.runtime_assessment.semantic_sha256,
            (
                None
                if self.pretrade_assessment is None
                else self.pretrade_assessment.semantic_sha256
            ),
            self.pre_control_transition_id,
            self.pre_control_transition_sha256,
            self.final_control_transition_id,
            self.final_control_transition_sha256,
            self.final_control_state,
            (None if self.phase2_decision is None else self.phase2_decision.semantic_sha256),
            None if self.admission is None else self.admission.semantic_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())
