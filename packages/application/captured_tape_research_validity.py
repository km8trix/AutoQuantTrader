"""Pure eligibility gate for captured-tape research evidence.

This boundary composes, but never upgrades, the Phase 1 production-evidence
prerequisite and generic source-admission decisions. V1 has no external trust
root, so every assessment retains an authenticated-provenance blocker. It owns
no source, storage, clock, persistence, experiment, promotion, or trading
authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from packages.application.production_market_data_admission import (
    IndependentProductionEvidenceReview,
    ProductionEvidenceBundle,
    ProductionEvidenceGateAssessment,
    ProductionEvidenceGateStatus,
    ProductionHistoricalSourceEvidenceSpecification,
    assess_production_market_data_evidence,
)
from packages.domain.canonical import canonical_json_text
from packages.market_data import (
    AdmissionEvidence,
    AdmissionReport,
    AdmissionSpecification,
    AdmissionStatus,
    evaluate_admission,
)

CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION = "phase3e-captured-tape-research-validity-v1"
SOURCE_ADMISSION_MAX_AGE = timedelta(days=30)

_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CapturedTapeResearchValidityError(ValueError):
    """A validity specification or evidence object is malformed."""


class CapturedTapeResearchValidityConflict(CapturedTapeResearchValidityError):
    """A proof-constructed assessment or canonical binding was altered."""


class CapturedTapeEvidenceClass(StrEnum):
    """Caller-asserted origin class; vendor labeling is necessary, not proof."""

    VENDOR_CAPTURED = "vendor_captured"
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    RECORDED_FIXTURE = "recorded_fixture"
    GENERIC_RESEARCH_CAPTURE = "generic_research_capture"
    CONTRACT_ONLY = "contract_only"


class CapturedTapeEvidenceDecision(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"


class CapturedTapeRetentionKind(StrEnum):
    CONTENT_ADDRESSED_IMMUTABLE = "content_addressed_immutable"
    MUTABLE = "mutable"


class CapturedTapeReviewClass(StrEnum):
    EXTERNAL_INDEPENDENT = "external_independent"
    RESEARCH_ONLY = "research_only"
    SYNTHETIC_CONTRACT = "synthetic_contract"


class CapturedTapeReviewDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class CapturedTapeResearchValidityStatus(StrEnum):
    BLOCKED = "blocked"
    ELIGIBLE = "eligible_as_captured_tape_research_evidence"


class CapturedTapeAuthorityEffect(StrEnum):
    NONE = "none"


class CapturedTapeResearchBlocker(StrEnum):
    """Canonical fail-closed reasons a candidate cannot count as captured tape."""

    PRODUCTION_PREREQUISITE_MISSING = "production_prerequisite_missing"
    PRODUCTION_PREREQUISITE_ASSESSMENT_MISMATCH = "production_prerequisite_assessment_mismatch"
    PRODUCTION_PREREQUISITE_BINDING_MISMATCH = "production_prerequisite_binding_mismatch"
    PRODUCTION_PREREQUISITE_BLOCKED = "production_prerequisite_blocked"
    PRODUCTION_PREREQUISITE_NOT_CURRENT = "production_prerequisite_not_current"
    SOURCE_ADMISSION_MISSING = "source_admission_missing"
    SOURCE_ADMISSION_REPORT_MISMATCH = "source_admission_report_mismatch"
    SOURCE_ADMISSION_BINDING_MISMATCH = "source_admission_binding_mismatch"
    SOURCE_NOT_ADMITTED = "source_not_admitted"
    SOURCE_ADMISSION_IN_FUTURE = "source_admission_in_future"
    SOURCE_ADMISSION_STALE = "source_admission_stale"
    CAPTURE_EVIDENCE_MISSING = "capture_evidence_missing"
    AUTHENTICATED_CAPTURE_PROVENANCE_MISSING = "authenticated_capture_provenance_missing"
    AUTHENTICATED_CAPTURE_PROVENANCE_INVALID = "authenticated_capture_provenance_invalid"
    NON_VENDOR_CAPTURE_EVIDENCE = "non_vendor_capture_evidence"
    CAPTURE_EVIDENCE_REJECTED = "capture_evidence_rejected"
    CAPTURE_BINDING_MISMATCH = "capture_binding_mismatch"
    CAPTURE_NOT_IMMUTABLE = "capture_not_immutable"
    CAPTURE_EVIDENCE_IN_FUTURE = "capture_evidence_in_future"
    CAPTURE_EVIDENCE_STALE = "capture_evidence_stale"
    REPLAY_EVIDENCE_MISSING = "replay_evidence_missing"
    REPLAY_EVIDENCE_REJECTED = "replay_evidence_rejected"
    REPLAY_BINDING_MISMATCH = "replay_binding_mismatch"
    CONFIGURATION_BINDING_MISMATCH = "configuration_binding_mismatch"
    REPLAY_EVIDENCE_IN_FUTURE = "replay_evidence_in_future"
    REPLAY_EVIDENCE_STALE = "replay_evidence_stale"
    TEMPORAL_BINDING_MISMATCH = "temporal_binding_mismatch"
    EVALUATION_PREDATES_SPECIFICATION = "evaluation_predates_specification"
    SPECIFICATION_STALE = "specification_stale"
    INDEPENDENT_REVIEW_MISSING = "independent_review_missing"
    NON_EXTERNAL_REVIEW = "non_external_review"
    REVIEW_REJECTED = "review_rejected"
    REVIEW_BINDING_MISMATCH = "review_binding_mismatch"
    REVIEW_REPLAYED_OR_SUBSTITUTED = "review_replayed_or_substituted"
    REVIEW_PREDATES_EVIDENCE = "review_predates_evidence"
    REVIEW_OBSERVED_IN_FUTURE = "review_observed_in_future"
    REVIEW_STALE = "review_stale"
    SELF_APPROVED = "self_approved"


_BLOCKER_ORDER = {blocker: index for index, blocker in enumerate(CapturedTapeResearchBlocker)}


def _require_safe_text(value: str, field_name: str) -> None:
    if type(value) is not str or _SAFE_TEXT.fullmatch(value) is None:
        raise CapturedTapeResearchValidityError(
            f"{field_name} must contain 1-256 bounded safe characters"
        )


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise CapturedTapeResearchValidityError(
            f"{field_name} must be a nonzero lowercase SHA-256 digest"
        )


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CapturedTapeResearchValidityError(
            f"{field_name} must be an exact timezone-aware datetime"
        )
    if value.utcoffset() != timedelta(0):
        raise CapturedTapeResearchValidityError(f"{field_name} must be stored in UTC")


def _require_exact_enum(value: object, enum_type: type[StrEnum], field_name: str) -> None:
    if type(value) is not enum_type:
        raise CapturedTapeResearchValidityError(
            f"{field_name} must be an exact {enum_type.__name__}"
        )


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProductionEvidencePrerequisite:
    """Exact Wave 1A inputs plus the assessment the caller observed."""

    specification: ProductionHistoricalSourceEvidenceSpecification
    evidence: ProductionEvidenceBundle
    review: IndependentProductionEvidenceReview | None
    assessment: ProductionEvidenceGateAssessment
    executor_id: str

    def __post_init__(self) -> None:
        if type(self.specification) is not ProductionHistoricalSourceEvidenceSpecification:
            raise CapturedTapeResearchValidityError(
                "production prerequisite requires an exact specification"
            )
        if type(self.evidence) is not ProductionEvidenceBundle:
            raise CapturedTapeResearchValidityError(
                "production prerequisite requires an exact evidence bundle"
            )
        if self.review is not None and type(self.review) is not IndependentProductionEvidenceReview:
            raise CapturedTapeResearchValidityError(
                "production prerequisite requires an exact review"
            )
        if type(self.assessment) is not ProductionEvidenceGateAssessment:
            raise CapturedTapeResearchValidityError(
                "production prerequisite requires an exact assessment"
            )
        _require_safe_text(self.executor_id, "production prerequisite executor ID")


@dataclass(frozen=True, slots=True)
class AdmittedHistoricalSourceEvidence:
    """Exact generic admission inputs and their caller-observed report."""

    specification: AdmissionSpecification
    evidence: AdmissionEvidence
    report: AdmissionReport

    def __post_init__(self) -> None:
        if type(self.specification) is not AdmissionSpecification:
            raise CapturedTapeResearchValidityError(
                "source admission requires an exact AdmissionSpecification"
            )
        if type(self.evidence) is not AdmissionEvidence:
            raise CapturedTapeResearchValidityError(
                "source admission requires exact AdmissionEvidence"
            )
        if type(self.report) is not AdmissionReport:
            raise CapturedTapeResearchValidityError(
                "source admission requires an exact AdmissionReport"
            )


@dataclass(frozen=True, slots=True)
class CapturedDatasetTapeEvidence:
    """One immutable capture assertion bound to production and admission evidence."""

    evidence_id: str
    evidence_class: CapturedTapeEvidenceClass
    decision: CapturedTapeEvidenceDecision
    retention_kind: CapturedTapeRetentionKind
    producer_id: str
    capture_executor_id: str
    source_id: str
    provider: str
    dataset: str
    feed: str
    profile_sha256: str
    scope_sha256: str
    production_specification_sha256: str
    production_assessment_sha256: str
    source_admission_report_sha256: str
    capture_id: str
    capture_manifest_sha256: str
    dataset_manifest_id: str
    dataset_manifest_sha256: str
    immutable_object_set_sha256: str
    source_tape_sha256: str
    coverage_start: datetime
    coverage_end: datetime
    capture_started_at: datetime
    capture_completed_at: datetime
    sealed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.evidence_id, "capture evidence ID"),
            (self.producer_id, "capture evidence producer ID"),
            (self.capture_executor_id, "capture executor ID"),
            (self.source_id, "capture source ID"),
            (self.provider, "capture provider"),
            (self.dataset, "capture dataset"),
            (self.feed, "capture feed"),
        ):
            _require_safe_text(value, field_name)
        _require_exact_enum(
            self.evidence_class,
            CapturedTapeEvidenceClass,
            "capture evidence class",
        )
        _require_exact_enum(
            self.decision,
            CapturedTapeEvidenceDecision,
            "capture evidence decision",
        )
        _require_exact_enum(
            self.retention_kind,
            CapturedTapeRetentionKind,
            "capture retention kind",
        )
        for value, field_name in (
            (self.profile_sha256, "capture profile digest"),
            (self.scope_sha256, "capture scope digest"),
            (self.production_specification_sha256, "capture production specification digest"),
            (self.production_assessment_sha256, "capture production assessment digest"),
            (self.source_admission_report_sha256, "capture source admission report digest"),
            (self.capture_id, "capture ID"),
            (self.capture_manifest_sha256, "capture manifest digest"),
            (self.dataset_manifest_id, "capture dataset manifest ID"),
            (self.dataset_manifest_sha256, "capture dataset manifest digest"),
            (self.immutable_object_set_sha256, "capture immutable object-set digest"),
            (self.source_tape_sha256, "capture source tape digest"),
        ):
            _require_sha256(value, field_name)
        if self.capture_id != self.capture_manifest_sha256:
            raise CapturedTapeResearchValidityError(
                "capture ID must equal its content-addressed manifest digest"
            )
        if self.dataset_manifest_id != self.dataset_manifest_sha256:
            raise CapturedTapeResearchValidityError(
                "dataset manifest ID must equal its content-addressed digest"
            )
        for timestamp, field_name in (
            (self.coverage_start, "capture coverage_start"),
            (self.coverage_end, "capture coverage_end"),
            (self.capture_started_at, "capture started_at"),
            (self.capture_completed_at, "capture completed_at"),
            (self.sealed_at, "capture sealed_at"),
            (self.valid_through, "capture valid_through"),
        ):
            _require_utc(timestamp, field_name)
        if self.coverage_end <= self.coverage_start:
            raise CapturedTapeResearchValidityError(
                "capture coverage_end must follow coverage_start"
            )
        if self.capture_completed_at < self.capture_started_at:
            raise CapturedTapeResearchValidityError(
                "capture completion cannot precede capture start"
            )
        if self.coverage_end > self.capture_completed_at:
            raise CapturedTapeResearchValidityError(
                "capture cannot complete before its claimed coverage"
            )
        if self.sealed_at < self.capture_completed_at:
            raise CapturedTapeResearchValidityError(
                "capture seal cannot precede capture completion"
            )
        if self.valid_through <= self.sealed_at:
            raise CapturedTapeResearchValidityError("capture valid_through must follow sealing")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
            "captured_dataset_tape_evidence",
            self.evidence_id,
            self.evidence_class,
            self.decision,
            self.retention_kind,
            self.producer_id,
            self.capture_executor_id,
            self.source_id,
            self.provider,
            self.dataset,
            self.feed,
            self.profile_sha256,
            self.scope_sha256,
            self.production_specification_sha256,
            self.production_assessment_sha256,
            self.source_admission_report_sha256,
            self.capture_id,
            self.capture_manifest_sha256,
            self.dataset_manifest_id,
            self.dataset_manifest_sha256,
            self.immutable_object_set_sha256,
            self.source_tape_sha256,
            self.coverage_start,
            self.coverage_end,
            self.capture_started_at,
            self.capture_completed_at,
            self.sealed_at,
            self.valid_through,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedCapturedTapeProvenance:
    """Unavailable capability reserved for a future reviewed external verifier.

    No repository-local factory or validation path exists because no current
    trust root can authenticate vendor capture origin. Private Python names and
    unkeyed hashes are not authentication, so even a forged exact instance is
    rejected by the v1 gate.
    """

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated captured-tape provenance requires a future reviewed issuer")


@dataclass(frozen=True, slots=True)
class CapturedTapeReplayEvidence:
    """Exact replay, temporal, runtime, and research-configuration pins."""

    evidence_id: str
    decision: CapturedTapeEvidenceDecision
    producer_id: str
    replay_executor_id: str
    capture_evidence_sha256: str
    dataset_manifest_sha256: str
    source_tape_sha256: str
    replay_run_id: str
    replay_manifest_sha256: str
    replay_tape_sha256: str
    replay_input_sha256: str
    replay_plan_sha256: str
    replay_runtime_sha256: str
    research_configuration_sha256: str
    coverage_start: datetime
    coverage_end: datetime
    replay_started_at: datetime
    replay_completed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.evidence_id, "replay evidence ID"),
            (self.producer_id, "replay evidence producer ID"),
            (self.replay_executor_id, "replay executor ID"),
        ):
            _require_safe_text(value, field_name)
        _require_exact_enum(
            self.decision,
            CapturedTapeEvidenceDecision,
            "replay evidence decision",
        )
        for value, field_name in (
            (self.capture_evidence_sha256, "replay capture-evidence digest"),
            (self.dataset_manifest_sha256, "replay dataset-manifest digest"),
            (self.source_tape_sha256, "replay source-tape digest"),
            (self.replay_run_id, "replay run ID"),
            (self.replay_manifest_sha256, "replay manifest digest"),
            (self.replay_tape_sha256, "replay tape digest"),
            (self.replay_input_sha256, "replay input digest"),
            (self.replay_plan_sha256, "replay plan digest"),
            (self.replay_runtime_sha256, "replay runtime digest"),
            (self.research_configuration_sha256, "research configuration digest"),
        ):
            _require_sha256(value, field_name)
        if self.replay_run_id != self.replay_manifest_sha256:
            raise CapturedTapeResearchValidityError(
                "replay run ID must equal its content-addressed manifest digest"
            )
        for timestamp, field_name in (
            (self.coverage_start, "replay coverage_start"),
            (self.coverage_end, "replay coverage_end"),
            (self.replay_started_at, "replay started_at"),
            (self.replay_completed_at, "replay completed_at"),
            (self.valid_through, "replay valid_through"),
        ):
            _require_utc(timestamp, field_name)
        if self.coverage_end <= self.coverage_start:
            raise CapturedTapeResearchValidityError(
                "replay coverage_end must follow coverage_start"
            )
        if self.replay_completed_at < self.replay_started_at:
            raise CapturedTapeResearchValidityError("replay completion cannot precede replay start")
        if self.valid_through <= self.replay_completed_at:
            raise CapturedTapeResearchValidityError(
                "replay valid_through must follow replay completion"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
            "captured_tape_replay_evidence",
            self.evidence_id,
            self.decision,
            self.producer_id,
            self.replay_executor_id,
            self.capture_evidence_sha256,
            self.dataset_manifest_sha256,
            self.source_tape_sha256,
            self.replay_run_id,
            self.replay_manifest_sha256,
            self.replay_tape_sha256,
            self.replay_input_sha256,
            self.replay_plan_sha256,
            self.replay_runtime_sha256,
            self.research_configuration_sha256,
            self.coverage_start,
            self.coverage_end,
            self.replay_started_at,
            self.replay_completed_at,
            self.valid_through,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class CapturedTapeResearchSpecification:
    """Frozen exact bundle expected to qualify for one research context."""

    specification_id: str
    research_evidence_id: str
    review_context_id: str
    source_id: str
    provider: str
    dataset: str
    feed: str
    profile_sha256: str
    scope_sha256: str
    production_specification_sha256: str
    production_assessment_sha256: str
    source_admission_report_sha256: str
    capture_evidence_sha256: str
    capture_manifest_sha256: str
    dataset_manifest_sha256: str
    source_tape_sha256: str
    replay_evidence_sha256: str
    replay_manifest_sha256: str
    replay_tape_sha256: str
    replay_input_sha256: str
    replay_plan_sha256: str
    replay_runtime_sha256: str
    research_configuration_sha256: str
    coverage_start: datetime
    coverage_end: datetime
    frozen_at: datetime
    valid_through: datetime
    authenticated_provenance_sha256: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.specification_id, "captured-tape specification ID"),
            (self.research_evidence_id, "captured-tape research evidence ID"),
            (self.review_context_id, "captured-tape review context ID"),
            (self.source_id, "captured-tape source ID"),
            (self.provider, "captured-tape provider"),
            (self.dataset, "captured-tape dataset"),
            (self.feed, "captured-tape feed"),
        ):
            _require_safe_text(value, field_name)
        for value, field_name in (
            (self.profile_sha256, "captured-tape profile digest"),
            (self.scope_sha256, "captured-tape scope digest"),
            (self.production_specification_sha256, "production specification digest"),
            (self.production_assessment_sha256, "production assessment digest"),
            (self.source_admission_report_sha256, "source admission report digest"),
            (self.capture_evidence_sha256, "capture evidence digest"),
            (self.capture_manifest_sha256, "capture manifest digest"),
            (self.dataset_manifest_sha256, "dataset manifest digest"),
            (self.source_tape_sha256, "source tape digest"),
            (self.replay_evidence_sha256, "replay evidence digest"),
            (self.replay_manifest_sha256, "replay manifest digest"),
            (self.replay_tape_sha256, "replay tape digest"),
            (self.replay_input_sha256, "replay input digest"),
            (self.replay_plan_sha256, "replay plan digest"),
            (self.replay_runtime_sha256, "replay runtime digest"),
            (self.research_configuration_sha256, "research configuration digest"),
        ):
            _require_sha256(value, field_name)
        _require_optional_sha256(
            self.authenticated_provenance_sha256,
            "authenticated provenance digest",
        )
        for timestamp, field_name in (
            (self.coverage_start, "captured-tape coverage_start"),
            (self.coverage_end, "captured-tape coverage_end"),
            (self.frozen_at, "captured-tape frozen_at"),
            (self.valid_through, "captured-tape valid_through"),
        ):
            _require_utc(timestamp, field_name)
        if self.coverage_end <= self.coverage_start:
            raise CapturedTapeResearchValidityError(
                "captured-tape coverage_end must follow coverage_start"
            )
        if self.valid_through <= self.frozen_at:
            raise CapturedTapeResearchValidityError(
                "captured-tape valid_through must follow frozen_at"
            )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
                "captured_tape_research_specification",
                self.specification_id,
                self.research_evidence_id,
                self.review_context_id,
                self.source_id,
                self.provider,
                self.dataset,
                self.feed,
                self.profile_sha256,
                self.scope_sha256,
                self.production_specification_sha256,
                self.production_assessment_sha256,
                self.source_admission_report_sha256,
                self.capture_evidence_sha256,
                self.capture_manifest_sha256,
                self.dataset_manifest_sha256,
                self.source_tape_sha256,
                self.replay_evidence_sha256,
                self.replay_manifest_sha256,
                self.replay_tape_sha256,
                self.replay_input_sha256,
                self.replay_plan_sha256,
                self.replay_runtime_sha256,
                self.research_configuration_sha256,
                self.coverage_start,
                self.coverage_end,
                self.frozen_at,
                self.valid_through,
                self.authenticated_provenance_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()


def captured_tape_review_subject_sha256(
    specification: CapturedTapeResearchSpecification,
    capture: CapturedDatasetTapeEvidence,
    replay: CapturedTapeReplayEvidence,
) -> str:
    """Return the exact whole-bundle identity an independent review must bind."""

    if type(specification) is not CapturedTapeResearchSpecification:
        raise CapturedTapeResearchValidityError(
            "review subject requires an exact captured-tape specification"
        )
    if type(capture) is not CapturedDatasetTapeEvidence:
        raise CapturedTapeResearchValidityError(
            "review subject requires exact captured dataset/tape evidence"
        )
    if type(replay) is not CapturedTapeReplayEvidence:
        raise CapturedTapeResearchValidityError(
            "review subject requires exact captured-tape replay evidence"
        )
    specification.__post_init__()
    capture.__post_init__()
    replay.__post_init__()
    return _sha256(
        (
            CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
            "independent_review_subject",
            specification.semantic_sha256,
            capture.semantic_sha256,
            replay.semantic_sha256,
        )
    )


@dataclass(frozen=True, slots=True)
class IndependentCapturedTapeResearchReview:
    """Caller-asserted review over one exact source/tape/replay/config bundle.

    V1 checks structural separation of reviewer identifiers, but does not
    authenticate the asserted reviewer identity or review class.
    """

    review_id: str
    reviewer_id: str
    review_class: CapturedTapeReviewClass
    decision: CapturedTapeReviewDecision
    research_evidence_id: str
    review_context_id: str
    specification_sha256: str
    review_subject_sha256: str
    reviewed_at: datetime
    valid_through: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.review_id, "captured-tape review ID"),
            (self.reviewer_id, "captured-tape reviewer ID"),
            (self.research_evidence_id, "captured-tape review research evidence ID"),
            (self.review_context_id, "captured-tape review context ID"),
        ):
            _require_safe_text(value, field_name)
        _require_exact_enum(
            self.review_class,
            CapturedTapeReviewClass,
            "captured-tape review class",
        )
        _require_exact_enum(
            self.decision,
            CapturedTapeReviewDecision,
            "captured-tape review decision",
        )
        _require_sha256(self.specification_sha256, "captured-tape review specification digest")
        _require_sha256(self.review_subject_sha256, "captured-tape review subject digest")
        _require_utc(self.reviewed_at, "captured-tape reviewed_at")
        _require_utc(self.valid_through, "captured-tape review valid_through")
        if self.valid_through <= self.reviewed_at:
            raise CapturedTapeResearchValidityError(
                "captured-tape review valid_through must follow reviewed_at"
            )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
                "independent_captured_tape_review",
                self.review_id,
                self.reviewer_id,
                self.review_class,
                self.decision,
                self.research_evidence_id,
                self.review_context_id,
                self.specification_sha256,
                self.review_subject_sha256,
                self.reviewed_at,
                self.valid_through,
            )
        )


def _assessment_material(
    *,
    specification_sha256: str,
    production_assessment_sha256: str | None,
    current_production_assessment_sha256: str | None,
    source_admission_report_sha256: str | None,
    capture_evidence_sha256: str | None,
    authenticated_provenance_sha256: str | None,
    replay_evidence_sha256: str | None,
    review_sha256: str | None,
    executor_sha256: str,
    evaluated_at: datetime,
    blockers: tuple[CapturedTapeResearchBlocker, ...],
) -> tuple[object, ...]:
    return (
        CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION,
        "captured_tape_research_validity_assessment",
        specification_sha256,
        production_assessment_sha256,
        current_production_assessment_sha256,
        source_admission_report_sha256,
        capture_evidence_sha256,
        authenticated_provenance_sha256,
        replay_evidence_sha256,
        review_sha256,
        executor_sha256,
        evaluated_at,
        blockers,
    )


@dataclass(frozen=True, slots=True)
class _CapturedTapeResearchValiditySeal:
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class CapturedTapeResearchValidityAssessment:
    """Integrity-checked v1 result with no positive or operational authority."""

    specification_sha256: str
    production_assessment_sha256: str | None
    current_production_assessment_sha256: str | None
    source_admission_report_sha256: str | None
    capture_evidence_sha256: str | None
    authenticated_provenance_sha256: str | None
    replay_evidence_sha256: str | None
    review_sha256: str | None
    executor_sha256: str
    evaluated_at: datetime
    blockers: tuple[CapturedTapeResearchBlocker, ...]
    _seal: _CapturedTapeResearchValiditySeal = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _require_sha256(self.specification_sha256, "validity specification digest")
        for value, field_name in (
            (self.production_assessment_sha256, "production assessment digest"),
            (
                self.current_production_assessment_sha256,
                "current production assessment digest",
            ),
            (self.source_admission_report_sha256, "source admission report digest"),
            (self.capture_evidence_sha256, "capture evidence digest"),
            (
                self.authenticated_provenance_sha256,
                "authenticated provenance digest",
            ),
            (self.replay_evidence_sha256, "replay evidence digest"),
            (self.review_sha256, "review digest"),
        ):
            _require_optional_sha256(value, field_name)
        _require_sha256(self.executor_sha256, "validity executor digest")
        _require_utc(self.evaluated_at, "validity evaluated_at")
        if type(self.blockers) is not tuple or any(
            type(blocker) is not CapturedTapeResearchBlocker for blocker in self.blockers
        ):
            raise CapturedTapeResearchValidityError(
                "validity blockers must be an exact immutable tuple"
            )
        if len(set(self.blockers)) != len(self.blockers):
            raise CapturedTapeResearchValidityConflict("validity blockers must be unique")
        if self.blockers != tuple(sorted(self.blockers, key=_BLOCKER_ORDER.__getitem__)):
            raise CapturedTapeResearchValidityConflict(
                "validity blockers are not in canonical order"
            )
        if type(self._seal) is not _CapturedTapeResearchValiditySeal:
            raise CapturedTapeResearchValidityError(
                "validity assessment requires gate construction"
            )
        expected = _sha256(
            _assessment_material(
                specification_sha256=self.specification_sha256,
                production_assessment_sha256=self.production_assessment_sha256,
                current_production_assessment_sha256=(self.current_production_assessment_sha256),
                source_admission_report_sha256=self.source_admission_report_sha256,
                capture_evidence_sha256=self.capture_evidence_sha256,
                authenticated_provenance_sha256=(self.authenticated_provenance_sha256),
                replay_evidence_sha256=self.replay_evidence_sha256,
                review_sha256=self.review_sha256,
                executor_sha256=self.executor_sha256,
                evaluated_at=self.evaluated_at,
                blockers=self.blockers,
            )
        )
        if self._seal.payload_sha256 != expected:
            raise CapturedTapeResearchValidityConflict("validity assessment seal is invalid")
        provenance_blockers = {
            CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING,
            CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_INVALID,
        }.intersection(self.blockers)
        if len(provenance_blockers) != 1:
            raise CapturedTapeResearchValidityConflict(
                "v1 validity assessment requires exactly one external-provenance blocker"
            )

    @property
    def status(self) -> CapturedTapeResearchValidityStatus:
        self.__post_init__()
        if self.blockers:
            return CapturedTapeResearchValidityStatus.BLOCKED
        return CapturedTapeResearchValidityStatus.ELIGIBLE

    @property
    def counts_as_captured_tape_research_evidence(self) -> bool:
        return self.status is CapturedTapeResearchValidityStatus.ELIGIBLE

    @property
    def assessment_id(self) -> str:
        self.__post_init__()
        return f"captured-tape-validity-{self.semantic_sha256[:32]}"

    @property
    def canonical_json(self) -> str:
        self.__post_init__()
        return canonical_json_text(
            _assessment_material(
                specification_sha256=self.specification_sha256,
                production_assessment_sha256=self.production_assessment_sha256,
                current_production_assessment_sha256=(self.current_production_assessment_sha256),
                source_admission_report_sha256=self.source_admission_report_sha256,
                capture_evidence_sha256=self.capture_evidence_sha256,
                authenticated_provenance_sha256=(self.authenticated_provenance_sha256),
                replay_evidence_sha256=self.replay_evidence_sha256,
                review_sha256=self.review_sha256,
                executor_sha256=self.executor_sha256,
                evaluated_at=self.evaluated_at,
                blockers=self.blockers,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return self._seal.payload_sha256

    @property
    def historical_source_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def admission_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def canonical_market_data_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def promotion_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def deployment_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def trading_effect(self) -> CapturedTapeAuthorityEffect:
        return CapturedTapeAuthorityEffect.NONE

    @property
    def historical_source_authorized(self) -> bool:
        return False

    @property
    def admission_authorized(self) -> bool:
        return False

    @property
    def canonical_market_data_authorized(self) -> bool:
        return False

    @property
    def promotion_authorized(self) -> bool:
        return False

    @property
    def deployment_authorized(self) -> bool:
        return False

    @property
    def trading_authorized(self) -> bool:
        return False


def _same_production_assessment(
    observed: ProductionEvidenceGateAssessment,
    expected: ProductionEvidenceGateAssessment,
) -> bool:
    return (
        observed.specification_sha256 == expected.specification_sha256
        and observed.evidence_bundle_sha256 == expected.evidence_bundle_sha256
        and observed.review_sha256 == expected.review_sha256
        and observed.executor_sha256 == expected.executor_sha256
        and observed.evaluated_at == expected.evaluated_at
        and observed.blockers == expected.blockers
        and observed.semantic_sha256 == expected.semantic_sha256
    )


def assess_captured_tape_research_validity(
    *,
    specification: CapturedTapeResearchSpecification,
    production_prerequisite: ProductionEvidencePrerequisite | None,
    source_admission: AdmittedHistoricalSourceEvidence | None,
    capture: CapturedDatasetTapeEvidence | None,
    replay: CapturedTapeReplayEvidence | None,
    review: IndependentCapturedTapeResearchReview | None,
    executor_id: str,
    evaluated_at: datetime,
    authenticated_provenance: AuthenticatedCapturedTapeProvenance | None = None,
) -> CapturedTapeResearchValidityAssessment:
    """Evaluate exact claims while retaining v1's external-provenance blocker."""

    if type(specification) is not CapturedTapeResearchSpecification:
        raise CapturedTapeResearchValidityError(
            "captured-tape validity requires an exact specification"
        )
    specification.__post_init__()
    _require_safe_text(executor_id, "captured-tape validity executor ID")
    _require_utc(evaluated_at, "captured-tape validity evaluated_at")

    blockers: list[CapturedTapeResearchBlocker] = []
    production_assessment_sha256: str | None = None
    current_production_assessment_sha256: str | None = None
    production_assessment: ProductionEvidenceGateAssessment | None = None
    source_report: AdmissionReport | None = None

    if production_prerequisite is None:
        blockers.append(CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_MISSING)
    else:
        if type(production_prerequisite) is not ProductionEvidencePrerequisite:
            raise CapturedTapeResearchValidityError(
                "captured-tape validity requires exact production prerequisite inputs"
            )
        production_prerequisite.__post_init__()
        production_assessment = production_prerequisite.assessment
        try:
            production_assessment.__post_init__()
            expected_assessment = assess_production_market_data_evidence(
                specification=production_prerequisite.specification,
                evidence=production_prerequisite.evidence,
                review=production_prerequisite.review,
                executor_id=production_prerequisite.executor_id,
                evaluated_at=production_assessment.evaluated_at,
            )
            assessment_matches = _same_production_assessment(
                production_assessment,
                expected_assessment,
            )
        except ValueError:
            assessment_matches = False
        production_assessment_sha256 = production_assessment.semantic_sha256
        if not assessment_matches:
            blockers.append(CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_ASSESSMENT_MISMATCH)
        if production_assessment.status is not (
            ProductionEvidenceGateStatus.READY_FOR_ADMISSION_EVALUATION
        ):
            blockers.append(CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_BLOCKED)

        current_assessment = assess_production_market_data_evidence(
            specification=production_prerequisite.specification,
            evidence=production_prerequisite.evidence,
            review=production_prerequisite.review,
            executor_id=production_prerequisite.executor_id,
            evaluated_at=evaluated_at,
        )
        current_production_assessment_sha256 = current_assessment.semantic_sha256
        if current_assessment.status is not (
            ProductionEvidenceGateStatus.READY_FOR_ADMISSION_EVALUATION
        ):
            blockers.append(CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_NOT_CURRENT)

        production_specification = production_prerequisite.specification
        if (
            production_specification.semantic_sha256
            != specification.production_specification_sha256
            or production_assessment.semantic_sha256 != specification.production_assessment_sha256
            or production_specification.source_id != specification.source_id
            or production_specification.provider != specification.provider
            or production_specification.dataset != specification.dataset
            or production_specification.feed != specification.feed
            or production_specification.profile_sha256 != specification.profile_sha256
            or production_specification.scope_sha256 != specification.scope_sha256
        ):
            blockers.append(CapturedTapeResearchBlocker.PRODUCTION_PREREQUISITE_BINDING_MISMATCH)

    if source_admission is None:
        blockers.append(CapturedTapeResearchBlocker.SOURCE_ADMISSION_MISSING)
    else:
        if type(source_admission) is not AdmittedHistoricalSourceEvidence:
            raise CapturedTapeResearchValidityError(
                "captured-tape validity requires exact source admission inputs"
            )
        source_admission.__post_init__()
        try:
            source_admission.specification.__post_init__()
            source_admission.evidence.__post_init__()
            source_admission.report.__post_init__()
            expected_report = evaluate_admission(
                source_admission.specification,
                source_admission.evidence,
            )
            report_matches = source_admission.report == expected_report
        except ValueError:
            report_matches = False
        source_report = source_admission.report
        if not report_matches:
            blockers.append(CapturedTapeResearchBlocker.SOURCE_ADMISSION_REPORT_MISMATCH)
        if source_report.status is not AdmissionStatus.ADMITTED:
            blockers.append(CapturedTapeResearchBlocker.SOURCE_NOT_ADMITTED)
        if (
            source_admission.specification.source_id != specification.source_id
            or source_admission.evidence.source_id != specification.source_id
            or source_report.source_id != specification.source_id
            or source_report.report_digest != specification.source_admission_report_sha256
        ):
            blockers.append(CapturedTapeResearchBlocker.SOURCE_ADMISSION_BINDING_MISMATCH)
        admission_evidence_times = (
            source_report.evaluated_at,
            *(check.checked_at for check in source_admission.evidence.technical_checks),
            *(
                ()
                if source_admission.evidence.approval is None
                else (source_admission.evidence.approval.reviewed_at,)
            ),
        )
        if any(timestamp > evaluated_at for timestamp in admission_evidence_times):
            blockers.append(CapturedTapeResearchBlocker.SOURCE_ADMISSION_IN_FUTURE)
        if any(
            timestamp <= evaluated_at and evaluated_at - timestamp >= SOURCE_ADMISSION_MAX_AGE
            for timestamp in admission_evidence_times
        ):
            blockers.append(CapturedTapeResearchBlocker.SOURCE_ADMISSION_STALE)

    if capture is None:
        blockers.append(CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_MISSING)
        capture_evidence_sha256 = None
    else:
        if type(capture) is not CapturedDatasetTapeEvidence:
            raise CapturedTapeResearchValidityError(
                "captured-tape validity requires exact captured dataset/tape evidence"
            )
        capture.__post_init__()
        capture_evidence_sha256 = capture.semantic_sha256
        if capture.evidence_class is not CapturedTapeEvidenceClass.VENDOR_CAPTURED:
            blockers.append(CapturedTapeResearchBlocker.NON_VENDOR_CAPTURE_EVIDENCE)
        if capture.decision is not CapturedTapeEvidenceDecision.VERIFIED:
            blockers.append(CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_REJECTED)
        if capture.retention_kind is not CapturedTapeRetentionKind.CONTENT_ADDRESSED_IMMUTABLE:
            blockers.append(CapturedTapeResearchBlocker.CAPTURE_NOT_IMMUTABLE)
        if (
            capture.semantic_sha256 != specification.capture_evidence_sha256
            or capture.source_id != specification.source_id
            or capture.provider != specification.provider
            or capture.dataset != specification.dataset
            or capture.feed != specification.feed
            or capture.profile_sha256 != specification.profile_sha256
            or capture.scope_sha256 != specification.scope_sha256
            or capture.production_specification_sha256
            != specification.production_specification_sha256
            or capture.production_assessment_sha256 != specification.production_assessment_sha256
            or capture.source_admission_report_sha256
            != specification.source_admission_report_sha256
            or capture.capture_manifest_sha256 != specification.capture_manifest_sha256
            or capture.dataset_manifest_sha256 != specification.dataset_manifest_sha256
            or capture.source_tape_sha256 != specification.source_tape_sha256
            or capture.coverage_start != specification.coverage_start
            or capture.coverage_end != specification.coverage_end
        ):
            blockers.append(CapturedTapeResearchBlocker.CAPTURE_BINDING_MISMATCH)
        if capture.sealed_at > evaluated_at:
            blockers.append(CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_IN_FUTURE)
        if evaluated_at >= capture.valid_through:
            blockers.append(CapturedTapeResearchBlocker.CAPTURE_EVIDENCE_STALE)

    if authenticated_provenance is None:
        blockers.append(CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_MISSING)
        authenticated_provenance_sha256 = None
    else:
        # V1 deliberately has no local trust root or issuer. An exact Python
        # instance, including one forged with object.__new__, is not evidence of
        # externally authenticated provenance and cannot remove this blocker.
        blockers.append(CapturedTapeResearchBlocker.AUTHENTICATED_CAPTURE_PROVENANCE_INVALID)
        authenticated_provenance_sha256 = None

    if replay is None:
        blockers.append(CapturedTapeResearchBlocker.REPLAY_EVIDENCE_MISSING)
        replay_evidence_sha256 = None
    else:
        if type(replay) is not CapturedTapeReplayEvidence:
            raise CapturedTapeResearchValidityError(
                "captured-tape validity requires exact replay evidence"
            )
        replay.__post_init__()
        replay_evidence_sha256 = replay.semantic_sha256
        if replay.decision is not CapturedTapeEvidenceDecision.VERIFIED:
            blockers.append(CapturedTapeResearchBlocker.REPLAY_EVIDENCE_REJECTED)
        expected_capture_sha256 = None if capture is None else capture.semantic_sha256
        if (
            replay.semantic_sha256 != specification.replay_evidence_sha256
            or replay.capture_evidence_sha256 != expected_capture_sha256
            or replay.dataset_manifest_sha256 != specification.dataset_manifest_sha256
            or replay.source_tape_sha256 != specification.source_tape_sha256
            or replay.replay_manifest_sha256 != specification.replay_manifest_sha256
            or replay.replay_tape_sha256 != specification.replay_tape_sha256
            or replay.replay_input_sha256 != specification.replay_input_sha256
            or replay.replay_plan_sha256 != specification.replay_plan_sha256
            or replay.replay_runtime_sha256 != specification.replay_runtime_sha256
            or replay.coverage_start != specification.coverage_start
            or replay.coverage_end != specification.coverage_end
        ):
            blockers.append(CapturedTapeResearchBlocker.REPLAY_BINDING_MISMATCH)
        if replay.research_configuration_sha256 != specification.research_configuration_sha256:
            blockers.append(CapturedTapeResearchBlocker.CONFIGURATION_BINDING_MISMATCH)
        if replay.replay_completed_at > evaluated_at:
            blockers.append(CapturedTapeResearchBlocker.REPLAY_EVIDENCE_IN_FUTURE)
        if evaluated_at >= replay.valid_through:
            blockers.append(CapturedTapeResearchBlocker.REPLAY_EVIDENCE_STALE)

    if evaluated_at < specification.frozen_at:
        blockers.append(CapturedTapeResearchBlocker.EVALUATION_PREDATES_SPECIFICATION)
    if evaluated_at >= specification.valid_through:
        blockers.append(CapturedTapeResearchBlocker.SPECIFICATION_STALE)

    if (
        production_assessment is not None
        and source_report is not None
        and capture is not None
        and not (
            production_assessment.evaluated_at
            < source_report.evaluated_at
            < capture.capture_started_at
        )
    ):
        blockers.append(CapturedTapeResearchBlocker.TEMPORAL_BINDING_MISMATCH)
    if (
        capture is not None
        and replay is not None
        and not (
            capture.sealed_at
            < specification.frozen_at
            < replay.replay_started_at
            < replay.replay_completed_at
            <= evaluated_at
        )
    ):
        blockers.append(CapturedTapeResearchBlocker.TEMPORAL_BINDING_MISMATCH)

    if review is None:
        blockers.append(CapturedTapeResearchBlocker.INDEPENDENT_REVIEW_MISSING)
        review_sha256 = None
    else:
        if type(review) is not IndependentCapturedTapeResearchReview:
            raise CapturedTapeResearchValidityError(
                "captured-tape validity requires an exact independent review"
            )
        review.__post_init__()
        review_sha256 = review.semantic_sha256
        if review.review_class is not CapturedTapeReviewClass.EXTERNAL_INDEPENDENT:
            blockers.append(CapturedTapeResearchBlocker.NON_EXTERNAL_REVIEW)
        if review.decision is not CapturedTapeReviewDecision.APPROVED:
            blockers.append(CapturedTapeResearchBlocker.REVIEW_REJECTED)
        if (
            review.research_evidence_id != specification.research_evidence_id
            or review.review_context_id != specification.review_context_id
            or review.specification_sha256 != specification.semantic_sha256
        ):
            blockers.append(CapturedTapeResearchBlocker.REVIEW_BINDING_MISMATCH)
        expected_review_subject = None
        if capture is not None and replay is not None:
            expected_review_subject = captured_tape_review_subject_sha256(
                specification,
                capture,
                replay,
            )
        if review.review_subject_sha256 != expected_review_subject:
            blockers.append(CapturedTapeResearchBlocker.REVIEW_REPLAYED_OR_SUBSTITUTED)

        latest_evidence_at = specification.frozen_at
        if capture is not None:
            latest_evidence_at = max(latest_evidence_at, capture.sealed_at)
        if replay is not None:
            latest_evidence_at = max(latest_evidence_at, replay.replay_completed_at)
        if source_report is not None:
            latest_evidence_at = max(latest_evidence_at, source_report.evaluated_at)
        if production_assessment is not None:
            latest_evidence_at = max(
                latest_evidence_at,
                production_assessment.evaluated_at,
            )
        if review.reviewed_at <= latest_evidence_at:
            blockers.append(CapturedTapeResearchBlocker.REVIEW_PREDATES_EVIDENCE)
        if review.reviewed_at > evaluated_at:
            blockers.append(CapturedTapeResearchBlocker.REVIEW_OBSERVED_IN_FUTURE)
        if evaluated_at >= review.valid_through:
            blockers.append(CapturedTapeResearchBlocker.REVIEW_STALE)

        disallowed_reviewers = {executor_id}
        if production_prerequisite is not None:
            disallowed_reviewers.add(production_prerequisite.executor_id)
            disallowed_reviewers.update(
                attestation.producer_id
                for attestation in production_prerequisite.evidence.attestations
            )
            if production_prerequisite.review is not None:
                disallowed_reviewers.add(production_prerequisite.review.reviewer_id)
        if source_admission is not None:
            disallowed_reviewers.add(source_admission.evidence.executor_id)
            if source_admission.evidence.approval is not None:
                disallowed_reviewers.add(source_admission.evidence.approval.reviewer_id)
        if capture is not None:
            disallowed_reviewers.update({capture.producer_id, capture.capture_executor_id})
        if replay is not None:
            disallowed_reviewers.update({replay.producer_id, replay.replay_executor_id})
        if review.reviewer_id in disallowed_reviewers:
            blockers.append(CapturedTapeResearchBlocker.SELF_APPROVED)

    ordered_blockers = tuple(sorted(set(blockers), key=_BLOCKER_ORDER.__getitem__))
    executor_sha256 = hashlib.sha256(executor_id.encode("utf-8")).hexdigest()
    material = _assessment_material(
        specification_sha256=specification.semantic_sha256,
        production_assessment_sha256=production_assessment_sha256,
        current_production_assessment_sha256=current_production_assessment_sha256,
        source_admission_report_sha256=(
            None if source_report is None else source_report.report_digest
        ),
        capture_evidence_sha256=capture_evidence_sha256,
        authenticated_provenance_sha256=authenticated_provenance_sha256,
        replay_evidence_sha256=replay_evidence_sha256,
        review_sha256=review_sha256,
        executor_sha256=executor_sha256,
        evaluated_at=evaluated_at,
        blockers=ordered_blockers,
    )
    return CapturedTapeResearchValidityAssessment(
        specification_sha256=specification.semantic_sha256,
        production_assessment_sha256=production_assessment_sha256,
        current_production_assessment_sha256=current_production_assessment_sha256,
        source_admission_report_sha256=(
            None if source_report is None else source_report.report_digest
        ),
        capture_evidence_sha256=capture_evidence_sha256,
        authenticated_provenance_sha256=authenticated_provenance_sha256,
        replay_evidence_sha256=replay_evidence_sha256,
        review_sha256=review_sha256,
        executor_sha256=executor_sha256,
        evaluated_at=evaluated_at,
        blockers=ordered_blockers,
        _seal=_CapturedTapeResearchValiditySeal(payload_sha256=_sha256(material)),
    )


__all__ = [
    "CAPTURED_TAPE_RESEARCH_VALIDITY_CONTRACT_VERSION",
    "SOURCE_ADMISSION_MAX_AGE",
    "AdmittedHistoricalSourceEvidence",
    "AuthenticatedCapturedTapeProvenance",
    "CapturedDatasetTapeEvidence",
    "CapturedTapeAuthorityEffect",
    "CapturedTapeEvidenceClass",
    "CapturedTapeEvidenceDecision",
    "CapturedTapeReplayEvidence",
    "CapturedTapeResearchBlocker",
    "CapturedTapeResearchSpecification",
    "CapturedTapeResearchValidityAssessment",
    "CapturedTapeResearchValidityConflict",
    "CapturedTapeResearchValidityError",
    "CapturedTapeResearchValidityStatus",
    "CapturedTapeRetentionKind",
    "CapturedTapeReviewClass",
    "CapturedTapeReviewDecision",
    "IndependentCapturedTapeResearchReview",
    "ProductionEvidencePrerequisite",
    "assess_captured_tape_research_validity",
    "captured_tape_review_subject_sha256",
]
