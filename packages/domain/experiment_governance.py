"""Pure bounded experiment governance with an opaque pre-reveal holdout.

The contracts in this module govern research declarations and lifecycle facts.
They deliberately do not execute a backtest, persist data, launch a worker, or
grant promotion or trading authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from typing import Self

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.experiment_registry import (
    EvaluationSegment,
    EvaluationSegmentKind,
    FrozenPromotionCriteria,
    StrategyConfigurationRecord,
    StrategyVersionRecord,
    validate_strategy_configuration_parameters,
)
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.feature_target import (
    MAX_TARGET_LIFETIME,
    REFERENCE_FEATURE_TARGET_STRATEGY_ID,
    REFERENCE_FEATURE_TARGET_STRATEGY_VERSION,
    CertifiedFeatureTargetReplay,
    RollingCloseMeanTargetPolicy,
)

EXPERIMENT_GOVERNANCE_CONTRACT_VERSION = "phase3-experiment-governance-v2"
EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION = "phase3-segment-evaluation-v1"
NON_EXECUTABLE_DOMAIN_FIXTURE = "non_executable_domain_fixture"
GOVERNED_SEGMENT_EVALUATION = "governed_segment_evaluation"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_STATUSES: frozenset[ExperimentAttemptStatus]


class ExperimentGovernanceError(ValueError):
    """An experiment-governance fact violates the bounded contract."""


class ExperimentAttemptStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    ABANDONED = "abandoned"


_TERMINAL_STATUSES = frozenset(
    {
        ExperimentAttemptStatus.COMPLETED,
        ExperimentAttemptStatus.FAILED,
        ExperimentAttemptStatus.CANCELED,
        ExperimentAttemptStatus.ABANDONED,
    }
)


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _payload_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ExperimentGovernanceError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_text(value: str, field_name: str, *, maximum: int = 1024) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ExperimentGovernanceError(f"{field_name} must be bounded, non-empty trimmed text")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ExperimentGovernanceError(f"{field_name} must be a timezone-aware UTC datetime")


def _certification_scope(
    certification: CertifiedFeatureReplay,
) -> tuple[datetime, datetime, str]:
    if type(certification) is not CertifiedFeatureReplay:
        raise ExperimentGovernanceError("segment evidence requires an exact CertifiedFeatureReplay")
    replay = certification.batch_result.source_replay
    if not replay.batches:
        raise ExperimentGovernanceError("segment certification requires a non-empty replay")
    return (
        replay.batches[0].watermark.event_time_through,
        replay.batches[-1].watermark.event_time_through,
        replay.semantic_sha256,
    )


def _validate_segment_certification(
    segment: EvaluationSegment,
    certification: CertifiedFeatureReplay,
) -> None:
    if type(segment) is not EvaluationSegment:
        raise ExperimentGovernanceError("segment evidence requires an exact segment")
    coverage_start, coverage_end, replay_sha256 = _certification_scope(certification)
    if (
        segment.coverage_start != coverage_start
        or segment.coverage_end != coverage_end
        or segment.dataset_replay_sha256 != replay_sha256
    ):
        raise ExperimentGovernanceError(
            "segment certification does not match the exact declared replay scope"
        )


@dataclass(frozen=True, slots=True, init=False)
class StrategyConfigurationValidationReceipt:
    """Proof that one exact configuration satisfies its registered schema."""

    strategy_version_sha256: str
    configuration_sha256: str
    parameter_schema_sha256: str
    parameter_schema_payload: str
    parameters_sha256: str
    receipt_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "StrategyConfigurationValidationReceipt is proof-constructed from exact records"
        )

    @classmethod
    def from_configuration(
        cls,
        strategy_version: StrategyVersionRecord,
        configuration: StrategyConfigurationRecord,
        parameter_schema_payload: str,
    ) -> Self:
        if type(strategy_version) is not StrategyVersionRecord:
            raise ExperimentGovernanceError(
                "configuration validation requires an exact strategy version"
            )
        if type(configuration) is not StrategyConfigurationRecord:
            raise ExperimentGovernanceError(
                "configuration validation requires an exact configuration"
            )
        if configuration.strategy_version_sha256 != strategy_version.semantic_sha256:
            raise ExperimentGovernanceError(
                "configuration validation changed strategy-version identity"
            )
        if type(parameter_schema_payload) is not str or (
            _payload_sha256(parameter_schema_payload) != strategy_version.parameter_schema_sha256
        ):
            raise ExperimentGovernanceError(
                "configuration validation changed the registered parameter schema"
            )
        validate_strategy_configuration_parameters(
            parameter_schema_payload,
            configuration.parameters,
        )
        parameters_sha256 = _sha256(tuple(configuration.parameters.items()))
        return cls._restore(
            strategy_version_sha256=strategy_version.semantic_sha256,
            configuration_sha256=configuration.semantic_sha256,
            parameter_schema_sha256=strategy_version.parameter_schema_sha256,
            parameter_schema_payload=parameter_schema_payload,
            parameters_sha256=parameters_sha256,
        )

    @classmethod
    def _restore(
        cls,
        *,
        strategy_version_sha256: str,
        configuration_sha256: str,
        parameter_schema_sha256: str,
        parameter_schema_payload: str,
        parameters_sha256: str,
        expected_receipt_sha256: str | None = None,
    ) -> Self:
        for value, field_name in (
            (strategy_version_sha256, "validation strategy-version digest"),
            (configuration_sha256, "validation configuration digest"),
            (parameter_schema_sha256, "validation parameter-schema digest"),
            (parameters_sha256, "validation parameters digest"),
        ):
            _require_sha256(value, field_name)
        if type(parameter_schema_payload) is not str or (
            _payload_sha256(parameter_schema_payload) != parameter_schema_sha256
        ):
            raise ExperimentGovernanceError(
                "validation parameter-schema payload conflicts with its digest"
            )
        material = (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "strategy-configuration-validation",
            strategy_version_sha256,
            configuration_sha256,
            parameter_schema_sha256,
            parameter_schema_payload,
            parameters_sha256,
        )
        receipt_sha256 = _sha256(material)
        if expected_receipt_sha256 is not None and expected_receipt_sha256 != receipt_sha256:
            raise ExperimentGovernanceError(
                "configuration-validation receipt digest is inconsistent"
            )
        instance = object.__new__(cls)
        for name, value in (
            ("strategy_version_sha256", strategy_version_sha256),
            ("configuration_sha256", configuration_sha256),
            ("parameter_schema_sha256", parameter_schema_sha256),
            ("parameter_schema_payload", parameter_schema_payload),
            ("parameters_sha256", parameters_sha256),
            ("receipt_sha256", receipt_sha256),
        ):
            object.__setattr__(instance, name, value)
        return instance

    @property
    def semantic_sha256(self) -> str:
        return self.receipt_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "strategy-configuration-validation",
            self.strategy_version_sha256,
            self.configuration_sha256,
            self.parameter_schema_sha256,
            self.parameter_schema_payload,
            self.parameters_sha256,
        )


@dataclass(frozen=True, slots=True, init=False)
class ExperimentSegmentEvidence:
    """Configuration-neutral feature input for one declared evaluation segment."""

    segment: EvaluationSegment
    feature_certification_sha256: str
    dataset_manifest_sha256: str
    source_tape_sha256: str
    replay_run_id: str
    replay_manifest_sha256: str
    replay_result_sha256: str
    feature_artifact_sha256: str
    feature_parity_receipt_sha256: str
    feature_transcript_sha256: str
    step_count: int
    snapshot_count: int
    evidence_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ExperimentSegmentEvidence is proof-constructed from exact evidence")

    @classmethod
    def from_certification(
        cls,
        segment: EvaluationSegment,
        certification: CertifiedFeatureReplay,
    ) -> Self:
        if type(segment) is not EvaluationSegment or segment.kind not in {
            EvaluationSegmentKind.TRAIN,
            EvaluationSegmentKind.VALIDATION,
        }:
            raise ExperimentGovernanceError(
                "pre-reveal segment evidence is limited to train or validation"
            )
        return cls._from_certification(segment, certification)

    @classmethod
    def _from_certification(
        cls,
        segment: EvaluationSegment,
        certification: CertifiedFeatureReplay,
    ) -> Self:
        _validate_segment_certification(segment, certification)
        lineage = certification.artifact.lineage
        return cls._restore(
            segment=segment,
            feature_certification_sha256=certification.semantic_sha256,
            dataset_manifest_sha256=lineage.manifest_sha256,
            source_tape_sha256=lineage.replay_tape_sha256,
            replay_run_id=lineage.replay_run_id,
            replay_manifest_sha256=lineage.replay_run_manifest_sha256,
            replay_result_sha256=lineage.replay_result_sha256,
            feature_artifact_sha256=certification.artifact.semantic_sha256,
            feature_parity_receipt_sha256=certification.receipt.semantic_sha256,
            feature_transcript_sha256=certification.batch_result.transcript_sha256,
            step_count=len(certification.batch_result.steps),
            snapshot_count=len(certification.batch_result.snapshots),
        )

    @classmethod
    def _restore(
        cls,
        *,
        segment: EvaluationSegment,
        feature_certification_sha256: str,
        dataset_manifest_sha256: str,
        source_tape_sha256: str,
        replay_run_id: str,
        replay_manifest_sha256: str,
        replay_result_sha256: str,
        feature_artifact_sha256: str,
        feature_parity_receipt_sha256: str,
        feature_transcript_sha256: str,
        step_count: int,
        snapshot_count: int,
        expected_evidence_sha256: str | None = None,
    ) -> Self:
        if type(segment) is not EvaluationSegment:
            raise ExperimentGovernanceError("segment evidence requires an exact segment")
        for value, field_name in (
            (feature_certification_sha256, "segment feature-certification digest"),
            (dataset_manifest_sha256, "segment dataset-manifest digest"),
            (source_tape_sha256, "segment source-tape digest"),
            (replay_run_id, "segment replay run ID"),
            (replay_manifest_sha256, "segment replay-manifest digest"),
            (replay_result_sha256, "segment replay-result digest"),
            (feature_artifact_sha256, "segment feature-artifact digest"),
            (feature_parity_receipt_sha256, "segment feature-parity digest"),
            (feature_transcript_sha256, "segment feature-transcript digest"),
        ):
            _require_sha256(value, field_name)
        if replay_run_id != replay_manifest_sha256:
            raise ExperimentGovernanceError(
                "segment replay run must retain content-addressed manifest identity"
            )
        if segment.dataset_replay_sha256 != replay_result_sha256:
            raise ExperimentGovernanceError(
                "segment declaration changed the certified replay-result identity"
            )
        if type(step_count) is not int or not 1 <= step_count <= 100_000:
            raise ExperimentGovernanceError("segment evidence step count is outside its bound")
        if type(snapshot_count) is not int or snapshot_count < 0 or snapshot_count > 5_000_000:
            raise ExperimentGovernanceError("segment evidence snapshot count is outside its bound")
        material = (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-segment-evidence",
            segment.semantic_sha256,
            feature_certification_sha256,
            dataset_manifest_sha256,
            source_tape_sha256,
            replay_run_id,
            replay_manifest_sha256,
            replay_result_sha256,
            feature_artifact_sha256,
            feature_parity_receipt_sha256,
            feature_transcript_sha256,
            step_count,
            snapshot_count,
        )
        evidence_sha256 = _sha256(material)
        if expected_evidence_sha256 is not None and expected_evidence_sha256 != evidence_sha256:
            raise ExperimentGovernanceError("segment evidence digest is inconsistent")
        instance = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("segment", segment),
            ("feature_certification_sha256", feature_certification_sha256),
            ("dataset_manifest_sha256", dataset_manifest_sha256),
            ("source_tape_sha256", source_tape_sha256),
            ("replay_run_id", replay_run_id),
            ("replay_manifest_sha256", replay_manifest_sha256),
            ("replay_result_sha256", replay_result_sha256),
            ("feature_artifact_sha256", feature_artifact_sha256),
            ("feature_parity_receipt_sha256", feature_parity_receipt_sha256),
            ("feature_transcript_sha256", feature_transcript_sha256),
            ("step_count", step_count),
            ("snapshot_count", snapshot_count),
            ("evidence_sha256", evidence_sha256),
        )
        for name, field_value in values:
            object.__setattr__(instance, name, field_value)
        return instance

    @property
    def semantic_sha256(self) -> str:
        return self.evidence_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def require_certification(self, certification: CertifiedFeatureReplay) -> None:
        """Reject any feature input other than the exact scoped certification."""

        expected = type(self)._from_certification(self.segment, certification)
        if expected != self:
            raise ExperimentGovernanceError(
                "feature certification does not match the exact segment input"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-segment-evidence",
            self.segment.semantic_sha256,
            self.feature_certification_sha256,
            self.dataset_manifest_sha256,
            self.source_tape_sha256,
            self.replay_run_id,
            self.replay_manifest_sha256,
            self.replay_result_sha256,
            self.feature_artifact_sha256,
            self.feature_parity_receipt_sha256,
            self.feature_transcript_sha256,
            self.step_count,
            self.snapshot_count,
        )


@dataclass(frozen=True, slots=True, init=False)
class TestSegmentCommitment:
    """Opaque pre-reveal commitment to configuration-neutral final-test input."""

    segment_sha256: str
    dataset_replay_sha256: str
    source_tape_sha256: str
    content_commitment_sha256: str
    feature_certification_commitment_sha256: str
    commitment_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("TestSegmentCommitment is proof-constructed from exact test evidence")

    @classmethod
    def from_certification(
        cls,
        segment: EvaluationSegment,
        certification: CertifiedFeatureReplay,
    ) -> Self:
        if type(segment) is not EvaluationSegment or segment.kind is not EvaluationSegmentKind.TEST:
            raise ExperimentGovernanceError("holdout commitment requires the exact test segment")
        _validate_segment_certification(segment, certification)
        source_tape_sha256 = certification.artifact.lineage.replay_tape_sha256
        content_commitment_sha256 = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "sealed-test-replay-content",
                source_tape_sha256,
            )
        )
        feature_certification_commitment_sha256 = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "sealed-test-feature-certification",
                certification.semantic_sha256,
            )
        )
        return cls._restore(
            segment_sha256=segment.semantic_sha256,
            dataset_replay_sha256=segment.dataset_replay_sha256,
            source_tape_sha256=source_tape_sha256,
            content_commitment_sha256=content_commitment_sha256,
            feature_certification_commitment_sha256=(feature_certification_commitment_sha256),
        )

    @classmethod
    def _restore(
        cls,
        *,
        segment_sha256: str,
        dataset_replay_sha256: str,
        source_tape_sha256: str,
        content_commitment_sha256: str,
        feature_certification_commitment_sha256: str,
        expected_commitment_sha256: str | None = None,
    ) -> Self:
        for value, field_name in (
            (segment_sha256, "test segment digest"),
            (dataset_replay_sha256, "test replay-result digest"),
            (source_tape_sha256, "test source-tape digest"),
            (content_commitment_sha256, "test replay-content commitment"),
            (
                feature_certification_commitment_sha256,
                "test feature-certification commitment",
            ),
        ):
            _require_sha256(value, field_name)
        expected_content_commitment = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "sealed-test-replay-content",
                source_tape_sha256,
            )
        )
        if content_commitment_sha256 != expected_content_commitment:
            raise ExperimentGovernanceError("test replay-content commitment is inconsistent")
        commitment_sha256 = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "test-segment-commitment",
                segment_sha256,
                dataset_replay_sha256,
                source_tape_sha256,
                content_commitment_sha256,
                feature_certification_commitment_sha256,
            )
        )
        if expected_commitment_sha256 is not None and (
            expected_commitment_sha256 != commitment_sha256
        ):
            raise ExperimentGovernanceError("test commitment digest is inconsistent")
        instance = object.__new__(cls)
        for name, value in (
            ("segment_sha256", segment_sha256),
            ("dataset_replay_sha256", dataset_replay_sha256),
            ("source_tape_sha256", source_tape_sha256),
            ("content_commitment_sha256", content_commitment_sha256),
            (
                "feature_certification_commitment_sha256",
                feature_certification_commitment_sha256,
            ),
            ("commitment_sha256", commitment_sha256),
        ):
            object.__setattr__(instance, name, value)
        return instance

    def require_certification(
        self,
        segment: EvaluationSegment,
        certification: CertifiedFeatureReplay,
    ) -> ExperimentSegmentEvidence:
        if type(segment) is not EvaluationSegment or segment.kind is not EvaluationSegmentKind.TEST:
            raise ExperimentGovernanceError("holdout opening requires the exact test segment")
        _validate_segment_certification(segment, certification)
        evidence = ExperimentSegmentEvidence._from_certification(segment, certification)
        self.require_evidence(segment, evidence)
        return evidence

    def require_evidence(
        self,
        segment: EvaluationSegment,
        evidence: ExperimentSegmentEvidence,
    ) -> None:
        """Verify that an opened receipt matches this exact sealed commitment."""

        if (
            type(segment) is not EvaluationSegment
            or segment.kind is not EvaluationSegmentKind.TEST
            or type(evidence) is not ExperimentSegmentEvidence
            or evidence.segment != segment
        ):
            raise ExperimentGovernanceError("holdout opening requires exact final-test evidence")
        feature_certification_commitment_sha256 = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "sealed-test-feature-certification",
                evidence.feature_certification_sha256,
            )
        )
        content_commitment_sha256 = _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "sealed-test-replay-content",
                evidence.source_tape_sha256,
            )
        )
        if (
            self.segment_sha256 != segment.semantic_sha256
            or self.dataset_replay_sha256 != segment.dataset_replay_sha256
            or self.source_tape_sha256 != evidence.source_tape_sha256
            or self.content_commitment_sha256 != content_commitment_sha256
            or self.feature_certification_commitment_sha256
            != feature_certification_commitment_sha256
        ):
            raise ExperimentGovernanceError(
                "test evidence does not open the registered holdout commitment"
            )

    @property
    def semantic_sha256(self) -> str:
        return self.commitment_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "test-segment-commitment",
                self.segment_sha256,
                self.dataset_replay_sha256,
                self.source_tape_sha256,
                self.content_commitment_sha256,
                self.feature_certification_commitment_sha256,
            )
        )


@dataclass(frozen=True, slots=True)
class ExperimentGovernanceFamily:
    """Immutable hypothesis, scoped evidence, and frozen holdout policy."""

    family_name: str
    hypothesis: str
    owner_id: str
    created_at: datetime
    strategy_version: StrategyVersionRecord
    evaluation_plan_version: str
    segments: tuple[EvaluationSegment, EvaluationSegment, EvaluationSegment]
    train_evidence: ExperimentSegmentEvidence
    validation_evidence: ExperimentSegmentEvidence
    test_commitment: TestSegmentCommitment
    promotion_criteria: FrozenPromotionCriteria
    family_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_text(self.family_name, "experiment family name", maximum=128)
        _require_text(self.hypothesis, "experiment hypothesis", maximum=4096)
        _require_text(self.owner_id, "experiment owner ID", maximum=128)
        _require_utc(self.created_at, "experiment family created_at")
        _require_text(self.evaluation_plan_version, "evaluation plan version", maximum=128)
        if type(self.strategy_version) is not StrategyVersionRecord:
            raise ExperimentGovernanceError("family requires an exact strategy version")
        if self.strategy_version.registered_at > self.created_at:
            raise ExperimentGovernanceError(
                "strategy version must be registered before family creation"
            )
        if (
            type(self.segments) is not tuple
            or len(self.segments) != 3
            or any(type(segment) is not EvaluationSegment for segment in self.segments)
        ):
            raise ExperimentGovernanceError(
                "family requires exact train, validation, and test segments"
            )
        train, validation, test = self.segments
        if tuple(segment.kind for segment in self.segments) != (
            EvaluationSegmentKind.TRAIN,
            EvaluationSegmentKind.VALIDATION,
            EvaluationSegmentKind.TEST,
        ):
            raise ExperimentGovernanceError(
                "family segments must be ordered train, validation, and test"
            )
        if train.coverage_end >= validation.coverage_start or (
            validation.coverage_end >= test.coverage_start
        ):
            raise ExperimentGovernanceError("family evaluation segments must not overlap")
        if (
            type(self.train_evidence) is not ExperimentSegmentEvidence
            or self.train_evidence.segment != train
            or type(self.validation_evidence) is not ExperimentSegmentEvidence
            or self.validation_evidence.segment != validation
            or type(self.test_commitment) is not TestSegmentCommitment
            or self.test_commitment.segment_sha256 != test.semantic_sha256
            or self.test_commitment.dataset_replay_sha256 != test.dataset_replay_sha256
        ):
            raise ExperimentGovernanceError(
                "family segment evidence conflicts with its declared plan"
            )
        source_tape_sha256s = {
            self.train_evidence.source_tape_sha256,
            self.validation_evidence.source_tape_sha256,
            self.test_commitment.source_tape_sha256,
        }
        if len(source_tape_sha256s) != 3:
            raise ExperimentGovernanceError(
                "each evaluation segment requires a distinct source tape"
            )
        if train.dataset_replay_sha256 == validation.dataset_replay_sha256 or (
            test.dataset_replay_sha256
            in {train.dataset_replay_sha256, validation.dataset_replay_sha256}
        ):
            raise ExperimentGovernanceError(
                "each evaluation segment requires a distinct scoped replay result"
            )
        if type(self.promotion_criteria) is not FrozenPromotionCriteria:
            raise ExperimentGovernanceError("family requires exact frozen promotion criteria")
        if self.promotion_criteria.frozen_at < self.created_at:
            raise ExperimentGovernanceError(
                "promotion criteria cannot be frozen before family creation"
            )
        object.__setattr__(self, "family_sha256", _sha256(self._semantic_material()))

    @property
    def family_id(self) -> str:
        return self.family_sha256

    @property
    def semantic_sha256(self) -> str:
        return self.family_sha256

    @property
    def evaluation_plan_sha256(self) -> str:
        return _sha256(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "scoped-evaluation-plan",
                self.evaluation_plan_version,
                tuple(segment.semantic_sha256 for segment in self.segments),
            )
        )

    @property
    def evidence_sha256(self) -> str:
        return _sha256(
            (
                self.train_evidence.semantic_sha256,
                self.validation_evidence.semantic_sha256,
                self.test_commitment.semantic_sha256,
            )
        )

    @property
    def dataset_replay_sha256(self) -> str:
        """Aggregate identity retained for compact SQL query projections."""

        return _sha256(tuple(segment.dataset_replay_sha256 for segment in self.segments))

    def segment(self, kind: EvaluationSegmentKind) -> EvaluationSegment:
        if type(kind) is not EvaluationSegmentKind:
            raise ExperimentGovernanceError("segment lookup requires an exact kind")
        return self.segments[
            {
                EvaluationSegmentKind.TRAIN: 0,
                EvaluationSegmentKind.VALIDATION: 1,
                EvaluationSegmentKind.TEST: 2,
            }[kind]
        ]

    def evidence(self, kind: EvaluationSegmentKind) -> ExperimentSegmentEvidence:
        if kind is EvaluationSegmentKind.TRAIN:
            return self.train_evidence
        if kind is EvaluationSegmentKind.VALIDATION:
            return self.validation_evidence
        raise ExperimentGovernanceError("test evidence remains sealed until reveal")

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def evidence_canonical_json(self) -> str:
        return canonical_json_text(
            (
                EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
                "family-evidence",
                self.train_evidence._semantic_material(),
                self.validation_evidence._semantic_material(),
                (
                    self.test_commitment.segment_sha256,
                    self.test_commitment.dataset_replay_sha256,
                    self.test_commitment.source_tape_sha256,
                    self.test_commitment.content_commitment_sha256,
                    self.test_commitment.feature_certification_commitment_sha256,
                ),
            )
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-governance-family",
            self.family_name,
            self.hypothesis,
            self.owner_id,
            self.created_at,
            self.strategy_version.semantic_sha256,
            self.evaluation_plan_version,
            self.evaluation_plan_sha256,
            self.train_evidence.semantic_sha256,
            self.validation_evidence.semantic_sha256,
            self.test_commitment.semantic_sha256,
            self.promotion_criteria.semantic_sha256,
        )


@dataclass(frozen=True, slots=True)
class ExperimentAttempt:
    """One stable, budget-counted research-attempt identity."""

    sequence: int
    attempt_number: int
    family_id: str
    configuration: StrategyConfigurationRecord
    configuration_validation: StrategyConfigurationValidationReceipt
    segment_kind: EvaluationSegmentKind
    segment_sha256: str
    requested_at: datetime
    requested_by: str
    holdout_reveal_sha256: str | None = None
    attempt_id: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ExperimentGovernanceError("attempt sequence must be non-negative")
        if self.attempt_number != self.sequence + 1:
            raise ExperimentGovernanceError("attempt number must be the one-based stable sequence")
        _require_sha256(self.family_id, "attempt family ID")
        if type(self.configuration) is not StrategyConfigurationRecord:
            raise ExperimentGovernanceError("attempt requires an exact configuration")
        if (
            type(self.configuration_validation) is not StrategyConfigurationValidationReceipt
            or self.configuration_validation.configuration_sha256
            != self.configuration.semantic_sha256
            or self.configuration_validation.strategy_version_sha256
            != self.configuration.strategy_version_sha256
        ):
            raise ExperimentGovernanceError(
                "attempt configuration lacks its exact schema-validation receipt"
            )
        expected_parameters_sha256 = _sha256(tuple(self.configuration.parameters.items()))
        if self.configuration_validation.parameters_sha256 != expected_parameters_sha256:
            raise ExperimentGovernanceError(
                "attempt validation receipt changed the exact configuration parameters"
            )
        try:
            validate_strategy_configuration_parameters(
                self.configuration_validation.parameter_schema_payload,
                self.configuration.parameters,
            )
        except ValueError as error:
            raise ExperimentGovernanceError(
                "attempt configuration violates its validation receipt schema"
            ) from error
        if type(self.segment_kind) is not EvaluationSegmentKind:
            raise ExperimentGovernanceError("attempt segment kind must be exact")
        _require_sha256(self.segment_sha256, "attempt segment digest")
        _require_utc(self.requested_at, "attempt requested_at")
        _require_text(self.requested_by, "attempt requester", maximum=128)
        _require_optional_sha256(self.holdout_reveal_sha256, "attempt holdout reveal digest")
        if (self.segment_kind is EvaluationSegmentKind.TEST) != (
            self.holdout_reveal_sha256 is not None
        ):
            raise ExperimentGovernanceError(
                "only a final-test attempt may bind holdout reveal evidence"
            )
        object.__setattr__(self, "attempt_id", _sha256(self._semantic_material()))

    @property
    def semantic_sha256(self) -> str:
        return self.attempt_id

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-attempt",
            self.sequence,
            self.attempt_number,
            self.family_id,
            self.configuration.semantic_sha256,
            self.configuration_validation.semantic_sha256,
            self.segment_kind.value,
            self.segment_sha256,
            self.requested_at,
            self.requested_by,
            self.holdout_reveal_sha256,
        )


def _target_policy_from_configuration(
    configuration: StrategyConfigurationRecord,
) -> RollingCloseMeanTargetPolicy:
    if type(configuration) is not StrategyConfigurationRecord:
        raise ExperimentGovernanceError(
            "segment evaluation requires an exact strategy configuration"
        )
    parameters = dict(configuration.parameters)
    if set(parameters) != {"long_quantity", "target_lifetime_seconds"}:
        raise ExperimentGovernanceError(
            "the bounded evaluator requires exactly long_quantity and target_lifetime_seconds"
        )
    long_quantity = parameters["long_quantity"]
    target_lifetime_seconds = parameters["target_lifetime_seconds"]
    if type(long_quantity) is not Decimal:
        raise ExperimentGovernanceError(
            "the bounded evaluator requires long_quantity as an exact Decimal"
        )
    if (
        type(target_lifetime_seconds) is not int
        or target_lifetime_seconds <= 0
        or timedelta(seconds=target_lifetime_seconds) > MAX_TARGET_LIFETIME
    ):
        raise ExperimentGovernanceError(
            "target_lifetime_seconds must be a positive integer within the target bound"
        )
    try:
        return RollingCloseMeanTargetPolicy(
            long_quantity=long_quantity,
            target_lifetime=timedelta(seconds=target_lifetime_seconds),
        )
    except ValueError as error:
        raise ExperimentGovernanceError(
            "strategy configuration cannot produce the bounded target policy"
        ) from error


@dataclass(frozen=True, slots=True, init=False)
class NonExecutableTerminalEvidence:
    """Typed unsuccessful evidence that explicitly makes no execution claim."""

    evidence_kind: str
    attempt_id: str
    status: ExperimentAttemptStatus
    source_evidence_sha256: str | None
    reason_code: str | None
    detail: str
    evidence_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal evidence is proof-constructed for an exact attempt")

    @classmethod
    def unsuccessful(
        cls,
        attempt: ExperimentAttempt,
        *,
        status: ExperimentAttemptStatus,
        reason_code: str,
        detail: str,
    ) -> Self:
        if type(attempt) is not ExperimentAttempt:
            raise ExperimentGovernanceError("terminal evidence requires an exact attempt")
        if type(status) is not ExperimentAttemptStatus or status not in (
            _TERMINAL_STATUSES - {ExperimentAttemptStatus.COMPLETED}
        ):
            raise ExperimentGovernanceError(
                "unsuccessful evidence requires failed, canceled, or abandoned status"
            )
        _require_text(reason_code, "terminal reason code", maximum=128)
        _require_text(detail, "terminal reason detail", maximum=1024)
        return cls._restore(
            attempt_id=attempt.attempt_id,
            status=status,
            source_evidence_sha256=None,
            reason_code=reason_code,
            detail=detail,
        )

    @classmethod
    def _restore(
        cls,
        *,
        attempt_id: str,
        status: ExperimentAttemptStatus,
        source_evidence_sha256: str | None,
        reason_code: str | None,
        detail: str,
        expected_evidence_sha256: str | None = None,
    ) -> Self:
        _require_sha256(attempt_id, "terminal-evidence attempt ID")
        if type(status) is not ExperimentAttemptStatus or status not in (
            _TERMINAL_STATUSES - {ExperimentAttemptStatus.COMPLETED}
        ):
            raise ExperimentGovernanceError("non-executable terminal evidence must be unsuccessful")
        _require_text(detail, "terminal evidence detail", maximum=1024)
        if source_evidence_sha256 is not None or reason_code is None:
            raise ExperimentGovernanceError("unsuccessful terminal evidence requires only a reason")
        _require_text(reason_code, "terminal reason code", maximum=128)
        material = (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "non-executable-terminal-evidence",
            NON_EXECUTABLE_DOMAIN_FIXTURE,
            attempt_id,
            status.value,
            source_evidence_sha256,
            reason_code,
            detail,
        )
        evidence_sha256 = _sha256(material)
        if expected_evidence_sha256 is not None and expected_evidence_sha256 != evidence_sha256:
            raise ExperimentGovernanceError("terminal evidence digest is inconsistent")
        instance = object.__new__(cls)
        for name, value in (
            ("evidence_kind", NON_EXECUTABLE_DOMAIN_FIXTURE),
            ("attempt_id", attempt_id),
            ("status", status),
            ("source_evidence_sha256", source_evidence_sha256),
            ("reason_code", reason_code),
            ("detail", detail),
            ("evidence_sha256", evidence_sha256),
        ):
            object.__setattr__(instance, name, value)
        return instance

    @property
    def semantic_sha256(self) -> str:
        return self.evidence_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "non-executable-terminal-evidence",
            self.evidence_kind,
            self.attempt_id,
            self.status.value,
            self.source_evidence_sha256,
            self.reason_code,
            self.detail,
        )


@dataclass(frozen=True, slots=True, init=False)
class GovernedSegmentEvaluationReceipt:
    """Exact configuration-specific target evaluation over one governed segment."""

    evidence_kind: str
    family_id: str
    attempt_id: str
    strategy_version_sha256: str
    configuration_sha256: str
    configuration_validation_sha256: str
    segment_kind: EvaluationSegmentKind
    segment_sha256: str
    source_evidence_sha256: str
    holdout_reveal_sha256: str | None
    feature_certification_sha256: str
    target_policy_sha256: str
    target_runtime_pin_sha256: str
    target_certification_sha256: str
    batch_result_sha256: str
    incremental_result_sha256: str
    target_parity_receipt_sha256: str
    target_transcript_sha256: str
    step_count: int
    target_count: int
    running_event_sha256: str
    started_at: datetime
    completed_at: datetime
    evaluated_by: str
    receipt_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "GovernedSegmentEvaluationReceipt is proof-constructed from exact evaluation"
        )

    @classmethod
    def _from_certification(
        cls,
        *,
        family: ExperimentGovernanceFamily,
        attempt: ExperimentAttempt,
        running_event: ExperimentAttemptEvent,
        source_evidence: ExperimentSegmentEvidence,
        certification: CertifiedFeatureTargetReplay,
        completed_at: datetime,
    ) -> Self:
        if type(family) is not ExperimentGovernanceFamily:
            raise ExperimentGovernanceError(
                "segment evaluation requires an exact governance family"
            )
        if type(attempt) is not ExperimentAttempt or attempt.family_id != family.family_id:
            raise ExperimentGovernanceError("segment evaluation requires an exact family attempt")
        if (
            type(running_event) is not ExperimentAttemptEvent
            or running_event.family_id != family.family_id
            or running_event.attempt_id != attempt.attempt_id
            or running_event.status is not ExperimentAttemptStatus.RUNNING
        ):
            raise ExperimentGovernanceError(
                "segment evaluation requires the attempt's exact running event"
            )
        if (
            type(source_evidence) is not ExperimentSegmentEvidence
            or source_evidence.segment.kind is not attempt.segment_kind
            or source_evidence.segment.semantic_sha256 != attempt.segment_sha256
            or family.segment(attempt.segment_kind) != source_evidence.segment
        ):
            raise ExperimentGovernanceError("segment evaluation changed its governed feature input")
        if type(certification) is not CertifiedFeatureTargetReplay:
            raise ExperimentGovernanceError(
                "segment evaluation requires an exact CertifiedFeatureTargetReplay"
            )
        source_evidence.require_certification(certification.feature_certification)
        expected_policy = _target_policy_from_configuration(attempt.configuration)
        if certification.policy != expected_policy:
            raise ExperimentGovernanceError(
                "segment evaluation target policy does not match the exact configuration"
            )
        runtime_pin = certification.runtime_pin
        if (
            family.strategy_version.strategy_id != REFERENCE_FEATURE_TARGET_STRATEGY_ID
            or family.strategy_version.strategy_version != REFERENCE_FEATURE_TARGET_STRATEGY_VERSION
            or runtime_pin.strategy_id != family.strategy_version.strategy_id
            or runtime_pin.strategy_version != family.strategy_version.strategy_version
        ):
            raise ExperimentGovernanceError(
                "segment evaluation changed the registered strategy implementation"
            )
        _require_utc(completed_at, "segment evaluation completed_at")
        if completed_at <= running_event.occurred_at:
            raise ExperimentGovernanceError(
                "segment evaluation completion must follow its running event"
            )
        return cls._restore(
            family_id=family.family_id,
            attempt_id=attempt.attempt_id,
            strategy_version_sha256=family.strategy_version.semantic_sha256,
            configuration_sha256=attempt.configuration.semantic_sha256,
            configuration_validation_sha256=(attempt.configuration_validation.semantic_sha256),
            segment_kind=attempt.segment_kind,
            segment_sha256=attempt.segment_sha256,
            source_evidence_sha256=source_evidence.semantic_sha256,
            holdout_reveal_sha256=attempt.holdout_reveal_sha256,
            feature_certification_sha256=(certification.feature_certification.semantic_sha256),
            target_policy_sha256=certification.policy.semantic_sha256,
            target_runtime_pin_sha256=certification.runtime_pin.semantic_sha256,
            target_certification_sha256=certification.semantic_sha256,
            batch_result_sha256=certification.batch_result.semantic_sha256,
            incremental_result_sha256=(certification.incremental_result.semantic_sha256),
            target_parity_receipt_sha256=certification.receipt.semantic_sha256,
            target_transcript_sha256=certification.batch_result.transcript_sha256,
            step_count=len(certification.batch_result.steps),
            target_count=len(certification.batch_result.targets),
            running_event_sha256=running_event.semantic_sha256,
            started_at=running_event.occurred_at,
            completed_at=completed_at,
            evaluated_by=running_event.actor_id,
        )

    @classmethod
    def _restore(
        cls,
        *,
        family_id: str,
        attempt_id: str,
        strategy_version_sha256: str,
        configuration_sha256: str,
        configuration_validation_sha256: str,
        segment_kind: EvaluationSegmentKind,
        segment_sha256: str,
        source_evidence_sha256: str,
        holdout_reveal_sha256: str | None,
        feature_certification_sha256: str,
        target_policy_sha256: str,
        target_runtime_pin_sha256: str,
        target_certification_sha256: str,
        batch_result_sha256: str,
        incremental_result_sha256: str,
        target_parity_receipt_sha256: str,
        target_transcript_sha256: str,
        step_count: int,
        target_count: int,
        running_event_sha256: str,
        started_at: datetime,
        completed_at: datetime,
        evaluated_by: str,
        expected_receipt_sha256: str | None = None,
    ) -> Self:
        for value, field_name in (
            (family_id, "evaluation family ID"),
            (attempt_id, "evaluation attempt ID"),
            (strategy_version_sha256, "evaluation strategy-version digest"),
            (configuration_sha256, "evaluation configuration digest"),
            (
                configuration_validation_sha256,
                "evaluation configuration-validation digest",
            ),
            (segment_sha256, "evaluation segment digest"),
            (source_evidence_sha256, "evaluation source-evidence digest"),
            (
                feature_certification_sha256,
                "evaluation feature-certification digest",
            ),
            (target_policy_sha256, "evaluation target-policy digest"),
            (target_runtime_pin_sha256, "evaluation target-runtime digest"),
            (target_certification_sha256, "evaluation target-certification digest"),
            (batch_result_sha256, "evaluation batch-result digest"),
            (incremental_result_sha256, "evaluation incremental-result digest"),
            (
                target_parity_receipt_sha256,
                "evaluation target-parity digest",
            ),
            (target_transcript_sha256, "evaluation target-transcript digest"),
            (running_event_sha256, "evaluation running-event digest"),
        ):
            _require_sha256(value, field_name)
        if type(segment_kind) is not EvaluationSegmentKind:
            raise ExperimentGovernanceError("segment evaluation kind must be an exact segment kind")
        _require_optional_sha256(
            holdout_reveal_sha256,
            "evaluation holdout-reveal digest",
        )
        if (segment_kind is EvaluationSegmentKind.TEST) != (holdout_reveal_sha256 is not None):
            raise ExperimentGovernanceError(
                "only a final-test evaluation may bind holdout reveal evidence"
            )
        if type(step_count) is not int or not 1 <= step_count <= 100_000:
            raise ExperimentGovernanceError("segment evaluation step count is outside its bound")
        if type(target_count) is not int or target_count < 0 or target_count > step_count:
            raise ExperimentGovernanceError("segment evaluation target count is outside its bound")
        _require_utc(started_at, "segment evaluation started_at")
        _require_utc(completed_at, "segment evaluation completed_at")
        if completed_at <= started_at:
            raise ExperimentGovernanceError("segment evaluation completion must follow its start")
        _require_text(evaluated_by, "segment evaluator", maximum=128)
        material = (
            EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION,
            "governed-segment-evaluation-receipt",
            GOVERNED_SEGMENT_EVALUATION,
            family_id,
            attempt_id,
            strategy_version_sha256,
            configuration_sha256,
            configuration_validation_sha256,
            segment_kind.value,
            segment_sha256,
            source_evidence_sha256,
            holdout_reveal_sha256,
            feature_certification_sha256,
            target_policy_sha256,
            target_runtime_pin_sha256,
            target_certification_sha256,
            batch_result_sha256,
            incremental_result_sha256,
            target_parity_receipt_sha256,
            target_transcript_sha256,
            step_count,
            target_count,
            running_event_sha256,
            started_at,
            completed_at,
            evaluated_by,
        )
        receipt_sha256 = _sha256(material)
        if expected_receipt_sha256 is not None and (expected_receipt_sha256 != receipt_sha256):
            raise ExperimentGovernanceError("segment evaluation receipt digest is inconsistent")
        instance = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("evidence_kind", GOVERNED_SEGMENT_EVALUATION),
            ("family_id", family_id),
            ("attempt_id", attempt_id),
            ("strategy_version_sha256", strategy_version_sha256),
            ("configuration_sha256", configuration_sha256),
            (
                "configuration_validation_sha256",
                configuration_validation_sha256,
            ),
            ("segment_kind", segment_kind),
            ("segment_sha256", segment_sha256),
            ("source_evidence_sha256", source_evidence_sha256),
            ("holdout_reveal_sha256", holdout_reveal_sha256),
            ("feature_certification_sha256", feature_certification_sha256),
            ("target_policy_sha256", target_policy_sha256),
            ("target_runtime_pin_sha256", target_runtime_pin_sha256),
            ("target_certification_sha256", target_certification_sha256),
            ("batch_result_sha256", batch_result_sha256),
            ("incremental_result_sha256", incremental_result_sha256),
            (
                "target_parity_receipt_sha256",
                target_parity_receipt_sha256,
            ),
            ("target_transcript_sha256", target_transcript_sha256),
            ("step_count", step_count),
            ("target_count", target_count),
            ("running_event_sha256", running_event_sha256),
            ("started_at", started_at),
            ("completed_at", completed_at),
            ("evaluated_by", evaluated_by),
            ("receipt_sha256", receipt_sha256),
        )
        for name, field_value in values:
            object.__setattr__(instance, name, field_value)
        return instance

    @property
    def status(self) -> ExperimentAttemptStatus:
        return ExperimentAttemptStatus.COMPLETED

    @property
    def reason_code(self) -> None:
        return None

    @property
    def detail(self) -> str:
        return (
            "Configuration-bound causal target evaluation; no P&L, promotion, "
            "paper, or live authority."
        )

    @property
    def semantic_sha256(self) -> str:
        return self.receipt_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def require_context(
        self,
        *,
        family: ExperimentGovernanceFamily,
        attempt: ExperimentAttempt,
        running_event: ExperimentAttemptEvent,
        source_evidence: ExperimentSegmentEvidence,
    ) -> None:
        if (
            type(family) is not ExperimentGovernanceFamily
            or type(attempt) is not ExperimentAttempt
            or type(running_event) is not ExperimentAttemptEvent
            or type(source_evidence) is not ExperimentSegmentEvidence
            or self.family_id != family.family_id
            or self.attempt_id != attempt.attempt_id
            or self.strategy_version_sha256 != family.strategy_version.semantic_sha256
            or self.configuration_sha256 != attempt.configuration.semantic_sha256
            or self.configuration_validation_sha256
            != attempt.configuration_validation.semantic_sha256
            or self.segment_kind is not attempt.segment_kind
            or self.segment_sha256 != attempt.segment_sha256
            or self.source_evidence_sha256 != source_evidence.semantic_sha256
            or self.holdout_reveal_sha256 != attempt.holdout_reveal_sha256
            or self.feature_certification_sha256 != source_evidence.feature_certification_sha256
            or self.target_policy_sha256
            != _target_policy_from_configuration(attempt.configuration).semantic_sha256
            or self.running_event_sha256 != running_event.semantic_sha256
            or self.started_at != running_event.occurred_at
            or self.evaluated_by != running_event.actor_id
            or running_event.family_id != family.family_id
            or running_event.attempt_id != attempt.attempt_id
            or running_event.status is not ExperimentAttemptStatus.RUNNING
        ):
            raise ExperimentGovernanceError(
                "segment evaluation receipt changed its exact governance context"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION,
            "governed-segment-evaluation-receipt",
            self.evidence_kind,
            self.family_id,
            self.attempt_id,
            self.strategy_version_sha256,
            self.configuration_sha256,
            self.configuration_validation_sha256,
            self.segment_kind.value,
            self.segment_sha256,
            self.source_evidence_sha256,
            self.holdout_reveal_sha256,
            self.feature_certification_sha256,
            self.target_policy_sha256,
            self.target_runtime_pin_sha256,
            self.target_certification_sha256,
            self.batch_result_sha256,
            self.incremental_result_sha256,
            self.target_parity_receipt_sha256,
            self.target_transcript_sha256,
            self.step_count,
            self.target_count,
            self.running_event_sha256,
            self.started_at,
            self.completed_at,
            self.evaluated_by,
        )


@dataclass(frozen=True, slots=True)
class ExperimentAttemptEvent:
    """One append-only lifecycle fact in the family-wide authenticated chain."""

    family_id: str
    attempt_id: str
    global_sequence_number: int
    attempt_sequence_number: int
    previous_entry_sha256: str | None
    status: ExperimentAttemptStatus
    occurred_at: datetime
    actor_id: str
    terminal_evidence: GovernedSegmentEvaluationReceipt | NonExecutableTerminalEvidence | None = (
        None
    )
    event_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_sha256(self.family_id, "attempt-event family ID")
        _require_sha256(self.attempt_id, "attempt-event attempt ID")
        if type(self.global_sequence_number) is not int or self.global_sequence_number < 0:
            raise ExperimentGovernanceError("global event sequence must be non-negative")
        if type(self.attempt_sequence_number) is not int or self.attempt_sequence_number < 0:
            raise ExperimentGovernanceError("attempt event sequence must be non-negative")
        _require_optional_sha256(self.previous_entry_sha256, "previous governance entry")
        if (self.global_sequence_number == 0) != (self.previous_entry_sha256 is None):
            raise ExperimentGovernanceError(
                "only the first governance entry may omit its predecessor"
            )
        if type(self.status) is not ExperimentAttemptStatus:
            raise ExperimentGovernanceError("attempt-event status must be exact")
        _require_utc(self.occurred_at, "attempt-event occurred_at")
        _require_text(self.actor_id, "attempt-event actor", maximum=128)
        if self.status is ExperimentAttemptStatus.COMPLETED:
            if (
                type(self.terminal_evidence) is not GovernedSegmentEvaluationReceipt
                or self.terminal_evidence.attempt_id != self.attempt_id
                or self.terminal_evidence.family_id != self.family_id
                or self.terminal_evidence.completed_at != self.occurred_at
                or self.terminal_evidence.evaluated_by != self.actor_id
            ):
                raise ExperimentGovernanceError(
                    "completed attempt event requires exact governed evaluation evidence"
                )
        elif self.status in (_TERMINAL_STATUSES - {ExperimentAttemptStatus.COMPLETED}):
            if (
                type(self.terminal_evidence) is not NonExecutableTerminalEvidence
                or self.terminal_evidence.attempt_id != self.attempt_id
                or self.terminal_evidence.status is not self.status
            ):
                raise ExperimentGovernanceError(
                    "unsuccessful attempt event requires exact non-executable evidence"
                )
        elif self.terminal_evidence is not None:
            raise ExperimentGovernanceError("active attempt event cannot retain terminal evidence")
        if self.attempt_sequence_number == 0 and self.status is not ExperimentAttemptStatus.QUEUED:
            raise ExperimentGovernanceError("the first attempt event must be queued")
        if self.attempt_sequence_number > 0 and self.status is ExperimentAttemptStatus.QUEUED:
            raise ExperimentGovernanceError("queued status cannot recur in an attempt")
        object.__setattr__(self, "event_sha256", _sha256(self._semantic_material()))

    @property
    def semantic_sha256(self) -> str:
        return self.event_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-attempt-event",
            self.family_id,
            self.attempt_id,
            self.global_sequence_number,
            self.attempt_sequence_number,
            self.previous_entry_sha256,
            self.status.value,
            self.occurred_at,
            self.actor_id,
            (None if self.terminal_evidence is None else self.terminal_evidence.semantic_sha256),
        )


@dataclass(frozen=True, slots=True, init=False)
class HoldoutRevealAuthorization:
    """Contextual authorization for exactly one current pre-reveal snapshot."""

    family_id: str
    holdout_commitment_sha256: str
    promotion_criteria_sha256: str
    selected_configuration_sha256: str
    pre_reveal_snapshot_sha256: str
    pre_reveal_head_sha256: str
    pre_reveal_attempts_sha256: str
    pre_reveal_attempt_count: int
    authorized_at: datetime
    authorized_by: str
    access_reason: str
    authorization_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("HoldoutRevealAuthorization is proof-constructed from a snapshot")

    @classmethod
    def _from_snapshot(
        cls,
        snapshot: ExperimentGovernanceSnapshot,
        *,
        selected_configuration_sha256: str,
        authorized_at: datetime,
        authorized_by: str,
        access_reason: str,
    ) -> Self:
        _require_sha256(selected_configuration_sha256, "selected configuration digest")
        _require_utc(authorized_at, "holdout authorization time")
        _require_text(authorized_by, "holdout authorizer", maximum=128)
        _require_text(access_reason, "holdout access reason", maximum=1024)
        if snapshot.holdout_reveal is not None:
            raise ExperimentGovernanceError("final holdout has already been revealed")
        if not snapshot.attempts:
            raise ExperimentGovernanceError(
                "holdout selection requires completed validation evidence"
            )
        latest = snapshot.latest_events
        if any(event.status not in _TERMINAL_STATUSES for event in latest):
            raise ExperimentGovernanceError(
                "holdout cannot be authorized while an exploratory attempt is active"
            )
        if authorized_at <= max(event.occurred_at for event in latest):
            raise ExperimentGovernanceError(
                "holdout authorization must follow every exploratory terminal event"
            )
        completed_validation = {
            attempt.configuration.semantic_sha256
            for attempt in snapshot.attempts
            if attempt.segment_kind is EvaluationSegmentKind.VALIDATION
            and snapshot.latest_event(attempt.attempt_id).status
            is ExperimentAttemptStatus.COMPLETED
        }
        if selected_configuration_sha256 not in completed_validation:
            raise ExperimentGovernanceError(
                "holdout selection requires an exact completed validation attempt"
            )
        return cls._restore(
            family_id=snapshot.family_id,
            holdout_commitment_sha256=snapshot.family.test_commitment.semantic_sha256,
            promotion_criteria_sha256=snapshot.family.promotion_criteria.semantic_sha256,
            selected_configuration_sha256=selected_configuration_sha256,
            pre_reveal_snapshot_sha256=snapshot.semantic_sha256,
            pre_reveal_head_sha256=snapshot.registry_head_sha256,
            pre_reveal_attempts_sha256=snapshot.attempts_sha256,
            pre_reveal_attempt_count=len(snapshot.attempts),
            authorized_at=authorized_at,
            authorized_by=authorized_by,
            access_reason=access_reason,
        )

    @classmethod
    def _restore(
        cls,
        *,
        family_id: str,
        holdout_commitment_sha256: str,
        promotion_criteria_sha256: str,
        selected_configuration_sha256: str,
        pre_reveal_snapshot_sha256: str,
        pre_reveal_head_sha256: str,
        pre_reveal_attempts_sha256: str,
        pre_reveal_attempt_count: int,
        authorized_at: datetime,
        authorized_by: str,
        access_reason: str,
        expected_authorization_sha256: str | None = None,
    ) -> Self:
        for value, field_name in (
            (family_id, "authorization family ID"),
            (holdout_commitment_sha256, "authorization holdout commitment"),
            (promotion_criteria_sha256, "authorization promotion criteria"),
            (selected_configuration_sha256, "authorization selected configuration"),
            (pre_reveal_snapshot_sha256, "authorization pre-reveal snapshot"),
            (pre_reveal_head_sha256, "authorization pre-reveal head"),
            (pre_reveal_attempts_sha256, "authorization pre-reveal attempts"),
        ):
            _require_sha256(value, field_name)
        if (
            type(pre_reveal_attempt_count) is not int
            or pre_reveal_attempt_count < 1
            or pre_reveal_attempt_count > 100_000
        ):
            raise ExperimentGovernanceError("authorization attempt count is outside its bound")
        _require_utc(authorized_at, "holdout authorization time")
        _require_text(authorized_by, "holdout authorizer", maximum=128)
        _require_text(access_reason, "holdout access reason", maximum=1024)
        material = (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "holdout-reveal-authorization",
            family_id,
            holdout_commitment_sha256,
            promotion_criteria_sha256,
            selected_configuration_sha256,
            pre_reveal_snapshot_sha256,
            pre_reveal_head_sha256,
            pre_reveal_attempts_sha256,
            pre_reveal_attempt_count,
            authorized_at,
            authorized_by,
            access_reason,
        )
        authorization_sha256 = _sha256(material)
        if expected_authorization_sha256 is not None and (
            expected_authorization_sha256 != authorization_sha256
        ):
            raise ExperimentGovernanceError("holdout authorization digest is inconsistent")
        instance = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("family_id", family_id),
            ("holdout_commitment_sha256", holdout_commitment_sha256),
            ("promotion_criteria_sha256", promotion_criteria_sha256),
            ("selected_configuration_sha256", selected_configuration_sha256),
            ("pre_reveal_snapshot_sha256", pre_reveal_snapshot_sha256),
            ("pre_reveal_head_sha256", pre_reveal_head_sha256),
            ("pre_reveal_attempts_sha256", pre_reveal_attempts_sha256),
            ("pre_reveal_attempt_count", pre_reveal_attempt_count),
            ("authorized_at", authorized_at),
            ("authorized_by", authorized_by),
            ("access_reason", access_reason),
            ("authorization_sha256", authorization_sha256),
        )
        for name, field_value in values:
            object.__setattr__(instance, name, field_value)
        return instance

    @property
    def semantic_sha256(self) -> str:
        return self.authorization_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "holdout-reveal-authorization",
            self.family_id,
            self.holdout_commitment_sha256,
            self.promotion_criteria_sha256,
            self.selected_configuration_sha256,
            self.pre_reveal_snapshot_sha256,
            self.pre_reveal_head_sha256,
            self.pre_reveal_attempts_sha256,
            self.pre_reveal_attempt_count,
            self.authorized_at,
            self.authorized_by,
            self.access_reason,
        )


@dataclass(frozen=True, slots=True)
class AuditedHoldoutReveal:
    """The first governance fact allowed to retain opened final-test evidence."""

    authorization: HoldoutRevealAuthorization
    test_evidence: ExperimentSegmentEvidence
    global_sequence_number: int
    previous_entry_sha256: str
    reveal_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.authorization) is not HoldoutRevealAuthorization:
            raise ExperimentGovernanceError("holdout reveal requires exact authorization")
        if (
            type(self.test_evidence) is not ExperimentSegmentEvidence
            or self.test_evidence.segment.kind is not EvaluationSegmentKind.TEST
        ):
            raise ExperimentGovernanceError("holdout reveal requires exact test evidence")
        if type(self.global_sequence_number) is not int or self.global_sequence_number < 1:
            raise ExperimentGovernanceError("holdout reveal sequence must be positive")
        _require_sha256(self.previous_entry_sha256, "holdout reveal predecessor")
        object.__setattr__(self, "reveal_sha256", _sha256(self._semantic_material()))

    @property
    def family_id(self) -> str:
        return self.authorization.family_id

    @property
    def selected_configuration_sha256(self) -> str:
        return self.authorization.selected_configuration_sha256

    @property
    def revealed_at(self) -> datetime:
        return self.authorization.authorized_at

    @property
    def revealed_by(self) -> str:
        return self.authorization.authorized_by

    @property
    def access_reason(self) -> str:
        return self.authorization.access_reason

    @property
    def semantic_sha256(self) -> str:
        return self.reveal_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "audited-holdout-reveal",
            self.authorization.semantic_sha256,
            self.test_evidence.semantic_sha256,
            self.global_sequence_number,
            self.previous_entry_sha256,
        )


_ALLOWED_TRANSITIONS: dict[ExperimentAttemptStatus, frozenset[ExperimentAttemptStatus]] = {
    ExperimentAttemptStatus.QUEUED: frozenset(
        {
            ExperimentAttemptStatus.RUNNING,
            ExperimentAttemptStatus.FAILED,
            ExperimentAttemptStatus.CANCELED,
            ExperimentAttemptStatus.ABANDONED,
        }
    ),
    ExperimentAttemptStatus.RUNNING: _TERMINAL_STATUSES,
}


@dataclass(frozen=True, slots=True)
class ExperimentGovernanceSnapshot:
    """Canonical family history with one interleaved reveal entry."""

    family: ExperimentGovernanceFamily
    attempts: tuple[ExperimentAttempt, ...]
    lifecycle_events: tuple[ExperimentAttemptEvent, ...]
    holdout_reveal: AuditedHoldoutReveal | None = None
    snapshot_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.family) is not ExperimentGovernanceFamily:
            raise ExperimentGovernanceError("snapshot requires an exact governance family")
        if type(self.attempts) is not tuple or any(
            type(attempt) is not ExperimentAttempt for attempt in self.attempts
        ):
            raise ExperimentGovernanceError("snapshot attempts must be exact immutable values")
        if type(self.lifecycle_events) is not tuple or any(
            type(event) is not ExperimentAttemptEvent for event in self.lifecycle_events
        ):
            raise ExperimentGovernanceError(
                "snapshot lifecycle events must be exact immutable values"
            )
        if self.holdout_reveal is not None and (
            type(self.holdout_reveal) is not AuditedHoldoutReveal
        ):
            raise ExperimentGovernanceError("snapshot holdout reveal must be exact")
        self._validate_attempts()
        self._validate_chain()
        self._validate_policy()
        object.__setattr__(self, "snapshot_sha256", _sha256(self._semantic_material()))

    @classmethod
    def empty(cls, family: ExperimentGovernanceFamily) -> Self:
        return cls(family=family, attempts=(), lifecycle_events=())

    def _validate_attempts(self) -> None:
        if tuple(attempt.sequence for attempt in self.attempts) != tuple(range(len(self.attempts))):
            raise ExperimentGovernanceError("attempt sequences must be contiguous")
        if tuple(attempt.attempt_number for attempt in self.attempts) != tuple(
            range(1, len(self.attempts) + 1)
        ):
            raise ExperimentGovernanceError("attempt numbers must be contiguous")
        if len({attempt.attempt_id for attempt in self.attempts}) != len(self.attempts):
            raise ExperimentGovernanceError("attempt identities must be unique")
        events_by_attempt: dict[str, list[ExperimentAttemptEvent]] = {
            attempt.attempt_id: [] for attempt in self.attempts
        }
        for event in self.lifecycle_events:
            if event.family_id != self.family_id or event.attempt_id not in events_by_attempt:
                raise ExperimentGovernanceError(
                    "lifecycle event belongs to an unknown family attempt"
                )
            events_by_attempt[event.attempt_id].append(event)
        for attempt in self.attempts:
            if attempt.family_id != self.family_id:
                raise ExperimentGovernanceError("attempt belongs to a different family")
            if attempt.segment_sha256 != self.family.segment(attempt.segment_kind).semantic_sha256:
                raise ExperimentGovernanceError("attempt changed its declared evaluation segment")
            if (
                attempt.configuration.strategy_version_sha256
                != self.family.strategy_version.semantic_sha256
            ):
                raise ExperimentGovernanceError(
                    "attempt configuration belongs to a different strategy version"
                )
            if (
                attempt.configuration_validation.parameter_schema_sha256
                != self.family.strategy_version.parameter_schema_sha256
            ):
                raise ExperimentGovernanceError(
                    "attempt validation receipt changed the family parameter schema"
                )
            if attempt.configuration.registered_at > attempt.requested_at:
                raise ExperimentGovernanceError(
                    "attempt configuration must be registered before request"
                )
            if attempt.requested_at < max(
                self.family.created_at,
                self.family.promotion_criteria.frozen_at,
            ):
                raise ExperimentGovernanceError(
                    "attempt cannot precede the family or frozen criteria"
                )
            attempt_events = events_by_attempt[attempt.attempt_id]
            if tuple(event.attempt_sequence_number for event in attempt_events) != tuple(
                range(len(attempt_events))
            ):
                raise ExperimentGovernanceError("per-attempt lifecycle sequence must be contiguous")
            if not attempt_events or attempt_events[0].status is not ExperimentAttemptStatus.QUEUED:
                raise ExperimentGovernanceError("every attempt requires its queued event")
            if attempt_events[0].occurred_at != attempt.requested_at:
                raise ExperimentGovernanceError(
                    "queued lifecycle time must equal the stable request time"
                )
            if attempt_events[0].actor_id != attempt.requested_by:
                raise ExperimentGovernanceError(
                    "queued lifecycle actor must equal the stable requester"
                )
            for previous, current in pairwise(attempt_events):
                if (
                    current.status not in _ALLOWED_TRANSITIONS.get(previous.status, frozenset())
                    or current.occurred_at <= previous.occurred_at
                ):
                    raise ExperimentGovernanceError(
                        "attempt lifecycle transition is invalid or non-monotonic"
                    )
            latest = attempt_events[-1]
            if latest.status is ExperimentAttemptStatus.COMPLETED:
                if (
                    len(attempt_events) < 3
                    or type(latest.terminal_evidence) is not GovernedSegmentEvaluationReceipt
                ):
                    raise ExperimentGovernanceError(
                        "completed attempt lacks governed segment evaluation evidence"
                    )
                latest.terminal_evidence.require_context(
                    family=self.family,
                    attempt=attempt,
                    running_event=attempt_events[-2],
                    source_evidence=self._segment_evidence(attempt),
                )

    def _validate_chain(self) -> None:
        event_sequences = tuple(event.global_sequence_number for event in self.lifecycle_events)
        if event_sequences != tuple(sorted(event_sequences)):
            raise ExperimentGovernanceError(
                "lifecycle events must be stored in global sequence order"
            )
        entries: list[tuple[int, str, str | None, datetime]] = [
            (
                event.global_sequence_number,
                event.semantic_sha256,
                event.previous_entry_sha256,
                event.occurred_at,
            )
            for event in self.lifecycle_events
        ]
        if self.holdout_reveal is not None:
            entries.append(
                (
                    self.holdout_reveal.global_sequence_number,
                    self.holdout_reveal.semantic_sha256,
                    self.holdout_reveal.previous_entry_sha256,
                    self.holdout_reveal.revealed_at,
                )
            )
        entries.sort(key=lambda item: item[0])
        if tuple(sequence for sequence, *_ in entries) != tuple(range(len(entries))):
            raise ExperimentGovernanceError(
                "family governance sequence must be globally contiguous"
            )
        previous_sha256: str | None = None
        previous_time: datetime | None = None
        for _, entry_sha256, predecessor, occurred_at in entries:
            if predecessor != previous_sha256:
                raise ExperimentGovernanceError(
                    "family governance predecessor chain is inconsistent"
                )
            if previous_time is not None and occurred_at <= previous_time:
                raise ExperimentGovernanceError(
                    "family governance event times must be strictly increasing"
                )
            previous_sha256 = entry_sha256
            previous_time = occurred_at

    def _validate_policy(self) -> None:
        exploratory = tuple(
            attempt
            for attempt in self.attempts
            if attempt.segment_kind is not EvaluationSegmentKind.TEST
        )
        final_tests = tuple(
            attempt
            for attempt in self.attempts
            if attempt.segment_kind is EvaluationSegmentKind.TEST
        )
        if len(exploratory) > self.family.promotion_criteria.maximum_pre_holdout_trials:
            raise ExperimentGovernanceError("pre-holdout stable-attempt budget is exhausted")
        if self.holdout_reveal is None:
            if final_tests:
                raise ExperimentGovernanceError(
                    "final-test attempt is forbidden before holdout reveal"
                )
            return
        reveal = self.holdout_reveal
        self.family.test_commitment.require_evidence(
            self.family.segment(EvaluationSegmentKind.TEST),
            reveal.test_evidence,
        )
        if (
            reveal.family_id != self.family_id
            or reveal.authorization.holdout_commitment_sha256
            != self.family.test_commitment.semantic_sha256
            or reveal.authorization.promotion_criteria_sha256
            != self.family.promotion_criteria.semantic_sha256
            or reveal.test_evidence.segment != self.family.segment(EvaluationSegmentKind.TEST)
        ):
            raise ExperimentGovernanceError(
                "holdout reveal conflicts with immutable family evidence"
            )
        pre_events = tuple(
            event
            for event in self.lifecycle_events
            if event.global_sequence_number < reveal.global_sequence_number
        )
        post_events = tuple(
            event
            for event in self.lifecycle_events
            if event.global_sequence_number > reveal.global_sequence_number
        )
        if any(
            event.attempt_id in {attempt.attempt_id for attempt in final_tests}
            for event in pre_events
        ):
            raise ExperimentGovernanceError("final-test lifecycle began before reveal")
        if any(
            event.attempt_id in {attempt.attempt_id for attempt in exploratory}
            for event in post_events
        ):
            raise ExperimentGovernanceError(
                "exploratory lifecycle cannot change after holdout reveal"
            )
        if len(final_tests) > 1:
            raise ExperimentGovernanceError("only one stable final-test attempt is permitted")
        for attempt in final_tests:
            if (
                attempt.configuration.semantic_sha256 != reveal.selected_configuration_sha256
                or attempt.holdout_reveal_sha256 != reveal.semantic_sha256
                or attempt.requested_at <= reveal.revealed_at
            ):
                raise ExperimentGovernanceError(
                    "final-test attempt changed the selected reveal configuration"
                )
        pre_snapshot = type(self)(
            family=self.family,
            attempts=exploratory,
            lifecycle_events=pre_events,
        )
        authorization = reveal.authorization
        if (
            authorization.pre_reveal_snapshot_sha256 != pre_snapshot.semantic_sha256
            or authorization.pre_reveal_head_sha256 != pre_snapshot.registry_head_sha256
            or authorization.pre_reveal_attempts_sha256 != pre_snapshot.attempts_sha256
            or authorization.pre_reveal_attempt_count != len(exploratory)
        ):
            raise ExperimentGovernanceError(
                "holdout authorization does not bind the exact pre-reveal registry"
            )
        expected_authorization = HoldoutRevealAuthorization._from_snapshot(
            pre_snapshot,
            selected_configuration_sha256=authorization.selected_configuration_sha256,
            authorized_at=authorization.authorized_at,
            authorized_by=authorization.authorized_by,
            access_reason=authorization.access_reason,
        )
        if expected_authorization != authorization:
            raise ExperimentGovernanceError("holdout authorization changed contextual evidence")

    def _segment_evidence(
        self,
        attempt: ExperimentAttempt,
    ) -> ExperimentSegmentEvidence:
        if attempt.segment_kind is EvaluationSegmentKind.TEST:
            if self.holdout_reveal is None:
                raise ExperimentGovernanceError(
                    "test completion requires an audited holdout reveal"
                )
            return self.holdout_reveal.test_evidence
        return self.family.evidence(attempt.segment_kind)

    def complete_attempt(
        self,
        attempt_id: str,
        certification: CertifiedFeatureTargetReplay,
        *,
        completed_at: datetime,
        actor_id: str,
    ) -> Self:
        """Atomically prove and record completion for the exact running attempt."""

        _require_sha256(attempt_id, "completion attempt ID")
        _require_text(actor_id, "completion actor", maximum=128)
        try:
            attempt = next(
                candidate for candidate in self.attempts if candidate.attempt_id == attempt_id
            )
        except StopIteration as error:
            raise ExperimentGovernanceError("unknown experiment attempt") from error
        running_event = self.latest_event(attempt_id)
        if running_event.status is not ExperimentAttemptStatus.RUNNING:
            raise ExperimentGovernanceError(
                "segment evaluation completion requires a running attempt"
            )
        if actor_id != running_event.actor_id:
            raise ExperimentGovernanceError(
                "completion must retain the recorded running actor identifier"
            )
        receipt = GovernedSegmentEvaluationReceipt._from_certification(
            family=self.family,
            attempt=attempt,
            running_event=running_event,
            source_evidence=self._segment_evidence(attempt),
            certification=certification,
            completed_at=completed_at,
        )
        event = ExperimentAttemptEvent(
            family_id=self.family_id,
            attempt_id=attempt_id,
            global_sequence_number=self.next_global_sequence_number,
            attempt_sequence_number=running_event.attempt_sequence_number + 1,
            previous_entry_sha256=self.chain_entry_sha256,
            status=ExperimentAttemptStatus.COMPLETED,
            occurred_at=completed_at,
            actor_id=actor_id,
            terminal_evidence=receipt,
        )
        return type(self)(
            family=self.family,
            attempts=self.attempts,
            lifecycle_events=(*self.lifecycle_events, event),
            holdout_reveal=self.holdout_reveal,
        )

    def request_attempt(
        self,
        *,
        configuration: StrategyConfigurationRecord,
        configuration_validation: StrategyConfigurationValidationReceipt,
        segment_kind: EvaluationSegmentKind,
        requested_at: datetime,
        requested_by: str,
    ) -> Self:
        if type(segment_kind) is not EvaluationSegmentKind:
            raise ExperimentGovernanceError("attempt request segment kind must be exact")
        if self.holdout_reveal is None:
            if segment_kind is EvaluationSegmentKind.TEST:
                raise ExperimentGovernanceError("final-test attempt is forbidden before reveal")
            if len(self.attempts) >= (self.family.promotion_criteria.maximum_pre_holdout_trials):
                raise ExperimentGovernanceError("pre-holdout stable-attempt budget is exhausted")
            holdout_reveal_sha256 = None
        else:
            if segment_kind is not EvaluationSegmentKind.TEST:
                raise ExperimentGovernanceError("exploratory attempts are forbidden after reveal")
            if any(attempt.segment_kind is EvaluationSegmentKind.TEST for attempt in self.attempts):
                raise ExperimentGovernanceError("only one stable final-test attempt is permitted")
            if configuration.semantic_sha256 != self.holdout_reveal.selected_configuration_sha256:
                raise ExperimentGovernanceError(
                    "final-test attempt must use the selected validation configuration"
                )
            holdout_reveal_sha256 = self.holdout_reveal.semantic_sha256
        attempt = ExperimentAttempt(
            sequence=len(self.attempts),
            attempt_number=len(self.attempts) + 1,
            family_id=self.family_id,
            configuration=configuration,
            configuration_validation=configuration_validation,
            segment_kind=segment_kind,
            segment_sha256=self.family.segment(segment_kind).semantic_sha256,
            requested_at=requested_at,
            requested_by=requested_by,
            holdout_reveal_sha256=holdout_reveal_sha256,
        )
        queued = ExperimentAttemptEvent(
            family_id=self.family_id,
            attempt_id=attempt.attempt_id,
            global_sequence_number=self.next_global_sequence_number,
            attempt_sequence_number=0,
            previous_entry_sha256=self.chain_entry_sha256,
            status=ExperimentAttemptStatus.QUEUED,
            occurred_at=requested_at,
            actor_id=requested_by,
        )
        return type(self)(
            family=self.family,
            attempts=(*self.attempts, attempt),
            lifecycle_events=(*self.lifecycle_events, queued),
            holdout_reveal=self.holdout_reveal,
        )

    def transition_attempt(
        self,
        attempt_id: str,
        *,
        status: ExperimentAttemptStatus,
        occurred_at: datetime,
        actor_id: str,
        terminal_evidence: NonExecutableTerminalEvidence | None = None,
    ) -> Self:
        _require_sha256(attempt_id, "transition attempt ID")
        if type(status) is not ExperimentAttemptStatus:
            raise ExperimentGovernanceError("transition status must be exact")
        if status is ExperimentAttemptStatus.COMPLETED:
            raise ExperimentGovernanceError("completed transitions must use complete_attempt")
        if not any(candidate.attempt_id == attempt_id for candidate in self.attempts):
            raise ExperimentGovernanceError("unknown experiment attempt")
        latest = self.latest_event(attempt_id)
        if status not in _ALLOWED_TRANSITIONS.get(latest.status, frozenset()):
            raise ExperimentGovernanceError("attempt lifecycle transition is not allowed")
        if status in (_TERMINAL_STATUSES - {ExperimentAttemptStatus.COMPLETED}):
            if type(terminal_evidence) is not NonExecutableTerminalEvidence:
                raise ExperimentGovernanceError(
                    "terminal transition requires exact non-executable evidence"
                )
        elif terminal_evidence is not None:
            raise ExperimentGovernanceError("active transition cannot carry terminal evidence")
        event = ExperimentAttemptEvent(
            family_id=self.family_id,
            attempt_id=attempt_id,
            global_sequence_number=self.next_global_sequence_number,
            attempt_sequence_number=latest.attempt_sequence_number + 1,
            previous_entry_sha256=self.chain_entry_sha256,
            status=status,
            occurred_at=occurred_at,
            actor_id=actor_id,
            terminal_evidence=terminal_evidence,
        )
        return type(self)(
            family=self.family,
            attempts=self.attempts,
            lifecycle_events=(*self.lifecycle_events, event),
            holdout_reveal=self.holdout_reveal,
        )

    def create_holdout_authorization(
        self,
        *,
        selected_configuration_sha256: str,
        authorized_at: datetime,
        authorized_by: str,
        access_reason: str,
    ) -> HoldoutRevealAuthorization:
        return HoldoutRevealAuthorization._from_snapshot(
            self,
            selected_configuration_sha256=selected_configuration_sha256,
            authorized_at=authorized_at,
            authorized_by=authorized_by,
            access_reason=access_reason,
        )

    def reveal_holdout(
        self,
        authorization: HoldoutRevealAuthorization,
        certification: CertifiedFeatureReplay,
    ) -> Self:
        if type(authorization) is not HoldoutRevealAuthorization:
            raise ExperimentGovernanceError("holdout reveal requires exact authorization")
        expected = self.create_holdout_authorization(
            selected_configuration_sha256=authorization.selected_configuration_sha256,
            authorized_at=authorization.authorized_at,
            authorized_by=authorization.authorized_by,
            access_reason=authorization.access_reason,
        )
        if expected != authorization:
            raise ExperimentGovernanceError(
                "holdout authorization does not bind the current registry"
            )
        test_evidence = self.family.test_commitment.require_certification(
            self.family.segment(EvaluationSegmentKind.TEST),
            certification,
        )
        reveal = AuditedHoldoutReveal(
            authorization=authorization,
            test_evidence=test_evidence,
            global_sequence_number=self.next_global_sequence_number,
            previous_entry_sha256=self.registry_head_sha256,
        )
        return type(self)(
            family=self.family,
            attempts=self.attempts,
            lifecycle_events=self.lifecycle_events,
            holdout_reveal=reveal,
        )

    def latest_event(self, attempt_id: str) -> ExperimentAttemptEvent:
        events = tuple(event for event in self.lifecycle_events if event.attempt_id == attempt_id)
        if not events:
            raise ExperimentGovernanceError("unknown experiment attempt")
        return events[-1]

    @property
    def latest_events(self) -> tuple[ExperimentAttemptEvent, ...]:
        return tuple(self.latest_event(attempt.attempt_id) for attempt in self.attempts)

    @property
    def family_id(self) -> str:
        return self.family.family_id

    @property
    def attempts_sha256(self) -> str:
        return _sha256(tuple(attempt.semantic_sha256 for attempt in self.attempts))

    @property
    def chain_entry_sha256(self) -> str | None:
        entries: list[tuple[int, str]] = [
            (event.global_sequence_number, event.semantic_sha256) for event in self.lifecycle_events
        ]
        if self.holdout_reveal is not None:
            entries.append(
                (
                    self.holdout_reveal.global_sequence_number,
                    self.holdout_reveal.semantic_sha256,
                )
            )
        return None if not entries else max(entries)[1]

    @property
    def registry_head_sha256(self) -> str:
        return self.chain_entry_sha256 or self.family.semantic_sha256

    @property
    def next_global_sequence_number(self) -> int:
        return len(self.lifecycle_events) + int(self.holdout_reveal is not None)

    @property
    def semantic_sha256(self) -> str:
        return self.snapshot_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "experiment-governance-snapshot",
            self.family.semantic_sha256,
            tuple(attempt.semantic_sha256 for attempt in self.attempts),
            tuple(event.semantic_sha256 for event in self.lifecycle_events),
            (None if self.holdout_reveal is None else self.holdout_reveal.semantic_sha256),
        )


__all__ = [
    "EXPERIMENT_GOVERNANCE_CONTRACT_VERSION",
    "EXPERIMENT_SEGMENT_EVALUATION_CONTRACT_VERSION",
    "GOVERNED_SEGMENT_EVALUATION",
    "NON_EXECUTABLE_DOMAIN_FIXTURE",
    "AuditedHoldoutReveal",
    "ExperimentAttempt",
    "ExperimentAttemptEvent",
    "ExperimentAttemptStatus",
    "ExperimentGovernanceError",
    "ExperimentGovernanceFamily",
    "ExperimentGovernanceSnapshot",
    "ExperimentSegmentEvidence",
    "GovernedSegmentEvaluationReceipt",
    "HoldoutRevealAuthorization",
    "NonExecutableTerminalEvidence",
    "StrategyConfigurationValidationReceipt",
    "TestSegmentCommitment",
]
