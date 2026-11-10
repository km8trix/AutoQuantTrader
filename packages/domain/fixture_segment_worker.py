"""Pure contracts for the bounded Phase 3F fixture-segment worker.

The worker owns durable scheduling and immutable transcript publication for the
repository fixture only.  It does not calculate economic metrics, reveal a
sealed holdout, admit captured data, or grant promotion or trading authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.experiment_governance import (
    ExperimentAttempt,
    ExperimentAttemptEvent,
    ExperimentAttemptStatus,
    ExperimentGovernanceFamily,
    ExperimentGovernanceSnapshot,
    ExperimentSegmentEvidence,
    GovernedSegmentEvaluationReceipt,
    NonExecutableTerminalEvidence,
    governed_target_policy,
)
from packages.domain.experiment_registry import EvaluationSegmentKind
from packages.domain.feature import CertifiedFeatureReplay
from packages.domain.feature_target import CertifiedFeatureTargetReplay

FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION = "phase3f-fixture-segment-worker-v1"
FIXTURE_SEGMENT_CLAIM_TOKEN_CONTRACT_VERSION = "phase3f-fixture-segment-claim-v1"
MAX_FIXTURE_SEGMENT_EVENTS = 10_000
MAX_FIXTURE_TRANSCRIPT_STEPS = 100_000
MAX_FIXTURE_TRANSCRIPT_OUTPUTS = 5_000_000
MAX_FIXTURE_TRANSCRIPT_PAYLOAD_BYTES = 8_388_608

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FACTORY_PROOF = object()


class FixtureSegmentWorkerError(ValueError):
    """Fixture-segment evidence violates the bounded worker contract."""


class FixtureSegmentWorkerConflict(FixtureSegmentWorkerError):
    """A retry, claim, or publication conflicts with immutable evidence."""


class FixtureSegmentJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FixtureTranscriptKind(StrEnum):
    FEATURE = "feature"
    TARGET = "target"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


FIXTURE_SEGMENT_FAILURE_CODE = "fixture_segment_evaluation_failed"
FIXTURE_SEGMENT_FAILURE_DETAIL = (
    "Bounded fixture-segment evaluation failed; raw exception text was not retained."
)
FIXTURE_SEGMENT_FAILURE_SHA256 = _sha256(
    (
        FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
        "fixture-segment-failure-classification",
        FIXTURE_SEGMENT_FAILURE_CODE,
    )
)


def _fixture_segment_failure_evidence_for_attempt_id(
    attempt_id: str,
) -> NonExecutableTerminalEvidence:
    return NonExecutableTerminalEvidence._restore(
        attempt_id=attempt_id,
        status=ExperimentAttemptStatus.FAILED,
        source_evidence_sha256=None,
        reason_code=FIXTURE_SEGMENT_FAILURE_CODE,
        detail=FIXTURE_SEGMENT_FAILURE_DETAIL,
    )


def fixture_segment_failure_evidence(
    attempt: ExperimentAttempt,
) -> NonExecutableTerminalEvidence:
    """Return the one closed governance failure fact accepted by this worker."""

    if type(attempt) is not ExperimentAttempt:
        raise FixtureSegmentWorkerError(
            "fixture failure evidence requires an exact governed attempt"
        )
    return _fixture_segment_failure_evidence_for_attempt_id(attempt.attempt_id)


def _payload_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str | None, field_name: str) -> None:
    if value is None or type(value) is not str or _SHA256.fullmatch(value) is None:
        raise FixtureSegmentWorkerError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_text(value: str | None, field_name: str, *, maximum: int = 128) -> None:
    if (
        value is None
        or type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise FixtureSegmentWorkerError(f"{field_name} must be bounded non-empty trimmed text")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise FixtureSegmentWorkerError(f"{field_name} must be a timezone-aware UTC datetime")


def _attempt(snapshot: ExperimentGovernanceSnapshot, attempt_id: str) -> ExperimentAttempt:
    if type(snapshot) is not ExperimentGovernanceSnapshot:
        raise FixtureSegmentWorkerError("fixture work requires an exact governance snapshot")
    _require_sha256(attempt_id, "fixture attempt ID")
    try:
        return next(attempt for attempt in snapshot.attempts if attempt.attempt_id == attempt_id)
    except StopIteration as error:
        raise FixtureSegmentWorkerError("fixture work references an unknown attempt") from error


def segment_evidence_for_attempt(
    snapshot: ExperimentGovernanceSnapshot,
    attempt: ExperimentAttempt,
) -> ExperimentSegmentEvidence:
    """Return only evidence that the governance registry has already opened."""

    if attempt.segment_kind is EvaluationSegmentKind.TEST:
        reveal = snapshot.holdout_reveal
        if reveal is None or attempt.holdout_reveal_sha256 != reveal.semantic_sha256:
            raise FixtureSegmentWorkerError(
                "fixture worker cannot access unrevealed final-test evidence"
            )
        return reveal.test_evidence
    return snapshot.family.evidence(attempt.segment_kind)


@dataclass(frozen=True, slots=True, init=False)
class FixtureTranscriptArtifact:
    """Immutable content-addressed feature or target transcript summary."""

    kind: FixtureTranscriptKind
    family_id: str
    attempt_id: str
    segment_kind: EvaluationSegmentKind
    segment_sha256: str
    source_evidence_sha256: str
    configuration_sha256: str | None
    certification_sha256: str
    parity_receipt_sha256: str
    transcript_sha256: str
    step_sha256s: tuple[str, ...]
    output_ids: tuple[str, ...]
    transcript_payload: str
    transcript_payload_sha256: str
    artifact_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fixture transcript artifacts are proof-constructed")

    @classmethod
    def from_feature_certification(
        cls,
        *,
        family: ExperimentGovernanceFamily,
        attempt: ExperimentAttempt,
        source_evidence: ExperimentSegmentEvidence,
        certification: CertifiedFeatureReplay,
    ) -> Self:
        cls._require_context(family, attempt, source_evidence)
        try:
            source_evidence.require_certification(certification)
        except ValueError as error:
            raise FixtureSegmentWorkerError(
                "feature transcript changed the governed segment evidence"
            ) from error
        step_sha256s = tuple(step.semantic_sha256 for step in certification.batch_result.steps)
        output_ids = tuple(
            snapshot.semantic_sha256 for snapshot in certification.batch_result.snapshots
        )
        return cls._restore(
            kind=FixtureTranscriptKind.FEATURE,
            family_id=family.family_id,
            attempt_id=attempt.attempt_id,
            segment_kind=attempt.segment_kind,
            segment_sha256=attempt.segment_sha256,
            source_evidence_sha256=source_evidence.semantic_sha256,
            configuration_sha256=None,
            certification_sha256=certification.semantic_sha256,
            parity_receipt_sha256=certification.receipt.semantic_sha256,
            transcript_sha256=certification.batch_result.transcript_sha256,
            step_sha256s=step_sha256s,
            output_ids=output_ids,
        )

    @classmethod
    def from_target_certification(
        cls,
        *,
        family: ExperimentGovernanceFamily,
        attempt: ExperimentAttempt,
        source_evidence: ExperimentSegmentEvidence,
        certification: CertifiedFeatureTargetReplay,
    ) -> Self:
        cls._require_context(family, attempt, source_evidence)
        if type(certification) is not CertifiedFeatureTargetReplay:
            raise FixtureSegmentWorkerError(
                "target transcript requires exact certified target replay"
            )
        try:
            source_evidence.require_certification(certification.feature_certification)
        except ValueError as error:
            raise FixtureSegmentWorkerError(
                "target transcript changed the governed feature evidence"
            ) from error
        if certification.policy != governed_target_policy(attempt.configuration):
            raise FixtureSegmentWorkerError(
                "target transcript changed the exact governed configuration"
            )
        step_sha256s = tuple(step.semantic_sha256 for step in certification.batch_result.steps)
        output_ids = tuple(target.target_id for target in certification.batch_result.targets)
        return cls._restore(
            kind=FixtureTranscriptKind.TARGET,
            family_id=family.family_id,
            attempt_id=attempt.attempt_id,
            segment_kind=attempt.segment_kind,
            segment_sha256=attempt.segment_sha256,
            source_evidence_sha256=source_evidence.semantic_sha256,
            configuration_sha256=attempt.configuration.semantic_sha256,
            certification_sha256=certification.semantic_sha256,
            parity_receipt_sha256=certification.receipt.semantic_sha256,
            transcript_sha256=certification.batch_result.transcript_sha256,
            step_sha256s=step_sha256s,
            output_ids=output_ids,
        )

    @staticmethod
    def _require_context(
        family: ExperimentGovernanceFamily,
        attempt: ExperimentAttempt,
        source_evidence: ExperimentSegmentEvidence,
    ) -> None:
        if (
            type(family) is not ExperimentGovernanceFamily
            or type(attempt) is not ExperimentAttempt
            or type(source_evidence) is not ExperimentSegmentEvidence
            or attempt.family_id != family.family_id
            or attempt.segment_sha256 != family.segment(attempt.segment_kind).semantic_sha256
            or source_evidence.segment != family.segment(attempt.segment_kind)
        ):
            raise FixtureSegmentWorkerError(
                "fixture transcript changed family, attempt, or segment identity"
            )

    @classmethod
    def _restore(
        cls,
        *,
        kind: FixtureTranscriptKind,
        family_id: str,
        attempt_id: str,
        segment_kind: EvaluationSegmentKind,
        segment_sha256: str,
        source_evidence_sha256: str,
        configuration_sha256: str | None,
        certification_sha256: str,
        parity_receipt_sha256: str,
        transcript_sha256: str,
        step_sha256s: tuple[str, ...],
        output_ids: tuple[str, ...],
        expected_transcript_payload: str | None = None,
        expected_transcript_payload_sha256: str | None = None,
        expected_artifact_sha256: str | None = None,
    ) -> Self:
        if type(kind) is not FixtureTranscriptKind:
            raise FixtureSegmentWorkerError("fixture transcript kind must be exact")
        for value, field_name in (
            (family_id, "transcript family ID"),
            (attempt_id, "transcript attempt ID"),
            (segment_sha256, "transcript segment digest"),
            (source_evidence_sha256, "transcript source-evidence digest"),
            (certification_sha256, "transcript certification digest"),
            (parity_receipt_sha256, "transcript parity-receipt digest"),
            (transcript_sha256, "transcript digest"),
        ):
            _require_sha256(value, field_name)
        if type(segment_kind) is not EvaluationSegmentKind:
            raise FixtureSegmentWorkerError("transcript segment kind must be exact")
        _require_optional_sha256(configuration_sha256, "transcript configuration digest")
        if (kind is FixtureTranscriptKind.TARGET) != (configuration_sha256 is not None):
            raise FixtureSegmentWorkerError("only target transcripts bind a strategy configuration")
        if (
            type(step_sha256s) is not tuple
            or not 1 <= len(step_sha256s) <= MAX_FIXTURE_TRANSCRIPT_STEPS
        ):
            raise FixtureSegmentWorkerError("fixture transcript step count is outside its bound")
        if type(output_ids) is not tuple or len(output_ids) > MAX_FIXTURE_TRANSCRIPT_OUTPUTS:
            raise FixtureSegmentWorkerError("fixture transcript output count is outside its bound")
        for digest in step_sha256s:
            _require_sha256(digest, "fixture transcript step digest")
        for output_id in output_ids:
            _require_text(output_id, "fixture transcript output ID", maximum=128)
        payload_material = (
            FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
            "fixture-segment-transcript",
            kind.value,
            family_id,
            attempt_id,
            segment_kind.value,
            segment_sha256,
            source_evidence_sha256,
            configuration_sha256,
            certification_sha256,
            parity_receipt_sha256,
            transcript_sha256,
            step_sha256s,
            output_ids,
        )
        transcript_payload = canonical_json_text(payload_material)
        if len(transcript_payload.encode("utf-8")) > MAX_FIXTURE_TRANSCRIPT_PAYLOAD_BYTES:
            raise FixtureSegmentWorkerError("fixture transcript payload exceeds its byte bound")
        if (
            expected_transcript_payload is not None
            and expected_transcript_payload != transcript_payload
        ):
            raise FixtureSegmentWorkerError("persisted fixture transcript payload is inconsistent")
        transcript_payload_sha256 = _payload_sha256(transcript_payload)
        if (
            expected_transcript_payload_sha256 is not None
            and expected_transcript_payload_sha256 != transcript_payload_sha256
        ):
            raise FixtureSegmentWorkerError("fixture transcript payload digest is inconsistent")
        artifact_sha256 = _sha256(
            (
                FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
                "fixture-segment-transcript-artifact",
                kind.value,
                family_id,
                attempt_id,
                segment_sha256,
                configuration_sha256,
                certification_sha256,
                transcript_sha256,
                transcript_payload_sha256,
            )
        )
        if expected_artifact_sha256 is not None and expected_artifact_sha256 != artifact_sha256:
            raise FixtureSegmentWorkerError("fixture transcript artifact digest is inconsistent")
        instance = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("kind", kind),
            ("family_id", family_id),
            ("attempt_id", attempt_id),
            ("segment_kind", segment_kind),
            ("segment_sha256", segment_sha256),
            ("source_evidence_sha256", source_evidence_sha256),
            ("configuration_sha256", configuration_sha256),
            ("certification_sha256", certification_sha256),
            ("parity_receipt_sha256", parity_receipt_sha256),
            ("transcript_sha256", transcript_sha256),
            ("step_sha256s", step_sha256s),
            ("output_ids", output_ids),
            ("transcript_payload", transcript_payload),
            ("transcript_payload_sha256", transcript_payload_sha256),
            ("artifact_sha256", artifact_sha256),
        )
        for name, field_value in values:
            object.__setattr__(instance, name, field_value)
        return instance

    @property
    def semantic_sha256(self) -> str:
        return self.artifact_sha256


@dataclass(frozen=True, slots=True)
class FixtureSegmentJob:
    """One exact queued governed attempt and its certified feature input."""

    family_id: str
    attempt_id: str
    configuration_sha256: str
    configuration_validation_sha256: str
    segment_kind: EvaluationSegmentKind
    segment_sha256: str
    source_evidence_sha256: str
    queued_governance_event_sha256: str
    feature_certification_sha256: str
    feature_transcript_artifact_sha256: str
    requested_at: datetime
    requested_by: str
    job_id: str = field(init=False)
    governed_actor_id: str = field(init=False)
    semantic_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.family_id, "job family ID"),
            (self.attempt_id, "job attempt ID"),
            (self.configuration_sha256, "job configuration digest"),
            (self.configuration_validation_sha256, "job configuration-validation digest"),
            (self.segment_sha256, "job segment digest"),
            (self.source_evidence_sha256, "job source-evidence digest"),
            (self.queued_governance_event_sha256, "job queued-event digest"),
            (self.feature_certification_sha256, "job feature-certification digest"),
            (self.feature_transcript_artifact_sha256, "job feature-artifact digest"),
        ):
            _require_sha256(value, field_name)
        if type(self.segment_kind) is not EvaluationSegmentKind:
            raise FixtureSegmentWorkerError("job segment kind must be exact")
        _require_utc(self.requested_at, "fixture job requested_at")
        _require_text(self.requested_by, "fixture job requester")
        job_id = _sha256(
            (
                FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
                "fixture-segment-job-identity",
                self.family_id,
                self.attempt_id,
            )
        )
        governed_actor_id = f"phase3f-governed-{job_id}"
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "governed_actor_id", governed_actor_id)
        object.__setattr__(self, "semantic_sha256", _sha256(self._semantic_material(job_id)))

    @classmethod
    def from_queued_attempt(
        cls,
        snapshot: ExperimentGovernanceSnapshot,
        attempt_id: str,
        certification: CertifiedFeatureReplay,
        *,
        requested_at: datetime,
        requested_by: str,
    ) -> tuple[Self, FixtureTranscriptArtifact]:
        return cls._from_original_enqueue(
            snapshot,
            attempt_id,
            certification,
            requested_at=requested_at,
            requested_by=requested_by,
            require_current_queued=True,
        )

    @classmethod
    def _from_original_enqueue(
        cls,
        snapshot: ExperimentGovernanceSnapshot,
        attempt_id: str,
        certification: CertifiedFeatureReplay,
        *,
        requested_at: datetime,
        requested_by: str,
        require_current_queued: bool,
    ) -> tuple[Self, FixtureTranscriptArtifact]:
        """Reconstruct immutable enqueue input from the attempt's first event.

        Persistence uses the non-current form only after it has resolved and
        locked an already durable job. New work must still use
        :meth:`from_queued_attempt` and therefore requires a currently queued
        governed attempt.
        """

        attempt = _attempt(snapshot, attempt_id)
        queued = next(
            (
                event
                for event in snapshot.lifecycle_events
                if event.attempt_id == attempt_id and event.attempt_sequence_number == 0
            ),
            None,
        )
        if (
            type(queued) is not ExperimentAttemptEvent
            or queued.status is not ExperimentAttemptStatus.QUEUED
            or (require_current_queued and snapshot.latest_event(attempt_id) != queued)
        ):
            raise FixtureSegmentWorkerError("fixture work can be enqueued only for queued attempts")
        _require_utc(requested_at, "fixture job requested_at")
        if requested_at < queued.occurred_at:
            raise FixtureSegmentWorkerError("fixture request cannot precede its queued attempt")
        source_evidence = segment_evidence_for_attempt(snapshot, attempt)
        artifact = FixtureTranscriptArtifact.from_feature_certification(
            family=snapshot.family,
            attempt=attempt,
            source_evidence=source_evidence,
            certification=certification,
        )
        return (
            cls(
                family_id=snapshot.family_id,
                attempt_id=attempt.attempt_id,
                configuration_sha256=attempt.configuration.semantic_sha256,
                configuration_validation_sha256=attempt.configuration_validation.semantic_sha256,
                segment_kind=attempt.segment_kind,
                segment_sha256=attempt.segment_sha256,
                source_evidence_sha256=source_evidence.semantic_sha256,
                queued_governance_event_sha256=queued.semantic_sha256,
                feature_certification_sha256=certification.semantic_sha256,
                feature_transcript_artifact_sha256=artifact.artifact_sha256,
                requested_at=requested_at,
                requested_by=requested_by,
            ),
            artifact,
        )

    def _semantic_material(self, job_id: str | None = None) -> tuple[object, ...]:
        return (
            FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
            "fixture-segment-job",
            self.job_id if job_id is None else job_id,
            self.family_id,
            self.attempt_id,
            self.configuration_sha256,
            self.configuration_validation_sha256,
            self.segment_kind.value,
            self.segment_sha256,
            self.source_evidence_sha256,
            self.queued_governance_event_sha256,
            self.feature_certification_sha256,
            self.feature_transcript_artifact_sha256,
            self.requested_at,
            self.requested_by,
            self.governed_actor_id,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class FixtureSegmentClaimToken:
    """Rotating authority for exactly one physical worker claim event."""

    job_id: str
    worker_id: str
    attempt_number: int
    claim_event_sha256: str
    token_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_sha256(self.job_id, "claim job ID")
        _require_text(self.worker_id, "claim worker ID")
        if type(self.attempt_number) is not int or self.attempt_number <= 0:
            raise FixtureSegmentWorkerError("claim attempt number must be positive")
        _require_sha256(self.claim_event_sha256, "claim event digest")
        object.__setattr__(
            self,
            "token_sha256",
            _sha256(
                (
                    FIXTURE_SEGMENT_CLAIM_TOKEN_CONTRACT_VERSION,
                    self.job_id,
                    self.worker_id,
                    self.attempt_number,
                    self.claim_event_sha256,
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class FixtureSegmentJobEvent:
    """One authenticated append-only fixture-job transition."""

    job_id: str
    sequence: int
    status: FixtureSegmentJobStatus
    occurred_at: datetime
    actor_id: str
    attempt_number: int
    previous_event_sha256: str | None
    worker_id: str | None
    claim_expires_at: datetime | None
    governance_event_sha256: str
    feature_artifact_sha256: str
    target_artifact_sha256: str | None
    completion_receipt_sha256: str | None
    terminal_reason_code: str | None
    terminal_reason_sha256: str | None
    _construction_proof: InitVar[object]
    event_sha256: str = field(init=False)

    def __post_init__(self, _construction_proof: object) -> None:
        if _construction_proof is not _FACTORY_PROOF:
            raise FixtureSegmentWorkerError("fixture job events require lifecycle factories")
        _require_sha256(self.job_id, "event job ID")
        if type(self.sequence) is not int or self.sequence < 0:
            raise FixtureSegmentWorkerError("event sequence must be non-negative")
        if type(self.status) is not FixtureSegmentJobStatus:
            raise FixtureSegmentWorkerError("event status must be exact")
        _require_utc(self.occurred_at, "event occurred_at")
        _require_text(self.actor_id, "event actor")
        if type(self.attempt_number) is not int or self.attempt_number < 0:
            raise FixtureSegmentWorkerError("event attempt number must be non-negative")
        _require_optional_sha256(self.previous_event_sha256, "event predecessor")
        _require_sha256(self.governance_event_sha256, "event governance digest")
        _require_sha256(self.feature_artifact_sha256, "event feature artifact")
        _require_optional_sha256(self.target_artifact_sha256, "event target artifact")
        _require_optional_sha256(self.completion_receipt_sha256, "event completion receipt")
        _require_optional_sha256(self.terminal_reason_sha256, "event failure digest")
        self._validate_shape()
        object.__setattr__(self, "event_sha256", _sha256(self._semantic_material()))

    def _validate_shape(self) -> None:
        if self.sequence == 0:
            if self.previous_event_sha256 is not None:
                raise FixtureSegmentWorkerError("queued event cannot have a predecessor")
        elif self.previous_event_sha256 is None:
            raise FixtureSegmentWorkerError("non-initial event requires a predecessor")
        if self.status is FixtureSegmentJobStatus.QUEUED:
            if (
                self.sequence != 0
                or self.attempt_number != 0
                or self.worker_id is not None
                or self.claim_expires_at is not None
                or self.target_artifact_sha256 is not None
                or self.completion_receipt_sha256 is not None
                or self.terminal_reason_code is not None
                or self.terminal_reason_sha256 is not None
            ):
                raise FixtureSegmentWorkerError("queued fixture event has terminal or claim data")
            return
        if self.status is FixtureSegmentJobStatus.RUNNING:
            if self.worker_id is None or self.claim_expires_at is None:
                raise FixtureSegmentWorkerError("running fixture event requires a bounded claim")
            _require_text(self.worker_id, "event worker ID")
            _require_utc(self.claim_expires_at, "claim expiry")
            if self.attempt_number <= 0 or self.claim_expires_at <= self.occurred_at:
                raise FixtureSegmentWorkerError("running fixture claim has an invalid bound")
            if (
                self.target_artifact_sha256 is not None
                or self.completion_receipt_sha256 is not None
                or self.terminal_reason_code is not None
                or self.terminal_reason_sha256 is not None
            ):
                raise FixtureSegmentWorkerError("running fixture event cannot claim a result")
            return
        if self.worker_id is None or self.claim_expires_at is not None or self.attempt_number <= 0:
            raise FixtureSegmentWorkerError("terminal fixture event must identify its worker claim")
        _require_text(self.worker_id, "terminal worker ID")
        if self.status is FixtureSegmentJobStatus.COMPLETED:
            if (
                self.target_artifact_sha256 is None
                or self.completion_receipt_sha256 is None
                or self.terminal_reason_code is not None
                or self.terminal_reason_sha256 is not None
            ):
                raise FixtureSegmentWorkerError("completed fixture event lacks exact publication")
            return
        if (
            self.target_artifact_sha256 is not None
            or self.completion_receipt_sha256 is not None
            or self.terminal_reason_code is None
            or self.terminal_reason_sha256 is None
        ):
            raise FixtureSegmentWorkerError("failed fixture event requires only a bounded reason")
        _require_text(self.terminal_reason_code, "failure reason code", maximum=64)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION,
            "fixture-segment-job-event",
            self.job_id,
            self.sequence,
            self.status.value,
            self.occurred_at,
            self.actor_id,
            self.attempt_number,
            self.previous_event_sha256,
            self.worker_id,
            self.claim_expires_at,
            self.governance_event_sha256,
            self.feature_artifact_sha256,
            self.target_artifact_sha256,
            self.completion_receipt_sha256,
            self.terminal_reason_code,
            self.terminal_reason_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _event(**values: object) -> FixtureSegmentJobEvent:
    return FixtureSegmentJobEvent(_construction_proof=_FACTORY_PROOF, **values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class FixtureSegmentJobProjection:
    """Authenticated job state reconstructed from its immutable facts."""

    job: FixtureSegmentJob
    feature_artifact: FixtureTranscriptArtifact
    events: tuple[FixtureSegmentJobEvent, ...]
    target_artifact: FixtureTranscriptArtifact | None = None

    def __post_init__(self) -> None:
        if type(self.job) is not FixtureSegmentJob:
            raise FixtureSegmentWorkerError("fixture projection requires an exact job")
        if (
            type(self.feature_artifact) is not FixtureTranscriptArtifact
            or self.feature_artifact.kind is not FixtureTranscriptKind.FEATURE
            or self.feature_artifact.artifact_sha256 != self.job.feature_transcript_artifact_sha256
            or self.feature_artifact.family_id != self.job.family_id
            or self.feature_artifact.attempt_id != self.job.attempt_id
        ):
            raise FixtureSegmentWorkerError("fixture projection changed its feature artifact")
        if not self.events or len(self.events) > MAX_FIXTURE_SEGMENT_EVENTS:
            raise FixtureSegmentWorkerError("fixture projection event chain is outside its bound")
        previous: str | None = None
        prior_time: datetime | None = None
        for sequence, event in enumerate(self.events):
            if (
                type(event) is not FixtureSegmentJobEvent
                or event.job_id != self.job.job_id
                or event.sequence != sequence
                or event.previous_event_sha256 != previous
                or event.feature_artifact_sha256 != self.feature_artifact.artifact_sha256
                or (prior_time is not None and event.occurred_at <= prior_time)
            ):
                raise FixtureSegmentWorkerError("fixture projection event chain is inconsistent")
            previous = event.event_sha256
            prior_time = event.occurred_at
        first = self.events[0]
        if (
            first.status is not FixtureSegmentJobStatus.QUEUED
            or first.actor_id != self.job.requested_by
            or first.occurred_at != self.job.requested_at
            or first.governance_event_sha256 != self.job.queued_governance_event_sha256
        ):
            raise FixtureSegmentWorkerError("fixture projection changed its queued request")
        for previous_event, event in zip(self.events, self.events[1:], strict=False):
            if event.status is FixtureSegmentJobStatus.RUNNING:
                if previous_event.status is FixtureSegmentJobStatus.QUEUED:
                    if event.attempt_number != 1:
                        raise FixtureSegmentWorkerError("first fixture claim must be attempt one")
                elif previous_event.status is FixtureSegmentJobStatus.RUNNING:
                    if event.attempt_number == previous_event.attempt_number:
                        if (
                            event.worker_id != previous_event.worker_id
                            or event.occurred_at > previous_event.claim_expires_at  # type: ignore[operator]
                            or event.claim_expires_at <= previous_event.claim_expires_at  # type: ignore[operator]
                        ):
                            raise FixtureSegmentWorkerError("fixture claim renewal is inconsistent")
                    elif (
                        event.attempt_number != previous_event.attempt_number + 1
                        or event.occurred_at <= previous_event.claim_expires_at  # type: ignore[operator]
                    ):
                        raise FixtureSegmentWorkerError("fixture claim takeover is inconsistent")
                else:
                    raise FixtureSegmentWorkerError("terminal fixture job cannot be reclaimed")
            elif previous_event.status is not FixtureSegmentJobStatus.RUNNING:
                raise FixtureSegmentWorkerError("fixture terminal event requires a running claim")
            elif (
                event.worker_id != previous_event.worker_id
                or event.actor_id != previous_event.worker_id
                or event.attempt_number != previous_event.attempt_number
                or event.occurred_at > previous_event.claim_expires_at  # type: ignore[operator]
            ):
                raise FixtureSegmentWorkerError(
                    "fixture terminal event changed or exceeded its physical claim"
                )
        latest = self.events[-1]
        if latest.status is FixtureSegmentJobStatus.COMPLETED:
            if (
                type(self.target_artifact) is not FixtureTranscriptArtifact
                or self.target_artifact.kind is not FixtureTranscriptKind.TARGET
                or latest.target_artifact_sha256 != self.target_artifact.artifact_sha256
                or self.target_artifact.family_id != self.job.family_id
                or self.target_artifact.attempt_id != self.job.attempt_id
                or self.target_artifact.configuration_sha256 != self.job.configuration_sha256
            ):
                raise FixtureSegmentWorkerError(
                    "completed fixture projection lacks target artifact"
                )
        elif self.target_artifact is not None:
            raise FixtureSegmentWorkerError("non-completed fixture job cannot publish a target")
        if latest.status is FixtureSegmentJobStatus.FAILED and (
            latest.terminal_reason_code != FIXTURE_SEGMENT_FAILURE_CODE
            or latest.terminal_reason_sha256 != FIXTURE_SEGMENT_FAILURE_SHA256
        ):
            raise FixtureSegmentWorkerError("fixture failure classification is not closed")

    @property
    def latest(self) -> FixtureSegmentJobEvent:
        return self.events[-1]

    @property
    def status(self) -> FixtureSegmentJobStatus:
        return self.latest.status

    @property
    def terminal(self) -> bool:
        return self.status in {FixtureSegmentJobStatus.COMPLETED, FixtureSegmentJobStatus.FAILED}

    @property
    def claim_token(self) -> FixtureSegmentClaimToken | None:
        if self.latest.status is not FixtureSegmentJobStatus.RUNNING:
            return None
        worker_id = self.latest.worker_id
        assert worker_id is not None
        return FixtureSegmentClaimToken(
            job_id=self.job.job_id,
            worker_id=worker_id,
            attempt_number=self.latest.attempt_number,
            claim_event_sha256=self.latest.event_sha256,
        )


def queue_fixture_segment_job(
    job: FixtureSegmentJob,
    feature_artifact: FixtureTranscriptArtifact,
) -> FixtureSegmentJobProjection:
    if feature_artifact.artifact_sha256 != job.feature_transcript_artifact_sha256:
        raise FixtureSegmentWorkerError("queued job changed its feature transcript")
    queued = _event(
        job_id=job.job_id,
        sequence=0,
        status=FixtureSegmentJobStatus.QUEUED,
        occurred_at=job.requested_at,
        actor_id=job.requested_by,
        attempt_number=0,
        previous_event_sha256=None,
        worker_id=None,
        claim_expires_at=None,
        governance_event_sha256=job.queued_governance_event_sha256,
        feature_artifact_sha256=feature_artifact.artifact_sha256,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
        terminal_reason_code=None,
        terminal_reason_sha256=None,
    )
    return FixtureSegmentJobProjection(job=job, feature_artifact=feature_artifact, events=(queued,))


def claim_fixture_segment_job(
    projection: FixtureSegmentJobProjection,
    *,
    worker_id: str,
    claimed_at: datetime,
    claim_expires_at: datetime,
    governance_running_event_sha256: str,
) -> FixtureSegmentJobProjection:
    if projection.terminal:
        raise FixtureSegmentWorkerConflict("terminal fixture job cannot be claimed")
    _require_text(worker_id, "claim worker ID")
    _require_utc(claimed_at, "claim time")
    _require_utc(claim_expires_at, "claim expiry")
    _require_sha256(governance_running_event_sha256, "governance running event")
    latest = projection.latest
    if latest.status is FixtureSegmentJobStatus.RUNNING:
        assert latest.claim_expires_at is not None
        if claimed_at <= latest.claim_expires_at:
            raise FixtureSegmentWorkerConflict("fixture job has an unexpired worker claim")
        attempt_number = latest.attempt_number + 1
    else:
        attempt_number = 1
    running = _event(
        job_id=projection.job.job_id,
        sequence=len(projection.events),
        status=FixtureSegmentJobStatus.RUNNING,
        occurred_at=claimed_at,
        actor_id=worker_id,
        attempt_number=attempt_number,
        previous_event_sha256=latest.event_sha256,
        worker_id=worker_id,
        claim_expires_at=claim_expires_at,
        governance_event_sha256=governance_running_event_sha256,
        feature_artifact_sha256=projection.feature_artifact.artifact_sha256,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
        terminal_reason_code=None,
        terminal_reason_sha256=None,
    )
    return FixtureSegmentJobProjection(
        job=projection.job,
        feature_artifact=projection.feature_artifact,
        events=(*projection.events, running),
    )


def renew_fixture_segment_claim(
    projection: FixtureSegmentJobProjection,
    token: FixtureSegmentClaimToken,
    *,
    renewed_at: datetime,
    claim_expires_at: datetime,
) -> FixtureSegmentJobProjection:
    _require_claim(projection, token, renewed_at)
    latest = projection.latest
    assert latest.claim_expires_at is not None and latest.worker_id is not None
    if renewed_at <= latest.occurred_at:
        raise FixtureSegmentWorkerConflict("fixture renewal must follow its current claim event")
    if claim_expires_at <= latest.claim_expires_at:
        raise FixtureSegmentWorkerConflict("fixture claim renewal must extend expiry")
    renewed = _event(
        job_id=projection.job.job_id,
        sequence=len(projection.events),
        status=FixtureSegmentJobStatus.RUNNING,
        occurred_at=renewed_at,
        actor_id=latest.worker_id,
        attempt_number=latest.attempt_number,
        previous_event_sha256=latest.event_sha256,
        worker_id=latest.worker_id,
        claim_expires_at=claim_expires_at,
        governance_event_sha256=latest.governance_event_sha256,
        feature_artifact_sha256=projection.feature_artifact.artifact_sha256,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
        terminal_reason_code=None,
        terminal_reason_sha256=None,
    )
    return FixtureSegmentJobProjection(
        job=projection.job,
        feature_artifact=projection.feature_artifact,
        events=(*projection.events, renewed),
    )


def _require_claim(
    projection: FixtureSegmentJobProjection,
    token: FixtureSegmentClaimToken,
    occurred_at: datetime,
) -> None:
    if type(token) is not FixtureSegmentClaimToken:
        raise FixtureSegmentWorkerConflict("fixture publication requires an exact claim token")
    _require_utc(occurred_at, "fixture claim command time")
    expected = projection.claim_token
    latest = projection.latest
    if expected is None or expected != token or token.job_id != projection.job.job_id:
        raise FixtureSegmentWorkerConflict("fixture claim token is stale or substituted")
    assert latest.claim_expires_at is not None
    if occurred_at > latest.claim_expires_at:
        raise FixtureSegmentWorkerConflict("fixture worker claim has expired")
    if occurred_at < latest.occurred_at:
        raise FixtureSegmentWorkerConflict("fixture command precedes its worker claim")


def complete_fixture_segment_job(
    projection: FixtureSegmentJobProjection,
    token: FixtureSegmentClaimToken,
    *,
    target_artifact: FixtureTranscriptArtifact,
    receipt: GovernedSegmentEvaluationReceipt,
    governance_completed_event: ExperimentAttemptEvent,
    completed_at: datetime,
) -> FixtureSegmentJobProjection:
    _require_claim(projection, token, completed_at)
    job = projection.job
    if (
        type(governance_completed_event) is not ExperimentAttemptEvent
        or governance_completed_event.status is not ExperimentAttemptStatus.COMPLETED
        or governance_completed_event.attempt_id != job.attempt_id
        or governance_completed_event.terminal_evidence != receipt
        or governance_completed_event.occurred_at != completed_at
    ):
        raise FixtureSegmentWorkerConflict(
            "fixture completion changed its governed completion event"
        )
    if (
        type(target_artifact) is not FixtureTranscriptArtifact
        or target_artifact.kind is not FixtureTranscriptKind.TARGET
        or target_artifact.family_id != job.family_id
        or target_artifact.attempt_id != job.attempt_id
        or target_artifact.segment_kind is not job.segment_kind
        or target_artifact.segment_sha256 != job.segment_sha256
        or target_artifact.source_evidence_sha256 != job.source_evidence_sha256
        or target_artifact.configuration_sha256 != job.configuration_sha256
        or type(receipt) is not GovernedSegmentEvaluationReceipt
        or receipt.family_id != job.family_id
        or receipt.attempt_id != job.attempt_id
        or receipt.configuration_sha256 != job.configuration_sha256
        or receipt.configuration_validation_sha256 != job.configuration_validation_sha256
        or receipt.segment_kind is not job.segment_kind
        or receipt.segment_sha256 != job.segment_sha256
        or receipt.source_evidence_sha256 != job.source_evidence_sha256
        or receipt.feature_certification_sha256 != job.feature_certification_sha256
        or receipt.target_certification_sha256 != target_artifact.certification_sha256
        or receipt.target_parity_receipt_sha256 != target_artifact.parity_receipt_sha256
        or receipt.target_transcript_sha256 != target_artifact.transcript_sha256
    ):
        raise FixtureSegmentWorkerConflict(
            "fixture completion substituted attempt, configuration, segment, or transcript"
        )
    latest = projection.latest
    assert latest.worker_id is not None
    completed = _event(
        job_id=job.job_id,
        sequence=len(projection.events),
        status=FixtureSegmentJobStatus.COMPLETED,
        occurred_at=completed_at,
        actor_id=latest.worker_id,
        attempt_number=latest.attempt_number,
        previous_event_sha256=latest.event_sha256,
        worker_id=latest.worker_id,
        claim_expires_at=None,
        governance_event_sha256=governance_completed_event.semantic_sha256,
        feature_artifact_sha256=projection.feature_artifact.artifact_sha256,
        target_artifact_sha256=target_artifact.artifact_sha256,
        completion_receipt_sha256=receipt.semantic_sha256,
        terminal_reason_code=None,
        terminal_reason_sha256=None,
    )
    return FixtureSegmentJobProjection(
        job=job,
        feature_artifact=projection.feature_artifact,
        events=(*projection.events, completed),
        target_artifact=target_artifact,
    )


def fail_fixture_segment_job(
    projection: FixtureSegmentJobProjection,
    token: FixtureSegmentClaimToken,
    *,
    governance_failed_event: ExperimentAttemptEvent,
    failed_at: datetime,
    reason_code: str,
    reason_sha256: str,
) -> FixtureSegmentJobProjection:
    _require_claim(projection, token, failed_at)
    if (
        reason_code != FIXTURE_SEGMENT_FAILURE_CODE
        or reason_sha256 != FIXTURE_SEGMENT_FAILURE_SHA256
    ):
        raise FixtureSegmentWorkerConflict("fixture failure classification is not closed")
    expected_terminal_evidence = _fixture_segment_failure_evidence_for_attempt_id(
        projection.job.attempt_id
    )
    if (
        type(governance_failed_event) is not ExperimentAttemptEvent
        or governance_failed_event.status is not ExperimentAttemptStatus.FAILED
        or governance_failed_event.family_id != projection.job.family_id
        or governance_failed_event.attempt_id != projection.job.attempt_id
        or governance_failed_event.occurred_at != failed_at
        or type(governance_failed_event.terminal_evidence) is not NonExecutableTerminalEvidence
        or governance_failed_event.terminal_evidence != expected_terminal_evidence
    ):
        raise FixtureSegmentWorkerConflict("fixture failure changed its governed terminal event")
    latest = projection.latest
    assert latest.worker_id is not None
    failed = _event(
        job_id=projection.job.job_id,
        sequence=len(projection.events),
        status=FixtureSegmentJobStatus.FAILED,
        occurred_at=failed_at,
        actor_id=latest.worker_id,
        attempt_number=latest.attempt_number,
        previous_event_sha256=latest.event_sha256,
        worker_id=latest.worker_id,
        claim_expires_at=None,
        governance_event_sha256=governance_failed_event.semantic_sha256,
        feature_artifact_sha256=projection.feature_artifact.artifact_sha256,
        target_artifact_sha256=None,
        completion_receipt_sha256=None,
        terminal_reason_code=reason_code,
        terminal_reason_sha256=reason_sha256,
    )
    return FixtureSegmentJobProjection(
        job=projection.job,
        feature_artifact=projection.feature_artifact,
        events=(*projection.events, failed),
    )


__all__ = [
    "FIXTURE_SEGMENT_CLAIM_TOKEN_CONTRACT_VERSION",
    "FIXTURE_SEGMENT_FAILURE_CODE",
    "FIXTURE_SEGMENT_FAILURE_DETAIL",
    "FIXTURE_SEGMENT_FAILURE_SHA256",
    "FIXTURE_SEGMENT_WORKER_CONTRACT_VERSION",
    "FixtureSegmentClaimToken",
    "FixtureSegmentJob",
    "FixtureSegmentJobEvent",
    "FixtureSegmentJobProjection",
    "FixtureSegmentJobStatus",
    "FixtureSegmentWorkerConflict",
    "FixtureSegmentWorkerError",
    "FixtureTranscriptArtifact",
    "FixtureTranscriptKind",
    "claim_fixture_segment_job",
    "complete_fixture_segment_job",
    "fail_fixture_segment_job",
    "fixture_segment_failure_evidence",
    "queue_fixture_segment_job",
    "renew_fixture_segment_claim",
    "segment_evidence_for_attempt",
]
