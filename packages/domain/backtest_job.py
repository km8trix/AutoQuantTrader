"""Pure durable-job lifecycle for fixture-only Phase 2 backtests.

The worker-facing lifecycle is append-only.  A mutable SQL head may cache the
latest event for locking and efficient queries, but every accepted transition
must remain reconstructable from the event chain defined here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from packages.domain.canonical import canonical_json_bytes, canonical_json_text

BACKTEST_JOB_CONTRACT_VERSION = "phase2-backtest-job-v1"
MAX_JOB_EVENTS = 10_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_FACTORY_PROOF = object()


class BacktestJobError(ValueError):
    """A fixture job or lifecycle transition violates the durable contract."""


class BacktestJobConflict(BacktestJobError):
    """A retry or transition conflicts with immutable job evidence."""


class BacktestJobNotClaimable(BacktestJobError):
    """A worker cannot currently acquire the requested job."""


class BacktestJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise BacktestJobError(f"{field_name} must be non-empty and trimmed")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise BacktestJobError(f"{field_name} contains unsupported text")


def _require_sha256(value: str | None, field_name: str) -> None:
    if value is None or type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BacktestJobError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise BacktestJobError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise BacktestJobError(f"{field_name} must be UTC")


@dataclass(frozen=True, slots=True)
class BacktestJobInput:
    """Exact immutable selection accepted by the local research launcher."""

    fixture_id: str
    fixture_version: str
    dataset_manifest_id: str
    dataset_manifest_sha256: str
    replay_run_id: str
    strategy_id: str
    strategy_version: str
    strategy_configuration_sha256: str
    benchmark_sha256: str
    cost_model_sha256: str
    fill_model_sha256: str
    metric_conventions_sha256: str
    input_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.fixture_id, "fixture ID"),
            (self.fixture_version, "fixture version"),
            (self.strategy_id, "strategy ID"),
            (self.strategy_version, "strategy version"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.dataset_manifest_id, "dataset manifest ID"),
            (self.dataset_manifest_sha256, "dataset manifest digest"),
            (self.replay_run_id, "replay run ID"),
            (self.strategy_configuration_sha256, "strategy configuration digest"),
            (self.benchmark_sha256, "benchmark digest"),
            (self.cost_model_sha256, "cost model digest"),
            (self.fill_model_sha256, "fill model digest"),
            (self.metric_conventions_sha256, "metric conventions digest"),
        ):
            _require_sha256(value, field_name)
        if self.dataset_manifest_id != self.dataset_manifest_sha256:
            raise BacktestJobError(
                "fixture dataset manifest ID must equal its content-addressed digest"
            )
        object.__setattr__(self, "input_sha256", _sha256(self._semantic_material()))

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BACKTEST_JOB_CONTRACT_VERSION,
            "input",
            self.fixture_id,
            self.fixture_version,
            self.dataset_manifest_id,
            self.dataset_manifest_sha256,
            self.replay_run_id,
            self.strategy_id,
            self.strategy_version,
            self.strategy_configuration_sha256,
            self.benchmark_sha256,
            self.cost_model_sha256,
            self.fill_model_sha256,
            self.metric_conventions_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestJob:
    """One idempotently launched job with immutable request and audit identity."""

    input: BacktestJobInput
    requested_by: str
    idempotency_key: str
    requested_at: datetime
    job_id: str = field(init=False)
    semantic_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.input) is not BacktestJobInput:
            raise BacktestJobError("job requires an exact BacktestJobInput")
        _require_text(self.requested_by, "requesting operator ID")
        if (
            type(self.idempotency_key) is not str
            or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
        ):
            raise BacktestJobError("idempotency key must contain 8-128 safe visible characters")
        _require_utc(self.requested_at, "job requested_at")
        job_id = _sha256(
            (
                BACKTEST_JOB_CONTRACT_VERSION,
                "identity",
                self.requested_by,
                self.idempotency_key,
            )
        )
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "semantic_sha256", _sha256(self._semantic_material(job_id)))

    def _semantic_material(self, job_id: str | None = None) -> tuple[object, ...]:
        return (
            BACKTEST_JOB_CONTRACT_VERSION,
            "job",
            self.job_id if job_id is None else job_id,
            self.input._semantic_material(),
            self.input.input_sha256,
            self.requested_by,
            self.idempotency_key,
            self.requested_at,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestJobEvent:
    """One authenticated state transition in a job's append-only chain."""

    job_id: str
    sequence: int
    status: BacktestJobStatus
    occurred_at: datetime
    actor_id: str
    attempt_number: int
    previous_event_sha256: str | None
    worker_id: str | None
    claim_expires_at: datetime | None
    run_manifest_sha256: str | None
    report_sha256: str | None
    report_artifact_sha256: str | None
    terminal_reason_code: str | None
    terminal_reason_sha256: str | None
    _construction_proof: InitVar[object]
    event_sha256: str = field(init=False)

    def __post_init__(self, _construction_proof: object) -> None:
        if _construction_proof is not _FACTORY_PROOF:
            raise BacktestJobError("job events must be constructed by lifecycle factories")
        _require_sha256(self.job_id, "job ID")
        if type(self.sequence) is not int or self.sequence < 0:
            raise BacktestJobError("job event sequence must be non-negative")
        if type(self.status) is not BacktestJobStatus:
            raise BacktestJobError("job event status must be exact")
        _require_utc(self.occurred_at, "job event occurred_at")
        _require_text(self.actor_id, "job event actor ID")
        if type(self.attempt_number) is not int or self.attempt_number < 0:
            raise BacktestJobError("attempt number must be a non-negative integer")
        _require_optional_sha256(self.previous_event_sha256, "previous event digest")
        _require_optional_sha256(self.run_manifest_sha256, "run manifest digest")
        _require_optional_sha256(self.report_sha256, "report digest")
        _require_optional_sha256(self.report_artifact_sha256, "report artifact digest")
        _require_optional_sha256(self.terminal_reason_sha256, "terminal reason digest")
        self._validate_evidence_shape()
        object.__setattr__(self, "event_sha256", _sha256(self._semantic_material()))

    def _validate_evidence_shape(self) -> None:
        if self.sequence == 0:
            if self.previous_event_sha256 is not None:
                raise BacktestJobError("initial job event cannot have a predecessor")
        elif self.previous_event_sha256 is None:
            raise BacktestJobError("non-initial job event requires its predecessor digest")

        result_values = (
            self.run_manifest_sha256,
            self.report_sha256,
            self.report_artifact_sha256,
        )
        if self.status is BacktestJobStatus.QUEUED:
            if self.sequence != 0 or self.attempt_number != 0:
                raise BacktestJobError("queued must be the initial attempt-zero event")
            if self.worker_id is not None or self.claim_expires_at is not None:
                raise BacktestJobError("queued event cannot retain a worker claim")
            if any(value is not None for value in result_values):
                raise BacktestJobError("queued event cannot claim a result")
            if self.terminal_reason_code is not None or self.terminal_reason_sha256 is not None:
                raise BacktestJobError("queued event cannot claim a terminal reason")
            return

        if self.status is BacktestJobStatus.RUNNING:
            if self.attempt_number <= 0:
                raise BacktestJobError("running event requires a positive attempt number")
            if self.worker_id is None or self.claim_expires_at is None:
                raise BacktestJobError("running event requires a bounded worker claim")
            _require_text(self.worker_id, "worker ID")
            _require_utc(self.claim_expires_at, "claim_expires_at")
            if self.claim_expires_at <= self.occurred_at:
                raise BacktestJobError("worker claim must expire after its event")
            if any(value is not None for value in result_values):
                raise BacktestJobError("running event cannot claim a result")
            if self.terminal_reason_code is not None or self.terminal_reason_sha256 is not None:
                raise BacktestJobError("running event cannot claim a terminal reason")
            return

        if self.worker_id is not None or self.claim_expires_at is not None:
            raise BacktestJobError("terminal event cannot retain a worker claim")
        if self.attempt_number <= 0:
            raise BacktestJobError("terminal event requires a positive attempt number")
        if self.status is BacktestJobStatus.COMPLETED:
            if any(value is None for value in result_values):
                raise BacktestJobError("completed event requires report and manifest evidence")
            if self.terminal_reason_code is not None or self.terminal_reason_sha256 is not None:
                raise BacktestJobError("completed event cannot claim a terminal reason")
            return
        if any(value is not None for value in result_values):
            raise BacktestJobError("failed or canceled event cannot claim result evidence")
        if self.terminal_reason_code is None or self.terminal_reason_sha256 is None:
            raise BacktestJobError("failed or canceled event requires a bounded reason")
        _require_text(self.terminal_reason_code, "terminal reason code", maximum=64)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            BACKTEST_JOB_CONTRACT_VERSION,
            "event",
            self.job_id,
            self.sequence,
            self.status.value,
            self.occurred_at,
            self.actor_id,
            self.attempt_number,
            self.previous_event_sha256,
            self.worker_id,
            self.claim_expires_at,
            self.run_manifest_sha256,
            self.report_sha256,
            self.report_artifact_sha256,
            self.terminal_reason_code,
            self.terminal_reason_sha256,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class BacktestJobProjection:
    """Proof-constructed current state derived from the complete event chain."""

    job_id: str
    events: tuple[BacktestJobEvent, ...]
    _construction_proof: InitVar[object]
    projection_sha256: str = field(init=False)

    def __post_init__(self, _construction_proof: object) -> None:
        if _construction_proof is not _FACTORY_PROOF:
            raise BacktestJobError("job projections must be constructed by the reducer")
        _require_sha256(self.job_id, "job ID")
        if type(self.events) is not tuple or not self.events:
            raise BacktestJobError("job projection requires an immutable non-empty event chain")
        if len(self.events) > MAX_JOB_EVENTS:
            raise BacktestJobError("job event chain exceeds its bounded size")
        object.__setattr__(
            self,
            "projection_sha256",
            _sha256(
                (
                    BACKTEST_JOB_CONTRACT_VERSION,
                    "projection",
                    self.job_id,
                    tuple(event.event_sha256 for event in self.events),
                )
            ),
        )

    @property
    def latest(self) -> BacktestJobEvent:
        return self.events[-1]

    @property
    def status(self) -> BacktestJobStatus:
        return self.latest.status

    @property
    def terminal(self) -> bool:
        return self.status in {
            BacktestJobStatus.COMPLETED,
            BacktestJobStatus.FAILED,
            BacktestJobStatus.CANCELED,
        }


def _event(
    *,
    job_id: str,
    sequence: int,
    status: BacktestJobStatus,
    occurred_at: datetime,
    actor_id: str,
    attempt_number: int,
    previous_event_sha256: str | None,
    worker_id: str | None = None,
    claim_expires_at: datetime | None = None,
    run_manifest_sha256: str | None = None,
    report_sha256: str | None = None,
    report_artifact_sha256: str | None = None,
    terminal_reason_code: str | None = None,
    terminal_reason_sha256: str | None = None,
) -> BacktestJobEvent:
    return BacktestJobEvent(
        job_id=job_id,
        sequence=sequence,
        status=status,
        occurred_at=occurred_at,
        actor_id=actor_id,
        attempt_number=attempt_number,
        previous_event_sha256=previous_event_sha256,
        worker_id=worker_id,
        claim_expires_at=claim_expires_at,
        run_manifest_sha256=run_manifest_sha256,
        report_sha256=report_sha256,
        report_artifact_sha256=report_artifact_sha256,
        terminal_reason_code=terminal_reason_code,
        terminal_reason_sha256=terminal_reason_sha256,
        _construction_proof=_FACTORY_PROOF,
    )


def queue_backtest_job(job: BacktestJob) -> BacktestJobProjection:
    """Create the only legal initial event for an immutable launch request."""

    if type(job) is not BacktestJob:
        raise BacktestJobError("queue requires an exact BacktestJob")
    queued = _event(
        job_id=job.job_id,
        sequence=0,
        status=BacktestJobStatus.QUEUED,
        occurred_at=job.requested_at,
        actor_id=job.requested_by,
        attempt_number=0,
        previous_event_sha256=None,
    )
    return reduce_backtest_job_events(job.job_id, (queued,))


def reduce_backtest_job_events(
    job_id: str,
    events: tuple[BacktestJobEvent, ...],
) -> BacktestJobProjection:
    """Validate and reduce a complete append-only event stream."""

    _require_sha256(job_id, "job ID")
    if type(events) is not tuple or not events:
        raise BacktestJobError("job reducer requires a non-empty immutable event tuple")
    if len(events) > MAX_JOB_EVENTS:
        raise BacktestJobError("job event chain exceeds its bounded size")
    previous: BacktestJobEvent | None = None
    for sequence, event in enumerate(events):
        if type(event) is not BacktestJobEvent:
            raise BacktestJobError("job event chain contains an unsupported value")
        if event.job_id != job_id or event.sequence != sequence:
            raise BacktestJobConflict("job events must have one identity and contiguous sequence")
        if previous is None:
            if event.status is not BacktestJobStatus.QUEUED:
                raise BacktestJobConflict("job event chain must begin queued")
        else:
            if event.previous_event_sha256 != previous.event_sha256:
                raise BacktestJobConflict("job event predecessor digest is invalid")
            if event.occurred_at < previous.occurred_at:
                raise BacktestJobConflict("job event time cannot regress")
            _validate_transition(previous, event)
        previous = event
    return BacktestJobProjection(
        job_id=job_id,
        events=events,
        _construction_proof=_FACTORY_PROOF,
    )


def _validate_transition(previous: BacktestJobEvent, current: BacktestJobEvent) -> None:
    if previous.status in {
        BacktestJobStatus.COMPLETED,
        BacktestJobStatus.FAILED,
        BacktestJobStatus.CANCELED,
    }:
        raise BacktestJobConflict("terminal job state cannot transition")
    if previous.status is BacktestJobStatus.QUEUED:
        if current.status not in {BacktestJobStatus.RUNNING, BacktestJobStatus.CANCELED}:
            raise BacktestJobConflict("queued job may only be claimed or canceled")
        if current.status is BacktestJobStatus.RUNNING and current.attempt_number != 1:
            raise BacktestJobConflict("first worker claim must be attempt one")
        if current.status is BacktestJobStatus.CANCELED and current.attempt_number != 1:
            raise BacktestJobConflict("queued cancellation must close attempt one")
        return

    if current.status is BacktestJobStatus.RUNNING:
        if previous.claim_expires_at is None or previous.worker_id is None:
            raise BacktestJobConflict("running predecessor is missing its claim")
        if (
            current.worker_id == previous.worker_id
            and current.occurred_at <= previous.claim_expires_at
        ):
            if current.attempt_number != previous.attempt_number:
                raise BacktestJobConflict("claim renewal cannot change attempt number")
        else:
            if current.occurred_at <= previous.claim_expires_at:
                raise BacktestJobNotClaimable("active worker claim cannot be stolen")
            if current.attempt_number != previous.attempt_number + 1:
                raise BacktestJobConflict("recovered claim must increment attempt number")
        return
    if current.status not in {
        BacktestJobStatus.COMPLETED,
        BacktestJobStatus.FAILED,
        BacktestJobStatus.CANCELED,
    }:
        raise BacktestJobConflict("running job may only renew, complete, fail, or cancel")
    if current.attempt_number != previous.attempt_number:
        raise BacktestJobConflict("terminal event must close the active attempt")
    if current.actor_id != previous.worker_id:
        raise BacktestJobConflict("only the active worker may publish a terminal result")
    if previous.claim_expires_at is None or current.occurred_at > previous.claim_expires_at:
        raise BacktestJobNotClaimable("expired worker claim cannot publish a result")


def claim_backtest_job(
    projection: BacktestJobProjection,
    *,
    worker_id: str,
    claimed_at: datetime,
    claim_expires_at: datetime,
) -> BacktestJobProjection:
    """Acquire, renew, or recover a bounded worker claim."""

    _require_projection(projection)
    _require_text(worker_id, "worker ID")
    latest = projection.latest
    if projection.terminal:
        raise BacktestJobNotClaimable("terminal job cannot be claimed")
    if latest.status is BacktestJobStatus.QUEUED:
        attempt_number = 1
    elif latest.worker_id == worker_id and (
        latest.claim_expires_at is not None and claimed_at <= latest.claim_expires_at
    ):
        attempt_number = latest.attempt_number
    else:
        attempt_number = latest.attempt_number + 1
    event = _event(
        job_id=projection.job_id,
        sequence=len(projection.events),
        status=BacktestJobStatus.RUNNING,
        occurred_at=claimed_at,
        actor_id=worker_id,
        attempt_number=attempt_number,
        previous_event_sha256=latest.event_sha256,
        worker_id=worker_id,
        claim_expires_at=claim_expires_at,
    )
    return reduce_backtest_job_events(projection.job_id, (*projection.events, event))


def complete_backtest_job(
    projection: BacktestJobProjection,
    *,
    worker_id: str,
    completed_at: datetime,
    run_manifest_sha256: str,
    report_sha256: str,
    report_artifact_sha256: str,
) -> BacktestJobProjection:
    """Publish immutable success evidence under the active worker claim."""

    return _terminal_transition(
        projection,
        worker_id=worker_id,
        occurred_at=completed_at,
        status=BacktestJobStatus.COMPLETED,
        run_manifest_sha256=run_manifest_sha256,
        report_sha256=report_sha256,
        report_artifact_sha256=report_artifact_sha256,
    )


def fail_backtest_job(
    projection: BacktestJobProjection,
    *,
    worker_id: str,
    failed_at: datetime,
    terminal_reason_code: str,
    terminal_reason_sha256: str,
) -> BacktestJobProjection:
    """Publish a bounded failure code without leaking raw exception text."""

    return _terminal_transition(
        projection,
        worker_id=worker_id,
        occurred_at=failed_at,
        status=BacktestJobStatus.FAILED,
        terminal_reason_code=terminal_reason_code,
        terminal_reason_sha256=terminal_reason_sha256,
    )


def cancel_running_backtest_job(
    projection: BacktestJobProjection,
    *,
    worker_id: str,
    canceled_at: datetime,
    terminal_reason_sha256: str,
) -> BacktestJobProjection:
    """Let the active worker acknowledge a durable cancellation request."""

    return _terminal_transition(
        projection,
        worker_id=worker_id,
        occurred_at=canceled_at,
        status=BacktestJobStatus.CANCELED,
        terminal_reason_code="operator_cancel",
        terminal_reason_sha256=terminal_reason_sha256,
    )


def _terminal_transition(
    projection: BacktestJobProjection,
    *,
    worker_id: str,
    occurred_at: datetime,
    status: BacktestJobStatus,
    run_manifest_sha256: str | None = None,
    report_sha256: str | None = None,
    report_artifact_sha256: str | None = None,
    terminal_reason_code: str | None = None,
    terminal_reason_sha256: str | None = None,
) -> BacktestJobProjection:
    _require_projection(projection)
    _require_text(worker_id, "worker ID")
    latest = projection.latest
    if latest.status is not BacktestJobStatus.RUNNING or latest.worker_id != worker_id:
        raise BacktestJobNotClaimable("only the active worker may close a running job")
    event = _event(
        job_id=projection.job_id,
        sequence=len(projection.events),
        status=status,
        occurred_at=occurred_at,
        actor_id=worker_id,
        attempt_number=latest.attempt_number,
        previous_event_sha256=latest.event_sha256,
        run_manifest_sha256=run_manifest_sha256,
        report_sha256=report_sha256,
        report_artifact_sha256=report_artifact_sha256,
        terminal_reason_code=terminal_reason_code,
        terminal_reason_sha256=terminal_reason_sha256,
    )
    return reduce_backtest_job_events(projection.job_id, (*projection.events, event))


def cancel_queued_backtest_job(
    projection: BacktestJobProjection,
    *,
    operator_id: str,
    canceled_at: datetime,
    terminal_reason_sha256: str,
) -> BacktestJobProjection:
    """Cancel a job before a worker has claimed it."""

    _require_projection(projection)
    _require_text(operator_id, "operator ID")
    if projection.status is not BacktestJobStatus.QUEUED:
        raise BacktestJobConflict("only a queued job can be canceled by the launcher")
    latest = projection.latest
    event = _event(
        job_id=projection.job_id,
        sequence=1,
        status=BacktestJobStatus.CANCELED,
        occurred_at=canceled_at,
        actor_id=operator_id,
        attempt_number=1,
        previous_event_sha256=latest.event_sha256,
        terminal_reason_code="operator_cancel",
        terminal_reason_sha256=terminal_reason_sha256,
    )
    # Queued cancellation is the sole terminal transition not owned by a worker.
    return reduce_backtest_job_events(projection.job_id, (*projection.events, event))


def _require_projection(projection: BacktestJobProjection) -> None:
    if type(projection) is not BacktestJobProjection:
        raise BacktestJobError("operation requires an exact BacktestJobProjection")
    reduce_backtest_job_events(projection.job_id, projection.events)


def create_backtest_job(
    *,
    input: BacktestJobInput,
    requested_by: str,
    idempotency_key: str,
    requested_at: datetime,
) -> tuple[BacktestJob, BacktestJobProjection]:
    """Construct an immutable launch and its initial queued projection."""

    job = BacktestJob(
        input=input,
        requested_by=requested_by,
        idempotency_key=idempotency_key,
        requested_at=requested_at,
    )
    return job, queue_backtest_job(job)


__all__ = [
    "BACKTEST_JOB_CONTRACT_VERSION",
    "BacktestJob",
    "BacktestJobConflict",
    "BacktestJobError",
    "BacktestJobEvent",
    "BacktestJobInput",
    "BacktestJobNotClaimable",
    "BacktestJobProjection",
    "BacktestJobStatus",
    "cancel_queued_backtest_job",
    "cancel_running_backtest_job",
    "claim_backtest_job",
    "complete_backtest_job",
    "create_backtest_job",
    "fail_backtest_job",
    "queue_backtest_job",
    "reduce_backtest_job_events",
]
