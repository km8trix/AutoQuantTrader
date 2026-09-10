"""Minimal versioned durable orchestration values; no execution authority."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal, Protocol, TypeVar

from packages.domain.engine_contracts import EngineInputs, RunSpec
from packages.domain.personal_contracts import ContractRecord, content_digest, require_digest
from packages.domain.report_contracts import ReportArtifact, ReportConventions
from packages.domain.research_dataset import ResearchDataClass

MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_EXECUTION_METADATA_BYTES = 8 * 1024 * 1024
MAX_PUBLICATION_BYTES = 16 * 1024
LEASE_SECONDS = 60
HEARTBEAT_SECONDS = 10
MAX_ATTEMPTS = 3
MAX_JOB_EVENTS = 4096
type ObjectCodec = Literal["personal-record/1", "personal-research-dataset-v1"]

type JobStatus = Literal["queued", "running", "completed", "incomplete", "failed", "cancelled"]
type AttemptOutcome = Literal[
    "running", "completed", "incomplete", "failed", "cancelled", "abandoned"
]
type TerminalOutcome = Literal["completed", "incomplete", "failed", "cancelled", "abandoned"]
type EventKind = Literal[
    "queued",
    "claimed",
    "renewed",
    "cancel_requested",
    "abandoned",
    "completed",
    "incomplete",
    "failed",
    "cancelled",
]


def require_identifier(value: str, name: str) -> None:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise ValueError(f"invalid bounded {name}")


class ResearchRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-research-job/2"


@dataclass(frozen=True, slots=True)
class ObjectRef(ResearchRecord):
    object_sha256: str
    byte_count: int
    codec_version: ObjectCodec = "personal-record/1"

    def __post_init__(self) -> None:
        super(ObjectRef, self).__post_init__()
        require_digest(self.object_sha256, "object digest")
        if not 0 < self.byte_count <= MAX_OBJECT_BYTES:
            raise ValueError("object exceeds the bounded storage contract")

    @property
    def media_type(self) -> str:
        return "application/json"


@dataclass(frozen=True, slots=True)
class ResearchRunRequest(ResearchRecord):
    spec: RunSpec
    conventions: ReportConventions
    inputs: ObjectRef
    owner_id: str
    idempotency_key: str
    trial_id: str
    dataset_archive: ObjectRef | None = None
    settlement_calendar: ObjectRef | None = None

    def __post_init__(self) -> None:
        super(ResearchRunRequest, self).__post_init__()
        for name in ("owner_id", "idempotency_key", "trial_id"):
            require_identifier(getattr(self, name), name)
        if len(self.idempotency_key) < 8:
            raise ValueError("idempotency key must contain at least eight characters")
        if any(
            ref is not None and ref.byte_count > MAX_INPUT_BYTES
            for ref in (self.inputs, self.dataset_archive, self.settlement_calendar)
        ):
            raise ValueError("research input exceeds the 32 MiB admission cap")
        if self.spec.max_output_bytes > MAX_OBJECT_BYTES:
            raise ValueError("W3 RunSpec output exceeds the 64 MiB cap")
        mib = 1024 * 1024
        if (
            self.spec.max_cpu_cores != 1
            or self.spec.max_memory_bytes < 128 * mib
            or self.spec.max_memory_bytes % mib
            or self.spec.max_output_bytes < mib
            or self.spec.max_output_bytes % mib
        ):
            raise ValueError("durable process limits require one core and exact MiB budgets")
        if self.inputs.codec_version != "personal-record/1" or (
            self.settlement_calendar is not None
            and self.settlement_calendar.codec_version != "personal-record/1"
        ):
            raise ValueError("engine inputs and calendar require the typed record codec")
        if (
            self.dataset_archive is not None
            and self.dataset_archive.codec_version != "personal-research-dataset-v1"
        ):
            raise ValueError("dataset archive requires its W1 archive codec")
        pins = {pin.name: pin for pin in self.spec.pins}
        convention_pin = pins.get("report_conventions")
        if (
            convention_pin is not None and convention_pin.sha256 != self.conventions.semantic_sha256
        ) or (
            convention_pin is None
            and (
                self.conventions != ReportConventions()
                or pins["report"].version != self.conventions.version
            )
        ):
            raise ValueError("report conventions differ from the accepted RunSpec")
        if self.spec.data_class is ResearchDataClass.VALIDATED_CURRENT_VINTAGE and (
            self.dataset_archive is None or self.settlement_calendar is None
        ):
            raise ValueError("real archive jobs require retained archive and calendar references")
        if self.spec.risk_policy.policy_scope != "product":
            raise ValueError("durable research jobs require the product simulation policy")

    @property
    def job_id(self) -> str:
        return content_digest((self.contract_version, "job", self.owner_id, self.idempotency_key))

    @property
    def run_id(self) -> str:
        return self.spec.run_id


@dataclass(frozen=True, slots=True)
class ResearchClaim(ResearchRecord):
    job_id: str
    attempt_id: str
    fence: int
    lease_revision: int
    worker_id: str
    worker_instance_id: str
    started_at: datetime
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        super(ResearchClaim, self).__post_init__()
        for name in ("job_id", "attempt_id"):
            require_digest(getattr(self, name), name)
        for name in ("worker_id", "worker_instance_id"):
            require_identifier(getattr(self, name), name)
        if not 1 <= self.fence <= MAX_ATTEMPTS or self.lease_revision < 0:
            raise ValueError("claim fence or revision is out of bounds")
        if self.lease_expires_at <= self.started_at:
            raise ValueError("claim expiry must follow its attempt start")
        if self.attempt_id != content_digest(
            (self.contract_version, "attempt", self.job_id, self.fence, self.worker_instance_id)
        ):
            raise ValueError("claim attempt identity differs from its fence")


@dataclass(frozen=True, slots=True)
class ResearchProgress(ResearchRecord):
    stage: Literal["loading", "running", "validating", "publishing", "stopping"] = "loading"
    processed_events: int | None = None
    frontier_sequence: int | None = None
    frontier_at: datetime | None = None

    def __post_init__(self) -> None:
        super(ResearchProgress, self).__post_init__()
        if any(
            value is not None and not 0 <= value <= 1000000
            for value in (self.processed_events, self.frontier_sequence)
        ):
            raise ValueError("progress counter is outside its observation bounds")


@dataclass(frozen=True, slots=True)
class ResearchPublication(ResearchRecord):
    job_id: str
    run_id: str
    attempt_id: str
    outcome: Literal["completed", "incomplete"]
    result_sha256: str
    report_sha256: str
    artifact_sha256: str
    object: ObjectRef

    def __post_init__(self) -> None:
        super(ResearchPublication, self).__post_init__()
        for name in (
            "job_id",
            "attempt_id",
            "result_sha256",
            "report_sha256",
            "artifact_sha256",
        ):
            require_digest(getattr(self, name), name)
        if not self.run_id.startswith("run-"):
            raise ValueError("publication requires a W2 run identity")
        require_digest(self.run_id[4:], "publication run digest")
        if self.object.codec_version != "personal-record/1":
            raise ValueError("report publication requires the typed record codec")


@dataclass(frozen=True, slots=True)
class ResearchJobEvent(ResearchRecord):
    job_id: str
    sequence: int
    previous_event_sha256: str | None
    kind: EventKind
    occurred_at: datetime
    actor_id: str
    claim: ResearchClaim | None = None
    publication: ResearchPublication | None = None
    reason_code: str | None = None
    command_id: str | None = None
    progress: ResearchProgress | None = None

    def __post_init__(self) -> None:
        super(ResearchJobEvent, self).__post_init__()
        require_digest(self.job_id, "event job")
        require_identifier(self.actor_id, "event actor")
        if not 0 <= self.sequence < MAX_JOB_EVENTS:
            raise ValueError("event sequence exceeds its bound")
        for value in (self.previous_event_sha256, self.command_id):
            if value is not None:
                require_digest(value, "event evidence")
        if self.reason_code is not None:
            require_identifier(self.reason_code, "reason code")
        if self.claim is not None and self.claim.job_id != self.job_id:
            raise ValueError("event claim belongs to another job")
        if self.publication is not None and self.publication.job_id != self.job_id:
            raise ValueError("event publication belongs to another job")


@dataclass(frozen=True, slots=True)
class ResearchAttempt(ResearchRecord):
    attempt_id: str
    attempt_number: int
    started_at: datetime
    ended_at: datetime | None
    outcome: AttemptOutcome
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class ResearchJobView(ResearchRecord):
    job_id: str
    run_id: str
    owner_id: str
    trial_id: str
    status: JobStatus
    requested_at: datetime
    updated_at: datetime
    cancel_requested: bool
    attempts: tuple[ResearchAttempt, ...]
    last_event_sha256: str
    reason_code: str | None = None
    publication: ResearchPublication | None = None
    progress: ResearchProgress | None = None


@dataclass(frozen=True, slots=True)
class ClaimedResearchJob(ResearchRecord):
    request: ResearchRunRequest
    claim: ResearchClaim


@dataclass(frozen=True, slots=True)
class ClaimControl(ResearchRecord):
    claim: ResearchClaim
    database_now: datetime
    cancel_requested: bool


@dataclass(frozen=True, slots=True)
class RunControl(ResearchRecord):
    stop: bool = False
    reason_code: Literal["cancel_requested", "lease_lost", "shutdown", "resource_limit"] | None = (
        None
    )

    def __post_init__(self) -> None:
        super(RunControl, self).__post_init__()
        if self.stop != (self.reason_code is not None):
            raise ValueError("stop control requires an explicit reason")


@dataclass(frozen=True, slots=True)
class ResearchExecutionRequest(ResearchRecord):
    request: ResearchRunRequest
    claim: ResearchClaim
    inputs: EngineInputs


@dataclass(frozen=True, slots=True)
class RetainedResearchExecutionRequest(ResearchRecord):
    """Metadata for a child that resolves the immutable retained input references."""

    request: ResearchRunRequest
    claim: ResearchClaim

    def __post_init__(self) -> None:
        super(RetainedResearchExecutionRequest, self).__post_init__()
        if self.claim.job_id != self.request.job_id:
            raise ValueError("execution claim differs from the accepted request")


@dataclass(frozen=True, slots=True)
class ResearchExecutionOutcome(ResearchRecord):
    outcome: TerminalOutcome
    artifact: ReportArtifact | None = None
    reason_code: str | None = None
    publication: ResearchPublication | None = None

    def __post_init__(self) -> None:
        super(ResearchExecutionOutcome, self).__post_init__()
        if self.reason_code is not None:
            require_identifier(self.reason_code, "execution reason")
        if self.outcome in ("completed", "incomplete"):
            if (
                (self.artifact is None) == (self.publication is None)
                or (self.artifact is not None and self.artifact.report.status != self.outcome)
                or (self.publication is not None and self.publication.outcome != self.outcome)
                or self.reason_code is not None
            ):
                raise ValueError("published outcome must match the actual report status")
        elif self.artifact is not None or self.publication is not None or self.reason_code is None:
            raise ValueError("nonpublication outcome requires only a bounded reason")


T = TypeVar("T")


class ResearchRecordCodec(Protocol):
    def encode_record(self, value: object) -> bytes: ...
    def decode_record(self, payload: bytes, expected_type: type[T]) -> T: ...


class ResearchWorkflowPort(Protocol):
    def launch(self, request: ResearchRunRequest) -> ResearchJobView: ...
    def get(self, job_id: str) -> ResearchJobView: ...
    def get_request(self, job_id: str) -> ResearchRunRequest: ...
    def jobs(self, *, owner_id: str, limit: int = 100) -> tuple[ResearchJobView, ...]: ...
    def request_cancel(
        self, job_id: str, *, owner_id: str, idempotency_key: str
    ) -> ResearchJobView: ...
    def claim_next(
        self, *, worker_id: str, worker_instance_id: str
    ) -> ClaimedResearchJob | None: ...
    def heartbeat(self, claim: ResearchClaim, *, progress: ResearchProgress) -> ClaimControl: ...
    def publish(
        self, claim: ResearchClaim, *, publication: ResearchPublication
    ) -> ResearchJobView: ...
    def finish(
        self,
        claim: ResearchClaim,
        *,
        outcome: Literal["failed", "cancelled", "abandoned"],
        reason_code: str,
    ) -> ResearchJobView: ...


class ResearchInputResolver(Protocol):
    def resolve(self, request: ResearchRunRequest) -> EngineInputs: ...


class ResearchRunnerPort(Protocol):
    def run(
        self,
        execution: ResearchExecutionRequest,
        *,
        control: Callable[[ResearchProgress], RunControl],
    ) -> ResearchExecutionOutcome: ...


class RetainedResearchRunnerPort(Protocol):
    def run_retained(
        self,
        execution: RetainedResearchExecutionRequest,
        *,
        control: Callable[[ResearchProgress], RunControl],
    ) -> ResearchExecutionOutcome: ...


class ResearchArtifactStore(Protocol):
    def put(
        self,
        payload: bytes,
        *,
        codec_version: ObjectCodec = "personal-record/1",
        max_bytes: int = MAX_OBJECT_BYTES,
    ) -> ObjectRef: ...
    def read(self, reference: ObjectRef, *, max_bytes: int = MAX_OBJECT_BYTES) -> bytes: ...
