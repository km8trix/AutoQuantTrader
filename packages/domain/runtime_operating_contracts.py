"""Original operating observations for a local stateful venue; no authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import JournalKey, JournalReceipt
from packages.domain.personal_contracts import ContractRecord, VersionPin, content_digest

CLOCK_SCHEMA = "runtime-clock-observation/1"
OPERATING_PROFILE = VersionPin(
    "runtime_operating",
    "local-stateful-operating-evidence/1",
    content_digest(("original-clock-calendar-attempts/1", 20, 10, 60, 30)),
)
CLOCK_POLICY = VersionPin(
    "clock",
    "personal-v1-clock-1",
    content_digest((250_000_000, 1_000_000_000, 30_000_000_000, 1_000_000_000, 60_000_000_000)),
)
ClockProfile = Literal["host_unqualified", "explicit_simulation_time_model"]


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeClockObservation(ContractRecord):
    contract_version: ClassVar[str] = CLOCK_SCHEMA
    scope: ContinuousAccountScope
    profile: ClockProfile
    policy: VersionPin
    status: Literal["healthy", "warning", "blocked"]
    reasons: tuple[str, ...]
    evidence_class: Literal["unavailable", "host-measurement", "simulated"]
    source_id: str | None
    observed_at_utc: datetime | None
    observed_monotonic_ns: int | None
    source_observed_at_utc: datetime | None
    source_observed_monotonic_ns: int | None
    epoch: str | None
    sequence: int
    offset_ns: int | None
    uncertainty_ns: int | None
    sampling_duration_ns: int | None
    sample_age_ns: int | None
    recovery_ready: bool
    rearm_required: bool

    def __post_init__(self) -> None:
        super(RuntimeClockObservation, self).__post_init__()
        if self.policy != CLOCK_POLICY or not 1 <= self.sequence < 2**63:
            raise ValueError("clock policy or original sequence differs")
        if self.profile == "explicit_simulation_time_model" and self.evidence_class not in (
            "simulated",
            "unavailable",
        ):
            raise ValueError("simulation time cannot claim a host measurement")
        if self.profile == "host_unqualified" and self.evidence_class == "simulated":
            raise ValueError("host time cannot relabel a simulation model")
        for value in (
            self.observed_monotonic_ns,
            self.source_observed_monotonic_ns,
            self.uncertainty_ns,
        ):
            if value is not None and value < 0:
                raise ValueError("clock magnitude cannot be negative")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeClockReference(ContractRecord):
    key: JournalKey
    receipt: JournalReceipt
    record: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(RuntimeClockReference, self).__post_init__()
        if (
            self.record.schema_id != CLOCK_SCHEMA
            or self.receipt.committed_head.key_sha256 != self.key.semantic_sha256
            or self.receipt.record_ids != (self.record.semantic_sha256,)
        ):
            raise ValueError("clock reference differs from its exact journal record")


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeOperatingFact(ContractRecord):
    role: Literal["clock", "session", "request_budget"]
    scope: ContinuousAccountScope
    profile: VersionPin
    source_sha256: str
    source_at: datetime | None
    received_at: datetime | None
    valid_until: datetime | None
    revision: int
    references: tuple[ContinuousEvidenceRef, ...]
    clock_epoch: str | None
    clock_valid_until_monotonic_ns: int | None
    status: Literal["available", "blocked", "unavailable"]
    reasons: tuple[str, ...]
    clock_profile: ClockProfile
    calendar_class: Literal[
        "synthetic_fixture", "validated_current_vintage", "recorded_as_observed"
    ]
    budget_scope: Literal["local_stateful_venue_only"] = "local_stateful_venue_only"

    def __post_init__(self) -> None:
        super(RuntimeOperatingFact, self).__post_init__()
        if self.profile != OPERATING_PROFILE or (
            self.source_at is not None
            and self.received_at is not None
            and self.source_at > self.received_at
        ):
            raise ValueError("operating source policy or chronology differs")
        if (self.status == "available") == bool(self.reasons):
            raise ValueError("operating availability must preserve explicit reasons")
        if self.status == "available" and any(
            value is None for value in (self.source_at, self.received_at, self.valid_until)
        ):
            raise ValueError("available operating evidence requires original timestamps")
