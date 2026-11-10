"""Unwired measured-clock values; neither ownership nor runtime admission.

Semantic identities use the domain canonical encoding. These records make no
claim about storage-codec compatibility, actual retention, or qualified host time.
"""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from typing import ClassVar, Literal

from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    JournalHead,
    JournalKey,
    JournalReceipt,
)
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.research_job_contracts import ObjectRef, require_identifier
from packages.domain.runtime_operating_contracts import CLOCK_POLICY
from packages.domain.trusted_time import TRUSTED_TIME_POLICY

MEASURED_CLOCK_SOURCE_SCHEMA = "measured-clock-source-association/1"
MEASURED_CLOCK_SCHEMA = "runtime-measured-clock-observation/1"
MEASURED_CLOCK_REFERENCE_SCHEMA = "runtime-measured-clock-reference/1"
MEASURED_CLOCK_PROFILE = "personal_chrony_measured/1"
MEASURED_CLOCK_BRIDGE_VERSION = "personal-chrony-standard-clock/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class MeasuredClockSourceAssociation(ContractRecord):
    """Pure reading/conversion association; a matching digest proves no source."""

    contract_version: ClassVar[str] = MEASURED_CLOCK_SOURCE_SCHEMA
    source_id: str
    source_authority_sha256: str
    authority_semantic_sha256: str
    bridge_version: Literal["personal-chrony-standard-clock/1"]
    measurement_source_id: str
    local_observed_at_utc: datetime
    trusted_at_utc: datetime
    observed_at_monotonic_ns: int
    source_uncertainty_milliseconds: Decimal
    source_evidence_sha256: str

    def __post_init__(self) -> None:
        super(MeasuredClockSourceAssociation, self).__post_init__()
        require_identifier(self.source_id, "measured clock source")
        require_identifier(self.measurement_source_id, "measured clock conversion source")
        for value in (
            self.source_authority_sha256,
            self.authority_semantic_sha256,
            self.source_evidence_sha256,
        ):
            require_digest(value, "measured clock source digest")
        if self.observed_at_monotonic_ns < 0:
            raise ValueError("measured clock source monotonic value cannot be negative")
        require_amount(
            self.source_uncertainty_milliseconds,
            "measured clock source uncertainty",
            nonnegative=True,
        )
        if (
            self.source_uncertainty_milliseconds
            > TRUSTED_TIME_POLICY.maximum_source_uncertainty_milliseconds
        ):
            raise ValueError("measured clock source uncertainty exceeds original limit")
        identity = sha256(
            canonical_json_bytes(
                (
                    self.bridge_version,
                    (
                        self.source_id,
                        self.source_authority_sha256,
                        self.authority_semantic_sha256,
                    ),
                )
            )
        ).hexdigest()
        if self.measurement_source_id != f"chrony-standard:{identity}":
            raise ValueError("measured clock conversion source identity differs")

    @property
    def offset_ns(self) -> int:
        delta = self.trusted_at_utc - self.local_observed_at_utc
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000

    @property
    def uncertainty_ns(self) -> int:
        numerator, denominator = self.source_uncertainty_milliseconds.as_integer_ratio()
        return -(-(numerator * 1_000_000) // denominator)


@dataclass(frozen=True, slots=True, kw_only=True)
class MeasuredRuntimeClockObservation(ContractRecord):
    """Actual scalar shape with optional audit association, never a healthy permit."""

    contract_version: ClassVar[str] = MEASURED_CLOCK_SCHEMA
    scope: ContinuousAccountScope
    profile: Literal["personal_chrony_measured/1"]
    policy: VersionPin
    status: Literal["healthy", "warning", "blocked"]
    reasons: tuple[str, ...]
    evidence_class: Literal["unavailable", "host-measurement"]
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
    source: MeasuredClockSourceAssociation | None

    def __post_init__(self) -> None:
        if type(self.reasons) is not tuple or len(self.reasons) > 64:
            raise ValueError("measured clock reasons exceed original history bound")
        super(MeasuredRuntimeClockObservation, self).__post_init__()
        ContinuousAccountScope.__post_init__(self.scope)
        VersionPin.__post_init__(self.policy)
        if self.source is not None:
            MeasuredClockSourceAssociation.__post_init__(self.source)
        if self.policy != CLOCK_POLICY or not 1 <= self.sequence < 2**63:
            raise ValueError("measured clock policy or original sequence differs")
        if self.epoch is not None and not 0 < len(self.epoch) <= 128:
            raise ValueError("measured clock epoch is outside original bound")
        for reason in self.reasons:
            require_text(reason, "measured clock reason")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("measured clock reasons must be sorted and unique")
        for value in (
            self.observed_monotonic_ns,
            self.source_observed_monotonic_ns,
            self.uncertainty_ns,
        ):
            if value is not None and value < 0:
                raise ValueError("measured clock magnitude cannot be negative")
        if self.evidence_class == "unavailable":
            if (
                self.status != "blocked"
                or self.recovery_ready is not False
                or any(
                    value is not None
                    for value in (
                        self.source_id,
                        self.source_observed_at_utc,
                        self.source_observed_monotonic_ns,
                        self.offset_ns,
                        self.uncertainty_ns,
                    )
                )
            ):
                raise ValueError("unavailable measured clock cannot promote source health")
        elif self.source is None or (
            self.source_id != self.source.measurement_source_id
            or self.source_observed_at_utc != self.source.local_observed_at_utc
            or self.source_observed_monotonic_ns != self.source.observed_at_monotonic_ns
            or self.offset_ns != self.source.offset_ns
            or self.uncertainty_ns != self.source.uncertainty_ns
        ):
            raise ValueError("measured clock observation differs from source conversion")


@dataclass(frozen=True, slots=True, kw_only=True)
class MeasuredRuntimeClockReference(ContractRecord):
    """A bounded claimed reference; no payload read or publication authentication."""

    contract_version: ClassVar[str] = MEASURED_CLOCK_REFERENCE_SCHEMA
    key: JournalKey
    receipt: JournalReceipt
    record: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(MeasuredRuntimeClockReference, self).__post_init__()
        if (
            type(self.receipt.record_ids) is not tuple
            or type(self.receipt.record_hashes) is not tuple
            or len(self.receipt.record_ids) != 1
            or len(self.receipt.record_hashes) != 1
        ):
            raise ValueError("measured clock reference requires one exact journal record")
        JournalKey.__post_init__(self.key)
        ContractRecord.__post_init__(self.receipt)
        JournalHead.__post_init__(self.receipt.previous_head)
        JournalHead.__post_init__(self.receipt.committed_head)
        JournalReceipt.__post_init__(self.receipt)
        ContractRecord.__post_init__(self.record)
        ObjectRef.__post_init__(self.record.object_ref)
        ContinuousEvidenceRef.__post_init__(self.record)
        if self.record.object_ref.byte_count > MAX_RECORD_BYTES:
            raise ValueError("measured clock claimed object exceeds original journal bound")
        if (
            self.record.schema_id != MEASURED_CLOCK_SCHEMA
            or self.receipt.previous_head.key_sha256 != self.key.semantic_sha256
            or self.receipt.committed_head.key_sha256 != self.key.semantic_sha256
            or self.receipt.record_ids != (self.record.semantic_sha256,)
            or self.receipt.record_hashes != (self.record.object_ref.object_sha256,)
        ):
            raise ValueError("measured clock reference differs from exact journal metadata")
