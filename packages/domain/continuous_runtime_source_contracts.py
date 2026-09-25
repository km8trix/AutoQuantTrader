"""Precomputation source references, never a future risk or dispatch permission."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountReceipt,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.daily_attempt_contracts import DailyFenceReference
from packages.domain.daily_runtime_contracts import (
    RUNTIME_ROLES,
    RuntimeProducerMap,
    RuntimeProducerSpec,
    RuntimeRole,
)
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    content_digest,
    require_digest,
    require_utc,
)
from packages.domain.reconciliation_contracts import RECONCILIATION_VERSION, ReconciliationPolicy
from packages.domain.research_job_contracts import require_identifier
from packages.domain.runtime_operating_contracts import OPERATING_PROFILE
from packages.domain.stateful_venue_contracts import VenueModel

RUNTIME_SOURCE_SCHEMA = "continuous-runtime-source/1"
MAX_RUNTIME_SOURCE_BYTES = 256 * 1024
MAX_RUNTIME_SOURCE_REFERENCES = 64
RUNTIME_PROJECTION_PROFILE = VersionPin(
    "continuous_runtime_projection",
    "canonical-continuous-runtime-projection/1",
    content_digest(("owned-checkpoint-control-hold-prefix/1", "original-source-times/1")),
)
RUNTIME_RECONCILIATION_PROFILE = VersionPin(
    "reconciliation",
    RECONCILIATION_VERSION,
    ReconciliationPolicy().semantic_sha256,
)


def runtime_producer_map(
    *,
    account_id: str,
    venue_model: VenueModel,
    daily: RuntimeProducerSpec,
    quotes: RuntimeProducerSpec,
) -> RuntimeProducerMap:
    """Fixed local roles plus declared market pins requiring retained-source checks.

    Market declarations confer no availability: the concrete reader must match
    the actual capture/normalizer pin and provider scope before emitting a role.
    """
    if (
        daily.role != "daily_inputs"
        or quotes.role != "quotes"
        or any(item.account_scope != account_id for item in (daily, quotes))
    ):
        raise ValueError("market producer declarations differ from role/account")
    producers = []
    for role in RUNTIME_ROLES:
        if role in ("daily_inputs", "quotes"):
            producers.append(daily if role == "daily_inputs" else quotes)
            continue
        pin, provider = RUNTIME_PROJECTION_PROFILE, "continuous-account"
        if role in ("clock", "session", "request_budget"):
            pin, provider = OPERATING_PROFILE, "local-operating"
        elif role in ("cash", "reconciliation"):
            pin = venue_model.producer if role == "cash" else RUNTIME_RECONCILIATION_PROFILE
            provider = venue_model.venue_id
        producers.append(
            RuntimeProducerSpec(
                role=role,
                producer=pin,
                provider_id=provider,
                source_environment="stateful_simulation",
                account_scope=account_id,
            )
        )
    return RuntimeProducerMap(producers=tuple(producers))


@dataclass(frozen=True, slots=True)
class ContinuousRuntimeRoleReferences(ContractRecord):
    role: RuntimeRole
    references: tuple[ContinuousEvidenceRef, ...]

    def __post_init__(self) -> None:
        super(ContinuousRuntimeRoleReferences, self).__post_init__()
        if self.role not in RUNTIME_ROLES or not 1 <= len(self.references) <= 32:
            raise ValueError("runtime role requires bounded original evidence references")
        if len(set(self.references)) != len(self.references):
            raise ValueError("runtime role duplicates an original evidence reference")


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousRuntimeSourceDescriptor(ContractRecord):
    """Retained dependencies before sole-engine callback computation.

    The referenced request is inputs or an external source-only frontier. An
    activation descriptor references the already observed quote frontier, never
    a future RuntimeAction containing the activation decision. Genesis contains
    no future checkpoint. All references still require their concrete resolver.
    """

    contract_version: ClassVar[str] = RUNTIME_SOURCE_SCHEMA
    descriptor_id: str
    scope: ContinuousAccountScope
    request_kind: Literal["initialize", "frontier", "activation_dependencies"]
    request: ContinuousEvidenceRef
    market_source: ContinuousEvidenceRef
    market_evidence_class: Literal["synthetic_fixture", "provider_https_read"]
    previous: ContinuousAccountReceipt | None
    original_checked_at: datetime
    captured_fence: DailyFenceReference
    producer_map: RuntimeProducerMap
    assignment_sha256: str | None
    control_sha256: str | None
    obligations_sha256: str
    attempts_sha256: str
    role_references: tuple[ContinuousRuntimeRoleReferences, ...]

    def __post_init__(self) -> None:
        super(ContinuousRuntimeSourceDescriptor, self).__post_init__()
        require_identifier(self.descriptor_id, "runtime source descriptor")
        require_utc(self.original_checked_at, "original runtime source time")
        for name in (
            "assignment_sha256",
            "control_sha256",
            "obligations_sha256",
            "attempts_sha256",
        ):
            value = getattr(self, name)
            if value is not None:
                require_digest(value, name)
        if self.request.schema_id != "continuous-account-request/1":
            raise ValueError("runtime source request must precede any action or decision")
        if (self.request_kind == "initialize") != (self.previous is None):
            raise ValueError("runtime source requires exact initialized predecessor")
        if self.previous is not None and (
            self.previous.commit.scope != self.scope
            or self.previous.commit.transition.applied_at > self.original_checked_at
            or self.assignment_sha256 is None
        ):
            raise ValueError("runtime source previous scope, time or assignment differs")
        if (
            self.captured_fence.fence.account_id != self.scope.account_id
            or self.original_checked_at > self.captured_fence.validated_at
        ):
            raise ValueError("runtime source original time or actual fence scope differs")
        if any(p.account_scope != self.scope.account_id for p in self.producer_map.producers):
            raise ValueError("runtime producer map belongs to another account")
        roles = tuple(item.role for item in self.role_references)
        if roles != tuple(sorted(set(roles))):
            raise ValueError("runtime evidence roles must be sorted and unique")
        if (
            sum(len(item.references) for item in self.role_references)
            > MAX_RUNTIME_SOURCE_REFERENCES
        ):
            raise ValueError("runtime evidence reference inventory exceeds its bound")
