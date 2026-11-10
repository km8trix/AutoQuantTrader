"""Provider-neutral historical-source and admission contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from packages.market_data.admission import EntitlementStatus, SourceKind
from packages.market_data.calendar import ExchangeCalendar
from packages.market_data.models import (
    CorporateActionRevision,
    FeedEntitlement,
    VendorBarRecord,
    require_digest,
    require_text,
    require_utc,
)
from packages.market_data.security import SecurityMaster


@dataclass(frozen=True, slots=True)
class HistoricalAdmissionProfile:
    """Immutable metadata and frozen policy inputs for one historical source.

    ``licensed`` records an entitlement assertion, not admission. Only an
    :class:`~packages.market_data.admission.AdmissionReport` can carry an
    admission decision, so this provider-supplied profile has no readiness flag.
    """

    source_id: str
    source_name: str
    provider: str
    dataset: str
    feed: str
    adapter_type: str
    identifier_authority: str
    kind: SourceKind
    licensed: bool
    detail: str
    captured_at: datetime
    coverage_start: datetime
    coverage_end: datetime
    required_symbols: tuple[str, ...]
    manifest_name: str
    universe_version: str
    universe_name: str
    corporate_action_version: str
    corporate_action_set_name: str
    tzdata_version: str
    entitlement_status: EntitlementStatus
    entitlement_scope: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.source_id, "source_id"),
            (self.source_name, "source_name"),
            (self.provider, "provider"),
            (self.dataset, "dataset"),
            (self.feed, "feed"),
            (self.adapter_type, "adapter_type"),
            (self.identifier_authority, "identifier_authority"),
            (self.detail, "detail"),
            (self.manifest_name, "manifest_name"),
            (self.universe_version, "universe_version"),
            (self.universe_name, "universe_name"),
            (self.corporate_action_version, "corporate_action_version"),
            (self.corporate_action_set_name, "corporate_action_set_name"),
            (self.tzdata_version, "tzdata_version"),
            (self.entitlement_status, "entitlement_status"),
            (self.entitlement_scope, "entitlement_scope"),
        ):
            require_text(value, field_name)
        require_utc(self.captured_at, "captured_at")
        require_utc(self.coverage_start, "coverage_start")
        require_utc(self.coverage_end, "coverage_end")
        if self.coverage_end <= self.coverage_start:
            raise ValueError("coverage_end must follow coverage_start")
        if self.captured_at < self.coverage_end:
            raise ValueError("captured_at cannot precede the declared coverage end")
        if type(self.required_symbols) is not tuple or not self.required_symbols:
            raise ValueError("required_symbols must be a non-empty immutable tuple")
        if any(not isinstance(symbol, str) for symbol in self.required_symbols):
            raise ValueError("required symbols must be strings")
        if self.required_symbols != tuple(sorted(set(self.required_symbols))):
            raise ValueError("required_symbols must be unique and sorted")
        for symbol in self.required_symbols:
            require_text(symbol, "required symbol")
            if symbol != symbol.upper():
                raise ValueError("required symbols must use canonical uppercase form")
        if not isinstance(self.kind, SourceKind):
            raise ValueError("kind must be a historical source kind")
        if not isinstance(self.entitlement_status, EntitlementStatus):
            raise ValueError("entitlement_status must be an entitlement status")
        if type(self.licensed) is not bool:
            raise ValueError("licensed must be a boolean")
        fixture = self.kind in {
            SourceKind.SYNTHETIC_FIXTURE,
            SourceKind.RECORDED_FIXTURE,
        }
        if fixture and self.licensed:
            raise ValueError("fixture sources cannot claim a licensed entitlement")
        if fixture and self.entitlement_status is not EntitlementStatus.FIXTURE_ONLY:
            raise ValueError("fixture sources require fixture_only entitlement status")
        if self.licensed and self.entitlement_status is not EntitlementStatus.ACTIVE:
            raise ValueError("a licensed historical source requires an active entitlement")


@dataclass(frozen=True, slots=True)
class HistoricalSourceBundle:
    """One immutable provider-normalized input bundle awaiting ingestion."""

    profile: HistoricalAdmissionProfile
    source_checksum: str
    records: tuple[VendorBarRecord, ...]
    security_master: SecurityMaster
    calendar: ExchangeCalendar
    corporate_actions: tuple[CorporateActionRevision, ...]
    entitlement: FeedEntitlement

    def __post_init__(self) -> None:
        require_digest(self.source_checksum, "source_checksum")
        if type(self.records) is not tuple or type(self.corporate_actions) is not tuple:
            raise ValueError("historical source facts must be immutable tuples")
        if not self.records:
            raise ValueError("historical source bundle requires at least one bar record")
        if self.entitlement.source_id != self.profile.source_id:
            raise ValueError("entitlement source_id does not match its admission profile")


@runtime_checkable
class HistoricalBarSource(Protocol):
    """Port implemented by recorded fixtures and future licensed adapters."""

    def load(self) -> HistoricalSourceBundle: ...
