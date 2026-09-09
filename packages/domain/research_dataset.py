"""Versioned daily research facts; historical assumptions never become receipts.

This additive port deliberately does not emit the older RawBar/VendorBarRecord.
Current-vintage admission means structural validation and an owner source review,
not independent provider qualification or historical point-in-time evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Protocol
from zoneinfo import ZoneInfo

from packages.domain.canonical import canonical_json_bytes

RESEARCH_DATASET_VERSION = "personal-research-dataset-v1"
DAILY_AVAILABILITY_POLICY = "assumed-session-2000-america-new-york-v1"
ACTION_POLICY = "tiingo-ex-date-candidates-no-payable-or-fractional-accounting-v1"
PERSONAL_SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be nonempty trimmed text")


def _require_utc(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be an aware UTC datetime")


def _require_digest(value: str, field_name: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class ResearchSession:
    venue: str
    session_label: date
    opens_at: datetime
    closes_at: datetime
    kind: str

    def __post_init__(self) -> None:
        _require_text(self.venue, "venue")
        _require_utc(self.opens_at, "opens_at")
        _require_utc(self.closes_at, "closes_at")
        if (
            type(self.session_label) is not date
            or self.venue != self.venue.upper()
            or self.kind not in ("regular", "half_day")
        ):
            raise ValueError("invalid research session identity or kind")
        local_open = self.opens_at.astimezone(ZoneInfo("America/New_York"))
        local_close = self.closes_at.astimezone(ZoneInfo("America/New_York"))
        if (
            local_open.date() != self.session_label
            or local_close.date() != self.session_label
            or not timedelta(0) < self.closes_at - self.opens_at < timedelta(days=1)
        ):
            raise ValueError("invalid research session date or interval")


@dataclass(frozen=True, slots=True)
class ResearchCalendar:
    calendar_id: str
    version: str
    venue: str
    timezone: str
    sessions: tuple[ResearchSession, ...]

    def __post_init__(self) -> None:
        for name in ("calendar_id", "version", "venue"):
            _require_text(getattr(self, name), name)
        if self.timezone != "America/New_York":
            raise ValueError("personal-v1 requires an America/New_York calendar")
        if (
            type(self.sessions) is not tuple
            or not self.sessions
            or any(type(session) is not ResearchSession for session in self.sessions)
        ):
            raise ValueError("calendar requires an immutable nonempty research session tuple")
        labels = tuple(session.session_label for session in self.sessions)
        if labels != tuple(sorted(set(labels))):
            raise ValueError("calendar session labels must be sorted and unique")
        if any(session.venue != self.venue for session in self.sessions):
            raise ValueError("session venue differs from calendar")


class ResearchDataClass(StrEnum):
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    VALIDATED_CURRENT_VINTAGE = "validated_current_vintage"


def research_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def modeled_daily_availability(session_label: date) -> datetime:
    return datetime.combine(session_label, time(20), ZoneInfo("America/New_York")).astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ResearchRawObject:
    symbol: str
    sha256: str
    payload: bytes = field(repr=False)
    observed_available_at: datetime | None = None
    capture_reference: str | None = None

    def __post_init__(self) -> None:
        _require_digest(self.sha256, "raw object sha256")
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("raw object payload must be non-empty bytes")
        if hashlib.sha256(self.payload).hexdigest() != self.sha256:
            raise ValueError("raw object checksum does not match its payload")
        if self.observed_available_at is not None:
            _require_utc(self.observed_available_at, "observed_available_at")
            if self.capture_reference is None:
                raise ValueError("local capture time requires its evidence reference")
            _require_text(self.capture_reference, "capture_reference")
        elif self.capture_reference is not None:
            raise ValueError("capture reference requires its factual local receipt time")


@dataclass(frozen=True, slots=True)
class DailyResearchBar:
    instrument_id: str
    symbol: str
    session_label: date
    interval_start: datetime
    interval_end: datetime
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: int
    adjusted_open_price: Decimal
    adjusted_high_price: Decimal
    adjusted_low_price: Decimal
    adjusted_close_price: Decimal
    adjusted_volume: int
    div_cash: Decimal
    split_factor: Decimal
    raw_object_sha256: str
    simulated_available_at: datetime
    vendor_published_at: datetime | None = None
    observed_available_at: datetime | None = None
    observation_evidence_reference: str | None = None
    factual_time_unknown_reason: str = "owner-export-has-no-publication-or-capture-evidence"
    simulated_available_at_policy_id: str = DAILY_AVAILABILITY_POLICY

    def __post_init__(self) -> None:
        _require_text(self.instrument_id, "instrument_id")
        _require_digest(self.raw_object_sha256, "raw_object_sha256")
        for name in ("interval_start", "interval_end", "simulated_available_at"):
            _require_utc(getattr(self, name), name)
        if self.interval_end <= self.interval_start:
            raise ValueError("daily interval must have positive duration")
        if self.simulated_available_at_policy_id != DAILY_AVAILABILITY_POLICY:
            raise ValueError("unsupported research availability policy")
        if self.simulated_available_at != modeled_daily_availability(self.session_label):
            raise ValueError("simulated availability does not match its explicit policy")
        if self.simulated_available_at < self.interval_end:
            raise ValueError("modeled availability cannot precede session close")
        if self.vendor_published_at is not None:
            raise ValueError("Tiingo owner-export v1 cannot assert vendor publication times")
        if self.observed_available_at is not None:
            _require_utc(self.observed_available_at, "observed_available_at")
            if self.observed_available_at < self.interval_end:
                raise ValueError("factual local receipt cannot precede the complete daily bar")
            if self.observation_evidence_reference is None:
                raise ValueError("factual local receipt requires an evidence reference")
            _require_text(self.observation_evidence_reference, "observation_evidence_reference")
        elif self.observation_evidence_reference is not None:
            raise ValueError("observation evidence requires its receipt time")
        _require_text(self.factual_time_unknown_reason, "factual_time_unknown_reason")
        for prefix in ("", "adjusted_"):
            values = tuple(
                getattr(self, f"{prefix}{name}_price") for name in ("open", "high", "low", "close")
            )
            if any(
                not isinstance(value, Decimal) or not value.is_finite() or value <= 0
                for value in values
            ):
                raise ValueError("OHLC must contain finite positive Decimals")
            open_, high, low, close = values
            if low > min(open_, close) or high < max(open_, close) or low > high:
                raise ValueError("OHLC range is invalid")
            volume = getattr(self, f"{prefix}volume")
            if type(volume) is not int or not 0 <= volume <= 9_223_372_036_854_775_807:
                raise ValueError("volume must be a nonnegative int64")
        if (
            not isinstance(self.div_cash, Decimal)
            or not self.div_cash.is_finite()
            or self.div_cash < 0
        ):
            raise ValueError("div_cash must be a finite nonnegative Decimal")
        if not isinstance(self.split_factor, Decimal) or self.split_factor != Decimal(1):
            raise ValueError("split-affected scope is excluded until fractional action support")


@dataclass(frozen=True, slots=True)
class ResearchDatasetManifest:
    source_kind: str
    rights_reference: str
    provenance_reference: str
    reviewer_id: str
    reviewed_at: datetime
    identity_reference: str
    calendar_reference: str
    tzdata_version: str
    instruments: tuple[tuple[str, str], ...]
    start_date: date
    end_date: date
    calendar: ResearchCalendar
    raw_object_hashes: tuple[tuple[str, str], ...]
    exclusions: tuple[str, ...]
    schema_version: str = RESEARCH_DATASET_VERSION
    source_id: str = "tiingo-eod-owner-import-v1"
    parser_version: str = "tiingo-eod-exact-fields-v1"
    availability_policy_id: str = DAILY_AVAILABILITY_POLICY
    action_policy_id: str = ACTION_POLICY
    admission_decision: str = "admitted_exploratory"
    quality_checks: tuple[str, ...] = (
        "exact-fields-and-finite-ohlcv",
        "complete-declared-calendar-coverage",
        "raw-adjusted-series-separated",
        "raw-object-checksums",
    )

    def __post_init__(self) -> None:
        for name in (
            "rights_reference",
            "provenance_reference",
            "reviewer_id",
            "identity_reference",
            "calendar_reference",
            "tzdata_version",
        ):
            _require_text(getattr(self, name), name)
        _require_utc(self.reviewed_at, "reviewed_at")
        if self.source_kind not in ("synthetic_fixture", "owner_export"):
            raise ValueError("unsupported source kind")
        if (
            self.schema_version != RESEARCH_DATASET_VERSION
            or self.source_id != "tiingo-eod-owner-import-v1"
            or self.parser_version != "tiingo-eod-exact-fields-v1"
            or self.availability_policy_id != DAILY_AVAILABILITY_POLICY
            or self.action_policy_id != ACTION_POLICY
            or self.admission_decision != "admitted_exploratory"
        ):
            raise ValueError("unsupported research dataset contract")
        symbols = self.symbols
        if (
            type(self.instruments) is not tuple
            or not symbols
            or symbols != tuple(sorted(set(symbols)))
            or not set(symbols).issubset(PERSONAL_SYMBOLS)
        ):
            raise ValueError("instrument symbols must be a sorted unique personal-v1 subset")
        for _, instrument_id in self.instruments:
            _require_text(instrument_id, "instrument_id")
        if len({item[1] for item in self.instruments}) != len(symbols):
            raise ValueError("instrument identities must be distinct")
        if (
            type(self.start_date) is not date
            or type(self.end_date) is not date
            or self.end_date < self.start_date
        ):
            raise ValueError("invalid requested date bounds")
        if self.calendar.timezone != "America/New_York":
            raise ValueError("personal-v1 requires an America/New_York calendar")
        if not self.calendar.sessions or any(
            not self.start_date <= session.session_label <= self.end_date
            for session in self.calendar.sessions
        ):
            raise ValueError("calendar sessions must exactly describe the requested scope")
        if tuple(symbol for symbol, _ in self.raw_object_hashes) != symbols:
            raise ValueError("raw object hashes must exactly cover the symbol universe")
        for _, sha256 in self.raw_object_hashes:
            _require_digest(sha256, "raw object hash")
        if type(self.exclusions) is not tuple or self.exclusions != tuple(
            sorted(set(self.exclusions))
        ):
            raise ValueError("exclusions must be a sorted unique immutable tuple")
        mandatory = {
            "no-historical-pit",
            "no-execution-time-quotes",
            "fixed-universe-selection-bias",
            "adjusted-series-not-executable",
            "owner-review-not-provider-qualification",
        }
        if not mandatory.issubset(self.exclusions):
            raise ValueError("research exclusions are incomplete")

    @property
    def symbols(self) -> tuple[str, ...]:
        return tuple(symbol for symbol, _ in self.instruments)

    @property
    def data_class(self) -> ResearchDataClass:
        return (
            ResearchDataClass.SYNTHETIC_FIXTURE
            if self.source_kind == "synthetic_fixture"
            else ResearchDataClass.VALIDATED_CURRENT_VINTAGE
        )

    @property
    def calendar_sha256(self) -> str:
        return research_digest(asdict(self.calendar))


@dataclass(frozen=True, slots=True)
class ResearchDataset:
    manifest: ResearchDatasetManifest
    rows: tuple[DailyResearchBar, ...]
    raw_objects: tuple[ResearchRawObject, ...] = field(repr=False)
    imported_at: datetime

    def __post_init__(self) -> None:
        _require_utc(self.imported_at, "imported_at")
        if self.imported_at < self.manifest.reviewed_at:
            raise ValueError("import predates source review")
        if type(self.rows) is not tuple or not self.rows:
            raise ValueError("dataset requires immutable nonempty rows")
        keys = tuple((row.session_label, row.symbol) for row in self.rows)
        expected = tuple(
            (session.session_label, symbol)
            for session in self.manifest.calendar.sessions
            for symbol in self.manifest.symbols
        )
        if keys != expected:
            raise ValueError("rows must exactly cover every calendar session and symbol in order")
        if (
            type(self.raw_objects) is not tuple
            or tuple((raw.symbol, raw.sha256) for raw in self.raw_objects)
            != self.manifest.raw_object_hashes
        ):
            raise ValueError("raw objects must match manifest hashes in symbol order")
        sessions = {session.session_label: session for session in self.manifest.calendar.sessions}
        identities = dict(self.manifest.instruments)
        hashes = dict(self.manifest.raw_object_hashes)
        observations = {raw.symbol: raw for raw in self.raw_objects}
        for row in self.rows:
            session = sessions[row.session_label]
            if (
                row.instrument_id != identities[row.symbol]
                or row.raw_object_sha256 != hashes[row.symbol]
                or (row.interval_start, row.interval_end) != (session.opens_at, session.closes_at)
            ):
                raise ValueError("row identity, raw object or session binding is invalid")
            if row.interval_end > self.imported_at:
                raise ValueError("import cannot contain an incomplete future session")
            observation = observations[row.symbol]
            if (
                row.observed_available_at != observation.observed_available_at
                or row.observation_evidence_reference != observation.capture_reference
            ):
                raise ValueError("row factual observation must match the retained source evidence")
            if (
                row.observed_available_at is not None
                and row.observed_available_at > self.imported_at
            ):
                raise ValueError("import cannot precede its source receipt")
        if (
            any(row.div_cash for row in self.rows)
            and "cash-dividend-payable-date-unavailable" not in self.manifest.exclusions
        ):
            raise ValueError("dividend candidates require an explicit payable-date exclusion")

    @property
    def dataset_id(self) -> str:
        # Import receipt time is factual metadata, not the frozen content identity.
        return "research-" + research_digest(
            {
                "manifest": asdict(self.manifest),
                "rows": tuple(asdict(row) for row in self.rows),
            }
        )


class ResearchDatasetSource(Protocol):
    def load(self) -> ResearchDataset:
        """Load one frozen dataset without assigning legacy factual availability."""
        ...
