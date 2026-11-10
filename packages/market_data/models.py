"""Pure, immutable point-in-time market-data facts.

The types in this module deliberately know nothing about Parquet, SQLAlchemy,
HTTP clients, or API transport models.  They are the contracts shared by
normalization, historical replay, and later live-data adapters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def require_text(value: str, field_name: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")


def require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be stored in UTC")


def to_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def require_digest(value: str, field_name: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def require_revision(
    revision: int,
    supersedes_event_revision_id: str | None,
) -> None:
    if type(revision) is not int or revision < 1:
        raise ValueError("revision must be a positive integer")
    if revision == 1 and supersedes_event_revision_id is not None:
        raise ValueError("an initial revision cannot supersede another revision")
    if revision > 1 and not supersedes_event_revision_id:
        raise ValueError("a correction must identify the revision it supersedes")


def require_positive_decimal(value: Decimal, field_name: str) -> None:
    if not value.is_finite() or value <= 0:
        raise ValueError(f"{field_name} must be a finite positive decimal")


class RevisionPolicy(StrEnum):
    """How revisions are exposed to a causal consumer."""

    FIRST_SEEN = "first_seen"
    REVISED_AS_OF = "revised_as_of"


class PriceBasis(StrEnum):
    """Execution-safe price basis.

    Adjusted research series intentionally do not have a member here and live
    in a separate infrastructure/research boundary.
    """

    RAW = "raw"


class BarInterval(StrEnum):
    ONE_MINUTE = "1m"
    ONE_DAY = "1d"

    @property
    def fixed_duration(self) -> timedelta | None:
        """Return a wall-clock duration only for fixed-duration intervals.

        Daily exchange bars are bounded by the pinned exchange session rather
        than by 24 elapsed hours.  This keeps half-days and calendar changes
        explicit at the normalization boundary.
        """

        if self is BarInterval.ONE_MINUTE:
            return timedelta(minutes=1)
        if self is BarInterval.ONE_DAY:
            return None
        raise AssertionError(f"unsupported bar interval: {self}")

    @property
    def duration(self) -> timedelta:
        duration = self.fixed_duration
        if duration is None:
            raise ValueError(f"{self.value} is bounded by an exchange session")
        return duration

    def has_valid_span(self, start: datetime, end: datetime) -> bool:
        """Perform interval-local validation without calendar authority."""

        span = end - start
        duration = self.fixed_duration
        if duration is not None:
            return span == duration
        if self is BarInterval.ONE_DAY:
            return timedelta(0) < span <= timedelta(days=1)
        raise AssertionError(f"unsupported bar interval: {self}")


class CaptureMode(StrEnum):
    HISTORICAL = "historical"
    LIVE = "live"


class AssetClass(StrEnum):
    ETF = "etf"
    EQUITY = "equity"


class CorporateActionType(StrEnum):
    SPLIT = "split"
    CASH_DIVIDEND = "cash_dividend"
    MERGER = "merger"
    SYMBOL_CHANGE = "symbol_change"
    DELISTING = "delisting"


class EntitlementLevel(StrEnum):
    HISTORICAL = "historical"
    DELAYED = "delayed"
    REAL_TIME = "real_time"


@dataclass(frozen=True, slots=True)
class Security:
    security_id: str
    asset_class: AssetClass
    currency: str
    name: str

    def __post_init__(self) -> None:
        require_text(self.security_id, "security_id")
        require_text(self.name, "name")
        if len(self.currency) != 3 or self.currency != self.currency.upper():
            raise ValueError("currency must be a three-letter uppercase code")


@dataclass(frozen=True, slots=True)
class SecurityIdentifier:
    """A bitemporal ticker/venue mapping revision.

    ``effective_*`` is valid time. ``available_at`` is knowledge time. All
    corrections for the same mapping share ``observation_id``.
    """

    observation_id: str
    event_revision_id: str
    security_id: str
    source_id: str
    symbol: str
    venue: str
    effective_from: datetime
    effective_to: datetime | None
    available_at: datetime
    tradable: bool
    revision: int
    supersedes_event_revision_id: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.observation_id, "observation_id"),
            (self.event_revision_id, "event_revision_id"),
            (self.security_id, "security_id"),
            (self.source_id, "source_id"),
            (self.symbol, "symbol"),
            (self.venue, "venue"),
        ):
            require_text(value, field_name)
        if self.symbol != self.symbol.upper() or self.venue != self.venue.upper():
            raise ValueError("symbol and venue must use their canonical uppercase form")
        require_utc(self.effective_from, "effective_from")
        require_utc(self.available_at, "available_at")
        if self.effective_to is not None:
            require_utc(self.effective_to, "effective_to")
            if self.effective_to <= self.effective_from:
                raise ValueError("effective_to must follow effective_from")
        if type(self.tradable) is not bool:
            raise ValueError("tradable must be a boolean")
        require_revision(self.revision, self.supersedes_event_revision_id)

    @property
    def event_time(self) -> datetime:
        return self.effective_from

    def is_effective_at(self, instant: datetime) -> bool:
        require_utc(instant, "instant")
        return self.effective_from <= instant and (
            self.effective_to is None or instant < self.effective_to
        )


@dataclass(frozen=True, slots=True)
class UniverseMembership:
    """An effective-dated, knowledge-time universe membership revision."""

    observation_id: str
    event_revision_id: str
    universe_id: str
    security_id: str
    effective_from: datetime
    effective_to: datetime | None
    available_at: datetime
    included: bool
    revision: int
    supersedes_event_revision_id: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.observation_id, "observation_id"),
            (self.event_revision_id, "event_revision_id"),
            (self.universe_id, "universe_id"),
            (self.security_id, "security_id"),
        ):
            require_text(value, field_name)
        require_utc(self.effective_from, "effective_from")
        require_utc(self.available_at, "available_at")
        if self.effective_to is not None:
            require_utc(self.effective_to, "effective_to")
            if self.effective_to <= self.effective_from:
                raise ValueError("effective_to must follow effective_from")
        if type(self.included) is not bool:
            raise ValueError("included must be a boolean")
        require_revision(self.revision, self.supersedes_event_revision_id)

    @property
    def event_time(self) -> datetime:
        return self.effective_from

    def is_effective_at(self, instant: datetime) -> bool:
        require_utc(instant, "instant")
        return self.effective_from <= instant and (
            self.effective_to is None or instant < self.effective_to
        )


@dataclass(frozen=True, slots=True)
class VendorBarRecord:
    """Provider-neutral record accepted by the normalization boundary.

    Provider timestamps may use any aware timezone. Normalization converts them
    to UTC before constructing a :class:`RawBar`.
    """

    source_id: str
    source_record_id: str
    symbol: str
    venue: str
    interval: BarInterval
    interval_start: datetime
    interval_end: datetime
    vendor_published_at: datetime
    ingested_at: datetime
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: int
    revision: int = 1
    source_sequence: int | None = None
    received_at: datetime | None = None
    available_at: datetime | None = None
    declared_session_label: date | None = None
    observation_key: str | None = None
    supersedes_event_revision_id: str | None = None
    trade_count: int | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.source_id, "source_id"),
            (self.source_record_id, "source_record_id"),
            (self.symbol, "symbol"),
            (self.venue, "venue"),
        ):
            require_text(value, field_name)
        if self.symbol != self.symbol.upper() or self.venue != self.venue.upper():
            raise ValueError("symbol and venue must use their canonical uppercase form")
        if self.source_sequence is not None and (
            type(self.source_sequence) is not int or self.source_sequence < 0
        ):
            raise ValueError("source_sequence must be a non-negative integer")
        if type(self.volume) is not int or self.volume < 0:
            raise ValueError("volume must be a non-negative integer")
        if self.trade_count is not None and (
            type(self.trade_count) is not int or self.trade_count < 0
        ):
            raise ValueError("trade_count must be a non-negative integer")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive integer")
        if self.revision == 1 and self.supersedes_event_revision_id is not None:
            raise ValueError("an initial revision cannot supersede another revision")


@dataclass(frozen=True, slots=True)
class RawBar:
    """Canonical unadjusted OHLCV fact used by execution-safe consumers.

    Construction validates calendar-independent invariants. A daily bar becomes
    canonical only after ``normalize_records`` or ``check_quality`` verifies its
    exact bounds against the pinned exchange calendar.
    """

    observation_id: str
    event_revision_id: str
    security_id: str
    source_id: str
    source_record_id: str
    schema_version: str
    payload_sha256: str
    symbol: str
    venue: str
    interval: BarInterval
    interval_start: datetime
    interval_end: datetime
    event_time: datetime
    vendor_published_at: datetime
    available_at: datetime
    ingested_at: datetime
    session_label: date
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: int
    revision: int
    capture_mode: CaptureMode = CaptureMode.HISTORICAL
    price_basis: PriceBasis = PriceBasis.RAW
    source_sequence: int | None = None
    received_at: datetime | None = None
    supersedes_event_revision_id: str | None = None
    trade_count: int | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.observation_id, "observation_id"),
            (self.event_revision_id, "event_revision_id"),
            (self.security_id, "security_id"),
            (self.source_id, "source_id"),
            (self.source_record_id, "source_record_id"),
            (self.schema_version, "schema_version"),
            (self.symbol, "symbol"),
            (self.venue, "venue"),
        ):
            require_text(value, field_name)
        require_digest(self.payload_sha256, "payload_sha256")
        if self.symbol != self.symbol.upper() or self.venue != self.venue.upper():
            raise ValueError("symbol and venue must use their canonical uppercase form")
        for timestamp, field_name in (
            (self.interval_start, "interval_start"),
            (self.interval_end, "interval_end"),
            (self.event_time, "event_time"),
            (self.vendor_published_at, "vendor_published_at"),
            (self.available_at, "available_at"),
            (self.ingested_at, "ingested_at"),
        ):
            require_utc(timestamp, field_name)
        if self.received_at is not None:
            require_utc(self.received_at, "received_at")
        if not self.interval.has_valid_span(self.interval_start, self.interval_end):
            raise ValueError("bar interval does not match its declared duration")
        if self.event_time != self.interval_end:
            raise ValueError("a completed bar event_time must equal interval_end")
        if self.vendor_published_at < self.interval_end:
            raise ValueError("vendor_published_at cannot precede interval_end")
        if self.available_at < self.vendor_published_at:
            raise ValueError("available_at cannot precede vendor_published_at")
        if self.ingested_at < self.vendor_published_at:
            raise ValueError("ingested_at cannot precede vendor_published_at")
        if self.capture_mode is CaptureMode.LIVE:
            if self.received_at is None:
                raise ValueError("live bars require received_at")
            if self.available_at < self.received_at:
                raise ValueError("live available_at cannot precede received_at")
        if self.received_at is not None and self.ingested_at < self.received_at:
            raise ValueError("ingested_at cannot precede received_at")
        for price, field_name in (
            (self.open_price, "open_price"),
            (self.high_price, "high_price"),
            (self.low_price, "low_price"),
            (self.close_price, "close_price"),
        ):
            require_positive_decimal(price, field_name)
        if self.low_price > min(self.open_price, self.close_price):
            raise ValueError("low_price cannot exceed open_price or close_price")
        if self.high_price < max(self.open_price, self.close_price):
            raise ValueError("high_price cannot be below open_price or close_price")
        if self.low_price > self.high_price:
            raise ValueError("low_price cannot exceed high_price")
        if type(self.volume) is not int or self.volume < 0:
            raise ValueError("volume must be a non-negative integer")
        if self.trade_count is not None and (
            type(self.trade_count) is not int or self.trade_count < 0
        ):
            raise ValueError("trade_count must be a non-negative integer")
        if self.source_sequence is not None and (
            type(self.source_sequence) is not int or self.source_sequence < 0
        ):
            raise ValueError("source_sequence must be a non-negative integer")
        if self.price_basis is not PriceBasis.RAW:
            raise ValueError("canonical market bars must use raw prices")
        require_revision(self.revision, self.supersedes_event_revision_id)


@dataclass(frozen=True, slots=True)
class SplitTerms:
    numerator: Decimal
    denominator: Decimal

    def __post_init__(self) -> None:
        require_positive_decimal(self.numerator, "numerator")
        require_positive_decimal(self.denominator, "denominator")


@dataclass(frozen=True, slots=True)
class CashDividendTerms:
    amount: Decimal
    currency: str

    def __post_init__(self) -> None:
        require_positive_decimal(self.amount, "amount")
        if len(self.currency) != 3 or self.currency != self.currency.upper():
            raise ValueError("currency must be a three-letter uppercase code")


@dataclass(frozen=True, slots=True)
class MergerTerms:
    target_security_id: str
    share_ratio: Decimal
    cash_amount: Decimal = Decimal("0")
    currency: str = "USD"

    def __post_init__(self) -> None:
        require_text(self.target_security_id, "target_security_id")
        if not self.share_ratio.is_finite() or self.share_ratio < 0:
            raise ValueError("share_ratio must be finite and non-negative")
        if not self.cash_amount.is_finite() or self.cash_amount < 0:
            raise ValueError("cash_amount must be finite and non-negative")
        if self.share_ratio == 0 and self.cash_amount == 0:
            raise ValueError("merger terms require stock, cash, or both")
        if len(self.currency) != 3 or self.currency != self.currency.upper():
            raise ValueError("currency must be a three-letter uppercase code")


@dataclass(frozen=True, slots=True)
class SymbolChangeTerms:
    new_symbol: str
    new_venue: str

    def __post_init__(self) -> None:
        require_text(self.new_symbol, "new_symbol")
        require_text(self.new_venue, "new_venue")
        if self.new_symbol != self.new_symbol.upper() or self.new_venue != self.new_venue.upper():
            raise ValueError("new symbol and venue must use their canonical uppercase form")


@dataclass(frozen=True, slots=True)
class DelistingTerms:
    reason: str

    def __post_init__(self) -> None:
        require_text(self.reason, "reason")


CorporateActionTerms = (
    SplitTerms | CashDividendTerms | MergerTerms | SymbolChangeTerms | DelistingTerms
)


@dataclass(frozen=True, slots=True)
class CorporateActionRevision:
    """An append-only, causally visible corporate-action revision."""

    observation_id: str
    event_revision_id: str
    security_id: str
    source_id: str
    source_record_id: str
    action_type: CorporateActionType
    announced_at: datetime
    effective_at: datetime
    vendor_published_at: datetime
    available_at: datetime
    ingested_at: datetime
    revision: int
    terms: CorporateActionTerms
    payable_at: datetime | None = None
    supersedes_event_revision_id: str | None = None

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.observation_id, "observation_id"),
            (self.event_revision_id, "event_revision_id"),
            (self.security_id, "security_id"),
            (self.source_id, "source_id"),
            (self.source_record_id, "source_record_id"),
        ):
            require_text(value, field_name)
        for timestamp, field_name in (
            (self.announced_at, "announced_at"),
            (self.effective_at, "effective_at"),
            (self.vendor_published_at, "vendor_published_at"),
            (self.available_at, "available_at"),
            (self.ingested_at, "ingested_at"),
        ):
            require_utc(timestamp, field_name)
        if self.payable_at is not None:
            require_utc(self.payable_at, "payable_at")
        if self.vendor_published_at < self.announced_at:
            raise ValueError("vendor_published_at cannot precede announced_at")
        if self.available_at < self.vendor_published_at:
            raise ValueError("available_at cannot precede vendor_published_at")
        if self.ingested_at < self.vendor_published_at:
            raise ValueError("ingested_at cannot precede vendor_published_at")
        expected_terms: dict[CorporateActionType, type[CorporateActionTerms]] = {
            CorporateActionType.SPLIT: SplitTerms,
            CorporateActionType.CASH_DIVIDEND: CashDividendTerms,
            CorporateActionType.MERGER: MergerTerms,
            CorporateActionType.SYMBOL_CHANGE: SymbolChangeTerms,
            CorporateActionType.DELISTING: DelistingTerms,
        }
        if type(self.terms) is not expected_terms[self.action_type]:
            raise ValueError("corporate-action type and terms do not agree")
        require_revision(self.revision, self.supersedes_event_revision_id)

    @property
    def event_time(self) -> datetime:
        return self.effective_at


@dataclass(frozen=True, slots=True)
class FeedEntitlement:
    entitlement_id: str
    source_id: str
    feed: str
    level: EntitlementLevel
    effective_from: datetime
    effective_to: datetime | None
    recorded_at: datetime
    terms_sha256: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.entitlement_id, "entitlement_id"),
            (self.source_id, "source_id"),
            (self.feed, "feed"),
        ):
            require_text(value, field_name)
        require_utc(self.effective_from, "effective_from")
        require_utc(self.recorded_at, "recorded_at")
        if self.effective_to is not None:
            require_utc(self.effective_to, "effective_to")
            if self.effective_to <= self.effective_from:
                raise ValueError("effective_to must follow effective_from")
        require_digest(self.terms_sha256, "terms_sha256")

    def is_effective_at(self, instant: datetime) -> bool:
        require_utc(instant, "instant")
        return self.effective_from <= instant and (
            self.effective_to is None or instant < self.effective_to
        )
