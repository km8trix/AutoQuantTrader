"""Offline, fail-closed reader for immutable Sharadar SFP research captures.

SFP supplies split/stock-dividend-adjusted OHLCV and one unadjusted close.
Consequently this adapter preserves provider semantics but deliberately cannot
emit execution-safe ``VendorBarRecord`` objects.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

from packages.market_data import BarInterval, ExchangeCalendar, ExchangeSession
from packages.market_data.models import (
    require_digest,
    require_positive_decimal,
    require_text,
    require_utc,
)

SFP_PROVIDER = "nasdaq-data-link"
SFP_TABLE = "SHARADAR/SFP"
SFP_CAPTURE_SCHEMA_VERSION = "sharadar-sfp-capture-v2"
SFP_AUTHORIZATION_SCHEMA_VERSION = "sharadar-sfp-capture-authorization-v1"
SFP_COLUMNS = (
    "ticker",
    "date",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "closeadj",
    "closeunadj",
    "lastupdated",
)
PHASE1_SFP_SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")
MAX_MANIFEST_BYTES = 1_048_576
MAX_AUTHORIZATION_BYTES = 1_048_576
MAX_PAGE_BYTES = 8_388_608

_SYMBOL = re.compile(r"^[A-Z][A-Z0-9.-]{0,14}$")
_PARAMETERIZED_BIG_DECIMAL = re.compile(r"^BigDecimal\([1-9][0-9]*,[0-9]+\)$")
_COMPATIBLE_TYPES = {
    "ticker": frozenset({"String", "text"}),
    "date": frozenset({"Date", "date"}),
    "open": frozenset({"BigDecimal", "double", "numeric"}),
    "high": frozenset({"BigDecimal", "double", "numeric"}),
    "low": frozenset({"BigDecimal", "double", "numeric"}),
    "close": frozenset({"BigDecimal", "double", "numeric"}),
    "volume": frozenset({"BigDecimal", "double", "numeric"}),
    "closeadj": frozenset({"BigDecimal", "double", "numeric"}),
    "closeunadj": frozenset({"BigDecimal", "double", "numeric"}),
    "lastupdated": frozenset({"Date", "date"}),
}


class SharadarSfpError(ValueError):
    """A capture, response, or SFP semantic invariant failed closed."""


class SfpPriceBasis(StrEnum):
    SPLIT_STOCK_DIVIDEND_ADJUSTED = "split_stock_dividend_adjusted"
    CORPORATE_ACTION_BACKWARD_ADJUSTED = "corporate_action_backward_adjusted"
    UNADJUSTED_CLOSE = "unadjusted_close"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SharadarSfpError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _json(payload_bytes: bytes, *, decimals: bool = False) -> object:
    try:
        return json.loads(
            payload_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=Decimal if decimals else float,
            parse_int=int,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SharadarSfpError("payload is not valid unambiguous UTF-8 JSON") from error


def _object(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SharadarSfpError(f"{field_name} must be a JSON object")
    return cast(dict[str, object], value)


def _fields(value: dict[str, object], expected: set[str], field_name: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown or missing:
        details: list[str] = []
        if unknown:
            details.append(f"unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            details.append(f"missing fields: {', '.join(sorted(missing))}")
        raise SharadarSfpError(f"{field_name} has {'; '.join(details)}")


def _text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise SharadarSfpError(f"{field_name} must be a string")
    try:
        require_text(value, field_name)
    except ValueError as error:
        raise SharadarSfpError(str(error)) from error
    return value


def _optional_text(value: object, field_name: str) -> str | None:
    return None if value is None else _text(value, field_name)


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int or value < 1:
        raise SharadarSfpError(f"{field_name} must be a positive integer")
    return value


def _boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise SharadarSfpError(f"{field_name} must be boolean")
    return value


def _date(value: object, field_name: str) -> date:
    if not isinstance(value, str):
        raise SharadarSfpError(f"{field_name} must be an ISO date string")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise SharadarSfpError(f"{field_name} must be an ISO date string") from error


def _datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise SharadarSfpError(f"{field_name} must be an ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(result, field_name)
    except ValueError as error:
        raise SharadarSfpError(f"{field_name} must be an ISO-8601 UTC timestamp") from error
    return result


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class SfpCaptureScope:
    symbols: tuple[str, ...]
    start_date: date
    end_date: date

    def __post_init__(self) -> None:
        if self.symbols != tuple(sorted(set(self.symbols))) or not self.symbols:
            raise ValueError("symbols must be a non-empty, unique, sorted tuple")
        if any(_SYMBOL.fullmatch(symbol) is None for symbol in self.symbols):
            raise ValueError("symbols must use canonical uppercase market notation")
        if self.end_date < self.start_date:
            raise ValueError("end_date cannot precede start_date")
        if (self.end_date - self.start_date).days > 365:
            raise ValueError("an SFP capture is limited to 366 inclusive dates")

    def to_dict(self) -> dict[str, object]:
        return {
            "end_date": self.end_date.isoformat(),
            "start_date": self.start_date.isoformat(),
            "symbols": list(self.symbols),
        }

    @classmethod
    def from_dict(cls, value: object) -> SfpCaptureScope:
        payload = _object(value, "scope")
        _fields(payload, {"symbols", "start_date", "end_date"}, "scope")
        symbols = payload["symbols"]
        if not isinstance(symbols, list) or not all(isinstance(item, str) for item in symbols):
            raise SharadarSfpError("scope.symbols must be an array of strings")
        try:
            return cls(
                symbols=tuple(symbols),
                start_date=_date(payload["start_date"], "scope.start_date"),
                end_date=_date(payload["end_date"], "scope.end_date"),
            )
        except ValueError as error:
            raise SharadarSfpError(str(error)) from error


@dataclass(frozen=True, slots=True)
class SfpCaptureAuthorization:
    authorization_id: str
    reviewer_id: str
    reviewed_at: datetime
    terms_sha256: str
    effective_from: date
    effective_through: date | None
    permits_local_snapshot_storage: bool
    permits_research_use: bool
    schema_version: str = SFP_AUTHORIZATION_SCHEMA_VERSION
    provider: str = SFP_PROVIDER
    table: str = SFP_TABLE

    def __post_init__(self) -> None:
        require_text(self.authorization_id, "authorization_id")
        require_text(self.reviewer_id, "reviewer_id")
        require_utc(self.reviewed_at, "reviewed_at")
        require_digest(self.terms_sha256, "terms_sha256")
        if self.terms_sha256 == "0" * 64:
            raise ValueError("terms_sha256 must identify the reviewed terms artifact")
        if self.schema_version != SFP_AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported SFP capture authorization schema")
        if self.provider != SFP_PROVIDER or self.table != SFP_TABLE:
            raise ValueError("authorization does not identify Sharadar SFP")
        if self.effective_through is not None and self.effective_through < self.effective_from:
            raise ValueError("effective_through cannot precede effective_from")
        if type(self.permits_local_snapshot_storage) is not bool:
            raise ValueError("permits_local_snapshot_storage must be boolean")
        if type(self.permits_research_use) is not bool:
            raise ValueError("permits_research_use must be boolean")

    def authorize(self, scope: SfpCaptureScope, *, requested_at: datetime) -> None:
        require_utc(requested_at, "requested_at")
        if self.reviewed_at > requested_at:
            raise ValueError("capture authorization has not yet been reviewed")
        if not self.permits_local_snapshot_storage or not self.permits_research_use:
            raise ValueError("capture authorization does not permit local research storage")
        if scope.start_date < self.effective_from:
            raise ValueError("capture scope predates its storage authorization")
        if self.effective_through is not None and scope.end_date > self.effective_through:
            raise ValueError("capture scope exceeds its storage authorization")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> SfpCaptureAuthorization:
        if len(payload_bytes) > MAX_AUTHORIZATION_BYTES:
            raise SharadarSfpError("capture authorization exceeds the size limit")
        payload = _object(_json(payload_bytes), "authorization")
        expected = {
            "authorization_id",
            "effective_from",
            "effective_through",
            "permits_local_snapshot_storage",
            "permits_research_use",
            "provider",
            "reviewed_at",
            "reviewer_id",
            "schema_version",
            "table",
            "terms_sha256",
        }
        _fields(payload, expected, "authorization")
        effective_through = payload["effective_through"]
        try:
            return cls(
                authorization_id=_text(payload["authorization_id"], "authorization_id"),
                reviewer_id=_text(payload["reviewer_id"], "reviewer_id"),
                reviewed_at=_datetime(payload["reviewed_at"], "reviewed_at"),
                terms_sha256=_text(payload["terms_sha256"], "terms_sha256"),
                effective_from=_date(payload["effective_from"], "effective_from"),
                effective_through=(
                    None
                    if effective_through is None
                    else _date(effective_through, "effective_through")
                ),
                permits_local_snapshot_storage=_boolean(
                    payload["permits_local_snapshot_storage"],
                    "permits_local_snapshot_storage",
                ),
                permits_research_use=_boolean(
                    payload["permits_research_use"], "permits_research_use"
                ),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                table=_text(payload["table"], "table"),
            )
        except (TypeError, ValueError) as error:
            if isinstance(error, SharadarSfpError):
                raise
            raise SharadarSfpError(str(error)) from error


@dataclass(frozen=True, slots=True)
class SfpPageReceipt:
    object_path: str
    sha256: str
    byte_count: int
    cursor_id: str | None
    next_cursor_id: str | None
    requested_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        require_digest(self.sha256, "sha256")
        if type(self.byte_count) is not int or self.byte_count < 1:
            raise ValueError("byte_count must be a positive integer")
        if self.byte_count > MAX_PAGE_BYTES:
            raise ValueError("page byte_count exceeds the capture limit")
        path = PurePosixPath(self.object_path)
        if (
            not self.object_path
            or path.is_absolute()
            or ".." in path.parts
            or "." in path.parts
            or "\\" in self.object_path
        ):
            raise ValueError("object_path must be a safe relative POSIX path")
        for cursor, field_name in (
            (self.cursor_id, "cursor_id"),
            (self.next_cursor_id, "next_cursor_id"),
        ):
            if cursor is not None:
                require_text(cursor, field_name)
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.received_at < self.requested_at:
            raise ValueError("received_at cannot precede requested_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "cursor_id": self.cursor_id,
            "next_cursor_id": self.next_cursor_id,
            "object_path": self.object_path,
            "received_at": _timestamp(self.received_at),
            "requested_at": _timestamp(self.requested_at),
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> SfpPageReceipt:
        payload = _object(value, f"pages[{index}]")
        expected = {
            "byte_count",
            "cursor_id",
            "next_cursor_id",
            "object_path",
            "received_at",
            "requested_at",
            "sha256",
        }
        _fields(payload, expected, f"pages[{index}]")
        try:
            return cls(
                object_path=_text(payload["object_path"], "object_path"),
                sha256=_text(payload["sha256"], "sha256"),
                byte_count=_integer(payload["byte_count"], "byte_count"),
                cursor_id=_optional_text(payload["cursor_id"], "cursor_id"),
                next_cursor_id=_optional_text(payload["next_cursor_id"], "next_cursor_id"),
                requested_at=_datetime(payload["requested_at"], "requested_at"),
                received_at=_datetime(payload["received_at"], "received_at"),
            )
        except ValueError as error:
            raise SharadarSfpError(str(error)) from error


@dataclass(frozen=True, slots=True)
class SfpCaptureManifest:
    scope: SfpCaptureScope
    pages: tuple[SfpPageReceipt, ...]
    requested_at: datetime
    received_at: datetime
    authorization_sha256: str
    terms_sha256: str
    column_schema_sha256: str
    schema_version: str = SFP_CAPTURE_SCHEMA_VERSION
    provider: str = SFP_PROVIDER
    table: str = SFP_TABLE

    def __post_init__(self) -> None:
        if self.schema_version != SFP_CAPTURE_SCHEMA_VERSION:
            raise ValueError("unsupported SFP capture schema version")
        if self.provider != SFP_PROVIDER or self.table != SFP_TABLE:
            raise ValueError("capture does not identify the Sharadar SFP table")
        require_digest(self.authorization_sha256, "authorization_sha256")
        require_digest(self.terms_sha256, "terms_sha256")
        require_digest(self.column_schema_sha256, "column_schema_sha256")
        if type(self.pages) is not tuple or not self.pages:
            raise ValueError("capture manifest requires an immutable page tuple")
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.requested_at != self.pages[0].requested_at:
            raise ValueError("manifest requested_at must equal the first page request")
        if self.received_at != self.pages[-1].received_at:
            raise ValueError("manifest received_at must equal the final page receipt")
        if self.pages[0].cursor_id is not None:
            raise ValueError("the first SFP page cannot have a cursor_id")
        seen_cursors: set[str] = set()
        previous: SfpPageReceipt | None = None
        for page in self.pages:
            if previous is not None:
                if previous.next_cursor_id is None:
                    raise ValueError("capture contains a page after a terminal cursor")
                if page.cursor_id != previous.next_cursor_id:
                    raise ValueError("capture page cursor chain is incomplete")
                if page.requested_at < previous.received_at:
                    raise ValueError("capture page timestamps are not monotonic")
            if page.cursor_id is not None:
                if page.cursor_id in seen_cursors:
                    raise ValueError("capture page cursor chain contains a cycle")
                seen_cursors.add(page.cursor_id)
            previous = page
        if self.pages[-1].next_cursor_id is not None:
            raise ValueError("capture manifest ends before pagination is complete")

    def to_dict(self) -> dict[str, object]:
        return {
            "authorization_sha256": self.authorization_sha256,
            "column_schema_sha256": self.column_schema_sha256,
            "pages": [page.to_dict() for page in self.pages],
            "provider": self.provider,
            "received_at": _timestamp(self.received_at),
            "requested_at": _timestamp(self.requested_at),
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "table": self.table,
            "terms_sha256": self.terms_sha256,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> SfpCaptureManifest:
        if len(payload_bytes) > MAX_MANIFEST_BYTES:
            raise SharadarSfpError("capture manifest exceeds the size limit")
        payload = _object(_json(payload_bytes), "manifest")
        expected = {
            "authorization_sha256",
            "column_schema_sha256",
            "pages",
            "provider",
            "received_at",
            "requested_at",
            "schema_version",
            "scope",
            "table",
            "terms_sha256",
        }
        _fields(payload, expected, "manifest")
        pages = payload["pages"]
        if not isinstance(pages, list):
            raise SharadarSfpError("manifest.pages must be an array")
        try:
            return cls(
                scope=SfpCaptureScope.from_dict(payload["scope"]),
                pages=tuple(
                    SfpPageReceipt.from_dict(page, index) for index, page in enumerate(pages)
                ),
                requested_at=_datetime(payload["requested_at"], "requested_at"),
                received_at=_datetime(payload["received_at"], "received_at"),
                authorization_sha256=_text(payload["authorization_sha256"], "authorization_sha256"),
                terms_sha256=_text(payload["terms_sha256"], "terms_sha256"),
                column_schema_sha256=_text(payload["column_schema_sha256"], "column_schema_sha256"),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                table=_text(payload["table"], "table"),
            )
        except ValueError as error:
            if isinstance(error, SharadarSfpError):
                raise
            raise SharadarSfpError(str(error)) from error


@dataclass(frozen=True, slots=True)
class SharadarSfpRow:
    ticker: str
    trading_date: date
    interval_start: datetime
    interval_end: datetime
    observed_at: datetime
    last_updated: date
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: Decimal
    close_adjusted: Decimal
    close_unadjusted: Decimal
    page_sha256: str
    ohlcv_basis: SfpPriceBasis = SfpPriceBasis.SPLIT_STOCK_DIVIDEND_ADJUSTED
    close_adjusted_basis: SfpPriceBasis = SfpPriceBasis.CORPORATE_ACTION_BACKWARD_ADJUSTED
    close_unadjusted_basis: SfpPriceBasis = SfpPriceBasis.UNADJUSTED_CLOSE
    interval: BarInterval = BarInterval.ONE_DAY

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.ticker) is None:
            raise ValueError("ticker must use canonical uppercase market notation")
        require_utc(self.interval_start, "interval_start")
        require_utc(self.interval_end, "interval_end")
        require_utc(self.observed_at, "observed_at")
        if not self.interval.has_valid_span(self.interval_start, self.interval_end):
            raise ValueError("SFP daily row has invalid session bounds")
        if self.observed_at < self.interval_end:
            raise ValueError("SFP row cannot be observed before its session ends")
        if self.last_updated < self.trading_date:
            raise ValueError("last_updated cannot precede the trading date")
        if self.last_updated > self.observed_at.date():
            raise ValueError("last_updated cannot follow the observation date")
        for value, field_name in (
            (self.open_price, "open_price"),
            (self.high_price, "high_price"),
            (self.low_price, "low_price"),
            (self.close_price, "close_price"),
            (self.close_adjusted, "close_adjusted"),
            (self.close_unadjusted, "close_unadjusted"),
        ):
            require_positive_decimal(value, field_name)
        if not self.volume.is_finite() or self.volume < 0:
            raise ValueError("volume must be a finite non-negative decimal")
        if self.low_price > min(self.open_price, self.close_price):
            raise ValueError("adjusted low cannot exceed adjusted open or close")
        if self.high_price < max(self.open_price, self.close_price):
            raise ValueError("adjusted high cannot be below adjusted open or close")
        if self.low_price > self.high_price:
            raise ValueError("adjusted low cannot exceed adjusted high")
        require_digest(self.page_sha256, "page_sha256")
        if self.ohlcv_basis is not SfpPriceBasis.SPLIT_STOCK_DIVIDEND_ADJUSTED:
            raise ValueError("SFP OHLCV basis must remain explicit")
        if self.close_adjusted_basis is not SfpPriceBasis.CORPORATE_ACTION_BACKWARD_ADJUSTED:
            raise ValueError("SFP close_adjusted basis must remain explicit")
        if self.close_unadjusted_basis is not SfpPriceBasis.UNADJUSTED_CLOSE:
            raise ValueError("SFP close_unadjusted basis must remain explicit")
        if self.interval is not BarInterval.ONE_DAY:
            raise ValueError("SFP rows are session-defined daily observations")


@dataclass(frozen=True, slots=True)
class SharadarSfpDataset:
    manifest: SfpCaptureManifest
    capture_sha256: str
    calendar_id: str
    calendar_version: str
    calendar_sha256: str
    semantic_sha256: str
    rows: tuple[SharadarSfpRow, ...]

    def __post_init__(self) -> None:
        require_digest(self.capture_sha256, "capture_sha256")
        require_text(self.calendar_id, "calendar_id")
        require_text(self.calendar_version, "calendar_version")
        require_digest(self.calendar_sha256, "calendar_sha256")
        require_digest(self.semantic_sha256, "semantic_sha256")
        if type(self.rows) is not tuple or not self.rows:
            raise ValueError("an SFP dataset requires an immutable non-empty row tuple")
        if self.rows != tuple(sorted(self.rows, key=lambda row: (row.ticker, row.trading_date))):
            raise ValueError("SFP dataset rows must use deterministic ticker/date order")

    def raw_bar_records(self) -> NoReturn:
        """Refuse a lossy mapping into canonical execution-safe raw OHLCV."""

        raise SharadarSfpError(
            "Sharadar SFP supplies adjusted open/high/low/volume; only closeunadj is raw. "
            "Canonical raw bars require a separately validated raw daily source or "
            "corporate-action reconstruction."
        )


def _calendar_binding(
    calendar: ExchangeCalendar,
    scope: SfpCaptureScope,
) -> tuple[tuple[ExchangeSession, ...], str]:
    if (
        calendar.sessions[0].session_label > scope.start_date
        or calendar.sessions[-1].session_label < scope.end_date
    ):
        raise SharadarSfpError("pinned calendar does not cover the complete capture scope")
    sessions = tuple(
        session
        for session in calendar.sessions
        if scope.start_date <= session.session_label <= scope.end_date
    )
    if not sessions:
        raise SharadarSfpError("capture scope contains no pinned exchange sessions")
    material = {
        "calendar_id": calendar.calendar_id,
        "sessions": [
            {
                "closes_at": session.closes_at.isoformat(),
                "kind": session.kind.value,
                "opens_at": session.opens_at.isoformat(),
                "session_label": session.session_label.isoformat(),
                "venue": session.venue,
            }
            for session in sessions
        ],
        "timezone": calendar.timezone,
        "venue": calendar.venue,
        "version": calendar.version,
    }
    encoded = json.dumps(material, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return sessions, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _decimal(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise SharadarSfpError(f"{field_name} must be numeric")
    try:
        result = Decimal(str(value))
    except (ArithmeticError, ValueError) as error:
        raise SharadarSfpError(f"{field_name} must be numeric") from error
    if not result.is_finite():
        raise SharadarSfpError(f"{field_name} must be finite")
    return result


def _parse_columns(value: object) -> tuple[tuple[str, ...], str]:
    if not isinstance(value, list):
        raise SharadarSfpError("datatable.columns must be an array")
    names: list[str] = []
    contract: list[dict[str, str]] = []
    for index, raw_column in enumerate(value):
        column = _object(raw_column, f"datatable.columns[{index}]")
        _fields(column, {"name", "type"}, f"datatable.columns[{index}]")
        name = _text(column["name"], f"columns[{index}].name")
        column_type = _text(column["type"], f"columns[{index}].type")
        if name not in SFP_COLUMNS:
            raise SharadarSfpError(f"unexpected SFP column {name!r}")
        compatible = column_type in _COMPATIBLE_TYPES[name]
        if name not in {"ticker", "date", "lastupdated"}:
            compatible = compatible or _PARAMETERIZED_BIG_DECIMAL.fullmatch(column_type) is not None
        if not compatible:
            raise SharadarSfpError(f"SFP column {name!r} has incompatible type")
        names.append(name)
        contract.append({"name": name, "type": column_type})
    if len(names) != len(set(names)):
        raise SharadarSfpError("SFP response contains duplicate columns")
    if set(names) != set(SFP_COLUMNS):
        missing = sorted(set(SFP_COLUMNS) - set(names))
        raise SharadarSfpError(f"SFP response is missing required columns: {', '.join(missing)}")
    encoded = json.dumps(
        contract,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return tuple(names), hashlib.sha256(encoded).hexdigest()


def _next_cursor(payload: dict[str, object]) -> str | None:
    meta = _object(payload.get("meta"), "meta")
    if "next_cursor_id" not in meta:
        raise SharadarSfpError("SFP response meta is missing next_cursor_id")
    return _optional_text(meta["next_cursor_id"], "meta.next_cursor_id")


def sfp_page_next_cursor(payload_bytes: bytes) -> str | None:
    """Inspect one response page for acquisition without exposing row data."""

    if len(payload_bytes) > MAX_PAGE_BYTES:
        raise SharadarSfpError("SFP response page exceeds the size limit")
    return sfp_page_contract(payload_bytes)[0]


def sfp_page_contract(payload_bytes: bytes) -> tuple[str | None, str]:
    """Return cursor and observed column-schema digest for one strict page."""

    if len(payload_bytes) > MAX_PAGE_BYTES:
        raise SharadarSfpError("SFP response page exceeds the size limit")
    response = _object(_json(payload_bytes), "response")
    datatable = _object(response.get("datatable"), "datatable")
    if "columns" not in datatable or "data" not in datatable:
        raise SharadarSfpError("SFP datatable requires columns and data")
    columns, schema_sha256 = _parse_columns(datatable["columns"])
    data = datatable["data"]
    if not isinstance(data, list) or any(
        not isinstance(row, list) or len(row) != len(columns) for row in data
    ):
        raise SharadarSfpError("SFP data rows do not match the column schema")
    return _next_cursor(response), schema_sha256


def _parse_page(
    payload_bytes: bytes,
    *,
    receipt: SfpPageReceipt,
    scope: SfpCaptureScope,
    calendar: ExchangeCalendar,
    column_schema_sha256: str,
) -> tuple[SharadarSfpRow, ...]:
    response = _object(_json(payload_bytes, decimals=True), "response")
    if _next_cursor(response) != receipt.next_cursor_id:
        raise SharadarSfpError("SFP response cursor does not match its capture receipt")
    datatable = _object(response.get("datatable"), "datatable")
    if "columns" not in datatable or "data" not in datatable:
        raise SharadarSfpError("SFP datatable requires columns and data")
    columns, observed_schema_sha256 = _parse_columns(datatable["columns"])
    if observed_schema_sha256 != column_schema_sha256:
        raise SharadarSfpError("SFP page schema does not match its capture manifest")
    data = datatable["data"]
    if not isinstance(data, list):
        raise SharadarSfpError("datatable.data must be an array")
    indexes = {name: index for index, name in enumerate(columns)}
    rows: list[SharadarSfpRow] = []
    for row_index, raw_row in enumerate(data):
        if not isinstance(raw_row, list) or len(raw_row) != len(columns):
            raise SharadarSfpError(f"SFP row {row_index} does not match the column schema")
        ticker = _text(raw_row[indexes["ticker"]], f"rows[{row_index}].ticker")
        trading_date = _date(raw_row[indexes["date"]], f"rows[{row_index}].date")
        if ticker not in scope.symbols:
            raise SharadarSfpError(f"SFP row {row_index} is outside the symbol scope")
        if not scope.start_date <= trading_date <= scope.end_date:
            raise SharadarSfpError(f"SFP row {row_index} is outside the date scope")
        session = calendar.session_for_label(trading_date)
        if session is None:
            raise SharadarSfpError(
                f"SFP row {row_index} has no session in the pinned exchange calendar"
            )
        try:
            rows.append(
                SharadarSfpRow(
                    ticker=ticker,
                    trading_date=trading_date,
                    interval_start=session.opens_at,
                    interval_end=session.closes_at,
                    observed_at=receipt.received_at,
                    last_updated=_date(
                        raw_row[indexes["lastupdated"]],
                        f"rows[{row_index}].lastupdated",
                    ),
                    open_price=_decimal(raw_row[indexes["open"]], "open"),
                    high_price=_decimal(raw_row[indexes["high"]], "high"),
                    low_price=_decimal(raw_row[indexes["low"]], "low"),
                    close_price=_decimal(raw_row[indexes["close"]], "close"),
                    volume=_decimal(raw_row[indexes["volume"]], "volume"),
                    close_adjusted=_decimal(raw_row[indexes["closeadj"]], "closeadj"),
                    close_unadjusted=_decimal(raw_row[indexes["closeunadj"]], "closeunadj"),
                    page_sha256=receipt.sha256,
                )
            )
        except ValueError as error:
            if isinstance(error, SharadarSfpError):
                raise
            raise SharadarSfpError(f"SFP row {row_index} is invalid: {error}") from error
    return tuple(rows)


_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


def _open_directory_path(path: Path, *, kind: str) -> int:
    """Open a directory chain without following any path-component symlink."""

    absolute = Path(os.path.abspath(path))
    try:
        descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    except OSError as error:
        raise SharadarSfpError(f"cannot open SFP {kind}") from error
    try:
        for part in absolute.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        os.close(descriptor)
        raise SharadarSfpError(
            f"SFP {kind} path cannot contain symlinks or non-directories"
        ) from error
    return descriptor


def _open_capture_directory(manifest_path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(manifest_path))
    descriptor = _open_directory_path(absolute.parent, kind="capture directory")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise SharadarSfpError("capture directory must be a directory")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SharadarSfpError("capture directory permissions must be owner-only")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, absolute.name


def _read_relative_owner_only(
    root_descriptor: int,
    relative: PurePosixPath,
    *,
    limit: int,
    kind: str,
) -> bytes:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SharadarSfpError(f"{kind} path must be a safe relative POSIX path")
    directory_descriptor = os.dup(root_descriptor)
    file_descriptor: int | None = None
    try:
        for part in relative.parts[:-1]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_descriptor)
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                os.close(next_descriptor)
                raise SharadarSfpError(f"{kind} parent directories must be owner-only")
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_descriptor = os.open(
            relative.parts[-1],
            _FILE_FLAGS,
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SharadarSfpError(f"{kind} must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise SharadarSfpError(f"{kind} permissions must be owner-only")
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            payload = stream.read(limit + 1)
    except OSError as error:
        raise SharadarSfpError(
            f"cannot read SFP {kind} through a symlink or non-directory path"
        ) from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(directory_descriptor)
    if len(payload) > limit:
        raise SharadarSfpError(f"{kind} exceeds the size limit")
    return payload


class RecordedSharadarSfpSnapshot:
    """Load provider bytes from a secret-free manifest without network access."""

    def __init__(
        self,
        manifest_path: Path,
        *,
        calendar: ExchangeCalendar,
        allowed_symbols: tuple[str, ...] = PHASE1_SFP_SYMBOLS,
        require_symbol_coverage: bool = True,
    ) -> None:
        self._manifest_path = manifest_path
        self._calendar = calendar
        self._allowed_symbols = frozenset(allowed_symbols)
        self._require_symbol_coverage = require_symbol_coverage

    def load(self) -> SharadarSfpDataset:
        root_descriptor, manifest_name = _open_capture_directory(self._manifest_path)
        try:
            manifest_bytes = _read_relative_owner_only(
                root_descriptor,
                PurePosixPath(manifest_name),
                limit=MAX_MANIFEST_BYTES,
                kind="capture manifest",
            )
            manifest = SfpCaptureManifest.from_json_bytes(manifest_bytes)
            if not set(manifest.scope.symbols).issubset(self._allowed_symbols):
                raise SharadarSfpError("SFP capture scope exceeds the configured allow-list")
            scoped_sessions, calendar_sha256 = _calendar_binding(self._calendar, manifest.scope)
            rows: list[SharadarSfpRow] = []
            keys: set[tuple[str, date]] = set()
            for receipt in manifest.pages:
                page_bytes = _read_relative_owner_only(
                    root_descriptor,
                    PurePosixPath(receipt.object_path),
                    limit=MAX_PAGE_BYTES,
                    kind="response page",
                )
                if len(page_bytes) != receipt.byte_count:
                    raise SharadarSfpError(
                        "SFP response page byte count does not match its receipt"
                    )
                if hashlib.sha256(page_bytes).hexdigest() != receipt.sha256:
                    raise SharadarSfpError("SFP response page digest does not match its receipt")
                for row in _parse_page(
                    page_bytes,
                    receipt=receipt,
                    scope=manifest.scope,
                    calendar=self._calendar,
                    column_schema_sha256=manifest.column_schema_sha256,
                ):
                    key = (row.ticker, row.trading_date)
                    if key in keys:
                        raise SharadarSfpError("SFP capture contains a duplicate ticker/date row")
                    keys.add(key)
                    rows.append(row)
        finally:
            os.close(root_descriptor)
        observed_symbols = {row.ticker for row in rows}
        if self._require_symbol_coverage and observed_symbols != set(manifest.scope.symbols):
            missing = sorted(set(manifest.scope.symbols) - observed_symbols)
            raise SharadarSfpError(
                f"SFP capture is missing required symbol coverage: {', '.join(missing)}"
            )
        expected_keys = {
            (symbol, session.session_label)
            for symbol in manifest.scope.symbols
            for session in scoped_sessions
        }
        missing_keys = sorted(expected_keys - keys)
        if missing_keys:
            first_symbol, first_date = missing_keys[0]
            raise SharadarSfpError(
                "SFP capture is missing required session coverage: "
                f"{len(missing_keys)} rows; first {first_symbol}/{first_date.isoformat()}"
            )
        rows.sort(key=lambda row: (row.ticker, row.trading_date))
        capture_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        semantic_material = json.dumps(
            {"calendar_sha256": calendar_sha256, "capture_sha256": capture_sha256},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return SharadarSfpDataset(
            manifest=manifest,
            capture_sha256=capture_sha256,
            calendar_id=self._calendar.calendar_id,
            calendar_version=self._calendar.version,
            calendar_sha256=calendar_sha256,
            semantic_sha256=hashlib.sha256(semantic_material).hexdigest(),
            rows=tuple(rows),
        )
