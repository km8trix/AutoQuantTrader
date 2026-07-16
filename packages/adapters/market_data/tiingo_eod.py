"""Strict, offline qualification for Tiingo end-of-day response observations.

Tiingo documents separate raw and adjusted OHLCV fields. Its EOD rows do not,
however, include a row publication timestamp, revision number, or historical
vintage. This module therefore qualifies economic and calendar semantics while
deliberately refusing conversion to canonical execution bars.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time
from decimal import Decimal
from enum import StrEnum
from typing import NoReturn, cast

from packages.market_data import BarInterval, ExchangeCalendar, ExchangeSession
from packages.market_data.models import (
    require_digest,
    require_positive_decimal,
    require_text,
    require_utc,
)

TIINGO_PROVIDER = "tiingo"
TIINGO_DATASET = "end-of-day"
TIINGO_QUALIFICATION_SCHEMA_VERSION = "tiingo-eod-qualification-v1"
TIINGO_EOD_FIELDS = (
    "date",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "adjOpen",
    "adjHigh",
    "adjLow",
    "adjClose",
    "adjVolume",
    "divCash",
    "splitFactor",
)
PHASE1_TIINGO_SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")
MAX_TIINGO_RESPONSE_BYTES = 4_194_304
MAX_INT64 = 9_223_372_036_854_775_807

_SYMBOL = re.compile(r"^[A-Z][A-Z0-9.-]{0,14}$")
_FIELD_CONTRACT = (
    ("date", "utc-midnight-or-iso-date"),
    ("open", "positive-decimal-raw"),
    ("high", "positive-decimal-raw"),
    ("low", "positive-decimal-raw"),
    ("close", "positive-decimal-raw"),
    ("volume", "non-negative-int64-raw"),
    ("adjOpen", "positive-decimal-split-dividend-adjusted"),
    ("adjHigh", "positive-decimal-split-dividend-adjusted"),
    ("adjLow", "positive-decimal-split-dividend-adjusted"),
    ("adjClose", "positive-decimal-split-dividend-adjusted"),
    ("adjVolume", "non-negative-int64-split-dividend-adjusted"),
    ("divCash", "non-negative-decimal-ex-date"),
    ("splitFactor", "positive-decimal"),
)


class TiingoEodError(ValueError):
    """A Tiingo response or qualification invariant failed closed."""


class TiingoEodAdjustedBasis(StrEnum):
    SPLIT_DIVIDEND_ADJUSTED = "split_dividend_adjusted"


class TiingoEodRawBasis(StrEnum):
    DOCUMENTED_RAW_CANDIDATE = "documented_raw_candidate"


class TiingoEodQualificationKind(StrEnum):
    SYNTHETIC_CONTRACT_ONLY = "synthetic_contract_only"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TiingoEodError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise TiingoEodError(f"non-finite JSON number is not permitted: {value}")


def _json(payload_bytes: bytes) -> object:
    try:
        return cast(
            object,
            json.loads(
                payload_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_float=Decimal,
                parse_int=int,
                parse_constant=_reject_constant,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TiingoEodError("response is not valid unambiguous UTF-8 JSON") from error


def _object(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TiingoEodError(f"{field_name} must be a JSON object")
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
        raise TiingoEodError(f"{field_name} has {'; '.join(details)}")


def _decimal(value: object, field_name: str, *, allow_zero: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise TiingoEodError(f"{field_name} must be a JSON number")
    result = Decimal(value)
    if not result.is_finite() or result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise TiingoEodError(f"{field_name} must be a finite {qualifier} decimal")
    return result


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise TiingoEodError(f"{field_name} must be a non-negative int64")
    return value


def _trading_date(value: object, field_name: str) -> date:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be an ISO date or UTC timestamp")
    if len(value) == 10:
        try:
            return date.fromisoformat(value)
        except ValueError as error:
            raise TiingoEodError(f"{field_name} must be an ISO date") from error
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(timestamp, field_name)
    except ValueError as error:
        raise TiingoEodError(f"{field_name} must be an ISO UTC timestamp") from error
    if timestamp.timetz().replace(tzinfo=None) != time(0):
        raise TiingoEodError(f"{field_name} timestamp must identify midnight UTC")
    return timestamp.date()


@dataclass(frozen=True, slots=True)
class TiingoEodScope:
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
            raise ValueError("a Tiingo qualification scope is limited to 366 inclusive dates")


@dataclass(frozen=True, slots=True)
class TiingoEodResponseObservation:
    symbol: str
    requested_at: datetime
    received_at: datetime
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("symbol must use canonical uppercase market notation")
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.received_at < self.requested_at:
            raise ValueError("received_at cannot precede requested_at")
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("payload must be non-empty immutable bytes")
        if len(self.payload) > MAX_TIINGO_RESPONSE_BYTES:
            raise ValueError("Tiingo response exceeds the qualification size limit")


@dataclass(frozen=True, slots=True)
class TiingoEodRow:
    symbol: str
    session_label: date
    interval_start: datetime
    interval_end: datetime
    observed_at: datetime
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
    response_sha256: str
    interval: BarInterval = BarInterval.ONE_DAY
    raw_price_basis: TiingoEodRawBasis = TiingoEodRawBasis.DOCUMENTED_RAW_CANDIDATE
    adjusted_price_basis: TiingoEodAdjustedBasis = TiingoEodAdjustedBasis.SPLIT_DIVIDEND_ADJUSTED

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("symbol must use canonical uppercase market notation")
        require_utc(self.interval_start, "interval_start")
        require_utc(self.interval_end, "interval_end")
        require_utc(self.observed_at, "observed_at")
        if self.observed_at < self.interval_end:
            raise ValueError("a completed EOD row cannot be observed before session close")
        if not self.interval.has_valid_span(self.interval_start, self.interval_end):
            raise ValueError("daily row has invalid local interval bounds")
        for value, field_name in (
            (self.open_price, "open_price"),
            (self.high_price, "high_price"),
            (self.low_price, "low_price"),
            (self.close_price, "close_price"),
            (self.adjusted_open_price, "adjusted_open_price"),
            (self.adjusted_high_price, "adjusted_high_price"),
            (self.adjusted_low_price, "adjusted_low_price"),
            (self.adjusted_close_price, "adjusted_close_price"),
        ):
            require_positive_decimal(value, field_name)
        if type(self.volume) is not int or not 0 <= self.volume <= MAX_INT64:
            raise ValueError("volume must be a non-negative int64")
        if type(self.adjusted_volume) is not int or not 0 <= self.adjusted_volume <= MAX_INT64:
            raise ValueError("adjusted_volume must be a non-negative int64")
        if not self.div_cash.is_finite() or self.div_cash < 0:
            raise ValueError("div_cash must be a finite non-negative decimal")
        require_positive_decimal(self.split_factor, "split_factor")
        if self.low_price > min(self.open_price, self.close_price):
            raise ValueError("raw low cannot exceed raw open or close")
        if self.high_price < max(self.open_price, self.close_price):
            raise ValueError("raw high cannot be below raw open or close")
        if self.low_price > self.high_price:
            raise ValueError("raw low cannot exceed raw high")
        if self.adjusted_low_price > min(
            self.adjusted_open_price,
            self.adjusted_close_price,
        ):
            raise ValueError("adjusted low cannot exceed adjusted open or close")
        if self.adjusted_high_price < max(
            self.adjusted_open_price,
            self.adjusted_close_price,
        ):
            raise ValueError("adjusted high cannot be below adjusted open or close")
        if self.adjusted_low_price > self.adjusted_high_price:
            raise ValueError("adjusted low cannot exceed adjusted high")
        require_digest(self.response_sha256, "response_sha256")
        if self.interval is not BarInterval.ONE_DAY:
            raise ValueError("Tiingo EOD rows require the session-defined daily interval")
        if self.raw_price_basis is not TiingoEodRawBasis.DOCUMENTED_RAW_CANDIDATE:
            raise ValueError("Tiingo raw-candidate OHLCV basis must remain explicit")
        if self.adjusted_price_basis is not TiingoEodAdjustedBasis.SPLIT_DIVIDEND_ADJUSTED:
            raise ValueError("Tiingo adjusted OHLCV basis must remain explicit")


@dataclass(frozen=True, slots=True)
class TiingoEodDataset:
    scope: TiingoEodScope
    response_sha256: str
    schema_sha256: str
    calendar_id: str
    calendar_version: str
    calendar_sha256: str
    semantic_sha256: str
    rows: tuple[TiingoEodRow, ...]
    schema_version: str = TIINGO_QUALIFICATION_SCHEMA_VERSION
    qualification_kind: TiingoEodQualificationKind = (
        TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY
    )

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.response_sha256, "response_sha256"),
            (self.schema_sha256, "schema_sha256"),
            (self.calendar_sha256, "calendar_sha256"),
            (self.semantic_sha256, "semantic_sha256"),
        ):
            require_digest(value, field_name)
        require_text(self.calendar_id, "calendar_id")
        require_text(self.calendar_version, "calendar_version")
        if self.schema_version != TIINGO_QUALIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD qualification schema")
        if self.qualification_kind is not TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY:
            raise ValueError("Tiingo EOD qualification is synthetic-contract-only")
        if type(self.rows) is not tuple or not self.rows:
            raise ValueError("Tiingo EOD qualification requires immutable non-empty rows")
        expected = tuple(sorted(self.rows, key=lambda row: (row.symbol, row.session_label)))
        if self.rows != expected:
            raise ValueError("Tiingo EOD rows must use deterministic symbol/session order")

    def raw_bar_records(self) -> NoReturn:
        """Refuse canonical conversion until publication and revision lineage exist."""

        raise TiingoEodError(
            "Tiingo EOD rows contain documented raw-candidate OHLCV but no row "
            "publication timestamp or historical vintage. Immutable authorized captures, "
            "local revision lineage, and venue/identity authority are required before "
            "VendorBarRecord emission."
        )

    def admission_evidence(self) -> NoReturn:
        """Refuse use of a synthetic contract result as provider evidence."""

        raise TiingoEodError(
            "synthetic Tiingo contract qualification is not licensed provider "
            "evidence and has no admission or trading effect"
        )


def _calendar_binding(
    calendar: ExchangeCalendar,
    scope: TiingoEodScope,
) -> tuple[tuple[ExchangeSession, ...], str]:
    if (
        calendar.sessions[0].session_label > scope.start_date
        or calendar.sessions[-1].session_label < scope.end_date
    ):
        raise TiingoEodError("pinned calendar does not cover the complete qualification scope")
    sessions = tuple(
        session
        for session in calendar.sessions
        if scope.start_date <= session.session_label <= scope.end_date
    )
    if not sessions:
        raise TiingoEodError("qualification scope contains no pinned exchange sessions")
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
    return sessions, _digest(material)


def _parse_response(
    observation: TiingoEodResponseObservation,
    *,
    scope: TiingoEodScope,
    calendar: ExchangeCalendar,
) -> tuple[TiingoEodRow, ...]:
    decoded = _json(observation.payload)
    if not isinstance(decoded, list) or not decoded:
        raise TiingoEodError("Tiingo EOD response must be a non-empty JSON array")
    response_sha256 = hashlib.sha256(observation.payload).hexdigest()
    seen_dates: set[date] = set()
    rows: list[TiingoEodRow] = []
    for index, value in enumerate(decoded):
        payload = _object(value, f"rows[{index}]")
        _fields(payload, set(TIINGO_EOD_FIELDS), f"rows[{index}]")
        trading_date = _trading_date(payload["date"], f"rows[{index}].date")
        if trading_date in seen_dates:
            raise TiingoEodError("Tiingo response contains a duplicate session date")
        seen_dates.add(trading_date)
        if not scope.start_date <= trading_date <= scope.end_date:
            raise TiingoEodError(f"rows[{index}] is outside the requested date scope")
        session = calendar.session_for_label(trading_date)
        if session is None:
            raise TiingoEodError(f"rows[{index}] has no pinned exchange session")
        try:
            rows.append(
                TiingoEodRow(
                    symbol=observation.symbol,
                    session_label=trading_date,
                    interval_start=session.opens_at,
                    interval_end=session.closes_at,
                    observed_at=observation.received_at,
                    open_price=_decimal(payload["open"], "open"),
                    high_price=_decimal(payload["high"], "high"),
                    low_price=_decimal(payload["low"], "low"),
                    close_price=_decimal(payload["close"], "close"),
                    volume=_integer(payload["volume"], "volume"),
                    adjusted_open_price=_decimal(payload["adjOpen"], "adjOpen"),
                    adjusted_high_price=_decimal(payload["adjHigh"], "adjHigh"),
                    adjusted_low_price=_decimal(payload["adjLow"], "adjLow"),
                    adjusted_close_price=_decimal(payload["adjClose"], "adjClose"),
                    adjusted_volume=_integer(payload["adjVolume"], "adjVolume"),
                    div_cash=_decimal(payload["divCash"], "divCash", allow_zero=True),
                    split_factor=_decimal(payload["splitFactor"], "splitFactor"),
                    response_sha256=response_sha256,
                )
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"rows[{index}] is invalid: {error}") from error
    return tuple(rows)


def qualify_tiingo_eod(
    responses: tuple[TiingoEodResponseObservation, ...],
    *,
    scope: TiingoEodScope,
    calendar: ExchangeCalendar,
    allowed_symbols: tuple[str, ...] = PHASE1_TIINGO_SYMBOLS,
) -> TiingoEodDataset:
    """Qualify synthetic contract observations without retaining their payloads.

    Every result is permanently marked synthetic-contract-only. A future
    authorized capture must use a separate API and evidence type.
    """

    if type(responses) is not tuple or not responses:
        raise TiingoEodError("qualification requires an immutable non-empty response tuple")
    if not set(scope.symbols).issubset(allowed_symbols):
        raise TiingoEodError("Tiingo qualification scope exceeds the configured allow-list")
    ordered = tuple(sorted(responses, key=lambda response: response.symbol))
    observed_symbols = tuple(response.symbol for response in ordered)
    if len(observed_symbols) != len(set(observed_symbols)):
        raise TiingoEodError("qualification contains duplicate symbol responses")
    if observed_symbols != scope.symbols:
        missing = sorted(set(scope.symbols) - set(observed_symbols))
        unknown = sorted(set(observed_symbols) - set(scope.symbols))
        details: list[str] = []
        if missing:
            details.append(f"missing symbols: {', '.join(missing)}")
        if unknown:
            details.append(f"out-of-scope symbols: {', '.join(unknown)}")
        raise TiingoEodError(f"response symbols do not match scope: {'; '.join(details)}")

    sessions, calendar_sha256 = _calendar_binding(calendar, scope)
    rows: list[TiingoEodRow] = []
    keys: set[tuple[str, date]] = set()
    response_material: list[dict[str, object]] = []
    for observation in ordered:
        payload_sha256 = hashlib.sha256(observation.payload).hexdigest()
        response_material.append(
            {
                "byte_count": len(observation.payload),
                "payload_sha256": payload_sha256,
                "received_at": observation.received_at.isoformat(),
                "requested_at": observation.requested_at.isoformat(),
                "symbol": observation.symbol,
            }
        )
        for row in _parse_response(observation, scope=scope, calendar=calendar):
            key = (row.symbol, row.session_label)
            if key in keys:
                raise TiingoEodError("qualification contains a duplicate symbol/session row")
            keys.add(key)
            rows.append(row)

    expected_keys = {
        (symbol, session.session_label) for symbol in scope.symbols for session in sessions
    }
    missing_keys = sorted(expected_keys - keys)
    if missing_keys:
        first_symbol, first_date = missing_keys[0]
        raise TiingoEodError(
            "Tiingo qualification is missing required session coverage: "
            f"{len(missing_keys)} rows; first {first_symbol}/{first_date.isoformat()}"
        )

    rows.sort(key=lambda row: (row.symbol, row.session_label))
    response_sha256 = _digest(response_material)
    schema_sha256 = _digest(_FIELD_CONTRACT)
    semantic_sha256 = _digest(
        {
            "calendar_sha256": calendar_sha256,
            "dataset": TIINGO_DATASET,
            "provider": TIINGO_PROVIDER,
            "qualification_kind": (TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY.value),
            "response_sha256": response_sha256,
            "schema_sha256": schema_sha256,
            "schema_version": TIINGO_QUALIFICATION_SCHEMA_VERSION,
            "scope": {
                "end_date": scope.end_date.isoformat(),
                "start_date": scope.start_date.isoformat(),
                "symbols": list(scope.symbols),
            },
        }
    )
    return TiingoEodDataset(
        scope=scope,
        response_sha256=response_sha256,
        schema_sha256=schema_sha256,
        calendar_id=calendar.calendar_id,
        calendar_version=calendar.version,
        calendar_sha256=calendar_sha256,
        semantic_sha256=semantic_sha256,
        rows=tuple(rows),
    )
