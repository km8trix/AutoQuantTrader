"""Strict JSONL historical-source adapter for deterministic admission fixtures."""

from __future__ import annotations

import builtins
import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from packages.market_data import (
    CorporateActionRevision,
    ExchangeCalendar,
    FeedEntitlement,
    HistoricalAdmissionProfile,
    HistoricalSourceBundle,
    SecurityMaster,
)
from packages.market_data.models import BarInterval, VendorBarRecord


class RecordedSourceError(ValueError):
    """A recorded source file is syntactically invalid or violates its contract."""


EXPECTED_FIELDS = {
    "source_id",
    "source_record_id",
    "source_sequence",
    "revision",
    "symbol",
    "venue",
    "interval",
    "interval_start",
    "interval_end",
    "vendor_published_at",
    "received_at",
    "available_at",
    "ingested_at",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "trade_count",
    "declared_session_label",
    "observation_key",
    "supersedes_event_revision_id",
}

REQUIRED_FIELDS = {
    "source_id",
    "source_record_id",
    "source_sequence",
    "revision",
    "symbol",
    "venue",
    "interval",
    "interval_start",
    "interval_end",
    "vendor_published_at",
    "received_at",
    "available_at",
    "ingested_at",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "declared_session_label",
}


def _datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise RecordedSourceError(f"{field_name} must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecordedSourceError(f"{field_name} is not a valid ISO-8601 timestamp") from error


def _optional_datetime(value: object, field_name: str) -> datetime | None:
    return None if value is None else _datetime(value, field_name)


def _decimal(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise RecordedSourceError(f"{field_name} must be a decimal string or number")
    try:
        return Decimal(str(value))
    except ArithmeticError as error:
        raise RecordedSourceError(f"{field_name} is not a valid decimal") from error


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise RecordedSourceError(f"{field_name} must be an integer")
    return value


def _optional_integer(value: object, field_name: str) -> int | None:
    return None if value is None else _integer(value, field_name)


def _optional_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecordedSourceError(f"{field_name} must be a string or null")
    return value


def _record(payload: object, line_number: int) -> VendorBarRecord:
    if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
        raise RecordedSourceError(f"line {line_number} must be a JSON object")
    unknown = set(payload) - EXPECTED_FIELDS
    missing = REQUIRED_FIELDS - set(payload)
    if unknown or missing:
        detail = []
        if unknown:
            detail.append(f"unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            detail.append(f"missing fields: {', '.join(sorted(missing))}")
        raise RecordedSourceError(f"line {line_number} has {'; '.join(detail)}")
    try:
        session_label = payload["declared_session_label"]
        if not isinstance(session_label, str):
            raise RecordedSourceError("declared_session_label must be an ISO date string")
        return VendorBarRecord(
            source_id=str(payload["source_id"]),
            source_record_id=str(payload["source_record_id"]),
            source_sequence=_integer(payload["source_sequence"], "source_sequence"),
            revision=_integer(payload["revision"], "revision"),
            symbol=str(payload["symbol"]),
            venue=str(payload["venue"]),
            interval=BarInterval(str(payload["interval"])),
            interval_start=_datetime(payload["interval_start"], "interval_start"),
            interval_end=_datetime(payload["interval_end"], "interval_end"),
            vendor_published_at=_datetime(payload["vendor_published_at"], "vendor_published_at"),
            received_at=_optional_datetime(payload["received_at"], "received_at"),
            available_at=_optional_datetime(payload["available_at"], "available_at"),
            ingested_at=_datetime(payload["ingested_at"], "ingested_at"),
            open_price=_decimal(payload["open"], "open"),
            high_price=_decimal(payload["high"], "high"),
            low_price=_decimal(payload["low"], "low"),
            close_price=_decimal(payload["close"], "close"),
            volume=_integer(payload["volume"], "volume"),
            trade_count=_optional_integer(payload.get("trade_count"), "trade_count"),
            declared_session_label=date.fromisoformat(session_label),
            observation_key=_optional_string(payload.get("observation_key"), "observation_key"),
            supersedes_event_revision_id=_optional_string(
                payload.get("supersedes_event_revision_id"),
                "supersedes_event_revision_id",
            ),
        )
    except (KeyError, ValueError, TypeError) as error:
        if isinstance(error, RecordedSourceError):
            raise
        raise RecordedSourceError(f"line {line_number} is invalid: {error}") from error


class RecordedJsonlBarSource:
    """Reads a checked-in, unlicensed fixture through a vendor-neutral boundary."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def bytes(self) -> bytes:
        try:
            return self.path.read_bytes()
        except OSError as error:
            raise RecordedSourceError(f"cannot read recorded source {self.path}") from error

    def checksum(self) -> str:
        return hashlib.sha256(self.bytes()).hexdigest()

    @staticmethod
    def _records(payload_bytes: builtins.bytes) -> tuple[VendorBarRecord, ...]:
        rows: list[VendorBarRecord] = []
        for line_number, raw_line in enumerate(payload_bytes.splitlines(), start=1):
            if not raw_line.strip():
                continue
            try:
                payload: Any = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RecordedSourceError(f"line {line_number} is not valid JSON") from error
            rows.append(_record(payload, line_number))
        if not rows:
            raise RecordedSourceError("recorded source contains no records")
        return tuple(rows)

    def records(self) -> tuple[VendorBarRecord, ...]:
        return self._records(self.bytes())

    def snapshot(self) -> tuple[str, tuple[VendorBarRecord, ...]]:
        """Hash and parse the same immutable byte snapshot."""

        payload = self.bytes()
        return hashlib.sha256(payload).hexdigest(), self._records(payload)


class RecordedHistoricalBarSource:
    """Adapt a strict JSONL export and frozen reference facts to the source port."""

    def __init__(
        self,
        path: Path,
        *,
        profile: HistoricalAdmissionProfile,
        security_master: SecurityMaster,
        calendar: ExchangeCalendar,
        corporate_actions: tuple[CorporateActionRevision, ...],
        entitlement: FeedEntitlement,
    ) -> None:
        self._recorded = RecordedJsonlBarSource(path)
        self._profile = profile
        self._security_master = security_master
        self._calendar = calendar
        self._corporate_actions = corporate_actions
        self._entitlement = entitlement

    def load(self) -> HistoricalSourceBundle:
        source_checksum, records = self._recorded.snapshot()
        return HistoricalSourceBundle(
            profile=self._profile,
            source_checksum=source_checksum,
            records=records,
            security_master=self._security_master,
            calendar=self._calendar,
            corporate_actions=self._corporate_actions,
            entitlement=self._entitlement,
        )
