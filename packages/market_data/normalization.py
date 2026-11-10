"""Deterministic normalization from provider records to canonical raw bars."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from packages.domain.identifiers import deterministic_id
from packages.market_data.calendar import ExchangeCalendar
from packages.market_data.models import (
    CaptureMode,
    PriceBasis,
    RawBar,
    RevisionPolicy,
    VendorBarRecord,
    require_text,
    to_utc,
)
from packages.market_data.quality import (
    QualityCode,
    QualityIssue,
    QualitySeverity,
    quality_issue,
)
from packages.market_data.security import (
    AmbiguousSecurityError,
    NonTradableSecurityError,
    SecurityMaster,
    UnknownSecurityError,
)


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    bars: tuple[RawBar, ...]
    issues: tuple[QualityIssue, ...]
    received_records: int
    accepted_records: int
    rejected_records: int

    def __post_init__(self) -> None:
        counts = (self.received_records, self.accepted_records, self.rejected_records)
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("normalization counts must be non-negative integers")
        if self.accepted_records != len(self.bars):
            raise ValueError("accepted_records must equal the normalized bar count")
        if self.received_records != self.accepted_records + self.rejected_records:
            raise ValueError("normalization counts do not reconcile")

    @property
    def publishable(self) -> bool:
        return self.rejected_records == 0 and not any(issue.blocking for issue in self.issues)


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _semantic_payload(
    record: VendorBarRecord,
    *,
    security_id: str,
    interval_start: datetime,
    interval_end: datetime,
    vendor_published_at: datetime,
    available_at: datetime,
    schema_version: str,
) -> dict[str, object]:
    # Local receipt/ingestion wall clocks are deliberately excluded. Re-fetching
    # the same vendor fact must retain the same semantic identity.
    return {
        "available_at": available_at.isoformat(),
        "close": _decimal_text(record.close_price),
        "high": _decimal_text(record.high_price),
        "interval": record.interval.value,
        "interval_end": interval_end.isoformat(),
        "interval_start": interval_start.isoformat(),
        "low": _decimal_text(record.low_price),
        "open": _decimal_text(record.open_price),
        "revision": record.revision,
        "schema_version": schema_version,
        "security_id": security_id,
        "source_id": record.source_id,
        "source_record_id": record.source_record_id,
        "source_sequence": record.source_sequence,
        "symbol": record.symbol,
        "trade_count": record.trade_count,
        "vendor_published_at": vendor_published_at.isoformat(),
        "venue": record.venue,
        "volume": record.volume,
    }


def _payload_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _error_code(error: ValueError) -> QualityCode:
    message = str(error).lower()
    if "timezone-aware" in message or "stored in utc" in message:
        return QualityCode.TIMEZONE_INVALID
    if any(token in message for token in ("price", "finite positive decimal")):
        return QualityCode.OHLC_INVALID
    if "session" in message:
        return QualityCode.SESSION_MISMATCH
    return QualityCode.TEMPORAL_INVALID


def _record_issue(
    record: VendorBarRecord,
    code: QualityCode,
    message: str,
    *,
    occurred_at: datetime | None = None,
    security_id: str | None = None,
) -> QualityIssue:
    return quality_issue(
        code,
        QualitySeverity.ERROR,
        message,
        source_id=record.source_id,
        security_id=security_id,
        session_label=record.declared_session_label,
        occurred_at=occurred_at,
        details=(("source_record_id", record.source_record_id),),
    )


def _sort_key(record: VendorBarRecord) -> tuple[str, str, str, str, int, str]:
    logical_key = record.observation_key or (
        f"{record.symbol}:{record.venue}:{record.interval.value}:"
        f"{record.interval_start.isoformat()}"
    )
    return (
        record.source_id,
        logical_key,
        record.symbol,
        record.venue,
        record.revision,
        record.source_record_id,
    )


def normalize_records(
    records: tuple[VendorBarRecord, ...] | list[VendorBarRecord],
    *,
    calendar: ExchangeCalendar,
    security_master: SecurityMaster,
    capture_mode: CaptureMode = CaptureMode.HISTORICAL,
    schema_version: str = "raw-bar-v1",
    identifier_policy: RevisionPolicy = RevisionPolicy.REVISED_AS_OF,
) -> NormalizationResult:
    """Normalize provider records without mutating, filling, or adjusting data.

    Invalid records become explicit blocking quality issues. Missing correction
    lineage is rejected unless the predecessor is present in the same batch or
    the adapter supplies ``supersedes_event_revision_id``.
    """

    require_text(schema_version, "schema_version")
    received_records = len(records)
    bars: list[RawBar] = []
    issues: list[QualityIssue] = []
    revision_ids: dict[tuple[str, int], str] = {}

    for record in sorted(records, key=_sort_key):
        available_at: datetime | None = None
        security_id: str | None = None
        try:
            interval_start = to_utc(record.interval_start, "interval_start")
            interval_end = to_utc(record.interval_end, "interval_end")
            vendor_published_at = to_utc(
                record.vendor_published_at,
                "vendor_published_at",
            )
            ingested_at = to_utc(record.ingested_at, "ingested_at")
            received_at = (
                None if record.received_at is None else to_utc(record.received_at, "received_at")
            )
            if capture_mode is CaptureMode.LIVE and received_at is None:
                raise ValueError("live records require received_at")
            if record.available_at is not None:
                available_at = to_utc(record.available_at, "available_at")
            elif capture_mode is CaptureMode.LIVE:
                if received_at is None:  # pragma: no cover - guarded above for type narrowing
                    raise ValueError("live records require received_at")
                available_at = max(vendor_published_at, received_at)
            else:
                available_at = vendor_published_at

            if not record.interval.has_valid_span(interval_start, interval_end):
                raise ValueError("vendor interval does not match its declared duration")
            session = calendar.session_for_bar(interval_start, interval_end, record.interval)
            if session is None:
                raise ValueError("vendor bar does not match an explicit exchange session")
            if record.declared_session_label is not None and (
                record.declared_session_label != session.session_label
            ):
                raise ValueError("vendor session label conflicts with the exchange calendar")

            security = security_master.resolve_security(
                symbol=record.symbol,
                venue=record.venue,
                effective_at=interval_end,
                as_of=available_at,
                policy=identifier_policy,
                require_tradable=True,
            )
            security_id = security.security_id
            observation_material = record.observation_key or (
                f"{record.source_id}:{security_id}:{record.interval.value}:"
                f"{interval_start.isoformat()}:{interval_end.isoformat()}"
            )
            observation_id = deterministic_id("market-observation", observation_material)
            payload = _semantic_payload(
                record,
                security_id=security_id,
                interval_start=interval_start,
                interval_end=interval_end,
                vendor_published_at=vendor_published_at,
                available_at=available_at,
                schema_version=schema_version,
            )
            payload_sha256 = _payload_sha256(payload)
            event_revision_id = deterministic_id(
                "market-event-revision",
                observation_id,
                record.revision,
                payload_sha256,
            )
            supersedes = record.supersedes_event_revision_id
            if record.revision > 1 and supersedes is None:
                supersedes = revision_ids.get((observation_id, record.revision - 1))
                if supersedes is None:
                    raise ValueError(
                        "correction predecessor is absent from the normalization batch"
                    )

            bar = RawBar(
                observation_id=observation_id,
                event_revision_id=event_revision_id,
                security_id=security_id,
                source_id=record.source_id,
                source_record_id=record.source_record_id,
                source_sequence=record.source_sequence,
                schema_version=schema_version,
                revision=record.revision,
                supersedes_event_revision_id=supersedes,
                payload_sha256=payload_sha256,
                symbol=record.symbol,
                venue=record.venue,
                interval=record.interval,
                price_basis=PriceBasis.RAW,
                interval_start=interval_start,
                interval_end=interval_end,
                event_time=interval_end,
                vendor_published_at=vendor_published_at,
                received_at=received_at,
                available_at=available_at,
                ingested_at=ingested_at,
                capture_mode=capture_mode,
                session_label=session.session_label,
                open_price=record.open_price,
                high_price=record.high_price,
                low_price=record.low_price,
                close_price=record.close_price,
                volume=record.volume,
                trade_count=record.trade_count,
            )
        except NonTradableSecurityError as error:
            issues.append(
                _record_issue(
                    record,
                    QualityCode.NON_TRADABLE,
                    str(error),
                    occurred_at=available_at,
                    security_id=security_id,
                )
            )
            continue
        except UnknownSecurityError as error:
            issues.append(
                _record_issue(
                    record,
                    QualityCode.UNKNOWN_SECURITY,
                    str(error),
                    occurred_at=available_at,
                )
            )
            continue
        except AmbiguousSecurityError as error:
            issues.append(
                _record_issue(
                    record,
                    QualityCode.UNKNOWN_SECURITY,
                    str(error),
                    occurred_at=available_at,
                )
            )
            continue
        except ValueError as error:
            issues.append(
                _record_issue(
                    record,
                    _error_code(error),
                    str(error),
                    occurred_at=available_at,
                    security_id=security_id,
                )
            )
            continue
        bars.append(bar)
        revision_ids[(bar.observation_id, bar.revision)] = bar.event_revision_id

    normalized = tuple(
        sorted(
            bars,
            key=lambda bar: (
                bar.available_at,
                bar.event_time,
                bar.source_id,
                bar.source_sequence if bar.source_sequence is not None else 2**63,
                bar.observation_id,
                bar.revision,
                bar.event_revision_id,
            ),
        )
    )
    stable_issues = tuple(sorted(issues, key=lambda issue: issue.issue_id))
    return NormalizationResult(
        bars=normalized,
        issues=stable_issues,
        received_records=received_records,
        accepted_records=len(normalized),
        rejected_records=received_records - len(normalized),
    )
