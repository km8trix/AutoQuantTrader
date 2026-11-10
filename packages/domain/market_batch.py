"""Provider-neutral contracts for sealed market-decision batches."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from packages.domain.canonical import canonical_decimal_text
from packages.domain.models import MarketEvent

MARKET_BATCH_CONTRACT_VERSION = "phase2-market-batch-v1"


class ReplayRevisionPolicy(StrEnum):
    FIRST_SEEN = "first_seen"
    REVISED_AS_OF = "revised_as_of"


class LateEventPolicy(StrEnum):
    HALT = "halt"


class MissingDataPolicy(StrEnum):
    SKIP = "skip"


class MarketBatchStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


def _require_text(value: str, field_name: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _semantic_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _event_semantics(event: MarketEvent) -> dict[str, object]:
    return {
        "available_at": _utc_text(event.available_at),
        "close_price": canonical_decimal_text(event.close_price),
        "event_id": event.event_id,
        "event_time": _utc_text(event.event_time),
        "instrument_id": event.instrument_id,
        "observation_id": event.observation_key,
        "revision": event.revision,
        "source": event.source,
        "source_sequence": event.source_sequence,
        "supersedes_event_revision_id": event.supersedes_event_revision_id,
        "symbol": event.symbol,
    }


@dataclass(frozen=True, slots=True)
class MarketWatermark:
    """An explicit event-time frontier sealed at one availability-time instant."""

    watermark_id: str
    event_time_through: datetime
    closed_at: datetime
    expected_instrument_ids: tuple[str, ...]
    revision_policy: ReplayRevisionPolicy = ReplayRevisionPolicy.REVISED_AS_OF
    missing_data_policy: MissingDataPolicy = MissingDataPolicy.SKIP
    late_event_policy: LateEventPolicy = LateEventPolicy.HALT

    def __post_init__(self) -> None:
        _require_text(self.watermark_id, "watermark_id")
        _require_utc(self.event_time_through, "event_time_through")
        _require_utc(self.closed_at, "closed_at")
        if self.closed_at < self.event_time_through:
            raise ValueError("watermark closed_at cannot precede its event-time frontier")
        if not self.expected_instrument_ids:
            raise ValueError("watermark requires at least one expected instrument")
        if self.expected_instrument_ids != tuple(sorted(set(self.expected_instrument_ids))):
            raise ValueError("expected instruments must be unique and sorted")
        for instrument_id in self.expected_instrument_ids:
            _require_text(instrument_id, "expected instrument_id")
        if not isinstance(self.revision_policy, ReplayRevisionPolicy):
            raise ValueError("unsupported replay revision policy")
        if self.missing_data_policy is not MissingDataPolicy.SKIP:
            raise ValueError("unsupported missing-data policy")
        if self.late_event_policy is not LateEventPolicy.HALT:
            raise ValueError("unsupported late-event policy")


def _watermark_semantics(watermark: MarketWatermark) -> dict[str, object]:
    return {
        "closed_at": _utc_text(watermark.closed_at),
        "event_time_through": _utc_text(watermark.event_time_through),
        "expected_instrument_ids": list(watermark.expected_instrument_ids),
        "late_event_policy": watermark.late_event_policy.value,
        "missing_data_policy": watermark.missing_data_policy.value,
        "revision_policy": watermark.revision_policy.value,
        "watermark_id": watermark.watermark_id,
    }


def _batch_event_key(event: MarketEvent) -> tuple[object, ...]:
    return (
        event.instrument_id,
        event.source,
        event.source_sequence is None,
        event.source_sequence or 0,
        event.observation_key,
        event.revision,
        event.event_id,
    )


@dataclass(frozen=True, slots=True, init=False)
class MarketBatch:
    """One permanently sealed decision slice produced by a trusted reducer."""

    watermark: MarketWatermark
    events: tuple[MarketEvent, ...]

    def __init__(
        self,
        *args: object,
        **kwargs: object,
    ) -> None:
        del args, kwargs
        raise TypeError("MarketBatch can only be created by the replay reducer")

    def _validate(self) -> None:
        if type(self.events) is not tuple:
            raise ValueError("market batch events must be an immutable tuple")
        if self.events != tuple(sorted(self.events, key=_batch_event_key)):
            raise ValueError("market batch events must use canonical order")
        instrument_ids = tuple(event.instrument_id for event in self.events)
        if len(instrument_ids) != len(set(instrument_ids)):
            raise ValueError("market batch must contain at most one event per instrument")
        expected = set(self.watermark.expected_instrument_ids)
        if not set(instrument_ids).issubset(expected):
            raise ValueError("market batch contains an unexpected instrument")
        for event in self.events:
            _require_utc(event.event_time, "event_time")
            _require_utc(event.available_at, "available_at")
            if event.event_time != self.watermark.event_time_through:
                raise ValueError("market batch event is outside its exact decision slice")
            if event.available_at > self.watermark.closed_at:
                raise ValueError("market batch cannot contain a fact unavailable at its as_of")

    @property
    def as_of(self) -> datetime:
        return self.watermark.closed_at

    @property
    def received_instrument_ids(self) -> tuple[str, ...]:
        return tuple(event.instrument_id for event in self.events)

    @property
    def missing_instrument_ids(self) -> tuple[str, ...]:
        received = set(self.received_instrument_ids)
        return tuple(
            instrument_id
            for instrument_id in self.watermark.expected_instrument_ids
            if instrument_id not in received
        )

    @property
    def status(self) -> MarketBatchStatus:
        if self.missing_instrument_ids:
            return MarketBatchStatus.INCOMPLETE
        return MarketBatchStatus.COMPLETE

    @property
    def complete(self) -> bool:
        return self.status is MarketBatchStatus.COMPLETE

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            {
                "contract_version": MARKET_BATCH_CONTRACT_VERSION,
                "events": [_event_semantics(event) for event in self.events],
                "watermark": _watermark_semantics(self.watermark),
            }
        )

    @property
    def batch_id(self) -> str:
        return f"market-batch-{self.semantic_sha256[:32]}"

    def event_for(self, instrument_id: str) -> MarketEvent:
        for event in self.events:
            if event.instrument_id == instrument_id:
                return event
        raise KeyError(instrument_id)


def _create_market_batch(
    *,
    watermark: MarketWatermark,
    events: tuple[MarketEvent, ...],
) -> MarketBatch:
    """Seal a validated batch; this private capability is reserved for replay."""

    batch = object.__new__(MarketBatch)
    object.__setattr__(batch, "watermark", watermark)
    object.__setattr__(batch, "events", events)
    batch._validate()
    return batch
