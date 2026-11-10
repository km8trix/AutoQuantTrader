"""Typed causal triggers for deterministic strategy decisions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from packages.domain.canonical import canonical_json_bytes

if TYPE_CHECKING:
    from packages.domain.clock import ClockEvent
    from packages.domain.market_batch import MarketBatch

DECISION_TRIGGER_CONTRACT_VERSION = "phase2-decision-trigger-v1"


class DecisionTriggerKind(StrEnum):
    MARKET_BATCH = "market_batch"
    CLOCK = "clock"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty, trimmed string")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class DecisionTrigger:
    """One exact market-batch or clock-event cause visible to a strategy."""

    kind: DecisionTriggerKind
    trigger_id: str
    trigger_sha256: str
    as_of: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.kind, DecisionTriggerKind):
            raise ValueError("decision trigger kind is unsupported")
        _require_text(self.trigger_id, "decision trigger ID")
        _require_sha256(self.trigger_sha256, "decision trigger digest")
        _require_utc(self.as_of, "decision trigger as_of")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                DECISION_TRIGGER_CONTRACT_VERSION,
                self.kind,
                self.trigger_id,
                self.trigger_sha256,
                self.as_of,
            )
        )

    @classmethod
    def from_market_batch(cls, batch: MarketBatch) -> DecisionTrigger:
        return cls(
            kind=DecisionTriggerKind.MARKET_BATCH,
            trigger_id=batch.batch_id,
            trigger_sha256=batch.semantic_sha256,
            as_of=batch.as_of,
        )

    @classmethod
    def from_clock_event(cls, event: ClockEvent) -> DecisionTrigger:
        return cls(
            kind=DecisionTriggerKind.CLOCK,
            trigger_id=event.clock_event_id,
            trigger_sha256=event.semantic_sha256,
            as_of=event.scheduled_at,
        )

    def require_market_batch(self, batch: MarketBatch) -> None:
        if self.kind is not DecisionTriggerKind.MARKET_BATCH:
            raise ValueError("decision trigger is not a market batch")
        if self.trigger_id != batch.batch_id:
            raise ValueError("decision trigger is not bound to the supplied market batch ID")
        if self.trigger_sha256 != batch.semantic_sha256:
            raise ValueError("decision trigger is not bound to the supplied market batch digest")
        if self.as_of != batch.as_of:
            raise ValueError("decision trigger and market batch must share the same as_of")
        if not batch.complete:
            raise ValueError("strategy cannot receive an incomplete market batch")

    def require_clock_event(self, event: ClockEvent) -> None:
        if self.kind is not DecisionTriggerKind.CLOCK:
            raise ValueError("decision trigger is not a clock event")
        if self.trigger_id != event.clock_event_id:
            raise ValueError("decision trigger is not bound to the supplied clock-event ID")
        if self.trigger_sha256 != event.semantic_sha256:
            raise ValueError("decision trigger is not bound to the supplied clock-event digest")
        if self.as_of != event.scheduled_at:
            raise ValueError("decision trigger and clock event must share the same as_of")
