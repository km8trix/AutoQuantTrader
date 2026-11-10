"""Trusted time ports used at risk and execution boundaries."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from packages.domain.canonical import canonical_json_bytes

CLOCK_EVENT_CONTRACT_VERSION = "phase2-clock-event-v1"


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class FixedClock:
    instant: datetime

    def __post_init__(self) -> None:
        if self.instant.tzinfo is None or self.instant.utcoffset() is None:
            raise ValueError("fixed clock instant must be timezone-aware")
        if self.instant.utcoffset() != UTC.utcoffset(self.instant):
            raise ValueError("fixed clock instant must be UTC")

    def now(self) -> datetime:
        return self.instant


@dataclass(frozen=True, slots=True)
class ClockEvent:
    """One explicit callback instant from a versioned deterministic schedule."""

    clock_event_id: str
    schedule_id: str
    scheduled_at: datetime
    sequence: int

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.clock_event_id, "clock event ID"),
            (self.schedule_id, "clock schedule ID"),
        ):
            if type(value) is not str or not value or value != value.strip():
                raise ValueError(f"{field_name} must be a non-empty, trimmed string")
        if self.scheduled_at.tzinfo is None or self.scheduled_at.utcoffset() is None:
            raise ValueError("clock event scheduled_at must be timezone-aware")
        if self.scheduled_at.utcoffset() != UTC.utcoffset(self.scheduled_at):
            raise ValueError("clock event scheduled_at must be UTC")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("clock event sequence must be a non-negative integer")

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    CLOCK_EVENT_CONTRACT_VERSION,
                    self.clock_event_id,
                    self.schedule_id,
                    self.scheduled_at,
                    self.sequence,
                )
            )
        ).hexdigest()


class SimulatedClock:
    """A UTC-only clock that can advance but can never travel backwards."""

    __slots__ = ("_instant",)

    def __init__(self, start_at: datetime) -> None:
        self._require_utc(start_at)
        self._instant = start_at

    @staticmethod
    def _require_utc(instant: datetime) -> None:
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("simulated clock instant must be timezone-aware")
        if instant.utcoffset() != UTC.utcoffset(instant):
            raise ValueError("simulated clock instant must be UTC")

    def now(self) -> datetime:
        return self._instant

    def advance_to(self, instant: datetime) -> datetime:
        self._require_utc(instant)
        if instant < self._instant:
            raise ValueError("simulated clock cannot move backwards")
        self._instant = instant
        return self._instant
