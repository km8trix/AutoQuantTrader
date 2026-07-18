"""Trusted time ports used at risk and execution boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


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

    def now(self) -> datetime:
        return self.instant


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
