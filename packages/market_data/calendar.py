"""Explicit, versioned exchange sessions used by normalization and replay."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from packages.market_data.models import BarInterval, require_text, require_utc


class SessionKind(StrEnum):
    REGULAR = "regular"
    HALF_DAY = "half_day"


@dataclass(frozen=True, slots=True)
class ExchangeSession:
    venue: str
    session_label: date
    opens_at: datetime
    closes_at: datetime
    kind: SessionKind = SessionKind.REGULAR

    def __post_init__(self) -> None:
        require_text(self.venue, "venue")
        if self.venue != self.venue.upper():
            raise ValueError("venue must use its canonical uppercase form")
        require_utc(self.opens_at, "opens_at")
        require_utc(self.closes_at, "closes_at")
        if self.closes_at <= self.opens_at:
            raise ValueError("closes_at must follow opens_at")

    def contains(self, instant: datetime) -> bool:
        require_utc(instant, "instant")
        return self.opens_at <= instant < self.closes_at

    def contains_interval(self, start: datetime, end: datetime) -> bool:
        require_utc(start, "start")
        require_utc(end, "end")
        return self.opens_at <= start < end <= self.closes_at

    def expected_starts(self, interval: BarInterval) -> tuple[datetime, ...]:
        duration = interval.duration
        session_duration = self.closes_at - self.opens_at
        if session_duration % duration:
            raise ValueError("session duration is not divisible by the requested interval")
        count = session_duration // duration
        return tuple(self.opens_at + index * duration for index in range(count))


@dataclass(frozen=True, slots=True)
class ExchangeCalendar:
    calendar_id: str
    version: str
    venue: str
    timezone: str
    sessions: tuple[ExchangeSession, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.calendar_id, "calendar_id"),
            (self.version, "version"),
            (self.venue, "venue"),
            (self.timezone, "timezone"),
        ):
            require_text(value, field_name)
        if self.venue != self.venue.upper():
            raise ValueError("venue must use its canonical uppercase form")
        try:
            timezone = ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError(f"unknown exchange timezone: {self.timezone}") from error
        if not self.sessions:
            raise ValueError("an exchange calendar requires at least one explicit session")
        expected_order = tuple(sorted(self.sessions, key=lambda session: session.session_label))
        if self.sessions != expected_order:
            raise ValueError("calendar sessions must be sorted by session_label")
        labels: set[date] = set()
        previous: ExchangeSession | None = None
        for session in self.sessions:
            if session.venue != self.venue:
                raise ValueError("calendar session venue does not match its calendar")
            if session.session_label in labels:
                raise ValueError("calendar session labels must be unique")
            labels.add(session.session_label)
            if session.opens_at.astimezone(timezone).date() != session.session_label:
                raise ValueError("session_label does not match the exchange-local open date")
            if previous is not None and session.opens_at < previous.closes_at:
                raise ValueError("calendar sessions cannot overlap")
            previous = session

    def session_for_label(self, session_label: date) -> ExchangeSession | None:
        return next(
            (session for session in self.sessions if session.session_label == session_label),
            None,
        )

    def session_for_instant(self, instant: datetime) -> ExchangeSession | None:
        require_utc(instant, "instant")
        return next((session for session in self.sessions if session.contains(instant)), None)

    def session_for_interval(
        self,
        start: datetime,
        end: datetime,
    ) -> ExchangeSession | None:
        require_utc(start, "start")
        require_utc(end, "end")
        return next(
            (session for session in self.sessions if session.contains_interval(start, end)),
            None,
        )

    def expected_starts(
        self,
        session_label: date,
        interval: BarInterval,
    ) -> tuple[datetime, ...]:
        session = self.session_for_label(session_label)
        if session is None:
            raise KeyError(f"unknown session label: {session_label.isoformat()}")
        return session.expected_starts(interval)
