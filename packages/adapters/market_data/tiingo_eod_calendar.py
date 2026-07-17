"""Portable, reviewed exchange calendars for offline Tiingo EOD verification.

The artifact is deliberately self-contained: every session used to interpret a
capture is serialized explicitly. Dates in the reviewed scope that are absent
from a symbol's calendar are reviewed non-session dates; consumers must never
infer additional sessions from a process-local calendar package.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import cast

from packages.adapters.market_data.tiingo_eod import (
    _SYMBOL,
    TIINGO_DATASET,
    TIINGO_PROVIDER,
    TiingoEodAcquisitionProfile,
    TiingoEodError,
    TiingoEodScope,
    _boolean,
    _date,
    _datetime,
    _fields,
    _json,
    _object,
    _text,
    _timestamp,
)
from packages.market_data import BarInterval, ExchangeCalendar, ExchangeSession, SessionKind
from packages.market_data.models import require_digest, require_text, require_utc

TIINGO_EOD_PINNED_CALENDAR_SCHEMA_VERSION = "tiingo-eod-pinned-calendar-v1"
MAX_TIINGO_CALENDAR_ARTIFACT_BYTES = 1_048_576


def _array(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise TiingoEodError(f"{field_name} must be a JSON array")
    return cast(list[object], value)


def _session_to_dict(session: ExchangeSession) -> dict[str, object]:
    return {
        "closes_at": _timestamp(session.closes_at),
        "kind": session.kind.value,
        "opens_at": _timestamp(session.opens_at),
        "session_label": session.session_label.isoformat(),
        "venue": session.venue,
    }


def _session_from_dict(value: object, field_name: str) -> ExchangeSession:
    payload = _object(value, field_name)
    _fields(
        payload,
        {"venue", "session_label", "opens_at", "closes_at", "kind"},
        field_name,
    )
    kind_value = _text(payload["kind"], f"{field_name}.kind")
    try:
        kind = SessionKind(kind_value)
    except ValueError as error:
        raise TiingoEodError(f"{field_name}.kind is unsupported: {kind_value!r}") from error
    try:
        return ExchangeSession(
            venue=_text(payload["venue"], f"{field_name}.venue"),
            session_label=_date(payload["session_label"], f"{field_name}.session_label"),
            opens_at=_datetime(payload["opens_at"], f"{field_name}.opens_at"),
            closes_at=_datetime(payload["closes_at"], f"{field_name}.closes_at"),
            kind=kind,
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"{field_name} is invalid: {error}") from error


def _calendar_to_dict(calendar: ExchangeCalendar) -> dict[str, object]:
    return {
        "calendar_id": calendar.calendar_id,
        "sessions": [_session_to_dict(session) for session in calendar.sessions],
        "timezone": calendar.timezone,
        "venue": calendar.venue,
        "version": calendar.version,
    }


def _calendar_from_dict(value: object, field_name: str) -> ExchangeCalendar:
    payload = _object(value, field_name)
    _fields(
        payload,
        {"calendar_id", "version", "venue", "timezone", "sessions"},
        field_name,
    )
    session_values = _array(payload["sessions"], f"{field_name}.sessions")
    sessions = tuple(
        _session_from_dict(session, f"{field_name}.sessions[{index}]")
        for index, session in enumerate(session_values)
    )
    try:
        return ExchangeCalendar(
            calendar_id=_text(payload["calendar_id"], f"{field_name}.calendar_id"),
            version=_text(payload["version"], f"{field_name}.version"),
            venue=_text(payload["venue"], f"{field_name}.venue"),
            timezone=_text(payload["timezone"], f"{field_name}.timezone"),
            sessions=sessions,
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"{field_name} is invalid: {error}") from error


@dataclass(frozen=True, slots=True)
class TiingoEodPinnedCalendar:
    """One symbol's exact exchange calendar within a reviewed artifact."""

    symbol: str
    calendar: ExchangeCalendar

    def __post_init__(self) -> None:
        if type(self.symbol) is not str:
            raise ValueError("calendar symbol must be a string")
        require_text(self.symbol, "calendar symbol")
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("calendar symbol must use canonical uppercase market notation")
        if type(self.calendar) is not ExchangeCalendar:
            raise ValueError("calendar must be an exact ExchangeCalendar")
        if any(type(session) is not ExchangeSession for session in self.calendar.sessions):
            raise ValueError("calendar sessions must be exact ExchangeSession values")
        if any(type(session.kind) is not SessionKind for session in self.calendar.sessions):
            raise ValueError("calendar session kind must be a supported SessionKind")
        try:
            ExchangeCalendar(
                calendar_id=self.calendar.calendar_id,
                version=self.calendar.version,
                venue=self.calendar.venue,
                timezone=self.calendar.timezone,
                sessions=self.calendar.sessions,
            )
        except ValueError as error:
            raise ValueError(f"calendar is invalid: {error}") from error

    def to_dict(self) -> dict[str, object]:
        return {
            "calendar": _calendar_to_dict(self.calendar),
            "symbol": self.symbol,
        }

    @classmethod
    def from_dict(
        cls, value: object, *, field_name: str = "calendar entry"
    ) -> TiingoEodPinnedCalendar:
        payload = _object(value, field_name)
        _fields(payload, {"symbol", "calendar"}, field_name)
        try:
            return cls(
                symbol=_text(payload["symbol"], f"{field_name}.symbol"),
                calendar=_calendar_from_dict(payload["calendar"], f"{field_name}.calendar"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"{field_name} is invalid: {error}") from error


@dataclass(frozen=True, slots=True)
class TiingoEodPinnedCalendarArtifact:
    """Canonical, approval-bound calendars for one exact Tiingo EOD scope."""

    artifact_id: str
    approved: bool
    reviewer_id: str
    reviewed_at: datetime
    profile_contract_sha256: str
    calendar_authority: str
    tzdata_version: str
    scope: TiingoEodScope
    calendars: tuple[TiingoEodPinnedCalendar, ...]
    schema_version: str = TIINGO_EOD_PINNED_CALENDAR_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.artifact_id, "artifact_id"),
            (self.reviewer_id, "reviewer_id"),
            (self.calendar_authority, "calendar_authority"),
            (self.tzdata_version, "tzdata_version"),
        ):
            if type(value) is not str:
                raise ValueError(f"{field_name} must be a string")
            require_text(value, field_name)
        if type(self.approved) is not bool:
            raise ValueError("approved must be boolean")
        require_utc(self.reviewed_at, "reviewed_at")
        require_digest(self.profile_contract_sha256, "profile_contract_sha256")
        if self.profile_contract_sha256 == "0" * 64:
            raise ValueError("profile_contract_sha256 must identify the reviewed profile")
        if type(self.scope) is not TiingoEodScope:
            raise ValueError("scope must be an exact TiingoEodScope")
        if self.schema_version != TIINGO_EOD_PINNED_CALENDAR_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD pinned-calendar schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("pinned-calendar artifact does not identify Tiingo EOD")
        if type(self.calendars) is not tuple or not self.calendars:
            raise ValueError("calendars must be a non-empty immutable tuple")
        if any(type(entry) is not TiingoEodPinnedCalendar for entry in self.calendars):
            raise ValueError("calendars must contain exact TiingoEodPinnedCalendar values")
        calendar_symbols = tuple(entry.symbol for entry in self.calendars)
        if calendar_symbols != self.scope.symbols:
            raise ValueError("calendar symbols must exactly match the sorted scope symbols")
        for entry in self.calendars:
            if any(
                session.session_label < self.scope.start_date
                or session.session_label > self.scope.end_date
                for session in entry.calendar.sessions
            ):
                raise ValueError("calendar sessions must be contained within the reviewed scope")
            if any(
                not BarInterval.ONE_DAY.has_valid_span(session.opens_at, session.closes_at)
                for session in entry.calendar.sessions
            ):
                raise ValueError("calendar sessions must have a valid one-day interval span")
        if len(self.to_json_bytes()) > MAX_TIINGO_CALENDAR_ARTIFACT_BYTES:
            raise ValueError("pinned-calendar artifact exceeds the size limit")

    @property
    def artifact_sha256(self) -> str:
        """Hash the one canonical byte representation accepted by the parser."""

        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    @property
    def calendars_by_symbol(self) -> Mapping[str, ExchangeCalendar]:
        return MappingProxyType({entry.symbol: entry.calendar for entry in self.calendars})

    def authorize(
        self,
        profile: TiingoEodAcquisitionProfile,
        *,
        requested_at: datetime,
    ) -> None:
        """Authorize use for an exact profile and request time or fail closed."""

        require_utc(requested_at, "requested_at")
        if type(profile) is not TiingoEodAcquisitionProfile:
            raise ValueError("profile must be an exact TiingoEodAcquisitionProfile")
        if not profile.approved:
            raise ValueError("acquisition profile has not been approved")
        if not self.approved:
            raise ValueError("pinned-calendar artifact has not been approved")
        if profile.contract_sha256 != self.profile_contract_sha256:
            raise ValueError("pinned-calendar artifact does not bind the acquisition profile")
        if profile.calendar_authority != self.calendar_authority:
            raise ValueError("pinned-calendar authority does not match the acquisition profile")
        if profile.scope != self.scope:
            raise ValueError("pinned-calendar scope does not match the acquisition profile")
        if profile.reviewed_at > self.reviewed_at:
            raise ValueError("pinned-calendar artifact predates the reviewed acquisition profile")
        if self.reviewed_at > requested_at:
            raise ValueError("pinned-calendar artifact has not yet been reviewed")

    def to_dict(self) -> dict[str, object]:
        return {
            "approved": self.approved,
            "artifact_id": self.artifact_id,
            "calendar_authority": self.calendar_authority,
            "calendars": [entry.to_dict() for entry in self.calendars],
            "dataset": self.dataset,
            "profile_contract_sha256": self.profile_contract_sha256,
            "provider": self.provider,
            "reviewed_at": _timestamp(self.reviewed_at),
            "reviewer_id": self.reviewer_id,
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "tzdata_version": self.tzdata_version,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodPinnedCalendarArtifact:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("pinned-calendar artifact must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_CALENDAR_ARTIFACT_BYTES:
            raise TiingoEodError("pinned-calendar artifact exceeds the size limit")
        payload = _object(_json(payload_bytes), "pinned-calendar artifact")
        expected = {
            "approved",
            "artifact_id",
            "calendar_authority",
            "calendars",
            "dataset",
            "profile_contract_sha256",
            "provider",
            "reviewed_at",
            "reviewer_id",
            "schema_version",
            "scope",
            "tzdata_version",
        }
        _fields(payload, expected, "pinned-calendar artifact")
        calendar_values = _array(payload["calendars"], "calendars")
        try:
            artifact = cls(
                artifact_id=_text(payload["artifact_id"], "artifact_id"),
                approved=_boolean(payload["approved"], "approved"),
                reviewer_id=_text(payload["reviewer_id"], "reviewer_id"),
                reviewed_at=_datetime(payload["reviewed_at"], "reviewed_at"),
                profile_contract_sha256=_text(
                    payload["profile_contract_sha256"],
                    "profile_contract_sha256",
                ),
                calendar_authority=_text(payload["calendar_authority"], "calendar_authority"),
                tzdata_version=_text(payload["tzdata_version"], "tzdata_version"),
                scope=TiingoEodScope.from_dict(payload["scope"]),
                calendars=tuple(
                    TiingoEodPinnedCalendar.from_dict(
                        calendar,
                        field_name=f"calendars[{index}]",
                    )
                    for index, calendar in enumerate(calendar_values)
                ),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error
        if artifact.to_json_bytes() != payload_bytes:
            raise TiingoEodError("pinned-calendar artifact is not canonically encoded")
        return artifact
