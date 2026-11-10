from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, cast

import pytest

from packages.adapters.market_data.tiingo_eod import (
    TIINGO_DATASET,
    TIINGO_PROVIDER,
    TiingoEodAcquisitionProfile,
    TiingoEodError,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
    TIINGO_EOD_PINNED_CALENDAR_SCHEMA_VERSION,
    TiingoEodPinnedCalendar,
    TiingoEodPinnedCalendarArtifact,
)
from packages.market_data import ExchangeCalendar, ExchangeSession, SessionKind

START_DATE = date(2026, 7, 13)
MISSING_DATE = date(2026, 7, 14)
END_DATE = date(2026, 7, 15)
PROFILE_REVIEWED_AT = datetime(2026, 6, 30, 12, tzinfo=UTC)
ARTIFACT_REVIEWED_AT = datetime(2026, 7, 1, 12, tzinfo=UTC)
REQUESTED_AT = datetime(2026, 7, 16, 12, tzinfo=UTC)
CALENDAR_AUTHORITY = "reviewed-us-equities-calendar-v1"


def acquisition_profile(
    *,
    approved: bool = True,
    scope: TiingoEodScope | None = None,
    reviewed_at: datetime = PROFILE_REVIEWED_AT,
    calendar_authority: str = CALENDAR_AUTHORITY,
) -> TiingoEodAcquisitionProfile:
    return TiingoEodAcquisitionProfile(
        scope=scope
        or TiingoEodScope(
            symbols=("QQQ", "SPY"),
            start_date=START_DATE,
            end_date=END_DATE,
        ),
        profile_id="reviewed-tiingo-profile",
        approved=approved,
        reviewer_id="profile-reviewer",
        reviewed_at=reviewed_at,
        source_id="tiingo-eod-rest",
        adapter_version="tiingo-eod-capture-v2",
        market_provenance="tiingo-eod-us-market",
        identifier_authority="tiingo-ticker-mapping-v1",
        calendar_authority=calendar_authority,
        corporate_action_authority="tiingo-eod-actions-v1",
        correction_policy="first-observed-local-revisions-v1",
    )


def exchange_calendar(
    symbol: str,
    *,
    scope_start: date = START_DATE,
    scope_end: date = END_DATE,
) -> ExchangeCalendar:
    venue = "XNAS" if symbol == "QQQ" else "XNYS"
    labels = (scope_start,) if scope_start == scope_end else (scope_start, scope_end)
    sessions = tuple(
        ExchangeSession(
            venue=venue,
            session_label=label,
            opens_at=datetime(label.year, label.month, label.day, 13, 30, tzinfo=UTC),
            closes_at=datetime(label.year, label.month, label.day, 20, tzinfo=UTC),
            kind=SessionKind.REGULAR,
        )
        for label in labels
    )
    return ExchangeCalendar(
        calendar_id=f"{venue.lower()}-{symbol.lower()}-calendar",
        version="2026a-reviewed",
        venue=venue,
        timezone="America/New_York",
        sessions=sessions,
    )


def pinned_calendars(scope: TiingoEodScope) -> tuple[TiingoEodPinnedCalendar, ...]:
    return tuple(
        TiingoEodPinnedCalendar(
            symbol=symbol,
            calendar=exchange_calendar(
                symbol,
                scope_start=scope.start_date,
                scope_end=scope.end_date,
            ),
        )
        for symbol in scope.symbols
    )


def calendar_artifact(
    *,
    profile: TiingoEodAcquisitionProfile | None = None,
    approved: bool = True,
    reviewed_at: datetime = ARTIFACT_REVIEWED_AT,
    profile_contract_sha256: str | None = None,
    calendar_authority: str | None = None,
    scope: TiingoEodScope | None = None,
    calendars: tuple[TiingoEodPinnedCalendar, ...] | None = None,
) -> TiingoEodPinnedCalendarArtifact:
    selected_profile = profile or acquisition_profile()
    selected_scope = scope or selected_profile.scope
    return TiingoEodPinnedCalendarArtifact(
        artifact_id="reviewed-tiingo-calendar-artifact",
        approved=approved,
        reviewer_id="calendar-reviewer",
        reviewed_at=reviewed_at,
        profile_contract_sha256=(profile_contract_sha256 or selected_profile.contract_sha256),
        calendar_authority=(calendar_authority or selected_profile.calendar_authority),
        tzdata_version="2026a",
        scope=selected_scope,
        calendars=calendars or pinned_calendars(selected_scope),
    )


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def artifact_payload() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(calendar_artifact().to_json_bytes()))


def test_canonical_round_trip_digest_and_explicit_non_session_date() -> None:
    artifact = calendar_artifact()
    encoded = artifact.to_json_bytes()

    parsed = TiingoEodPinnedCalendarArtifact.from_json_bytes(encoded)

    assert parsed == artifact
    assert parsed.schema_version == TIINGO_EOD_PINNED_CALENDAR_SCHEMA_VERSION
    assert parsed.provider == TIINGO_PROVIDER
    assert parsed.dataset == TIINGO_DATASET
    assert encoded.endswith(b"\n")
    assert parsed.artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    assert tuple(parsed.calendars_by_symbol) == parsed.scope.symbols
    assert all(
        calendar.session_for_label(MISSING_DATE) is None
        for calendar in parsed.calendars_by_symbol.values()
    )


def test_calendars_by_symbol_is_read_only() -> None:
    mapping = calendar_artifact().calendars_by_symbol

    with pytest.raises(TypeError):
        mapping["SPY"] = exchange_calendar("SPY")  # type: ignore[index]


@pytest.mark.parametrize(
    "requested_at",
    [ARTIFACT_REVIEWED_AT, REQUESTED_AT],
)
def test_authorize_accepts_review_boundaries(requested_at: datetime) -> None:
    profile = acquisition_profile()
    calendar_artifact(profile=profile).authorize(profile, requested_at=requested_at)


@pytest.mark.parametrize("payload", [b"", bytearray(b"{}"), "{}"])
def test_parser_requires_non_empty_immutable_bytes(payload: object) -> None:
    with pytest.raises(TiingoEodError, match="non-empty immutable bytes"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(payload)  # type: ignore[arg-type]


def test_parser_rejects_oversized_bytes_before_json_parsing() -> None:
    payload = b" " * (MAX_TIINGO_CALENDAR_ARTIFACT_BYTES + 1)

    with pytest.raises(TiingoEodError, match="exceeds the size limit"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(payload)


@pytest.mark.parametrize(
    "presentation",
    [
        lambda payload: json.dumps(json.loads(payload)).encode(),
        lambda payload: payload.rstrip(b"\n"),
        lambda payload: payload.replace(b"\n", b"\r\n"),
        lambda payload: b" " + payload,
    ],
)
def test_parser_rejects_noncanonical_presentation(presentation: object) -> None:
    encoded = calendar_artifact().to_json_bytes()
    mutate = cast(Any, presentation)

    with pytest.raises(TiingoEodError, match="not canonically encoded"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(mutate(encoded))


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            b'  "approved": true,\n',
            b'  "approved": true,\n  "approved": true,\n',
        ),
        (
            b'      "symbol": "QQQ"\n',
            b'      "symbol": "QQQ",\n      "symbol": "QQQ"\n',
        ),
        (
            b'        "timezone": "America/New_York",\n',
            b'        "timezone": "America/New_York",\n        "timezone": "America/New_York",\n',
        ),
        (
            b'            "venue": "XNAS"\n',
            b'            "venue": "XNAS",\n            "venue": "XNAS"\n',
        ),
    ],
)
def test_parser_rejects_duplicate_keys_at_every_nesting_level(
    needle: bytes,
    replacement: bytes,
) -> None:
    encoded = calendar_artifact().to_json_bytes()
    assert encoded.count(needle) >= 1

    with pytest.raises(TiingoEodError, match="duplicate JSON key"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(encoded.replace(needle, replacement, 1))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update({"unexpected": True}), "unknown fields"),
        (lambda value: value.pop("artifact_id"), "missing fields"),
        (
            lambda value: value["calendars"][0].update({"unexpected": True}),
            "unknown fields",
        ),
        (
            lambda value: value["calendars"][0].pop("symbol"),
            "missing fields",
        ),
        (
            lambda value: value["calendars"][0]["calendar"].update({"unexpected": True}),
            "unknown fields",
        ),
        (
            lambda value: value["calendars"][0]["calendar"].pop("timezone"),
            "missing fields",
        ),
        (
            lambda value: value["calendars"][0]["calendar"]["sessions"][0].update(
                {"unexpected": True}
            ),
            "unknown fields",
        ),
        (
            lambda value: value["calendars"][0]["calendar"]["sessions"][0].pop("kind"),
            "missing fields",
        ),
    ],
)
def test_parser_rejects_unknown_and_missing_fields(mutate: Any, message: str) -> None:
    payload = artifact_payload()
    mutate(payload)

    with pytest.raises(TiingoEodError, match=message):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize(
    "profile_digest",
    ["0" * 64, "A" * 64, "1" * 63, "not-a-digest"],
)
def test_profile_digest_must_be_nonzero_lowercase_sha256(profile_digest: str) -> None:
    payload = artifact_payload()
    payload["profile_contract_sha256"] = profile_digest

    with pytest.raises(TiingoEodError, match="profile_contract_sha256"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("schema_version", "tiingo-eod-pinned-calendar-v2", "unsupported"),
        ("provider", "other-provider", "does not identify Tiingo EOD"),
        ("dataset", "other-dataset", "does not identify Tiingo EOD"),
        ("approved", 1, "must be boolean"),
    ],
)
def test_frozen_identity_and_approval_types_are_exact(
    field: str,
    replacement: object,
    message: str,
) -> None:
    payload = artifact_payload()
    payload[field] = replacement

    with pytest.raises(TiingoEodError, match=message):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize("shape", [None, {}, "not-an-array"])
def test_calendars_must_be_a_non_empty_array(shape: object) -> None:
    payload = artifact_payload()
    payload["calendars"] = [] if shape is None else shape

    with pytest.raises(TiingoEodError, match="calendars"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize("shape", [None, {}, "not-an-array"])
def test_sessions_must_be_a_non_empty_array(shape: object) -> None:
    payload = artifact_payload()
    payload["calendars"][0]["calendar"]["sessions"] = [] if shape is None else shape

    with pytest.raises(TiingoEodError, match=r"sessions|explicit session"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize("case", ["reversed", "missing", "extra", "duplicate"])
def test_calendar_entries_must_exactly_match_sorted_scope_symbols(case: str) -> None:
    payload = artifact_payload()
    entries = payload["calendars"]
    if case == "reversed":
        entries.reverse()
    elif case == "missing":
        entries.pop()
    elif case == "extra":
        extra = json.loads(json.dumps(entries[-1]))
        extra["symbol"] = "IWM"
        entries.append(extra)
    else:
        entries[-1]["symbol"] = entries[0]["symbol"]

    with pytest.raises(TiingoEodError, match="exactly match the sorted scope symbols"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


@pytest.mark.parametrize("outside_date", [date(2026, 7, 12), date(2026, 7, 16)])
def test_sessions_outside_the_reviewed_scope_are_rejected(outside_date: date) -> None:
    scope = TiingoEodScope(symbols=("SPY",), start_date=START_DATE, end_date=END_DATE)
    calendar = exchange_calendar("SPY", scope_start=outside_date, scope_end=outside_date)

    with pytest.raises(ValueError, match="contained within the reviewed scope"):
        calendar_artifact(
            scope=scope,
            calendars=(TiingoEodPinnedCalendar(symbol="SPY", calendar=calendar),),
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda calendar: calendar.update({"timezone": "Mars/Olympus_Mons"}),
            "unknown exchange timezone",
        ),
        (lambda calendar: calendar.update({"venue": "xnas"}), "canonical uppercase"),
        (
            lambda calendar: calendar["sessions"][0].update({"venue": "XNYS"}),
            "venue does not match",
        ),
        (
            lambda calendar: calendar["sessions"][0].update({"kind": "early_close"}),
            "kind is unsupported",
        ),
        (
            lambda calendar: calendar.update({"sessions": list(reversed(calendar["sessions"]))}),
            "sorted by session_label",
        ),
        (
            lambda calendar: calendar["sessions"][1].update(
                {"session_label": calendar["sessions"][0]["session_label"]}
            ),
            "sorted by session_label|unique",
        ),
        (
            lambda calendar: calendar["sessions"][0].update(
                {
                    "closes_at": calendar["sessions"][0]["opens_at"],
                }
            ),
            "closes_at must follow opens_at",
        ),
        (
            lambda calendar: calendar["sessions"][0].update(
                {"opens_at": "2026-07-13T13:30:00-04:00"}
            ),
            "UTC timestamp",
        ),
        (
            lambda calendar: calendar["sessions"][0].update({"session_label": "2026-07-12"}),
            "exchange-local open date",
        ),
        (
            lambda calendar: calendar["sessions"][1].update({"closes_at": "2026-07-16T20:00:00Z"}),
            "valid one-day interval span",
        ),
    ],
)
def test_core_calendar_invariants_are_enforced(mutate: Any, message: str) -> None:
    payload = artifact_payload()
    calendar = payload["calendars"][0]["calendar"]
    mutate(calendar)

    with pytest.raises(TiingoEodError, match=message):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


def test_overlapping_sessions_are_rejected_by_core_calendar_model() -> None:
    payload = artifact_payload()
    calendar = payload["calendars"][0]["calendar"]
    first, second = calendar["sessions"]
    first["closes_at"] = "2026-07-15T14:00:00Z"
    second["opens_at"] = "2026-07-15T13:30:00Z"

    with pytest.raises(TiingoEodError, match="cannot overlap"):
        TiingoEodPinnedCalendarArtifact.from_json_bytes(canonical_json(payload))


def test_direct_entry_rejects_kind_not_validated_by_core_constructor() -> None:
    session = ExchangeSession(
        venue="XNYS",
        session_label=START_DATE,
        opens_at=datetime(2026, 7, 13, 13, 30, tzinfo=UTC),
        closes_at=datetime(2026, 7, 13, 20, tzinfo=UTC),
        kind=cast(SessionKind, "regular"),
    )
    calendar = ExchangeCalendar(
        calendar_id="direct-invalid-kind",
        version="1",
        venue="XNYS",
        timezone="America/New_York",
        sessions=(session,),
    )

    with pytest.raises(ValueError, match="supported SessionKind"):
        TiingoEodPinnedCalendar(symbol="SPY", calendar=calendar)


@pytest.mark.parametrize("symbol", ["spy", "SP Y", "_SPY", ""])
def test_direct_entry_requires_canonical_market_symbol(symbol: str) -> None:
    with pytest.raises(ValueError, match=r"canonical uppercase market notation|non-empty"):
        TiingoEodPinnedCalendar(symbol=symbol, calendar=exchange_calendar("SPY"))


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        ("profile-unapproved", "acquisition profile has not been approved"),
        ("artifact-unapproved", "artifact has not been approved"),
        ("profile-digest", "does not bind the acquisition profile"),
        ("authority", "authority does not match"),
        ("scope", "scope does not match"),
        ("profile-timeline", "predates the reviewed acquisition profile"),
        ("artifact-timeline", "has not yet been reviewed"),
    ],
)
def test_authorize_fails_closed_for_every_review_binding(setup: str, message: str) -> None:
    profile = acquisition_profile()
    artifact = calendar_artifact(profile=profile)
    requested_at = REQUESTED_AT
    if setup == "profile-unapproved":
        profile = acquisition_profile(approved=False)
        artifact = calendar_artifact(profile=profile)
    elif setup == "artifact-unapproved":
        artifact = replace(artifact, approved=False)
    elif setup == "profile-digest":
        artifact = replace(artifact, profile_contract_sha256="1" * 64)
    elif setup == "authority":
        artifact = replace(artifact, calendar_authority="different-calendar-authority")
    elif setup == "scope":
        other_scope = TiingoEodScope(
            symbols=("SPY",),
            start_date=START_DATE,
            end_date=END_DATE,
        )
        artifact = calendar_artifact(
            profile=profile,
            scope=other_scope,
            calendars=pinned_calendars(other_scope),
        )
    elif setup == "profile-timeline":
        profile = acquisition_profile(reviewed_at=ARTIFACT_REVIEWED_AT + timedelta(days=1))
        artifact = calendar_artifact(profile=profile, reviewed_at=ARTIFACT_REVIEWED_AT)
    else:
        requested_at = ARTIFACT_REVIEWED_AT - timedelta(seconds=1)

    with pytest.raises(ValueError, match=message):
        artifact.authorize(profile, requested_at=requested_at)


def test_authorize_requires_a_utc_request_time() -> None:
    profile = acquisition_profile()

    with pytest.raises(ValueError, match="timezone-aware"):
        calendar_artifact(profile=profile).authorize(
            profile,
            requested_at=REQUESTED_AT.replace(tzinfo=None),
        )


def test_artifact_cannot_exceed_its_serialization_bound() -> None:
    profile = acquisition_profile()

    with pytest.raises(ValueError, match="exceeds the size limit"):
        replace(
            calendar_artifact(profile=profile),
            reviewer_id="r" * MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
        )
