"""Synthetic calendar consistency only; no exchange-source or provider authority."""

import hashlib
import json
from dataclasses import asdict, replace
from datetime import UTC, date, datetime, timedelta

import pytest

from packages.adapters.market_data.tiingo_eod import TiingoEodScope
from packages.adapters.market_data.tiingo_eod_import import (
    TiingoImportDeclaration,
    parse_tiingo_research_dataset,
)
from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    require_capture_research_calendar_binding,
)
from packages.domain.forward_capture_contracts import ForwardCaptureRequest
from packages.domain.personal_contracts import VersionPin
from packages.domain.research_dataset import (
    ResearchCalendar,
    ResearchRawObject,
    ResearchSession,
    research_digest,
)
from packages.market_data import ExchangeCalendar, ExchangeSession, SessionKind
from tests.unit.test_personal_forward_capture import request

CASES = (
    (date(2026, 1, 9), 14, 21, SessionKind.REGULAR),
    (date(2026, 7, 9), 13, 20, SessionKind.REGULAR),
    (date(2026, 11, 27), 14, 18, SessionKind.HALF_DAY),
)


def _calendar():
    return ExchangeCalendar(
        "synthetic-calendar",
        "fixture-v1",
        "US-EQUITIES",
        "America/New_York",
        tuple(
            ExchangeSession(
                "US-EQUITIES",
                day,
                datetime(day.year, day.month, day.day, open_hour, 30, tzinfo=UTC),
                datetime(day.year, day.month, day.day, close_hour, tzinfo=UTC),
                kind,
            )
            for day, open_hour, close_hour, kind in CASES
        ),
    )


def _research_calendar():
    return ResearchCalendar(
        "synthetic-calendar",
        "fixture-v1",
        "US-EQUITIES",
        "America/New_York",
        tuple(
            ResearchSession(
                "US-EQUITIES",
                day,
                datetime(day.year, day.month, day.day, open_hour, 30, tzinfo=UTC),
                datetime(day.year, day.month, day.day, close_hour, tzinfo=UTC),
                kind.value,
            )
            for day, open_hour, close_hour, kind in CASES
        ),
    )


def _request(index=0, kind="quote"):
    calendar = _research_calendar()
    session = calendar.sessions[index]
    return request(
        kind,
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.opens_at,
        window_end=session.closes_at,
        calendar=VersionPin(
            calendar.calendar_id, calendar.version, research_digest(asdict(calendar))
        ),
    )


@pytest.mark.parametrize("kind", ("daily", "quote"))
@pytest.mark.parametrize("index", (0, 1, 2))
def test_exact_winter_summer_and_half_day_content_matches(index, kind):
    assert require_capture_research_calendar_binding(_request(index, kind), _calendar()) is None


def test_digest_matches_existing_tiingo_import_projection_and_manifest():
    calendar = _calendar()
    payload = json.dumps(
        [
            {
                "date": session.session_label.isoformat(),
                "open": 100,
                "high": 102,
                "low": 99,
                "close": 101,
                "volume": 1000,
                "adjOpen": 100,
                "adjHigh": 102,
                "adjLow": 99,
                "adjClose": 101,
                "adjVolume": 1000,
                "divCash": 0,
                "splitFactor": 1,
            }
            for session in calendar.sessions
        ]
    ).encode()
    raw = ResearchRawObject("SPY", hashlib.sha256(payload).hexdigest(), payload)
    imported_at = datetime(2026, 11, 28, 16, tzinfo=UTC)
    declaration = TiingoImportDeclaration(
        "synthetic_fixture",
        "fixture-no-provider-rights",
        "fixture-generated-in-test",
        "fixture-reviewer",
        imported_at,
        "fixture-identities",
        "fixture-calendar-reference",
        "fixture-tzdata",
        TiingoEodScope(("SPY",), CASES[0][0], CASES[-1][0]),
        (("SPY", "spy"),),
        (("SPY", raw.sha256),),
        True,
        (("SPY", None, None),),
    )
    dataset = parse_tiingo_research_dataset(
        declaration=declaration,
        calendar=calendar,
        raw_objects=(raw,),
        imported_at=imported_at,
    )
    assert dataset.manifest.calendar == _research_calendar()
    assert tuple(session.kind for session in dataset.manifest.calendar.sessions) == (
        "regular",
        "regular",
        "half_day",
    )
    assert all(type(session.kind) is str for session in dataset.manifest.calendar.sessions)
    assert _request().calendar.sha256 == dataset.manifest.calendar_sha256
    assert dataset.manifest.calendar_sha256 != research_digest(asdict(calendar))
    for index in range(3):
        req = _request(index)
        assert require_capture_research_calendar_binding(req, calendar) is None
        raw_pin = replace(req.calendar, sha256=research_digest(asdict(calendar)))
        with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_BINDING_DIFFERS$"):
            require_capture_research_calendar_binding(replace(req, calendar=raw_pin), calendar)


@pytest.mark.parametrize(
    "field,value", (("name", "other"), ("version", "other"), ("sha256", "b" * 64))
)
def test_wrong_request_calendar_pin_is_rejected(field, value):
    req = _request()
    changed = replace(req, calendar=replace(req.calendar, **{field: value}))
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_BINDING_DIFFERS$"):
        require_capture_research_calendar_binding(changed, _calendar())


@pytest.mark.parametrize(
    "index,field,delta",
    (
        (0, "session_open", timedelta(hours=-1)),
        (0, "session_close", timedelta(hours=-1)),
        (1, "session_open", timedelta(hours=1)),
        (1, "session_close", timedelta(hours=1)),
        (2, "session_close", timedelta(hours=3)),
        (2, "session_open", timedelta(minutes=1)),
    ),
)
def test_wrong_dst_offset_or_half_day_interval_is_rejected(index, field, delta):
    req = _request(index)
    changed = replace(req, **{field: getattr(req, field) + delta})
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_SESSION_DIFFERS$"):
        require_capture_research_calendar_binding(changed, _calendar())


def test_missing_session_is_rejected():
    req = replace(_request(), session=date(2026, 1, 10))
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_SESSION_DIFFERS$"):
        require_capture_research_calendar_binding(req, _calendar())


@pytest.mark.parametrize("field,value", (("calendar_id", "other"), ("version", "other")))
def test_wrong_calendar_identity_rejected_even_with_its_content_digest(field, value):
    calendar = replace(_calendar(), **{field: value})
    projected = replace(_research_calendar(), **{field: value})
    req = _request()
    req = replace(req, calendar=replace(req.calendar, sha256=research_digest(asdict(projected))))
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_BINDING_DIFFERS$"):
        require_capture_research_calendar_binding(req, calendar)


@pytest.mark.parametrize("index", (0, 1))
@pytest.mark.parametrize("field", ("opens_at", "closes_at", "kind"))
def test_selected_and_unselected_nested_mutation_requires_original_digest(index, field):
    calendar = _calendar()
    req = _request()
    session = calendar.sessions[index]
    original = getattr(session, field)
    changed = SessionKind.HALF_DAY if field == "kind" else original + timedelta(minutes=1)
    assert require_capture_research_calendar_binding(req, calendar) is None
    object.__setattr__(session, field, changed)
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_BINDING_DIFFERS$"):
        require_capture_research_calendar_binding(req, calendar)
    object.__setattr__(session, field, original)
    assert require_capture_research_calendar_binding(req, calendar) is None


@pytest.mark.parametrize("field,value", (("name", ""), ("version", ""), ("sha256", "invalid")))
def test_mutated_nested_request_pin_is_revalidated(field, value):
    req = _request()
    object.__setattr__(req.calendar, field, value)
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_INVALID$"):
        require_capture_research_calendar_binding(req, _calendar())


@pytest.mark.parametrize(
    "target,field,value",
    (
        ("calendar", "sessions", ()),
        ("calendar", "timezone", "UTC"),
        ("calendar", "venue", "OTHER"),
        ("session", "kind", "regular"),
        ("session", "venue", "OTHER"),
        ("session", "session_label", date(2026, 1, 10)),
        ("session", "opens_at", datetime(2026, 1, 9, 14, 30)),
        ("session", "closes_at", datetime(2026, 1, 9, 13, tzinfo=UTC)),
        ("request", "session", "2026-01-09"),
        ("request", "session_open", datetime(2026, 1, 9, 14, 30)),
    ),
)
def test_invalid_post_construction_mutations_are_denied(target, field, value):
    calendar = _calendar()
    req = _request()
    item = {"calendar": calendar, "session": calendar.sessions[0], "request": req}[target]
    object.__setattr__(item, field, value)
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_INVALID$"):
        require_capture_research_calendar_binding(req, calendar)


@pytest.mark.parametrize("target", ("calendar", "session", "sessions", "request"))
def test_exact_existing_contract_types_are_required(target):
    class CalendarSubclass(ExchangeCalendar):
        pass

    class SessionSubclass(ExchangeSession):
        pass

    class RequestSubclass(ForwardCaptureRequest):
        pass

    calendar = _calendar()
    req = _request()
    if target == "calendar":
        calendar = CalendarSubclass(**{name: getattr(calendar, name) for name in asdict(calendar)})
    elif target == "session":
        session = calendar.sessions[0]
        changed = SessionSubclass(**asdict(session))
        calendar = replace(calendar, sessions=(changed, *calendar.sessions[1:]))
    elif target == "sessions":
        object.__setattr__(calendar, "sessions", list(calendar.sessions))
    else:
        req = RequestSubclass(**{name: getattr(req, name) for name in asdict(req)})
    with pytest.raises(ForwardCaptureError, match=r"^CAPTURE_CALENDAR_INVALID$"):
        require_capture_research_calendar_binding(req, calendar)


@pytest.mark.parametrize("evidence_class", ("synthetic_fixture", "provider_https_read"))
def test_equal_copied_content_passes_without_conveying_source_authority(evidence_class):
    original = replace(_request(), evidence_class=evidence_class)
    copied = replace(original, calendar=replace(original.calendar))
    calendar = _calendar()
    copied_calendar = replace(calendar, sessions=tuple(replace(s) for s in calendar.sessions))
    assert copied == original and copied is not original
    assert copied.calendar is not original.calendar
    assert copied_calendar == calendar and copied_calendar is not calendar
    assert require_capture_research_calendar_binding(copied, copied_calendar) is None
    assert copied.evidence_class == evidence_class
    assert copied.semantic_sha256 == original.semantic_sha256
