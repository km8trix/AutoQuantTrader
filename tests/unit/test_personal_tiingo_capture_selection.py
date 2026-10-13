"""Synthetic record matching only; passing never qualifies a genuine source."""

import socket
import subprocess
from dataclasses import asdict, replace
from datetime import UTC, date, datetime, timedelta

import pytest

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_PROFILE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_calendar import TiingoEodPinnedCalendarArtifact
from packages.application.personal_forward_capture import ForwardCaptureError
from packages.application.personal_tiingo_capture_selection import (
    TiingoCaptureSelectionError,
    require_tiingo_capture_selection,
)
from packages.domain.personal_contracts import VersionPin
from packages.domain.research_dataset import ResearchCalendar, ResearchSession, research_digest
from tests.unit.test_personal_forward_capture import Harness, request
from tests.unit.test_tiingo_eod_capture import authorization, calendar_artifact, profile

AT = datetime(2026, 7, 14, 21, tzinfo=UTC)


def _selection():
    selected_profile = profile()
    selected_authorization = authorization(selected_profile)
    selected_calendar = calendar_artifact(selected_profile)
    calendar = selected_calendar.calendars_by_symbol["SPY"]
    projected = ResearchCalendar(
        calendar.calendar_id,
        calendar.version,
        calendar.venue,
        calendar.timezone,
        tuple(
            ResearchSession(
                entry.venue,
                entry.session_label,
                entry.opens_at,
                entry.closes_at,
                entry.kind.value,
            )
            for entry in calendar.sessions
        ),
    )
    session = calendar.sessions[0]
    selected_request = request(
        "daily",
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.closes_at,
        window_end=AT + timedelta(hours=1),
        calendar=VersionPin(
            projected.calendar_id, projected.version, research_digest(asdict(projected))
        ),
    )
    return selected_request, {
        "profile": selected_profile,
        "authorization": selected_authorization,
        "calendar": selected_calendar,
        "requested_at": AT,
    }


def _source(requested, **changes):
    source = replace(requested.source, **changes)
    return replace(
        requested,
        source=source,
        journal_key=replace(
            requested.journal_key,
            source_provider=source.provider,
            source_environment=source.environment,
            source_scope_sha256=source.semantic_sha256,
            account_scope=source.account_scope,
        ),
    )


def test_existing_profile_authorization_and_symbol_calendar_match_without_effects(monkeypatch):
    requested, selected = _selection()
    original = (
        requested.semantic_sha256,
        *(value.to_json_bytes() for value in list(selected.values())[:3]),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("selection must not contact a provider or start a process")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert require_tiingo_capture_selection(requested, **selected) is None
    assert original == (
        requested.semantic_sha256,
        *(value.to_json_bytes() for value in list(selected.values())[:3]),
    )


@pytest.mark.parametrize("record", ["request", "profile", "authorization", "calendar"])
def test_missing_or_wrong_record_is_rejected_before_its_methods(record):
    requested, selected = _selection()

    class WrongRecord:
        def __getattribute__(self, name):
            raise AssertionError("must reject a foreign record before invoking methods")

    if record == "request":
        requested = WrongRecord()
    else:
        selected[record] = WrongRecord()
    with pytest.raises(TiingoCaptureSelectionError, match="RECORD_TYPE_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


@pytest.mark.parametrize(
    "change",
    [
        {"rights_status": "denied"},
        {"rights_status": "unknown"},
        {"entitlement_status": "unknown"},
        {"entitlement_status": "realtime"},
        {"entitlement_status": "delayed"},
        {"identity_reference": None},
        {"rights_reference": None},
        {"entitlement_reference": None},
    ],
)
def test_missing_or_unavailable_source_declarations_reject(change):
    requested, selected = _selection()
    with pytest.raises(TiingoCaptureSelectionError, match="SOURCE_DECLARATION_UNAVAILABLE"):
        require_tiingo_capture_selection(_source(requested, **change), **selected)


def test_quote_request_is_not_a_tiingo_daily_selection():
    _, selected = _selection()
    with pytest.raises(TiingoCaptureSelectionError, match="DAILY_SOURCE_REQUIRED"):
        require_tiingo_capture_selection(request("quote"), **selected)


@pytest.mark.parametrize("when", [AT - timedelta(hours=1, microseconds=1), AT + timedelta(hours=1)])
def test_request_window_start_is_inclusive_and_end_exclusive(when):
    requested, selected = _selection()
    selected["requested_at"] = when
    with pytest.raises(TiingoCaptureSelectionError, match="REQUEST_OUTSIDE_WINDOW"):
        require_tiingo_capture_selection(requested, **selected)
    selected["requested_at"] = requested.window_start
    assert require_tiingo_capture_selection(requested, **selected) is None


@pytest.mark.parametrize(
    "record,change",
    [
        ("profile", {"approved": False}),
        ("profile", {"reviewed_at": AT + timedelta(seconds=1)}),
        ("authorization", {"reviewed_at": AT + timedelta(seconds=1)}),
        ("authorization", {"reviewed_at": datetime(2026, 6, 29, tzinfo=UTC)}),
        ("authorization", {"profile_contract_sha256": "c" * 64}),
        ("authorization", {"permits_local_snapshot_storage": False}),
        ("authorization", {"permits_research_use": False}),
        ("authorization", {"effective_from": date(2026, 7, 15)}),
        ("authorization", {"effective_through": date(2026, 7, 13)}),
        ("calendar", {"approved": False}),
        ("calendar", {"reviewed_at": AT + timedelta(seconds=1)}),
        ("calendar", {"reviewed_at": datetime(2026, 6, 29, tzinfo=UTC)}),
        ("calendar", {"profile_contract_sha256": "c" * 64}),
        ("calendar", {"calendar_authority": "another-calendar-authority"}),
    ],
)
def test_existing_approval_scope_and_chronology_checks_remain_required(record, change):
    requested, selected = _selection()
    selected[record] = replace(selected[record], **change)
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


def test_coverage_dates_are_not_reinterpreted_as_request_time_expiry():
    requested, selected = _selection()
    selected["authorization"] = replace(
        selected["authorization"], effective_through=requested.session
    )
    later = AT + timedelta(days=1)
    requested = replace(requested, window_start=later, window_end=later + timedelta(seconds=3))
    selected["requested_at"] = later
    assert require_tiingo_capture_selection(requested, **selected) is None


@pytest.mark.parametrize("outside", ["symbol", "before", "after"])
def test_requested_symbol_and_data_session_must_be_in_profile_scope(outside):
    requested, selected = _selection()
    if outside == "symbol":
        requested = replace(
            requested, instruments=(replace(requested.instruments[0], symbol="QQQ"),)
        )
    else:
        requested = replace(
            requested, session=requested.session + timedelta(days=-1 if outside == "before" else 1)
        )
    with pytest.raises(TiingoCaptureSelectionError, match="REQUEST_OUTSIDE_SCOPE"):
        require_tiingo_capture_selection(requested, **selected)


@pytest.mark.parametrize("field", ["sha256", "name", "version"])
def test_request_must_use_selected_calendar_content_and_identity(field):
    requested, selected = _selection()
    changed = "d" * 64 if field == "sha256" else "different"
    requested = replace(requested, calendar=replace(requested.calendar, **{field: changed}))
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


@pytest.mark.parametrize("field", ["session_open", "session_close"])
def test_selected_session_boundaries_must_match_calendar(field):
    requested, selected = _selection()
    requested = replace(requested, **{field: getattr(requested, field) + timedelta(minutes=1)})
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


@pytest.mark.parametrize("fault", ["unselected_session", "scope", "instrument", "profile"])
def test_mutated_nested_content_is_revalidated_on_every_call(fault):
    requested, selected = _selection()
    assert require_tiingo_capture_selection(requested, **selected) is None
    if fault == "unselected_session":
        session = selected["calendar"].calendars_by_symbol["DIA"].sessions[0]
        object.__setattr__(session, "closes_at", session.opens_at)
    elif fault == "scope":
        object.__setattr__(selected["profile"].scope, "symbols", ("NOT-APPROVED",))
    elif fault == "instrument":
        object.__setattr__(requested.instruments[0], "currency", "EUR")
    else:
        object.__setattr__(selected["profile"], "endpoint_template", "private-unreviewed-url")
    with pytest.raises(TiingoCaptureSelectionError) as error:
        require_tiingo_capture_selection(requested, **selected)
    assert "private" not in str(error.value)
    assert error.value.__cause__ is None


def test_equal_reconstructed_records_pass_without_becoming_source_authority():
    requested, selected = _selection()
    copies = {
        "profile": TiingoEodAcquisitionProfile.from_json_bytes(selected["profile"].to_json_bytes()),
        "authorization": TiingoEodCaptureAuthorization.from_json_bytes(
            selected["authorization"].to_json_bytes()
        ),
        "calendar": TiingoEodPinnedCalendarArtifact.from_json_bytes(
            selected["calendar"].to_json_bytes()
        ),
        "requested_at": selected["requested_at"],
    }
    assert copies["profile"] is not selected["profile"]
    assert require_tiingo_capture_selection(requested, **copies) is None
    genuine_shaped = replace(requested, evidence_class="provider_https_read")
    assert require_tiingo_capture_selection(genuine_shaped, **copies) is None
    harness = Harness(genuine_shaped)
    try:
        with pytest.raises(ForwardCaptureError, match="CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED"):
            harness.capture()
        assert harness.clock.calls == harness.transport.calls == harness.objects.writes == 0
        assert harness.verifier.calls == [] and not harness.journal.entries
    finally:
        harness.journal.engine.dispose()


def test_profile_calendar_scope_disagreement_is_not_narrowed_to_requested_symbol():
    requested, selected = _selection()
    other = profile(capture_scope=TiingoEodScope(("SPY",), requested.session, requested.session))
    selected["calendar"] = calendar_artifact(other)
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


@pytest.mark.parametrize("when", [None, AT.replace(tzinfo=None), AT.date()])
def test_request_time_requires_exact_aware_utc_datetime(when):
    requested, selected = _selection()
    selected["requested_at"] = when
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)


def test_existing_profile_byte_limit_is_preserved():
    requested, selected = _selection()
    selected["profile"] = replace(
        selected["profile"], market_provenance="x" * (MAX_TIINGO_PROFILE_BYTES + 1)
    )
    with pytest.raises(TiingoCaptureSelectionError, match="TIINGO_SELECTION_INVALID"):
        require_tiingo_capture_selection(requested, **selected)
