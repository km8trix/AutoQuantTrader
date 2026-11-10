"""Known-value synthetic response scenarios through the unchanged capture collector."""

import json
from dataclasses import replace
from datetime import timedelta
from decimal import ROUND_DOWN, Decimal, localcontext

import pytest

from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureClock,
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application.personal_forward_capture import replay_capture
from packages.application.synthetic_capture_scenario import (
    synthetic_daily_capture_scenario,
    synthetic_quote_capture_scenario,
)
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.forward_capture_contracts import MAX_CAPTURE_BYTES
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import modeled_daily_availability
from tests.unit.test_causal_checkpoint import PINS
from tests.unit.test_personal_forward_capture import Harness


def _daily_values():
    scenario = synthetic_continuous_inputs(fixture="regime", pins=PINS)
    event = scenario.daily_events[0]
    session = next(
        item
        for item in scenario.inputs.spec.calendar.sessions
        if item.session_label == event.payload.session
    )
    return {
        "price": event.payload,
        "session": session,
        "capture_id": "synthetic-scenario-daily",
        "account_scope": scenario.inputs.spec.account_id,
        "calendar_pin": VersionPin(
            "synthetic-calendar", "unit-only/1", content_digest(scenario.inputs.spec.calendar)
        ),
        "producer_pin": VersionPin(
            "synthetic-capture-producer", "unit-only/1", content_digest("synthetic-capture")
        ),
        "evidence_class": "synthetic_fixture",
    }


def _quote_values():
    daily = _daily_values()
    price = daily.pop("price")
    return {
        **daily,
        "instrument_id": price.instrument_id,
        "symbol": price.symbol,
        "at": daily["session"].opens_at,
        "bid": Decimal("99999999999999999.123456789"),
        "ask": Decimal("99999999999999999.223456789"),
        "capture_id": "synthetic-scenario-quote",
    }


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_scenario_source_state_pins_and_all_assumptions_are_explicitly_synthetic(kind):
    values = _daily_values() if kind == "daily" else _quote_values()
    scenario = (
        synthetic_daily_capture_scenario if kind == "daily" else synthetic_quote_capture_scenario
    )(**values)
    req, source = scenario.request, scenario.request.source
    assert req.evidence_class == "synthetic_fixture"
    assert req.kind == kind
    assert source.provider == ("tiingo" if kind == "daily" else "etrade")
    assert source.environment == "production"  # Parser shape, never actual source proof.
    assert source.source_id.startswith("synthetic-capture-")
    assert source.identity_reference.startswith("synthetic-identity-model/")
    assert source.rights_reference.startswith("synthetic-rights-model/")
    assert source.entitlement_reference.startswith("synthetic-entitlement-model/")
    assert req.instruments[0].identity_reference.startswith("synthetic-instrument-USD-model/")
    assert req.calendar is values["calendar_pin"] and req.producer is values["producer_pin"]
    assert req.max_response_bytes == MAX_CAPTURE_BYTES == 2097152
    assert req.deadline_ms == 3000
    assert 0 < len(scenario.body) < req.max_response_bytes
    assert scenario.state.sources == (source,) and scenario.state.mode == "recorded"
    assert not scenario.state.observations and not scenario.state.frontiers
    assert "PROVIDER_ENVIRONMENT_IS_PARSER_SHAPE_NOT_ACTUAL_SOURCE_PROOF" in scenario.assumptions
    assert "NO_NETWORK_OR_EXECUTION_AUTHORITY" in scenario.assumptions
    assert len(scenario.clock_samples) == 3
    assert all(
        sample.boot_id == "synthetic-capture-clock-model/1" for sample in scenario.clock_samples
    )
    assert tuple(sample.monotonic_ns for sample in scenario.clock_samples) == (
        1000000000,
        1100000000,
        1200000000,
    )
    assert tuple(sample.at - scenario.clock_samples[0].at for sample in scenario.clock_samples) == (
        timedelta(0),
        timedelta(milliseconds=100),
        timedelta(milliseconds=200),
    )
    assert (
        req.window_start
        <= scenario.clock_samples[0].at
        < scenario.clock_samples[-1].at
        < req.window_end
    )


def test_daily_known_values_preserve_prices_without_inventing_actions_or_volume():
    values = _daily_values()
    price = replace(
        values["price"],
        open_price=Decimal("99.123456789"),
        close_price=Decimal("100.987654321"),
        adjusted_close=Decimal("100.987654321"),
    )
    scenario = synthetic_daily_capture_scenario(**{**values, "price": price})
    (row,) = json.loads(scenario.body, parse_float=Decimal)
    assert row == {
        "date": price.session.isoformat() + "T00:00:00.000Z",
        "open": Decimal("99.123456789"),
        "high": Decimal("100.987654321"),
        "low": Decimal("99.123456789"),
        "close": Decimal("100.987654321"),
        "adjOpen": Decimal("99.123456789"),
        "adjHigh": Decimal("100.987654321"),
        "adjLow": Decimal("99.123456789"),
        "adjClose": Decimal("100.987654321"),
        "volume": 0,
        "adjVolume": 0,
        "divCash": 0,
        "splitFactor": 1,
    }
    available = modeled_daily_availability(price.session)
    assert scenario.clock_samples[-1].at == available
    assert scenario.clock_samples[0].at == available - timedelta(milliseconds=200)
    assert scenario.clock_samples[0].at > values["session"].closes_at


def test_quote_known_values_keep_decimal_digits_and_exact_source_side_times():
    values = _quote_values()
    scenario = synthetic_quote_capture_scenario(**values)
    document = json.loads(scenario.body, parse_float=Decimal)
    (row,) = document["QuoteResponse"]["QuoteData"]
    assert row["Product"] == {"symbol": "SPY", "securityType": "EQ"}
    assert row["quoteStatus"] == "REALTIME"
    assert row["All"]["bid"] == Decimal("99999999999999999.123456789")
    assert row["All"]["ask"] == Decimal("99999999999999999.223456789")
    assert row["dateTimeUTC"] == 1672842600  # 2023-01-04 14:30:00 UTC.
    assert row["All"]["bidTime"] == row["All"]["askTime"] == "09:30:00 EST 01-04-2023"
    assert scenario.clock_samples[0].at == values["at"]


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_scenarios_conform_to_actual_capture_and_replay_with_synthetic_ports(kind):
    values = _daily_values() if kind == "daily" else _quote_values()
    scenario = (
        synthetic_daily_capture_scenario if kind == "daily" else synthetic_quote_capture_scenario
    )(**values)
    harness = Harness(scenario.request)
    try:
        harness.state = scenario.state
        harness.clock = SyntheticForwardCaptureClock(
            scenario.request, samples=scenario.clock_samples
        )
        harness.verifier = SyntheticForwardCaptureVerifier(
            scenario.request,
            producer=values["producer_pin"],
            valid_until=scenario.request.window_end,
        )
        harness.transport = SyntheticForwardCaptureTransport(scenario.request, body=scenario.body)
        publication = harness.capture()
        record = publication.record
        assert record.live_authorized is False
        assert record.request == scenario.request
        assert harness.objects.read(record.raw_object) == scenario.body
        assert all(proof.evidence_class == "synthetic_fixture" for proof in record.verifications)
        assert "SYNTHETIC_TRANSPORT_NOT_PROVIDER_EVIDENCE" in record.limitations
        (observed,) = record.observations
        assert observed.known_at == scenario.clock_samples[-1].at
        if kind == "daily":
            assert observed.payload == values["price"]
            assert observed.known_at == modeled_daily_availability(values["price"].session)
        else:
            assert observed.payload.bid == values["bid"] and observed.payload.ask == values["ask"]
            assert observed.payload.source_at == values["at"]
            assert observed.payload.bid_at == observed.payload.ask_at == values["at"]
        replayed = replay_capture(record, scenario.state, artifacts=harness.objects)
        assert replayed.observations == (observed,)
    finally:
        harness.journal.engine.dispose()


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_response_and_request_are_deterministic_under_hostile_decimal_context(kind):
    values = _daily_values() if kind == "daily" else _quote_values()
    build = (
        synthetic_daily_capture_scenario if kind == "daily" else synthetic_quote_capture_scenario
    )
    first = build(**values)
    with localcontext() as context:
        context.prec = 2
        context.rounding = ROUND_DOWN
        repeated = build(**values)
    assert repeated == first
    assert repeated.request.semantic_sha256 == first.request.semantic_sha256


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_numeric_response_bytes_ignore_decimal_exponent_capitalization(kind):
    values = _daily_values() if kind == "daily" else _quote_values()
    if kind == "daily":
        values["price"] = replace(
            values["price"],
            open_price=Decimal("100"),
            close_price=Decimal("100"),
            adjusted_close=Decimal("100"),
        )
    else:
        values.update(bid=Decimal("100"), ask=Decimal("101"))
    build = (
        synthetic_daily_capture_scenario if kind == "daily" else synthetic_quote_capture_scenario
    )
    with localcontext() as context:
        context.capitals = 1
        first = build(**values)
        context.capitals = 0
        repeated = build(**values)
    assert repeated.body == first.body
    assert repeated == first


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_provider_evidence_cannot_be_requested_from_synthetic_builder(kind):
    values = _daily_values() if kind == "daily" else _quote_values()
    values["evidence_class"] = "provider_https_read"
    with pytest.raises(ValueError, match="synthetic_fixture"):
        (synthetic_daily_capture_scenario if kind == "daily" else synthetic_quote_capture_scenario)(
            **values
        )


@pytest.mark.parametrize(
    "change", ["session", "adjustment", "revision", "calendar", "symbol", "pin", "capture_id"]
)
def test_daily_scope_and_unsupported_financial_inferences_fail_closed(change):
    values = _daily_values()
    if change == "session":
        values["price"] = replace(
            values["price"], session=values["price"].session + timedelta(days=1)
        )
    elif change == "adjustment":
        values["price"] = replace(values["price"], adjusted_close=Decimal(90))
    elif change == "revision":
        values["price"] = replace(
            values["price"], revision=2, predecessor_revision_id="older-observation"
        )
    elif change == "calendar":
        values["session"] = replace(values["session"], venue="XNYS")
    elif change == "symbol":
        values["price"] = replace(values["price"], symbol="IBM")
    elif change == "pin":
        values["calendar_pin"] = None
    else:
        values["capture_id"] = "x" * 129
    with pytest.raises(ValueError):
        synthetic_daily_capture_scenario(**values)


@pytest.mark.parametrize(
    "bid",
    [99.5, True, Decimal(0), Decimal(-1), Decimal("NaN"), Decimal("Infinity"), Decimal("1e-11")],
)
def test_quote_prices_require_positive_exact_bounded_decimals(bid):
    values = _quote_values()
    values["bid"] = bid
    with pytest.raises(ValueError):
        synthetic_quote_capture_scenario(**values)


@pytest.mark.parametrize(
    "change",
    ["crossed", "before_open", "at_close", "capture_crosses_close", "subsecond", "naive", "symbol"],
)
def test_quote_time_scope_and_crossed_sides_fail_closed(change):
    values = _quote_values()
    if change == "crossed":
        values["bid"], values["ask"] = Decimal(101), Decimal(100)
    elif change == "before_open":
        values["at"] -= timedelta(seconds=1)
    elif change == "at_close":
        values["at"] = values["session"].closes_at
    elif change == "capture_crosses_close":
        values["session"] = replace(
            values["session"], closes_at=values["session"].closes_at.replace(microsecond=100000)
        )
        values["at"] = values["session"].closes_at.replace(microsecond=0)
    elif change == "subsecond":
        values["at"] += timedelta(microseconds=1)
    elif change == "naive":
        values["at"] = values["at"].replace(tzinfo=None)
    else:
        values["symbol"] = "IBM"
    with pytest.raises(ValueError):
        synthetic_quote_capture_scenario(**values)
