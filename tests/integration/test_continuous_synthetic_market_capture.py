"""Actual scored synthetic captures with explicit coherent model clocks and no authority."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest
import sqlalchemy as sa

from apps.trader import synthetic_market_capture as capture_join
from apps.trader.synthetic_session_genesis import initialize_synthetic_session
from packages.application import personal_codec as codec
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.application.continuous_source_events import project_continuous_daily_frontier
from packages.application.personal_forward_capture import read_capture
from packages.application.synthetic_capture_scenario import (
    synthetic_daily_capture_scenario,
    synthetic_quote_capture_scenario,
)
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.engine_contracts import DailyPrice
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.models import Side
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import ResearchDataClass, modeled_daily_availability
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_forward_sources import (
    ContinuousForwardSourceError,
    SqlContinuousForwardSources,
)
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import phase5_operational_control_transitions
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured
from tests.unit.test_causal_checkpoint import PINS


def _ns(delta):
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000


def _scenario(
    kind, inputs, *, event_index=0, capture_id=None, calendar_pin=None, producer_pin=None
):
    event = inputs.daily_events[event_index]
    price = event.payload
    session = next(
        value
        for value in inputs.inputs.spec.calendar.sessions
        if value.session_label == price.session
    )
    arguments = {
        "session": session,
        "capture_id": capture_id or f"synthetic-scored-{kind}-{event_index}",
        "account_scope": inputs.inputs.spec.account_id,
        "calendar_pin": calendar_pin
        or VersionPin(
            "synthetic-calendar", "integration-model/1", content_digest(inputs.inputs.spec.calendar)
        ),
        "producer_pin": producer_pin
        or VersionPin("synthetic-producer", "integration-model/1", content_digest("producer")),
        "evidence_class": "synthetic_fixture",
    }
    if kind == "daily":
        return synthetic_daily_capture_scenario(price=price, **arguments)
    return synthetic_quote_capture_scenario(
        instrument_id=price.instrument_id,
        symbol=price.symbol,
        at=session.opens_at,
        bid=Decimal("99.123456789"),
        ask=Decimal("100.987654321"),
        **arguments,
    )


def _samples(scenario, origin):
    # Same exact integer UTC-delta mapping used by the existing warmup join.
    return tuple(
        replace(
            sample,
            monotonic_ns=origin.monotonic_ns + _ns(sample.at - origin.at),
            boot_id=origin.boot_id,
        )
        for sample in scenario.clock_samples
    )


def _call(kind, scenario, samples, ports, **changed):
    admitted_at = samples[-1].at + timedelta(milliseconds=100)
    arguments = {
        "samples": samples,
        "admitted_at": admitted_at,
        **ports,
    }
    if kind == "quote":
        arguments.update(side=Side.BUY, admitted_monotonic_ns=samples[-1].monotonic_ns + 100000000)
    arguments.update(changed)
    function = (
        capture_join.capture_synthetic_daily
        if kind == "daily"
        else capture_join.capture_synthetic_quote
    )
    return function(scenario, **arguments)


def _financial_rows(engine):
    with engine.connect() as connection:
        return tuple(
            tuple(
                tuple(row)
                for row in connection.execute(sa.select(table).order_by(*table.primary_key.columns))
            )
            for table in (
                continuous_account_commits,
                phase5_operational_control_transitions,
                *DAILY_RUNTIME_TABLES,
            )
        )


def _objects(store):
    return tuple((path.name, path.read_bytes()) for path in sorted(store._root.iterdir()))


@pytest.fixture
def market(captured):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    inputs = synthetic_continuous_inputs(fixture="regime", pins=bootstrap.inputs.spec.pins)
    journal = SqlDurableJournal(
        ports["account_engine"], codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
    )
    origin = bootstrap.closure.publications[0].record.verifications[0].sample
    yield {
        "genesis": genesis,
        "inputs": inputs,
        "origin": origin,
        "artifacts": ports["account_artifacts"],
        "engine": ports["account_engine"],
        "capture_ports": {
            "journal": journal,
            "publisher": SqlForwardCapturePublication(ports["account_engine"], journal=journal),
            "artifacts": ports["account_artifacts"],
            "codec": codec,
        },
        "scenario_pins": {
            "calendar_pin": bootstrap.closure.publications[0].record.request.calendar,
            "producer_pin": ports["quote_producer"],
        },
    }


def _owned(result, market):
    sources = SqlContinuousForwardSources(
        market["engine"],
        artifacts=market["artifacts"],
        codec=codec,
        evidence_class="synthetic_fixture",
    )
    resolved = sources.resolve(result.closure)
    sources.require_resolved(resolved)
    assert resolved.state == result.state and resolved.closure == result.closure
    assert len(resolved.reads) == 1
    with pytest.raises(
        ContinuousForwardSourceError, match="OWNED_CAPTURE_SOURCE_RESOLUTION_REQUIRED"
    ):
        sources.require_resolved(replace(resolved))
    return resolved


def test_scored_daily_preserves_actual_price_causality_and_original_sql_projection(market):
    scenario = _scenario("daily", market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    before = _financial_rows(market["engine"])
    result = _call("daily", scenario, samples, market["capture_ports"])
    resolved = _owned(result, market)
    (observed,) = result.state.observations
    expected = market["inputs"].daily_events[0].payload
    assert observed.payload == expected
    assert observed.payload.close_price == Decimal("100.2")
    assert observed.known_at == modeled_daily_availability(expected.session)
    assert expected.session in market["inputs"].inputs.spec.window.scored_sessions
    assert expected.session not in market["inputs"].inputs.spec.window.warmup_sessions
    assert result.publication.record.request == scenario.request
    assert market["artifacts"].read(result.publication.record.raw_object) == scenario.body
    frontier = project_continuous_daily_frontier(
        checkpoint=market["genesis"].restored.checkpoint,
        source_state=resolved.state,
        observation_ids=result.closure.observation_ids,
        frontier_id="actual-scored-daily-frontier",
        admitted_at=result.closure.admitted_at,
        benchmark_instrument_id=expected.instrument_id,
        capture_evidence_class="synthetic_fixture",
    )
    daily = tuple(event for event in frontier.events if isinstance(event.payload, DailyPrice))
    assert len(frontier.events) == 2 and len(daily) == 1
    assert daily[0].payload == expected
    assert daily[0].knowledge_at == result.closure.admitted_at
    assert daily[0].provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert daily[0].provenance.observed_at is None
    assert daily[0].provenance.simulated_available_at == observed.known_at
    assert _financial_rows(market["engine"]) == before


@pytest.mark.parametrize(
    "side,price,basis",
    [
        (Side.BUY, Decimal("100.987654321"), "runtime_quote_ask_v1"),
        (Side.SELL, Decimal("99.123456789"), "runtime_quote_bid_v1"),
    ],
)
def test_exact_quote_side_prices_reach_original_projection_without_financial_changes(
    market, side, price, basis
):
    scenario = _scenario("quote", market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    before = _financial_rows(market["engine"])
    result = _call("quote", scenario, samples, market["capture_ports"], side=side)
    resolved = _owned(result, market)
    assert result.closure.boot_id == market["origin"].boot_id
    assert result.closure.admitted_monotonic_ns == samples[-1].monotonic_ns + 100000000
    assert result.closure.selections[0].side is side
    frontier = project_continuous_quote_frontier(
        checkpoint=market["genesis"].restored.checkpoint,
        closure=result.closure,
        source_state=resolved.state,
    )
    (event,) = frontier.events
    mark = event.payload.payload
    assert mark.price == price and mark.basis == basis
    assert mark.economic_at == scenario.clock_samples[0].at
    assert mark.knowledge_at == samples[-1].at
    assert event.knowledge_at == result.closure.admitted_at
    assert event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert event.provenance.observed_at is None
    assert _financial_rows(market["engine"]) == before


def test_weekend_daily_then_quote_scripts_preserve_one_explicit_utc_monotonic_timeline(market):
    events = market["inputs"].daily_events
    friday = next(
        index for index, event in enumerate(events) if event.payload.session.weekday() == 4
    )
    daily = _scenario("daily", market["inputs"], event_index=friday, **market["scenario_pins"])
    quote = _scenario("quote", market["inputs"], event_index=friday + 1, **market["scenario_pins"])
    first_samples, second_samples = (
        _samples(daily, market["origin"]),
        _samples(quote, market["origin"]),
    )
    before = _financial_rows(market["engine"])
    first = _call("daily", daily, first_samples, market["capture_ports"])
    second = _call("quote", quote, second_samples, market["capture_ports"])
    _owned(first, market)
    _owned(second, market)
    assert first.publication.record.request.session.weekday() == 4
    assert second.publication.record.request.session.weekday() == 0
    assert second_samples[0].at - first_samples[-1].at == timedelta(days=2, hours=13, minutes=30)
    assert second_samples[0].monotonic_ns - first_samples[-1].monotonic_ns == 221400000000000
    assert second_samples[0].boot_id == first_samples[0].boot_id == market["origin"].boot_id
    assert _financial_rows(market["engine"]) == before


def test_retained_quote_does_not_bypass_existing_projection_freshness(market):
    scenario = _scenario("quote", market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    before = _financial_rows(market["engine"])
    admitted_at = samples[-1].at + timedelta(seconds=31)
    result = _call(
        "quote",
        scenario,
        samples,
        market["capture_ports"],
        admitted_at=admitted_at,
        admitted_monotonic_ns=samples[-1].monotonic_ns + 31000000000,
    )
    resolved = _owned(result, market)
    with pytest.raises(ValueError, match="runtime quote unavailable"):
        project_continuous_quote_frontier(
            checkpoint=market["genesis"].restored.checkpoint,
            closure=result.closure,
            source_state=resolved.state,
        )
    assert (
        read_capture(
            scenario.request,
            journal=market["capture_ports"]["journal"],
            artifacts=market["artifacts"],
            codec=codec,
        )
        == result.publication
    )
    assert _financial_rows(market["engine"]) == before


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_exact_repeated_capture_reuses_original_receipt_bytes_and_objects(market, kind):
    scenario = _scenario(kind, market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    first = _call(kind, scenario, samples, market["capture_ports"])
    journal = market["capture_ports"]["journal"]
    head, objects = journal.read_head(scenario.request.journal_key), _objects(market["artifacts"])
    before = _financial_rows(market["engine"])
    repeated = _call(kind, scenario, samples, market["capture_ports"])
    assert repeated == first
    assert journal.read_head(scenario.request.journal_key) == head
    assert _objects(market["artifacts"]) == objects
    assert _financial_rows(market["engine"]) == before


@pytest.mark.parametrize("kind", ["daily", "quote"])
@pytest.mark.parametrize("changed", ["body", "script"])
def test_reused_request_cannot_silently_discard_changed_body_or_script(market, kind, changed):
    scenario = _scenario(kind, market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    original = _call(kind, scenario, samples, market["capture_ports"])
    journal = market["capture_ports"]["journal"]
    head, objects = journal.read_head(scenario.request.journal_key), _objects(market["artifacts"])
    before = _financial_rows(market["engine"])
    if changed == "body":
        scenario = replace(scenario, body=scenario.body + b"\n")
    else:
        samples = tuple(
            replace(sample, monotonic_ns=sample.monotonic_ns + 1000000000) for sample in samples
        )
    with pytest.raises(ValueError, match="synthetic market retained capture inputs differ"):
        _call(kind, scenario, samples, market["capture_ports"])
    assert journal.read_head(scenario.request.journal_key) == head
    assert _objects(market["artifacts"]) == objects
    assert (
        read_capture(
            scenario.request,
            **{key: value for key, value in market["capture_ports"].items() if key != "publisher"},
        )
        == original.publication
    )
    assert _financial_rows(market["engine"]) == before


class ForbiddenPort:
    def __getattribute__(self, name):
        raise AssertionError("invalid scenario reached a supplied capture port")


def _forbidden_ports():
    forbidden = ForbiddenPort()
    return {name: forbidden for name in ("journal", "publisher", "artifacts", "codec")}


@pytest.mark.parametrize("kind", ["daily", "quote"])
@pytest.mark.parametrize(
    "changed",
    [
        "count",
        "list",
        "sample_type",
        "epoch",
        "utc_regression",
        "mono_regression",
        "overflow",
        "boolean",
        "drift",
        "stage_shift",
        "early_admission",
        "naive_admission",
    ],
)
def test_invalid_scripts_fail_before_supplied_port_access(kind, changed):
    inputs = synthetic_continuous_inputs(fixture="regime", pins=PINS)
    scenario = _scenario(kind, inputs)
    samples = scenario.clock_samples
    arguments = {}
    if changed == "count":
        samples = samples[:2]
    elif changed == "list":
        samples = list(samples)
    elif changed == "sample_type":
        samples = (samples[0], object(), samples[-1])
    elif changed == "epoch":
        samples = (*samples[:2], replace(samples[-1], boot_id="foreign-epoch"))
    elif changed == "utc_regression":
        samples = (*samples[:2], replace(samples[-1], at=samples[0].at - timedelta(microseconds=1)))
    elif changed == "mono_regression":
        samples = (*samples[:2], replace(samples[-1], monotonic_ns=samples[0].monotonic_ns - 1))
    elif changed in ("overflow", "boolean"):
        last = replace(samples[-1])
        object.__setattr__(last, "monotonic_ns", 2**63 if changed == "overflow" else True)
        samples = (*samples[:2], last)
    elif changed == "drift":
        samples = (*samples[:2], replace(samples[-1], monotonic_ns=samples[-1].monotonic_ns + 1))
    elif changed == "stage_shift":
        samples = tuple(
            replace(sample, at=sample.at + timedelta(microseconds=1)) for sample in samples
        )
    elif changed == "early_admission":
        arguments["admitted_at"] = samples[-1].at - timedelta(microseconds=1)
    else:
        arguments["admitted_at"] = samples[-1].at.replace(tzinfo=None)
    # _call's default admission reads only the supplied last sample. The exact
    # primitive values above remain test inputs; no capture port is substituted.
    with pytest.raises(ValueError):
        _call(kind, scenario, samples, _forbidden_ports(), **arguments)


@pytest.mark.parametrize("changed", ["side", "boolean", "overflow", "mismatch", "outside_session"])
def test_invalid_quote_selection_or_admission_fails_before_ports(changed):
    inputs = synthetic_continuous_inputs(fixture="regime", pins=PINS)
    scenario = _scenario("quote", inputs)
    samples = scenario.clock_samples
    arguments = {}
    if changed == "side":
        arguments["side"] = "buy"
    elif changed == "boolean":
        arguments["admitted_monotonic_ns"] = True
    elif changed == "overflow":
        arguments["admitted_monotonic_ns"] = 2**63
    elif changed == "mismatch":
        arguments["admitted_monotonic_ns"] = samples[-1].monotonic_ns + 1
    else:
        arguments["admitted_at"] = scenario.request.session_close
    with pytest.raises(ValueError):
        _call("quote", scenario, samples, _forbidden_ports(), **arguments)


@pytest.mark.parametrize("kind", ["daily", "quote"])
@pytest.mark.parametrize(
    "changed", ["wrong_kind", "provider", "state", "body", "pin", "pin_digest"]
)
def test_invalid_scenario_profile_fails_before_supplied_ports(kind, changed):
    inputs = synthetic_continuous_inputs(fixture="regime", pins=PINS)
    scenario = _scenario(kind, inputs)
    if changed == "wrong_kind":
        scenario = _scenario("quote" if kind == "daily" else "daily", inputs)
    elif changed == "provider":
        scenario = replace(
            scenario, request=replace(scenario.request, evidence_class="provider_https_read")
        )
    elif changed == "state":
        # A valid modeled source state is still outside this recorded-capture
        # join. Reach the app's own profile guard without failing fixture setup.
        source = replace(scenario.request.source, provider="fixture", environment="synthetic")
        scenario = replace(scenario, state=ForwardDataState((source,), "modeled"))
    elif changed == "body":
        scenario = replace(scenario, body=b"")
    elif changed == "pin":
        request = replace(scenario.request)
        object.__setattr__(request, "producer", object())
        scenario = replace(scenario, request=request)
    else:
        pin = replace(scenario.request.producer)
        object.__setattr__(pin, "sha256", "not-a-digest")
        request = replace(scenario.request, producer=pin)
        scenario = replace(scenario, request=request)
    expected = (
        r"^synthetic market scenario profile or empty origin differs$"
        if changed == "state"
        else None
    )
    with pytest.raises(ValueError, match=expected):
        _call(kind, scenario, scenario.clock_samples, _forbidden_ports())


@pytest.mark.parametrize("kind", ["daily", "quote"])
@pytest.mark.parametrize("changed", ["journal", "publisher", "codec", "artifacts"])
def test_wrong_capture_graph_cannot_change_capture_or_financial_facts(market, kind, changed):
    scenario = _scenario(kind, market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    journal = market["capture_ports"]["journal"]
    head, objects = journal.read_head(scenario.request.journal_key), _objects(market["artifacts"])
    before = _financial_rows(market["engine"])
    with pytest.raises(ValueError, match="original synthetic market capture ports required"):
        _call(kind, scenario, samples, {**market["capture_ports"], changed: object()})
    assert journal.read_head(scenario.request.journal_key) == head
    assert _objects(market["artifacts"]) == objects
    assert _financial_rows(market["engine"]) == before


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_postcapture_replay_failure_preserves_real_receipt_and_raw_object(
    market, monkeypatch, kind
):
    scenario = _scenario(kind, market["inputs"], **market["scenario_pins"])
    samples = _samples(scenario, market["origin"])
    journal = market["capture_ports"]["journal"]
    head = journal.read_head(scenario.request.journal_key)
    before = _financial_rows(market["engine"])
    calls = []
    failure = RuntimeError("injected application replay failure")

    def fail_replay(*args, **kwargs):
        calls.append((args, kwargs))
        raise failure

    monkeypatch.setattr(capture_join, "replay_continuous_forward_closure", fail_replay)
    with pytest.raises(RuntimeError) as caught:
        _call(kind, scenario, samples, market["capture_ports"])
    assert caught.value is failure and len(calls) == 1
    retained = read_capture(
        scenario.request, journal=journal, artifacts=market["artifacts"], codec=codec
    )
    assert retained is not None
    assert retained.journal_receipt.previous_head == head
    assert journal.read_head(scenario.request.journal_key).sequence == head.sequence + 1
    assert market["artifacts"].read(retained.record.raw_object) == scenario.body
    assert _financial_rows(market["engine"]) == before
