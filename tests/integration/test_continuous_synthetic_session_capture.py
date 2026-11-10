"""Actual synthetic warmup capture/replay without account or control initialization."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from apps.trader.synthetic_session_capture import capture_synthetic_bootstrap
from packages.application import personal_codec
from packages.application.continuous_source_events import compile_continuous_bootstrap
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.engine_contracts import BenchmarkPrice, DailyPrice
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import ResearchDataClass, modeled_daily_availability
from packages.persistence.continuous_forward_sources import (
    ContinuousForwardSourceError,
    SqlContinuousForwardSources,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata
from tests.unit.test_causal_checkpoint import PINS
from tests.unit.test_personal_forward_capture import Objects


@pytest.fixture
def ports():
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    journal = SqlDurableJournal(
        engine, codec=personal_codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
    )
    try:
        yield engine, journal, SqlForwardCapturePublication(engine, journal=journal), Objects()
    finally:
        engine.dispose()


def _pins(inputs):
    return {
        "calendar_pin": VersionPin(
            "synthetic-calendar", "unit-only/1", content_digest(inputs.inputs.spec.calendar)
        ),
        "producer_pin": VersionPin(
            "synthetic-capture", "unit-only/1", content_digest("capture-model")
        ),
    }


def _capture(inputs, ports):
    _engine, journal, publisher, objects = ports
    return capture_synthetic_bootstrap(
        inputs,
        **_pins(inputs),
        journal=journal,
        publisher=publisher,
        artifacts=objects,
        codec=personal_codec,
    )


@pytest.mark.parametrize(
    "fixture,expected",
    [("flat", (Decimal(100), Decimal(100))), ("regime", (Decimal(100), Decimal("100.1")))],
)
def test_actual_warmup_compiles_exact_synthetic_values_without_scored_capture(
    ports, fixture, expected
):
    synthetic = synthetic_continuous_inputs(fixture=fixture, pins=PINS)
    result = _capture(synthetic, ports)
    spec = synthetic.inputs.spec
    assert replace(result.inputs.spec, bootstrap_events_sha256=spec.bootstrap_events_sha256) == spec
    assert result.inputs.initial_state == synthetic.inputs.initial_state
    assert result.inputs.spec.live_authorized is False
    assert result.closure.evidence_class == "synthetic_fixture"
    assert result.closure.admitted_at == spec.initialized_at
    sessions = tuple(
        publication.record.request.session for publication in result.closure.publications
    )
    assert sessions == spec.window.warmup_sessions
    assert not set(sessions) & set(spec.window.scored_sessions)
    observations = sorted(result.state.observations, key=lambda value: value.payload.session)
    assert tuple(value.payload.close_price for value in observations) == expected
    for observed in observations:
        assert observed.known_at == modeled_daily_availability(observed.payload.session)
    daily = sorted(
        (
            event
            for event in result.inputs.bootstrap_events
            if isinstance(event.payload, DailyPrice)
        ),
        key=lambda event: event.payload.session,
    )
    assert tuple(event.payload.close_price for event in daily) == expected
    assert (
        len(result.inputs.bootstrap_events) == 4
    )  # Daily plus existing SPY benchmark normalization.
    for event in daily:
        assert event.knowledge_at == spec.initialized_at
        assert event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
        assert event.provenance.observed_at is None
        assert event.provenance.simulated_available_at == modeled_daily_availability(
            event.payload.session
        )
        assert event.provenance.assumption_id == "synthetic-capture-replay/1"
    assert result.inputs.spec.bootstrap_events_sha256 == content_digest(
        result.inputs.bootstrap_events
    )


def test_actual_original_sources_resolve_and_equal_copies_do_not_own_the_graph(ports):
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS)
    result = _capture(synthetic, ports)
    engine, _journal, _publisher, objects = ports
    source = SqlContinuousForwardSources(
        engine, artifacts=objects, codec=personal_codec, evidence_class="synthetic_fixture"
    )
    resolved = source.resolve(result.closure)
    source.require_resolved(resolved)
    assert resolved.state == result.state and resolved.closure == result.closure
    assert len(resolved.reads) == 2
    with pytest.raises(
        ContinuousForwardSourceError, match=r"^OWNED_CAPTURE_SOURCE_RESOLUTION_REQUIRED$"
    ):
        source.require_resolved(replace(resolved))


@pytest.mark.parametrize("warmup", [1, 64])
def test_capture_count_boundaries_resolve_and_compile_complete_original_sources(ports, warmup):
    synthetic = synthetic_continuous_inputs(
        fixture="flat", pins=PINS, warmup_count=warmup, session_count=warmup + 2
    )
    result = _capture(synthetic, ports)
    spec = synthetic.inputs.spec
    publications = result.closure.publications
    assert len(publications) == len(result.closure.observation_ids) == warmup
    assert tuple(publication.record.request.session for publication in publications) == (
        spec.window.warmup_sessions
    )
    assert not set(spec.window.warmup_sessions) & set(spec.window.scored_sessions)
    engine, journal, _publisher, objects = ports
    key = publications[0].record.request.journal_key
    assert all(publication.record.request.journal_key == key for publication in publications)
    assert publications[0].journal_receipt.previous_head == empty_head(key)
    assert journal.read_head(key).sequence == warmup

    # Resolve actual retained SQL records and raw objects before compiling again.
    # The maximum case is not represented by a mocked or count-only closure.
    source = SqlContinuousForwardSources(
        engine, artifacts=objects, codec=personal_codec, evidence_class="synthetic_fixture"
    )
    resolved = source.resolve(result.closure)
    source.require_resolved(resolved)
    assert resolved.closure == result.closure and resolved.state == result.state
    assert len(resolved.reads) == len(resolved.state.observations) == warmup
    observed = sorted(resolved.state.observations, key=lambda value: value.payload.session)
    assert tuple(value.payload.session for value in observed) == spec.window.warmup_sessions
    for value in observed:
        assert value.payload.close_price == Decimal(100)
        assert value.known_at == modeled_daily_availability(value.payload.session)
        assert value.known_at < spec.initialized_at

    benchmark = next(instrument_id for instrument_id, symbol in spec.instruments if symbol == "SPY")
    compiled = compile_continuous_bootstrap(
        spec,
        resolved.state,
        resolved.closure.observation_ids,
        spec.initialized_at,
        benchmark_instrument_id=benchmark,
        capture_evidence_class="synthetic_fixture",
    )
    assert compiled == result.inputs
    assert replace(compiled.spec, bootstrap_events_sha256=spec.bootstrap_events_sha256) == spec
    assert compiled.initial_state == synthetic.inputs.initial_state
    assert compiled.spec.live_authorized is False
    daily = tuple(
        event for event in compiled.bootstrap_events if isinstance(event.payload, DailyPrice)
    )
    benchmarks = tuple(
        event for event in compiled.bootstrap_events if isinstance(event.payload, BenchmarkPrice)
    )
    assert len(daily) == len(benchmarks) == warmup
    assert len(compiled.bootstrap_events) == 2 * warmup
    assert {event.payload.session for event in daily} == set(spec.window.warmup_sessions)
    assert all(event.payload.close_price == Decimal(100) for event in daily)
    assert all(event.payload.unit_price == Decimal(100) for event in benchmarks)
    for event in compiled.bootstrap_events:
        assert event.knowledge_at == spec.initialized_at
        assert event.provenance.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
        assert event.provenance.observed_at is None
        assert event.provenance.assumption_id == "synthetic-capture-replay/1"
    assert compiled.spec.bootstrap_events_sha256 == content_digest(compiled.bootstrap_events)


def test_exact_repeated_capture_uses_original_receipts_without_new_appends_or_object_writes(ports):
    synthetic = synthetic_continuous_inputs(fixture="regime", pins=PINS)
    first = _capture(synthetic, ports)
    _engine, journal, _publisher, objects = ports
    key = first.closure.publications[0].record.request.journal_key
    head, writes = journal.read_head(key), objects.writes
    assert head.sequence == 2
    assert first.closure.publications[0].journal_receipt.previous_head == empty_head(key)
    repeated = _capture(synthetic, ports)
    assert repeated == first
    assert journal.read_head(key) == head and objects.writes == writes


def test_modeled_monotonic_nanoseconds_preserve_utc_gaps_across_weekend(ports):
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS, warmup_count=6)
    result = _capture(synthetic, ports)
    receipts = tuple(publication.record.receipt for publication in result.closure.publications)
    origin = receipts[0]
    assert origin.requested_monotonic_ns == 1000000000
    for index, receipt in enumerate(receipts):
        delta = receipt.requested_at - origin.requested_at
        expected_ns = ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000
        assert receipt.boot_id == "synthetic-capture-clock-model/1"
        assert receipt.requested_monotonic_ns - origin.requested_monotonic_ns == expected_ns
        assert receipt.validated_monotonic_ns - receipt.requested_monotonic_ns == 200000000
        assert receipt.validated_at - receipt.requested_at == timedelta(milliseconds=200)
        if index:
            assert receipt.requested_monotonic_ns > receipts[index - 1].validated_monotonic_ns
    assert receipts[-1].requested_at - receipts[-2].requested_at == timedelta(days=3)


class _ForbiddenPort:
    def __getattribute__(self, name):
        raise AssertionError("invalid input reached a capture port")


def test_complete_multi_instrument_input_is_outside_this_serial_model_before_io():
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS)
    inputs = synthetic.inputs
    extra = []
    for event in inputs.bootstrap_events:
        price = replace(event.payload, instrument_id="synthetic-qqq", symbol="QQQ")
        extra.append(
            replace(
                event,
                event_id="qqq-" + event.event_id,
                payload=price,
                provenance=replace(event.provenance, normalized_sha256=content_digest(price)),
            )
        )
    events = tuple(sorted(inputs.bootstrap_events + tuple(extra), key=lambda event: event.event_id))
    spec = replace(
        inputs.spec,
        instruments=tuple(sorted((*inputs.spec.instruments, ("synthetic-qqq", "QQQ")))),
        bootstrap_events_sha256=content_digest(events),
    )
    synthetic = replace(synthetic, inputs=replace(inputs, spec=spec, bootstrap_events=events))
    assert len(events) == len(spec.instruments) * len(spec.window.warmup_sessions)
    assert {(event.payload.instrument_id, event.payload.session) for event in events} == {
        (instrument, session)
        for instrument, _ in spec.instruments
        for session in spec.window.warmup_sessions
    }
    forbidden = _ForbiddenPort()
    with pytest.raises(
        ValueError, match=r"^synthetic capture bootstrap requires one declared instrument$"
    ):
        capture_synthetic_bootstrap(
            synthetic,
            **_pins(synthetic),
            journal=forbidden,
            publisher=forbidden,
            artifacts=forbidden,
            codec=forbidden,
        )


@pytest.mark.parametrize("name", ["calendar_pin", "producer_pin"])
@pytest.mark.parametrize("changed", ["wrong_type", "corrupt_digest"])
def test_invalid_capture_pins_fail_before_port_access(name, changed):
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS)
    pins = _pins(synthetic)
    if changed == "wrong_type":
        pins[name] = object()
        expected = "exact synthetic capture calendar and producer pins required"
    else:
        # Bypass construction only to exercise the app's own pin revalidation.
        invalid = replace(pins[name])
        object.__setattr__(invalid, "sha256", "not-a-digest")
        pins[name] = invalid
        expected = "pin content requires a SHA-256 digest"
    forbidden = _ForbiddenPort()
    with pytest.raises(ValueError, match=f"^{expected}$"):
        capture_synthetic_bootstrap(
            synthetic,
            **pins,
            journal=forbidden,
            publisher=forbidden,
            artifacts=forbidden,
            codec=forbidden,
        )


@pytest.mark.parametrize("warmup,count", [(0, 8), (65, 66)])
def test_unsupported_capture_counts_fail_before_port_access(warmup, count):
    synthetic = synthetic_continuous_inputs(
        fixture="flat", pins=PINS, warmup_count=warmup, session_count=count
    )
    forbidden = _ForbiddenPort()
    with pytest.raises(ValueError, match=r"requires 1\.\.64"):
        capture_synthetic_bootstrap(
            synthetic,
            **_pins(synthetic),
            journal=forbidden,
            publisher=forbidden,
            artifacts=forbidden,
            codec=forbidden,
        )


@pytest.mark.parametrize("changed", ["source", "live", "coverage", "provenance", "wrong_type"])
def test_non_synthetic_or_incomplete_inputs_fail_before_port_access(changed):
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS)
    pins = _pins(synthetic)
    inputs = synthetic.inputs
    if changed == "source":
        inputs = replace(inputs, spec=replace(inputs.spec, source_mode="recorded_as_observed"))
    elif changed == "live":
        # A valid constructor already rejects True. Exercise the app's own
        # preflight against a deliberately corrupted local frozen input instead.
        inputs = replace(inputs)
        spec = replace(inputs.spec)
        object.__setattr__(spec, "live_authorized", True)
        object.__setattr__(inputs, "spec", spec)
    elif changed == "coverage":
        events = inputs.bootstrap_events[:1]
        inputs = replace(
            inputs,
            spec=replace(inputs.spec, bootstrap_events_sha256=content_digest(events)),
            bootstrap_events=events,
        )
    elif changed == "provenance":
        first, second = inputs.bootstrap_events
        first = replace(
            first, provenance=replace(first.provenance, data_class="recorded_as_observed")
        )
        events = (first, second)
        inputs = replace(
            inputs,
            spec=replace(inputs.spec, bootstrap_events_sha256=content_digest(events)),
            bootstrap_events=events,
        )
    synthetic = None if changed == "wrong_type" else replace(synthetic, inputs=inputs)
    forbidden = _ForbiddenPort()
    with pytest.raises(ValueError):
        capture_synthetic_bootstrap(
            synthetic,
            **pins,
            journal=forbidden,
            publisher=forbidden,
            artifacts=forbidden,
            codec=forbidden,
        )


@pytest.mark.parametrize("changed", ["journal", "publisher", "codec"])
def test_wrong_original_port_graph_fails_before_journal_or_artifact_io(ports, monkeypatch, changed):
    synthetic = synthetic_continuous_inputs(fixture="flat", pins=PINS)
    _engine, journal, publisher, objects = ports

    def forbidden(*_args, **_kwargs):
        raise AssertionError("wrong graph performed capture I/O")

    monkeypatch.setattr(journal, "read_head", forbidden)
    monkeypatch.setattr(objects, "put", forbidden)
    monkeypatch.setattr(objects, "read", forbidden)
    values = {
        "journal": journal,
        "publisher": publisher,
        "artifacts": objects,
        "codec": personal_codec,
    }
    values[changed] = object()
    with pytest.raises(ValueError, match="original synthetic capture"):
        capture_synthetic_bootstrap(synthetic, **_pins(synthetic), **values)
