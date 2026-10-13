"""Injected clock/source evidence only; no actual host or capture qualification."""

import copy
import gc
import weakref
from dataclasses import fields, replace
from datetime import timedelta
from decimal import Decimal
from threading import Event, Thread

import pytest

from packages.adapters import standard_clock as standard
from packages.adapters.personal_measured_clock import (
    MeasuredClockError,
    PersonalMeasuredClock,
    SampledMeasuredHealth,
)
from packages.adapters.standard_clock_chrony import ChronyStandardTimeSource
from packages.adapters.trusted_time import chrony_nts
from packages.application.personal_runtime import ClockHealthSnapshot, ClockHealthStatus
from packages.application.trusted_time_monitor import TrustedTimeSourceReading
from tests.unit.test_chrony_nts import BASE, _authority


class Scenario:
    def __init__(self):
        self.at = BASE
        self.mono = 10_000_000_000
        self.epoch_value = "synthetic-epoch"
        self.offset_ns = 0
        self.uncertainty_ns = 0
        self.age_ns = 0
        self.duration_ns = 0
        self.source_error = False
        self.utc_error_number = None
        self.utc_count = 0
        self.calls = []
        self.hook = None

    def event(self, name):
        self.calls.append(name)
        if self.hook is not None:
            self.hook(name)

    def utc(self):
        self.event("utc")
        self.utc_count += 1
        if self.utc_count == self.utc_error_number:
            raise RuntimeError("private UTC diagnostic")
        return self.at

    def monotonic(self):
        self.event("monotonic")
        return self.mono

    def epoch(self):
        self.event("epoch")
        return self.epoch_value

    def read(self, source, *, deadline_monotonic_ns):
        self.event("source")
        assert deadline_monotonic_ns == self.mono + standard.MAX_SAMPLING_DURATION_NS
        if self.source_error:
            raise RuntimeError("private source diagnostic")
        observed = self.at - timedelta(microseconds=self.age_ns // 1_000)
        reading = TrustedTimeSourceReading(
            source.authority.source_id,
            source.authority.source_authority_sha256,
            observed,
            observed + timedelta(microseconds=self.offset_ns // 1_000),
            self.mono - self.age_ns,
            Decimal(self.uncertainty_ns) / 1_000_000,
            "b" * 64,
        )
        self.at += timedelta(microseconds=self.duration_ns // 1_000)
        self.mono += self.duration_ns
        return reading

    def second(self, elapsed):
        self.at = BASE + timedelta(seconds=elapsed)
        self.mono = 10_000_000_000 + elapsed * 1_000_000_000


@pytest.fixture
def factory(monkeypatch):
    scenarios = {}

    def forbidden(*args, **kwargs):
        pytest.fail("real Chrony process forbidden")

    monkeypatch.setattr(chrony_nts.subprocess, "Popen", forbidden)

    def read(source, *, deadline_monotonic_ns):
        return scenarios[id(source)].read(source, deadline_monotonic_ns=deadline_monotonic_ns)

    monkeypatch.setattr(chrony_nts.ChronyNtsTrustedTimeSource, "read_trusted_time", read)

    def create(*, plain=False):
        scenario = Scenario()
        source = chrony_nts.ChronyNtsTrustedTimeSource(
            _authority(),
            utc_clock=scenario.utc,
            monotonic_clock=scenario.monotonic,
            runner=forbidden,
        )
        scenarios[id(source)] = scenario
        bridge = ChronyStandardTimeSource(source)
        arguments = {
            "source": bridge,
            "utc_now": source.utc_clock,
            "monotonic_now_ns": source.monotonic_clock,
            "epoch_provider": scenario.epoch,
        }
        clock = standard.StandardClock(**arguments) if plain else PersonalMeasuredClock(**arguments)
        return clock, scenario, bridge

    return create


def test_constructor_and_original_verification_have_no_clock_or_source_effects(factory):
    owner, scenario, bridge = factory()
    assert scenario.calls == []
    token = owner.sample_health()
    assert scenario.calls == ["monotonic", "utc", "epoch", "source", "utc", "monotonic"]
    before = scenario.calls[:]
    owner.require_original_health(token)
    assert scenario.calls == before
    assert token.source_observation is not None
    bridge.require_original_observation(token.source_observation)
    assert token.snapshot.status is ClockHealthStatus.BLOCKED
    assert token.snapshot.reasons == ("startup_qualifying",)
    assert token.snapshot.rearm_required


def test_explicit_clock_domain_rejects_equal_wrappers_and_simulated_source(factory):
    _owner, scenario, bridge = factory()
    for source, utc, monotonic in (
        (bridge, lambda: scenario.utc(), bridge.source.monotonic_clock),
        (bridge, bridge.source.utc_clock, lambda: scenario.monotonic()),
        (standard.StandardClock(simulated_health=True), scenario.utc, scenario.monotonic),
    ):
        with pytest.raises(MeasuredClockError, match="CONFIGURATION_INVALID"):
            PersonalMeasuredClock(
                source=source,
                utc_now=utc,
                monotonic_now_ns=monotonic,
                epoch_provider=scenario.epoch,
            )
    assert scenario.calls == []


def compare_step(owner, owned_scenario, plain, plain_scenario, **changes):
    for key, value in changes.items():
        setattr(owned_scenario, key, value)
        setattr(plain_scenario, key, value)
    token = owner.sample_health()
    expected = plain.health_snapshot()
    assert token.snapshot == expected
    assert owned_scenario.calls == plain_scenario.calls
    owner.require_original_health(token)
    return token


def test_original_sixty_second_history_matches_independent_standard_clock(factory):
    owner, scenario, _ = factory()
    plain, reference, _ = factory(plain=True)
    for elapsed in (0, 10, 20, 30, 40, 50, 60):
        scenario.second(elapsed)
        reference.second(elapsed)
        token = compare_step(owner, scenario, plain, reference)
        assert token.snapshot.recovery_ready is (elapsed == 60)
        assert (token.snapshot.status is ClockHealthStatus.HEALTHY) is (elapsed == 60)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"offset_ns": 249_999_000}, "startup_qualifying"),
        ({"offset_ns": 250_000_000}, "offset_warning"),
        ({"offset_ns": 1_000_000_000}, "offset_blocked"),
        ({"offset_ns": -1_000_000_000}, "offset_blocked"),
        ({"age_ns": 29_999_999_000}, "startup_qualifying"),
        ({"age_ns": 30_000_000_000}, "sample_stale"),
        ({"age_ns": -1_000}, "future_sample"),
        ({"duration_ns": 999_999_000}, "startup_qualifying"),
        ({"duration_ns": 1_000_000_000}, "sampling_timeout"),
        ({"source_error": True}, "clock_or_source_unavailable"),
        ({"utc_error_number": 1}, "clock_or_source_unavailable"),
        ({"utc_error_number": 2}, "clock_or_source_unavailable"),
    ],
)
def test_boundaries_and_callback_failures_preserve_reducer_semantics(factory, changes, reason):
    owner, scenario, _ = factory()
    plain, reference, _ = factory(plain=True)
    # An old measurement must still have a nonnegative original monotonic value.
    scenario.mono = reference.mono = 100_000_000_000
    token = compare_step(owner, scenario, plain, reference, **changes)
    assert reason in token.snapshot.reasons
    if changes.get("source_error") or changes.get("utc_error_number") == 1:
        assert token.source_observation is None
    elif changes.get("utc_error_number") == 2:
        assert token.source_observation is not None
        assert token.snapshot.evidence_class == "unavailable"
        assert token.snapshot.source_id is None


@pytest.mark.parametrize(
    "fault", ["epoch", "cadence", "utc_regression", "mono_regression", "disagreement", "offset"]
)
def test_fault_and_subsequent_recovery_remain_latched(factory, fault):
    owner, scenario, _ = factory()
    plain, reference, _ = factory(plain=True)
    for elapsed in (0, 10, 20, 30, 40, 50, 60):
        scenario.second(elapsed)
        reference.second(elapsed)
        healthy = compare_step(owner, scenario, plain, reference)
    assert healthy.snapshot.status is ClockHealthStatus.HEALTHY
    for state in (scenario, reference):
        state.second(61)
        if fault == "epoch":
            state.epoch_value = "different-epoch"
        elif fault == "cadence":
            state.second(90)
        elif fault == "utc_regression":
            state.at = BASE
        elif fault == "mono_regression":
            state.mono = 0
        elif fault == "disagreement":
            state.at += timedelta(milliseconds=250)
        else:
            state.offset_ns = 1_000_000_000
    failed = compare_step(owner, scenario, plain, reference)
    assert failed.snapshot.status is ClockHealthStatus.BLOCKED
    for elapsed in (100, 110, 120, 130, 140, 150, 160):
        scenario.second(elapsed)
        reference.second(elapsed)
        later = compare_step(owner, scenario, plain, reference, offset_ns=0)
    assert "fault_latched_rearm_required" in later.snapshot.reasons
    # Historical authenticity is deliberately distinct from current health/age.
    before = scenario.calls[:]
    owner.require_original_health(healthy)
    assert scenario.calls == before


def test_failed_source_cannot_reuse_previous_successful_observation(factory):
    owner, scenario, _ = factory()
    first = owner.sample_health()
    scenario.second(10)
    scenario.source_error = True
    second = owner.sample_health()
    assert first.source_observation is not None
    assert second.source_observation is None
    assert second.snapshot.evidence_class == "unavailable"
    owner.require_original_health(first)
    owner.require_original_health(second)


def test_final_clock_callback_cannot_substitute_previous_equal_measurement(factory):
    owner, scenario, _ = factory()
    first = owner.sample_health()
    original_read = scenario.read

    def same_coordinates_new_reading(source, *, deadline_monotonic_ns):
        reading = original_read(source, deadline_monotonic_ns=deadline_monotonic_ns)
        previous = first.source_observation.reading
        for field in ("local_observed_at_utc", "trusted_at_utc", "observed_at_monotonic_ns"):
            object.__setattr__(reading, field, getattr(previous, field))
        object.__setattr__(reading, "source_evidence_sha256", "c" * 64)
        return reading

    def substitute(name):
        if name == "utc" and scenario.utc_count == 3:
            assert owner._pending is not first.source_observation
            assert owner._pending.reading.source_evidence_sha256 == "c" * 64
            assert first.source_observation.reading.source_evidence_sha256 == "b" * 64
            assert all(
                getattr(owner._pending.measurement, field.name)
                is getattr(first.source_observation.measurement, field.name)
                for field in fields(standard.TimeSourceMeasurement)
            )
            owner._pending = first.source_observation

    scenario.read = same_coordinates_new_reading
    scenario.hook = substitute
    with pytest.raises(MeasuredClockError, match="OWNERSHIP_CHANGED"):
        owner.sample_health()
    assert list(owner._owned.values()) == [first]


@pytest.mark.parametrize("warm", [False, True])
def test_copied_owner_cannot_adopt_fresh_or_warmed_history(factory, warm):
    owner, scenario, _ = factory()
    for elapsed in (0, 10, 20, 30, 40, 50, 60) if warm else ():
        scenario.second(elapsed)
        token = owner.sample_health()
    copied = copy.copy(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match="OWNER_REQUIRED"):
        copied.sample_health()
    assert scenario.calls == before
    if not warm:
        token = owner.sample_health()
        before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match="OWNER_REQUIRED"):
        copied.require_original_health(token)
    assert scenario.calls == before
    owner.require_original_health(token)


@pytest.mark.parametrize(
    ("kind", "member"),
    [
        ("clock_class", "health_snapshot"),
        ("clock_class", "now"),
        ("clock_class", "monotonic_ns"),
        ("bridge_class", "read_observation"),
        ("bridge_class", "require_original_observation"),
        ("bridge_class", "_read_measurement"),
        ("source_class", "read_trusted_time"),
        ("authority_class", "semantic_sha256"),
        ("authority_class", "argv"),
        ("source", "utc_clock"),
        ("source", "monotonic_clock"),
        ("source", "runner"),
        ("authority", "source_id"),
        ("owner_class", "_utc"),
        ("owner_class", "_monotonic"),
        ("owner_class", "_epoch"),
        ("owner_class", "_measurement"),
        ("owner", "_utc"),
        ("owner", "_monotonic"),
        ("owner", "_epoch"),
        ("owner", "_measurement"),
    ],
)
def test_source_and_reducer_rebinding_rejects_before_substituted_behavior(
    factory, monkeypatch, kind, member
):
    owner, scenario, bridge = factory()
    token = owner.sample_health()
    invocations = []

    def substituted(*args, **kwargs):
        invocations.append(member)
        raise AssertionError("substituted behavior must not run")

    objects = {
        "clock_class": standard.StandardClock,
        "bridge_class": ChronyStandardTimeSource,
        "source_class": type(bridge.source),
        "authority_class": type(bridge.source.authority),
        "source": bridge.source,
        "authority": bridge.source.authority,
        "owner_class": PersonalMeasuredClock,
        "owner": owner,
    }
    if kind.endswith("_class"):
        replacement = property(substituted) if kind == "authority_class" else substituted
        monkeypatch.setattr(objects[kind], member, replacement)
    else:
        object.__setattr__(objects[kind], member, substituted)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError):
        owner.require_original_health(token)
    with pytest.raises(MeasuredClockError):
        owner.sample_health()
    assert not invocations and scenario.calls == before


@pytest.mark.parametrize("clone", [copy.copy, copy.deepcopy, replace])
def test_token_copy_or_reconstruction_is_not_owned(factory, clone):
    owner, scenario, _ = factory()
    token = owner.sample_health()
    before = scenario.calls[:]
    for changed in (clone(token), SampledMeasuredHealth(token.snapshot, token.source_observation)):
        with pytest.raises(MeasuredClockError, match="HEALTH_INVALID"):
            owner.require_original_health(changed)
    owner.require_original_health(token)
    assert scenario.calls == before


@pytest.mark.parametrize("member", ["snapshot", "source_observation", "reading", "measurement"])
def test_nested_equal_reconstruction_is_rejected(factory, member):
    owner, scenario, _ = factory()
    token = owner.sample_health()
    target = token if member in ("snapshot", "source_observation") else token.source_observation
    object.__setattr__(target, member, replace(getattr(target, member)))
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match="HEALTH_INVALID"):
        owner.require_original_health(token)
    assert scenario.calls == before


def test_every_snapshot_field_and_original_reading_digest_is_bound(factory):
    for member in (*[item.name for item in fields(ClockHealthSnapshot)], "reading_digest"):
        owner, scenario, _ = factory()
        token = owner.sample_health()
        if member == "reading_digest":
            object.__setattr__(token.source_observation.reading, "source_evidence_sha256", "c" * 64)
        else:
            object.__setattr__(token.snapshot, member, object())
        before = scenario.calls[:]
        with pytest.raises(MeasuredClockError, match="HEALTH_INVALID"):
            owner.require_original_health(token)
        assert scenario.calls == before


@pytest.mark.parametrize(
    "mutation",
    [
        lambda owner: setattr(owner._clock, "_sequence", 99),
        lambda owner: setattr(owner._clock, "_previous", tuple(list(owner._clock._previous))),
        lambda owner: setattr(owner._clock, "_source_id", "substituted"),
        lambda owner: setattr(owner._clock, "_healthy_since", 0),
        lambda owner: setattr(owner._clock, "_latched_reasons", set()),
        lambda owner: owner._clock._latched_reasons.add("forged"),
        lambda owner: setattr(owner._clock, "_simulated_health", True),
        lambda owner: setattr(owner._clock, "_source", lambda *args: None),
        lambda owner: setattr(owner._clock, "now", lambda: BASE),
        lambda owner: setattr(owner, "_clock", standard.StandardClock(simulated_health=True)),
        lambda owner: setattr(owner, "_source", replace(owner._source)),
    ],
)
def test_between_sample_state_and_binding_tampering_rejects_without_effects(factory, mutation):
    owner, scenario, _ = factory()
    token = owner.sample_health()
    mutation(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError):
        owner.sample_health()
    with pytest.raises(MeasuredClockError):
        owner.require_original_health(token)
    assert scenario.calls == before


@pytest.mark.parametrize("method", ["health_snapshot", "now", "monotonic_ns"])
def test_external_private_clock_use_cannot_advance_owned_history(factory, method):
    owner, scenario, _ = factory()
    token = owner.sample_health()
    before = scenario.calls[:]
    if method == "health_snapshot":
        assert getattr(owner._clock, method)().status is ClockHealthStatus.BLOCKED
    else:
        with pytest.raises(MeasuredClockError):
            getattr(owner._clock, method)()
    with pytest.raises(MeasuredClockError):
        owner.require_original_health(token)
    assert scenario.calls == before


@pytest.mark.parametrize("event", ["utc", "monotonic", "epoch", "source"])
@pytest.mark.parametrize("raise_after", [False, True])
@pytest.mark.parametrize("target", ["history", "pending", "source_calls"])
def test_callback_tamper_is_not_swallowed_as_ordinary_source_failure(
    factory, event, raise_after, target
):
    owner, scenario, _ = factory()

    def tamper(name):
        if name == event:
            if target == "history":
                owner._clock._healthy_since = 0
            elif target == "pending":
                owner._pending = object()
            else:
                owner._source_calls = 123
            if raise_after:
                raise RuntimeError("private callback failure")

    scenario.hook = tamper
    with pytest.raises(MeasuredClockError, match="OWNERSHIP_CHANGED"):
        owner.sample_health()
    assert not owner._owned and not owner._original
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError):
        owner.sample_health()
    assert scenario.calls == before


def test_recursive_and_concurrent_sampling_cannot_interleave_history(factory):
    owner, scenario, _ = factory()
    entered, release = Event(), Event()
    results = []

    def pause(name):
        if name == "source":
            with pytest.raises(MeasuredClockError, match="BUSY"):
                owner.sample_health()
            entered.set()
            assert release.wait(2)

    scenario.hook = pause
    worker = Thread(target=lambda: results.append(owner.sample_health()))
    worker.start()
    try:
        assert entered.wait(2)
        before = scenario.calls[:]
        with pytest.raises(MeasuredClockError, match="BUSY"):
            owner.sample_health()
        assert scenario.calls == before
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert len(results) == 1 and results[0].snapshot.sequence == 1
    owner.require_original_health(results[0])


def test_tokens_and_copied_registry_do_not_retain_original_owner(factory):
    owner, _scenario, bridge = factory()
    token = owner.sample_health()
    copied = copy.copy(owner)
    original_owner = weakref.ref(owner)
    token_reference = weakref.ref(token)
    source_reference = weakref.ref(token.source_observation)
    del owner
    gc.collect()
    assert original_owner() is None
    with pytest.raises(MeasuredClockError, match="OWNER_REQUIRED"):
        copied.require_original_health(token)
    del token
    gc.collect()
    assert token_reference() is None and source_reference() is None
    assert not copied._owned and not copied._original
    assert not bridge._owned and not bridge._original
