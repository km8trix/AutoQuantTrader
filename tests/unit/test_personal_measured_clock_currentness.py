"""Modeled local-current checks only; no host, source-runner or trading qualification."""

import copy
import gc
import weakref
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from threading import Event, Thread

import pytest

from packages.adapters.personal_measured_clock import MeasuredClockError, SampledMeasuredHealth
from packages.application.personal_runtime import ClockHealthStatus
from tests.unit.test_chrony_nts import BASE
from tests.unit.test_personal_measured_clock import factory as factory

CURRENT_CALLS = ["monotonic", "utc", "epoch", "monotonic"]
CURRENT_ERROR = r"^MEASURED_CLOCK_CURRENT_INVALID$"
SECOND = 1_000_000_000


def _at(scenario, elapsed_ns):
    assert type(elapsed_ns) is int and elapsed_ns % 1_000 == 0
    scenario.at = BASE + timedelta(microseconds=elapsed_ns // 1_000)
    scenario.mono = 10 * SECOND + elapsed_ns


def _warm(factory, *, last_source_age=0):
    owner, scenario, bridge = factory()
    assert scenario.calls == []
    for elapsed in (0, 10, 20, 30, 40, 50, 60):
        scenario.second(elapsed)
        if elapsed == 60:
            scenario.age_ns = last_source_age
        token = owner.sample_health()
    assert token.snapshot.status is ClockHealthStatus.HEALTHY
    assert token.snapshot.reasons == ("within_limit",)
    assert token.snapshot.recovery_ready is True
    assert token.snapshot.rearm_required is True
    assert token.snapshot.evidence_class == "host-measurement"
    assert token.source_observation is not None
    assert scenario.calls.count("source") == 7
    return owner, scenario, bridge, token


def _history(owner):
    clock = owner._clock
    names = ("_previous", "_source_id", "_healthy_since", "_latched_reasons", "_sequence")
    return (
        tuple((name, id(getattr(clock, name))) for name in names),
        clock._previous,
        clock._source_id,
        clock._healthy_since,
        frozenset(clock._latched_reasons),
        clock._sequence,
        id(owner._expected),
        id(owner._pending),
        owner._source_calls,
    )


def _success(owner, scenario, token):
    before_calls = scenario.calls[:]
    before_history = _history(owner)
    assert owner.require_current_health(token) is None
    assert scenario.calls == before_calls + CURRENT_CALLS
    assert scenario.calls.count("source") == before_calls.count("source")
    assert _history(owner) == before_history


def _denied_without_callbacks(owner, scenario, token):
    before_calls = scenario.calls[:]
    before_history = _history(owner)
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR) as failure:
        owner.require_current_health(token)
    assert str(failure.value) == "MEASURED_CLOCK_CURRENT_INVALID"
    assert failure.value.__cause__ is None
    assert scenario.calls == before_calls
    assert _history(owner) == before_history


def _sticky(owner, scenario, token):
    scenario.hook = None
    _at(scenario, 63 * SECOND)
    _denied_without_callbacks(owner, scenario, token)
    # Local-current refusal must not rewrite otherwise authentic historical evidence.
    before = scenario.calls[:]
    owner.require_original_health(token)
    assert scenario.calls == before


def test_current_checks_have_exact_local_effects_and_do_not_refresh_source(factory):
    owner, scenario, _bridge, token = _warm(factory)
    # An unsampled source failure is intentionally invisible to this local-only guard.
    scenario.source_error = True
    for second in (60, 61, 62):
        scenario.second(second)
        _success(owner, scenario, token)
    assert scenario.calls.count("source") == 7
    assert token.snapshot.sequence == 7
    assert token.snapshot.rearm_required is True


def test_startup_refusal_has_no_callbacks_and_does_not_poison_later_qualification(factory):
    owner, scenario, _bridge = factory()
    first = owner.sample_health()
    assert first.snapshot.reasons == ("startup_qualifying",)
    _denied_without_callbacks(owner, scenario, first)
    for second in (10, 20, 30, 40, 50, 60):
        scenario.second(second)
        token = owner.sample_health()
    assert token.snapshot.status is ClockHealthStatus.HEALTHY
    _success(owner, scenario, token)


@pytest.mark.parametrize("kind", ["copy", "deepcopy", "replace", "reconstruct", "foreign", "bare"])
def test_unowned_token_denial_does_not_poison_the_original_owner(factory, kind):
    owner, scenario, _bridge, token = _warm(factory)
    if kind == "foreign":
        _other, _other_scenario, _other_bridge, changed = _warm(factory)
    elif kind == "bare":
        changed = token.snapshot
    elif kind == "reconstruct":
        changed = SampledMeasuredHealth(token.snapshot, token.source_observation)
    else:
        changed = {"copy": copy.copy, "deepcopy": copy.deepcopy, "replace": replace}[kind](token)
    _denied_without_callbacks(owner, scenario, changed)
    _success(owner, scenario, token)


def test_superseded_and_collected_latest_tokens_cannot_revive_old_sequence(factory):
    owner, scenario, _bridge, old = _warm(factory)
    scenario.second(61)
    latest = owner.sample_health()
    assert latest.snapshot.status is ClockHealthStatus.HEALTHY
    assert latest.snapshot.sequence == old.snapshot.sequence + 1
    _denied_without_callbacks(owner, scenario, old)
    latest_ref = weakref.ref(latest)
    del latest
    gc.collect()
    assert latest_ref() is None
    _denied_without_callbacks(owner, scenario, old)
    scenario.second(62)
    replacement = owner.sample_health()
    assert replacement.snapshot.sequence == old.snapshot.sequence + 2
    _success(owner, scenario, replacement)


@pytest.mark.parametrize("regression", ["utc", "monotonic", "both"])
def test_new_healthy_sample_cannot_hide_regression_below_previous_current(factory, regression):
    owner, scenario, _bridge, old = _warm(factory)
    scenario.second(62)
    _success(owner, scenario, old)
    if regression == "both":
        scenario.second(61)
    else:
        _at(scenario, 62 * SECOND + 1_000_000)
        if regression == "utc":
            scenario.at = BASE + timedelta(seconds=62, milliseconds=-1)
        else:
            scenario.mono = 10 * SECOND + 62 * SECOND - 1_000_000
    newer = owner.sample_health()
    # The original reducer compares against sample60, not the intervening current62.
    assert newer.snapshot.status is ClockHealthStatus.HEALTHY
    assert newer.snapshot.reasons == ("within_limit",)
    assert newer.snapshot.sequence == old.snapshot.sequence + 1
    scenario.second(63)
    before = scenario.calls[:]
    before_history = _history(owner)
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(newer)
    assert scenario.calls.count("source") == before.count("source")
    assert _history(owner) == before_history
    _sticky(owner, scenario, newer)


def test_new_source_reading_can_predate_previous_current_within_original_age(factory):
    owner, scenario, _bridge, old = _warm(factory)
    scenario.second(62)
    _success(owner, scenario, old)
    scenario.second(63)
    scenario.age_ns = 2 * SECOND
    newer = owner.sample_health()
    assert newer.snapshot.status is ClockHealthStatus.HEALTHY
    assert newer.snapshot.source_observed_at_utc == BASE + timedelta(seconds=61)
    assert newer.snapshot.source_observed_monotonic_ns == 71 * SECOND
    scenario.second(64)
    _success(owner, scenario, newer)


@pytest.mark.parametrize("fault", ["utc", "monotonic", "epoch"])
def test_current_regressions_latch_even_after_original_scalars_are_restored(factory, fault):
    owner, scenario, _bridge, token = _warm(factory)
    scenario.second(61)
    _success(owner, scenario, token)
    _at(scenario, 61 * SECOND + 1_000_000)
    if fault == "utc":
        scenario.at = BASE + timedelta(seconds=61, milliseconds=-1)
    elif fault == "monotonic":
        scenario.mono = 71 * SECOND - 1_000_000
    else:
        scenario.epoch_value = "changed-synthetic-epoch"
    history = _history(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls != before
    assert scenario.calls.count("source") == before.count("source")
    assert _history(owner) == history
    scenario.epoch_value = "synthetic-epoch"
    _sticky(owner, scenario, token)


@pytest.mark.parametrize(
    ("last_source_age", "elapsed_ns", "admitted"),
    [
        (0, 89_999_999_000, True),
        (0, 90_000_000_000, False),
        (0, 59_999_999_000, False),
        (2 * SECOND, 87_999_999_000, True),
        (2 * SECOND, 88_000_000_000, False),
    ],
)
def test_local_and_source_age_boundaries_are_independently_enforced(
    factory, last_source_age, elapsed_ns, admitted
):
    owner, scenario, _bridge, token = _warm(factory, last_source_age=last_source_age)
    assert token.snapshot.source_observed_at_utc == BASE + timedelta(
        seconds=60, microseconds=-(last_source_age // 1_000)
    )
    _at(scenario, elapsed_ns)
    if admitted:
        _success(owner, scenario, token)
    else:
        history = _history(owner)
        before = scenario.calls[:]
        with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
            owner.require_current_health(token)
        assert scenario.calls.count("source") == before.count("source")
        assert _history(owner) == history
        _sticky(owner, scenario, token)


@pytest.mark.parametrize(("delta_ns", "admitted"), [(249_999_000, True), (250_000_000, False)])
def test_utc_monotonic_disagreement_uses_original_equality_policy(factory, delta_ns, admitted):
    owner, scenario, _bridge, token = _warm(factory)
    scenario.at = BASE + timedelta(seconds=60, microseconds=delta_ns // 1_000)
    scenario.mono = 70 * SECOND
    if admitted:
        _success(owner, scenario, token)
    else:
        before = scenario.calls[:]
        with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
            owner.require_current_health(token)
        assert scenario.calls == before + CURRENT_CALLS
        _sticky(owner, scenario, token)


@pytest.mark.parametrize(("span_ns", "admitted"), [(0, True), (999_999_000, True), (SECOND, False)])
def test_local_read_span_is_strictly_below_one_second(factory, span_ns, admitted):
    owner, scenario, _bridge, token = _warm(factory)
    count = 0

    def scripted(name):
        nonlocal count
        if name == "monotonic":
            scenario.mono = 70 * SECOND + (span_ns if count else 0)
            count += 1
        elif name == "utc":
            scenario.at = BASE + timedelta(seconds=60, microseconds=span_ns // 1_000)

    scenario.hook = scripted
    if admitted:
        _success(owner, scenario, token)
    else:
        before = scenario.calls[:]
        with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
            owner.require_current_health(token)
        assert scenario.calls == before + CURRENT_CALLS
        _sticky(owner, scenario, token)
    assert count == 2


@pytest.mark.parametrize("transient", ["before_sample", "before_previous", "after_before"])
def test_transient_monotonic_regression_cannot_be_hidden_by_final_read(factory, transient):
    owner, scenario, _bridge, token = _warm(factory)
    if transient == "before_previous":
        scenario.second(61)
        _success(owner, scenario, token)
        before_ns, after_ns, utc_ns = 70_999_000_000, 71_001_000_000, 61_001_000_000
    elif transient == "before_sample":
        before_ns, after_ns, utc_ns = 69_999_000_000, 70_001_000_000, 60_001_000_000
    else:
        before_ns, after_ns, utc_ns = 70_001_000_000, 70 * SECOND, 60 * SECOND
    count = 0

    def scripted(name):
        nonlocal count
        if name == "monotonic":
            scenario.mono = before_ns if count == 0 else after_ns
            count += 1
        elif name == "utc":
            scenario.at = BASE + timedelta(microseconds=utc_ns // 1_000)

    scenario.hook = scripted
    history = _history(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls[len(before) :] in (CURRENT_CALLS[:1], CURRENT_CALLS)
    assert scenario.calls.count("source") == before.count("source")
    assert _history(owner) == history
    _sticky(owner, scenario, token)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mono", True),
        ("mono", -1),
        ("mono", 70_000_000_000.0),
        ("at", True),
        ("at", datetime(2026, 7, 31, 14, 1)),
        ("epoch_value", True),
        ("epoch_value", ""),
        ("epoch_value", "x" * 129),
    ],
)
def test_native_local_callback_results_are_required_and_failure_is_sticky(factory, field, value):
    owner, scenario, _bridge, token = _warm(factory)
    setattr(scenario, field, value)
    history = _history(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls != before
    assert scenario.calls.count("source") == before.count("source")
    assert _history(owner) == history
    scenario.epoch_value = "synthetic-epoch"
    _sticky(owner, scenario, token)


@pytest.mark.parametrize("callback_index", range(4))
@pytest.mark.parametrize("abort_type", [RuntimeError, BaseException])
def test_each_callback_exception_is_private_sticky_and_releases_the_lock(
    factory, callback_index, abort_type
):
    owner, scenario, _bridge, token = _warm(factory)
    count = 0

    def fail(_name):
        nonlocal count
        index = count
        count += 1
        if index == callback_index:
            raise abort_type("private callback payload must not escape")

    scenario.hook = fail
    history = _history(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR) as failure:
        owner.require_current_health(token)
    assert str(failure.value) == "MEASURED_CLOCK_CURRENT_INVALID"
    assert failure.value.__cause__ is None
    assert scenario.calls == before + CURRENT_CALLS[: callback_index + 1]
    assert _history(owner) == history
    _sticky(owner, scenario, token)


@pytest.mark.parametrize(
    ("member", "replacement"),
    [("_pending", object()), ("_source_calls", 2), ("_source_calls", True)],
)
def test_authenticated_healthy_idle_progress_failure_latches_before_callbacks(
    factory, member, replacement
):
    owner, scenario, _bridge, token = _warm(factory)
    original = getattr(owner, member)
    setattr(owner, member, replacement)
    _denied_without_callbacks(owner, scenario, token)
    setattr(owner, member, original)
    _sticky(owner, scenario, token)


@pytest.mark.parametrize(
    ("member", "replacement"),
    [("_pending", object()), ("_source_calls", 2), ("_source_calls", True)],
)
@pytest.mark.parametrize("callback_index", range(4))
def test_idle_source_progress_mutation_is_detected_after_each_callback(
    factory, member, replacement, callback_index
):
    owner, scenario, _bridge, token = _warm(factory)
    original = getattr(owner, member)
    count = 0

    def mutate(_name):
        nonlocal count
        if count == callback_index:
            setattr(owner, member, replacement)
        count += 1

    scenario.hook = mutate
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert getattr(owner, member) is replacement
    assert scenario.calls == before + CURRENT_CALLS[: callback_index + 1]
    assert scenario.calls.count("source") == before.count("source")
    setattr(owner, member, original)
    _sticky(owner, scenario, token)


@pytest.mark.parametrize("member", ["snapshot", "source_digest"])
def test_original_token_is_rechecked_after_callbacks_and_restoration_cannot_rearm(factory, member):
    owner, scenario, _bridge, token = _warm(factory)
    target = token.snapshot if member == "snapshot" else token.source_observation.reading
    field = "offset_ns" if member == "snapshot" else "source_evidence_sha256"
    original = getattr(target, field)

    def mutate(_name):
        object.__setattr__(target, field, 1 if member == "snapshot" else "c" * 64)

    scenario.hook = mutate
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls == before + CURRENT_CALLS[:1]
    assert scenario.calls.count("source") == before.count("source")
    object.__setattr__(target, field, original)
    _sticky(owner, scenario, token)


def test_latch_survives_new_healthy_samples_without_changing_reducer_history(factory):
    owner, scenario, _bridge, old = _warm(factory)
    scenario.second(90)
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(old)
    # The failed current check never advances reducer sample60; step70 is still valid.
    scenario.second(70)
    latest = owner.sample_health()
    assert latest.snapshot.status is ClockHealthStatus.HEALTHY
    assert latest.snapshot.reasons == ("within_limit",)
    assert latest.snapshot.sequence == old.snapshot.sequence + 1
    assert latest.snapshot.rearm_required is True
    _denied_without_callbacks(owner, scenario, latest)
    owner.require_original_health(old)
    owner.require_original_health(latest)


def test_sampling_does_not_reset_previous_current_cadence_baseline(factory):
    owner, scenario, _bridge, token = _warm(factory)
    scenario.second(61)
    _success(owner, scenario, token)
    for second in (70, 80, 90):
        scenario.second(second)
        token = owner.sample_health()
        assert token.snapshot.status is ClockHealthStatus.HEALTHY
    scenario.second(91)
    history = _history(owner)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls.count("source") == before.count("source")
    assert _history(owner) == history
    _denied_without_callbacks(owner, scenario, token)


def test_sampled_fault_cannot_reuse_previous_healthy_current_authority(factory):
    owner, scenario, _bridge, healthy = _warm(factory)
    _success(owner, scenario, healthy)
    scenario.second(61)
    scenario.offset_ns = SECOND
    failed = owner.sample_health()
    assert failed.snapshot.status is ClockHealthStatus.BLOCKED
    assert "offset_blocked" in failed.snapshot.reasons
    _denied_without_callbacks(owner, scenario, healthy)
    _denied_without_callbacks(owner, scenario, failed)
    scenario.offset_ns = 0
    for second in (70, 80, 90, 100, 110, 120, 130):
        scenario.second(second)
        later = owner.sample_health()
    assert later.snapshot.recovery_ready is True
    assert later.snapshot.status is ClockHealthStatus.BLOCKED
    assert "fault_latched_rearm_required" in later.snapshot.reasons
    _denied_without_callbacks(owner, scenario, later)
    owner.require_original_health(healthy)


def test_reentrant_and_concurrent_operations_cannot_interleave_current_callbacks(factory):
    owner, scenario, _bridge, token = _warm(factory)
    entered, release = Event(), Event()
    errors, results = [], []

    def pause(_name):
        if not entered.is_set():
            for operation in (owner.require_current_health, owner.require_original_health):
                with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_BUSY$"):
                    operation(token)
            with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_BUSY$"):
                owner.sample_health()
            entered.set()
            assert release.wait(2)

    def work():
        try:
            results.append(owner.require_current_health(token))
        except BaseException as failure:
            errors.append(failure)

    scenario.hook = pause
    before = scenario.calls[:]
    history = _history(owner)
    worker = Thread(target=work)
    worker.start()
    try:
        assert entered.wait(2)
        paused = scenario.calls[:]
        for operation in (owner.require_current_health, owner.require_original_health):
            with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_BUSY$"):
                operation(token)
        with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_BUSY$"):
            owner.sample_health()
        assert scenario.calls == paused
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert errors == []
    assert results == [None]
    assert scenario.calls == before + CURRENT_CALLS
    assert _history(owner) == history
    scenario.hook = None
    scenario.second(61)
    _success(owner, scenario, token)


def test_propagated_recursive_busy_failure_latches_only_the_admitted_outer_call(factory):
    owner, scenario, _bridge, token = _warm(factory)

    def recurse(_name):
        owner.require_current_health(token)

    scenario.hook = recurse
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
        owner.require_current_health(token)
    assert scenario.calls == before + CURRENT_CALLS[:1]
    _sticky(owner, scenario, token)


def test_current_baseline_does_not_retain_tokens_or_original_source_observations(factory):
    owner, scenario, bridge, token = _warm(factory)
    _success(owner, scenario, token)
    token_ref = weakref.ref(token)
    observation_ref = weakref.ref(token.source_observation)
    del token
    gc.collect()
    assert token_ref() is None and observation_ref() is None
    assert not owner._owned and not owner._original
    assert not bridge._owned and not bridge._original
    scenario.second(61)
    latest = owner.sample_health()
    _success(owner, scenario, latest)


def test_copied_owner_and_new_owner_cannot_adopt_previous_current_authority(factory):
    owner, scenario, _bridge, token = _warm(factory)
    _success(owner, scenario, token)
    copied = copy.copy(owner)
    owner_ref = weakref.ref(owner)
    del owner
    gc.collect()
    assert owner_ref() is None
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_OWNER_REQUIRED$"):
        copied.require_current_health(token)
    assert scenario.calls == before
    fresh, fresh_scenario, _fresh_bridge = factory()
    _denied_without_callbacks(fresh, fresh_scenario, token)
    startup = fresh.sample_health()
    assert startup.snapshot.reasons == ("startup_qualifying",)
    _denied_without_callbacks(fresh, fresh_scenario, startup)


@pytest.mark.parametrize(
    "member",
    [
        "require_current_health",
        "_require_current_state",
        "_require_current_sample",
        "_current_callback",
        "_current_elapsed",
        "_require_state",
        "_configuration",
        "_history",
    ],
)
@pytest.mark.parametrize("target_kind", ["class", "instance"])
@pytest.mark.parametrize("when", ["before", "callback"])
def test_current_method_substitution_never_runs_and_restoration_cannot_clear_denial(
    factory, member, target_kind, when
):
    owner, scenario, _bridge, token = _warm(factory)
    # Retain the genuine entry before rebinding, including when testing that entry itself.
    original_entry = owner.require_current_health
    target = type(owner) if target_kind == "class" else owner
    original_descriptor = vars(type(owner))[member] if target_kind == "class" else None
    assert member not in vars(owner)
    invocations = []
    installed = False

    def substituted(*_args, **_kwargs):
        invocations.append(member)
        raise AssertionError("substituted currentness behavior must never execute")

    def install(_name=None):
        nonlocal installed
        if not installed:
            setattr(target, member, substituted)
            installed = True

    before = scenario.calls[:]
    history = _history(owner)
    try:
        if when == "before":
            install()
        else:
            scenario.hook = install
        with pytest.raises(MeasuredClockError, match=CURRENT_ERROR) as failure:
            original_entry(token)
        assert str(failure.value) == "MEASURED_CLOCK_CURRENT_INVALID"
        assert failure.value.__cause__ is None
        assert installed is True
        assert invocations == []
        expected = [] if when == "before" else CURRENT_CALLS[:1]
        assert scenario.calls == before + expected
        assert _history(owner) == history
    finally:
        scenario.hook = None
        if installed:
            if target_kind == "class":
                setattr(target, member, original_descriptor)
            else:
                delattr(target, member)
    # Exact descriptor restoration leaves historical verification intact, but never rearms.
    assert member not in vars(owner)
    _sticky(owner, scenario, token)


@pytest.mark.parametrize(
    ("old_offset_ms", "next_utc_ms", "admitted"),
    [(-200, 61_100, True), (200, 60_900, False)],
)
def test_current_baseline_is_independent_of_a_later_mutated_zero_offset_timezone(
    factory, old_offset_ms, next_utc_ms, admitted
):
    class MutableOffset(tzinfo):
        def __init__(self):
            self.offset = timedelta(0)

        def utcoffset(self, _instant):
            return self.offset

        def dst(self, _instant):
            return timedelta(0)

    owner, scenario, _bridge, token = _warm(factory)
    zone = MutableOffset()
    canonical_first = BASE + timedelta(seconds=61)
    original_instant = canonical_first.replace(tzinfo=zone)
    assert original_instant.utcoffset() == timedelta(0)
    scenario.at = original_instant
    scenario.mono = 71 * SECOND
    _success(owner, scenario, token)

    zone.offset = timedelta(milliseconds=old_offset_ms)
    assert original_instant.utcoffset() == timedelta(milliseconds=old_offset_ms)
    scenario.at = BASE + timedelta(milliseconds=next_utc_ms)
    scenario.mono = 71_100_000_000
    assert scenario.at.tzinfo is UTC
    assert scenario.mono > 71 * SECOND
    # Both cases satisfy the original sample's age/disagreement bounds. Keeping the
    # mutable datetime as the previous baseline reverses the correct outcome:
    # -200ms reinterprets prior61 as61.2; +200ms reinterprets it as60.8.
    wall_from_sample = scenario.at - token.snapshot.observed_at_utc
    mono_from_sample = scenario.mono - token.snapshot.observed_monotonic_ns
    wall_ns = (wall_from_sample.days * 86400 + wall_from_sample.seconds) * SECOND
    wall_ns += wall_from_sample.microseconds * 1_000
    assert 0 <= wall_ns < 30 * SECOND
    assert 0 <= mono_from_sample < 30 * SECOND
    assert abs(wall_ns - mono_from_sample) < 250_000_000
    assert (scenario.at >= canonical_first) is admitted
    assert (scenario.at >= original_instant) is not admitted
    if admitted:
        _success(owner, scenario, token)
        scenario.second(62)
        _success(owner, scenario, token)
    else:
        before = scenario.calls[:]
        history = _history(owner)
        with pytest.raises(MeasuredClockError, match=CURRENT_ERROR):
            owner.require_current_health(token)
        assert scenario.calls == before + CURRENT_CALLS
        assert _history(owner) == history
        _sticky(owner, scenario, token)
