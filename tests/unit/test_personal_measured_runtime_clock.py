"""Original modeled clock delegation only; no wire, host or operating admission."""

import copy
import gc
import weakref
from dataclasses import fields, replace
from decimal import Decimal
from threading import Event, Thread

import pytest

from packages.adapters import standard_clock_chrony as chrony
from packages.adapters.measured_runtime_clock import (
    MeasuredRuntimeClockError,
    MeasuredRuntimeClockSampler,
    SampledMeasuredRuntimeClock,
)
from packages.adapters.personal_measured_clock import MeasuredClockError, SampledMeasuredHealth
from packages.adapters.standard_clock_chrony import CHRONY_STANDARD_BRIDGE_VERSION
from packages.application.personal_runtime import ClockHealthSnapshot
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.measured_runtime_clock_contracts import (
    MeasuredClockSourceAssociation,
    MeasuredRuntimeClockObservation,
)
from packages.domain.runtime_operating_contracts import CLOCK_POLICY
from tests.unit.test_personal_measured_clock import factory as factory

SAMPLE_CALLS = ["monotonic", "utc", "epoch", "source", "utc", "monotonic"]
CURRENT_CALLS = ["monotonic", "utc", "epoch", "monotonic"]
ADAPTER_ERROR = r"^MEASURED_RUNTIME_CLOCK_[A-Z_]+$"


def _scope():
    return ContinuousAccountScope("measured-fixture", "a" * 64, "measured-fixture:clock")


def _history(owner):
    clock = owner._clock
    return (
        clock._sequence,
        id(clock._previous),
        clock._previous,
        id(clock._healthy_since),
        clock._healthy_since,
        id(clock._latched_reasons),
        frozenset(clock._latched_reasons),
        id(owner._expected),
    )


def _new(factory, *, warm=False):
    owner, scenario, bridge = factory()
    if warm:
        for second in (0, 10, 20, 30, 40, 50, 60):
            scenario.second(second)
            owner.sample_health()
    scope = _scope()
    before, history = scenario.calls[:], _history(owner)
    adapter = MeasuredRuntimeClockSampler(scope=scope, measured_clock=owner)
    assert scenario.calls == before
    assert _history(owner) == history
    return adapter, owner, scenario, bridge, scope


def _health(owner, token):
    matches = [
        candidate
        for candidate in owner._owned.values()
        if candidate.snapshot.sequence == token.observation.sequence
    ]
    assert len(matches) == 1
    result = matches[0]
    before = _history(owner)
    owner.require_original_health(result)
    assert _history(owner) == before
    return result


def _assert_projection(owner, bridge, scope, token):
    original = _health(owner, token)
    observed = token.observation
    assert type(token) is SampledMeasuredRuntimeClock
    assert [item.name for item in fields(token)] == ["observation"]
    assert type(observed) is MeasuredRuntimeClockObservation
    assert observed.scope is scope
    assert observed.policy is CLOCK_POLICY
    assert observed.profile == "personal_chrony_measured/1"
    for item in fields(ClockHealthSnapshot):
        expected = getattr(original.snapshot, item.name)
        if item.name == "status":
            assert observed.status == expected.value
        else:
            assert getattr(observed, item.name) is expected
    if original.source_observation is None:
        assert observed.source is None
    else:
        source = observed.source
        assert source is not None
        original_source = original.source_observation
        bridge.require_original_observation(original_source)
        for item in fields(original_source.reading):
            assert getattr(source, item.name) is getattr(original_source.reading, item.name)
        assert source.authority_semantic_sha256 is bridge._authority_binding[2]
        assert source.measurement_source_id is original_source.measurement.source_id
        assert source.bridge_version == CHRONY_STANDARD_BRIDGE_VERSION
        assert source.offset_ns == original_source.measurement.offset_ns
        assert source.uncertainty_ns == original_source.measurement.uncertainty_ns
    return original


def _sample(adapter, owner, scenario, bridge, scope, *, calls=SAMPLE_CALLS):
    before, sequence = scenario.calls[:], owner._clock._sequence
    token = adapter.sample()
    assert owner._clock._sequence == sequence + 1
    assert scenario.calls == before + calls
    assert scenario.calls.count("source") - before.count("source") == calls.count("source")
    _assert_projection(owner, bridge, scope, token)
    assert scenario.calls == before + calls
    return token


def _historical(adapter, owner, scenario, token):
    before, history = scenario.calls[:], _history(owner)
    assert adapter.require_sample(token) is None
    assert scenario.calls == before
    assert _history(owner) == history


def _current(adapter, owner, scenario, token):
    before, history = scenario.calls[:], _history(owner)
    assert adapter.require_current(token) is None
    assert scenario.calls == before + CURRENT_CALLS
    assert _history(owner) == history


def _poisoned(adapter, owner, scenario, token):
    scenario.hook = None
    before, history = scenario.calls[:], _history(owner)
    for operation, arguments in (
        (adapter.require_sample, (token,)),
        (adapter.require_current, (token,)),
        (adapter.sample, ()),
    ):
        with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR) as failure:
            operation(*arguments)
        assert str(failure.value) != "MEASURED_RUNTIME_CLOCK_BUSY"
        assert failure.value.__cause__ is None
    assert scenario.calls == before
    assert _history(owner) == history


def test_constructor_uses_original_warmed_owner_without_any_clock_or_history_effect(factory):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    assert owner._clock._sequence == 7
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    assert token.observation.sequence == 8
    assert token.observation.status == "healthy"
    assert token.observation.recovery_ready is True
    assert token.observation.rearm_required is True
    _historical(adapter, owner, scenario, token)
    _current(adapter, owner, scenario, token)


@pytest.mark.parametrize(
    ("state", "expected", "calls", "has_source"),
    [
        ("startup", "blocked", SAMPLE_CALLS, True),
        ("healthy", "healthy", SAMPLE_CALLS, True),
        ("warning", "warning", SAMPLE_CALLS, True),
        ("fault", "blocked", SAMPLE_CALLS, True),
        ("source_failure", "blocked", SAMPLE_CALLS[:4], False),
        ("first_utc_failure", "blocked", SAMPLE_CALLS[:2], False),
        ("final_utc_failure", "blocked", SAMPLE_CALLS[:5], True),
    ],
)
def test_sample_projects_actual_original_steps_and_optional_source_audit_exactly(
    factory, state, expected, calls, has_source
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=state != "startup")
    if state != "startup":
        scenario.second(61)
    if state == "warning":
        scenario.offset_ns = 250_000_000
    elif state == "fault":
        scenario.offset_ns = 1_000_000_000
    elif state == "source_failure":
        scenario.source_error = True
    elif state == "first_utc_failure":
        scenario.utc_error_number = scenario.utc_count + 1
    elif state == "final_utc_failure":
        scenario.utc_error_number = scenario.utc_count + 2
    token = _sample(adapter, owner, scenario, bridge, scope, calls=calls)
    observed = token.observation
    assert observed.status == expected
    assert (observed.source is not None) is has_source
    if state.endswith("failure"):
        assert observed.evidence_class == "unavailable"
        assert observed.recovery_ready is False
        for member in (
            "source_id",
            "source_observed_at_utc",
            "source_observed_monotonic_ns",
            "offset_ns",
            "uncertainty_ns",
        ):
            assert getattr(observed, member) is None
    _historical(adapter, owner, scenario, token)


@pytest.mark.parametrize(
    "bad_identity", ["callable", "weakref_subclass", "copied_owner", "foreign_type"]
)
def test_constructor_rejects_unowned_identity_without_invoking_replacement(factory, bad_identity):
    owner, scenario, _bridge = factory()
    invocations = []

    def replaced_identity():
        invocations.append("identity")
        return owner

    if bad_identity == "callable":
        owner._identity = replaced_identity
        candidate = owner
    elif bad_identity == "weakref_subclass":

        class ReplacedReference(weakref.ref):
            def __call__(self):
                return replaced_identity()

        owner._identity = ReplacedReference(owner)
        candidate = owner
    elif bad_identity == "copied_owner":
        candidate = copy.copy(owner)
    else:
        candidate = object()
    before, history = scenario.calls[:], _history(owner)
    with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR):
        MeasuredRuntimeClockSampler(scope=_scope(), measured_clock=candidate)
    assert invocations == []
    assert scenario.calls == before
    assert _history(owner) == history


def test_constructor_freshly_revalidates_scope_data_without_account_authority(factory):
    owner, scenario, _bridge = factory()
    scope = _scope()
    object.__setattr__(scope, "account_id", "")
    with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR):
        MeasuredRuntimeClockSampler(scope=scope, measured_clock=owner)
    assert scenario.calls == []
    assert owner._clock._sequence == 0


@pytest.mark.parametrize("offset", [-123_456_000, 123_456_000])
def test_projection_keeps_signed_original_offset_and_sub_nanosecond_uncertainty(factory, offset):
    adapter, owner, scenario, bridge, scope = _new(factory)
    scenario.offset_ns = offset
    scenario.uncertainty_ns = Decimal("0.0001")
    token = _sample(adapter, owner, scenario, bridge, scope)
    assert token.observation.source is not None
    assert token.observation.source.source_uncertainty_milliseconds == Decimal("0.0000000001")
    assert token.observation.source.uncertainty_ns == token.observation.uncertainty_ns == 1
    assert token.observation.source.offset_ns == token.observation.offset_ns == offset


def test_copied_adapter_cannot_adopt_original_ownership_or_poison_original_adapter(factory):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    copied = copy.copy(adapter)
    before, history = scenario.calls[:], _history(owner)
    for operation, arguments in (
        (copied.sample, ()),
        (copied.require_sample, (token,)),
        (copied.require_current, (token,)),
    ):
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNER_REQUIRED$"
        ):
            operation(*arguments)
    assert scenario.calls == before
    assert _history(owner) == history
    _historical(adapter, owner, scenario, token)
    _current(adapter, owner, scenario, token)


@pytest.mark.parametrize("operation", ["require_sample", "require_current"])
@pytest.mark.parametrize(
    "clone", ["copy", "deepcopy", "replace", "reconstructed", "foreign", "trap"]
)
def test_unowned_arguments_are_rejected_before_fields_and_do_not_poison_registered_history(
    factory, operation, clone
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    field_reads = []

    class UnownedTrap:
        @property
        def observation(self):
            field_reads.append("observation")
            raise AssertionError("unowned fields must never be read")

    if clone == "trap":
        changed = UnownedTrap()
    elif clone == "foreign":
        other, other_owner, other_scenario, other_bridge, other_scope = _new(factory)
        changed = _sample(other, other_owner, other_scenario, other_bridge, other_scope)
    elif clone == "reconstructed":
        changed = SampledMeasuredRuntimeClock(observation=token.observation)
    else:
        changed = {"copy": copy.copy, "deepcopy": copy.deepcopy, "replace": replace}[clone](token)
    before, history = scenario.calls[:], _history(owner)
    with pytest.raises(
        MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_SAMPLE_REQUIRED$"
    ):
        getattr(adapter, operation)(changed)
    assert field_reads == []
    assert scenario.calls == before
    assert _history(owner) == history
    _historical(adapter, owner, scenario, token)
    _current(adapter, owner, scenario, token)


def test_historical_tokens_remain_original_while_currentness_uses_only_latest_underlying_health(
    factory,
):
    adapter, owner, scenario, bridge, scope = _new(factory)
    startup = _sample(adapter, owner, scenario, bridge, scope)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(startup)
    assert scenario.calls == before
    for second in (10, 20, 30, 40, 50, 60):
        scenario.second(second)
        latest = _sample(adapter, owner, scenario, bridge, scope)
    _current(adapter, owner, scenario, latest)
    scenario.second(61)
    newer = _sample(adapter, owner, scenario, bridge, scope)
    _historical(adapter, owner, scenario, startup)
    _historical(adapter, owner, scenario, latest)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(latest)
    assert scenario.calls == before
    _current(adapter, owner, scenario, newer)


@pytest.mark.parametrize(
    "mutation",
    ["observation", "scope", "policy", "source", "source_text", "decimal_representation", "utc"],
)
def test_mutation_of_registered_projection_is_sticky_even_after_equal_fields_are_restored(
    factory, mutation
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    scenario.uncertainty_ns = 10_000
    token = _sample(adapter, owner, scenario, bridge, scope)
    original_health = _health(owner, token)
    if mutation == "observation":
        target, member = token, "observation"
        changed = replace(token.observation)
    elif mutation in ("scope", "policy", "source"):
        target, member = token.observation, mutation
        changed = replace(getattr(target, member))
    elif mutation == "source_text":
        target, member = token.observation.source, "source_evidence_sha256"
        changed = getattr(target, member).encode().decode()
    elif mutation == "decimal_representation":
        target, member = token.observation.source, "source_uncertainty_milliseconds"
        changed = Decimal("0.0100")
        assert changed == getattr(target, member)
        assert changed.as_tuple() != getattr(target, member).as_tuple()
    else:
        target, member = token.observation, "observed_at_utc"
        changed = getattr(target, member).replace()
    original = getattr(target, member)
    assert changed == original and changed is not original
    object.__setattr__(target, member, changed)
    before = scenario.calls[:]
    with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR):
        adapter.require_sample(token)
    assert scenario.calls == before
    object.__setattr__(target, member, original)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(original_health)
    assert scenario.calls == before


@pytest.mark.parametrize("member", ["snapshot", "source_reading"])
def test_registered_underlying_original_mutation_also_poisons_adapter_after_restoration(
    factory, member
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    if member == "snapshot":
        target, field, changed = health.snapshot, "offset_ns", 1
    else:
        target, field, changed = (
            health.source_observation.reading,
            "source_evidence_sha256",
            "c" * 64,
        )
    original = getattr(target, field)
    object.__setattr__(target, field, changed)
    before = scenario.calls[:]
    with pytest.raises(MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED$"):
        adapter.require_sample(token)
    assert scenario.calls == before
    object.__setattr__(target, field, original)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


def test_underlying_temporal_latch_is_preserved_without_poisoning_authentic_historical_projection(
    factory,
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    scenario.second(91)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(token)
    assert scenario.calls == before + CURRENT_CALLS
    _historical(adapter, owner, scenario, token)
    scenario.second(71)
    newer = _sample(adapter, owner, scenario, bridge, scope)
    assert newer.observation.status == "healthy"
    _historical(adapter, owner, scenario, newer)
    before = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(newer)
    assert scenario.calls == before


def test_failed_projection_keeps_original_step_without_retry_or_fabricated_owned_record(factory):
    adapter, owner, scenario, _bridge, _scope_value = _new(factory)
    scenario.epoch_value = "e" * 129
    before = scenario.calls[:]
    with pytest.raises(
        MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_FAILED$"
    ) as failure:
        adapter.sample()
    assert failure.value.__cause__ is None
    assert owner._clock._sequence == 1
    assert owner._expected.sequence == 1
    assert "clock_or_source_unavailable" in owner._clock._latched_reasons
    assert scenario.calls == [*before, "monotonic", "utc", "epoch"]
    assert scenario.calls.count("source") == 0
    assert not adapter._owned and not adapter._original
    del failure
    gc.collect()
    assert not owner._owned and not owner._original


@pytest.mark.parametrize("fails", [False, True])
def test_final_checks_detect_scope_mutation_on_normal_and_exceptional_current_exit(factory, fails):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    original_stream = scope.stream_id

    def mutate(_name):
        object.__setattr__(scope, "stream_id", "another-valid-stream")
        if fails:
            scenario.epoch_value = "changed-epoch"

    scenario.hook = mutate
    before, history = scenario.calls[:], _history(owner)
    if fails:
        with pytest.raises(BaseExceptionGroup) as failure:
            adapter.require_current(token)
        assert len(failure.value.exceptions) == 2
        primary, final = failure.value.exceptions
        assert type(primary) is MeasuredClockError
        assert str(primary) == "MEASURED_CLOCK_CURRENT_INVALID"
        assert type(final) is MeasuredRuntimeClockError
        assert str(final).startswith("MEASURED_RUNTIME_CLOCK_")
        assert failure.value.message == "MEASURED_RUNTIME_CLOCK_OPERATION_AND_CHECK_FAILED"
        assert scenario.calls == before + CURRENT_CALLS[:3]
    else:
        with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR):
            adapter.require_current(token)
        assert scenario.calls == before + CURRENT_CALLS
    assert _history(owner) == history
    scenario.hook = None
    scenario.epoch_value = "synthetic-epoch"
    object.__setattr__(scope, "stream_id", original_stream)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


@pytest.mark.parametrize("member", ["observation", "source_digest"])
def test_current_final_check_authenticates_registered_projection_after_normal_delegation(
    factory, member
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    if member == "observation":
        target, field, changed = token, "observation", replace(token.observation)
    else:
        target, field, changed = token.observation.source, "source_evidence_sha256", "c" * 64
    original = getattr(target, field)

    def mutate(_name):
        object.__setattr__(target, field, changed)

    scenario.hook = mutate
    before, history = scenario.calls[:], _history(owner)
    with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR):
        adapter.require_current(token)
    assert scenario.calls == before + CURRENT_CALLS
    assert _history(owner) == history
    scenario.hook = None
    object.__setattr__(target, field, original)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


def test_unexpected_sampling_abort_and_final_mutation_retain_both_safe_failures_in_order(factory):
    adapter, owner, scenario, _bridge, scope = _new(factory)
    original_stream = scope.stream_id

    def abort(_name):
        object.__setattr__(scope, "stream_id", "another-valid-stream")
        raise BaseException("private source callback payload must not escape")

    scenario.hook = abort
    before = scenario.calls[:]
    with pytest.raises(BaseExceptionGroup) as failure:
        adapter.sample()
    assert len(failure.value.exceptions) == 2
    primary, final = failure.value.exceptions
    assert type(primary) is MeasuredRuntimeClockError
    assert str(primary) == "MEASURED_RUNTIME_CLOCK_FAILED"
    assert primary.__cause__ is None
    assert type(final) is MeasuredRuntimeClockError
    assert str(final).startswith("MEASURED_RUNTIME_CLOCK_")
    assert failure.value.message == "MEASURED_RUNTIME_CLOCK_OPERATION_AND_CHECK_FAILED"
    assert scenario.calls == before + SAMPLE_CALLS[:1]
    assert owner._clock._sequence == 1
    assert scenario.calls.count("source") == 0
    scenario.hook = None
    object.__setattr__(scope, "stream_id", original_stream)
    # No fabricated token exists. A bad argument still acquires/releases the adapter
    # lock and cannot turn either retained failure into a second sampling attempt.
    with pytest.raises(MeasuredRuntimeClockError, match=ADAPTER_ERROR) as stopped:
        adapter.require_sample(object())
    assert str(stopped.value) != "MEASURED_RUNTIME_CLOCK_BUSY"
    assert scenario.calls == before + SAMPLE_CALLS[:1]


def test_adapter_busy_and_reentrant_calls_cannot_interleave_original_current_guard(factory):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    entered, release = Event(), Event()
    results, errors = [], []

    def pause(_name):
        if not entered.is_set():
            for operation, arguments in (
                (adapter.sample, ()),
                (adapter.require_sample, (token,)),
                (adapter.require_current, (token,)),
            ):
                with pytest.raises(
                    MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_BUSY$"
                ):
                    operation(*arguments)
            entered.set()
            assert release.wait(2)

    def work():
        try:
            results.append(adapter.require_current(token))
        except BaseException as failure:
            errors.append(failure)

    scenario.hook = pause
    before, history = scenario.calls[:], _history(owner)
    worker = Thread(target=work)
    worker.start()
    try:
        assert entered.wait(2)
        paused = scenario.calls[:]
        for operation, arguments in (
            (adapter.sample, ()),
            (adapter.require_sample, (token,)),
            (adapter.require_current, (token,)),
        ):
            with pytest.raises(MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_BUSY$"):
                operation(*arguments)
        assert scenario.calls == paused
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert errors == [] and results == [None]
    assert scenario.calls == before + CURRENT_CALLS
    assert _history(owner) == history
    scenario.hook = None
    _historical(adapter, owner, scenario, token)
    _current(adapter, owner, scenario, token)


def test_propagated_adapter_reentry_keeps_original_current_failure_and_releases_both_locks(factory):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)

    def recurse(_name):
        adapter.require_sample(token)

    scenario.hook = recurse
    before, history = scenario.calls[:], _history(owner)
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(token)
    assert scenario.calls == before + CURRENT_CALLS[:1]
    assert _history(owner) == history
    scenario.hook = None
    _historical(adapter, owner, scenario, token)
    stopped = scenario.calls[:]
    with pytest.raises(MeasuredClockError, match=r"^MEASURED_CLOCK_CURRENT_INVALID$"):
        adapter.require_current(token)
    assert scenario.calls == stopped


def test_dying_returned_token_releases_underlying_original_health_without_collecting_owners(
    factory,
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    token_ref, health_ref = weakref.ref(token), weakref.ref(health)
    source_ref = weakref.ref(health.source_observation)
    del health
    del token
    gc.collect()
    assert token_ref() is None and health_ref() is None and source_ref() is None
    assert not owner._owned and not owner._original
    assert not bridge._owned and not bridge._original
    scenario.second(62)
    replacement = _sample(adapter, owner, scenario, bridge, scope)
    _current(adapter, owner, scenario, replacement)


def test_returned_token_does_not_keep_adapter_or_measured_owner_alive(factory):
    adapter, owner, scenario, _bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, owner._source, scope)
    health = _health(owner, token)
    adapter_ref, owner_ref = weakref.ref(adapter), weakref.ref(owner)
    token_ref, health_ref = weakref.ref(token), weakref.ref(health)
    source_ref = weakref.ref(health.source_observation)
    del health
    del owner
    gc.collect()
    assert owner_ref() is not None  # The live adapter intentionally owns its supplied clock.
    del adapter
    gc.collect()
    assert adapter_ref() is None and owner_ref() is None
    assert token_ref() is token and health_ref() is not None and source_ref() is not None
    assert token.observation.profile == "personal_chrony_measured/1"
    del token
    gc.collect()
    assert token_ref() is None and health_ref() is None and source_ref() is None


@pytest.mark.parametrize(
    ("target_kind", "member"),
    [
        ("adapter", "__init__"),
        ("adapter", "sample"),
        ("adapter", "require_sample"),
        ("adapter", "require_current"),
        ("adapter", "_bindings"),
        ("adapter", "_require_bindings"),
        ("adapter", "_acquire"),
        ("adapter", "_lookup"),
        ("adapter", "_require_token"),
        ("adapter", "_project"),
        ("adapter", "_run"),
        ("measured", "sample_health"),
        ("measured", "require_original_health"),
        ("measured", "require_current_health"),
        ("measured", "_configuration"),
        ("measured", "_history"),
        ("measured", "_require_state"),
        ("measured", "_current_callback"),
    ],
)
@pytest.mark.parametrize("level", ["class", "instance"])
@pytest.mark.parametrize("when", ["before", "callback"])
def test_finite_adapter_and_owner_handler_substitution_never_runs_or_revives_after_restoration(
    factory, target_kind, member, level, when
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    original_entry = adapter.require_current
    instance = adapter if target_kind == "adapter" else owner
    target = type(instance) if level == "class" else instance
    original_descriptor = vars(type(instance))[member] if level == "class" else None
    assert member not in vars(instance)
    installed, invocations = False, []

    def substituted(*_args, **_kwargs):
        invocations.append(member)
        raise AssertionError("substituted pinned handler must never run")

    def install(_name=None):
        nonlocal installed
        if not installed:
            setattr(target, member, substituted)
            installed = True

    # These fields also belong to the original current guard's own finite seal;
    # it fails first, then the adapter separately retains its final binding failure.
    measured_current_seal = {
        "require_current_health",
        "_configuration",
        "_history",
        "_require_state",
        "_current_callback",
    }
    group_expected = (
        when == "callback" and target_kind == "measured" and (member in measured_current_seal)
    )
    before, history = scenario.calls[:], _history(owner)
    try:
        if when == "before":
            install()
        else:
            scenario.hook = install
        if group_expected:
            with pytest.raises(BaseExceptionGroup) as failure:
                original_entry(token)
            assert failure.value.message == "MEASURED_RUNTIME_CLOCK_OPERATION_AND_CHECK_FAILED"
            assert len(failure.value.exceptions) == 2
            primary, final = failure.value.exceptions
            assert type(primary) is MeasuredClockError
            assert str(primary) == "MEASURED_CLOCK_CURRENT_INVALID"
            assert type(final) is MeasuredRuntimeClockError
            assert str(final) == "MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED"
        else:
            with pytest.raises(
                MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED$"
            ):
                original_entry(token)
        assert installed is True
        assert invocations == []
        expected = (
            [] if when == "before" else (CURRENT_CALLS[:1] if group_expected else CURRENT_CALLS)
        )
        assert scenario.calls == before + expected
        assert _history(owner) == history
    finally:
        scenario.hook = None
        if installed:
            if level == "class":
                setattr(target, member, original_descriptor)
            else:
                delattr(target, member)
    assert member not in vars(instance)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


@pytest.mark.parametrize(
    ("record_kind", "member"),
    [
        ("association", "__init__"),
        ("association", "__post_init__"),
        ("association", "offset_ns"),
        ("association", "uncertainty_ns"),
        ("observation", "__init__"),
        ("observation", "__post_init__"),
        ("scope", "__post_init__"),
    ],
)
@pytest.mark.parametrize("when", ["before", "callback"])
def test_pinned_record_constructor_and_conversion_properties_cannot_certify_substitution(
    factory, record_kind, member, when
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    target = {
        "association": MeasuredClockSourceAssociation,
        "observation": MeasuredRuntimeClockObservation,
        "scope": ContinuousAccountScope,
    }[record_kind]
    descriptor = vars(target)[member]
    installed, invocations = False, []

    def substituted(*_args, **_kwargs):
        invocations.append(member)
        raise AssertionError("substituted domain admission must never run")

    replacement = (
        property(substituted) if member in ("offset_ns", "uncertainty_ns") else substituted
    )

    def install(_name=None):
        nonlocal installed
        if not installed:
            setattr(target, member, replacement)
            installed = True

    before, history = scenario.calls[:], _history(owner)
    try:
        if when == "before":
            install()
        else:
            scenario.hook = install
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED$"
        ):
            adapter.require_current(token)
        assert invocations == [] and installed is True
        assert scenario.calls == before + ([] if when == "before" else CURRENT_CALLS)
        assert _history(owner) == history
    finally:
        scenario.hook = None
        if installed:
            setattr(target, member, descriptor)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


def test_runtime_measured_identity_replacement_is_rejected_without_calling_it(factory):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    original = owner._identity
    invocations = []

    def substituted():
        invocations.append("identity")
        return owner

    owner._identity = substituted
    before = scenario.calls[:]
    try:
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED$"
        ):
            adapter.require_current(token)
        assert invocations == []
        assert scenario.calls == before
    finally:
        owner._identity = original
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


@pytest.mark.parametrize("when", ["before", "callback"])
def test_replacing_supplied_measured_owner_cannot_transfer_registered_health_or_clear_adapter_fault(
    factory, when
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    foreign, foreign_scenario, _foreign_bridge = factory()

    def install(_name=None):
        adapter._measured_clock = foreign

    before, foreign_before = scenario.calls[:], foreign_scenario.calls[:]
    try:
        if when == "before":
            install()
        else:
            scenario.hook = install
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED$"
        ):
            adapter.require_current(token)
        assert scenario.calls == before + ([] if when == "before" else CURRENT_CALLS)
        assert foreign_scenario.calls == foreign_before
    finally:
        scenario.hook = None
        adapter._measured_clock = owner
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


@pytest.mark.parametrize(
    "mutation", ["foreign_weak_owner", "dead_weak_owner", "callable_owner", "health_token"]
)
def test_current_final_check_binds_original_metadata_owner_and_underlying_health_token(
    factory, mutation
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    metadata = adapter._original[id(token)]
    invocations = []

    def substituted_owner():
        invocations.append("metadata owner")
        return adapter

    if mutation == "foreign_weak_owner":
        foreign, _foreign_owner, _foreign_scenario, _foreign_bridge, _foreign_scope = _new(factory)
        field, changed = "owner", weakref.ref(foreign)
        assert changed() is foreign and foreign is not adapter
    elif mutation == "dead_weak_owner":

        class DeadOwner:
            pass

        dead = DeadOwner()
        changed = weakref.ref(dead)
        del dead
        gc.collect()
        assert changed() is None
        field = "owner"
    elif mutation == "callable_owner":
        field, changed = "owner", substituted_owner
    else:
        field = "health"
        changed = SampledMeasuredHealth(health.snapshot, health.source_observation)
        assert changed is not health
        assert changed.snapshot is health.snapshot
        assert changed.source_observation is health.source_observation
    original = getattr(metadata, field)

    def mutate(_name):
        object.__setattr__(metadata, field, changed)

    scenario.hook = mutate
    before, history = scenario.calls[:], _history(owner)
    try:
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_SAMPLE_CHANGED$"
        ):
            adapter.require_current(token)
        assert scenario.calls == before + CURRENT_CALLS
        assert _history(owner) == history
        assert invocations == []
    finally:
        scenario.hook = None
        object.__setattr__(metadata, field, original)
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)


@pytest.mark.parametrize("actual_version", ["personal-chrony-standard-clock/2", True])
def test_constructor_rejects_actual_bridge_version_drift_after_genuine_old_owner_was_built(
    factory, monkeypatch, actual_version
):
    owner, scenario, bridge = factory()
    health = owner.sample_health()
    assert chrony.CHRONY_STANDARD_BRIDGE_VERSION == "personal-chrony-standard-clock/1"
    before, history = scenario.calls[:], _history(owner)
    binding = bridge._authority_binding
    with monkeypatch.context() as patcher:
        patcher.setattr(chrony, "CHRONY_STANDARD_BRIDGE_VERSION", actual_version)
        with pytest.raises(
            MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_CONFIGURATION_INVALID$"
        ):
            MeasuredRuntimeClockSampler(scope=_scope(), measured_clock=owner)
        assert scenario.calls == before
        assert _history(owner) == history
        assert bridge._authority_binding is binding
    owner.require_original_health(health)
    assert scenario.calls == before


@pytest.mark.parametrize("when", ["before", "callback"])
def test_actual_bridge_version_drift_after_adapter_construction_is_sticky(
    factory, monkeypatch, when
):
    adapter, owner, scenario, bridge, scope = _new(factory, warm=True)
    scenario.second(61)
    token = _sample(adapter, owner, scenario, bridge, scope)
    health = _health(owner, token)
    before, history = scenario.calls[:], _history(owner)
    with monkeypatch.context() as patcher:

        def install(_name=None):
            patcher.setattr(
                chrony, "CHRONY_STANDARD_BRIDGE_VERSION", "personal-chrony-standard-clock/2"
            )

        if when == "before":
            install()
        else:
            scenario.hook = install
        try:
            with pytest.raises(
                MeasuredRuntimeClockError, match=r"^MEASURED_RUNTIME_CLOCK_OWNERSHIP_CHANGED$"
            ):
                adapter.require_current(token)
            assert scenario.calls == before + ([] if when == "before" else CURRENT_CALLS)
            assert _history(owner) == history
        finally:
            scenario.hook = None
    _poisoned(adapter, owner, scenario, token)
    owner.require_original_health(health)
