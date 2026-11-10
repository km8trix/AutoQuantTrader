"""Native and Condition transport only; no configured preparation is modeled.

These cases never replace G/E or pretend to establish financial readiness,
preparation, durable effects or cleanup. The separate genuine integrations own
those claims. Any manually staged owner state below is explicitly transport data.
"""

import builtins
import copy
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine

from apps.trader import initial_selection_preparation_owner as host
from apps.trader.continuous_readiness_owner import ReadinessOwnerLimits
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor

_ARGUMENT = "^INITIAL_SELECTION_PREPARATION_OWNER_ARGUMENT_INVALID$"
_STATE = "^INITIAL_SELECTION_PREPARATION_OWNER_STATE_INVALID$"
_BINDING = "^INITIAL_SELECTION_PREPARATION_OWNER_BINDING_CHANGED$"
_MAX_NS = 2**63 - 1


def _owner(**changes):
    arguments = {
        "configuration_path": "/private/tmp/preparation-native/configuration.json",
        "account_id": "native-preparation-account",
        "instance_lock": "/private/tmp/preparation-native/instance.lock",
    }
    arguments.update(changes)
    return host.InitialSelectionPreparationOwner(**arguments)


def test_constructor_and_native_status_have_no_storage_clock_or_thread_effects(monkeypatch):
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("data-only construction reached a live effect")

    with monkeypatch.context() as local:
        for target, name in (
            (builtins, "open"),
            (Path, "open"),
            (Path, "resolve"),
            (Path, "stat"),
            (Path, "lstat"),
            (Path, "read_bytes"),
            (Path, "write_bytes"),
            (socket, "socket"),
            (sqlite3, "connect"),
            (subprocess, "Popen"),
            (Engine, "connect"),
            (threading.Thread, "start"),
            (time, "time"),
            (time, "monotonic"),
            (time, "monotonic_ns"),
        ):
            local.setattr(target, name, forbidden)
        owner = _owner()
        first, second = owner.status(), owner.status()
    assert effects == []
    assert first is not second and first == second
    assert (first.phase, first.busy, first.attempted, first.cleanup_complete) == (
        "new",
        False,
        False,
        True,
    )
    assert first.primary_failure is first.cleanup_failure is None
    assert type(first.incarnation) is str and first.incarnation
    assert all(
        type(getattr(first, name)) is bool for name in ("busy", "attempted", "cleanup_complete")
    )
    with pytest.raises(FrozenInstanceError):
        first.phase = "idle"


def test_constructor_copies_shortened_original_limits_and_not_the_callers_record():
    limits = ReadinessOwnerLimits(
        startup_ns=900_000_000,
        request_ns=800_000_000,
        shutdown_ns=700_000_000,
        lifetime_ns=6_000_000_000,
    )
    owner = _owner(limits=limits)
    assert type(owner._limits) is tuple
    before = owner._limits
    assert before == (900_000_000, 800_000_000, 700_000_000, 6_000_000_000)
    object.__setattr__(limits, "request_ns", 1)
    object.__setattr__(limits, "lifetime_ns", 2)
    assert owner._limits == before
    assert owner.status().phase == "new"


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("configuration_path", "relative.json"),
        ("configuration_path", "/private/tmp/preparation-native/configuration.txt"),
        ("configuration_path", "/private/tmp/.env.private/configuration.json"),
        ("configuration_path", Path("/private/tmp/preparation-native/configuration.json")),
        ("configuration_path", None),
        ("instance_lock", "instance.lock"),
        ("instance_lock", "/private/tmp/.env.private/instance.lock"),
        ("instance_lock", Path("/private/tmp/preparation-native/instance.lock")),
        ("instance_lock", None),
        ("account_id", ""),
        ("account_id", "a" * 129),
        ("account_id", "account/foreign"),
        ("account_id", True),
        ("account_id", None),
        ("limits", object()),
    ],
)
def test_invalid_native_constructor_arguments_are_rejected_before_live_effects(
    monkeypatch, name, bad
):
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("invalid native argument reached a live effect")

    with monkeypatch.context() as local:
        local.setattr(Path, "resolve", forbidden)
        local.setattr(Path, "stat", forbidden)
        local.setattr(Engine, "connect", forbidden)
        local.setattr(threading.Thread, "start", forbidden)
        local.setattr(time, "monotonic_ns", forbidden)
        with pytest.raises(ValueError, match=_ARGUMENT) as caught:
            _owner(**{name: bad})
    assert type(caught.value) is ValueError
    assert effects == []


@pytest.mark.parametrize(
    ("name", "maximum"),
    [
        ("startup_ns", 10_000_000_000),
        ("request_ns", 5_000_000_000),
        ("shutdown_ns", 1_000_000_000),
        ("lifetime_ns", 60_000_000_000),
    ],
)
@pytest.mark.parametrize("kind", ["zero", "negative", "bool", "float", "over"])
def test_mutated_limits_cannot_escape_original_native_shortening_only_bounds(name, maximum, kind):
    limits = ReadinessOwnerLimits()
    bad = {"zero": 0, "negative": -1, "bool": True, "float": 1.0, "over": maximum + 1}[kind]
    object.__setattr__(limits, name, bad)
    with pytest.raises(ValueError, match=_ARGUMENT):
        _owner(limits=limits)


@pytest.mark.parametrize(
    "initially_valid", [False, True], ids=["invalid-snapshot", "valid-snapshot"]
)
def test_limits_validation_consumes_the_captured_tuple_despite_caller_mutation(initially_valid):
    caller = ReadinessOwnerLimits()
    if not initially_valid:
        object.__setattr__(caller, "request_ns", 5_000_000_001)
    original_profile = sys.getprofile()
    original_code = ReadinessOwnerLimits.__post_init__.__code__
    validations = []

    def profile(frame, event, argument):
        if event == "call" and frame.f_code is original_code:
            validations.append(frame.f_locals["self"])
            object.__setattr__(
                caller, "request_ns", 5_000_000_001 if initially_valid else 5_000_000_000
            )

    try:
        sys.setprofile(profile)
        if initially_valid:
            owner = _owner(limits=caller)
        else:
            with pytest.raises(ValueError, match=_ARGUMENT):
                _owner(limits=caller)
    finally:
        sys.setprofile(original_profile)
    assert sys.getprofile() is original_profile
    assert len(validations) == 1 and validations[0] is not caller
    if initially_valid:
        assert owner._limits == (10_000_000_000, 5_000_000_000, 1_000_000_000, 60_000_000_000)
        assert caller.request_ns == 5_000_000_001
        assert owner.status().phase == "new"
    else:
        assert validations[0].request_ns == 5_000_000_001
        assert caller.request_ns == 5_000_000_000


def test_stop_before_start_is_terminal_without_creating_a_thread(monkeypatch):
    owner = _owner()
    effects = []

    def forbidden(*args, **kwargs):
        effects.append("start")
        raise AssertionError("a stopped new owner attempted native launch")

    with monkeypatch.context() as local:
        local.setattr(threading.Thread, "start", forbidden)
        first, second = owner.stop(), owner.stop()
        later = owner.start()
    assert effects == []
    assert first == second == later
    assert first.phase == "stopped" and first.cleanup_complete
    assert not first.busy and not first.attempted
    assert first.primary_failure is first.cleanup_failure is None
    assert owner._thread is None
    with monkeypatch.context() as local:
        local.setattr(time, "monotonic_ns", forbidden)
        result = owner.prepare_initial_selection("after-stop")
    assert (result.status, result.reason, result.descriptor) == ("unavailable", "stopped", None)
    assert effects == []


@pytest.mark.parametrize("call_id", ["", "x" * 129, "wrong/id", None, True, 1])
def test_invalid_call_identifier_does_not_claim_a_slot_or_consume_an_attempt(call_id):
    owner = _owner()
    before = owner.status()
    with pytest.raises(ValueError, match=_ARGUMENT):
        owner.prepare_initial_selection(call_id)
    assert owner.status() == before
    assert owner._slot is None


def test_new_owner_returns_only_unavailable_native_data_without_implicit_start():
    owner = _owner()
    result = owner.prepare_initial_selection("before-start")
    assert (result.status, result.reason, result.call_id, result.descriptor) == (
        "unavailable",
        "not_started",
        "before-start",
        None,
    )
    assert result.incarnation == owner.status().incarnation
    assert not owner.status().attempted and owner._slot is None
    with pytest.raises(FrozenInstanceError):
        result.status = "prepared"


def test_original_maximum_identifier_lengths_remain_accepted_as_native_data():
    owner = _owner(account_id="a" * 128)
    result = owner.prepare_initial_selection("c" * 128)
    assert result.call_id == "c" * 128
    assert result.status == "unavailable" and result.reason == "not_started"
    assert owner.status().phase == "new" and not owner.status().attempted


@pytest.mark.parametrize("name", ["configuration_path", "account_id", "instance_lock"])
def test_native_string_subclasses_cannot_invoke_user_conversion_during_admission(name):
    callbacks = []

    class HostileText(str):
        def __str__(self):
            callbacks.append("str")
            raise AssertionError("a native string boundary coerced a subclass")

        def __fspath__(self):
            callbacks.append("fspath")
            raise AssertionError("a path boundary invoked a subclass")

        def __len__(self):
            callbacks.append("len")
            raise AssertionError("a native string boundary measured a subclass")

    with pytest.raises(ValueError, match=_ARGUMENT):
        _owner(**{name: HostileText("/private/tmp/native.json")})
    assert callbacks == []


@pytest.mark.parametrize(
    "method", ["__init__", "start", "status", "stop", "prepare_initial_selection"]
)
def test_foreign_unbound_receiver_is_denied_without_loaning_attributes(method):
    callbacks = []

    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign receiver attributes were borrowed")

        def __setattr__(self, name, value):
            callbacks.append(name)
            raise AssertionError("foreign receiver received host state")

    operation = getattr(host.InitialSelectionPreparationOwner, method)
    with pytest.raises(ValueError, match=_ARGUMENT):
        if method == "__init__":
            operation(
                Foreign(),
                configuration_path="/private/tmp/native.json",
                account_id="native-account",
                instance_lock="/private/tmp/native.lock",
            )
        elif method == "prepare_initial_selection":
            operation(Foreign(), "native-call")
        else:
            operation(Foreign())
    assert callbacks == []


def test_reinitialization_cannot_reset_the_original_native_incarnation_or_latch():
    owner = _owner()
    before = vars(owner).copy()
    with pytest.raises(ValueError, match=_STATE):
        owner.__init__(
            configuration_path="/private/tmp/other.json",
            account_id="other-account",
            instance_lock="/private/tmp/other.lock",
        )
    assert vars(owner) == before
    assert owner.status().phase == "new"


def test_copied_receiver_cannot_borrow_original_condition_event_or_incarnation():
    owner = _owner()
    copied = copy.copy(owner)
    assert copied is not owner and type(copied) is type(owner)
    with pytest.raises(ValueError, match=_STATE):
        copied.status()
    assert owner.status().phase == "new"
    assert not owner.status().attempted


@pytest.mark.parametrize(
    "missing", ["_instance", "_condition", "_stop_event", "_limits", "_original", "_attempted"]
)
def test_missing_native_identity_or_state_fails_with_fixed_public_diagnostic(missing):
    owner = _owner()
    del vars(owner)[missing]
    with pytest.raises(ValueError, match=_STATE):
        owner.status()


@pytest.mark.parametrize("bad", [0, 1, None])
def test_attempt_latch_requires_native_boolean_state_before_transport_admission(bad):
    owner = _owner()
    owner._attempted = bad
    with pytest.raises(ValueError, match=_STATE):
        owner.prepare_initial_selection("bad-attempt-state")
    assert owner._slot is None


def test_saved_event_read_ignores_an_instance_is_set_callback():
    event = threading.Event()
    calls = []

    def replacement():
        calls.append("substitute")
        raise AssertionError("overridden Event method ran")

    event.is_set = replacement
    assert host._event_is_set(event) is False
    event.set()
    assert host._event_is_set(event) is True
    assert calls == []


@pytest.mark.parametrize("bad", [None, 0, 1, "set", object()])
def test_native_event_flag_cannot_smuggle_non_boolean_state(bad):
    event = threading.Event()
    event._flag = bad
    with pytest.raises(ValueError, match=_STATE):
        host._event_is_set(event)


@pytest.mark.parametrize("kind", ["object", "true", "number", "subclass"])
def test_invalid_cancel_event_does_not_claim_a_slot_or_consume_an_attempt(kind):
    class DerivedEvent(threading.Event):
        def is_set(self):
            raise AssertionError("a derived Event callback ran")

    bad = {"object": object(), "true": True, "number": 1, "subclass": DerivedEvent()}[kind]
    owner = _owner()
    before = owner.status()
    with pytest.raises(ValueError, match=_ARGUMENT):
        owner.prepare_initial_selection("invalid-cancel", cancel_event=bad)
    assert owner.status() == before and owner._slot is None


def _descriptor_values():
    record = InitialSelectionDescriptor(
        account_id="native-preparation-account",
        account_binding_sha256="0" * 64,
        stream_id="native-preparation-stream",
        after_assignment_sha256="1" * 64,
        ledger_sha256="2" * 64,
        order_sha256="3" * 64,
        capacity_sha256="4" * 64,
        effect_watermark=7,
        attempt_sha256="5" * 64,
        control_revision=11,
        lease_generation=13,
        dependency_schema_id="runtime-owner-dependencies/1",
        dependency_object_sha256="6" * 64,
        dependency_byte_count=1024,
        dependency_codec_version="personal-record/1",
        dependency_semantic_sha256="7" * 64,
        checked_at=datetime(2026, 10, 28, 14, 0, tzinfo=UTC),
        valid_until=datetime(2026, 10, 28, 14, 0, 30, tzinfo=UTC),
        c1_receipt_sha256="8" * 64,
        control_sha256="9" * 64,
        original_lease_sha256="a" * 64,
    )
    return tuple(getattr(record, field.name) for field in fields(record))


def test_pure_result_projection_makes_fresh_metadata_without_preparation_claim():
    # Literal metadata exercises serialization-free copying only. No original
    # Runtime, E adapter, retained object or actual successful work exists here.
    baseline = _descriptor_values()
    first = host._result("native-result", "native-incarnation", "prepared", baseline)
    second = host._result("native-result", "native-incarnation", "prepared", baseline)
    assert first is not second and first.descriptor is not second.descriptor
    assert (first.status, first.reason, first.call_id, first.incarnation) == (
        "prepared",
        "prepared",
        "native-result",
        "native-incarnation",
    )
    assert type(first.descriptor) is type(second.descriptor) is InitialSelectionDescriptor
    assert (
        tuple(getattr(first.descriptor, field.name) for field in fields(first.descriptor))
        == baseline
    )
    object.__setattr__(first.descriptor, "dependency_byte_count", 0)
    object.__setattr__(first.descriptor, "account_id", "caller-mutated")
    third = host._result("native-result", "native-incarnation", "prepared", baseline)
    assert third.descriptor == second.descriptor
    assert third.descriptor is not second.descriptor
    assert host._result("native-result", "native-incarnation", "cancelled").descriptor is None
    assert baseline == _descriptor_values()


def test_request_nonce_is_distinct_even_for_identical_correlation_fields():
    first = host._Request("same-id", "same-incarnation", _MAX_NS, None)
    second = host._Request("same-id", "same-incarnation", _MAX_NS, None)
    assert first is not second and first.nonce is not second.nonce
    assert first.call_id == second.call_id == "same-id"
    assert first.incarnation == second.incarnation == "same-incarnation"
    assert first.deadline_ns == second.deadline_ns == _MAX_NS
    assert first.result is second.result is None
    assert first.abandoned is first.dispatched is False
    first.abandoned = True
    assert second.abandoned is second.dispatched is False


def _idle_transport():
    """Stage only native request admission; there is NO worker or G/E graph.

    No work can consume a staged request. These carriers qualify caller waiting,
    slot identity and abandonment only, never startup or cleanup completion.
    """
    owner = _owner()
    with owner._condition:
        owner._phase = "idle"
        owner._busy = False
        owner._cleanup_ok = False
        owner._startup_deadline = _MAX_NS
        owner._lifetime_deadline = _MAX_NS
        owner._work_deadline = _MAX_NS
    return owner


def test_condition_wait_interruption_preserves_exact_primary_and_occupied_nonce(monkeypatch):
    owner = _idle_transport()
    primary = KeyboardInterrupt("native transport wait interruption")
    waiting = []

    def interrupt(timeout):
        waiting.append(timeout)
        assert owner._slot is not None
        assert not owner._slot.dispatched
        raise primary

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", interrupt)
        with pytest.raises(KeyboardInterrupt) as caught:
            owner.prepare_initial_selection("interrupted")
    assert caught.value is primary and len(waiting) == 1
    request = owner._slot
    assert request is not None and request.call_id == "interrupted"
    assert request.abandoned and not request.dispatched
    assert not owner.status().attempted
    result = owner.prepare_initial_selection("interrupted")
    assert (result.status, result.reason, result.descriptor) == ("unavailable", "busy", None)
    assert owner._slot is request and owner._active_nonce is request.nonce
    assert owner.status().busy


def test_condition_cancellation_abandons_only_request_without_releasing_slot(monkeypatch):
    owner = _idle_transport()
    cancelled = threading.Event()
    waiting = []

    def cancel(timeout):
        waiting.append(timeout)
        cancelled.set()
        return False

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", cancel)
        result = owner.prepare_initial_selection("cancelled", cancel_event=cancelled)
    assert (result.status, result.reason, result.descriptor) == ("unavailable", "cancelled", None)
    assert len(waiting) == 1
    request = owner._slot
    assert request is not None and request.abandoned and not request.dispatched
    assert owner._active_nonce is request.nonce
    assert owner.status().busy and not owner.status().attempted
    assert not owner._stop_event.is_set()
    cancelled.clear()
    assert owner.prepare_initial_selection("cancelled", cancel_event=cancelled).reason == "busy"
    assert owner._slot is request


def test_pre_cancelled_native_transport_call_does_not_create_a_request():
    owner = _idle_transport()
    cancelled = threading.Event()
    cancelled.set()
    result = owner.prepare_initial_selection("not-dispatched", cancel_event=cancelled)
    assert (result.status, result.reason, result.descriptor) == ("unavailable", "cancelled", None)
    assert owner._slot is None and owner._active_nonce is None
    assert not owner.status().busy and not owner.status().attempted
    assert not owner._stop_event.is_set()


def test_native_transport_reentry_returns_without_waiting_or_claiming_a_request(monkeypatch):
    owner = _idle_transport()
    callbacks = []
    outcomes = []

    def forbidden(timeout):
        callbacks.append(timeout)
        raise AssertionError("owner-thread reentry attempted to wait")

    def enter():
        try:
            owner._thread = threading.current_thread()
            outcomes.append(owner.prepare_initial_selection("owner-thread"))
        except BaseException as error:
            outcomes.append(error)

    caller = threading.Thread(target=enter)
    try:
        with monkeypatch.context() as local:
            local.setattr(owner._condition, "wait", forbidden)
            caller.start()
            caller.join(2)
    finally:
        if caller.ident is not None:
            caller.join(2)
    assert not caller.is_alive() and len(outcomes) == 1
    result = outcomes[0]
    assert (result.status, result.reason, result.descriptor) == ("unavailable", "reentrant", None)
    assert callbacks == []
    assert owner._slot is None and owner._active_nonce is None
    assert not owner.status().attempted


def test_existing_shutdown_cutoff_never_resets_or_infers_completion_from_not_alive(monkeypatch):
    owner = _idle_transport()
    # Deliberately unstarted native Thread: this pure model has no evidence of
    # _run completion. A false is_alive alone cannot qualify actual cleanup.
    owner._thread = threading.Thread(target=lambda: None)
    owner._shutdown_deadline = 1
    callbacks = []

    def forbidden(timeout):
        callbacks.append(timeout)
        raise AssertionError("an elapsed shutdown cutoff granted another wait")

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", forbidden)
        first, second = owner.stop(), owner.stop()
    assert callbacks == []
    assert owner._shutdown_deadline == 1
    assert first.phase == second.phase == "stopping"
    assert first.cleanup_complete is second.cleanup_complete is False
    assert not owner._thread.is_alive()
    assert owner._finalized is False


_OWN_METHODS = (
    "__init__",
    "start",
    "status",
    "stop",
    "prepare_initial_selection",
    "_snapshot",
    "_latch",
    "_now",
    "_serve",
    "_run",
)


@pytest.mark.parametrize("method", _OWN_METHODS)
@pytest.mark.parametrize("placement", ["class", "instance"])
def test_saved_public_entry_denies_finite_workflow_substitution_before_callback(
    monkeypatch, method, placement
):
    owner = _owner()
    original_entry = host.InitialSelectionPreparationOwner.status
    assert tuple(name for name, _ in host._OWN_METHODS) == _OWN_METHODS
    assert original_entry(owner).phase == "new"
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("changed host workflow ran")

    with monkeypatch.context() as local:
        if placement == "class":
            local.setattr(type(owner), method, replacement)
        else:
            local.setitem(vars(owner), method, replacement)
        # The protected original entry is explicit. Invoking a replaced public
        # callable itself is outside this finite cooperating-process claim.
        with pytest.raises(RuntimeError, match=_BINDING):
            original_entry(owner)
    assert calls == []
    assert original_entry(owner).phase == "new"


@pytest.mark.parametrize(
    "binding",
    [
        "argument_path",
        "generator",
        "adapter_class",
        "adapter_init",
        "adapter_prepare",
        "adapter_descriptor",
        "descriptor_class",
        "descriptor_init",
        "descriptor_values",
        "validated_values",
        "descriptor_copy",
    ],
)
def test_pure_operation_binding_gate_never_invokes_changed_g_e_or_d_callbacks(monkeypatch, binding):
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("a changed configured/preparation/data operation ran")

    targets = {
        "argument_path": (host.configured, "_argument_path"),
        "generator": (host.configured, "_configured_runtime_generator"),
        "adapter_class": (host.preparation, "_InitialSelectionPreparation"),
        "adapter_init": (host._ADAPTER, "__init__"),
        "adapter_prepare": (host._ADAPTER, "prepare"),
        "adapter_descriptor": (host._ADAPTER, "descriptor"),
        "descriptor_class": (host.descriptors, "InitialSelectionDescriptor"),
        "descriptor_init": (InitialSelectionDescriptor, "__post_init__"),
        "descriptor_values": (host.descriptors, "_descriptor_values"),
        "validated_values": (host.descriptors, "_validated_values"),
        "descriptor_copy": (host.descriptors, "_from_values"),
    }
    assert host._operation_bindings() is None
    with monkeypatch.context() as local:
        target, name = targets[binding]
        local.setattr(target, name, replacement)
        with pytest.raises(RuntimeError, match=_BINDING):
            host._operation_bindings()
    assert calls == []
    assert host._operation_bindings() is None


@pytest.mark.parametrize(
    "binding",
    ["property", "class-require", "instance-property", "instance-require", "runtime-class"],
)
def test_lease_ceiling_binding_denial_precedes_any_substituted_property_or_require(
    monkeypatch, binding
):
    # This incomplete exact-class carrier is NEVER admitted as a runtime. Only
    # the negative finite binding gate is reached, before original _require.
    runtime = object.__new__(host._RUNTIME)
    runtime._instance = runtime
    runtime._thread = threading.current_thread()
    calls = []

    def replacement(*args, **kwargs):
        calls.append("substitute")
        raise AssertionError("changed R1 property or require ran")

    with monkeypatch.context() as local:
        if binding == "property":
            local.setattr(host._RUNTIME, "lease_deadline_ns", property(replacement))
        elif binding == "class-require":
            local.setattr(host._RUNTIME, "_require", replacement)
        elif binding == "instance-property":
            local.setitem(vars(runtime), "lease_deadline_ns", replacement)
        elif binding == "instance-require":
            local.setitem(vars(runtime), "_require", replacement)
        else:
            local.setattr(host.readiness, "_ReadinessRuntime", replacement)
        with pytest.raises(RuntimeError, match=_BINDING):
            host._lease_ceiling(runtime)
    assert calls == []


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, RuntimeError])
def test_unacknowledged_native_start_never_infers_cleanup_from_unstarted_thread(
    monkeypatch, error_type
):
    owner = _owner(limits=ReadinessOwnerLimits(shutdown_ns=1))
    primary = error_type("native launch acknowledgement unknown")
    attempts = []

    def unacknowledged(thread):
        # Model only the low-level start acknowledgement. No native launch or
        # configured/preparation work occurs; a false alive flag proves none.
        attempts.append(thread)
        raise primary

    with monkeypatch.context() as local:
        local.setattr(host, "_THREAD_START", unacknowledged)
        started = owner.start()
        stopped = owner.stop()
        repeated = owner.start()
    assert len(attempts) == 1 and attempts[0] is owner._thread
    assert owner._thread.ident is None and not owner._thread.is_alive()
    assert owner._primary_error is primary
    assert started.phase == stopped.phase == repeated.phase == "stopping"
    assert (
        started.cleanup_complete is stopped.cleanup_complete is repeated.cleanup_complete is False
    )
    assert owner._finalized is False and not owner.status().attempted


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, RuntimeError])
def test_actual_start_then_failed_ack_finishes_before_any_configured_work(monkeypatch, error_type):
    owner = _owner(limits=ReadinessOwnerLimits(shutdown_ns=1))
    primary = error_type("native launch completed before failed acknowledgement")
    original_start = host._THREAD_START
    attempts = []
    effects = []

    def launched(thread):
        attempts.append(thread)
        original_start(thread)
        raise primary

    def forbidden(*args, **kwargs):
        effects.append("effect")
        raise AssertionError("latched startup still reached configured I/O")

    try:
        with monkeypatch.context() as local:
            local.setattr(host, "_THREAD_START", launched)
            local.setattr(Path, "resolve", forbidden)
            local.setattr(Engine, "connect", forbidden)
            started = owner.start()
            assert started.phase == "stopping" and not started.cleanup_complete
            assert len(attempts) == 1
            attempts[0].join(2)
            assert not attempts[0].is_alive()
            stopped = owner.status()
    finally:
        for thread in attempts:
            thread.join(2)
            assert not thread.is_alive()
    assert effects == [] and owner._primary_error is primary
    assert stopped.phase == "stopped" and stopped.cleanup_complete
    assert stopped.primary_failure == "startup_failed" and stopped.cleanup_failure is None
    assert not stopped.attempted and owner._slot is None


@pytest.mark.parametrize("bad", [None, True, -1, 1.5, "1", _MAX_NS + 1])
def test_native_monotonic_sampling_denies_invalid_values_without_starting_work(monkeypatch, bad):
    owner = _owner()
    monkeypatch.setattr(host.time, "monotonic_ns", lambda: bad)
    with owner._condition:
        assert host._NOW(owner) is None
    status = owner.status()
    assert status.phase == "stopped" and status.primary_failure == "clock_invalid"
    assert status.cleanup_complete and not status.attempted
    assert owner._thread is None and owner._slot is None


def test_positive_native_monotonic_regression_latches_denial_without_dispatch(monkeypatch):
    owner = _owner()
    samples = iter([100, 99])
    monkeypatch.setattr(host.time, "monotonic_ns", lambda: next(samples))
    with owner._condition:
        assert host._NOW(owner) == 100
        assert host._NOW(owner) is None
    assert owner.status().primary_failure == "clock_invalid"
    assert owner.status().attempted is False and owner._slot is None


def _delivery_tail(monkeypatch, owner, *, fault=None):
    """Stage a native acknowledgement, never an actual G/E completion.

    Literal D data and a controlled Condition wake exercise only the caller's
    delivery tail. No worker, runtime, adapter, proof or retained object exists.
    """
    held = []

    def acknowledge(timeout):
        request = owner._slot
        held.append(request)
        request.dispatched = True
        request.result = ("prepared", _descriptor_values())
        owner._attempted = True
        owner._slot = owner._active_nonce = None
        owner._busy, owner._phase = False, "idle"
        if fault == "undispatched":
            request.dispatched = False
        elif fault == "unattempted":
            owner._attempted = False
        elif fault == "foreign-slot":
            foreign = host._Request(request.call_id, request.incarnation, request.deadline_ns, None)
            owner._slot, owner._active_nonce = foreign, foreign.nonce
        elif fault == "busy":
            owner._busy = True
        elif fault == "phase":
            owner._phase = "busy"
        return False

    monkeypatch.setattr(owner._condition, "wait", acknowledge)
    return held


@pytest.mark.parametrize("fault", ["undispatched", "unattempted", "foreign-slot", "busy", "phase"])
def test_native_delivery_tail_rejects_an_unacknowledged_or_replaced_request(monkeypatch, fault):
    owner = _idle_transport()
    held = _delivery_tail(monkeypatch, owner, fault=fault)
    with pytest.raises(ValueError, match=_STATE):
        owner.prepare_initial_selection("native-tail")
    assert len(held) == 1 and held[0].abandoned
    assert owner._thread is None
    if fault == "foreign-slot":
        assert owner._slot is not held[0]
        assert owner._slot.call_id == held[0].call_id
        assert owner._slot.nonce is not held[0].nonce


def test_native_delivery_tail_projects_only_the_acknowledged_request_data(monkeypatch):
    owner = _idle_transport()
    held = _delivery_tail(monkeypatch, owner)
    result = owner.prepare_initial_selection("native-tail")
    assert result.status == result.reason == "prepared"
    assert result.call_id == "native-tail" and result.incarnation == owner.status().incarnation
    assert type(result.descriptor) is InitialSelectionDescriptor
    assert tuple(getattr(result.descriptor, field.name) for field in fields(result.descriptor)) == (
        _descriptor_values()
    )
    assert len(held) == 1 and held[0].dispatched and not held[0].abandoned
    assert owner._slot is owner._active_nonce is owner._thread is None


@pytest.mark.parametrize("mode", ["clock", "stop", "deadline", "cancel"])
def test_rejection_after_native_projection_marks_the_request_abandoned(monkeypatch, mode):
    owner = _idle_transport()
    held = _delivery_tail(monkeypatch, owner)
    clock = [100]
    cancelled = threading.Event()
    monkeypatch.setattr(host.time, "monotonic_ns", lambda: clock[0])
    original_profile = sys.getprofile()
    result_code = host._result.__code__
    observations = []

    def profile(frame, event, argument):
        if (
            event != "return"
            or frame.f_code is not result_code
            or type(argument) is not host.InitialSelectionPreparationResult
            or argument.status != "prepared"
        ):
            return
        observations.append(mode)
        if mode == "clock":
            clock[0] = None
        elif mode == "stop":
            owner._stop_latched = True
            owner._stop_event.set()
        elif mode == "deadline":
            clock[0] = held[0].deadline_ns
        else:
            cancelled.set()

    try:
        sys.setprofile(profile)
        result = owner.prepare_initial_selection("native-tail", cancel_event=cancelled)
    finally:
        sys.setprofile(original_profile)
    assert sys.getprofile() is original_profile
    expected = {
        "clock": "clock_invalid",
        "stop": "stopping",
        "deadline": "deadline",
        "cancel": "cancelled",
    }[mode]
    assert (result.status, result.reason, result.descriptor) == ("unavailable", expected, None)
    assert observations == [mode]
    assert len(held) == 1 and held[0].abandoned
    assert owner._thread is None


def test_sampled_predispatch_cancellation_acknowledges_cancelled_after_event_clears(monkeypatch):
    owner = _idle_transport()
    cancelled = threading.Event()
    cancelled.set()
    request = host._Request("sampled-cancel", owner._incarnation, _MAX_NS, cancelled)
    owner._slot, owner._active_nonce = request, request.nonce
    owner._busy, owner._phase = True, "busy"
    callbacks = []
    acknowledgements = []

    class Unreadable:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("pre-dispatch cancellation borrowed financial work")

    def after_acknowledgement(timeout):
        # The next idle wait occurs only after this original _SERVE dispatch
        # branch has acknowledged the slot. Clear the caller Event before any
        # possible delivery so its later value cannot hide a wrong reason.
        cancelled.clear()
        acknowledgements.append(request.result)
        owner._stop_latched = True
        owner._stop_event.set()
        return False

    with monkeypatch.context() as local:
        local.setattr(owner._condition, "wait", after_acknowledgement)
        host._SERVE(owner, Unreadable(), Unreadable())
    assert acknowledgements == [("cancelled", None)]
    assert request.result == ("cancelled", None)
    assert not cancelled.is_set()
    assert callbacks == [] and not request.dispatched
    assert not owner.status().attempted
    assert owner._slot is owner._active_nonce is owner._thread is None
