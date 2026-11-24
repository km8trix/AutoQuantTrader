"""Finite inert native-timing controls; no worker, SQL, account or deadline fit.

Expected wires and interval sums are handwritten. Clock substitutions are private
finite seams installed only after genuine native constructor admission; there is
no public custom-clock API. Lifetime controls use no forced GC or manual cleanup
of a new auxiliary edge. Thread controls always release and join their children.
"""

import copy
import json
import sys
import weakref
from threading import Event, Thread, current_thread
from time import perf_counter_ns, thread_time_ns

import pytest

from tests.fixtures import lifecycle_failure_output as output
from tests.fixtures import lifecycle_forwarding_diagnostic as forwarding

PORTS = ("prepare", "observe", "require_result")
EMPTY_V1 = (
    '{"schema_version":1,"available":true,"incomplete":false,"overflow":false,'
    '"state":"empty","stages":{"prepare":{"entered":0,"returned":0,"raised":0,'
    '"active":0},"observe":{"entered":0,"returned":0,"raised":0,"active":0},'
    '"require_result":{"entered":0,"returned":0,"raised":0,"active":0}}}'
)
UNKNOWN_V1 = (
    '{"schema_version":1,"available":false,"incomplete":true,"overflow":false,'
    '"state":"unavailable","stages":null}'
)
UNKNOWN_V2 = (
    '{"schema_version":2,"available":false,"incomplete":true,"overflow":false,'
    '"state":"unavailable","stages":null,"timing":{"available":false,'
    '"overflow":false,"stages":null}}'
)
ZERO_TIMING = {
    "completed_count": 0,
    "wall_sum_ns": 0,
    "wall_max_ns": 0,
    "thread_cpu_sum_ns": 0,
    "thread_cpu_max_ns": 0,
}


class DynamicDelegate:
    def __init__(self, callback):
        self.callback = callback
        self.lookups = []

    def __getattribute__(self, name):
        if name in PORTS:
            object.__getattribute__(self, "lookups").append(name)
            return object.__getattribute__(self, "callback")
        return object.__getattribute__(self, name)


def invoke(port, target, first=None, second=None):
    try:
        if port == "prepare":
            return target.prepare(first)
        if port == "observe":
            return target.observe(child_pid=first, child_exited=second)
        return target.require_result(first)
    finally:
        target = first = second = None


def arguments(port, first, second):
    return (
        ((), {"child_pid": first, "child_exited": second}) if port == "observe" else ((first,), {})
    )


def timed(wall, cpu):
    diagnostic = forwarding.LifecycleForwardingDiagnostic(native_timing=True)
    assert diagnostic._wall_clock_ns is perf_counter_ns
    assert diagnostic._thread_clock_ns is thread_time_ns
    diagnostic._wall_clock_ns = wall
    diagnostic._thread_clock_ns = cpu
    return diagnostic


def samples(wall_values=(100, 160), cpu_values=(200, 225)):
    wall, cpu = iter(wall_values), iter(cpu_values)
    return timed(lambda: next(wall), lambda: next(cpu))


def original_error(kind=ValueError):
    primary, cause, context = kind("original"), LookupError("cause"), IndexError("context")
    primary.__cause__, primary.__context__ = cause, context
    primary.__suppress_context__ = False
    return primary, cause, context


def assert_original(primary, cause, context):
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False


def assert_timing_unknown(diagnostic, *, overflow):
    value = diagnostic.snapshot()
    assert value["schema_version"] == 2
    assert value["timing"] == {"available": False, "overflow": overflow, "stages": None}
    return value


@pytest.mark.parametrize("explicit", [False, True])
def test_default_v1_literal_wire_has_no_native_reads_or_owner_retention(monkeypatch, explicit):
    calls = []

    def forbidden():
        calls.append(None)
        raise AssertionError("default mode must not sample")

    monkeypatch.setattr(forwarding, "_native_wall_time_ns", forbidden)
    monkeypatch.setattr(forwarding, "_native_thread_time_ns", forbidden)
    diagnostic = (
        forwarding.LifecycleForwardingDiagnostic(native_timing=False)
        if explicit
        else forwarding.LifecycleForwardingDiagnostic()
    )
    assert diagnostic.summary() == EMPTY_V1
    delegate = DynamicDelegate(lambda value: value)
    argument = object()
    assert forwarding.ObservedLifecycle(delegate, diagnostic).prepare(argument) is argument
    assert calls == [] and delegate.lookups == ["prepare"]
    assert diagnostic._wall_clock_ns is None and diagnostic._thread_clock_ns is None
    assert "timing" not in diagnostic.snapshot()


class HookValue:
    def __bool__(self):
        raise AssertionError("foreign boolean hook")

    def __int__(self):
        raise AssertionError("foreign integer hook")

    def __index__(self):
        raise AssertionError("foreign index hook")

    def __eq__(self, other):
        raise AssertionError("foreign equality hook")

    def __repr__(self):
        raise AssertionError("foreign representation hook")


class IntSubclass(int):
    pass


@pytest.mark.parametrize("value", [None, 0, 1, "true", IntSubclass(1), HookValue()])
@pytest.mark.parametrize("constructor", ["recorder", "manager", "create"])
def test_native_timing_admission_is_exact_bool_before_setup(monkeypatch, value, constructor):
    called = []

    def forbidden(*args, **kwargs):
        called.append((args, kwargs))
        raise AssertionError("setup before primitive admission")

    monkeypatch.setattr(forwarding, "Lock", forbidden)
    if constructor == "recorder":
        with pytest.raises((TypeError, ValueError)):
            forwarding.LifecycleForwardingDiagnostic(native_timing=value)
    elif constructor == "manager":
        with pytest.raises((TypeError, ValueError)):
            output.ParentLifecycleDiagnostics(native_timing=value)
    else:
        with pytest.raises(TypeError, match="exact bool"):
            output.create_parent_diagnostics(native_timing=value)
    assert called == []


@pytest.mark.parametrize("port", PORTS)
@pytest.mark.parametrize("raises", [False, True])
def test_v2_handwritten_intervals_preserve_lookup_once_inputs_result_and_primary(port, raises):
    first, second, result = object(), object(), object()
    calls = []
    primary, cause, context = original_error()

    def callback(*args, **kwargs):
        calls.append((args, kwargs))
        if raises:
            raise primary
        return result

    diagnostic = samples()
    delegate = DynamicDelegate(callback)
    observed = forwarding.ObservedLifecycle(delegate, diagnostic)
    if raises:
        with pytest.raises(ValueError) as caught:
            invoke(port, observed, first, second)
        assert caught.value is primary
        assert_original(primary, cause, context)
    else:
        assert invoke(port, observed, first, second) is result
    assert calls == [arguments(port, first, second)] and delegate.lookups == [port]
    snapshot = diagnostic.snapshot()
    assert list(snapshot) == [
        "schema_version",
        "available",
        "incomplete",
        "overflow",
        "state",
        "stages",
        "timing",
    ]
    assert snapshot["schema_version"] == 2 and snapshot["available"] is True
    assert snapshot["state"] == "balanced"
    assert snapshot["stages"][port] == {
        "entered": 1,
        "returned": int(not raises),
        "raised": int(raises),
        "active": 0,
    }
    expected = {name: ZERO_TIMING.copy() for name in PORTS}
    expected[port] = {
        "completed_count": 1,
        "wall_sum_ns": 60,
        "wall_max_ns": 60,
        "thread_cpu_sum_ns": 25,
        "thread_cpu_max_ns": 25,
    }
    assert snapshot["timing"] == {"available": True, "overflow": False, "stages": expected}


def test_completed_sums_maxima_are_handwritten_across_ports_and_raised_callbacks():
    diagnostic = samples((10, 60, 100, 170, 200, 225, 300, 390), (20, 30, 40, 75, 80, 85, 90, 130))
    primary, _, _ = original_error()

    def callback(value):
        if value == "raises":
            raise primary
        return value

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    assert observed.prepare("first") == "first"
    with pytest.raises(ValueError):
        observed.prepare("raises")
    assert observed.require_result("third") == "third"
    assert observed.require_result("fourth") == "fourth"
    assert diagnostic.snapshot()["timing"] == {
        "available": True,
        "overflow": False,
        "stages": {
            "prepare": {
                "completed_count": 2,
                "wall_sum_ns": 120,
                "wall_max_ns": 70,
                "thread_cpu_sum_ns": 45,
                "thread_cpu_max_ns": 35,
            },
            "observe": ZERO_TIMING.copy(),
            "require_result": {
                "completed_count": 2,
                "wall_sum_ns": 115,
                "wall_max_ns": 90,
                "thread_cpu_sum_ns": 45,
                "thread_cpu_max_ns": 40,
            },
        },
    }


@pytest.mark.parametrize("port", PORTS)
def test_sample_precedes_fresh_delegate_lookup_and_pointer_is_frozen(monkeypatch, port):
    events = []
    wall, cpu = iter((10, 30)), iter((40, 47))

    def wall_clock():
        events.append("wall")
        return next(wall)

    def cpu_clock():
        events.append("cpu")
        return next(cpu)

    diagnostic = timed(wall_clock, cpu_clock)

    class Delegate:
        def __getattribute__(self, name):
            assert name == port
            events.append("lookup")
            monkeypatch.setattr(forwarding, "_native_wall_time_ns", HookValue())
            monkeypatch.setattr(forwarding, "_native_thread_time_ns", HookValue())

            def callback(*args, **kwargs):
                events.append("callback")
                return 77

            return callback

    assert invoke(port, forwarding.ObservedLifecycle(Delegate(), diagnostic)) == 77
    assert events == ["wall", "cpu", "lookup", "callback", "wall", "cpu"]
    assert diagnostic._wall_clock_ns is wall_clock and diagnostic._thread_clock_ns is cpu_clock
    assert diagnostic.snapshot()["timing"]["stages"][port]["wall_sum_ns"] == 20


@pytest.mark.parametrize("clock", ["wall", "cpu"])
@pytest.mark.parametrize("phase", ["start", "end"])
@pytest.mark.parametrize(
    "value", [None, True, False, -1, 1.0, "1", IntSubclass(1), (1 << 63), HookValue()]
)
def test_invalid_native_endpoint_denies_timing_without_inspecting_values(clock, phase, value):
    count = 0

    def selected_clock():
        nonlocal count
        count += 1
        return value if count == (1 if phase == "start" else 2) else 100

    diagnostic = (
        timed(selected_clock, lambda: 100)
        if clock == "wall"
        else timed(lambda: 100, selected_clock)
    )
    result, calls = object(), []

    def callback(value):
        calls.append(value)
        return result

    assert forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic).prepare(17) is result
    snapshot = assert_timing_unknown(diagnostic, overflow=True)
    assert calls == [17] and snapshot["available"] is True
    assert snapshot["stages"]["prepare"] == {"entered": 1, "returned": 1, "raised": 0, "active": 0}


@pytest.mark.parametrize("clock", ["wall", "cpu"])
@pytest.mark.parametrize("start,end", [(2, 1), (0, 10**15 + 1)])
def test_backward_or_excess_elapsed_is_unavailable_and_sticky(clock, start, end):
    values = iter((start, end, 1, 2))
    diagnostic = (
        timed(lambda: next(values), lambda: 100)
        if clock == "wall"
        else timed(lambda: 100, lambda: next(values))
    )
    observed = forwarding.ObservedLifecycle(DynamicDelegate(lambda value: value), diagnostic)
    assert observed.prepare("first") == "first"
    assert_timing_unknown(diagnostic, overflow=True)
    assert observed.prepare("second") == "second"
    snapshot = assert_timing_unknown(diagnostic, overflow=True)
    assert snapshot["stages"]["prepare"]["returned"] == 2


def test_exact_endpoint_and_elapsed_caps_are_admitted_but_aggregate_saturation_is_not():
    limit = (1 << 63) - 1
    diagnostic = samples((limit - 10**15, limit, 0, 1), (limit - 10**15, limit, 0, 1))
    observed = forwarding.ObservedLifecycle(DynamicDelegate(lambda value: value), diagnostic)
    assert observed.prepare(None) is None
    assert diagnostic.snapshot()["timing"]["stages"]["prepare"] == {
        "completed_count": 1,
        "wall_sum_ns": 10**15,
        "wall_max_ns": 10**15,
        "thread_cpu_sum_ns": 10**15,
        "thread_cpu_max_ns": 10**15,
    }
    assert observed.prepare(None) is None
    snapshot = assert_timing_unknown(diagnostic, overflow=True)
    assert snapshot["stages"]["prepare"]["returned"] == 2


@pytest.mark.parametrize("clock", ["wall", "cpu"])
@pytest.mark.parametrize("phase", ["start", "end"])
@pytest.mark.parametrize("port", PORTS)
def test_exact_native_oserror_is_metadata_only_and_forwarding_remains_balanced(clock, phase, port):
    metadata, calls, samples_count = OSError("private metadata"), [], 0

    def failing_clock():
        nonlocal samples_count
        samples_count += 1
        if samples_count == (1 if phase == "start" else 2):
            raise metadata
        return 100

    diagnostic = (
        timed(failing_clock, lambda: 100) if clock == "wall" else timed(lambda: 100, failing_clock)
    )
    result = object()

    def callback(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    first, second = object(), object()
    assert (
        invoke(
            port, forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic), first, second
        )
        is result
    )
    assert calls == [arguments(port, first, second)]
    snapshot = assert_timing_unknown(diagnostic, overflow=True)
    assert snapshot["stages"][port] == {"entered": 1, "returned": 1, "raised": 0, "active": 0}
    assert metadata.__traceback__ is None


class RestoreDeadline(BaseException):
    pass


@pytest.mark.parametrize("kind", [KeyboardInterrupt, RestoreDeadline])
@pytest.mark.parametrize("phase", ["start", "end"])
@pytest.mark.parametrize("ambient", [False, True])
def test_new_interrupt_is_not_suppressed_by_ambient_exception(kind, phase, ambient):
    interrupt, calls, count = kind("external interrupt"), [], 0

    def clock():
        nonlocal count
        count += 1
        if count == (1 if phase == "start" else 2):
            raise interrupt
        return 10

    diagnostic = timed(clock, lambda: 20)
    observed = forwarding.ObservedLifecycle(
        DynamicDelegate(lambda value: calls.append(value)), diagnostic
    )
    if ambient:
        try:
            raise ValueError("unrelated outer exception")
        except ValueError:
            with pytest.raises(kind) as caught:
                observed.prepare(77)
    else:
        with pytest.raises(kind) as caught:
            observed.prepare(77)
    assert caught.value is interrupt
    assert calls == ([] if phase == "start" else [77])
    assert_timing_unknown(diagnostic, overflow=True)


@pytest.mark.parametrize("clock", ["wall", "cpu"])
@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt, RestoreDeadline])
def test_pending_operation_primary_survives_end_clock_fault_with_exact_edges(clock, kind):
    primary, cause, context = original_error()
    metadata, count = kind("new metadata fault"), 0

    def failing_clock():
        nonlocal count
        count += 1
        if count == 2:
            raise metadata
        return 100

    diagnostic = (
        timed(failing_clock, lambda: 100) if clock == "wall" else timed(lambda: 100, failing_clock)
    )

    def callback(value):
        raise primary

    with pytest.raises(ValueError) as caught:
        forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic).prepare(None)
    assert caught.value is primary
    assert_original(primary, cause, context)
    assert metadata.__traceback__ is None and metadata.__context__ is None
    snapshot = assert_timing_unknown(diagnostic, overflow=True)
    assert snapshot["stages"]["prepare"] == {"entered": 1, "returned": 0, "raised": 1, "active": 0}


def test_same_pending_primary_restores_exact_entry_traceback_before_outer_catch():
    primary, cause, context = original_error()
    count, entries = 0, []

    def clock():
        nonlocal count
        count += 1
        if count == 2:
            entries.append(BaseException.__traceback__.__get__(primary))
            raise primary
        return 10

    diagnostic = timed(clock, lambda: 20)

    def callback(value):
        raise primary

    with pytest.raises(ValueError) as caught:
        forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic).prepare(None)
    assert caught.value is primary and len(entries) == 1 and entries[0] is not None
    current = BaseException.__traceback__.__get__(primary)
    names = []
    while current is not entries[0]:
        assert current is not None
        names.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    assert names == [
        "test_same_pending_primary_restores_exact_entry_traceback_before_outer_catch",
        "prepare",
    ]
    assert_original(primary, cause, context)


@pytest.mark.parametrize("direct_cause", [False, True])
@pytest.mark.parametrize("suppressed", [False, True])
def test_auxiliary_detaches_direct_primary_only_preserving_foreign_cause_and_suppression(
    direct_cause, suppressed
):
    primary, cause, context = original_error()
    metadata, foreign, count = RuntimeError("retained auxiliary"), LookupError("foreign"), 0

    def clock():
        nonlocal count
        count += 1
        if count == 2:
            metadata.__cause__ = primary if direct_cause else foreign
            metadata.__suppress_context__ = suppressed
            raise metadata
        return 10

    diagnostic = timed(clock, lambda: 20)

    def callback(value):
        raise primary

    with pytest.raises(ValueError) as caught:
        forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic).prepare(None)
    assert caught.value is primary
    assert_original(primary, cause, context)
    assert metadata.__traceback__ is None and metadata.__context__ is None
    assert metadata.__cause__ is (None if direct_cause else foreign)
    assert metadata.__suppress_context__ is suppressed


def test_auxiliary_unrelated_context_is_preserved():
    primary, cause, context = original_error()
    metadata, foreign, count = RuntimeError("retained auxiliary"), LookupError("foreign"), 0

    def clock():
        nonlocal count
        count += 1
        if count == 2:
            try:
                raise metadata
            finally:
                metadata.__context__ = foreign
        return 10

    diagnostic = timed(clock, lambda: 20)

    def callback(value):
        raise primary

    with pytest.raises(ValueError) as caught:
        forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic).prepare(None)
    assert caught.value is primary
    assert_original(primary, cause, context)
    assert metadata.__traceback__ is None and metadata.__context__ is foreign


def test_active_callback_snapshot_contains_only_completed_intervals_and_no_clock_read():
    entered, release = Event(), Event()
    wall, cpu = iter((10, 50)), iter((100, 115))
    clock_calls, errors = [], []

    def clock(values, label):
        clock_calls.append(label)
        return next(values)

    diagnostic = timed(lambda: clock(wall, "wall"), lambda: clock(cpu, "cpu"))

    def callback(value):
        entered.set()
        assert release.wait(2)
        return value

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)

    def run():
        try:
            assert observed.prepare(77) == 77
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=run)
    thread.start()
    try:
        assert entered.wait(2)
        snapshot = diagnostic.snapshot()
        assert snapshot["state"] == "active"
        assert snapshot["stages"]["prepare"] == {
            "entered": 1,
            "returned": 0,
            "raised": 0,
            "active": 1,
        }
        assert snapshot["timing"]["stages"]["prepare"] == ZERO_TIMING
        assert clock_calls == ["wall", "cpu"]
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and errors == []
    assert diagnostic.snapshot()["timing"]["stages"]["prepare"] == {
        "completed_count": 1,
        "wall_sum_ns": 40,
        "wall_max_ns": 40,
        "thread_cpu_sum_ns": 15,
        "thread_cpu_max_ns": 15,
    }


def test_genuine_metadata_lock_contention_does_not_block_callback_or_sample():
    diagnostic = samples()
    calls = []
    observed = forwarding.ObservedLifecycle(
        DynamicDelegate(lambda value: calls.append(value)), diagnostic
    )
    diagnostic._lock.acquire()
    try:
        assert observed.prepare(77) is None
        snapshot = diagnostic.snapshot()
        assert snapshot["available"] is False and snapshot["stages"] is None
    finally:
        diagnostic._lock.release()
    assert calls == [77]


def test_reentrant_intervals_are_completed_independently_with_explicit_overlap():
    diagnostic = samples((10, 20, 50, 80), (100, 110, 130, 145))
    observed = None

    def callback(value):
        if value == "outer":
            return observed.prepare("inner")
        return "result"

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    assert observed.prepare("outer") == "result"
    value = diagnostic.snapshot()
    assert value["stages"]["prepare"] == {"entered": 2, "returned": 2, "raised": 0, "active": 0}
    assert value["timing"]["stages"]["prepare"] == {
        "completed_count": 2,
        "wall_sum_ns": 100,
        "wall_max_ns": 70,
        "thread_cpu_sum_ns": 65,
        "thread_cpu_max_ns": 45,
    }
    assert value["timing"]["stages"]["prepare"]["wall_sum_ns"] > 80 - 10


def test_default_manager_literal_unknown_line_and_enabled_unknown_slots(monkeypatch):
    lines = []

    class Sink:
        def write(self, text):
            lines.append(text)

    monkeypatch.setattr(sys, "stdout", Sink())
    manager = output.create_parent_diagnostics()
    output.emit_parent_failure_line(manager, iteration=1)
    assert lines == [
        "AQT_PARENT_LIFECYCLE_DIAGNOSTIC "
        '{"schema_version":1,"current_iteration":1,"misused":false,"iterations":['
        + UNKNOWN_V1
        + ","
        + UNKNOWN_V1
        + "]}\n"
    ]
    lines.clear()
    enabled = output.create_parent_diagnostics(native_timing=True)
    output.emit_parent_failure_line(enabled, iteration=2)
    assert lines == [
        "AQT_PARENT_LIFECYCLE_DIAGNOSTIC "
        '{"schema_version":2,"current_iteration":2,"misused":false,"iterations":['
        + UNKNOWN_V2
        + ","
        + UNKNOWN_V2
        + "]}\n"
    ]


def test_two_enabled_slots_are_admitted_once_and_third_attempt_does_not_allocate(monkeypatch):
    manager = output.create_parent_diagnostics(native_timing=True)
    first, second, third = object(), object(), object()
    wrapped1 = output.wrap_already_constructed(first, diagnostics=manager, iteration=1)
    wrapped2 = output.wrap_already_constructed(second, diagnostics=manager, iteration=2)
    slots = manager._slots.copy()
    assert type(wrapped1) is forwarding.ObservedLifecycle
    assert type(wrapped2) is forwarding.ObservedLifecycle
    assert wrapped1._delegate is first and wrapped2._delegate is second
    assert all(slot.snapshot()["schema_version"] == 2 for slot in slots)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("third allocation")

    monkeypatch.setattr(output, "LifecycleForwardingDiagnostic", forbidden)
    assert output.wrap_already_constructed(third, diagnostics=manager, iteration=1) is third
    assert manager._slots == slots and calls == [] and manager._misused is True


def full_width_v2():
    return {
        "schema_version": 2,
        "available": True,
        "incomplete": False,
        "overflow": False,
        "state": "active",
        "stages": {
            port: {"entered": 4096, "returned": 1365, "raised": 1365, "active": 1366}
            for port in PORTS
        },
        "timing": {
            "available": True,
            "overflow": False,
            "stages": {
                port: {
                    "completed_count": 2730,
                    "wall_sum_ns": 10**15,
                    "wall_max_ns": 10**15,
                    "thread_cpu_sum_ns": 10**15,
                    "thread_cpu_max_ns": 10**15,
                }
                for port in PORTS
            },
        },
    }


def test_full_width_two_slot_v2_wire_fits_original_cap_and_is_one_dynamic_write(monkeypatch):
    manager = output.create_parent_diagnostics(native_timing=True)
    output.wrap_already_constructed(object(), diagnostics=manager, iteration=1)
    output.wrap_already_constructed(object(), diagnostics=manager, iteration=2)
    monkeypatch.setattr(
        forwarding.LifecycleForwardingDiagnostic, "snapshot", lambda self: full_width_v2()
    )
    lines = []

    class Sink:
        def write(self, text):
            lines.append(text)

    monkeypatch.setattr(sys, "stdout", Sink())
    output.emit_parent_failure_line(manager, iteration=2)
    assert len(lines) == 1 and lines[0].endswith("\n") and lines[0].isascii()
    assert len(lines[0].encode()) == 1902
    assert len(lines[0].encode()) <= 4096
    value = json.loads(lines[0].removeprefix("AQT_PARENT_LIFECYCLE_DIAGNOSTIC "))
    assert value == {
        "schema_version": 2,
        "current_iteration": 2,
        "misused": False,
        "iterations": [full_width_v2(), full_width_v2()],
    }


@pytest.mark.parametrize("field", list(ZERO_TIMING))
@pytest.mark.parametrize("value", [True, -1, 10**15 + 1, IntSubclass(1), HookValue()])
def test_exact_scalar_v2_admission_rejects_malformed_rows_without_hooks(field, value):
    snapshot = full_width_v2()
    snapshot["timing"]["stages"]["prepare"][field] = value
    assert forwarding._scalar_timing_snapshot(snapshot) is False
    assert forwarding._scalar_snapshot(snapshot) is False


def test_v1_validator_does_not_admit_new_fields_and_v2_does_not_admit_removed_or_reordered_keys():
    legacy = json.loads(EMPTY_V1)
    assert forwarding._scalar_snapshot(legacy) is True
    added = copy.deepcopy(legacy)
    added["timing"] = {"available": False, "overflow": False, "stages": None}
    assert forwarding._scalar_snapshot(added) is False
    enabled = full_width_v2()
    assert forwarding._scalar_timing_snapshot(enabled) is True
    removed = copy.deepcopy(enabled)
    del removed["timing"]["stages"]["prepare"]["wall_max_ns"]
    assert forwarding._scalar_timing_snapshot(removed) is False
    reordered = dict(reversed(tuple(enabled.items())))
    assert forwarding._scalar_timing_snapshot(reordered) is False


def test_partial_failure_write_never_retries_or_emits_second_fallback(monkeypatch):
    writes = []

    class Sink:
        def write(self, text):
            writes.append(text)
            raise OSError("partial synthetic write")

    monkeypatch.setattr(sys, "stdout", Sink())
    output.emit_parent_failure_line(
        output.create_parent_diagnostics(native_timing=True), iteration=1
    )
    assert len(writes) == 1 and len(writes[0].encode()) <= 4096


@pytest.mark.parametrize("port", PORTS)
def test_dynamic_lookup_error_has_one_completed_interval_and_preserves_selected_primary(port):
    diagnostic = samples()
    primary, cause, context = original_error(AttributeError)
    lookups = []

    class MissingDelegate:
        def __getattribute__(self, name):
            lookups.append(name)
            raise primary

    with pytest.raises(AttributeError) as caught:
        invoke(
            port, forwarding.ObservedLifecycle(MissingDelegate(), diagnostic), object(), object()
        )
    assert caught.value is primary and lookups == [port]
    assert_original(primary, cause, context)
    value = diagnostic.snapshot()
    assert value["stages"][port] == {"entered": 1, "returned": 0, "raised": 1, "active": 0}
    assert value["timing"]["stages"][port] == {
        "completed_count": 1,
        "wall_sum_ns": 60,
        "wall_max_ns": 60,
        "thread_cpu_sum_ns": 25,
        "thread_cpu_max_ns": 25,
    }


@pytest.mark.parametrize("phase", ["start", "end"])
def test_new_invalid_hook_timestamp_is_released_without_conversion_or_retention(phase):
    references, count = [], 0

    def clock():
        nonlocal count
        count += 1
        if count == (1 if phase == "start" else 2):
            value = HookValue()
            references.append(weakref.ref(value))
            return value
        return 10

    diagnostic = timed(clock, lambda: 20)
    assert (
        forwarding.ObservedLifecycle(DynamicDelegate(lambda value: value), diagnostic).prepare(77)
        == 77
    )
    assert len(references) == 1 and references[0]() is None
    assert_timing_unknown(diagnostic, overflow=True)


@pytest.mark.parametrize("port", PORTS)
@pytest.mark.parametrize("raises", [False, True])
def test_kept_primary_and_auxiliary_add_no_private_dispatcher_owners_beyond_default(port, raises):
    def exercise(enabled):
        references = []
        metadata = (RuntimeError if raises else OSError)("externally kept end-clock fault")
        primary, cause, context = original_error()
        diagnostic = first = second = result = delegate = observed = callback = None
        count = 0

        class Private:
            pass

        def clock():
            nonlocal count
            count += 1
            if count == 2:
                raise metadata
            return 10

        try:
            diagnostic = (
                timed(clock, lambda: 20) if enabled else forwarding.LifecycleForwardingDiagnostic()
            )
            first, second, result = Private(), Private(), Private()

            def callback(*args, **kwargs):
                try:
                    assert (args, kwargs) == arguments(port, first, second)
                    if raises:
                        raise primary
                    return result
                finally:
                    args = kwargs = None

            delegate = DynamicDelegate(callback)
            observed = forwarding.ObservedLifecycle(delegate, diagnostic)
            references.extend(
                weakref.ref(value) for value in (first, second, result, delegate, observed)
            )
            if raises:
                try:
                    invoke(port, observed, first, second)
                except ValueError as caught:
                    assert caught is primary
                    assert_original(primary, cause, context)
                else:
                    raise AssertionError("original must fail")
            else:
                assert invoke(port, observed, first, second) is result
            return references, (diagnostic, metadata, primary)
        finally:
            first = second = result = delegate = observed = callback = cause = context = None

    baseline_refs, baseline_kept = exercise(False)
    timing_refs, timing_kept = exercise(True)
    assert tuple(value() is None for value in baseline_refs) == (True, True, True, True, True)
    assert tuple(value() is None for value in timing_refs) == (True, True, True, True, True)
    assert len(baseline_kept) == len(timing_kept) == 3
    assert timing_kept[1].__traceback__ is None and timing_kept[1].__context__ is None


def test_retained_auxiliary_releases_private_primary_graph_relative_to_default():
    def exercise(enabled):
        metadata = RuntimeError("kept auxiliary")
        references = []
        primary = cause = context = private = diagnostic = observed = delegate = callback = None
        count = 0

        class Private:
            pass

        class PrivatePrimary(ValueError):
            pass

        class PrivateCause(LookupError):
            pass

        class PrivateContext(IndexError):
            pass

        def clock():
            nonlocal count
            count += 1
            if count == 2:
                metadata.__cause__ = primary
                metadata.__suppress_context__ = False
                raise metadata
            return 10

        try:
            primary, cause, context, private = (
                PrivatePrimary(),
                PrivateCause(),
                PrivateContext(),
                Private(),
            )
            primary.__cause__, primary.__context__ = cause, context
            primary.private = private
            primary.__suppress_context__ = False
            references.extend(weakref.ref(value) for value in (primary, cause, context, private))
            diagnostic = (
                timed(clock, lambda: 20) if enabled else forwarding.LifecycleForwardingDiagnostic()
            )

            def callback(value):
                try:
                    assert value is not None
                    raise primary
                finally:
                    value = None

            delegate = DynamicDelegate(callback)
            observed = forwarding.ObservedLifecycle(delegate, diagnostic)
            try:
                observed.prepare(object())
            except ValueError as caught:
                assert caught is primary
            else:
                raise AssertionError("original must fail")
            return references, (metadata, diagnostic)
        finally:
            primary = cause = context = private = observed = delegate = callback = None

    baseline_refs, baseline_kept = exercise(False)
    timing_refs, timing_kept = exercise(True)
    assert tuple(value() is None for value in baseline_refs) == (True, True, True, True)
    assert tuple(value() is None for value in timing_refs) == (True, True, True, True)
    assert baseline_kept[0].__traceback__ is None
    assert (
        timing_kept[0].__traceback__
        is timing_kept[0].__cause__
        is timing_kept[0].__context__
        is None
    )
    assert timing_kept[0].__suppress_context__ is False


def test_two_concurrent_callbacks_complete_without_holding_metadata_lock_across_delegate():
    started = {"A": Event(), "B": Event()}
    release = Event()
    counts, errors = {}, []
    wall_values = {"A": (10, 100), "B": (20, 80)}
    cpu_values = {"A": (100, 115), "B": (200, 225)}

    def clock(kind, values):
        name = current_thread().name
        index = counts.get((name, kind), 0)
        counts[name, kind] = index + 1
        return values[name][index]

    diagnostic = timed(lambda: clock("wall", wall_values), lambda: clock("cpu", cpu_values))

    def callback(name):
        assert diagnostic._lock.acquire(blocking=False)
        diagnostic._lock.release()
        started[name].set()
        assert release.wait(2)
        return name

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)

    def run(name):
        try:
            assert observed.prepare(name) == name
        except BaseException as error:
            errors.append(error)

    threads = [Thread(target=run, args=(name,), name=name) for name in ("A", "B")]
    for thread in threads:
        thread.start()
    try:
        assert all(event.wait(2) for event in started.values())
        value = diagnostic.snapshot()
        assert value["stages"]["prepare"] == {"entered": 2, "returned": 0, "raised": 0, "active": 2}
        assert value["timing"]["stages"]["prepare"] == ZERO_TIMING
    finally:
        release.set()
        for thread in threads:
            thread.join(2)
    assert all(not thread.is_alive() for thread in threads) and errors == []
    assert diagnostic.snapshot()["timing"]["stages"]["prepare"] == {
        "completed_count": 2,
        "wall_sum_ns": 150,
        "wall_max_ns": 90,
        "thread_cpu_sum_ns": 40,
        "thread_cpu_max_ns": 25,
    }


def test_timing_completed_count_exact_cap_and_next_attempt_fail_closed():
    diagnostic = timed(lambda: 100, lambda: 200)
    diagnostic._counts[0] = [4095, 4095, 0, 0]
    diagnostic._timing[0] = [4095, 0, 0, 0, 0]
    calls = []
    observed = forwarding.ObservedLifecycle(
        DynamicDelegate(lambda value: calls.append(value)), diagnostic
    )
    assert observed.prepare(1) is None
    assert diagnostic.snapshot()["timing"]["stages"]["prepare"]["completed_count"] == 4096
    assert observed.prepare(2) is None
    value = diagnostic.snapshot()
    assert value["available"] is False and value["overflow"] is True
    assert value["timing"]["available"] is False and value["timing"]["stages"] is None
    assert calls == [1, 2]


@pytest.mark.parametrize("port", PORTS)
@pytest.mark.parametrize("phase", ["start", "end"])
def test_kept_native_oserror_releases_ambient_private_graph_relative_to_default(port, phase):
    def exercise(enabled):
        metadata = OSError("externally kept admitted native clock fault")
        references, calls = [], []
        ambient = cause = context = private = diagnostic = callback = delegate = observed = None
        count = 0

        class Private:
            pass

        class PrivateAmbient(RuntimeError):
            pass

        class PrivateCause(LookupError):
            pass

        class PrivateContext(IndexError):
            pass

        def clock():
            nonlocal count
            count += 1
            if count == (1 if phase == "start" else 2):
                metadata.__cause__ = ambient
                metadata.__suppress_context__ = False
                raise metadata
            return 10

        try:
            ambient, cause, context, private = (
                PrivateAmbient(),
                PrivateCause(),
                PrivateContext(),
                Private(),
            )
            ambient.__cause__, ambient.__context__ = cause, context
            ambient.__suppress_context__ = False
            ambient.private = private
            references.extend(weakref.ref(value) for value in (ambient, cause, context, private))
            diagnostic = (
                timed(clock, lambda: 20) if enabled else forwarding.LifecycleForwardingDiagnostic()
            )

            def callback(*args, **kwargs):
                assert args == ((77,) if port != "observe" else ())
                assert kwargs == (
                    {"child_pid": 77, "child_exited": False} if port == "observe" else {}
                )
                calls.append("returned")
                return 88

            delegate = DynamicDelegate(callback)
            observed = forwarding.ObservedLifecycle(delegate, diagnostic)
            try:
                raise ambient
            except RuntimeError:
                entry = BaseException.__traceback__.__get__(ambient)
                assert invoke(port, observed, 77, False) == 88
                assert BaseException.__traceback__.__get__(ambient) is entry
                assert ambient.__cause__ is cause and ambient.__context__ is context
                assert ambient.__suppress_context__ is False
                entry = None
            assert calls == ["returned"] and delegate.lookups == [port]
            if enabled:
                value = assert_timing_unknown(diagnostic, overflow=True)
                assert value["stages"][port] == {
                    "entered": 1,
                    "returned": 1,
                    "raised": 0,
                    "active": 0,
                }
            return references, (metadata, diagnostic)
        finally:
            ambient = cause = context = private = callback = delegate = observed = None

    baseline_refs, baseline_kept = exercise(False)
    timing_refs, timing_kept = exercise(True)
    assert tuple(value() is None for value in baseline_refs) == (True, True, True, True)
    assert tuple(value() is None for value in timing_refs) == (True, True, True, True)
    assert baseline_kept[0].__traceback__ is None
    assert (
        timing_kept[0].__traceback__
        is timing_kept[0].__cause__
        is timing_kept[0].__context__
        is None
    )
    assert timing_kept[0].__suppress_context__ is False


@pytest.mark.parametrize("port", PORTS)
@pytest.mark.parametrize("phase", ["start", "end"])
@pytest.mark.parametrize("same_ambient", [False, True])
@pytest.mark.parametrize("suppressed", [False, True])
def test_isolated_native_fault_preserves_ambient_entry_and_unrelated_edges(
    port, phase, same_ambient, suppressed
):
    ambient = OSError("handled ambient native error")
    cause, context = LookupError("independent cause"), IndexError("independent context")
    ambient.__cause__, ambient.__context__ = cause, context
    ambient.__suppress_context__ = suppressed
    private = object()
    ambient.private = private
    metadata = ambient if same_ambient else OSError("different native error")
    foreign_cause, foreign_context = LookupError("foreign cause"), IndexError("foreign context")
    count, calls = 0, []

    def clock():
        nonlocal count
        count += 1
        if count == (1 if phase == "start" else 2):
            if not same_ambient:
                metadata.__cause__ = foreign_cause
                metadata.__suppress_context__ = suppressed
            try:
                raise metadata
            finally:
                if not same_ambient:
                    metadata.__context__ = foreign_context
        return 10

    diagnostic = timed(clock, lambda: 20)

    def callback(*args, **kwargs):
        assert (args, kwargs) == arguments(port, 77, False)
        calls.append("returned")
        return 88

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    try:
        raise ambient
    except OSError as caught:
        assert caught is ambient
        entry = BaseException.__traceback__.__get__(ambient)
        assert invoke(port, observed, 77, False) == 88
        assert BaseException.__traceback__.__get__(ambient) is entry
        assert ambient.__cause__ is cause and ambient.__context__ is context
        assert ambient.__suppress_context__ is suppressed and ambient.private is private
    assert calls == ["returned"]
    assert_timing_unknown(diagnostic, overflow=True)
    if not same_ambient:
        assert metadata.__traceback__ is None
        assert metadata.__cause__ is foreign_cause and metadata.__context__ is foreign_context
        assert metadata.__suppress_context__ is suppressed


@pytest.mark.parametrize("port", PORTS)
@pytest.mark.parametrize("phase", ["start", "end"])
@pytest.mark.parametrize("ambient", [False, True])
def test_new_runtime_clock_fault_without_pending_operation_propagates(port, phase, ambient):
    metadata = RuntimeError("fresh non-admitted native clock fault")
    cause, previous_context = LookupError("independent cause"), IndexError("prior context")
    metadata.__cause__, metadata.__context__ = cause, previous_context
    metadata.__suppress_context__ = False
    outer = ValueError("handled ambient error, no suppression authority")
    calls, count = [], 0

    def clock():
        nonlocal count
        count += 1
        if count == (1 if phase == "start" else 2):
            raise metadata
        return 10

    diagnostic = timed(clock, lambda: 20)

    def callback(*args, **kwargs):
        assert (args, kwargs) == arguments(port, 77, False)
        calls.append("returned")
        return 88

    observed = forwarding.ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    if ambient:
        try:
            raise outer
        except ValueError:
            with pytest.raises(RuntimeError) as caught:
                invoke(port, observed, 77, False)
    else:
        with pytest.raises(RuntimeError) as caught:
            invoke(port, observed, 77, False)
    assert caught.value is metadata
    assert metadata.__cause__ is cause
    assert metadata.__context__ is (outer if ambient else previous_context)
    assert metadata.__suppress_context__ is False
    assert calls == ([] if phase == "start" else ["returned"])
    trace = BaseException.__traceback__.__get__(metadata)
    names = []
    while trace is not None:
        names.append(trace.tb_frame.f_code.co_name)
        trace = trace.tb_next
    assert "clock" in names
    value = assert_timing_unknown(diagnostic, overflow=True)
    assert value["stages"][port] == {
        "entered": 1,
        "returned": int(phase == "end"),
        "raised": int(phase == "start"),
        "active": 0,
    }
