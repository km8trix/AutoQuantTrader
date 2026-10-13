"""Inert callback oracles; no worker/account, financial entry or timing acceptance.

Threads use explicit release/join cleanup. Weak lifetime comparisons use callbacks
whose own traceback locals are cleared, so an observer's extra retention is not
mistaken for the unwrapped callback's ordinary retention.
"""

import gc
import json
import weakref
from threading import Event, Thread

import pytest

from tests.fixtures import lifecycle_forwarding_diagnostic as module
from tests.fixtures.lifecycle_forwarding_diagnostic import (
    COUNTER_CAP,
    STAGES,
    SUMMARY_CAP,
    LifecycleForwardingDiagnostic,
    ObservedLifecycle,
)


class DynamicDelegate:
    def __init__(self, callback):
        self.callback = callback
        self.lookups = []

    def __getattribute__(self, name):
        if name in STAGES:
            object.__getattribute__(self, "lookups").append(name)
            return object.__getattribute__(self, "callback")
        return object.__getattribute__(self, name)


def invoke(port, target, first, second):
    try:
        if port == "prepare":
            return target.prepare(first)
        if port == "observe":
            return target.observe(child_pid=first, child_exited=second)
        assert port == "require_result"
        return target.require_result(first)
    finally:
        target = first = second = None


def expected_arguments(port, first, second):
    return (
        ((), {"child_pid": first, "child_exited": second}) if port == "observe" else ((first,), {})
    )


def selected_error(kind):
    error = kind("original callback failure")
    cause, context = LookupError("original cause"), IndexError("original context")
    error.__cause__, error.__context__ = cause, context
    error.__suppress_context__ = False
    return error, cause, context


def assert_unavailable(diagnostic):
    snapshot = diagnostic.snapshot()
    assert snapshot["available"] is False
    assert snapshot["incomplete"] is True
    assert snapshot["state"] == "unavailable"
    assert snapshot["stages"] is None
    summary = diagnostic.summary()
    assert type(summary) is str and len(summary.encode("utf-8")) <= SUMMARY_CAP
    decoded = json.loads(summary)
    assert decoded["available"] is False and decoded["incomplete"] is True
    assert decoded["stages"] is None


@pytest.mark.parametrize("port", STAGES)
@pytest.mark.parametrize("outcome", ["returned", RuntimeError, KeyboardInterrupt])
def test_all_ports_preserve_exact_arguments_lookup_return_and_original_error(port, outcome):
    first, second, result = object(), object(), object()
    calls = []
    original = None if outcome == "returned" else selected_error(outcome)

    def callback(*args, **kwargs):
        calls.append((args, kwargs))
        if original is not None:
            raise original[0]
        return result

    delegate = DynamicDelegate(callback)
    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(delegate, diagnostic)
    assert delegate.lookups == []
    if original is None:
        assert invoke(port, observed, first, second) is result
    else:
        with pytest.raises(outcome) as raised:
            invoke(port, observed, first, second)
        assert raised.value is original[0]
        assert raised.value.__cause__ is original[1]
        assert raised.value.__context__ is original[2]
        assert raised.value.__suppress_context__ is False
    assert delegate.lookups == [port]
    assert calls == [expected_arguments(port, first, second)]
    snapshot = diagnostic.snapshot()
    assert snapshot["available"] is True and snapshot["state"] == "balanced"
    expected = {
        "entered": 1,
        "returned": int(original is None),
        "raised": int(original is not None),
        "active": 0,
    }
    assert snapshot["stages"][port] == expected
    for untouched in set(STAGES) - {port}:
        assert snapshot["stages"][untouched] == {
            "entered": 0,
            "returned": 0,
            "raised": 0,
            "active": 0,
        }


@pytest.mark.parametrize("port", STAGES)
def test_methods_are_resolved_at_forwarding_after_delegate_binding_changes(port):
    old_result, new_result = object(), object()
    old_calls, new_calls = [], []

    def old(*args, **kwargs):
        old_calls.append((args, kwargs))
        return old_result

    def new(*args, **kwargs):
        new_calls.append((args, kwargs))
        return new_result

    delegate = DynamicDelegate(old)
    observed = ObservedLifecycle(delegate, LifecycleForwardingDiagnostic())
    delegate.callback = new
    first, second = object(), object()
    assert invoke(port, observed, first, second) is new_result
    assert old_calls == []
    assert new_calls == [expected_arguments(port, first, second)]
    assert delegate.lookups == [port]


@pytest.mark.parametrize("port", STAGES)
def test_lookup_failure_is_a_forwarding_attempt_and_preserves_original_error(port):
    error, cause, context = selected_error(AttributeError)

    class RefusingDelegate:
        def __getattribute__(self, name):
            if name in STAGES:
                raise error
            return object.__getattribute__(self, name)

    diagnostic = LifecycleForwardingDiagnostic()
    with pytest.raises(AttributeError) as raised:
        invoke(port, ObservedLifecycle(RefusingDelegate(), diagnostic), object(), object())
    assert raised.value is error
    assert error.__cause__ is cause and error.__context__ is context
    assert error.__suppress_context__ is False
    assert diagnostic.snapshot()["stages"][port] == {
        "entered": 1,
        "returned": 0,
        "raised": 1,
        "active": 0,
    }


class HostilePrivateValue:
    def __init__(self):
        self.touches = []

    def __repr__(self):
        self.touches.append("repr")
        raise AssertionError("private value must not be represented")

    def __str__(self):
        self.touches.append("str")
        raise AssertionError("private value must not be serialized")

    def __iter__(self):
        self.touches.append("iter")
        raise AssertionError("private value must not be traversed")

    def __bool__(self):
        self.touches.append("bool")
        raise AssertionError("private value must not be inspected")

    def __getattr__(self, name):
        self.touches.append("getattr")
        raise AssertionError("private getter must not be called")


@pytest.mark.parametrize("port", STAGES)
def test_private_arguments_and_results_are_not_inspected_or_serialized(port):
    first, second, result = HostilePrivateValue(), HostilePrivateValue(), HostilePrivateValue()

    def callback(*args, **kwargs):
        if port == "observe":
            assert args == ()
            assert kwargs["child_pid"] is first and kwargs["child_exited"] is second
        else:
            assert len(args) == 1 and args[0] is first and kwargs == {}
        return result

    diagnostic = LifecycleForwardingDiagnostic()
    assert (
        invoke(port, ObservedLifecycle(DynamicDelegate(callback), diagnostic), first, second)
        is result
    )
    assert diagnostic.snapshot()["state"] == "balanced"
    assert len(diagnostic.summary().encode("utf-8")) <= SUMMARY_CAP
    assert first.touches == second.touches == result.touches == []


@pytest.mark.parametrize("port", STAGES)
@pytest.mark.parametrize("phase", ["_enter", "_leave"])
@pytest.mark.parametrize("raises", [False, True])
def test_metadata_baseexception_does_not_replace_original_return_or_error(
    monkeypatch, port, phase, raises
):
    original = selected_error(RuntimeError)
    result, first, second = object(), object(), object()
    calls = []

    def broken(*args, **kwargs):
        raise KeyboardInterrupt("metadata failure")

    def callback(*args, **kwargs):
        calls.append((args, kwargs))
        if raises:
            raise original[0]
        return result

    monkeypatch.setattr(LifecycleForwardingDiagnostic, phase, broken)
    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    if raises:
        with pytest.raises(RuntimeError) as caught:
            invoke(port, observed, first, second)
        assert caught.value is original[0]
        assert caught.value.__cause__ is original[1]
        assert caught.value.__context__ is original[2]
        assert caught.value.__suppress_context__ is False
    else:
        assert invoke(port, observed, first, second) is result
    assert calls == [expected_arguments(port, first, second)]
    assert_unavailable(diagnostic)


def run_thread(callback):
    finished, values, errors = Event(), [], []

    def run():
        try:
            values.append(callback())
        except BaseException as error:
            errors.append(error)
        finally:
            finished.set()

    thread = Thread(target=run)
    thread.start()
    return thread, finished, values, errors


def join_threads(*threads):
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads), "controlled test thread did not retire"


def test_genuinely_stalled_callback_has_prompt_active_snapshot_and_retires_after_release():
    entered, release = Event(), Event()
    result = object()

    def callback(*args, **kwargs):
        entered.set()
        if not release.wait(timeout=5):
            raise RuntimeError("test callback was not released")
        return result

    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    worker, finished, values, errors = run_thread(
        lambda: observed.observe(child_pid=123, child_exited=False)
    )
    reader = None
    try:
        assert entered.wait(timeout=2)
        reader, copied, snapshots, snapshot_errors = run_thread(diagnostic.snapshot)
        assert copied.wait(timeout=2), "snapshot waited for the original callback"
        assert snapshot_errors == []
        assert snapshots[0]["state"] == "active"
        assert snapshots[0]["stages"]["observe"] == {
            "entered": 1,
            "returned": 0,
            "raised": 0,
            "active": 1,
        }
        assert not finished.is_set()
    finally:
        release.set()
        join_threads(worker, *(() if reader is None else (reader,)))
    assert errors == [] and len(values) == 1 and values[0] is result
    assert diagnostic.snapshot()["state"] == "balanced"


def test_actual_metadata_lock_contention_does_not_wait_before_forwarding():
    callback_called = Event()
    result = object()

    def callback(*args, **kwargs):
        callback_called.set()
        return result

    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    diagnostic._lock.acquire()
    worker = None
    try:
        worker, finished, values, errors = run_thread(lambda: observed.prepare(object()))
        assert callback_called.wait(timeout=2), "metadata contention prevented forwarding"
        assert finished.wait(timeout=2)
    finally:
        diagnostic._lock.release()
        if worker is not None:
            join_threads(worker)
    assert errors == [] and len(values) == 1 and values[0] is result
    assert_unavailable(diagnostic)


def test_actual_snapshot_contention_returns_unavailable_without_waiting():
    diagnostic = LifecycleForwardingDiagnostic()
    diagnostic._lock.acquire()
    reader = None
    try:
        reader, finished, values, errors = run_thread(diagnostic.snapshot)
        assert finished.wait(timeout=2), "snapshot waited for a held metadata lock"
    finally:
        diagnostic._lock.release()
        if reader is not None:
            join_threads(reader)
    assert errors == [] and values[0]["available"] is False
    assert_unavailable(diagnostic)


def test_reentrant_callbacks_balance_each_stage_without_holding_metadata_lock():
    diagnostic = LifecycleForwardingDiagnostic()
    snapshots = []
    result = object()
    observed = None

    def callback(*args, **kwargs):
        snapshots.append(diagnostic.snapshot())
        if args:
            assert observed.observe(child_pid=321, child_exited=False) is result
        return result

    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    assert observed.prepare(object()) is result
    assert snapshots[0]["stages"]["prepare"]["active"] == 1
    assert snapshots[1]["stages"]["prepare"]["active"] == 1
    assert snapshots[1]["stages"]["observe"]["active"] == 1
    snapshot = diagnostic.snapshot()
    assert snapshot["available"] is True and snapshot["state"] == "balanced"
    for stage in ("prepare", "observe"):
        assert snapshot["stages"][stage] == {"entered": 1, "returned": 1, "raised": 0, "active": 0}


def test_two_concurrent_active_callbacks_have_coherent_balanced_counters():
    first_entered, second_entered, release = Event(), Event(), Event()
    result = object()

    def callback(startup):
        startup.set()
        if not release.wait(timeout=5):
            raise RuntimeError("test callback was not released")
        return result

    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    workers = []
    try:
        workers.append(run_thread(lambda: observed.prepare(first_entered)))
        assert first_entered.wait(timeout=2)
        workers.append(run_thread(lambda: observed.prepare(second_entered)))
        assert second_entered.wait(timeout=2)
        snapshot = diagnostic.snapshot()
        assert snapshot["available"] is True
        assert snapshot["stages"]["prepare"] == {
            "entered": 2,
            "returned": 0,
            "raised": 0,
            "active": 2,
        }
    finally:
        release.set()
        join_threads(*(worker for worker, _finished, _values, _errors in workers))
    for _worker, _finished, values, errors in workers:
        assert errors == [] and len(values) == 1 and values[0] is result
    snapshot = diagnostic.snapshot()
    if snapshot["available"]:
        assert snapshot["stages"]["prepare"] == {
            "entered": 2,
            "returned": 2,
            "raised": 0,
            "active": 0,
        }
    else:
        # Genuine simultaneous retirement may contend; never present lost data
        # as a balanced or zero-active complete observation.
        assert_unavailable(diagnostic)


def test_counter_saturation_is_sticky_bounded_and_still_forwards_original_calls():
    calls = 0

    def callback(startup):
        nonlocal calls
        calls += 1
        return calls

    diagnostic = LifecycleForwardingDiagnostic()
    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    for expected in range(1, COUNTER_CAP + 1):
        assert observed.prepare(None) == expected
    assert diagnostic.snapshot()["stages"]["prepare"] == {
        "entered": COUNTER_CAP,
        "returned": COUNTER_CAP,
        "raised": 0,
        "active": 0,
    }
    assert observed.prepare(None) == COUNTER_CAP + 1
    assert observed.prepare(None) == COUNTER_CAP + 2
    assert_unavailable(diagnostic)
    assert diagnostic.snapshot()["overflow"] is True
    assert json.loads(diagnostic.summary())["overflow"] is True


def test_snapshots_are_defensive_copies_and_summary_has_only_fixed_bounded_scalars():
    diagnostic = LifecycleForwardingDiagnostic()
    empty = diagnostic.snapshot()
    assert empty["state"] == "empty"
    observed = ObservedLifecycle(DynamicDelegate(lambda startup: None), diagnostic)
    observed.prepare(object())
    copy = diagnostic.snapshot()
    copy["stages"]["prepare"]["entered"] = 99999
    copy["stages"]["injected"] = {"private": object()}
    copy["available"] = False
    actual = diagnostic.snapshot()
    assert actual["available"] is True
    assert tuple(actual["stages"]) == STAGES
    assert actual["stages"]["prepare"]["entered"] == 1
    text = diagnostic.summary()
    assert len(text.encode("utf-8")) <= SUMMARY_CAP
    assert json.loads(text) == actual


@pytest.mark.parametrize("fault", ["snapshot", "serializer", "oversized", "non_scalar"])
@pytest.mark.parametrize("raises", [False, True])
def test_snapshot_and_serialization_faults_fail_closed_without_private_serialization(
    monkeypatch, fault, raises
):
    diagnostic = LifecycleForwardingDiagnostic()
    private = HostilePrivateValue()
    original = selected_error(RuntimeError)
    original[0].private_marker = private

    def callback(startup):
        if raises:
            raise original[0]
        return startup

    observed = ObservedLifecycle(DynamicDelegate(callback), diagnostic)
    if raises:
        with pytest.raises(RuntimeError) as caught:
            observed.prepare(private)
        assert caught.value is original[0]
    else:
        assert observed.prepare(private) is private

    def broken(*args, **kwargs):
        raise KeyboardInterrupt("metadata representation failure")

    with monkeypatch.context() as patch:
        if fault == "snapshot":
            patch.setattr(LifecycleForwardingDiagnostic, "snapshot", broken)
        elif fault == "serializer":
            patch.setattr(module.json, "dumps", broken)
        elif fault == "oversized":
            patch.setattr(module.json, "dumps", lambda *args, **kwargs: "x" * (SUMMARY_CAP + 1))
        else:
            patch.setattr(LifecycleForwardingDiagnostic, "snapshot", lambda self: private)
            patch.setattr(
                module.json,
                "dumps",
                lambda *args, **kwargs: pytest.fail("serialized private snapshot"),
            )
        text = diagnostic.summary()
    assert len(text.encode("utf-8")) <= SUMMARY_CAP
    assert json.loads(text)["available"] is False
    assert private.touches == []
    assert original[0].__cause__ is original[1] and original[0].__context__ is original[2]
    assert original[0].__suppress_context__ is False
    assert_unavailable(diagnostic)
    if raises:
        with pytest.raises(RuntimeError) as caught:
            observed.require_result(private)
        assert caught.value is original[0]
    else:
        assert observed.require_result(private) is private


def test_serialization_occurs_after_metadata_lock_release(monkeypatch):
    diagnostic = LifecycleForwardingDiagnostic()
    original_dumps = module.json.dumps
    acquired = []

    def serializer(value, **kwargs):
        locked = diagnostic._lock.acquire(blocking=False)
        acquired.append(locked)
        try:
            assert locked, "metadata lock spans serialization"
            return original_dumps(value, **kwargs)
        finally:
            if locked:
                diagnostic._lock.release()

    monkeypatch.setattr(module.json, "dumps", serializer)
    assert json.loads(diagnostic.summary())["state"] == "empty"
    assert acquired == [True]


class WeakPrivateValue:
    pass


class ClearingDelegate:
    def __init__(self, result, error=None):
        self.result, self.error = result, error

    def prepare(self, startup):
        try:
            if self.error is not None:
                raise self.error
            return self.result
        finally:
            self = None
            del startup

    def observe(self, *, child_pid, child_exited):
        try:
            if self.error is not None:
                raise self.error
            return self.result
        finally:
            self = None
            del child_pid, child_exited

    def require_result(self, payload):
        try:
            if self.error is not None:
                raise self.error
            return self.result
        finally:
            self = None
            del payload


def success_lifetime(port, wrapped):
    diagnostic = LifecycleForwardingDiagnostic()
    first, second, result = WeakPrivateValue(), WeakPrivateValue(), WeakPrivateValue()
    delegate = ClearingDelegate(result)
    target = ObservedLifecycle(delegate, diagnostic) if wrapped else delegate
    refs = tuple(weakref.ref(value) for value in (delegate, first, second, result, target))
    assert invoke(port, target, first, second) is result
    return diagnostic, refs


@pytest.mark.parametrize("port", STAGES)
def test_kept_recorder_does_not_extend_private_success_lifetimes_relative_to_unwrapped(port):
    baseline, baseline_refs = success_lifetime(port, False)
    diagnostic, observed_refs = success_lifetime(port, True)
    gc.collect()
    assert all(ref() is None for ref in baseline_refs)
    assert all(ref() is None for ref in observed_refs)
    assert baseline.snapshot()["state"] == "empty"
    assert diagnostic.snapshot()["state"] == "balanced"


def error_lifetime(port, wrapped):
    diagnostic = LifecycleForwardingDiagnostic()
    first, second, result, marker = (WeakPrivateValue() for _ in range(4))
    error = RuntimeError("original lifetime failure")
    error.private_marker = marker
    delegate = ClearingDelegate(result, error)
    target = ObservedLifecycle(delegate, diagnostic) if wrapped else delegate
    refs = tuple(weakref.ref(value) for value in (delegate, first, second, result, target, marker))
    caught = None
    try:
        invoke(port, target, first, second)
    except RuntimeError as actual:
        if actual is not error:
            raise
        caught = actual
    finally:
        delegate = first = second = result = target = marker = error = None
    return diagnostic, caught, refs


@pytest.mark.parametrize("port", STAGES)
def test_original_error_traceback_does_not_keep_extra_wrapper_values_or_kept_recorder_errors(port):
    baseline, baseline_error, baseline_refs = error_lifetime(port, False)
    diagnostic, observed_error, observed_refs = error_lifetime(port, True)
    # Keep both original errors and their tracebacks alive. All delegate/argument/
    # result holders were explicitly cleared in both baseline and wrapped calls.
    assert all(ref() is None for ref in baseline_refs[:-1])
    assert all(ref() is None for ref in observed_refs[:-1])
    assert baseline_refs[-1]() is baseline_error.private_marker
    assert observed_refs[-1]() is observed_error.private_marker
    baseline_error = observed_error = None
    gc.collect()
    assert baseline_refs[-1]() is None and observed_refs[-1]() is None
    assert baseline.snapshot()["state"] == "empty"
    assert diagnostic.snapshot()["stages"][port]["raised"] == 1
