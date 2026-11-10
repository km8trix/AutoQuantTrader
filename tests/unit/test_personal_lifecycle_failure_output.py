"""Inert two-slot/output oracles, without worker, SQL or financial acceptance.

The argument-evaluation example is not an original-worker integration test.
Threads are always released/joined; lifetime baselines clear their own private
traceback holders. Earlier forwarding and child-observer units stay unchanged.
"""

import gc
import json
import weakref
from threading import Event
from types import SimpleNamespace

import pytest

from tests.fixtures import lifecycle_failure_output as module
from tests.fixtures.lifecycle_failure_output import (
    LINE_CAP,
    PREFIX,
    ParentLifecycleDiagnostics,
    create_parent_diagnostics,
    emit_parent_failure_line,
    wrap_already_constructed,
)
from tests.fixtures.lifecycle_forwarding_diagnostic import (
    COUNTER_CAP,
    STAGES,
    LifecycleForwardingDiagnostic,
    ObservedLifecycle,
)
from tests.unit.test_personal_lifecycle_forwarding_diagnostic import (
    ClearingDelegate,
    DynamicDelegate,
    HostilePrivateValue,
    WeakPrivateValue,
    invoke,
    join_threads,
    run_thread,
    selected_error,
)


def decode_line(line):
    assert type(line) is str and line.isascii()
    assert len(line.encode("utf-8")) <= LINE_CAP
    assert line.startswith(PREFIX) and line.endswith("\n") and line.count("\n") == 1
    payload = json.loads(line[len(PREFIX) : -1])
    assert tuple(payload) == ("schema_version", "current_iteration", "misused", "iterations")
    assert type(payload["schema_version"]) is int and payload["schema_version"] == 1
    assert type(payload["iterations"]) is list and len(payload["iterations"]) == 2
    return payload


def output_lines(monkeypatch, manager, *, iteration=2):
    lines = []
    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(write=lines.append))
        assert emit_parent_failure_line(manager, iteration=iteration) is None
    assert len(lines) == 1
    return lines[0], decode_line(lines[0])


def assert_unknown(snapshot):
    assert snapshot["available"] is False and snapshot["incomplete"] is True
    assert snapshot["state"] == "unavailable" and snapshot["stages"] is None


def populate_two(manager):
    delegates = [DynamicDelegate(lambda *args, **kwargs: None) for _ in range(2)]
    wrappers = [
        wrap_already_constructed(delegate, diagnostics=manager, iteration=index)
        for index, delegate in enumerate(delegates, 1)
    ]
    assert all(type(wrapper) is ObservedLifecycle for wrapper in wrappers)
    return delegates, wrappers


def test_original_constructor_is_evaluated_once_at_its_keyword_position_before_wrapping():
    manager = create_parent_diagnostics()
    assert type(manager) is ParentLifecycleDiagnostics
    events = []
    request, delegate, startup, later = (
        object(),
        DynamicDelegate(lambda value: value),
        object(),
        object(),
    )

    def original_constructor(value):
        assert value is request
        events.append("constructor")
        return delegate

    def before():
        events.append("before")
        return startup

    def after():
        events.append("after")
        return later

    def inert_worker(**kwargs):
        events.append("worker")
        assert kwargs["startup"] is startup and kwargs["later"] is later
        assert type(kwargs["lifecycle"]) is ObservedLifecycle
        assert kwargs["lifecycle"].prepare(startup) is startup

    inert_worker(
        startup=before(),
        lifecycle=wrap_already_constructed(
            original_constructor(request), diagnostics=manager, iteration=1
        ),
        later=after(),
    )
    assert events == ["before", "constructor", "after", "worker"]
    assert delegate.lookups == ["prepare"]


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_original_constructor_errors_stay_outside_new_metadata_recovery(monkeypatch, kind):
    error, cause, context = selected_error(kind)
    manager = create_parent_diagnostics()
    events = []

    def constructor(request):
        events.append("constructor")
        raise error

    def forbidden_wrapper(*args, **kwargs):
        pytest.fail("wrapper entered after an original constructor failure")

    monkeypatch.setattr(module, "wrap_already_constructed", forbidden_wrapper)
    with pytest.raises(kind) as raised:
        dict(
            lifecycle=module.wrap_already_constructed(
                constructor(object()), diagnostics=manager, iteration=1
            ),
            later=events.append("after"),
        )
    assert raised.value is error
    assert error.__cause__ is cause and error.__context__ is context
    assert error.__suppress_context__ is False
    assert events == ["constructor"] and manager._slots == [None, None]


@pytest.mark.parametrize("fault", [RuntimeError, KeyboardInterrupt, "wrong_type"])
def test_safe_manager_creation_fault_has_unknown_output_and_returns_exact_delegate(
    monkeypatch, fault
):
    private = HostilePrivateValue()

    def failed():
        if fault == "wrong_type":
            return private
        raise fault("new manager failure")

    with monkeypatch.context() as patch:
        patch.setattr(module, "ParentLifecycleDiagnostics", failed)
        manager = create_parent_diagnostics()
    assert manager is None
    assert wrap_already_constructed(private, diagnostics=manager, iteration=1) is private
    _, payload = output_lines(monkeypatch, manager, iteration=1)
    assert payload["current_iteration"] == 1 and payload["misused"] is None
    for row in payload["iterations"]:
        assert_unknown(row)
    assert private.touches == []


@pytest.mark.parametrize("constructor", ["LifecycleForwardingDiagnostic", "ObservedLifecycle"])
@pytest.mark.parametrize("fault", [RuntimeError, KeyboardInterrupt, "wrong_type"])
def test_new_constructor_fault_preserves_earlier_slot_and_failed_slot_is_not_retried(
    monkeypatch, constructor, fault
):
    manager = create_parent_diagnostics()
    earlier = wrap_already_constructed(
        DynamicDelegate(lambda value: value), diagnostics=manager, iteration=1
    )
    first = manager._slots[0]
    delegate, private = DynamicDelegate(lambda value: value), HostilePrivateValue()
    attempts = []

    def failed(*args):
        attempts.append(constructor)
        if fault == "wrong_type":
            return private
        raise fault("new wrapper setup failure")

    with monkeypatch.context() as patch:
        patch.setattr(module, constructor, failed)
        assert wrap_already_constructed(delegate, diagnostics=manager, iteration=2) is delegate
        assert manager._slots[0] is first and manager._slots[1] is False
        assert manager._misused is False
        assert wrap_already_constructed(delegate, diagnostics=manager, iteration=2) is delegate
    assert attempts == [constructor] and manager._slots[0] is first
    assert manager._slots[1] is False and manager._misused is True
    assert delegate.lookups == [] and private.touches == []
    assert earlier.prepare(private) is private
    _, payload = output_lines(monkeypatch, manager)
    assert payload["misused"] is True
    for row in payload["iterations"]:
        assert_unknown(row)
    assert private.touches == []


def test_two_slots_keep_independent_real_scalar_recorders_and_missing_means_unknown(monkeypatch):
    manager = create_parent_diagnostics()
    result = object()
    one = wrap_already_constructed(
        DynamicDelegate(lambda value: result), diagnostics=manager, iteration=1
    )
    assert one.prepare(object()) is result
    _, partial = output_lines(monkeypatch, manager, iteration=1)
    assert partial["iterations"][0]["stages"]["prepare"]["returned"] == 1
    assert_unknown(partial["iterations"][1])
    two = wrap_already_constructed(
        DynamicDelegate(lambda value: result), diagnostics=manager, iteration=2
    )
    assert two.require_result(object()) is result
    _, full = output_lines(monkeypatch, manager)
    assert manager._slots[0] is not manager._slots[1]
    assert all(type(value) is LifecycleForwardingDiagnostic for value in manager._slots)
    assert full["iterations"][0]["stages"]["require_result"]["entered"] == 0
    assert full["iterations"][1]["stages"]["prepare"]["entered"] == 0
    assert full["iterations"][1]["stages"]["require_result"]["returned"] == 1


@pytest.mark.parametrize(
    "invalid", [True, False, 0, 3, -1, "private", "duplicate_one", "duplicate_two"]
)
def test_misuse_never_allocates_third_recorder_or_replaces_either_previous_slot(
    monkeypatch, invalid
):
    manager = create_parent_diagnostics()
    populate_two(manager)
    prior = tuple(manager._slots)
    private = HostilePrivateValue()
    iteration = (
        private
        if invalid == "private"
        else 1
        if invalid == "duplicate_one"
        else 2
        if invalid == "duplicate_two"
        else invalid
    )

    def forbidden():
        pytest.fail("third recorder allocation")

    with monkeypatch.context() as patch:
        patch.setattr(module, "LifecycleForwardingDiagnostic", forbidden)
        assert (
            wrap_already_constructed(private, diagnostics=manager, iteration=iteration) is private
        )
    assert all(actual is expected for actual, expected in zip(manager._slots, prior, strict=True))
    assert manager._misused is True and private.touches == []
    _, payload = output_lines(monkeypatch, manager)
    assert payload["misused"] is True
    for row in payload["iterations"]:
        assert_unknown(row)


def test_reservation_rejects_same_iteration_reentry_without_replacing_previous_slot(monkeypatch):
    manager = create_parent_diagnostics()
    wrap_already_constructed(object(), diagnostics=manager, iteration=1)
    prior = manager._slots[0]
    delegate, nested = object(), object()
    allocations = []

    def reentrant():
        allocations.append("recorder")
        assert wrap_already_constructed(nested, diagnostics=manager, iteration=2) is nested
        return LifecycleForwardingDiagnostic()

    with monkeypatch.context() as patch:
        patch.setattr(module, "LifecycleForwardingDiagnostic", reentrant)
        assert wrap_already_constructed(delegate, diagnostics=manager, iteration=2) is delegate
    assert allocations == ["recorder"]
    assert manager._slots[0] is prior and manager._slots[1] is False and manager._misused is True


def test_earlier_real_stalled_callback_does_not_block_current_slot_or_separate_failure_snapshots(
    monkeypatch,
):
    manager = create_parent_diagnostics()
    entered, release = Event(), Event()
    value = object()

    def stalled(startup):
        entered.set()
        assert release.wait(2), "test cleanup did not release callback"
        return startup

    one = wrap_already_constructed(DynamicDelegate(stalled), diagnostics=manager, iteration=1)
    two = wrap_already_constructed(
        DynamicDelegate(lambda payload: value), diagnostics=manager, iteration=2
    )
    first_thread, _, first_values, first_errors = run_thread(lambda: one.prepare(value))
    output_thread = None
    try:
        assert entered.wait(1)
        assert two.require_result(value) is value
        output_thread, finished, outputs, errors = run_thread(
            lambda: output_lines(monkeypatch, manager)
        )
        assert finished.wait(0.5), "failure metadata blocked on earlier callback"
        assert errors == []
        payload = outputs[0][1]
        assert payload["iterations"][0]["stages"]["prepare"]["active"] == 1
        assert payload["iterations"][1]["stages"]["require_result"]["returned"] == 1
        assert first_values == []
    finally:
        release.set()
        join_threads(first_thread, *(() if output_thread is None else (output_thread,)))
    assert first_errors == [] and first_values == [value]


def test_both_full_width_legal_counter_snapshots_fit_whole_line_including_prefix_and_lf(
    monkeypatch,
):
    manager = create_parent_diagnostics()
    populate_two(manager)
    for recorder in manager._slots:
        for stage in range(len(STAGES)):
            for _ in range(COUNTER_CAP):
                assert recorder._enter(stage)
            for _ in range(1365):
                recorder._leave(stage, raised=False)
                recorder._leave(stage, raised=True)
    line, payload = output_lines(monkeypatch, manager)
    assert len(line.encode("utf-8")) <= LINE_CAP
    for snapshot in payload["iterations"]:
        assert snapshot["available"] is True and snapshot["state"] == "active"
        for stage in STAGES:
            assert snapshot["stages"][stage] == {
                "entered": 4096,
                "returned": 1365,
                "raised": 1365,
                "active": 1366,
            }


@pytest.mark.parametrize("fault", ["snapshot_error", "private", "bool_counter", "wrong_keys"])
def test_faulted_or_forged_first_snapshot_is_unknown_without_inspecting_private_values(
    monkeypatch, fault
):
    manager = create_parent_diagnostics()
    populate_two(manager)
    first, second = manager._slots
    original_snapshot = LifecycleForwardingDiagnostic.snapshot
    private = HostilePrivateValue()
    snapshot = first.snapshot()
    if fault == "bool_counter":
        snapshot["stages"]["prepare"]["entered"] = False
    elif fault == "wrong_keys":
        snapshot["private"] = private

    def selected_snapshot(self):
        if self is not first:
            return original_snapshot(self)
        if fault == "snapshot_error":
            raise KeyboardInterrupt("new snapshot failure")
        return private if fault == "private" else snapshot

    with monkeypatch.context() as patch:
        patch.setattr(LifecycleForwardingDiagnostic, "snapshot", selected_snapshot)
        _, payload = output_lines(monkeypatch, manager)
    assert_unknown(payload["iterations"][0])
    assert payload["iterations"][1]["available"] is True
    assert manager._slots[0] is first and manager._slots[1] is second
    assert private.touches == []


@pytest.mark.parametrize(
    "fault",
    [
        RuntimeError,
        KeyboardInterrupt,
        "non_string",
        "surrogate",
        "oversize",
        "wrong_json",
        "whitespace",
    ],
)
def test_serializer_faults_choose_fixed_unknown_line_before_one_write(monkeypatch, fault):
    manager = create_parent_diagnostics()
    populate_two(manager)
    private = HostilePrivateValue()

    def failed(*args, **kwargs):
        if fault == "non_string":
            return private
        if fault == "surrogate":
            return "\ud800"
        if fault == "oversize":
            return "x" * LINE_CAP
        if fault == "wrong_json":
            return '{"schema_version":1}'
        if fault == "whitespace":
            return "{}\n"
        raise fault("new serializer failure")

    with monkeypatch.context() as patch:
        patch.setattr(module.json, "dumps", failed)
        line, payload = output_lines(monkeypatch, manager)
    assert payload["current_iteration"] == 2 and payload["misused"] is None
    assert line == module._fallback_line(2)
    for row in payload["iterations"]:
        assert_unknown(row)
    assert private.touches == []


def test_invalid_manager_and_native_bool_iteration_have_no_private_inspection(monkeypatch):
    private = HostilePrivateValue()
    assert wrap_already_constructed(private, diagnostics=private, iteration=private) is private
    _, invalid = output_lines(monkeypatch, private, iteration=private)
    _, boolean = output_lines(monkeypatch, create_parent_diagnostics(), iteration=True)
    assert invalid["current_iteration"] is None and boolean["current_iteration"] is None
    for payload in (invalid, boolean):
        for row in payload["iterations"]:
            assert_unknown(row)
    assert private.touches == []


def test_stdout_write_is_resolved_dynamically_once_and_can_return_arbitrary_object(monkeypatch):
    lines, lookups = [], []
    private = HostilePrivateValue()

    class Stream:
        @property
        def write(self):
            lookups.append("write")

            def selected(line):
                lines.append(line)
                return private

            return selected

    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", Stream())
        assert emit_parent_failure_line(create_parent_diagnostics(), iteration=1) is None
    assert lookups == ["write"] and len(lines) == 1
    decode_line(lines[0])
    assert private.touches == []


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("partial", [False, True])
def test_write_error_has_no_retry_and_does_not_replace_pending_original_assertion(
    monkeypatch, kind, partial
):
    original, cause, context = selected_error(AssertionError)
    attempts, emitted = [], []
    metadata_error = kind("new stdout failure")

    def write(line):
        attempts.append("write")
        if partial:
            emitted.append(line[:10])
        raise metadata_error

    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(write=write))
        with pytest.raises(AssertionError) as raised:
            try:
                raise original
            except AssertionError:
                emit_parent_failure_line(create_parent_diagnostics(), iteration=2)
                raise
    assert raised.value is original
    assert original.__cause__ is cause and original.__context__ is context
    assert original.__suppress_context__ is False
    assert attempts == ["write"] and len(emitted) == int(partial)


@pytest.mark.parametrize("fault", ["snapshot", "serializer"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_prewrite_metadata_failure_preserves_pending_original_error_and_prints_unknown(
    monkeypatch, fault, kind
):
    manager = create_parent_diagnostics()
    populate_two(manager)
    original, cause, context = selected_error(AssertionError)
    metadata_error = kind("new metadata failure")
    lines = []

    def failed(*args, **kwargs):
        raise metadata_error

    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(write=lines.append))
        if fault == "snapshot":
            patch.setattr(LifecycleForwardingDiagnostic, "snapshot", failed)
        else:
            patch.setattr(module.json, "dumps", failed)
        with pytest.raises(AssertionError) as raised:
            try:
                raise original
            except AssertionError:
                emit_parent_failure_line(manager, iteration=2)
                raise
    assert raised.value is original
    assert original.__cause__ is cause and original.__context__ is context
    assert original.__suppress_context__ is False
    assert len(lines) == 1
    for row in decode_line(lines[0])["iterations"]:
        assert_unknown(row)


def private_lifetime(monkeypatch, port, *, wrapped, raises):
    manager = create_parent_diagnostics()
    first, second, result, marker = (WeakPrivateValue() for _ in range(4))
    error = RuntimeError("original lifetime failure") if raises else None
    if error is not None:
        error.private_marker = marker
    delegate = ClearingDelegate(result, error)
    target = (
        wrap_already_constructed(delegate, diagnostics=manager, iteration=1)
        if wrapped
        else delegate
    )
    refs = tuple(weakref.ref(value) for value in (delegate, first, second, result, target, marker))
    caught = None
    try:
        if raises:
            try:
                invoke(port, target, first, second)
            except RuntimeError as actual:
                assert actual is error
                caught = actual
        else:
            assert invoke(port, target, first, second) is result
        line, _ = output_lines(monkeypatch, manager, iteration=1)
    finally:
        delegate = first = second = result = target = marker = error = None
    return manager, line, caught, refs


@pytest.mark.parametrize("port", STAGES)
def test_kept_two_slot_manager_and_output_do_not_extend_success_lifetimes(monkeypatch, port):
    baseline, baseline_line, _, baseline_refs = private_lifetime(
        monkeypatch, port, wrapped=False, raises=False
    )
    manager, line, _, refs = private_lifetime(monkeypatch, port, wrapped=True, raises=False)
    gc.collect()
    assert all(ref() is None for ref in (*baseline_refs, *refs))
    assert_unknown(decode_line(baseline_line)["iterations"][0])
    assert decode_line(line)["iterations"][0]["stages"][port]["returned"] == 1
    assert (
        baseline._slots == [None, None] and type(manager._slots[0]) is LifecycleForwardingDiagnostic
    )


@pytest.mark.parametrize("port", STAGES)
def test_kept_manager_output_and_original_error_match_unwrapped_private_retention(
    monkeypatch, port
):
    baseline, baseline_line, baseline_error, baseline_refs = private_lifetime(
        monkeypatch, port, wrapped=False, raises=True
    )
    manager, line, error, refs = private_lifetime(monkeypatch, port, wrapped=True, raises=True)
    assert all(ref() is None for ref in (*baseline_refs[:-1], *refs[:-1]))
    assert baseline_refs[-1]() is baseline_error.private_marker
    assert refs[-1]() is error.private_marker
    assert_unknown(decode_line(baseline_line)["iterations"][0])
    assert decode_line(line)["iterations"][0]["stages"][port]["raised"] == 1
    baseline_error = error = None
    gc.collect()
    assert baseline_refs[-1]() is None and refs[-1]() is None
    assert (
        baseline._slots == [None, None] and type(manager._slots[0]) is LifecycleForwardingDiagnostic
    )


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_retained_new_wrapper_constructor_error_does_not_keep_fallback_delegate(monkeypatch, kind):
    metadata_error = kind("new retained wrapper failure")

    def failed(delegate, diagnostic):
        try:
            raise metadata_error
        finally:
            del delegate, diagnostic

    def construct_and_drop():
        manager, delegate = create_parent_diagnostics(), WeakPrivateValue()
        ref = weakref.ref(delegate)
        try:
            assert wrap_already_constructed(delegate, diagnostics=manager, iteration=1) is delegate
            return manager, ref
        finally:
            delegate = None

    with monkeypatch.context() as patch:
        patch.setattr(module, "ObservedLifecycle", failed)
        manager, ref = construct_and_drop()
    assert metadata_error.__traceback__ is not None and ref() is None
    assert manager._slots == [False, None]


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_retained_write_error_does_not_keep_manager_or_private_unused_iteration(monkeypatch, kind):
    metadata_error = kind("new retained output failure")

    def write(line):
        try:
            raise metadata_error
        finally:
            del line

    def emit_and_drop():
        manager, private = create_parent_diagnostics(), WeakPrivateValue()
        refs = weakref.ref(manager), weakref.ref(private)
        try:
            emit_parent_failure_line(manager, iteration=private)
            return refs
        finally:
            manager = private = None

    with monkeypatch.context() as patch:
        patch.setattr(module.sys, "stdout", SimpleNamespace(write=write))
        refs = emit_and_drop()
    assert metadata_error.__traceback__ is not None
    assert all(ref() is None for ref in refs)
