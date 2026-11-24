"""Finite fault/ownership controls for the temporary first-observe diagnostic.

Private native-owner seams are injected only after genuine enabled construction.
They model selected native faults; no arbitrary callback-profiler API, recursive
exception-graph transparency, timing threshold or financial acceptance is claimed.
"""

from __future__ import annotations

import json
import os
import stat
import weakref

import pytest

from tests.fixtures import parent_first_observe_profile as module


class _Alarm(BaseException):
    pass


class _Box:
    __slots__ = ("__weakref__",)


class _WeakError(RuntimeError):
    pass


class _Delegate:
    def __init__(self, events, *, error=None, result=None, owner=None):
        self.events, self.error, self.result, self.owner = events, error, result, owner

    def observe(self, *, child_pid, child_exited):
        try:
            self.events.append(("callback", child_pid, child_exited))
            if self.error is not None:
                raise self.error
            return self.result
        finally:
            self = child_pid = child_exited = None


class _NativeStub:
    """A finite native-fault model that clears its own Python frame owners."""

    def __init__(self, events, faults):
        self.events, self.faults = events, faults

    def _act(self, stage):
        try:
            self.events.append(stage)
            if stage in self.faults:
                raise self.faults[stage]
        finally:
            self = stage = None

    def enable(self):
        try:
            self._act("enable")
        finally:
            self = None

    def disable(self):
        try:
            self._act("disable")
        finally:
            self = None

    def getstats(self):
        try:
            self._act("getstats")
            return []
        finally:
            self = None

    def clear(self):
        try:
            self._act("clear")
        finally:
            self = None


def _setup(*, error=None, result=None, owner=None, faults=None):
    events = []
    profile = module.create_first_observe_profile(enabled=True)
    native = _NativeStub(events, {} if faults is None else faults)

    def factory():
        events.append("create")
        if "create" in native.faults:
            raise native.faults["create"]
        return native

    # These private seams follow genuine native admission. Public construction
    # accepts only an exact bool, never a custom factory or hook parameter.
    profile._factory, profile._profile_type = factory, _NativeStub
    profile._get_ident = lambda: 7
    profile._getprofile = profile._gettrace = lambda: None
    profile._get_tool = lambda _tool: None
    profile._get_events = lambda _tool: 0
    delegate = _Delegate(events, error=error, result=result, owner=owner)
    wrapped = module.wrap_first_observe_profile(delegate, profile=profile, iteration=2)
    return profile, wrapped, delegate, events


def _raise(error):
    def fault(*_args, **_kwargs):
        try:
            raise error
        finally:
            _args = _kwargs = None

    return fault


def _ready():
    result = object()
    profile, wrapped, _delegate, events = _setup(result=result)
    assert wrapped.observe(child_pid=13, child_exited=False) is result
    assert profile.availability() == {
        "schema_version": 1,
        "selected": True,
        "active": False,
        "completed": True,
        "available": True,
        "report_written": False,
    }
    return profile, events


def _callback_count(events):
    return sum(type(event) is tuple and event[0] == "callback" for event in events)


def _tb_names(error):
    names = []
    current = BaseException.__traceback__.__get__(error)
    while current is not None:
        names.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    return names


@pytest.mark.parametrize(
    "phase", ["create", "enable", "disable", "getstats", "clear", "conversion"]
)
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, _Alarm])
@pytest.mark.parametrize("ambient", [False, True])
def test_fresh_metadata_faults_propagate_without_callback_primary(
    monkeypatch, phase, error_type, ambient
):
    error, cause = error_type("finite native fault"), LookupError("explicit cause")
    error.__cause__, error.__suppress_context__ = cause, True
    faults = {phase: error} if phase != "conversion" else {}
    profile, wrapped, _delegate, events = _setup(faults=faults)
    if phase == "conversion":
        monkeypatch.setattr(module, "_static_report", _raise(error))

    def invoke():
        wrapped.observe(child_pid=19, child_exited=True)

    if ambient:
        try:
            raise RuntimeError("ambient handler is not suppression authority")
        except RuntimeError:
            with pytest.raises(error_type) as caught:
                invoke()
    else:
        with pytest.raises(error_type) as caught:
            invoke()
    assert caught.value is error
    assert BaseException.__cause__.__get__(error) is cause
    assert BaseException.__suppress_context__.__get__(error) is True
    assert _callback_count(events) == (0 if phase in ("create", "enable") else 1)
    assert events.count("create") == 1
    assert profile.availability()["available"] is False
    assert profile._profiler is profile._disable is profile._getstats is profile._clear is None


@pytest.mark.parametrize("phase", ["disable", "getstats", "clear", "conversion"])
@pytest.mark.parametrize("same_primary", [False, True])
def test_pending_callback_primary_keeps_native_edges_and_removes_only_auxiliary_direct_edges(
    monkeypatch, phase, same_primary
):
    primary = _WeakError("original callback")
    cause, context = LookupError("primary cause"), ValueError("primary context")
    primary.__cause__, primary.__context__, primary.__suppress_context__ = cause, context, True
    auxiliary = primary if same_primary else RuntimeError("native metadata")
    auxiliary_owner = LookupError("unrelated auxiliary cause")
    if not same_primary:
        auxiliary.__cause__, auxiliary.__suppress_context__ = auxiliary_owner, True
    profile, wrapped, _delegate, events = _setup(
        error=primary, faults={} if phase == "conversion" else {phase: auxiliary}
    )
    if phase == "conversion":
        monkeypatch.setattr(module, "_static_report", _raise(auxiliary))
    with pytest.raises(_WeakError) as caught:
        wrapped.observe(child_pid=17, child_exited=False)
    assert caught.value is primary
    assert BaseException.__cause__.__get__(primary) is cause
    assert BaseException.__context__.__get__(primary) is context
    assert BaseException.__suppress_context__.__get__(primary) is True
    assert "_act" not in _tb_names(primary)
    assert "fault" not in _tb_names(primary)
    assert _callback_count(events) == 1
    assert events.count("disable") == 1
    assert profile.availability()["available"] is False
    if not same_primary:
        assert BaseException.__traceback__.__get__(auxiliary) is None
        assert BaseException.__context__.__get__(auxiliary) is None
        assert BaseException.__cause__.__get__(auxiliary) is auxiliary_owner
        assert BaseException.__suppress_context__.__get__(auxiliary) is True


@pytest.mark.parametrize("phase", ["disable", "getstats", "clear", "conversion"])
def test_retained_primary_and_auxiliary_do_not_retain_new_dispatch_arguments_without_gc(
    monkeypatch, phase
):
    owner, argument = _Box(), _Box()
    owner_ref, argument_ref = weakref.ref(owner), weakref.ref(argument)
    primary, auxiliary = _WeakError("callback"), RuntimeError("metadata")
    profile, wrapped, delegate, events = _setup(
        error=primary, owner=owner, faults={} if phase == "conversion" else {phase: auxiliary}
    )
    if phase == "conversion":
        monkeypatch.setattr(module, "_static_report", _raise(auxiliary))
    try:
        wrapped.observe(child_pid=argument, child_exited=False)
    except _WeakError as caught:
        assert caught is primary
    else:
        pytest.fail("original callback error was lost")
    # Drop the test's own deliberately captured argument event. Keep both errors
    # and their surviving tracebacks; never clear auxiliary context or invoke GC.
    events.clear()
    del profile, wrapped, delegate, owner, argument
    assert owner_ref() is None
    assert argument_ref() is None
    assert auxiliary.__traceback__ is None
    assert auxiliary.__context__ is None
    assert "observe" in _tb_names(primary)


def test_partial_activation_cleanup_keeps_enable_primary_when_disable_also_fails():
    primary, auxiliary = _Alarm("enable interrupted"), KeyboardInterrupt("cleanup interrupted")
    profile, wrapped, _delegate, events = _setup(faults={"enable": primary, "disable": auxiliary})
    with pytest.raises(_Alarm) as caught:
        wrapped.observe(child_pid=23, child_exited=False)
    assert caught.value is primary
    assert events == ["create", "enable", "disable"]
    assert auxiliary.__traceback__ is None and auxiliary.__context__ is None
    assert profile.availability()["available"] is False


@pytest.mark.parametrize("phase", ["scalar", "export", "close"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, _Alarm])
def test_fresh_export_faults_propagate_even_with_ambient_handler(
    monkeypatch, tmp_path, phase, error_type
):
    profile, events = _ready()
    error = error_type("export metadata interrupted")
    tmp_path.chmod(0o700)
    output = str(tmp_path / "parent-probe-first-observe.json")
    if phase == "scalar":
        monkeypatch.setattr(module.FirstObserveProfile, "availability", _raise(error))
        invoke = profile.emit_availability
    elif phase == "export":
        monkeypatch.setattr(module, "_admit_report", _raise(error))

        def invoke():
            return profile.write_after_cleanup(output)
    else:
        # Force fdopen to leave the native descriptor to the guarded finalizer.
        monkeypatch.setattr(module.os, "fdopen", _raise(error))

        def invoke():
            return profile.write_after_cleanup(output)

    try:
        raise LookupError("ambient error")
    except LookupError:
        with pytest.raises(error_type) as caught:
            invoke()
    assert caught.value is error
    assert _callback_count(events) == 1


@pytest.mark.parametrize("phase", ["scalar", "export", "close"])
def test_explicit_pending_export_primary_preserves_edges_and_auxiliary_owner(
    monkeypatch, tmp_path, phase
):
    profile, events = _ready()
    primary, auxiliary, unrelated = (
        _WeakError("operation failed"),
        OSError("metadata failed"),
        LookupError("unrelated"),
    )
    cause, context = RuntimeError("cause"), ValueError("context")
    primary.__cause__, primary.__context__, primary.__suppress_context__ = cause, context, True
    auxiliary.__cause__, auxiliary.__suppress_context__ = unrelated, True
    tmp_path.chmod(0o700)
    output = str(tmp_path / "parent-probe-first-observe.json")
    if phase == "scalar":
        monkeypatch.setattr(module.FirstObserveProfile, "availability", _raise(auxiliary))
    elif phase == "export":
        monkeypatch.setattr(module, "_admit_report", _raise(auxiliary))
    else:
        monkeypatch.setattr(module.os, "fdopen", _raise(auxiliary))

    def invoke():
        if phase == "scalar":
            return profile.emit_availability(primary=primary)
        return profile.write_after_cleanup(output, primary=primary)

    try:
        raise primary
    except _WeakError:
        before = (
            primary.__traceback__,
            primary.__cause__,
            primary.__context__,
            primary.__suppress_context__,
        )
        invoke()
        assert (
            primary.__traceback__,
            primary.__cause__,
            primary.__context__,
            primary.__suppress_context__,
        ) == before
    assert primary.__cause__ is cause
    assert primary.__suppress_context__ is True
    assert auxiliary.__traceback__ is None and auxiliary.__context__ is None
    assert auxiliary.__cause__ is unrelated
    assert auxiliary.__suppress_context__ is True
    assert _callback_count(events) == 1


def test_wrong_thread_cannot_disable_export_or_clear_native_owner():
    profile, _wrapped, _delegate, events = _setup()
    assert profile._claim() is True
    assert profile._start() is True
    profile._get_ident = lambda: 8
    with pytest.raises(RuntimeError, match="PARENT_PROFILE_WRONG_THREAD"):
        profile._finish(None, returned=True)
    assert events == ["create", "enable"]
    assert profile.availability()["active"] is True


def test_active_or_contended_writer_never_waits_or_touches_native_stats(tmp_path):
    profile, _wrapped, _delegate, events = _setup()
    tmp_path.chmod(0o700)
    output = str(tmp_path / "parent-probe-first-observe.json")
    assert profile._claim() is True
    assert profile._start() is True
    assert profile.write_after_cleanup(output) is False
    assert profile._lock.acquire(blocking=False)
    try:
        assert profile.write_after_cleanup(output) is False
    finally:
        profile._lock.release()
    assert events == ["create", "enable"]
    assert not (tmp_path / "parent-probe-first-observe.json").exists()
    profile._finish(None, returned=True)


def test_exclusive_report_is_0600_bounded_json_and_written_once(tmp_path):
    profile, events = _ready()
    tmp_path.chmod(0o700)
    output = tmp_path / "parent-probe-first-observe.json"
    assert profile.write_after_cleanup(str(output)) is True
    raw = output.read_bytes()
    assert 0 < len(raw) <= 1_000_000
    assert raw.isascii() and raw.endswith(b"\n")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    report = json.loads(raw)
    assert list(report) == [
        "schema",
        "diagnostic_only",
        "iteration",
        "observe_ordinal",
        "scope",
        "observe_started",
        "observe_returned",
        "stats_entries_considered",
        "selection",
        "rows",
    ]
    assert report["diagnostic_only"] is True and report["rows"] == []
    assert report["observe_started"] is report["observe_returned"] is True
    assert report["stats_entries_considered"] == 0
    assert (json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode() == raw
    assert profile.write_after_cleanup(str(output)) is False
    assert output.read_bytes() == raw
    assert _callback_count(events) == 1


def test_existing_output_failure_consumes_write_without_retry(tmp_path):
    profile, _events = _ready()
    tmp_path.chmod(0o700)
    output = tmp_path / "parent-probe-first-observe.json"
    output.write_bytes(b"existing\n")
    with pytest.raises(FileExistsError):
        profile.write_after_cleanup(str(output))
    assert output.read_bytes() == b"existing\n"
    assert profile.write_after_cleanup(str(output)) is False
    assert profile.availability()["available"] is False


def test_actual_one_megabyte_limit_rejects_before_open(monkeypatch, tmp_path):
    profile, _events = _ready()
    tmp_path.chmod(0o700)
    monkeypatch.setattr(module.json, "dumps", lambda *args, **kwargs: "x" * 1_000_000)
    monkeypatch.setattr(
        module.os, "open", lambda *args, **kwargs: pytest.fail("oversize report reached filesystem")
    )
    with pytest.raises(ValueError, match="PARENT_PROFILE_OUTPUT_BOUND"):
        profile.write_after_cleanup(str(tmp_path / "parent-probe-first-observe.json"))


def test_actual_4096_line_limit_rejects_before_single_write(monkeypatch):
    profile, _events = _ready()
    monkeypatch.setattr(module.json, "dumps", lambda *args, **kwargs: "x" * 4096)

    class Sink:
        def write(self, _value):
            pytest.fail("oversize availability reached output")

    monkeypatch.setattr(module.sys, "stdout", Sink())
    with pytest.raises(ValueError, match="PARENT_PROFILE_LINE_BOUND"):
        profile.emit_availability()


class _HookValue:
    def __eq__(self, _other):
        pytest.fail("foreign equality invoked")

    def __bool__(self):
        pytest.fail("foreign truth invoked")

    def __iter__(self):
        pytest.fail("foreign iteration invoked")

    def __getattr__(self, _name):
        pytest.fail("foreign attribute invoked")


@pytest.mark.parametrize(
    "field", ["schema_version", "selected", "active", "completed", "available", "report_written"]
)
def test_foreign_scalar_values_rejected_without_hooks(monkeypatch, field):
    profile, _events = _ready()
    snapshot = {
        "schema_version": 1,
        "selected": True,
        "active": False,
        "completed": True,
        "available": True,
        "report_written": False,
    }
    snapshot[field] = _HookValue()
    monkeypatch.setattr(module.FirstObserveProfile, "availability", lambda _self: snapshot)
    with pytest.raises(ValueError, match="PARENT_PROFILE_SCALAR_DATA_INVALID"):
        profile.emit_availability()


@pytest.mark.parametrize(
    "stats", [0, 1, 2, 3, 4], ids=["None", "stats1", "stats2", "stats3", "stats4"]
)
def test_foreign_stats_rejected_without_iteration_or_attribute_hooks(stats):
    # Pytest inspects parameter objects for __name__ while producing IDs. Defer
    # hostile construction until the actual admission check, preserving those
    # intended IDs and all five original input shapes without granting hooks.
    if stats == 0:
        stats = None
    elif stats == 1:
        stats = ()
    elif stats == 2:
        stats = _HookValue()
    elif stats == 3:
        stats = [_HookValue()]
    else:
        stats = [("safe", 1, 0, 1.0, 0.5, None)]
    with pytest.raises(ValueError, match="PARENT_PROFILE_NATIVE_STATS"):
        module._static_report(stats, __file__, True)


def test_spoofed_tuple_entry_names_do_not_establish_native_stats_ownership():
    spoof = type("profiler_entry", (tuple,), {"__module__": "_lsprof"})
    entry = spoof(("not a native entry", 1, 0, 1.0, 0.5, None))
    with pytest.raises(ValueError, match="PARENT_PROFILE_NATIVE_STATS"):
        module._static_report([entry], __file__, True)


@pytest.mark.parametrize(
    "filename,function",
    [
        ("../private.py", "safe"),
        ("tests/secret with space.py", "safe"),
        ("tests/safe.py", "SELECT value"),
        ("tests/safe.py", "https://invalid.example"),
        ("tests/\u00e9.py", "safe"),
    ],
)
def test_unsafe_native_ascii_or_unicode_static_rows_never_export(filename, function):
    profile, _events = _ready()
    report = profile._report.copy()
    report["stats_entries_considered"] = 1
    report["rows"] = [
        {
            "stats_entry_ordinal": 0,
            "group": "project",
            "file": filename,
            "line": 1,
            "function": function,
            "calls": 1,
            "recursive_calls": 0,
            "inclusive_seconds": 1.0,
            "self_seconds": 0.5,
        }
    ]
    assert module._admit_report(report) is False


def test_failed_scalar_write_is_once_and_not_retried(monkeypatch):
    profile, _events = _ready()
    calls = []
    error = OSError("single write failure")

    class Sink:
        def write(self, value):
            calls.append(value)
            raise error

    monkeypatch.setattr(module.sys, "stdout", Sink())
    with pytest.raises(OSError) as caught:
        profile.emit_availability()
    assert caught.value is error
    assert len(calls) == 1
    assert calls[0].startswith("AQT_PARENT_FIRST_OBSERVE_PROFILE ")
    assert calls[0].endswith("\n") and calls[0].isascii()
    assert len(calls[0].encode()) <= 4096


def test_retained_fresh_native_stats_rejection_releases_its_input_without_gc():
    private = _Box()
    private_ref = weakref.ref(private)
    stats = [private]
    try:
        module._static_report(stats, __file__, True)
    except ValueError as caught:
        retained = caught
    else:
        pytest.fail("foreign stats were accepted")
    del stats, private
    assert str(retained) == "PARENT_PROFILE_NATIVE_STATS"
    assert private_ref() is None


@pytest.mark.parametrize("pending", [False, True])
def test_retained_native_close_fault_clears_diagnostic_owners_and_preserves_explicit_primary(
    monkeypatch, tmp_path, pending
):
    profile, _events = _ready()
    private = _Box()
    private_ref = weakref.ref(private)
    profile._factory = lambda owner=private: None
    operation = _WeakError("original operation")
    original_cause, original_context = (
        LookupError("operation cause"),
        ValueError("operation context"),
    )
    operation.__cause__, operation.__context__, operation.__suppress_context__ = (
        original_cause,
        original_context,
        True,
    )
    fdopen_error, close_error = RuntimeError("fdopen failed"), _Alarm("close interrupted")
    unrelated = LookupError("auxiliary unrelated cause")
    close_error.__cause__, close_error.__suppress_context__ = unrelated, True
    native_close = os.close
    close_calls = []

    def close(descriptor):
        try:
            close_calls.append(descriptor)
            native_close(descriptor)
            raise close_error
        finally:
            descriptor = None

    tmp_path.chmod(0o700)
    monkeypatch.setattr(module.os, "fdopen", _raise(fdopen_error))
    monkeypatch.setattr(module.os, "close", close)
    output = str(tmp_path / "parent-probe-first-observe.json")
    if pending:
        try:
            raise operation
        except _WeakError:
            before = (
                operation.__traceback__,
                operation.__cause__,
                operation.__context__,
                operation.__suppress_context__,
            )
            assert profile.write_after_cleanup(output, primary=operation) is False
            assert (
                operation.__traceback__,
                operation.__cause__,
                operation.__context__,
                operation.__suppress_context__,
            ) == before
        assert fdopen_error.__traceback__ is None and fdopen_error.__context__ is None
        assert close_error.__traceback__ is None
        assert close_error.__context__ is not operation
    else:
        try:
            profile.write_after_cleanup(output)
        except _Alarm as caught:
            assert caught is close_error
        else:
            pytest.fail("fresh close interruption was suppressed")
        # Normal exception chaining is preserved in the no-primary path.
        assert close_error.__context__ is fdopen_error
    assert len(close_calls) == 1
    assert close_error.__cause__ is unrelated
    assert close_error.__suppress_context__ is True
    del profile, private
    assert private_ref() is None
