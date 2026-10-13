"""Finite native fault models after admission; no public clock API or timing thresholds."""

import json
import weakref
from contextlib import suppress

import pytest

from tests import retained_restore_profile as profile

_CLOCK_MAX = (1 << 63) - 1
_DELTA_MAX = 10**15
_SCOPE = (
    "Native staggered whole factory.execute wall/process/thread intervals inside cProfile; "
    "clock and wrapper overhead included. Process CPU includes other process threads, "
    "not child processes; thread CPU covers the calling thread. Setup, construction, "
    "decoding, assertions, cleanup and report generation excluded. No subtraction, "
    "cause attribution, profitability or deadline-fit evidence."
)
_LEGACY_REPORT = {
    "schema": "retained-factory-execute-static-cprofile/1",
    "diagnostic_only": True,
    "scope": (
        "Instrumented factory.execute only; fixture setup, factory construction, "
        "result decoding/assertions, cleanup and report generation are excluded. "
        "A returned execute call is not a passing restore test or startup acceptance."
    ),
    "factory_execute_started": True,
    "factory_execute_returned": True,
    "stats_entries_considered": 0,
    "selection": (
        "Union of top128 inclusive and self-time entries, overall and project-only; "
        "up to512 rows. Unselected entries are omitted. Inclusive times overlap. "
        "Ordinals distinguish captured entries with identical static labels. "
        "These limits bound emitted data, not cProfile internal storage."
    ),
    "rows": [],
    "profile_status": "valid",
    "diagnostic_faults": [],
}


class FakeProfiler:
    def __init__(self, events, *, enable_error=None, disable_error=None):
        self.events = events
        self.enable_error = enable_error
        self.disable_error = disable_error
        self.disabled = False

    def enable(self):
        self.events.append("enable")
        if self.enable_error is not None:
            raise self.enable_error

    def disable(self):
        self.events.append("disable")
        if self.disable_error is not None:
            raise self.disable_error
        self.disabled = True

    def getstats(self):
        self.events.append("stats")
        assert self.disabled
        return []


class LiteralPrecedingExecute:
    """Preceding wrapper independent of production timing helper."""

    def __init__(self, profiler):
        self.profiler = profiler
        self.execute_started = self.execute_returned = False
        self.diagnostic_faults = []

    def execute(self, operation, **arguments):
        try:
            self.profiler.enable()
        except BaseException:
            self.diagnostic_faults.append("enable_failed")
            raise
        self.execute_started = True
        try:
            result = operation(**arguments)
            self.execute_returned = True
            return result
        finally:
            try:
                self.profiler.disable()
            except BaseException:
                self.diagnostic_faults.append("execute_disable_failed")


def capture_for(tmp_path, events, starts=(10, 20, 30), ends=(40, 80, 100)):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"), measure_execute=True)
    capture.profiler = FakeProfiler(events)
    for name, start, end in zip(("wall", "process", "thread"), starts, ends, strict=True):
        values = iter((start, end))

        def clock(values=values, name=name):
            events.append(name)
            return next(values)

        # Private deterministic fault seam AFTER native-pointer constructor admission.
        setattr(capture, f"_{name}_clock_ns", clock)
    return capture


def require_timing(capture, status, deltas):
    actual = capture._execute_timing_report()
    assert tuple(actual) == (
        "status",
        "wall_elapsed_ns",
        "process_cpu_elapsed_ns",
        "thread_cpu_elapsed_ns",
        "scope",
    )
    assert actual == {
        "status": status,
        "wall_elapsed_ns": deltas[0],
        "process_cpu_elapsed_ns": deltas[1],
        "thread_cpu_elapsed_ns": deltas[2],
        "scope": _SCOPE,
    }


def selected_error():
    primary = ValueError("original operation")
    cause, context = RuntimeError("original cause"), LookupError("original context")
    primary.__cause__, primary.__context__ = cause, context
    primary.__suppress_context__ = False
    return primary, cause, context


def test_default_literal_wire_order_and_none_owners_without_clock_reads(tmp_path, monkeypatch):
    def forbidden():
        raise AssertionError("default read clock")

    for name in ("perf_counter", "process_time", "thread_time"):
        monkeypatch.setattr(profile, f"_native_{name}_ns", forbidden)
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
    events, arguments = [], []
    capture.profiler = FakeProfiler(events)
    assert capture._wall_clock_ns is capture._process_clock_ns is capture._thread_clock_ns is None
    sentinel = object()

    def operation(**kwargs):
        events.append("operation")
        arguments.append(kwargs)
        return sentinel

    assert capture.execute(operation, operation_id="one", sentinel=sentinel) is sentinel
    assert arguments == [{"operation_id": "one", "sentinel": sentinel}]
    assert events == ["enable", "operation", "disable"]
    capture.write_report()
    assert events == ["enable", "operation", "disable", "disable", "stats"]
    assert capture.output.read_bytes() == (
        json.dumps(_LEGACY_REPORT, allow_nan=False, indent=2) + "\n"
    ).encode("utf-8")
    assert capture.report_written and capture.profile_valid


class ForeignBool:
    def __bool__(self):
        raise AssertionError("foreign bool hook")


@pytest.mark.parametrize("value", [None, 0, 1, "yes", ForeignBool()])
def test_exact_bool_rejected_before_any_optional_work(tmp_path, monkeypatch, value):
    def forbidden(*args, **kwargs):
        raise AssertionError("premature optional work")

    monkeypatch.setattr(profile, "Path", forbidden)
    monkeypatch.setattr(profile.cProfile, "Profile", forbidden)
    with pytest.raises(TypeError, match="RETAINED_PROFILE_MEASURE_EXECUTE_BOOL"):
        profile.RetainedRestoreProfile(str(tmp_path / "profile.json"), measure_execute=value)


def test_enabled_literal_clock_order_and_forwarding(tmp_path):
    events, arguments = [], []
    capture = capture_for(tmp_path, events)
    sentinel = object()

    def operation(**kwargs):
        events.append("operation")
        arguments.append(kwargs)
        return sentinel

    assert capture.execute(operation, operation_id="one", sentinel=sentinel) is sentinel
    assert arguments == [{"operation_id": "one", "sentinel": sentinel}]
    assert events == [
        "enable",
        "wall",
        "process",
        "thread",
        "operation",
        "wall",
        "process",
        "thread",
        "disable",
    ]
    require_timing(capture, "valid", (30, 60, 70))
    capture.write_report()
    report = json.loads(capture.output.read_bytes())
    assert report["schema"] == "retained-factory-execute-static-cprofile/2"
    assert report["execute_timing"] == {
        "status": "valid",
        "wall_elapsed_ns": 30,
        "process_cpu_elapsed_ns": 60,
        "thread_cpu_elapsed_ns": 70,
        "scope": _SCOPE,
    }
    assert capture.report_written and capture.profile_valid


@pytest.mark.parametrize(
    ("starts", "ends", "deltas"),
    [
        ((0, 0, 0), (0, 0, 0), (0, 0, 0)),
        ((_CLOCK_MAX - _DELTA_MAX,) * 3, (_CLOCK_MAX,) * 3, (_DELTA_MAX,) * 3),
        ((10, 100, 300), (11, 200, 900), (1, 100, 600)),
    ],
)
def test_native_bounds_and_separate_intervals_without_crossclock_comparisons(
    tmp_path, starts, ends, deltas
):
    capture = capture_for(tmp_path, [], starts, ends)
    sentinel = object()
    assert capture.execute(lambda: sentinel) is sentinel
    require_timing(capture, "valid", deltas)
    assert capture.diagnostic_faults == []


class HookInt(int):
    def __int__(self):
        raise AssertionError("conversion hook")

    def __le__(self, other):
        raise AssertionError("comparison hook")

    def __ge__(self, other):
        raise AssertionError("comparison hook")


@pytest.mark.parametrize("stage", ["start", "end"])
@pytest.mark.parametrize("value", [True, 1.0, "1", HookInt(1), None, -1, _CLOCK_MAX + 1])
def test_invalid_native_readings_rejected_without_conversion_or_hooks(tmp_path, stage, value):
    starts = (10, 20, value if stage == "start" else 30)
    ends = (40, 80, value if stage == "end" else 100)
    capture = capture_for(tmp_path, [], starts, ends)
    assert capture.execute(lambda: "result") == "result"
    require_timing(capture, "invalid", (None,) * 3)
    assert capture.diagnostic_faults == ["execute_timing_invalid"]
    capture.write_report()
    report = json.loads(capture.output.read_bytes())
    assert report["profile_status"] == "invalid" and report["rows"] == []
    assert capture.report_written and not capture.profile_valid


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("end", [9, 10 + _DELTA_MAX + 1])
def test_backward_or_oversized_delta_in_each_clock_rejects_all_timing(tmp_path, index, end):
    starts, ends = [10] * 3, [20] * 3
    ends[index] = end
    capture = capture_for(tmp_path, [], tuple(starts), tuple(ends))
    assert capture.execute(lambda: "result") == "result"
    require_timing(capture, "invalid", (None,) * 3)
    assert capture.diagnostic_faults == ["execute_timing_invalid"]


@pytest.mark.parametrize("name", ["wall", "process", "thread"])
@pytest.mark.parametrize("stage", ["start", "end"])
def test_exact_oserror_at_all_endpoints_does_not_replace_operation(tmp_path, name, stage):
    events, calls, reads = [], [], []
    capture = capture_for(tmp_path, events)
    metadata = OSError("private native clock detail")

    def clock():
        reads.append(None)
        if len(reads) == (1 if stage == "start" else 2):
            raise metadata
        return 1

    setattr(capture, f"_{name}_clock_ns", clock)
    sentinel = object()
    assert capture.execute(lambda: calls.append("operation") or sentinel) is sentinel
    assert calls == ["operation"] and len(reads) == 2
    assert metadata.__traceback__ is None
    assert events.count("enable") == events.count("disable") == 1
    require_timing(capture, "invalid", (None,) * 3)


class RestoreDeadline(OSError):
    pass


@pytest.mark.parametrize("stage", ["start", "end"])
@pytest.mark.parametrize("kind", [RestoreDeadline, KeyboardInterrupt, RuntimeError])
@pytest.mark.parametrize("ambient", [False, True])
def test_fresh_interrupt_is_not_suppressed_by_ambient_handled_error(tmp_path, stage, kind, ambient):
    events, calls, reads = [], [], []
    capture = capture_for(tmp_path, events)
    interrupt, ambient_error = kind("fresh interrupt"), LookupError("handled ambient")

    def clock():
        reads.append(None)
        if len(reads) == (1 if stage == "start" else 2):
            raise interrupt
        return 1

    capture._thread_clock_ns = clock

    def operation():
        calls.append("operation")
        return "result"

    if ambient:
        try:
            raise ambient_error
        except LookupError:
            with pytest.raises(kind) as caught:
                capture.execute(operation)
    else:
        with pytest.raises(kind) as caught:
            capture.execute(operation)
    assert caught.value is interrupt
    assert calls == ([] if stage == "start" else ["operation"])
    assert events.count("enable") == events.count("disable") == 1
    assert capture.execute_started is (stage == "end")
    assert capture.execute_returned is (stage == "end")
    require_timing(capture, "invalid", (None,) * 3)


@pytest.mark.parametrize("name", ["wall", "process", "thread"])
@pytest.mark.parametrize("kind", ["ordinary", "interrupt", "group"])
def test_only_actual_operation_primary_authorizes_secondary_fault_isolation(tmp_path, name, kind):
    capture = capture_for(tmp_path, [])
    calls, reads = [], []
    primary = {
        "ordinary": RuntimeError("original"),
        "interrupt": KeyboardInterrupt("original"),
        "group": BaseExceptionGroup("original", [ValueError("leaf"), KeyboardInterrupt("leaf")]),
    }[kind]
    metadata = KeyboardInterrupt("secondary clock fault")

    def clock():
        reads.append(None)
        if len(reads) == 2:
            raise metadata
        return 1

    setattr(capture, f"_{name}_clock_ns", clock)

    def operation(*, operation_id):
        calls.append(operation_id)
        raise primary

    with pytest.raises(type(primary)) as caught:
        capture.execute(operation, operation_id="one")
    assert caught.value is primary and calls == ["one"]
    assert metadata.__traceback__ is metadata.__context__ is None
    assert capture.execute_started and not capture.execute_returned
    require_timing(capture, "invalid", (None,) * 3)


def test_same_primary_fault_restores_entry_traceback_cause_context_and_suppression(tmp_path):
    primary, cause, context = selected_error()
    capture = capture_for(tmp_path, [])
    entries, reads = [], []

    def clock():
        reads.append(None)
        if len(reads) == 2:
            entries.append(BaseException.__traceback__.__get__(primary))
            raise primary
        return 1

    capture._thread_clock_ns = clock

    def operation():
        raise primary

    with pytest.raises(ValueError) as caught:
        capture.execute(operation)
    assert caught.value is primary and len(entries) == 1
    frame, visited = BaseException.__traceback__.__get__(primary), []
    while frame is not entries[0] and frame is not None and len(visited) < 16:
        visited.append(frame.tb_frame.f_code.co_name)
        frame = frame.tb_next
    assert frame is entries[0]
    assert "_read_execute_clock" not in visited and "_sample_execute_clocks" not in visited
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False


@pytest.mark.parametrize("cause_kind", ["primary", "foreign"])
@pytest.mark.parametrize("suppressed", [False, True])
def test_direct_auxiliary_primary_edges_are_detached_without_clearing_foreign_cause(
    tmp_path, cause_kind, suppressed
):
    primary, cause, context = selected_error()
    capture = capture_for(tmp_path, [])
    metadata, foreign, reads = RuntimeError("retained error"), LookupError("foreign"), []

    def clock():
        reads.append(None)
        if len(reads) == 2:
            metadata.__cause__ = primary if cause_kind == "primary" else foreign
            metadata.__suppress_context__ = suppressed
            raise metadata
        return 1

    capture._thread_clock_ns = clock

    def operation():
        raise primary

    with pytest.raises(ValueError) as caught:
        capture.execute(operation)
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False
    assert metadata.__traceback__ is metadata.__context__ is None
    assert metadata.__cause__ is (None if cause_kind == "primary" else foreign)
    assert metadata.__suppress_context__ is suppressed


def test_auxiliary_independently_owned_context_is_preserved(tmp_path):
    primary, cause, context = selected_error()
    capture = capture_for(tmp_path, [])
    metadata, foreign, reads = RuntimeError("retained error"), LookupError("foreign"), []

    def clock():
        reads.append(None)
        if len(reads) == 2:
            try:
                raise metadata
            finally:
                metadata.__context__ = foreign
        return 1

    capture._thread_clock_ns = clock

    def operation():
        raise primary

    with pytest.raises(ValueError) as caught:
        capture.execute(operation)
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert metadata.__traceback__ is None and metadata.__context__ is foreign
    assert metadata.__cause__ is None and metadata.__suppress_context__ is False


def test_retained_auxiliary_fault_adds_no_private_primary_ownership_relative_to_legacy(tmp_path):
    def exercise(enabled):
        metadata, refs, reads, events = RuntimeError("retained error"), [], [], []

        class Private:
            pass

        class PrivateError(RuntimeError):
            pass

        class PrivateCause(RuntimeError):
            pass

        class PrivateContext(LookupError):
            pass

        def operation():
            private = Private()
            cause, context = PrivateCause(private), PrivateContext(private)
            try:
                raise PrivateError(private)
            except PrivateError as primary:
                primary.__cause__, primary.__context__ = cause, context
                refs.extend(weakref.ref(item) for item in (private, primary, cause, context))
                raise
            finally:
                private = cause = context = None

        def clock():
            reads.append(None)
            if len(reads) == 2:
                raise metadata
            return 1

        if enabled:
            capture = capture_for(tmp_path, events)
            capture._thread_clock_ns = clock
        else:
            capture = LiteralPrecedingExecute(FakeProfiler(events))
        with suppress(PrivateError):
            capture.execute(operation)
        return capture, metadata, tuple(ref() is None for ref in refs)

    baseline, baseline_error, baseline_released = exercise(False)
    candidate, metadata, released = exercise(True)
    assert baseline_released == released == (True, True, True, True)
    assert baseline_error.__traceback__ is baseline_error.__context__ is None
    assert metadata.__traceback__ is metadata.__context__ is None
    assert baseline.execute_started and candidate.execute_started
    # Captures and auxiliary errors remain held; no manual context clearing or forced GC.


def test_invalid_foreign_sample_does_not_invoke_hooks_or_retain_value(tmp_path):
    capture = capture_for(tmp_path, [])
    refs, calls = [], []

    class Foreign:
        def __int__(self):
            raise AssertionError("foreign conversion")

        def __le__(self, other):
            raise AssertionError("foreign comparison")

    def clock():
        calls.append(None)
        value = Foreign()
        refs.append(weakref.ref(value))
        return value

    capture._thread_clock_ns = clock
    assert capture.execute(lambda: "result") == "result"
    assert calls == [None, None] and all(ref() is None for ref in refs)
    require_timing(capture, "invalid", (None,) * 3)


def test_native_pointer_binding_resists_delegate_alias_replacement(tmp_path, monkeypatch):
    capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"), measure_execute=True)
    assert (capture._wall_clock_ns, capture._process_clock_ns, capture._thread_clock_ns) == (
        profile._native_perf_counter_ns,
        profile._native_process_time_ns,
        profile._native_thread_time_ns,
    )
    events, reads = [], []
    capture.profiler = FakeProfiler(events)
    for name in ("wall", "process", "thread"):

        def clock(name=name):
            reads.append(name)
            return 0

        # Private finite sample model after native admission.
        setattr(capture, f"_{name}_clock_ns", clock)

    def foreign():
        raise AssertionError("foreign alias replacement executed")

    def operation():
        for name in ("perf_counter", "process_time", "thread_time"):
            monkeypatch.setattr(profile, f"_native_{name}_ns", foreign)
        return "result"

    assert capture.execute(operation) == "result"
    assert reads == ["wall", "process", "thread"] * 2
    require_timing(capture, "valid", (0, 0, 0))


def test_repeat_invalidates_metadata_but_forwards_each_operation_and_cleanup_once(tmp_path):
    events, calls = [], []
    capture = capture_for(tmp_path, events)
    primary = RuntimeError("second operation")

    def operation(*, index):
        calls.append(index)
        if index == 2:
            raise primary
        return index

    assert capture.execute(operation, index=1) == 1
    require_timing(capture, "valid", (30, 60, 70))
    with pytest.raises(RuntimeError) as caught:
        capture.execute(operation, index=2)
    assert caught.value is primary
    assert capture.execute(operation, index=3) == 3
    assert calls == [1, 2, 3]
    assert events.count("wall") == events.count("process") == events.count("thread") == 2
    assert events.count("enable") == events.count("disable") == 3
    require_timing(capture, "invalid", (None,) * 3)
    assert capture.diagnostic_faults == ["execute_timing_invalid"]


def test_enable_interrupt_preserves_unstarted_unavailable_and_no_clock_or_operation(tmp_path):
    events, calls = [], []
    capture = capture_for(tmp_path, events)
    primary = RestoreDeadline("enable interrupt")
    capture.profiler = FakeProfiler(events, enable_error=primary)
    with pytest.raises(RestoreDeadline) as caught:
        capture.execute(lambda: calls.append("operation"))
    assert caught.value is primary and calls == [] and events == ["enable"]
    assert not capture.execute_started and not capture.execute_returned
    require_timing(capture, "unavailable", (None,) * 3)
    assert capture.diagnostic_faults == ["enable_failed"]


def test_enabled_report_before_operation_has_only_unavailable_null_timing(tmp_path):
    capture = capture_for(tmp_path, [])
    capture.write_report()
    report = json.loads(capture.output.read_bytes())
    assert report["schema"] == "retained-factory-execute-static-cprofile/2"
    assert report["execute_timing"]["status"] == "unavailable"
    assert report["factory_execute_started"] is report["factory_execute_returned"] is False
    require_timing(capture, "unavailable", (None,) * 3)


@pytest.mark.parametrize("invalid", [False, True])
def test_optin_json_remains_silent_private_finite_and_bounded(
    tmp_path, monkeypatch, capsys, invalid
):
    capture = capture_for(tmp_path, [], (0, 0, True if invalid else 0), (10, 20, 30))
    assert capture.execute(lambda: "result") == "result"

    def forbidden_print(*args, **kwargs):
        raise AssertionError("writer attempted output")

    monkeypatch.setattr("builtins.print", forbidden_print)
    capture.write_report()
    raw = capture.output.read_bytes()
    assert len(raw) <= 1_000_000 and raw.endswith(b"\n")
    assert capture.output.stat().st_mode & 0o777 == 0o600

    def reject_constant(value):
        raise AssertionError("nonfinite JSON")

    report = json.loads(raw, parse_constant=reject_constant)
    assert report["schema"] == "retained-factory-execute-static-cprofile/2"
    assert report["execute_timing"]["status"] == ("invalid" if invalid else "valid")
    assert capture.profile_valid is (not invalid) and capture.report_written
    assert capsys.readouterr() == ("", "")


def test_optin_exclusive_evidence_and_byte_cap_are_not_weakened(tmp_path, monkeypatch):
    capture = capture_for(tmp_path, [])
    assert capture.execute(lambda: "result") == "result"
    capture.output.write_bytes(b"prior")
    capture.write_report()
    assert capture.output.read_bytes() == b"prior" and not capture.report_written
    capture.output.unlink()
    monkeypatch.setattr(profile, "_MAX_REPORT_BYTES", 1)
    capture.write_report()
    assert not capture.output.exists() and not capture.report_written


def test_default_error_metadata_and_cleanup_match_literal_preceding_wrapper(tmp_path):
    for candidate in (False, True):
        events = []
        primary, cause, context = selected_error()
        if candidate:
            capture = profile.RetainedRestoreProfile(str(tmp_path / "profile.json"))
            capture.profiler = FakeProfiler(events)
        else:
            capture = LiteralPrecedingExecute(FakeProfiler(events))

        def operation(*, operation_id, events=events, primary=primary):
            events.append(("operation", operation_id))
            raise primary

        with pytest.raises(ValueError) as caught:
            capture.execute(operation, operation_id="one")
        assert caught.value is primary
        assert primary.__cause__ is cause and primary.__context__ is context
        assert primary.__suppress_context__ is False
        assert events == ["enable", ("operation", "one"), "disable"]
        assert capture.execute_started and not capture.execute_returned


@pytest.mark.parametrize("scenario", ["success", "original-error", "both-errors", "start-deadline"])
def test_optin_integration_keeps_close_errors_financial_checks_and_original_alarm(
    tmp_path, monkeypatch, scenario
):
    import signal
    from contextlib import nullcontext
    from types import SimpleNamespace

    from apps.trader.continuous_simulation_factory import _ActualClock
    from tests.integration import test_continuous_simulation_factory_outcome as integration

    calls, events, timers, handlers = [], [], [], []
    original, cleanup, deadline_error = (
        RuntimeError("execute"),
        RuntimeError("close"),
        RestoreDeadline("deadline"),
    )
    capture = capture_for(tmp_path, events)
    if scenario == "start-deadline":

        def clock():
            raise deadline_error

        capture._thread_clock_ns = clock
    independent = ("independent sentinel",)
    venue = SimpleNamespace(read=lambda: independent)
    pair = SimpleNamespace(
        base=SimpleNamespace(
            h=SimpleNamespace(
                lease=SimpleNamespace(fence="old"),
                coordinator=SimpleNamespace(release=lambda fence: calls.append(("release", fence))),
            ),
            scope=SimpleNamespace(account_id="synthetic"),
        ),
        counts=lambda: (1, 2, 3),
        venue=venue,
    )
    prior = SimpleNamespace(
        checkpoint=SimpleNamespace(semantic_sha256="checkpoint"),
        receipt=SimpleNamespace(commit=SimpleNamespace(semantic_sha256="commit")),
    )
    daily = SimpleNamespace(assignment=SimpleNamespace(semantic_sha256="assignment"))
    history = (pair, None, prior, daily, object(), independent, ())

    class Factory:
        def __init__(self, config, *, account_id, stop_requested):
            assert account_id == "synthetic" and stop_requested() is False
            self.clock = _ActualClock()
            self.lease = SimpleNamespace(fence="new")
            self.outcomes = SimpleNamespace(require_bindings=lambda: None)
            self.delivery = SimpleNamespace(
                publisher=SimpleNamespace(require_completed=self.reject)
            )
            self.venue = venue
            self.engine = self.venue_engine = object()

        def reject(self, batch):
            raise ValueError("SUCCESSFUL_DISPATCH_COMMIT")

        def execute(self, *, operation_id):
            calls.append(("execute", operation_id))
            if scenario in {"original-error", "both-errors"}:
                raise original
            return json.dumps(
                {
                    "checkpoint_sha256": "checkpoint",
                    "commit_sha256": "commit",
                    "assignment_sha256": "assignment",
                    "status": "restored",
                }
            )

        def close(self):
            calls.append(("close",))
            self.engine = self.venue_engine = None
            if scenario == "both-errors":
                raise cleanup

    def construct(output, *, measure_execute):
        assert output == str(capture.output) and measure_execute is True
        calls.append(("profile",))
        return capture

    old_handler = object()
    monkeypatch.setattr(signal, "getsignal", lambda kind: old_handler)
    monkeypatch.setattr(signal, "getitimer", lambda kind: (0.0, 0.0))
    monkeypatch.setattr(signal, "signal", lambda kind, handler: handlers.append((kind, handler)))
    monkeypatch.setattr(signal, "setitimer", lambda kind, delay: timers.append((kind, delay)))
    monkeypatch.setenv("AQT_RETAINED_RESTORE_PROFILE_PATH", str(capture.output))
    monkeypatch.setattr(profile, "RetainedRestoreProfile", construct)
    monkeypatch.setattr(integration, "ContinuousSimulationFactory", Factory)
    monkeypatch.setattr(integration, "_no_new_sources", lambda patch: nullcontext())
    if scenario == "success":
        integration._execute_retained_factory(history, None, monkeypatch)
        assert capture.report_written and capture.profile_valid
    else:
        expected = (
            ExceptionGroup
            if scenario == "both-errors"
            else (RestoreDeadline if scenario == "start-deadline" else RuntimeError)
        )
        with pytest.raises(expected) as caught:
            integration._execute_retained_factory(history, None, monkeypatch)
        if scenario == "both-errors":
            assert caught.value.exceptions == (original, cleanup)
        else:
            assert caught.value is (deadline_error if scenario == "start-deadline" else original)
    assert calls[0] == ("profile",) and calls[-1] == ("close",)
    assert timers == [(signal.ITIMER_REAL, 120), (signal.ITIMER_REAL, 0)]
    assert len(handlers) == 2 and handlers[-1] == (signal.SIGALRM, old_handler)
    assert callable(handlers[0][1])
    assert sum(call[0] == "execute" for call in calls) == (0 if scenario == "start-deadline" else 1)


def inject_metadata_interrupt(capture, phase, error, reads):
    sample = capture._sample_execute_clocks

    def wrapped_sample(primary):
        reads.append(primary)
        if phase == "start-sampler" or (phase == "end-sampler" and len(reads) == 2):
            raise error
        return sample(primary)

    capture._sample_execute_clocks = wrapped_sample
    if phase == "finalizer":

        def finalizer(starts, ends):
            raise error

        capture._finish_execute_timing = finalizer


@pytest.mark.parametrize("phase", ["start-sampler", "end-sampler", "finalizer"])
@pytest.mark.parametrize("kind", [RestoreDeadline, KeyboardInterrupt])
@pytest.mark.parametrize("ambient", [False, True])
def test_metadata_boundary_interrupt_without_operation_primary_propagates(
    tmp_path, phase, kind, ambient
):
    capture = capture_for(tmp_path, [])
    interrupt, calls, reads = kind("fresh metadata interrupt"), [], []
    inject_metadata_interrupt(capture, phase, interrupt, reads)

    def operation():
        calls.append("operation")
        return "result"

    if ambient:
        try:
            raise LookupError("ambient handled error")
        except LookupError:
            with pytest.raises(kind) as caught:
                capture.execute(operation)
    else:
        with pytest.raises(kind) as caught:
            capture.execute(operation)
    assert caught.value is interrupt
    assert calls == ([] if phase == "start-sampler" else ["operation"])
    assert all(primary is None for primary in reads)
    assert capture.profiler.events.count("enable") == capture.profiler.events.count("disable") == 1
    require_timing(capture, "invalid", (None,) * 3)
    assert capture.diagnostic_faults == ["execute_timing_invalid"]


@pytest.mark.parametrize("phase", ["end-sampler", "finalizer"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_whole_pending_metadata_block_preserves_actual_operation_primary(tmp_path, phase, kind):
    capture = capture_for(tmp_path, [])
    primary, cause, context = selected_error()
    metadata, reads = kind("retained metadata interrupt"), []
    inject_metadata_interrupt(capture, phase, metadata, reads)

    def operation():
        raise primary

    with pytest.raises(ValueError) as caught:
        capture.execute(operation)
    assert caught.value is primary and reads == [None, primary]
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False
    assert metadata.__traceback__ is metadata.__context__ is None
    require_timing(capture, "invalid", (None,) * 3)
    assert capture.diagnostic_faults == ["execute_timing_invalid"]


def test_optin_nonfinite_profile_json_still_rejects_before_creating_evidence(tmp_path):
    from types import SimpleNamespace

    capture = capture_for(tmp_path, [])
    assert capture.execute(lambda: "result") == "result"
    entry = SimpleNamespace(
        code="<built-in method builtins.len>",
        callcount=1,
        reccallcount=0,
        totaltime=float("nan"),
        inlinetime=0.0,
    )
    capture.profiler.getstats = lambda: [entry]
    capture.write_report()
    assert not capture.report_written and not capture.output.exists()
    assert capture.diagnostic_faults == ["report_write_failed"]
