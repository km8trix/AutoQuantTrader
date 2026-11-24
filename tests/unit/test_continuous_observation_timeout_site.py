"""Deadline metadata identifies the original check without changing observation.

The original reader, dispatcher and parser run against controlled clocks and
syscall mocks. No kernel, worker, process or provider is exercised. Synthetic
traceback/code changes test metadata bounds only; they confer no worker evidence.
"""

import gc
import json
import os
import stat
import subprocess
import weakref
from contextlib import suppress
from types import CodeType, SimpleNamespace, TracebackType

import pytest

from packages.application import continuous_process as process_module
from tests.fixtures.continuous_process_observation import ChildObservationDiagnostic

NATIVE_CODE = process_module._observe_linux_child.__code__
INNER_CODE = next(
    value
    for value in NATIVE_CODE.co_consts
    if type(value) is CodeType and value.co_name == "require_time"
)
FIRST_FAILURE_KEYS = {"call", "category", "requested_timeout_seconds", "elapsed_ns"}
STATUS = (
    b"Name:\tfixture\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\n"
    b"VmRSS:\t17 kB\nnonvoluntary_ctxt_switches:\t0\n"
)


class ReaderModel:
    def __init__(self, parser):
        self.parser = parser
        self.now = 0.0
        self.advance_at = None
        self.failure_at = None
        self.failure = None
        self.remaining = STATUS
        self.calls = []
        self.original_calls = []

    def step(self, operation):
        self.calls.append(operation)
        if operation == self.advance_at:
            self.now += 0.1
        if operation == self.failure_at:
            raise self.failure

    def open(self, path, flags):
        assert path == "/proc/1234/status"
        assert flags == os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        self.step("open")
        return 41

    def fstat(self, descriptor):
        assert descriptor == 41
        self.step("fstat")
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o444)

    def read(self, descriptor, maximum):
        assert descriptor == 41 and 0 < maximum <= 16385
        self.step("read")
        result, self.remaining = self.remaining[:maximum], self.remaining[maximum:]
        return result

    def close(self, descriptor):
        assert descriptor == 41
        self.step("close")

    def parse(self, payload, pid):
        self.step("parse")
        return self.parser(payload, pid)

    def observe(self, *args, **kwargs):
        self.original_calls.append((args, kwargs))
        return process_module._observe_child(*args, **kwargs)


@pytest.fixture
def reader(monkeypatch):
    model = ReaderModel(process_module._parse_linux_child_status)
    fake_os = SimpleNamespace(
        O_RDONLY=os.O_RDONLY,
        O_CLOEXEC=os.O_CLOEXEC,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_NONBLOCK=os.O_NONBLOCK,
        open=model.open,
        fstat=model.fstat,
        read=model.read,
        close=model.close,
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("observation must not launch, refetch through ps, or change timers")

    monkeypatch.setattr(process_module, "os", fake_os)
    monkeypatch.setattr(process_module, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        process_module,
        "time",
        SimpleNamespace(monotonic=lambda: model.now, sleep=forbidden),
    )
    monkeypatch.setattr(
        process_module,
        "subprocess",
        SimpleNamespace(TimeoutExpired=subprocess.TimeoutExpired, run=forbidden, Popen=forbidden),
    )
    monkeypatch.setattr(process_module, "_parse_linux_child_status", model.parse)
    return model


def diagnostic(original, *, code=NATIVE_CODE, clock_ns=None):
    if clock_ns is None:
        clock_ns = iter((100, 150)).__next__
    return ChildObservationDiagnostic(original, clock_ns=clock_ns, deadline_code=code)


def first_failure(value, *, offset=None, timeout=0.1, overflow=False):
    summary = value.summary(iteration=2)
    first = summary["first_failure"]
    expected = {
        "call": 1,
        "category": "TimeoutExpired",
        "requested_timeout_seconds": timeout,
        "elapsed_ns": 50,
    }
    if offset is not None:
        expected["deadline_check_line_offset"] = offset
    assert first == expected
    assert set(first) == FIRST_FAILURE_KEYS | (
        {"deadline_check_line_offset"} if offset is not None else set()
    )
    assert summary["call_count"] == 1 and summary["counts"]["TimeoutExpired"] == 1
    assert sum(summary["counts"].values()) == 1
    assert summary["overflow"] is overflow
    return summary


@pytest.mark.parametrize(
    "operation,timeout,offset",
    [(None, 0.0, 15), ("open", 0.1, 21), ("fstat", 0.1, 26), ("read", 0.1, 28), ("close", 0.1, 43)],
    ids=["entry", "after-open", "before-read", "after-read", "after-close"],
)
def test_original_native_deadline_sites_are_reported_after_required_cleanup(
    reader, operation, timeout, offset
):
    reader.advance_at = operation
    value = diagnostic(reader.observe)
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=timeout)
    first_failure(value, offset=offset, timeout=timeout)
    assert reader.original_calls == [((1234,), {"timeout": timeout})]
    assert reader.calls == [] if operation is None else reader.calls[-1] == "close"
    assert reader.calls.count("open") == (operation is not None)
    assert reader.calls.count("close") == (operation is not None)


def test_original_parser_overrun_qualifies_only_the_final_post_close_check(reader):
    reader.advance_at = "parse"
    value = diagnostic(reader.observe)
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    first_failure(value, offset=43)
    assert reader.calls[-2:] == ["parse", "close"]
    assert reader.calls.count("open") == 1 and reader.calls.count("close") == 1


def test_success_keeps_original_result_and_exact_legacy_summary_shape(reader):
    observed = []

    def original(*args, **kwargs):
        result = reader.observe(*args, **kwargs)
        observed.append(result)
        return result

    value = diagnostic(original)
    assert value.observe(1234, timeout=0.1) is observed[0]
    assert observed[0] == process_module._ChildObservation(False, 17 * 1024)
    summary = value.summary(iteration=1)
    assert set(summary) == {"iteration", "call_count", "counts", "overflow", "first_failure"}
    assert summary["first_failure"] is None and summary["counts"]["returned"] == 1
    assert not summary["overflow"]
    assert reader.original_calls == [((1234,), {"timeout": 0.1})]
    assert reader.calls == ["open", "fstat", "read", "read", "parse", "close"]


def test_attribution_uses_original_traceback_lineno_after_finally_moved_the_frame(reader):
    reader.advance_at = "read"
    value = diagnostic(reader.observe)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        value.observe(1234, timeout=0.1)
    trace = caught.value.__traceback__
    while trace is not None and trace.tb_frame.f_code is not NATIVE_CODE:
        trace = trace.tb_next
    assert trace is not None
    assert trace.tb_lineno - NATIVE_CODE.co_firstlineno == 28
    assert trace.tb_frame.f_lineno != trace.tb_lineno
    first_failure(value, offset=28)
    assert reader.calls[-1] == "close"


def test_traceback_admission_occurs_after_the_original_ending_clock_sample(reader):
    reader.advance_at = "read"
    errors = []
    samples = []

    def original(*args, **kwargs):
        try:
            return reader.observe(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            errors.append(weakref.ref(error))
            raise

    def clock_ns():
        samples.append(len(samples))
        if len(samples) == 2:
            # Removing only the traceback in this adverse fixture makes early
            # scanning observable: admission must see no pair after this sample.
            errors[0]().__traceback__ = None
        return 100 if len(samples) == 1 else 150

    value = diagnostic(original, clock_ns=clock_ns)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        value.observe(1234, timeout=0.1)
    assert caught.value is errors[0]()
    first_failure(value)
    assert samples == [0, 1] and reader.calls[-1] == "close"


def foreign_reader(*args, **kwargs):
    def require_time():
        raise subprocess.TimeoutExpired("foreign observation", kwargs["timeout"])

    require_time()


@pytest.mark.parametrize("origin", ["syscall", "same-name-foreign-code"])
def test_foreign_native_timeout_is_not_misattributed_to_the_known_check(reader, origin):
    error = subprocess.TimeoutExpired("foreign read", 0.1)
    if origin == "syscall":
        reader.failure_at, reader.failure = "read", error
        original = reader.observe
    else:
        original = foreign_reader
    value = diagnostic(original)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        value.observe(1234, timeout=0.1)
    if origin == "syscall":
        assert caught.value is error and reader.calls[-1] == "close"
    first_failure(value)


@pytest.mark.parametrize("code", [None, foreign_reader.__code__], ids=["unbound", "other-code"])
def test_no_known_adjacent_pair_keeps_the_exact_original_unqualified_shape(reader, code):
    reader.advance_at = "read"
    value = diagnostic(reader.observe, code=code)
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    first_failure(value)


def test_timeout_subclass_is_not_qualified_even_with_the_known_native_frame_pair(
    reader, monkeypatch
):
    class SpecializedTimeout(subprocess.TimeoutExpired):
        pass

    monkeypatch.setattr(process_module.subprocess, "TimeoutExpired", SpecializedTimeout)
    reader.advance_at = "read"
    value = diagnostic(reader.observe)
    with pytest.raises(SpecializedTimeout):
        value.observe(1234, timeout=0.1)
    first_failure(value)


def tunneled_observation(extra, *args, **kwargs):
    if extra:
        return tunneled_observation(extra - 1, *args, **kwargs)
    return process_module._observe_linux_child(*args, **kwargs)


@pytest.mark.parametrize(
    "extra,overflow", [(4, False), (5, True)], ids=["eight-frames", "nine-frames"]
)
def test_traceback_depth_bound_does_not_qualify_a_pair_beyond_the_capture_cap(
    reader, extra, overflow
):
    # diagnostic + original + extra tunnel frames + reader + require_time
    # gives extra+4 frames. Passing extra-1 creates exactly extra tunnel frames.
    def original(*args, **kwargs):
        return tunneled_observation(extra - 1, *args, **kwargs)

    value = diagnostic(original)
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.0)
    first_failure(value, offset=None if overflow else 15, timeout=0.0, overflow=overflow)
    assert reader.calls == []


def rewritten_traceback(error, *, pairs=1, offset=28, tail_frames=0):
    trace = error.__traceback__
    while trace is not None and trace.tb_frame.f_code is not NATIVE_CODE:
        trace = trace.tb_next
    assert trace is not None and trace.tb_next is not None
    inner = trace.tb_next
    assert inner.tb_frame.f_code is INNER_CODE
    result = None
    for _ in range(tail_frames):
        result = TracebackType(result, inner.tb_frame, inner.tb_lasti, inner.tb_lineno)
    for _ in range(pairs):
        result = TracebackType(result, inner.tb_frame, inner.tb_lasti, inner.tb_lineno)
        result = TracebackType(
            result, trace.tb_frame, trace.tb_lasti, NATIVE_CODE.co_firstlineno + offset
        )
    return result


def rewriting_observer(reader, **changes):
    def original(*args, **kwargs):
        try:
            return reader.observe(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            error.__traceback__ = rewritten_traceback(error, **changes)
            raise

    return original


def test_duplicate_known_pairs_are_ambiguous_instead_of_selecting_one(reader):
    reader.advance_at = "read"
    value = diagnostic(rewriting_observer(reader, pairs=2))
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    first_failure(value, overflow=True)


def test_early_known_pair_does_not_hide_a_traceback_that_exceeds_the_cap(reader):
    reader.advance_at = "read"
    value = diagnostic(rewriting_observer(reader, tail_frames=9))
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    first_failure(value, overflow=True)


@pytest.mark.parametrize("offset", [-1, 0, 4095, 4096])
def test_only_native_bounded_line_offsets_are_emitted(reader, offset):
    reader.advance_at = "read"
    value = diagnostic(rewriting_observer(reader, offset=offset))
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    allowed = 0 <= offset <= 4095
    first_failure(value, offset=offset if allowed else None, overflow=not allowed)


@pytest.mark.parametrize(
    "kind", ["wrong-type", "missing-inner", "duplicate-inner", "at-cap", "over-cap"]
)
def test_invalid_binding_cannot_change_original_calls_or_exception_identity(reader, kind):
    constants = (INNER_CODE,)
    if kind == "wrong-type":
        code = process_module._observe_linux_child
    elif kind == "missing-inner":
        code = NATIVE_CODE.replace(co_consts=(None,))
    elif kind == "duplicate-inner":
        code = NATIVE_CODE.replace(co_consts=(INNER_CODE, INNER_CODE))
    else:
        count = 32 if kind == "at-cap" else 33
        code = NATIVE_CODE.replace(co_consts=constants + (None,) * (count - 1))
    error = subprocess.TimeoutExpired("foreign read", 0.1)
    reader.failure_at, reader.failure = "read", error
    value = diagnostic(reader.observe, code=code)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        value.observe(1234, timeout=0.1)
    assert caught.value is error
    first_failure(value, overflow=kind != "at-cap")
    assert reader.original_calls == [((1234,), {"timeout": 0.1})]
    assert reader.calls[-1] == "close"


@pytest.mark.parametrize("stage", ["binding", "partial-binding", "scanner"])
def test_metadata_fault_cannot_replace_the_native_error_cause_or_context(
    reader, monkeypatch, stage
):
    metadata_error = RuntimeError("metadata operation failed")
    cause, context = LookupError("original cause"), IndexError("original context")
    observed = []
    reader.advance_at = "read"

    def original(*args, **kwargs):
        try:
            return reader.observe(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            error.__cause__, error.__context__ = cause, context
            observed.append(error)
            raise

    original_binding = ChildObservationDiagnostic._bind_deadline_code

    def faulty(*args, **kwargs):
        if stage == "partial-binding":
            original_binding(*args, **kwargs)
        raise metadata_error

    if stage in ("binding", "partial-binding"):
        monkeypatch.setattr(ChildObservationDiagnostic, "_bind_deadline_code", faulty)
    value = diagnostic(original)
    if stage == "scanner":
        monkeypatch.setattr(value, "_timeout_check_offset", faulty)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        value.observe(1234, timeout=0.1)
    assert caught.value is observed[0]
    assert caught.value.__cause__ is cause and caught.value.__context__ is context
    first_failure(value, overflow=True)
    assert reader.calls[-1] == "close"


@pytest.mark.parametrize("first_known", [False, True], ids=["first-foreign", "first-qualified"])
def test_first_failure_metadata_stays_fixed_through_later_failure_and_return(reader, first_known):
    clock_ns = iter((0, 50, 100, 150, 200, 250)).__next__
    value = diagnostic(reader.observe, clock_ns=clock_ns)
    if first_known:
        reader.advance_at = "read"
    else:
        reader.failure_at, reader.failure = "read", subprocess.TimeoutExpired("foreign", 0.1)
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    before = value.summary(iteration=1)["first_failure"]
    assert ("deadline_check_line_offset" in before) is first_known
    reader.failure_at, reader.failure, reader.advance_at = None, None, "open"
    reader.remaining = STATUS
    with pytest.raises(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    reader.advance_at, reader.remaining = None, STATUS
    assert value.observe(1234, timeout=0.1) == process_module._ChildObservation(False, 17 * 1024)
    summary = value.summary(iteration=1)
    assert summary["first_failure"] == before
    assert summary["call_count"] == 3
    assert summary["counts"]["TimeoutExpired"] == 2 and summary["counts"]["returned"] == 1
    assert not summary["overflow"]


def test_qualified_metadata_does_not_retain_private_values_error_cause_context_or_frames(reader):
    references = []
    reader.advance_at = "read"

    class Private:
        def __str__(self):
            raise AssertionError("private value converted")

        def __repr__(self):
            raise AssertionError("private value represented")

    class PrivateFailure(RuntimeError):
        pass

    def original(*args, **kwargs):
        private = Private()
        cause, context = PrivateFailure(private), PrivateFailure(private)
        references.extend((weakref.ref(private), weakref.ref(cause), weakref.ref(context)))
        try:
            return reader.observe(*args, **kwargs)
        except subprocess.TimeoutExpired as error:
            error.cmd, error.output, error.stderr = private, private, private
            error.__cause__, error.__context__ = cause, context
            references.append(weakref.ref(error))
            raise

    value = diagnostic(original)
    with suppress(subprocess.TimeoutExpired):
        value.observe(1234, timeout=0.1)
    summary = first_failure(value, offset=28)
    encoded = json.dumps(summary, allow_nan=False)
    assert "1234" not in encoded and "private" not in encoded and "/proc" not in encoded
    assert len(encoded) < 1024
    # CPython releases this original error and its payload immediately once the
    # handler exits. Waiting for cyclic GC would hide observer-frame retention.
    assert len(references) == 4 and all(reference() is None for reference in references)
    gc.collect()
    assert all(reference() is None for reference in references)
    # The diagnostic and its original callable remain strongly held above.
    assert value.summary(iteration=2) == summary
