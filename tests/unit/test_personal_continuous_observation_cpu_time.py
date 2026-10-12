"""Finite native-clock fault models; custom public clock markers remain inadmissible.

The private stored native pointer is replaced only after constructor admission. These
models qualify metadata isolation, not arbitrary callback effects or timing fit.
"""

import json
import subprocess
import weakref
from contextlib import suppress

import pytest

from tests.fixtures import continuous_process_observation as module
from tests.fixtures.continuous_process_observation import ChildObservationDiagnostic
from tests.unit import test_continuous_observation_timeout_site as timeout_fixture

reader = timeout_fixture.reader


class LiteralPrecedingDiagnostic:
    """Independent preceding observe/record/summary with no optional code binding."""

    def __init__(self, original, clock_ns):
        self.original = original
        self.clock_ns = clock_ns
        self.calls = 0
        self.counts = dict.fromkeys(
            ("returned", "TimeoutExpired", "ValueError", "OSError", "SubprocessError", "other"), 0
        )
        self.overflow = False
        self.first = None

    def observe(self, *args, **kwargs):
        started = self.clock_ns()
        category = "returned"
        try:
            return self.original(*args, **kwargs)
        except subprocess.TimeoutExpired:
            category = "TimeoutExpired"
            raise
        except ValueError:
            category = "ValueError"
            raise
        except OSError:
            category = "OSError"
            raise
        except subprocess.SubprocessError:
            category = "SubprocessError"
            raise
        except BaseException:
            category = "other"
            raise
        finally:
            elapsed = self.clock_ns() - started
            if self.calls == 4096 or self.counts[category] == 4096:
                self.overflow = True
            self.calls = min(4096, self.calls + 1)
            self.counts[category] = min(4096, self.counts[category] + 1)
            if category != "returned" and self.first is None:
                timeout = kwargs.get("timeout", 0.1)
                assert type(timeout) is float and timeout == 0.1
                self.first = (self.calls, category, timeout, min(10**15, max(0, elapsed)))

    def summary(self, *, iteration):
        first = self.first
        return {
            "iteration": iteration,
            "call_count": self.calls,
            "counts": dict(self.counts),
            "overflow": self.overflow,
            "first_failure": None
            if first is None
            else {
                "call": first[0],
                "category": first[1],
                "requested_timeout_seconds": first[2],
                "elapsed_ns": first[3],
            },
        }


def selected_error():
    primary = ValueError("original observation failed")
    cause, context = LookupError("original cause"), IndexError("original context")
    primary.__cause__, primary.__context__ = cause, context
    primary.__suppress_context__ = False
    return primary, cause, context


def native_model(monkeypatch, original, wall, sample, *, deadline_code=None):
    # Admission uses the genuine native identity. Changing its private stored pointer
    # afterward is a finite fault seam, not support for public custom clocks.
    diagnostic = ChildObservationDiagnostic(
        original,
        clock_ns=wall,
        deadline_code=deadline_code,
        thread_clock_ns=module._native_thread_time_ns,
    )
    monkeypatch.setattr(diagnostic, "_thread_cpu_clock", sample)
    return diagnostic


@pytest.mark.parametrize("mode", ["omitted", "none"])
@pytest.mark.parametrize("raises", [False, True])
def test_default_and_none_match_literal_preceding_behavior_without_cpu_reads(
    monkeypatch, mode, raises
):
    result = object()

    def exercise(diagnostic_type):
        events = []
        primary, cause, context = selected_error()
        samples = iter((100, 150))

        def wall():
            value = next(samples)
            events.append(("wall", value))
            return value

        def original(*args, **kwargs):
            events.append(("original", args, kwargs))
            if raises:
                raise primary
            return result

        kwargs = {"thread_clock_ns": None} if mode == "none" else {}
        diagnostic = (
            LiteralPrecedingDiagnostic(original, wall)
            if diagnostic_type is LiteralPrecedingDiagnostic
            else diagnostic_type(original, clock_ns=wall, **kwargs)
        )
        if raises:
            with pytest.raises(ValueError) as caught:
                diagnostic.observe(1234, timeout=0.1)
            assert caught.value is primary
            assert primary.__cause__ is cause and primary.__context__ is context
            assert primary.__suppress_context__ is False
        else:
            assert diagnostic.observe(1234, timeout=0.1) is result
        return events, diagnostic.summary(iteration=1)

    def forbidden():
        raise AssertionError("disabled CPU clock was read")

    monkeypatch.setattr(module, "_native_thread_time_ns", forbidden)
    baseline = exercise(LiteralPrecedingDiagnostic)
    candidate = exercise(ChildObservationDiagnostic)
    assert candidate == baseline
    assert candidate[0] == [
        ("wall", 100),
        ("original", (1234,), {"timeout": 0.1}),
        ("wall", 150),
    ]
    assert "thread_cpu_elapsed_ns" not in json.dumps(candidate[1])


@pytest.mark.parametrize("raises", [False, True])
def test_native_samples_surround_unchanged_wall_samples_and_one_original_call(monkeypatch, raises):
    events = []
    cpu_values, wall_values = iter((10, 45)), iter((100, 150))
    result = object()
    primary, cause, context = selected_error()

    def cpu():
        value = next(cpu_values)
        events.append(("cpu", value))
        return value

    def wall():
        value = next(wall_values)
        events.append(("wall", value))
        return value

    def original(*args, **kwargs):
        events.append(("original", args, kwargs))
        if raises:
            raise primary
        return result

    diagnostic = native_model(monkeypatch, original, wall, cpu)
    if raises:
        with pytest.raises(ValueError) as caught:
            diagnostic.observe(1234, timeout=0.1)
        assert caught.value is primary
        assert primary.__cause__ is cause and primary.__context__ is context
    else:
        assert diagnostic.observe(1234, timeout=0.1) is result
    assert events == [
        ("cpu", 10),
        ("wall", 100),
        ("original", (1234,), {"timeout": 0.1}),
        ("wall", 150),
        ("cpu", 45),
    ]
    summary = diagnostic.summary(iteration=1)
    assert summary["overflow"] is False
    if raises:
        assert summary["first_failure"] == {
            "call": 1,
            "category": "ValueError",
            "requested_timeout_seconds": 0.1,
            "elapsed_ns": 50,
            "thread_cpu_elapsed_ns": 35,
        }
    else:
        assert summary["first_failure"] is None


@pytest.mark.parametrize(
    "start,end,expected",
    [(0, 0, 0), (7, 8, 1), (0, 10**15, 10**15), ((1 << 63) - 2, (1 << 63) - 1, 1)],
)
def test_native_delta_includes_zero_and_the_existing_elapsed_cap(monkeypatch, start, end, expected):
    samples = iter((start, end))
    wall = iter((100, 150))
    primary, _, _ = selected_error()

    def original():
        raise primary

    diagnostic = native_model(monkeypatch, original, lambda: next(wall), lambda: next(samples))
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    summary = diagnostic.summary(iteration=1)
    assert summary["first_failure"]["thread_cpu_elapsed_ns"] == expected
    assert summary["overflow"] is False


class HookValue:
    def __call__(self):
        raise AssertionError("foreign clock invoked")

    def __eq__(self, other):
        raise AssertionError("foreign value compared")

    def __bool__(self):
        raise AssertionError("foreign value truth-tested")

    def __int__(self):
        raise AssertionError("foreign value converted")

    def __index__(self):
        raise AssertionError("foreign value indexed")

    def __repr__(self):
        raise AssertionError("foreign value represented")


class IntSubclass(int):
    pass


@pytest.mark.parametrize(
    "start,end",
    [
        (None, 1),
        (True, 1),
        (0, False),
        (1.0, 2),
        (0, "2"),
        (IntSubclass(1), 2),
        (-1, 2),
        (2, -1),
        (3, 2),
        (0, 10**15 + 1),
        ((1 << 63), (1 << 63)),
    ],
)
def test_invalid_native_samples_remain_unavailable_and_do_not_change_original_error(
    monkeypatch, start, end
):
    samples = iter((start, end))
    wall = iter((100, 150))
    primary, cause, context = selected_error()

    def original():
        raise primary

    diagnostic = native_model(monkeypatch, original, lambda: next(wall), lambda: next(samples))
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    summary = diagnostic.summary(iteration=1)
    assert summary["overflow"] is True
    assert summary["first_failure"]["elapsed_ns"] == 50
    assert summary["first_failure"]["thread_cpu_elapsed_ns"] is None


@pytest.mark.parametrize("stage", ["start", "end"])
def test_invalid_native_hook_value_is_not_inspected_or_retained(monkeypatch, stage):
    references = []
    calls = []
    wall = iter((100, 150))
    primary, _, _ = selected_error()

    def cpu():
        calls.append(None)
        if len(calls) == (1 if stage == "start" else 2):
            value = HookValue()
            references.append(weakref.ref(value))
            return value
        return 1

    def original():
        raise primary

    diagnostic = native_model(monkeypatch, original, lambda: next(wall), cpu)
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert len(references) == 1 and references[0]() is None
    assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] is None


def test_foreign_public_clock_marker_is_never_invoked_or_retained():
    marker = HookValue()
    reference = weakref.ref(marker)
    wall = iter((100, 150))
    primary, cause, context = selected_error()

    def original():
        raise primary

    diagnostic = ChildObservationDiagnostic(
        original, clock_ns=lambda: next(wall), thread_clock_ns=marker
    )
    del marker
    assert reference() is None
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    summary = diagnostic.summary(iteration=1)
    assert summary["overflow"] is True
    assert summary["first_failure"]["thread_cpu_elapsed_ns"] is None


@pytest.mark.parametrize("raises", [False, True])
def test_delegate_cannot_rebind_the_admitted_sampling_pointer_to_a_foreign_global(
    monkeypatch, raises
):
    samples = iter((10, 45))
    wall_values = iter((100, 150))
    calls = []
    foreign = HookValue()
    result = object()
    primary, cause, context = selected_error()

    def cpu():
        calls.append("cpu")
        return next(samples)

    def original():
        calls.append("original")
        monkeypatch.setattr(module, "_native_thread_time_ns", foreign)
        if raises:
            raise primary
        return result

    diagnostic = native_model(monkeypatch, original, lambda: next(wall_values), cpu)
    if raises:
        with pytest.raises(ValueError) as caught:
            diagnostic.observe()
        assert caught.value is primary
        assert primary.__cause__ is cause and primary.__context__ is context
        assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] == 35
    else:
        assert diagnostic.observe() is result
    assert calls == ["cpu", "original", "cpu"]
    assert diagnostic.summary(iteration=1)["overflow"] is False


@pytest.mark.parametrize("stage", ["start", "end"])
@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_native_clock_fault_preserves_original_return_or_error(monkeypatch, stage, raises, kind):
    metadata = kind("retained native clock fault")
    primary, cause, context = selected_error()
    result = object()
    cpu_calls, original_calls, wall_calls = [], [], []

    def cpu():
        cpu_calls.append(None)
        if len(cpu_calls) == (1 if stage == "start" else 2):
            raise metadata
        return 1

    def wall():
        wall_calls.append(None)
        return 100 if len(wall_calls) == 1 else 150

    def original(*args, **kwargs):
        original_calls.append((args, kwargs))
        if raises:
            raise primary
        return result

    diagnostic = native_model(monkeypatch, original, wall, cpu)
    if raises:
        with pytest.raises(ValueError) as caught:
            diagnostic.observe(1234, timeout=0.1)
        assert caught.value is primary
        assert primary.__cause__ is cause and primary.__context__ is context
        assert primary.__suppress_context__ is False
        assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] is None
    else:
        assert diagnostic.observe(1234, timeout=0.1) is result
    assert original_calls == [((1234,), {"timeout": 0.1})]
    assert len(wall_calls) == 2
    assert metadata.__traceback__ is None
    assert metadata.__context__ is None
    assert diagnostic.summary(iteration=1)["overflow"] is True


def test_same_primary_native_fault_restores_exact_traceback_cause_context_and_suppression(
    monkeypatch,
):
    primary, cause, context = selected_error()
    cpu_calls, wall_calls, entries = [], [], []

    def cpu():
        cpu_calls.append(None)
        if len(cpu_calls) == 2:
            raise primary
        return 1

    def wall():
        wall_calls.append(None)
        if len(wall_calls) == 2:
            entries.append(BaseException.__traceback__.__get__(primary))
        return 100 if len(wall_calls) == 1 else 150

    def original():
        raise primary

    diagnostic = native_model(monkeypatch, original, wall, cpu)
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert len(entries) == 1 and entries[0] is not None
    assert BaseException.__traceback__.__get__(primary).tb_next is entries[0]
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False
    assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] is None


@pytest.mark.parametrize("stage", ["start", "end"])
def test_same_outer_pending_error_keeps_exact_entry_state_while_original_returns(
    monkeypatch, stage
):
    primary, cause, context = selected_error()
    calls = []
    wall_values = iter((100, 150))
    result = object()

    def cpu():
        calls.append(None)
        if len(calls) == (1 if stage == "start" else 2):
            raise primary
        return 1

    diagnostic = native_model(monkeypatch, lambda: result, lambda: next(wall_values), cpu)
    with pytest.raises(ValueError) as caught:
        try:
            raise primary
        except ValueError:
            entry = BaseException.__traceback__.__get__(primary)
            assert diagnostic.observe() is result
            assert BaseException.__traceback__.__get__(primary) is entry
            assert primary.__cause__ is cause and primary.__context__ is context
            assert primary.__suppress_context__ is False
            raise
    assert caught.value is primary
    assert diagnostic.summary(iteration=1)["first_failure"] is None
    assert diagnostic.summary(iteration=1)["overflow"] is True


@pytest.mark.parametrize("cause_kind", ["primary", "foreign"])
@pytest.mark.parametrize("suppressed", [False, True])
def test_auxiliary_cleanup_detaches_only_direct_primary_edges_and_preserves_suppression(
    monkeypatch, cause_kind, suppressed
):
    primary, cause, context = selected_error()
    metadata = RuntimeError("retained auxiliary")
    foreign = LookupError("independently owned foreign cause")
    calls = []
    wall_values = iter((100, 150))

    def cpu():
        calls.append(None)
        if len(calls) == 2:
            metadata.__cause__ = primary if cause_kind == "primary" else foreign
            metadata.__suppress_context__ = suppressed
            raise metadata
        return 1

    def original():
        raise primary

    diagnostic = native_model(monkeypatch, original, lambda: next(wall_values), cpu)
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False
    assert metadata.__traceback__ is metadata.__context__ is None
    assert metadata.__cause__ is (None if cause_kind == "primary" else foreign)
    assert metadata.__suppress_context__ is suppressed


def test_retained_auxiliary_native_fault_does_not_keep_private_primary_payload(monkeypatch):
    def exercise(enabled):
        metadata = RuntimeError("externally retained native clock error")
        references, wall_calls, cpu_calls = [], [], []

        class Private:
            pass

        class PrivateCause(RuntimeError):
            pass

        class PrivateContext(LookupError):
            pass

        def original():
            private = Private()
            cause, context = PrivateCause(private), PrivateContext(private)
            try:
                raise subprocess.TimeoutExpired(private, 0.1, output=private, stderr=private)
            except subprocess.TimeoutExpired as primary:
                primary.__cause__, primary.__context__ = cause, context
                references.extend(
                    weakref.ref(value) for value in (private, primary, cause, context)
                )
                raise
            finally:
                private = cause = context = None

        def cpu():
            cpu_calls.append(None)
            if len(cpu_calls) == 2:
                raise metadata
            return 1

        def wall():
            wall_calls.append(None)
            return 100 if len(wall_calls) == 1 else 150

        if enabled:
            diagnostic = native_model(monkeypatch, original, wall, cpu)
        else:
            diagnostic = LiteralPrecedingDiagnostic(original, wall)
        with suppress(subprocess.TimeoutExpired):
            diagnostic.observe()
        assert len(references) == 4
        return diagnostic, metadata, tuple(reference() is None for reference in references)

    baseline_diagnostic, baseline_error, baseline_released = exercise(False)
    diagnostic, metadata, released = exercise(True)
    assert baseline_released == released == (True, True, True, True)
    assert baseline_error.__traceback__ is baseline_error.__context__ is None
    assert metadata.__traceback__ is metadata.__context__ is None
    assert baseline_diagnostic.summary(iteration=1)["first_failure"]["category"] == "TimeoutExpired"
    assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] is None
    # Both diagnostics and auxiliary errors remain held; no manual context
    # clearing or cyclic GC hides a newly introduced primary retention edge.


def test_auxiliary_cleanup_preserves_an_independently_owned_foreign_context(monkeypatch):
    primary, cause, context = selected_error()
    metadata = RuntimeError("retained auxiliary")
    foreign = LookupError("independently owned foreign context")
    cpu_calls, original_calls = [], []
    wall_values = iter((100, 150))

    def cpu():
        cpu_calls.append(None)
        if len(cpu_calls) == 2:
            try:
                raise metadata
            finally:
                # Finite native-fault model: set the direct edge before the
                # sampler handles it. No edge is manually cleared afterward.
                metadata.__context__ = foreign
        return 1

    def original():
        original_calls.append(None)
        raise primary

    diagnostic = native_model(monkeypatch, original, lambda: next(wall_values), cpu)
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is False
    assert metadata.__traceback__ is None
    assert metadata.__context__ is foreign and metadata.__cause__ is None
    assert metadata.__suppress_context__ is False
    assert foreign.__traceback__ is foreign.__context__ is None
    assert len(cpu_calls) == 2 and original_calls == [None]
    assert diagnostic.summary(iteration=1)["first_failure"]["thread_cpu_elapsed_ns"] is None


def test_first_failure_cpu_value_stays_fixed_after_later_failure_and_success(monkeypatch):
    wall_values = iter((0, 50, 100, 150, 200, 250))
    cpu_values = iter((10, 45, 100, 105, 200, 207))
    original_calls = []
    first = ValueError("first original failure")
    later = OSError("later cleanup failure")
    result = object()

    def original():
        original_calls.append(None)
        if len(original_calls) == 1:
            raise first
        if len(original_calls) == 2:
            raise later
        return result

    diagnostic = native_model(
        monkeypatch, original, lambda: next(wall_values), lambda: next(cpu_values)
    )
    with pytest.raises(ValueError) as caught:
        diagnostic.observe()
    assert caught.value is first
    saved = diagnostic.summary(iteration=1)["first_failure"]
    with pytest.raises(OSError) as caught:
        diagnostic.observe()
    assert caught.value is later
    assert diagnostic.observe() is result
    summary = diagnostic.summary(iteration=1)
    assert len(original_calls) == summary["call_count"] == 3
    assert summary["counts"]["ValueError"] == summary["counts"]["OSError"] == 1
    assert summary["counts"]["returned"] == 1
    assert summary["first_failure"] == saved
    assert saved["thread_cpu_elapsed_ns"] == 35


@pytest.mark.parametrize("clock_fault", [False, True])
def test_cpu_metadata_preserves_original_native_deadline_and_descriptor_cleanup(
    monkeypatch, reader, clock_fault
):
    reader.advance_at = "open"
    wall_values = iter((100, 150))
    calls = []
    metadata = RuntimeError("native CPU sample failed")

    def cpu():
        calls.append(None)
        if len(calls) == 2 and clock_fault:
            raise metadata
        return 10 if len(calls) == 1 else 45

    diagnostic = native_model(
        monkeypatch,
        reader.observe,
        lambda: next(wall_values),
        cpu,
        deadline_code=timeout_fixture.NATIVE_CODE,
    )
    with pytest.raises(subprocess.TimeoutExpired):
        diagnostic.observe(1234, timeout=0.1)
    assert reader.original_calls == [((1234,), {"timeout": 0.1})]
    assert reader.calls == ["open", "close"]
    summary = diagnostic.summary(iteration=1)
    assert summary["first_failure"] == {
        "call": 1,
        "category": "TimeoutExpired",
        "requested_timeout_seconds": 0.1,
        "elapsed_ns": 50,
        "deadline_check_line_offset": 21,
        "thread_cpu_elapsed_ns": None if clock_fault else 35,
    }
    assert summary["overflow"] is clock_fault
    assert metadata.__traceback__ is metadata.__context__ is None


def test_full_width_cpu_failure_summary_fits_existing_whole_output_line(monkeypatch):
    wall_values, cpu_values = iter((0, 10**15)), iter((0, 10**15))
    primary = subprocess.SubprocessError("original failure")

    def original(pid, *, timeout):
        assert (pid, timeout) == (1234, 120.0)
        raise primary

    diagnostic = native_model(
        monkeypatch, original, lambda: next(wall_values), lambda: next(cpu_values)
    )
    diagnostic._calls = 4095
    diagnostic._counts["SubprocessError"] = 4095
    with pytest.raises(subprocess.SubprocessError) as caught:
        diagnostic.observe(1234, timeout=120.0)
    assert caught.value is primary
    summary = diagnostic.summary(iteration=2)
    assert summary["call_count"] == summary["counts"]["SubprocessError"] == 4096
    assert summary["first_failure"]["elapsed_ns"] == 10**15
    assert summary["first_failure"]["thread_cpu_elapsed_ns"] == 10**15
    line = "AQT_CHILD_OBSERVATION_DIAGNOSTIC " + json.dumps(summary, sort_keys=True) + "\n"
    assert line.isascii() and len(line.encode("ascii")) <= 4096
    assert "original failure" not in line and "1234" not in line
