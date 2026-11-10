"""Observation metadata cannot change the original worker call or expose its inputs."""

import gc
import json
import subprocess
import weakref
from contextlib import suppress

import pytest

from tests.fixtures import continuous_process_observation as diagnostic_module
from tests.fixtures.continuous_process_observation import ChildObservationDiagnostic


def clock(*values):
    return iter(values).__next__


@pytest.mark.parametrize("kwargs", [{}, {"timeout": 0.1}, {"timeout": 0.0}])
def test_one_original_call_with_identical_arguments_and_return_identity(kwargs):
    calls = []
    pid = object()
    result = object()

    def original(*args, **forwarded):
        calls.append((args, forwarded))
        return result

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(100, 150))
    assert diagnostic.observe(pid, **kwargs) is result
    assert calls == [((pid,), kwargs)]
    summary = diagnostic.summary(iteration=1)
    assert summary["call_count"] == 1
    assert summary["counts"]["returned"] == 1
    assert summary["first_failure"] is None
    assert not summary["overflow"]


@pytest.mark.parametrize(
    "error,category",
    [
        (
            subprocess.TimeoutExpired("private command", 0.1, output=b"private bytes"),
            "TimeoutExpired",
        ),
        (ValueError("private parser output"), "ValueError"),
        (OSError("private path"), "OSError"),
        (
            subprocess.CalledProcessError(7, "private command", output=b"private bytes"),
            "SubprocessError",
        ),
        (RuntimeError("private message"), "other"),
        (KeyboardInterrupt("private interrupt"), "other"),
        (SystemExit("private exit"), "other"),
    ],
)
def test_bare_reraise_preserves_original_exception_cause_and_context(error, category):
    cause = LookupError("private cause")
    context = IndexError("private context")
    error.__cause__ = cause
    error.__context__ = context
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        raise error

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(10, 80))
    with pytest.raises(type(error)) as caught:
        diagnostic.observe(12345, timeout=0.03125)
    assert caught.value is error
    assert error.__cause__ is cause and error.__context__ is context
    assert calls == [((12345,), {"timeout": 0.03125})]
    summary = diagnostic.summary(iteration=2)
    assert summary["first_failure"] == {
        "call": 1,
        "category": category,
        "requested_timeout_seconds": 0.03125,
        "elapsed_ns": 70,
    }
    assert summary["counts"][category] == 1
    encoded = json.dumps(summary, allow_nan=False)
    assert "private" not in encoded and "12345" not in encoded
    assert len(encoded) < 1024


def test_first_failure_survives_later_cleanup_failure_and_success():
    actions = iter((ValueError("main"), subprocess.TimeoutExpired("cleanup", 0.01), None))

    def original(*args, **kwargs):
        action = next(actions)
        if action is not None:
            raise action
        return "success"

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(0, 10, 20, 50, 60, 80))
    with pytest.raises(ValueError):
        diagnostic.observe(1, timeout=0.1)
    first = diagnostic.summary(iteration=1)["first_failure"]
    with pytest.raises(subprocess.TimeoutExpired):
        diagnostic.observe(1, timeout=0.01)
    assert diagnostic.observe(1) == "success"
    summary = diagnostic.summary(iteration=1)
    assert summary["first_failure"] == first
    assert summary["call_count"] == 3
    assert summary["counts"]["ValueError"] == summary["counts"]["TimeoutExpired"] == 1
    assert summary["counts"]["returned"] == 1


def test_new_iteration_resets_all_metadata_and_summary_copies_state():
    def original(*args, **kwargs):
        raise ValueError

    first = ChildObservationDiagnostic(original, clock_ns=clock(0, 10))
    with pytest.raises(ValueError):
        first.observe(1)
    summary = first.summary(iteration=1)
    summary["counts"]["ValueError"] = 99
    summary["first_failure"]["category"] = "replaced"
    assert first.summary(iteration=1)["counts"]["ValueError"] == 1
    assert first.summary(iteration=1)["first_failure"]["category"] == "ValueError"
    second = ChildObservationDiagnostic(original)
    assert second.summary(iteration=2) == {
        "iteration": 2,
        "call_count": 0,
        "counts": dict.fromkeys(diagnostic_module._CATEGORIES, 0),
        "overflow": False,
        "first_failure": None,
    }


def test_saturating_counts_and_elapsed_keep_calling_original(monkeypatch):
    monkeypatch.setattr(diagnostic_module, "_COUNT_CAP", 2)
    monkeypatch.setattr(diagnostic_module, "_ELAPSED_CAP_NS", 5)
    calls = 0

    def original(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise ValueError

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(0, 10, 20, 30, 40, 50))
    for _ in range(3):
        with pytest.raises(ValueError):
            diagnostic.observe(1, timeout=0.1)
    summary = diagnostic.summary(iteration=1)
    assert calls == 3
    assert summary["call_count"] == summary["counts"]["ValueError"] == 2
    assert summary["first_failure"]["elapsed_ns"] == 5
    assert summary["first_failure"]["call"] == 1
    assert summary["overflow"]


def test_unknown_timeout_is_forwarded_without_conversion_or_retention():
    class Private:
        def __str__(self):
            pytest.fail("private input converted")

        def __repr__(self):
            pytest.fail("private input represented")

        def __float__(self):
            pytest.fail("private input converted")

    class Failure(ValueError):
        pass

    observed_error = []

    def original(*args, **kwargs):
        assert type(kwargs["timeout"]) is Private
        error = Failure("private exception")
        observed_error.append(weakref.ref(error))
        raise error

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(0, 10))
    private = Private()
    reference = weakref.ref(private)
    with suppress(Failure):
        diagnostic.observe(private, timeout=private)
    del private
    gc.collect()
    assert reference() is None and observed_error[0]() is None
    summary = diagnostic.summary(iteration=1)
    assert summary["first_failure"]["requested_timeout_seconds"] is None
    assert summary["overflow"]
    assert "private" not in json.dumps(summary, allow_nan=False)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -0.1, 121, True])
def test_nonfinite_or_outside_fixture_timeout_is_redacted_without_affecting_error(timeout):
    error = ValueError("original")

    def original(*args, **kwargs):
        assert kwargs["timeout"] is timeout
        raise error

    diagnostic = ChildObservationDiagnostic(original, clock_ns=clock(0, 10))
    with pytest.raises(ValueError) as caught:
        diagnostic.observe(1, timeout=timeout)
    assert caught.value is error
    summary = diagnostic.summary(iteration=1)
    assert summary["first_failure"]["requested_timeout_seconds"] is None
    assert summary["overflow"]
    json.dumps(summary, allow_nan=False)
