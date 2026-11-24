"""Finite enabled-converter error/lifetime controls for the fixed bounded route."""

import weakref
from pathlib import Path

import pytest

from tests.fixtures import parent_first_observe_profile as module
from tests.unit.test_personal_parent_first_observe_linux_route import _bounded
from tests.unit.test_personal_parent_first_observe_profile_adverse import (
    _Alarm,
    _Box,
    _Delegate,
    _raise,
    _tb_names,
    _WeakError,
)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt, _Alarm])
@pytest.mark.parametrize("ambient", [False, True])
def test_new_bounded_conversion_fault_propagates_without_callback_primary(
    monkeypatch, kind, ambient
):
    error, cause = kind("bounded conversion fault"), LookupError("explicit cause")
    error.__cause__, error.__suppress_context__ = cause, True
    owner, events = _bounded(monkeypatch)
    delegate = _Delegate(events, result="original result")
    wrapped = owner.wrap(delegate, iteration=2)
    monkeypatch.setattr(module, "_bounded_static_report", _raise(error))
    if ambient:
        try:
            raise RuntimeError("ambient is not suppression authority")
        except RuntimeError:
            with pytest.raises(kind) as caught:
                wrapped.observe(child_pid=17, child_exited=False)
    else:
        with pytest.raises(kind) as caught:
            wrapped.observe(child_pid=17, child_exited=False)
    assert caught.value is error and error.__cause__ is cause
    assert error.__suppress_context__ is True and "fault" in _tb_names(error)
    assert sum(type(row) is tuple and row[0] == "callback" for row in events) == 1
    assert events.count("disable") == events.count("getstats") == 1
    assert owner.availability()["available"] is False
    assert owner._profiler is owner._disable is owner._getstats is owner._clear is None


@pytest.mark.parametrize("same_primary", [False, True])
def test_new_bounded_conversion_isolates_only_explicit_original_primary(monkeypatch, same_primary):
    primary = _WeakError("original callback")
    cause, context = LookupError("original cause"), ValueError("original context")
    primary.__cause__, primary.__context__, primary.__suppress_context__ = cause, context, True
    auxiliary = primary if same_primary else RuntimeError("bounded conversion")
    unrelated = LookupError("unrelated auxiliary owner")
    if not same_primary:
        auxiliary.__cause__, auxiliary.__suppress_context__ = unrelated, True
    owner, events = _bounded(monkeypatch)
    wrapped = owner.wrap(_Delegate(events, error=primary), iteration=2)
    monkeypatch.setattr(module, "_bounded_static_report", _raise(auxiliary))
    with pytest.raises(_WeakError) as caught:
        wrapped.observe(child_pid=17, child_exited=False)
    assert caught.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is True and "fault" not in _tb_names(primary)
    assert sum(type(row) is tuple and row[0] == "callback" for row in events) == 1
    assert owner.availability()["available"] is False
    if not same_primary:
        assert auxiliary.__traceback__ is None and auxiliary.__context__ is None
        assert auxiliary.__cause__ is unrelated and auxiliary.__suppress_context__ is True


def test_kept_new_converter_validation_error_releases_raw_payload_without_gc():
    refs, kept = [], []

    def invoke():
        value, stats = None, None
        try:
            value = _Box()
            refs.append(weakref.ref(value))
            stats = [module._NativeEntry((value, 1, 0, 0.0, 0.0, None))]
            module._bounded_static_report(stats, Path(__file__).resolve().parents[2], True)
        finally:
            value = stats = None

    try:
        invoke()
    except ValueError as error:
        kept.append(error)
    assert len(kept) == 1 and kept[0].args == ("PARENT_PROFILE_NATIVE_STATS",)
    assert len(refs) == 1 and refs[0]() is None
    assert kept[0].__traceback__ is not None
