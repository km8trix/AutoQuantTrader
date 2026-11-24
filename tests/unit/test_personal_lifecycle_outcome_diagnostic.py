"""Offline scalar-output/privacy/lifetime controls, not lifecycle acceptance."""

from __future__ import annotations

import gc
import json
import weakref
from contextlib import suppress

import pytest

from tests.fixtures import lifecycle_outcome_diagnostic as diagnostic

_LOADS = json.loads
_DUMPS = json.dumps
_BASE = {
    "fault": "stop",
    "status": "failed",
    "reason": "child_observation_failed",
    "stopped": False,
    "acted": False,
}
_HOOKS = []


def _hook(name):
    _HOOKS.append(name)
    raise RuntimeError("PRIVATE_TOKEN_MUST_NOT_BE_OBSERVED")


class Private:
    def __getattribute__(self, name):
        return _hook("getattribute")

    def __str__(self):
        return _hook("str")

    def __repr__(self):
        return _hook("repr")

    def __eq__(self, other):
        return _hook("eq")

    def __bool__(self):
        return _hook("bool")


class StringSubclass(str):
    def __eq__(self, other):
        return _hook("str_subclass_eq")

    def __str__(self):
        return _hook("str_subclass_str")

    def __repr__(self):
        return _hook("str_subclass_repr")

    __hash__ = str.__hash__


class IntSubclass(int):
    def __eq__(self, other):
        return _hook("int_subclass_eq")

    def __bool__(self):
        return _hook("int_subclass_bool")


class DictSubclass(dict):
    def __getitem__(self, key):
        return _hook("dict_subclass_getitem")


class Capture:
    def __init__(self):
        self.attempts = []
        self.flushes = 0

    def write(self, line):
        self.attempts.append(line)
        return len(line)

    def flush(self):
        self.flushes += 1


def _expected(**changes):
    values = dict(_BASE)
    values.update(changes)
    return {
        "schema_version": 1,
        "sample_scope": "post_return_independent",
        "available": all(value is not None for value in values.values()),
        **values,
    }


def _unknown():
    return _expected(fault=None, status=None, reason=None, stopped=None, acted=None)


def _emit(monkeypatch, values, sink=None):
    target = Capture() if sink is None else sink
    with monkeypatch.context() as patch:
        patch.setitem(diagnostic.sys.__dict__, "stdout", target)
        diagnostic.emit_lifecycle_outcome_failure(**values)
    return target


def _line(sink):
    assert len(sink.attempts) == 1 and sink.flushes == 0
    text = sink.attempts[0]
    assert type(text) is str and text.isascii()
    assert len(text.encode("utf-8")) <= 4096
    assert text.startswith("AQT_PARENT_OUTCOME_DIAGNOSTIC ")
    assert text.endswith("\n") and text.count("\n") == 1
    encoded = text.removeprefix("AQT_PARENT_OUTCOME_DIAGNOSTIC ").removesuffix("\n")
    assert not any(char in encoded for char in " \t\n\r")
    return _LOADS(encoded)


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("fault", "stop"),
        ("fault", "ready_pid"),
        ("fault", "result"),
        ("fault", "early_release"),
        ("fault", "takeover"),
        ("status", "completed"),
        ("status", "failed"),
        ("status", "stopped"),
        ("reason", "child_failed"),
        ("reason", "child_observation_failed"),
        ("reason", "cleanup_incomplete"),
        ("reason", "completed"),
        ("reason", "deadline"),
        ("reason", "lease_lost"),
        ("reason", "lifecycle_incomplete"),
        ("reason", "lifecycle_invalid"),
        ("reason", "lifecycle_required"),
        ("reason", "memory_limit"),
        ("reason", "operation_busy"),
        ("reason", "output_limit"),
        ("reason", "probe_failed"),
        ("reason", "probe_stalled"),
        ("reason", "process_failed"),
        ("reason", "request_invalid"),
        ("reason", "stopped"),
    ],
)
def test_each_original_native_code_is_reported_without_cross_field_inference(
    monkeypatch, field, code
):
    values = {**_BASE, field: code, "stopped": True, "acted": True}
    assert _line(_emit(monkeypatch, values)) == _expected(**{field: code}, stopped=True, acted=True)


@pytest.mark.parametrize("field", ["fault", "status", "reason", "stopped", "acted"])
@pytest.mark.parametrize("kind", ["private", "subclass", "wrong_native", "unknown"])
def test_invalid_input_is_unavailable_without_private_hooks(monkeypatch, field, kind):
    _HOOKS.clear()
    if kind == "private":
        value = Private()
    elif kind == "subclass":
        value = (
            StringSubclass(_BASE[field])
            if field in ("fault", "status", "reason")
            else IntSubclass(1)
        )
    elif kind == "wrong_native":
        value = 1
    else:
        value = "PRIVATE_PATH_/account/秘密\n" if field in ("fault", "status", "reason") else None
    values = {**_BASE, field: value}
    sink = _emit(monkeypatch, values)
    assert _HOOKS == []
    assert _line(sink) == _expected(**{field: None})
    assert "PRIVATE" not in sink.attempts[0]


def test_all_unavailable_and_native_false_flags_remain_distinct(monkeypatch):
    assert _line(_emit(monkeypatch, {key: None for key in _BASE})) == _unknown()
    assert _line(_emit(monkeypatch, dict(_BASE))) == _expected()


@pytest.mark.parametrize("stage", ["dumps", "loads"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_new_serializer_fault_uses_only_the_constant_unknown_line(monkeypatch, stage, kind):
    error = kind("PRIVATE_SERIALIZER_MESSAGE")

    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(diagnostic.json, stage, fail)
    sink = _emit(monkeypatch, dict(_BASE))
    assert _line(sink) == _unknown()
    assert "PRIVATE" not in sink.attempts[0]


@pytest.mark.parametrize(
    "kind", ["oversize", "unicode", "subclass", "nonstring", "spaces", "newline"]
)
def test_serialized_text_is_bounded_before_any_decoder_call(monkeypatch, kind):
    _HOOKS.clear()
    text = {
        "oversize": "x" * 4096,
        "unicode": "é",
        "subclass": StringSubclass("{}"),
        "nonstring": Private(),
        "spaces": _DUMPS(_expected()),
        "newline": _DUMPS(_expected(), separators=(",", ":")) + "\n",
    }[kind]
    calls = []
    monkeypatch.setattr(diagnostic.json, "dumps", lambda *_a, **_kw: text)

    def decode(value, **kwargs):
        calls.append(value)
        return _LOADS(value, **kwargs)

    monkeypatch.setattr(diagnostic.json, "loads", decode)
    assert _line(_emit(monkeypatch, dict(_BASE))) == _unknown()
    assert calls == [] and _HOOKS == []


@pytest.mark.parametrize(
    "kind",
    [
        "dict_subclass",
        "key_subclass",
        "schema_bool",
        "scope_subclass",
        "available_int",
        "foreign_reason",
        "status_subclass",
        "bool_int",
        "key_order",
        "extra_key",
        "available_mismatch",
    ],
)
def test_decoded_payload_admission_precedes_equality_and_rejects_private_values(monkeypatch, kind):
    _HOOKS.clear()
    value = _expected()
    if kind == "dict_subclass":
        value = DictSubclass(value)
    elif kind == "key_subclass":
        value = {
            StringSubclass(key) if key == "reason" else key: item for key, item in value.items()
        }
    elif kind == "schema_bool":
        value["schema_version"] = True
    elif kind == "scope_subclass":
        value["sample_scope"] = StringSubclass("post_return_independent")
    elif kind == "available_int":
        value["available"] = 1
    elif kind == "foreign_reason":
        value["reason"] = Private()
    elif kind == "status_subclass":
        value["status"] = StringSubclass("failed")
    elif kind == "bool_int":
        value["acted"] = 1
    elif kind == "key_order":
        value = dict(reversed(tuple(value.items())))
    elif kind == "extra_key":
        value["PRIVATE_EXTRA"] = "PRIVATE_CONTENT"
    else:
        value["available"] = False
    monkeypatch.setattr(diagnostic.json, "loads", lambda _text, **_kwargs: value)
    sink = _emit(monkeypatch, dict(_BASE))
    assert _HOOKS == []
    assert _line(sink) == _unknown()
    assert "PRIVATE" not in sink.attempts[0]


@pytest.mark.parametrize("kind", ["malformed", "different_valid_payload"])
def test_wrong_roundtrip_cannot_be_reported_as_the_original_sample(monkeypatch, kind):
    text = (
        "{}"
        if kind == "malformed"
        else _DUMPS(_expected(reason="completed"), separators=(",", ":"))
    )
    monkeypatch.setattr(diagnostic.json, "dumps", lambda *_args, **_kwargs: text)
    assert _line(_emit(monkeypatch, dict(_BASE))) == _unknown()


@pytest.mark.parametrize("field", ["fault", "status", "reason", "stopped", "acted"])
def test_private_duplicate_raw_field_cannot_hide_behind_the_original_decoded_value(
    monkeypatch, field
):
    original = _DUMPS(_expected(), separators=(",", ":"))
    # The trailing original field defeats an ordinary stock-decoder/equality gate.
    text = '{"' + field + '":"PRIVATE_RAW_VALUE",' + original[1:]
    assert _LOADS(text) == _expected()
    monkeypatch.setattr(diagnostic.json, "dumps", lambda *_args, **_kwargs: text)
    sink = _emit(monkeypatch, dict(_BASE))
    assert _line(sink) == _unknown()
    assert "PRIVATE_RAW_VALUE" not in sink.attempts[0]


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("partial", [False, True])
def test_output_fault_never_retries_or_replaces_pending_original_assertion(
    monkeypatch, kind, partial
):
    metadata_error = kind("PRIVATE_OUTPUT_MESSAGE")

    class Failing(Capture):
        def write(self, line):
            self.attempts.append(line[:9] if partial else line)
            raise metadata_error

    target = Failing()
    primary = AssertionError("original assertion")
    cause = ValueError("original cause")
    context = KeyError("original context")
    with pytest.raises(AssertionError) as raised:
        try:
            raise primary
        except AssertionError:
            primary.__cause__ = cause
            primary.__context__ = context
            _emit(monkeypatch, dict(_BASE), target)
            raise
    assert raised.value is primary
    assert primary.__cause__ is cause and primary.__context__ is context
    assert primary.__suppress_context__ is True
    assert len(target.attempts) == 1 and target.flushes == 0
    assert "PRIVATE" not in target.attempts[0]


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_setup_fault_cannot_replace_pending_original_assertion(monkeypatch, kind):
    error = kind("PRIVATE_SETUP_MESSAGE")

    def fail(**_kwargs):
        raise error

    monkeypatch.setattr(diagnostic, "_payload", fail)
    primary = AssertionError("original")
    target = Capture()
    with pytest.raises(AssertionError) as raised:
        try:
            raise primary
        except AssertionError:
            _emit(monkeypatch, dict(_BASE), target)
            raise
    assert raised.value is primary and _line(target) == _unknown()


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_dynamic_write_lookup_fault_is_not_retried(monkeypatch, kind):
    calls = []

    class MissingWriter:
        def __getattribute__(self, name):
            calls.append(name)
            raise kind("PRIVATE_WRITE_LOOKUP")

    _emit(monkeypatch, dict(_BASE), MissingWriter())
    assert calls == ["write"]


def test_short_write_is_unknown_and_never_retried(monkeypatch):
    class Short(Capture):
        def write(self, line):
            self.attempts.append(line[:9])
            return 9

    target = Short()
    assert _emit(monkeypatch, dict(_BASE), target) is target
    assert len(target.attempts) == 1 and target.flushes == 0
    assert target.attempts[0] == "AQT_PAREN"


@pytest.mark.parametrize("stage", ["serializer", "writer"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_retained_new_error_does_not_extend_private_input_lifetime_vs_baseline(
    monkeypatch, stage, kind
):
    def exercise(use_helper):
        private = Private()
        ref = weakref.ref(private)
        metadata_error = kind("controlled metadata failure")
        values = {**_BASE, "fault": private}

        def fail(*args, **kwargs):
            try:
                raise metadata_error
            finally:
                del args, kwargs

        class Writer:
            def write(self, line):
                return fail(line)

        try:
            with monkeypatch.context() as patch:
                if stage == "serializer":
                    patch.setattr(diagnostic.json, "dumps", fail)
                    patch.setattr(diagnostic.sys, "stdout", Capture())
                else:
                    patch.setattr(diagnostic.sys, "stdout", Writer())
                if use_helper:
                    diagnostic.emit_lifecycle_outcome_failure(**values)
                else:
                    with suppress(BaseException):
                        fail("baseline native scalar")
        finally:
            private = values = None
        return ref, metadata_error

    baseline_ref, baseline_error = exercise(False)
    helper_ref, helper_error = exercise(True)
    gc.collect()
    assert baseline_ref() is None and helper_ref() is None
    assert baseline_error.__traceback__ is not None
    # Suppressed metadata history is discarded, including preexisting frames.
    assert helper_error.__traceback__ is None


def test_keyword_only_scalar_api_rejects_outcome_or_list_inputs(monkeypatch):
    _HOOKS.clear()
    target = Capture()
    with monkeypatch.context() as patch:
        patch.setattr(diagnostic.sys, "stdout", target)
        with pytest.raises(TypeError):
            diagnostic.emit_lifecycle_outcome_failure(dict(_BASE))
        with pytest.raises(TypeError):
            diagnostic.emit_lifecycle_outcome_failure(**_BASE, result=Private())
        with pytest.raises(TypeError):
            diagnostic.emit_lifecycle_outcome_failure(**_BASE, observed=[])
    assert target.attempts == []
    assert _HOOKS == []


@pytest.mark.parametrize("stage", ["serializer", "decoder", "writer"])
@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_retained_auxiliary_history_matches_caller_local_baseline(monkeypatch, stage, kind):
    def exercise(use_helper):
        metadata = kind("controlled auxiliary history")
        try:
            raise metadata
        except BaseException:
            pass
        assert metadata.__traceback__ is not None
        target = Capture()

        def fail(*args, **kwargs):
            try:
                if stage == "writer":
                    target.attempts.append(args[0])
                raise metadata
            finally:
                del args, kwargs

        def caller():
            private = Private()
            reference = weakref.ref(private)
            try:
                raise AssertionError("original pending failure")
            except AssertionError as primary:
                if use_helper:
                    with monkeypatch.context() as patch:
                        if stage == "writer":
                            patch.setattr(target, "write", fail)
                        else:
                            patch.setattr(
                                diagnostic.json, "dumps" if stage == "serializer" else "loads", fail
                            )
                        _emit(patch, dict(_BASE), target)
                return primary, reference

        primary, reference = caller()
        gc.collect()
        assert reference() is not None
        primary.__traceback__ = None
        metadata.__context__ = None
        gc.collect()
        assert reference() is None
        assert metadata.__traceback__ is None if use_helper else metadata.__traceback__ is not None
        assert len(target.attempts) == (1 if use_helper else 0)

    exercise(False)
    exercise(True)


@pytest.mark.parametrize("stage", ["serializer", "decoder", "writer"])
@pytest.mark.parametrize("kind", [AssertionError, KeyboardInterrupt])
def test_rethrowing_exact_pending_primary_restores_entry_traceback(monkeypatch, stage, kind):
    primary = kind("original pending failure")
    cause = ValueError("original cause")
    context = RuntimeError("original context")
    target = Capture()

    def fail(*args, **kwargs):
        try:
            if stage == "writer":
                target.attempts.append(args[0])
            raise primary
        finally:
            del args, kwargs

    try:
        raise context
    except RuntimeError:
        try:
            raise primary from cause
        except BaseException:
            entry = BaseException.__traceback__.__get__(primary)
            before = primary.__cause__, primary.__context__, primary.__suppress_context__
            with monkeypatch.context() as patch:
                if stage == "writer":
                    patch.setattr(target, "write", fail)
                else:
                    patch.setattr(
                        diagnostic.json, "dumps" if stage == "serializer" else "loads", fail
                    )
                _emit(patch, dict(_BASE), target)
            assert BaseException.__traceback__.__get__(primary) is entry
            assert primary.__cause__ is before[0] is cause
            assert primary.__context__ is before[1] is context
            assert primary.__suppress_context__ is before[2] is True
            assert len(target.attempts) == 1 and target.flushes == 0


@pytest.mark.parametrize("stage", ["serializer", "decoder", "writer"])
def test_auxiliary_traceback_cleanup_bypasses_hostile_exception_hooks(monkeypatch, stage):
    calls = []

    class HostileError(RuntimeError):
        def __getattribute__(self, name):
            calls.append(("get", name))
            raise AssertionError("exception hook must not run")

        def __setattr__(self, name, value):
            calls.append(("set", name))
            raise AssertionError("exception hook must not run")

    metadata = HostileError("controlled auxiliary failure")
    target = Capture()

    def fail(*args, **kwargs):
        try:
            if stage == "writer":
                target.attempts.append(args[0])
            raise metadata
        finally:
            del args, kwargs

    with monkeypatch.context() as patch:
        if stage == "writer":
            patch.setattr(target, "write", fail)
        else:
            patch.setattr(diagnostic.json, "dumps" if stage == "serializer" else "loads", fail)
        _emit(patch, dict(_BASE), target)
    assert BaseException.__traceback__.__get__(metadata) is None
    assert calls == []
    assert len(target.attempts) == 1 and target.flushes == 0


@pytest.mark.parametrize("stage", ["serializer", "decoder", "writer"])
def test_preexisting_auxiliary_private_frame_is_released_without_metadata_changes(
    monkeypatch, stage
):
    metadata = RuntimeError("controlled auxiliary history")
    cause, context = ValueError("auxiliary cause"), KeyError("auxiliary context")
    metadata.__cause__, metadata.__context__ = cause, context
    args, suppressed = metadata.args, metadata.__suppress_context__

    def prime():
        private = Private()
        reference = weakref.ref(private)
        try:
            raise metadata
        except RuntimeError:
            return reference

    reference = prime()
    gc.collect()
    assert reference() is not None
    target = Capture()

    def fail(*args, **kwargs):
        try:
            if stage == "writer":
                target.attempts.append(args[0])
            raise metadata
        finally:
            del args, kwargs

    with monkeypatch.context() as patch:
        if stage == "writer":
            patch.setattr(target, "write", fail)
        else:
            patch.setattr(diagnostic.json, "dumps" if stage == "serializer" else "loads", fail)
        _emit(patch, dict(_BASE), target)
    gc.collect()
    assert reference() is None and metadata.__traceback__ is None
    assert metadata.__cause__ is cause and metadata.__context__ is context
    assert metadata.args is args and metadata.__suppress_context__ is suppressed
    assert len(target.attempts) == 1 and target.flushes == 0


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_pending_primary_admission_failure_is_isolated_without_cleanup(monkeypatch, kind):
    primary = AssertionError("original primary")
    metadata = kind("controlled admission failure")
    target = Capture()

    def fail():
        raise metadata

    try:
        raise primary
    except AssertionError:
        entry = primary.__traceback__
        with monkeypatch.context() as patch:
            patch.setitem(diagnostic.sys.__dict__, "exception", fail)
            _emit(patch, dict(_BASE), target)
        assert primary.__traceback__ is entry
        assert metadata.__traceback__ is not None
        assert metadata.__context__ is primary
        assert target.attempts == []
