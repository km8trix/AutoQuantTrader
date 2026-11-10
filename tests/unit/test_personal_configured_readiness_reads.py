"""Explicit lifecycle model only; no account, Engine or readiness proof is modeled.

Fresh migrated integration cases separately exercise the unchanged G/J/K owners.
These native statuses and controlled failures qualify L's finite transport rules.
"""

import asyncio
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from apps.api import configured_readiness_reads as lifecycle_module
from apps.api.readiness_read_store import ReadinessReadStoreStatus
from apps.trader.continuous_readiness_owner import ReadinessOwnerLimits, ReadinessOwnerStatus


@pytest.fixture
def lifecycle(monkeypatch):
    model = SimpleNamespace(
        calls=[],
        started=ReadinessOwnerStatus("idle", False, False, None, None, "model-incarnation"),
        stopped=ReadinessOwnerStatus("stopped", False, True, None, None, "model-incarnation"),
        closed=ReadinessReadStoreStatus("closed", False, True, None),
        start_error=None,
        open_error=None,
        close_error=None,
        stop_error=None,
        start_entered=threading.Event(),
        start_allowed=threading.Event(),
        callers=[],
    )
    model.start_allowed.set()

    class ModelOwner:
        def start(self):
            model.calls.append("start")
            model.start_entered.set()
            assert model.start_allowed.wait(3), "test did not release start barrier"
            if model.start_error is not None:
                raise model.start_error
            return model.started

        def stop(self):
            model.calls.append("stop")
            if model.stop_error is not None:
                raise model.stop_error
            return model.stopped

    class ModelStore:
        def close(self):
            model.calls.append("close")
            if model.close_error is not None:
                raise model.close_error
            return model.closed

    model.owner = ModelOwner()
    model.store = ModelStore()
    model.built = model.owner
    model.opened = model.store

    def build(**arguments):
        model.calls.append("construct")
        assert arguments == {
            "configuration_path": "/private/tmp/no-model-file-opened.json",
            "account_id": "model-account",
            "instance_lock": "/private/tmp/no-model-lock-opened.lock",
            "limits": ReadinessOwnerLimits(),
        }
        return model.built

    def open_store(owner):
        assert owner is model.owner
        model.calls.append("open")
        if model.open_error is not None:
            raise model.open_error
        return model.opened

    for name, value in {
        "_OWNER": ModelOwner,
        "_START": ModelOwner.start,
        "_STOP": ModelOwner.stop,
        "_STORE": ModelStore,
        "_CLOSE": ModelStore.close,
        "create_configured_readiness_owner": build,
        "open_readiness_read_store": open_store,
    }.items():
        monkeypatch.setattr(lifecycle_module, name, value)
    yield model
    model.start_allowed.set()
    for caller in model.callers:
        caller.join(4)
        assert not caller.is_alive(), "controlled lifecycle caller did not finish"


def _manager():
    return lifecycle_module.configured_readiness_reads(
        configuration_path="/private/tmp/no-model-file-opened.json",
        account_id="model-account",
        instance_lock="/private/tmp/no-model-lock-opened.lock",
    )


def _code(error, suffix):
    assert type(error) is RuntimeError
    assert str(error) == "CONFIGURED_READINESS_READS_" + suffix


def test_construction_is_data_only_and_recreated_context_cannot_restart(lifecycle):
    manager = _manager()
    recreated = manager._recreate_cm()
    assert lifecycle.calls == ["construct"]
    with manager as store:
        assert store is lifecycle.store
        assert lifecycle.calls == ["construct", "start", "open"]
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]
    with pytest.raises(RuntimeError) as raised, recreated:
        pytest.fail("recreated context silently restarted")
    _code(raised.value, "ALREADY_ENTERED")
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


def test_concurrent_recreated_context_is_denied_before_second_start(lifecycle):
    manager = _manager()
    recreated = manager._recreate_cm()
    lifecycle.start_allowed.clear()
    errors = []

    def enter():
        try:
            with manager as store:
                assert store is lifecycle.store
        except BaseException as error:
            errors.append(error)

    caller = threading.Thread(target=enter)
    lifecycle.callers.append(caller)
    caller.start()
    try:
        assert lifecycle.start_entered.wait(2)
        with pytest.raises(RuntimeError) as raised, recreated:
            pytest.fail("overlapping recreated context entered")
        _code(raised.value, "ALREADY_ENTERED")
        assert lifecycle.calls == ["construct", "start"]
    finally:
        lifecycle.start_allowed.set()
        caller.join(4)
    assert not caller.is_alive() and errors == []
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


@pytest.mark.parametrize("bad", [None, object()])
def test_nonoriginal_builder_result_denies_before_start(lifecycle, bad):
    lifecycle.built = bad
    with pytest.raises(ValueError, match=r"^CONFIGURED_READINESS_READS_ORIGINAL_OWNER_REQUIRED$"):
        _manager()
    assert lifecycle.calls == ["construct"]


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"busy": 0}, "OWNER_STATUS_INVALID"),
        ({"cleanup_complete": 0}, "OWNER_STATUS_INVALID"),
        ({"incarnation": " padded "}, "OWNER_STATUS_INVALID"),
        ({"phase": "starting"}, "STARTUP_UNAVAILABLE"),
        ({"busy": True}, "STARTUP_UNAVAILABLE"),
        ({"cleanup_complete": True}, "STARTUP_UNAVAILABLE"),
        ({"primary_failure": "runtime_failed"}, "STARTUP_UNAVAILABLE"),
    ],
)
def test_startup_native_and_admission_denials_still_stop_once(lifecycle, changes, code):
    lifecycle.started = replace(lifecycle.started, **changes)
    with pytest.raises(RuntimeError) as raised, _manager():
        pytest.fail("invalid startup yielded a store")
    _code(raised.value, code)
    assert lifecycle.calls == ["construct", "start", "stop"]


@pytest.mark.parametrize("error_type", [ValueError, KeyboardInterrupt])
def test_attempted_start_failure_preserves_primary_and_stops_once(lifecycle, error_type):
    primary = error_type("private modeled start failure")
    lifecycle.start_error = primary
    with pytest.raises(BaseException) as raised, _manager():
        pytest.fail("failed startup yielded")
    assert raised.value is primary
    assert lifecycle.calls == ["construct", "start", "stop"]


def test_failed_opener_is_not_repeated_or_closed_by_lifecycle(lifecycle):
    primary = BaseExceptionGroup("private opener group", [ValueError("original open")])
    lifecycle.open_error = primary
    with pytest.raises(BaseExceptionGroup) as raised, _manager():
        pytest.fail("failed opening yielded")
    assert raised.value is primary
    assert lifecycle.calls == ["construct", "start", "open", "stop"]


@pytest.mark.parametrize("bad", [None, object()])
def test_nonoriginal_opened_result_is_not_adopted_or_closed(lifecycle, bad):
    lifecycle.opened = bad
    with (
        pytest.raises(ValueError, match=r"^CONFIGURED_READINESS_READS_READ_STORE_REQUIRED$"),
        _manager(),
    ):
        pytest.fail("foreign read store yielded")
    assert lifecycle.calls == ["construct", "start", "open", "stop"]


@pytest.mark.parametrize("kind", ["base", "cancel", "group"])
def test_sole_body_primary_propagates_by_identity_after_both_cleanups(lifecycle, kind):
    primary = {
        "base": KeyboardInterrupt("private body interruption"),
        "cancel": asyncio.CancelledError("private cancellation"),
        "group": BaseExceptionGroup("private nested body", [KeyboardInterrupt(), ValueError()]),
    }[kind]
    with pytest.raises(BaseException) as raised, _manager():
        raise primary
    assert raised.value is primary
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


@pytest.mark.parametrize(
    "has_primary,has_close,has_stop",
    [
        (False, True, False),
        (False, False, True),
        (False, True, True),
        (True, True, False),
        (True, False, True),
        (True, True, True),
    ],
)
def test_actual_raised_failures_keep_exact_order_and_nested_identity(
    lifecycle, has_primary, has_close, has_stop
):
    primary = BaseExceptionGroup("private original body", [KeyboardInterrupt(), ValueError()])
    close = BaseExceptionGroup("private K close", [ValueError("guard"), OSError("cleanup")])
    stop = KeyboardInterrupt("private actual stop")
    lifecycle.close_error = close if has_close else None
    lifecycle.stop_error = stop if has_stop else None
    with pytest.raises(BaseException) as raised, _manager():
        if has_primary:
            raise primary
    expected = tuple(
        error
        for present, error in ((has_primary, primary), (has_close, close), (has_stop, stop))
        if present
    )
    if len(expected) == 1:
        assert raised.value is expected[0]
    else:
        assert isinstance(raised.value, BaseExceptionGroup)
        assert raised.value.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
        assert len(raised.value.exceptions) == len(expected)
        assert all(
            actual is original
            for actual, original in zip(raised.value.exceptions, expected, strict=True)
        )
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


@pytest.mark.parametrize(
    "changes",
    [
        {"phase": "closing", "busy": True, "cleanup_complete": False},
        {"busy": 0},
        {"cleanup_complete": 1},
        {"cleanup_failure": "cleanup_failed"},
    ],
)
def test_observed_read_cleanup_cutoff_is_not_replaced_by_private_details(lifecycle, changes):
    lifecycle.closed = replace(lifecycle.closed, **changes)
    lifecycle.store._cleanup_error = AssertionError("must not inspect this private error")
    with pytest.raises(RuntimeError) as raised, _manager():
        pass
    _code(raised.value, "READ_CLEANUP_INCOMPLETE")
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"phase": "stopping", "cleanup_complete": False}, "OWNER_CLEANUP_INCOMPLETE"),
        ({"busy": True}, "OWNER_CLEANUP_INCOMPLETE"),
        ({"cleanup_failure": "cleanup_failed"}, "OWNER_CLEANUP_INCOMPLETE"),
        ({"incarnation": "different-incarnation"}, "OWNER_CLEANUP_INCOMPLETE"),
        ({"busy": 0}, "OWNER_STATUS_INVALID"),
    ],
)
def test_observed_owner_cleanup_requires_exact_native_same_incarnation(lifecycle, changes, code):
    lifecycle.stopped = replace(lifecycle.stopped, **changes)
    with pytest.raises(RuntimeError) as raised, _manager():
        pass
    _code(raised.value, code)
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


def test_historical_primary_failure_is_not_a_new_owner_cleanup_failure(lifecycle):
    lifecycle.stopped = replace(lifecycle.stopped, primary_failure="runtime_failed")
    with _manager() as store:
        assert store is lifecycle.store
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


@pytest.mark.parametrize("name", ["start", "stop", "close"])
@pytest.mark.parametrize("placement", ["class", "instance"])
def test_changed_public_binding_cannot_replace_known_original_cleanup(
    lifecycle, monkeypatch, name, placement
):
    instance = lifecycle.store if name == "close" else lifecycle.owner
    substitutes = []

    def replacement(*args, **kwargs):
        substitutes.append(name)
        raise AssertionError("substitute must not run")

    with monkeypatch.context() as local:
        with pytest.raises(RuntimeError) as raised, _manager():
            if placement == "class":
                local.setattr(type(instance), name, replacement)
            else:
                assert name not in vars(instance)
                local.setitem(vars(instance), name, replacement)
        _code(raised.value, "BINDING_CHANGED")
    assert name not in vars(instance)
    assert substitutes == []
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]


def test_prestart_binding_denial_does_not_claim_an_attempted_start(lifecycle, monkeypatch):
    manager = _manager()
    with monkeypatch.context() as local:
        local.setitem(vars(lifecycle.owner), "start", lambda: pytest.fail("foreign start"))
        with pytest.raises(RuntimeError) as raised, manager:
            pytest.fail("invalid binding admitted")
        _code(raised.value, "BINDING_CHANGED")
    assert "start" not in vars(lifecycle.owner)
    assert lifecycle.calls == ["construct"]


@pytest.mark.parametrize("step", ["close", "stop"])
def test_binding_guard_and_actual_cleanup_failure_remain_an_ordered_step_group(
    lifecycle, monkeypatch, step
):
    primary = KeyboardInterrupt("private original body")
    cleanup = OSError("private original cleanup")
    instance = lifecycle.store if step == "close" else lifecycle.owner
    if step == "close":
        lifecycle.close_error = cleanup
    else:
        lifecycle.stop_error = cleanup
    with monkeypatch.context() as local:
        with pytest.raises(BaseExceptionGroup) as raised, _manager():
            local.setitem(vars(instance), step, lambda: pytest.fail("foreign cleanup"))
            raise primary
        outer = raised.value
        assert outer.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
        assert len(outer.exceptions) == 2 and outer.exceptions[0] is primary
        nested = outer.exceptions[1]
        assert isinstance(nested, BaseExceptionGroup)
        assert nested.message == f"CONFIGURED_READINESS_READS_{step.upper()}_AND_CHECK_FAILED"
        assert len(nested.exceptions) == 2 and nested.exceptions[1] is cleanup
        _code(nested.exceptions[0], "BINDING_CHANGED")
    assert step not in vars(instance)
    assert lifecycle.calls == ["construct", "start", "open", "close", "stop"]
