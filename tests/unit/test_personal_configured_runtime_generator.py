"""Finite extraction/binding transport only, with real native owner Threads.

The setup boundary is trapped before filesystem or factory work. No runtime,
lease, financial proof or successful readiness is fabricated by these units.
Original fresh integration tests separately qualify the preserved generator body.
"""

import builtins
import os
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import Engine

from apps.trader import configured_readiness_owner as configured_module
from apps.trader.continuous_readiness_owner import (
    ContinuousReadinessOwner,
    ReadinessOwnerLimits,
    ReadinessOwnerStatus,
)

_CONFIGURATION = "/private/tmp/unopened-generator-configuration.json"
_LOCK = "/private/tmp/unopened-generator-instance.lock"
_ACCOUNT = "pure-generator-test-account"


def _create():
    return configured_module.create_configured_readiness_owner(
        configuration_path=_CONFIGURATION,
        account_id=_ACCOUNT,
        instance_lock=_LOCK,
    )


def _trap_setup(monkeypatch, *, constructor):
    attempts = []

    def denied(label):
        def invoke(*args, **kwargs):
            attempts.append((label, threading.current_thread()))
            raise AssertionError("pure configured-generator test reached a forbidden effect")

        return invoke

    targets = [
        (builtins, "open"),
        (os, "open"),
        (os, "stat"),
        (os, "lstat"),
        (Path, "open"),
        (Path, "stat"),
        (Path, "lstat"),
        (Path, "resolve"),
        (Engine, "connect"),
        (configured_module, "_preflight"),
        (configured_module, "_existing_private"),
        (configured_module, "load_continuous_configuration"),
        (configured_module, "_held_guard"),
        (configured_module, "_database_identity"),
        (configured_module, "ContinuousSimulationFactory"),
    ]
    if constructor:
        targets.extend([(time, "monotonic_ns"), (time, "monotonic"), (threading.Thread, "start")])
    for target, name in targets:
        monkeypatch.setattr(target, name, denied(name))
    return attempts


def _finish(owner):
    # Always attempt the native join even if original stop unexpectedly raises.
    failures = []
    try:
        owner.stop()
    except BaseException as error:
        failures.append(error)
    if owner._thread is not None:
        try:
            owner._thread.join(2)
            assert not owner._thread.is_alive(), "original unit owner Thread did not exit"
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup("configured-generator unit cleanup failed", failures)
    return owner.status()


def _failed_start(owner, initial):
    assert type(initial) is ReadinessOwnerStatus
    # start() can observe the original stopping window before _run's finally
    # and actual Thread exit. Only the post-join status can assert completion.
    assert initial.phase in ("stopping", "stopped")
    assert initial.primary_failure == "startup_failed"
    assert initial.cleanup_failure is None
    assert type(initial.busy) is bool and type(initial.cleanup_complete) is bool
    assert initial.incarnation == owner.status().incarnation


def _stopped(owner, status, incarnation):
    assert type(status) is ReadinessOwnerStatus
    assert status == ReadinessOwnerStatus(
        "stopped", False, True, "startup_failed", None, incarnation
    )
    assert owner._thread is not None and not owner._thread.is_alive()
    assert owner.store_binding() is None
    thread = owner._thread
    assert owner.start() == status
    assert owner._thread is thread  # A failed startup is never silently retried.


def test_configured_generator_extraction_keeps_construction_data_only(monkeypatch):
    with monkeypatch.context() as local:
        attempts = _trap_setup(local, constructor=True)
        owner = _create()
        try:
            assert type(owner) is ContinuousReadinessOwner
            initial = owner.status()
            assert type(initial) is ReadinessOwnerStatus
            assert initial == ReadinessOwnerStatus(
                "new", False, True, None, None, initial.incarnation
            )
            assert owner._thread is None and owner.store_binding() is None
            assert owner._limits == ReadinessOwnerLimits()
            assert attempts == []
        finally:
            final = _finish(owner)
        assert final == ReadinessOwnerStatus(
            "stopped", False, True, None, None, initial.incarnation
        )
        assert owner._thread is None and attempts == []


def test_changed_named_generator_denies_before_construction_effects(monkeypatch):
    substituted = []

    def replacement(**kwargs):
        substituted.append(threading.current_thread())
        raise AssertionError("changed generator must never be called")

    with monkeypatch.context() as local:
        attempts = _trap_setup(local, constructor=True)
        local.setattr(configured_module, "_configured_runtime_generator", replacement)
        with pytest.raises(RuntimeError) as raised:
            _create()
        assert str(raised.value) == "CONFIGURED_READINESS_RUNTIME_BINDING_CHANGED"
        assert type(raised.value) is RuntimeError
        assert substituted == attempts == []


def test_named_generator_drift_before_start_denies_on_original_owner_thread(monkeypatch):
    substituted = []

    def replacement(**kwargs):
        substituted.append(threading.current_thread())
        raise AssertionError("changed generator must never be called")

    with monkeypatch.context() as local:
        attempts = _trap_setup(local, constructor=False)
        owner = _create()
        incarnation = owner.status().incarnation
        local.setattr(configured_module, "_configured_runtime_generator", replacement)
        try:
            started = owner.start()
            _failed_start(owner, started)
            assert owner._thread is not threading.current_thread()
        finally:
            final = _finish(owner)
        _stopped(owner, final, incarnation)
        assert substituted == attempts == []


def test_alias_drift_after_capture_cannot_redirect_original_worker_dispatch(monkeypatch):
    substituted, preflight_calls = [], []
    boundary = ValueError("controlled pure preflight boundary")

    def replacement(**kwargs):
        substituted.append(threading.current_thread())
        raise AssertionError("changed saved alias must never be called")

    with monkeypatch.context() as local:
        attempts = _trap_setup(local, constructor=False)
        original = configured_module._CONFIGURED_RUNTIME_GENERATOR
        assert configured_module._configured_runtime_generator is original
        owner = _create()
        incarnation = owner.status().incarnation

        def reject_preflight(configuration_file, lock_path):
            stopped = owner._stop_event.is_set()
            preflight_calls.append(
                (threading.current_thread(), configuration_file, lock_path, stopped)
            )
            assert threading.current_thread() is owner._thread
            assert stopped is False
            raise boundary

        local.setattr(configured_module, "_CONFIGURED_RUNTIME_GENERATOR", replacement)
        local.setattr(configured_module, "_preflight", reject_preflight)
        try:
            started = owner.start()
            _failed_start(owner, started)
        finally:
            final = _finish(owner)
        _stopped(owner, final, incarnation)
        assert preflight_calls == [(owner._thread, Path(_CONFIGURATION), Path(_LOCK), False)]
        assert configured_module._configured_runtime_generator is original
        assert substituted == attempts == []
