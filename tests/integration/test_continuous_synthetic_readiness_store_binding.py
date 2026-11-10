"""Actual configured-owner store metadata, with original financial proof and cleanup.

Every case uses a new migrated fixture. Forwarders observe the original owner,
factory and Runtime; only explicit adverse binding arguments or a pre-open file
replacement differ. No returned metadata record is a readiness capability.
"""

import builtins
import os
import threading
import time
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import Engine

from apps.trader import configured_readiness_owner as configured_module
from apps.trader import continuous_readiness_owner as owner_module
from apps.trader import continuous_simulation_factory as factory_module
from apps.trader.readiness_store_binding import ReadinessStoreBinding
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_configured_readiness import _case


def _values(binding):
    assert type(binding) is ReadinessStoreBinding
    return (
        binding.incarnation,
        binding.account_id,
        binding.account_binding_sha256,
        binding.stream_id,
        binding.database_path,
        binding.database_device,
        binding.database_inode,
        binding.configuration_payload_sha256,
    )


@contextmanager
def _no_caller_effects(monkeypatch, caller):
    """Trap the getter's caller only; the real owner retains its clock and cleanup."""
    attempts = []

    def guarded(original, label):
        def invoke(*args, **kwargs):
            if threading.current_thread() is caller:
                attempts.append(label)
                raise AssertionError("store getter attempted a caller-side effect")
            return original(*args, **kwargs)

        return invoke

    with monkeypatch.context() as local:
        for target, name in (
            (builtins, "open"),
            (os, "open"),
            (os, "stat"),
            (os, "lstat"),
            (Path, "open"),
            (Path, "stat"),
            (Path, "resolve"),
            (Engine, "connect"),
            (time, "monotonic_ns"),
            (time, "monotonic"),
            (threading.Thread, "start"),
            (configured_module, "load_continuous_configuration"),
        ):
            local.setattr(target, name, guarded(getattr(target, name), name))
        yield
    assert attempts == []


@contextmanager
def _starting(case):
    starts, errors = [], []

    def start():
        try:
            starts.append(case.owner.start())
        except BaseException as error:
            errors.append(error)

    caller = threading.Thread(target=start)
    caller.start()
    primary = None
    try:
        yield starts, errors
    except BaseException as error:
        primary = error
        raise
    finally:
        case.allow_startup.set()
        try:
            caller.join(12)
            assert not caller.is_alive(), "startup caller did not actually finish"
        except BaseException as cleanup:
            if primary is not None:
                raise BaseExceptionGroup(
                    "binding startup observation and caller cleanup failed", [primary, cleanup]
                ) from None
            raise


def test_original_configured_binding_is_native_fresh_and_never_a_readiness_grant(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch) as case:
        with _no_caller_effects(monkeypatch, case.caller_thread):
            assert case.owner.store_binding() is None
        assert case.trace == [] and case.acquires == []
        started = case.owner.start()
        assert started.phase == "idle" and started.cleanup_complete is False
        path = case.study.paths["database_path"].resolve(strict=True)
        physical = path.stat()
        scope = case.study.genesis.scope
        assert case.factory._original_configuration == case.configuration_bytes
        expected = (
            started.incarnation,
            scope.account_id,
            scope.account_binding_sha256,
            scope.stream_id,
            str(path),
            physical.st_dev,
            physical.st_ino,
            sha256(case.configuration_bytes).hexdigest(),
        )
        assert case.runtime.reader.scope == scope
        assert case.runtime.reader.engine is case.factory.engine is case.account_engine
        baseline = case.owner._store_binding_values
        assert type(baseline) is tuple and baseline == expected
        assert all(type(value) in (str, int) for value in baseline)
        with _no_caller_effects(monkeypatch, case.caller_thread):
            first = case.owner.store_binding()
            repeated = case.owner.store_binding()
        assert first is not repeated and _values(first) == _values(repeated) == expected
        assert str(path) not in repr(first)
        substitutions = {
            "incarnation": "different-owner-incarnation",
            "account_id": "different-account",
            "account_binding_sha256": "c" * 64,
            "stream_id": "different-stream",
            "database_path": str(case.study.paths["venue_database_path"]),
            "database_device": physical.st_dev + 1,
            "database_inode": physical.st_ino + 1,
            "configuration_payload_sha256": "d" * 64,
        }
        for name, replacement in substitutions.items():
            caller_record = case.owner.store_binding()
            object.__setattr__(caller_record, name, replacement)
            # Each substitution remains a valid DTO; validity grants no ownership.
            ReadinessStoreBinding.__post_init__(caller_record)
            with _no_caller_effects(monkeypatch, case.caller_thread):
                fresh = case.owner.store_binding()
            assert fresh is not caller_record and _values(fresh) == expected
            assert case.owner._store_binding_values is baseline
        assert case.proofs == 0 and case.release_attempts == []
        checked = case.owner.check("original-proof-after-caller-record-mutations")
        assert checked.status == "ready" and checked.reason == "verified"
        assert checked.incarnation == expected[0] and case.proofs == 1
    # The inherited finalizer requires actual join, original release/null head,
    # both engine disposals, guard exit and exact financial/venue/object facts.
    with _no_caller_effects(monkeypatch, case.caller_thread):
        historical = case.owner.store_binding()
    assert historical is not first and _values(historical) == expected
    assert case.owner.check("historical-binding-is-not-ready").status == "unavailable"
    assert case.owner.status().cleanup_complete is True
    assert len(case.acquires) == len(case.releases) == case.close_calls == case.proofs == 1


@pytest.mark.parametrize("stop_before_admission", [False, True], ids=["continue", "stop"])
def test_no_store_binding_before_original_startup_admission(
    tmp_path, monkeypatch, stop_before_admission
):
    with _case(tmp_path, monkeypatch, mode="startup-stop") as case:
        with _starting(case) as (starts, errors):
            assert case.startup_entered.wait(10), "original returned-lease checkpoint not reached"
            assert len(case.acquires) == 1 and case.checkpoints == 2
            assert case.runtime is None and case.proofs == 0
            with _no_caller_effects(monkeypatch, case.caller_thread):
                assert case.owner.store_binding() is None
            if stop_before_admission:
                stopped = case.owner.stop()
                assert stopped.phase == "stopping" and stopped.cleanup_complete is False
                assert case.release_attempts == []
                assert case.owner.store_binding() is None
        assert errors == [] and len(starts) == 1
        if stop_before_admission:
            assert starts[0].phase != "idle" and case.runtime is None
            assert case.owner.store_binding() is None
        else:
            assert starts[0].phase == "idle" and case.runtime is not None
            assert _values(case.owner.store_binding())[0] == starts[0].incarnation
        assert case.proofs == 0
    assert case.owner.status().cleanup_complete is True
    assert len(case.acquires) == len(case.releases) == case.close_calls == 1
    if stop_before_admission:
        assert case.owner.store_binding() is None


@pytest.mark.parametrize("field", ["account", "binding", "stream", "physical-path"])
def test_original_runtime_rejects_valid_native_but_foreign_store_identity(
    tmp_path, monkeypatch, field
):
    with _case(tmp_path, monkeypatch) as case:
        bind = owner_module._ReadinessRuntime._bind_store_identity
        attempts, errors = [], []
        venue = case.study.paths["venue_database_path"]
        venue_stat = venue.stat()

        def foreign_identity(runtime, values):
            assert threading.current_thread() is case.owner._thread
            assert runtime is case.runtime and runtime._store_identity_values is None
            assert type(values) is tuple and len(values) == 7
            altered = list(values)
            if field == "account":
                altered[0] = "different-selected-account"
            elif field == "binding":
                altered[1] = "f" * 64 if values[1] != "f" * 64 else "e" * 64
            elif field == "stream":
                altered[2] = "different-selected-stream"
            else:
                altered[3:6] = [str(venue), venue_stat.st_dev, venue_stat.st_ino]
            proposal = tuple(altered)
            assert proposal != values
            # Admit native shape independently; the real Runtime must reject scope/store.
            ReadinessStoreBinding(case.owner._incarnation, *proposal)
            attempts.append((values, proposal))
            try:
                return bind(runtime, proposal)
            except BaseException as error:
                errors.append(error)
                raise

        monkeypatch.setattr(
            owner_module._ReadinessRuntime, "_bind_store_identity", foreign_identity
        )
        assert case.owner.start().phase != "idle"
        assert len(attempts) == len(errors) == 1
        assert type(errors[0]) is ValueError
        assert str(errors[0]) == "READINESS_STORE_IDENTITY_DIFFERS"
        assert case.runtime._store_identity_values is None
        assert case.owner.store_binding() is None and case.proofs == 0
        assert case.constructor_error is None
    assert case.owner.status().primary_failure == "startup_failed"
    assert case.owner.status().cleanup_complete is True


def test_original_runtime_rejects_second_binding_before_host_publication(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        bind = owner_module._ReadinessRuntime._bind_store_identity
        attempts, errors = [], []

        def bind_twice(runtime, values):
            assert threading.current_thread() is case.owner._thread and runtime is case.runtime
            assert runtime._store_identity_values is None
            assert bind(runtime, values) is None
            attempts.append(values)
            assert runtime._store_identity_values == values
            try:
                return bind(runtime, values)
            except BaseException as error:
                errors.append(error)
                raise

        monkeypatch.setattr(owner_module._ReadinessRuntime, "_bind_store_identity", bind_twice)
        assert case.owner.start().phase != "idle"
        assert len(attempts) == len(errors) == 1
        assert type(errors[0]) is ValueError
        assert str(errors[0]) == "READINESS_STORE_IDENTITY_ALREADY_BOUND"
        assert case.runtime._store_identity_values == attempts[0]
        assert case.owner.store_binding() is None and case.proofs == 0
        assert case.constructor_error is None
    assert case.owner.status().cleanup_complete is True


def test_pre_factory_one_way_replacement_is_not_adopted_as_original_store(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        initialize = factory_module.ContinuousSimulationFactory.__init__
        project = configured_module._store_identity
        path = case.study.paths["database_path"]
        replacement = case.study.root / "exclusive-quiescent-account-copy.sqlite"
        replacements, projections, errors = [], [], []

        def replace_before_open(factory, *args, **kwargs):
            assert threading.current_thread() is case.owner._thread
            assert case.guard_entered and case.guard._descriptor is not None
            assert case.factory is None and case.acquires == [] and case.account_engine is None
            assert not Path(f"{path}-wal").exists() and not Path(f"{path}-shm").exists()
            before = path.stat()
            payload = path.read_bytes()
            study_module._exclusive_file(replacement, payload)
            copied = replacement.stat()
            assert copied.st_ino != before.st_ino and copied.st_dev == before.st_dev
            assert replacement.read_bytes() == payload
            # Setup engines are disposed and no factory connection exists yet.
            os.replace(replacement, path)
            after = path.stat()
            assert (after.st_dev, after.st_ino) == (copied.st_dev, copied.st_ino)
            assert path.read_bytes() == payload and not replacement.exists()
            replacements.append((before.st_dev, before.st_ino, after.st_dev, after.st_ino))
            return initialize(factory, *args, **kwargs)

        def observe_projection(factory, runtime, configuration, **kwargs):
            assert threading.current_thread() is case.owner._thread
            assert factory is case.factory and runtime is case.runtime
            assert len(replacements) == 1 and len(case.acquires) == 1
            before_device, before_inode, after_device, after_inode = replacements[0]
            assert kwargs["baseline"] == (str(path), before_device, before_inode)
            actual = path.stat()
            assert (actual.st_dev, actual.st_ino) == (after_device, after_inode)
            projections.append(kwargs["baseline"])
            try:
                return project(factory, runtime, configuration, **kwargs)
            except BaseException as error:
                errors.append(error)
                raise

        monkeypatch.setattr(
            factory_module.ContinuousSimulationFactory, "__init__", replace_before_open
        )
        monkeypatch.setattr(configured_module, "_store_identity", observe_projection)
        assert case.owner.start().phase != "idle"
        assert len(replacements) == len(projections) == len(errors) == 1
        assert type(errors[0]) is ValueError
        assert str(errors[0]) == "CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS"
        assert case.constructor_error is None and case.runtime is not None
        assert case.owner.store_binding() is None and case.proofs == 0
    # The replacement stays in this fresh namespace; the known returned R1 alone
    # is released by the original factory. No head adoption or guessed rescue.
    actual = path.stat()
    assert (actual.st_dev, actual.st_ino) == replacements[0][2:]
    assert case.owner.status().cleanup_complete is True
    assert len(case.acquires) == len(case.releases) == case.close_calls == 1
