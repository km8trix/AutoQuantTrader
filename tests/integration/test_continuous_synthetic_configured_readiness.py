"""Fresh configured readiness on the original owner thread, without HTTP.

Only new disposable migrated stores are loaded. Forwarding observers record the
real loader, factory, runtime, full verifier and cleanup; no proof is replaced.
Actual recovery UTC and original 60/5/10 lease policy are never retimed.
"""

import os
import threading
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine

from apps.trader import configured_readiness_owner as configured_module
from apps.trader import continuous_readiness_owner as owner_module
from apps.trader import continuous_simulation_factory as factory_module
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.database import DatabaseSchemaNotReady
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_scopes_closed,
    _seed_phase_zero,
)


def _observe(case, monkeypatch):
    load = configured_module.load_continuous_configuration
    initialize = factory_module.ContinuousSimulationFactory.__init__
    checkpoint = factory_module.ContinuousSimulationFactory._check_stop
    close = factory_module.ContinuousSimulationFactory.close
    execute = factory_module.ContinuousSimulationFactory.execute
    factory_read = SqlContinuousIntegrityReader.original_factory_read
    acquire = SqlAccountCoordinator.acquire
    release = SqlAccountCoordinator.release
    dispose = Engine.dispose
    enter_guard = LocalInstanceGuard.__enter__
    exit_guard = LocalInstanceGuard.__exit__
    initialize_runtime = owner_module._ReadinessRuntime.__init__
    verify = owner_module.verify_operational_schema

    def record(label):
        thread = threading.current_thread()
        assert thread is not case.caller_thread
        case.trace.append((label, thread))

    def load_configuration(path):
        record("load")
        assert path == case.configuration_path
        value = load(path)
        assert value == case.configuration
        return value

    def factory_init(factory, *args, **kwargs):
        record("factory")
        assert case.factory is None
        case.factory = factory
        try:
            return initialize(factory, *args, **kwargs)
        except BaseException as error:
            case.constructor_error = error
            raise

    def factory_checkpoint(factory):
        assert factory is case.factory
        case.checkpoints += 1
        if case.mode == "startup-stop" and case.checkpoints == 2:
            case.startup_entered.set()
            assert case.allow_startup.wait(12), "test did not release its startup barrier"
        return checkpoint(factory)

    def factory_close(factory):
        record("close")
        assert factory is case.factory
        case.close_calls += 1
        return close(factory)

    def execute_operation(factory, *args, **kwargs):
        case.executions += 1
        return execute(factory, *args, **kwargs)

    def factory_scope(reader, *args, **kwargs):
        case.factory_reads += 1
        return factory_read(reader, *args, **kwargs)

    def acquire_once(coordinator, owner_id):
        record("acquire")
        assert coordinator is case.factory.coordinator and case.acquires == []
        case.account_engine = case.factory.engine
        actual = acquire(coordinator, owner_id)
        case.acquires.append(actual)
        if case.mode == "unknown":
            assert case.factory.lease is None
            raise case.unknown_primary
        return actual

    def release_once(coordinator, fence):
        record("release")
        assert coordinator is case.factory.coordinator
        case.release_attempts.append(fence)
        result = release(coordinator, fence)
        case.releases.append(result)
        return result

    def engine_dispose(engine, *args, **kwargs):
        if engine is case.account_engine:
            label = "dispose-account"
        elif engine is case.venue_engine:
            label = "dispose-venue"
        else:
            return dispose(engine, *args, **kwargs)
        result = dispose(engine, *args, **kwargs)
        record(label)
        case.disposals.append(label)
        return result

    def guard_enter(guard):
        if threading.current_thread() is case.caller_thread:
            return enter_guard(guard)
        record("guard-enter")
        assert guard.path == case.lock_path
        case.guard = guard
        result = enter_guard(guard)
        info = os.fstat(guard.fileno())
        case.lock_identity = info.st_dev, info.st_ino
        case.guard_entered = True
        return result

    def guard_exit(guard, *args):
        if guard is not case.guard:
            return exit_guard(guard, *args)
        result = exit_guard(guard, *args)
        record("guard-exit")
        case.guard_exits += 1
        return result

    def runtime_init(runtime, **kwargs):
        record("runtime")
        assert case.runtime is None
        factory = case.factory
        assert kwargs["reader"] is factory.integrity
        assert kwargs["lease"] is factory.lease is case.acquires[0]
        assert kwargs["guard"] is case.guard
        assert kwargs["venue"] is factory.venue
        assert kwargs["venue_engine"] is factory.venue_engine
        case.venue_engine = factory.venue_engine
        case.stop_event = kwargs["stop_event"]
        result = initialize_runtime(runtime, **kwargs)
        case.runtime = runtime
        assert len(runtime.reader.journals) == 8
        assert all(journal._engine is case.account_engine for journal in runtime.reader.journals)
        assert runtime.reader.daily.producers is factory.runtime_sources
        assert factory.runtime_sources.operating.clock_sampler.profile == (
            "explicit_simulation_time_model"
        )
        assert factory.runtime_sources.forward_sources.evidence_class == "synthetic_fixture"
        return result

    def full_verify(engine, **kwargs):
        record("proof")
        assert engine is case.account_engine
        assert set(kwargs) == {"research_codec", "continuous_integrity"}
        assert kwargs["research_codec"] is personal_codec
        assert kwargs["continuous_integrity"] is case.runtime.reader
        case.proofs += 1
        try:
            return verify(engine, **kwargs)
        except BaseException as error:
            case.proof_errors.append(error)
            raise
        finally:
            _assert_scopes_closed(case.runtime.reader)

    monkeypatch.setattr(configured_module, "load_continuous_configuration", load_configuration)
    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "__init__", factory_init)
    monkeypatch.setattr(
        factory_module.ContinuousSimulationFactory, "_check_stop", factory_checkpoint
    )
    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "close", factory_close)
    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "execute", execute_operation)
    monkeypatch.setattr(SqlContinuousIntegrityReader, "original_factory_read", factory_scope)
    monkeypatch.setattr(SqlAccountCoordinator, "acquire", acquire_once)
    monkeypatch.setattr(SqlAccountCoordinator, "release", release_once)
    monkeypatch.setattr(Engine, "dispose", engine_dispose)
    monkeypatch.setattr(LocalInstanceGuard, "__enter__", guard_enter)
    monkeypatch.setattr(LocalInstanceGuard, "__exit__", guard_exit)
    monkeypatch.setattr(owner_module._ReadinessRuntime, "__init__", runtime_init)
    monkeypatch.setattr(owner_module, "verify_operational_schema", full_verify)


def _require_closed(case):
    status = case.owner.status()
    assert status.phase == "stopped"
    assert status.cleanup_complete is (case.mode != "unknown")
    assert status.cleanup_failure == ("cleanup_failed" if case.mode == "unknown" else None)
    assert not case.owner._thread.is_alive()
    assert case.executions == case.factory_reads == 0
    assert all(thread is case.owner._thread for _, thread in case.trace)
    if case.guard_entered:
        assert case.guard_exits == 1 and case.guard._descriptor is None
        labels = [label for label, _ in case.trace]
        assert labels[-1] == "guard-exit"
        if "close" in labels:
            assert labels.index("close") < labels.index("guard-exit")
    before, after = case.before, _snapshot(case.study)
    case.after = after
    assert after.financial == before.financial
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    if not case.acquires:
        assert after.leases == before.leases and after.releases == before.releases
        assert after.heads == before.heads
        assert case.release_attempts == [] and case.disposals == []
        assert case.factory is None
        return
    assert len(case.acquires) == 1 and case.close_calls == 1
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    added = [row for row in after.leases if row not in before.leases]
    actual = account_lease_from_row(added[0])
    assert actual == case.acquires[0]
    assert actual.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert actual.revision_number == 1 and actual.previous_lease_sha256 is None
    assert actual.policy_sha256 == case.configuration.lease_policy().semantic_sha256
    assert actual.expires_at - actual.acquired_at == case.configuration.lease_policy().lease_ttl
    assert case.disposals == (
        ["dispose-account"] if case.venue_engine is None else ["dispose-venue", "dispose-account"]
    )
    if case.mode == "unknown":
        assert case.release_attempts == [] and case.releases == []
        assert after.releases == before.releases
        assert after.heads[0] == {
            "account_id": actual.account_id,
            "last_fencing_generation": actual.fencing_generation,
            "current_fencing_generation": actual.fencing_generation,
            "current_lease_sha256": actual.semantic_sha256,
            "updated_at": added[0]["acquired_at"],
        }
        return
    assert case.release_attempts == [actual.fence] and len(case.releases) == 1
    labels = [label for label, _ in case.trace]
    assert labels.index("release") < labels.index("dispose-account")
    if case.venue_engine is not None:
        assert labels.index("release") < labels.index("dispose-venue")
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    released_row = next(row for row in after.releases if row not in before.releases)
    released = account_lease_release_from_row(released_row)
    assert released == case.releases[0]
    assert released.fence == actual.fence and released.lease_sha256 == actual.semantic_sha256
    assert actual.acquired_at <= released.released_at < actual.expires_at
    assert after.heads[0] == {
        "account_id": actual.account_id,
        "last_fencing_generation": actual.fencing_generation,
        "current_fencing_generation": None,
        "current_lease_sha256": None,
        "updated_at": released_row["released_at"],
    }


@contextmanager
def _case(tmp_path, monkeypatch, *, seed=True, changes=None, mode="normal"):
    with study_module._study(tmp_path) as study:
        configuration = study_module._export(study)
        if seed:
            _seed_phase_zero(study)
        if changes:
            configuration = replace(configuration, **changes)
        path = study.root / "configured-readiness.json"
        payload = personal_codec.encode_record(configuration)
        study_module._exclusive_file(path, payload)
        study_module._release_setup(study)
        assert study.lease is None
        before = _snapshot(study)
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()
        case = SimpleNamespace(
            study=study,
            configuration=configuration,
            configuration_path=path,
            configuration_bytes=payload,
            lock_path=study.root / "configured-readiness.lock",
            before=before,
            after=None,
            mode=mode,
            caller_thread=threading.current_thread(),
            trace=[],
            factory=None,
            constructor_error=None,
            checkpoints=0,
            close_calls=0,
            executions=0,
            factory_reads=0,
            acquires=[],
            release_attempts=[],
            releases=[],
            disposals=[],
            account_engine=None,
            venue_engine=None,
            runtime=None,
            stop_event=None,
            proofs=0,
            proof_errors=[],
            guard=None,
            guard_entered=False,
            guard_exits=0,
            lock_identity=None,
            startup_entered=threading.Event(),
            allow_startup=threading.Event(),
            unknown_primary=ValueError("private acquire return interrupted"),
            owner=None,
        )
        _observe(case, monkeypatch)
        case.owner = configured_module.create_configured_readiness_owner(
            configuration_path=str(path),
            account_id=study.genesis.scope.account_id,
            instance_lock=str(case.lock_path),
        )
        assert type(case.owner) is owner_module.ContinuousReadinessOwner
        assert case.owner._limits == owner_module.ReadinessOwnerLimits()
        assert case.owner.status().phase == "new"
        assert case.trace == [] and not case.lock_path.exists()
        assert _snapshot(study).__dict__ == before.__dict__
        assert path.read_bytes() == payload
        primary = None
        try:
            yield case
        except BaseException as error:
            primary = error
            raise
        finally:
            errors = []
            case.allow_startup.set()
            try:
                case.owner.stop()
            except BaseException as error:
                errors.append(error)
            thread = case.owner._thread
            if thread is not None:
                try:
                    thread.join(12)
                    assert not thread.is_alive(), "owner has not actually completed cleanup"
                except BaseException as error:
                    errors.append(error)
            if thread is not None and not thread.is_alive():
                try:
                    _require_closed(case)
                except BaseException as error:
                    errors.append(error)
            if errors:
                if primary is not None:
                    errors.insert(0, primary)
                raise BaseExceptionGroup(
                    "configured readiness and independent cleanup failed", errors
                )


def test_cold_configured_owner_runs_two_fresh_full_checks_for_the_same_request_id(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch) as case:
        assert case.owner.start().phase == "idle"
        assert case.owner.status().cleanup_complete is False
        first = case.owner.check("same-explicit-request")
        second = case.owner.check("same-explicit-request")
        assert first.status == second.status == "ready"
        assert first.reason == second.reason == "verified"
        assert first.request_id == second.request_id == "same-explicit-request"
        assert first.incarnation == second.incarnation == case.owner.status().incarnation
        assert first is not second and case.proofs == 2 and case.proof_errors == []
        assert _snapshot(case.study).financial == case.before.financial
        assert case.release_attempts == []
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


def test_cold_configured_owner_keeps_default_phase_zero_prerequisite(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, seed=False) as case:
        assert case.owner.start().phase == "idle"
        result = case.owner.check("missing-original-phase-zero")
        assert result.status == "unavailable"
        assert case.proofs == 1 and len(case.proof_errors) == 1
        assert type(case.proof_errors[0]) is DatabaseSchemaNotReady
    assert case.owner.status().primary_failure == "runtime_failed"


def test_held_configured_guard_denies_before_factory_or_acquisition(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case, LocalInstanceGuard(case.lock_path) as held:
        identity = os.fstat(held.fileno())
        assert case.owner.start().phase != "idle"
        assert case.owner.check("held-original-guard").status == "unavailable"
        assert case.factory is None and case.acquires == [] and case.proofs == 0
        assert os.fstat(held.fileno()).st_ino == identity.st_ino


@pytest.mark.parametrize(
    "changes",
    [
        {"operation": "integrity"},
        {"capture_evidence_class": "provider_https_read"},
        {"clock_profile": "host_unqualified"},
        {"lease_ttl_microseconds": 61_000_000},
    ],
    ids=["operation", "evidence", "clock", "lease"],
)
def test_unsupported_cold_profile_denies_before_factory_or_acquisition(
    tmp_path, monkeypatch, changes
):
    with _case(tmp_path, monkeypatch, changes=changes) as case:
        assert case.owner.start().phase != "idle"
        assert case.owner.check("unsupported-configured-profile").status == "unavailable"
        assert case.factory is None and case.acquires == [] and case.proofs == 0


def test_cold_acquisition_unknown_stops_incomplete_without_adopting_or_releasing(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="unknown") as case:
        assert case.owner.store_binding() is None
        assert case.owner.start().phase != "idle"
        assert case.owner.store_binding() is None
        assert case.owner.check("unknown-lease-completion").status == "unavailable"
        assert isinstance(case.constructor_error, BaseExceptionGroup)
        assert case.constructor_error.message == (
            "offline factory lease acquisition completion unknown"
        )
        assert case.constructor_error.exceptions == (case.unknown_primary,)
        assert case.proofs == 0 and case.runtime is None
    assert case.owner.status().cleanup_complete is False
    assert case.owner.store_binding() is None
    assert case.owner.start().phase == "stopped" and len(case.acquires) == 1
    # No test rescue. The original retained head remains in this disposable namespace.


def test_stop_during_original_cold_startup_releases_on_the_owner_thread(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, mode="startup-stop") as case:
        starts, errors = [], []

        def start():
            try:
                starts.append(case.owner.start())
            except BaseException as error:
                errors.append(error)

        caller = threading.Thread(target=start)
        caller.start()
        try:
            assert case.startup_entered.wait(10), "original returned-lease checkpoint not reached"
            stopped = case.owner.stop()
            assert stopped.phase == "stopping" and stopped.cleanup_complete is False
            assert case.owner.check("stopped-during-startup").status == "unavailable"
            assert case.proofs == 0 and case.release_attempts == []
        finally:
            case.allow_startup.set()
            caller.join(12)
            assert not caller.is_alive()
        assert errors == [] and len(starts) == 1
        assert starts[0].phase != "idle"
        assert case.runtime is None and case.proofs == 0
