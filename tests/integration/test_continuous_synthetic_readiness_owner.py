"""Actual fresh SQL proof on its owner thread; no host, HTTP or active authority.

Only the test's observation wrapper surrounds the ORIGINAL schema verifier.
Financial algorithms, runtime admission and the private runtime class are real.
All clocks used by the financial fixture remain explicitly modeled.
"""

import copy
import os
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, timedelta
from hashlib import sha256
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from apps.trader import continuous_readiness_owner as owner_module
from packages.application import personal_codec
from packages.application.personal_runtime import DuplicateRuntimeError, LocalInstanceGuard
from packages.persistence.database import DatabaseSchemaNotReady
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_held,
    _assert_initial_state,
    _assert_released,
    _assert_scopes_closed,
    _facts,
    _reader,
    _seed_phase_zero,
)


def _lease_rows(study):
    with study.ports["account_engine"].connect() as connection:
        return tuple(
            tuple(
                dict(row)
                for row in connection.execute(
                    sa.select(table).order_by(*table.primary_key.columns)
                ).mappings()
            )
            for table in (
                phase2_account_leases,
                phase2_account_lease_releases,
                phase2_account_lease_heads,
            )
        )


def _except_lease_head(facts):
    account, venue, objects = facts
    return (
        tuple((name, rows) for name, rows in account if name != phase2_account_lease_heads.name),
        venue,
        objects,
    )


def _except_lease_lifecycle(facts):
    account, venue, objects = facts
    names = {
        phase2_account_leases.name,
        phase2_account_lease_releases.name,
        phase2_account_lease_heads.name,
    }
    return tuple((name, rows) for name, rows in account if name not in names), venue, objects


def _assert_private_runtime_identity(runtime, study, model):
    before = _facts(study)
    copied = copy.copy(runtime)
    with pytest.raises(ValueError, match=r"^READINESS_ORIGINAL_RUNTIME_CHANGED$"):
        _ = copied.lease_deadline_ns
    outcome = []

    def foreign():
        try:
            _ = runtime.lease_deadline_ns
        except BaseException as error:
            outcome.append(error)

    thread = threading.Thread(target=foreign)
    thread.start()
    thread.join(2)
    assert not thread.is_alive()
    assert len(outcome) == 1 and type(outcome[0]) is ValueError
    assert outcome[0].args == ("READINESS_ORIGINAL_RUNTIME_CHANGED",)
    replacements = (
        ("reader", copy.copy(runtime.reader)),
        ("lease", replace(runtime.lease)),
        ("guard", LocalInstanceGuard(model.lock_path)),
        ("venue_engine", runtime.reader.engine),
        ("stop_event", threading.Event()),
    )
    for field, replacement in replacements:
        original = getattr(runtime, field)
        setattr(runtime, field, replacement)
        try:
            with pytest.raises(ValueError, match=r"^READINESS_ORIGINAL_RUNTIME_CHANGED$"):
                _ = runtime.lease_deadline_ns
        finally:
            setattr(runtime, field, original)
    assert type(runtime.lease_deadline_ns) is int
    assert model.proof_count == 0
    assert _facts(study) == before


@pytest.fixture
def fresh_owner(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    caller_thread = threading.current_thread()
    model = SimpleNamespace(
        mode="normal",
        installed=False,
        thread=None,
        owner=None,
        stop_event=None,
        trace=[],
        engine_ids=(),
        proof_count=0,
        proof_equal=[],
        proof_completed=threading.Event(),
        deliver=threading.Event(),
        release_attempts=0,
        cleanup_started=threading.Event(),
        context_exited=threading.Event(),
        guard_exited=threading.Event(),
        cleanup_rows=None,
        cleanup_facts=None,
        observation_error=None,
        original_failure=None,
        fault_facts=None,
        fault_rows=None,
        caller=None,
        caller_completed=threading.Event(),
        caller_results=[],
    )
    model.deliver.set()
    active = [None]
    original_verify = owner_module.verify_operational_schema
    original_release_setup = study_module._release_setup
    original_dispose = Engine.dispose
    lock_path = tmp_path / "readiness-owner.lock"
    model.lock_path = lock_path

    def dispose(engine, *args, **kwargs):
        # Migration also owns a short-lived engine. Record only the two
        # retained graph engines, so a later Python id reuse cannot alias it.
        if id(engine) in model.engine_ids:
            model.trace.append(("dispose", threading.current_thread(), id(engine)))
        return original_dispose(engine, *args, **kwargs)

    def release_setup(study):
        assert threading.current_thread() is model.thread
        model.release_attempts += 1
        model.trace.append(("release", threading.current_thread(), None))
        model.cleanup_started.set()
        lease = study.lease
        try:
            return original_release_setup(study)
        finally:
            # Keep the original primary release failure even if observation
            # itself fails; pytest separately checks this test-only recorder.
            try:
                model.cleanup_rows = _lease_rows(study)
                model.cleanup_facts = _facts(study)
                if model.mode not in ("expired", "renewed"):
                    _assert_released(study, lease)
            except BaseException as error:
                model.observation_error = error

    def verify(engine, **kwargs):
        study = active[0]
        assert study is not None
        assert threading.current_thread() is model.thread
        assert id(engine) == model.engine_ids[0]
        assert set(kwargs) == {"research_codec", "continuous_integrity"}
        assert kwargs["research_codec"] is personal_codec
        assert id(kwargs["continuous_integrity"]) == model.reader_id
        # In particular there is no False phase-zero flag, alternate revision,
        # provisional factory scope, cached snapshot or replacement validator.
        model.trace.append(("proof", threading.current_thread(), id(engine)))
        model.proof_count += 1
        before = _facts(study)
        if model.mode == "damaged":
            reference = study.genesis.restored.receipt.commit.source_evidence.object_ref
            original = study.ports["account_artifacts"].read(reference)
            assert original and len(original) == reference.byte_count
            assert sha256(original).hexdigest() == reference.object_sha256
            target = study.paths["artifact_root"] / (reference.object_sha256 + ".json")
            assert target.read_bytes() == original
            damaged = original[:-1] + bytes((original[-1] ^ 1,))
            assert damaged != original and len(damaged) == reference.byte_count
            assert target.write_bytes(damaged) == reference.byte_count
            before = model.fault_facts = _facts(study)
        try:
            result = original_verify(engine, **kwargs)
        except DatabaseSchemaNotReady as error:
            model.original_failure = error.args
            raise
        finally:
            model.proof_equal.append(_facts(study) == before)
            _assert_scopes_closed(kwargs["continuous_integrity"])
        assert result is None
        if model.mode == "expired":
            model.expired_at = study.lease.expires_at + timedelta(microseconds=1)
            study.ports["clock"].advance_to(model.expired_at)
            model.fault_facts, model.fault_rows = _facts(study), _lease_rows(study)
        elif model.mode == "renewed":
            original_lease = study.lease
            study.ports["clock"].advance_to(
                study.ports["clock"].now() + timedelta(milliseconds=500)
            )
            renewed = study.genesis.account.coordinator.renew(original_lease.fence)
            assert renewed.fence == original_lease.fence
            assert renewed.revision_number == original_lease.revision_number + 1
            assert renewed.semantic_sha256 != original_lease.semantic_sha256
            model.renewed_digest = renewed.semantic_sha256
            model.original_digest = original_lease.semantic_sha256
            # Only the fixture's natural cleanup follows the actual new revision.
            # The runtime's captured R1 object is deliberately never replaced.
            study.lease = renewed
            model.fault_facts, model.fault_rows = _facts(study), _lease_rows(study)
        model.proof_completed.set()
        if model.mode == "late":
            assert model.deliver.wait(8), "controlled post-proof barrier was not released"
        return result

    @contextmanager
    def open_runtime(stop_event):
        model.thread = threading.current_thread()
        model.stop_event = stop_event
        model.trace.append(("construct", model.thread, None))
        assert model.thread is not caller_thread
        try:
            with LocalInstanceGuard(lock_path) as guard:
                model.trace.append(("guard-enter", threading.current_thread(), None))
                held = os.fstat(guard.fileno())
                model.lock_identity = held.st_dev, held.st_ino
                with study_module._study(tmp_path, install=model.installed) as study:
                    active[0] = study
                    model.engine_ids = tuple(
                        id(study.ports[name]) for name in ("account_engine", "venue_engine")
                    )
                    _seed_phase_zero(study)
                    _assert_initial_state(study, installed=model.installed)
                    _assert_held(study, study.lease)
                    reader = _reader(study)
                    _assert_scopes_closed(reader)
                    model.reader_id = id(reader)
                    model.startup_digest = study.genesis.lease.semantic_sha256
                    model.caller_digest = study.lease.semantic_sha256
                    runtime = owner_module._ReadinessRuntime(
                        reader=reader,
                        lease=study.lease,
                        guard=guard,
                        venue=study.genesis.venue,
                        venue_engine=study.ports["venue_engine"],
                        stop_event=stop_event,
                    )
                    if model.mode == "normal":
                        _assert_private_runtime_identity(runtime, study, model)
                    model.initial_facts = _facts(study)
                    try:
                        yield runtime
                    finally:
                        assert threading.current_thread() is model.thread
                        _assert_scopes_closed(reader)
                        model.before_release_facts = _facts(study)
                        model.before_release_rows = _lease_rows(study)
                        model.trace.append(("context-exit", threading.current_thread(), None))
                        model.context_exited.set()
                active[0] = None
        finally:
            active[0] = None
            model.trace.append(("guard-exit", threading.current_thread(), None))
            model.guard_exited.set()

    monkeypatch.setattr(Engine, "dispose", dispose)
    monkeypatch.setattr(study_module, "_release_setup", release_setup)
    monkeypatch.setattr(owner_module, "verify_operational_schema", verify)

    def create():
        owner = owner_module.ContinuousReadinessOwner(_open_runtime=open_runtime)
        model.owner = owner
        return owner

    model.create = create
    yield model
    model.deliver.set()
    if model.owner is not None:
        model.owner.stop()
    if model.caller is not None:
        model.caller.join(8)
        assert not model.caller.is_alive()
    if model.thread is not None:
        model.thread.join(8)
        assert not model.thread.is_alive()
    if model.observation_error is not None:
        raise model.observation_error


def _finished(model, *, cleanup=True):
    model.owner.stop()
    model.thread.join(8)
    assert not model.thread.is_alive()
    status = model.owner.status()
    assert status.phase == "stopped"
    assert status.cleanup_complete is cleanup
    assert model.context_exited.is_set() and model.guard_exited.is_set()
    assert model.release_attempts == 1
    assert model.proof_equal and all(model.proof_equal)
    assert all(thread is model.thread for _kind, thread, _identity in model.trace)
    for engine_id in model.engine_ids:
        assert (
            sum(
                kind == "dispose" and identity == engine_id
                for kind, _thread, identity in model.trace
            )
            == 1
        )
    names = [kind for kind, _thread, _identity in model.trace]
    assert names.index("context-exit") < names.index("release")
    assert names.index("release") < min(
        index for index, kind in enumerate(names) if kind == "dispose"
    )
    assert max(index for index, kind in enumerate(names) if kind == "dispose") < names.index(
        "guard-exit"
    )
    assert model.observation_error is None
    assert _except_lease_lifecycle(model.cleanup_facts) == _except_lease_lifecycle(
        model.before_release_facts
    )
    before_leases, before_releases, _before_heads = model.before_release_rows
    leases, releases, _heads = model.cleanup_rows
    assert leases == before_leases
    assert all(row in releases for row in before_releases)
    # A real same-inode acquisition after actual join proves the original guard
    # was released; a terminal status alone is insufficient evidence.
    with LocalInstanceGuard(model.lock_path) as guard:
        metadata = os.fstat(guard.fileno())
        assert (metadata.st_dev, metadata.st_ino) == model.lock_identity
    return status


@pytest.mark.parametrize("installed", [False, True], ids=["empty_b", "disabled_generation1"])
def test_owner_thread_runs_full_readiness_without_financial_changes(fresh_owner, installed):
    model = fresh_owner
    model.installed = installed
    owner = model.create()
    assert owner.start().phase == "idle"
    assert model.thread.is_alive() and not owner.status().cleanup_complete
    result = owner.check("same-request-id")
    assert (result.status, result.reason) == ("ready", "verified")
    if installed:
        repeated = owner.check("same-request-id")
        assert repeated is not result and repeated.status == "ready"
        assert repeated.incarnation == result.incarnation
    assert model.proof_count == (2 if installed else 1)
    status = _finished(model)
    assert status.primary_failure is None and status.cleanup_failure is None
    assert model.before_release_facts == model.initial_facts


def test_owner_denies_genuine_object_damage_through_original_full_verifier(fresh_owner):
    model = fresh_owner
    model.mode = "damaged"
    owner = model.create()
    assert owner.start().phase == "idle"
    result = owner.check("damaged-object")
    assert result.status == "unavailable" and result.reason == "runtime_failed"
    status = _finished(model)
    assert status.primary_failure == "runtime_failed" and status.cleanup_failure is None
    assert model.original_failure == ("continuous retained integrity verification failed",)
    assert model.proof_count == 1
    assert model.fault_facts != model.initial_facts
    assert model.before_release_facts == model.fault_facts


def test_caller_timeout_keeps_actual_owner_busy_and_cannot_deliver_late_pass(fresh_owner):
    model = fresh_owner
    model.mode = "late"
    model.deliver.clear()
    owner = model.create()
    assert owner.start().phase == "idle"

    def check():
        try:
            model.caller_results.append(owner.check("late-original-proof"))
        finally:
            model.caller_completed.set()

    model.caller = threading.Thread(target=check)
    model.caller.start()
    assert model.proof_completed.wait(5), "original full proof did not reach the controlled barrier"
    assert model.caller_completed.wait(7)
    assert len(model.caller_results) == 1
    abandoned = model.caller_results[0]
    assert abandoned.status == "unavailable" and abandoned.reason == "deadline"
    assert owner.status().phase == "busy" and owner.status().busy
    assert not owner.status().cleanup_complete and model.thread.is_alive()
    assert not model.stop_event.is_set()
    assert not model.cleanup_started.is_set() and not model.context_exited.is_set()
    assert owner.check("must-not-queue").reason == "busy"
    with pytest.raises(DuplicateRuntimeError), LocalInstanceGuard(model.lock_path):
        pytest.fail("abandoned caller must not release the owner's real lock")
    model.deliver.set()
    _finished(model)
    assert model.caller_results == [abandoned] and abandoned.status == "unavailable"
    assert model.proof_count == 1
    assert model.before_release_facts == model.initial_facts


def test_expired_original_release_retains_head_without_false_cleanup_success(fresh_owner):
    model = fresh_owner
    model.mode = "expired"
    owner = model.create()
    assert owner.start().phase == "idle"
    assert owner.check("expire-after-original-proof").status == "unavailable"
    status = _finished(model, cleanup=False)
    assert status.primary_failure == "runtime_failed"
    assert status.cleanup_failure == "cleanup_failed"
    assert model.proof_count == 1
    before_leases, before_releases, before_heads = model.fault_rows
    leases, releases, heads = model.cleanup_rows
    assert leases == before_leases and releases == before_releases
    assert len(leases) == 2 and len(releases) == 1
    assert releases[0]["lease_sha256"] == model.startup_digest
    assert heads[0]["current_lease_sha256"] == model.caller_digest
    assert heads[0]["current_fencing_generation"] == 2
    assert {key: value for key, value in heads[0].items() if key != "updated_at"} == {
        key: value for key, value in before_heads[0].items() if key != "updated_at"
    }
    assert heads[0]["updated_at"].replace(tzinfo=UTC) == model.expired_at
    assert _except_lease_head(model.before_release_facts) == _except_lease_head(model.fault_facts)
    assert _except_lease_head(model.cleanup_facts) == _except_lease_head(model.fault_facts)


def test_real_same_fence_renewal_is_not_adopted_as_original_runtime_lease(fresh_owner):
    model = fresh_owner
    model.mode = "renewed"
    owner = model.create()
    assert owner.start().phase == "idle"
    assert owner.check("same-fence-new-revision").status == "unavailable"
    status = _finished(model)
    assert status.primary_failure == "runtime_failed" and status.cleanup_failure is None
    assert model.proof_count == 1
    assert model.before_release_facts == model.fault_facts
    before_leases, before_releases, _before_heads = model.fault_rows
    leases, releases, heads = model.cleanup_rows
    assert leases == before_leases and len(leases) == 3
    assert len(before_releases) == 1 and len(releases) == 2
    assert {row["lease_sha256"] for row in releases} == {model.startup_digest, model.renewed_digest}
    assert model.original_digest not in {row["lease_sha256"] for row in releases}
    released = next(row for row in releases if row["lease_sha256"] == model.renewed_digest)
    renewed = next(row for row in leases if row["lease_sha256"] == model.renewed_digest)
    assert released["owner_id"] == renewed["owner_id"]
    assert released["lease_id"] == renewed["lease_id"]
    assert released["fencing_generation"] == renewed["fencing_generation"]
    assert released["policy_sha256"] == renewed["policy_sha256"]
    assert heads[0]["last_fencing_generation"] == 2
    assert heads[0]["current_fencing_generation"] is None
    assert heads[0]["current_lease_sha256"] is None
