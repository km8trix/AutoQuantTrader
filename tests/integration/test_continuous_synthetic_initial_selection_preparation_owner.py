"""Actual configured preparation through its single original owner thread.

Only fresh private migrated fixtures are used. The host opens G itself; no
Runtime, preparation object, context or financial proof is injected. Test-owned
barriers demonstrate caller abandonment while original work still owns effects.
"""

import os
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

from sqlalchemy import Engine

from apps.trader import continuous_simulation_factory as factory_module
from apps.trader.continuous_readiness_owner import ReadinessOwnerLimits
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    copy_initial_selection_descriptor,
    initial_selection_request_data,
)
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationOwnerStatus,
    InitialSelectionPreparationResult,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.runtime_owner_dependency_contracts import (
    MAX_OWNER_DEPENDENCIES_BYTES,
    OWNER_DEPENDENCIES_SCHEMA,
)
from packages.persistence.account_coordinator import (
    account_lease_from_row,
    account_lease_release_from_row,
)
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_configured_readiness import _observe
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_initial_state,
    _seed_phase_zero,
)
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _configuration,
    _retained_record,
    _same_application_facts,
)
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _require_closed as _require_original_lifecycle,
)


def _observe_effects(case, monkeypatch):
    put = LocalResearchArtifactStore.put
    dispose = Engine.dispose
    close = factory_module.ContinuousSimulationFactory.close
    guard_exit = LocalInstanceGuard.__exit__

    def actual_put(store, payload, **kwargs):
        reference = put(store, payload, **kwargs)
        if case.runtime is None or store is not case.runtime.reader.account.artifacts:
            return reference
        assert threading.current_thread() is case.owner._thread
        assert len(case.puts) == 0 and kwargs["max_bytes"] == MAX_OWNER_DEPENDENCIES_BYTES
        assert (store._root / (reference.object_sha256 + ".json")).read_bytes() == payload
        case.puts.append((reference, payload))
        case.put_seen.set()
        if case.mode in ("put-failure", "cleanup-failure"):
            raise case.primary
        if case.mode in ("cancelled", "deadline", "stop-cutoff"):
            assert case.allow_put.wait(15), "test did not release its actual put barrier"
        return reference

    def actual_dispose(engine, *args, **kwargs):
        returned = dispose(engine, *args, **kwargs)
        if engine is case.venue_engine and case.mode == "cleanup-failure":
            # The saved observer has recorded the original disposal's return.
            # This outer wrapper deliberately fails; factory.close does not
            # return successfully, although its finally still disposes account.
            case.failed_disposals.append((engine, case.cleanup_primary))
            raise case.cleanup_primary
        return returned

    def actual_close(factory):
        try:
            returned = close(factory)
        except BaseException as error:
            case.close_errors.append(error)
            raise
        case.close_returns.append(returned)
        return returned

    def actual_guard_exit(guard, kind, primary, traceback):
        if guard is case.guard:
            case.guard_primaries.append(primary)
        returned = guard_exit(guard, kind, primary, traceback)
        if guard is case.guard:
            case.guard_exited.set()
        return returned

    monkeypatch.setattr(LocalResearchArtifactStore, "put", actual_put)
    monkeypatch.setattr(Engine, "dispose", actual_dispose)
    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "close", actual_close)
    monkeypatch.setattr(LocalInstanceGuard, "__exit__", actual_guard_exit)


def _require_no_entry(case):
    assert case.admitted is None and case.runtime is None and case.factory is None
    assert case.acquires == case.release_attempts == case.releases == []
    assert case.puts == case.disposals == case.close_returns == case.close_errors == []
    assert case.close_calls == case.proofs == case.executions == case.factory_reads == 0
    assert not case.guard_entered and case.guard_exits == 0
    assert _snapshot(case.study).__dict__ == case.before.__dict__
    assert case.configuration_path.read_bytes() == case.configuration_bytes


def _require_idle_lifecycle(case):
    """No dispatch: exact native lease lifecycle with zero new object allowance."""
    assert case.runtime is not None and case.admitted is not None
    assert case.puts == [] and case.proofs == 0
    assert case.executions == case.factory_reads == 0
    assert case.close_calls == 1 and case.constructor_error is None
    assert case.disposals == ["dispose-venue", "dispose-account"]
    assert all(thread is case.thread for _, thread in case.trace)
    assert case.guard_exits == 1 and case.guard._descriptor is None
    labels = [label for label, _ in case.trace]
    assert labels[-1] == "guard-exit"
    assert labels.index("close") < labels.index("release")
    assert labels.index("release") < labels.index("dispose-venue")
    assert labels.index("dispose-account") < labels.index("guard-exit")
    before, after = case.before, _snapshot(case.study)
    assert _same_application_facts(before, case.admitted) == {}
    assert _same_application_facts(case.admitted, after) == {}
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    assert len(case.acquires) == len(case.releases) == 1
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    added = next(row for row in after.leases if row not in before.leases)
    lease = account_lease_from_row(added)
    assert lease == case.acquires[0]
    assert lease.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert lease.revision_number == 1 and lease.previous_lease_sha256 is None
    policy = case.configuration.lease_policy()
    assert lease.policy_sha256 == policy.semantic_sha256
    assert lease.expires_at - lease.acquired_at == policy.lease_ttl
    assert before.heads[0]["current_lease_sha256"] is None
    assert before.heads[0]["current_fencing_generation"] is None
    assert case.admitted.leases == after.leases and case.admitted.releases == before.releases
    assert case.admitted.heads == (
        {
            "account_id": lease.account_id,
            "last_fencing_generation": lease.fencing_generation,
            "current_fencing_generation": lease.fencing_generation,
            "current_lease_sha256": lease.semantic_sha256,
            "updated_at": case.admitted.heads[0]["updated_at"],
        },
    )
    assert case.admitted.heads[0]["updated_at"] >= added["acquired_at"]
    assert case.release_attempts == [lease.fence]
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    released_row = next(row for row in after.releases if row not in before.releases)
    released = account_lease_release_from_row(released_row)
    assert released == case.releases[0]
    assert released.fence == lease.fence and released.lease_sha256 == lease.semantic_sha256
    assert lease.acquired_at <= released.released_at < lease.expires_at
    assert after.heads == (
        {
            "account_id": lease.account_id,
            "last_fencing_generation": lease.fencing_generation,
            "current_fencing_generation": None,
            "current_lease_sha256": None,
            "updated_at": released_row["released_at"],
        },
    )
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


def _require_closed(case):
    status = case.owner.status()
    assert type(status) is InitialSelectionPreparationOwnerStatus
    assert status.phase == "stopped" and status.busy is False
    assert status.incarnation == case.incarnation
    assert case.owner._thread is case.thread and not case.thread.is_alive()
    if case.mode == "held-guard":
        assert status.cleanup_complete is True and status.cleanup_failure is None
        assert status.attempted is False
        _require_no_entry(case)
        return
    if case.mode == "idle-expiry":
        assert status.cleanup_complete is True and status.cleanup_failure is None
        assert status.attempted is False
        assert case.close_returns == case.releases and len(case.close_returns) == 1
        assert case.close_errors == case.failed_disposals == []
        _require_idle_lifecycle(case)
        return
    # The unchanged E oracle independently checks both native baselines, every
    # application/venue row, retained objects, actual R1/release/head, original
    # returned disposal effects, guard exit/reacquisition and the dead Thread.
    _require_original_lifecycle(case)
    assert status.attempted is True
    if case.mode == "cleanup-failure":
        assert status.cleanup_complete is False and status.cleanup_failure == "cleanup_failed"
        assert case.close_returns == [] and case.close_errors == [case.cleanup_primary]
        assert case.failed_disposals == [(case.venue_engine, case.cleanup_primary)]
        assert len(case.guard_primaries) == 1
        group = case.guard_primaries[0]
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert group.exceptions == (case.primary, case.cleanup_primary)
        assert case.owner._primary_error is case.primary
        assert case.owner._context_error is group
    else:
        assert status.cleanup_complete is True and status.cleanup_failure is None
        assert case.close_returns == case.releases and len(case.close_returns) == 1
        assert case.close_errors == case.failed_disposals == []


@contextmanager
def _host_case(tmp_path, monkeypatch, *, mode="success", limits=None):
    with study_module._study(tmp_path, install=mode == "selected") as study:
        _assert_initial_state(study, installed=mode == "selected")
        daily = study.owners.daily.resolve_snapshot(
            study.owners.daily.read_snapshot(
                account_id=study.genesis.scope.account_id, fence=study.lease.fence
            )
        )
        configuration = _configuration(study)
        _seed_phase_zero(study)
        path = study.root / "preparation-owner.json"
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
            lock_path=study.root / "preparation-owner.lock",
            before=before,
            admitted=None,
            after=None,
            setup_daily=daily,
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
            unknown_primary=None,
            owner=None,
            thread=None,
            incarnation=None,
            puts=[],
            put_seen=threading.Event(),
            allow_put=threading.Event(),
            primary=RuntimeError("test original dependency put returned then failed"),
            cleanup_primary=RuntimeError("test original venue disposal returned then failed"),
            failed_disposals=[],
            close_returns=[],
            close_errors=[],
            guard_primaries=[],
            guard_exited=threading.Event(),
            waiter=None,
            waiter_done=threading.Event(),
            waiter_results=[],
            waiter_errors=[],
        )
        _observe(case, monkeypatch)
        _observe_effects(case, monkeypatch)
        options = {} if limits is None else {"limits": limits}
        case.owner = InitialSelectionPreparationOwner(
            configuration_path=str(path),
            account_id=study.genesis.scope.account_id,
            instance_lock=str(case.lock_path),
            **options,
        )
        assert type(case.owner) is InitialSelectionPreparationOwner
        status = case.owner.status()
        assert type(status) is InitialSelectionPreparationOwnerStatus
        case.incarnation = status.incarnation
        assert status.phase == "new" and status.busy is False and status.attempted is False
        assert case.owner._thread is None
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
            # Only test barriers are released here; the host/G owns its sole
            # close/release. No factory.close, guessed release, retry or rescue.
            case.allow_put.set()
            case.allow_startup.set()
            failures = []
            try:
                case.owner.stop()
            except BaseException as error:
                failures.append(error)
            if case.waiter is not None:
                case.waiter.join(20)
                if case.waiter.is_alive():
                    failures.append(AssertionError("preparation caller has not returned"))
            thread = case.owner._thread
            case.thread = thread
            if thread is not None:
                thread.join(20)
                if thread.is_alive():
                    failures.append(AssertionError("original owner thread has not exited"))
                else:
                    try:
                        _require_closed(case)
                    except BaseException as error:
                        failures.append(error)
            failures.extend(error for error in case.waiter_errors if error is not primary)
            if failures:
                if primary is not None:
                    failures.insert(0, primary)
                raise BaseExceptionGroup(
                    "preparation host test and original cleanup failed", failures
                )


def _start(case):
    status = case.owner.start()
    assert type(status) is InitialSelectionPreparationOwnerStatus
    assert status.phase == "idle" and status.busy is False and status.attempted is False
    assert status.cleanup_complete is False and status.incarnation == case.incarnation
    case.thread = case.owner._thread
    assert case.thread is not None and case.thread.is_alive()
    assert case.runtime is not None and case.stop_event is case.owner._stop_event
    # Public idle means original G entry and exact E construction have returned.
    # No preparation has been submitted, and the worker remains idle during this
    # caller's independent read-only snapshot. No pinned method is replaced.
    case.admitted = _snapshot(case.study)
    assert _same_application_facts(case.before, case.admitted) == {}
    assert case.proofs == 0 and case.puts == [] and case.close_calls == 0
    return status


def _unavailable(case, result, call_id, reason=None):
    assert type(result) is InitialSelectionPreparationResult
    assert result.status == "unavailable" and result.descriptor is None
    assert result.call_id == call_id and result.incarnation == case.incarnation
    if reason is not None:
        assert result.reason == reason


def _success(case, *, call_id="same-correlation-id"):
    started = time.monotonic_ns()
    result = case.owner.prepare_initial_selection(call_id)
    elapsed = time.monotonic_ns() - started
    assert type(result) is InitialSelectionPreparationResult
    assert result.status == result.reason == "prepared"
    assert result.call_id == call_id and result.incarnation == case.incarnation
    assert type(result.descriptor) is InitialSelectionDescriptor
    assert 0 <= elapsed < 5_000_000_000
    status = case.owner.status()
    assert status.phase == "idle" and status.busy is False and status.attempted is True
    assert status.cleanup_complete is False and case.owner._thread.is_alive()
    assert case.close_calls == 0 and case.release_attempts == []
    assert case.proofs == 2 and len(case.puts) == 1 and case.proof_errors == []
    reference, record = _retained_record(case)
    original = copy_initial_selection_descriptor(result.descriptor)
    scope, heads, evidence = initial_selection_request_data(original)
    assert scope == record.scope and heads == record.heads
    assert evidence == ContinuousEvidenceRef(
        OWNER_DEPENDENCIES_SCHEMA, reference, record.semantic_sha256
    )
    assert original.after_assignment_sha256 == record.proposed.semantic_sha256
    assert original.checked_at == record.checked_at and original.valid_until == record.valid_until
    assert original.c1_receipt_sha256 == record.previous.semantic_sha256
    assert original.control_sha256 == record.control_sha256
    assert original.original_lease_sha256 == record.fence.lease_sha256
    object.__setattr__(result.descriptor, "dependency_semantic_sha256", "0" * 64)
    assert original.dependency_semantic_sha256 == record.semantic_sha256
    counts = case.proofs, len(case.puts)
    for repeated in (call_id, "different-correlation-id"):
        _unavailable(
            case, case.owner.prepare_initial_selection(repeated), repeated, "already_attempted"
        )
    assert (case.proofs, len(case.puts)) == counts == (2, 1)
    # A mutated exported DTO cannot affect the actual immutable object. There is
    # deliberately no public history getter or successful same-ID replay.
    assert _retained_record(case)[1] == record


def _launch_call(case, *, call_id="held-call", cancel_event=None):
    def call():
        try:
            case.waiter_results.append(
                case.owner.prepare_initial_selection(call_id, cancel_event=cancel_event)
            )
        except BaseException as error:
            case.waiter_errors.append(error)
        finally:
            case.waiter_done.set()

    assert case.waiter is None
    case.waiter = threading.Thread(target=call, name="fresh-preparation-caller")
    case.waiter.start()


def _join_call(case):
    case.waiter.join(10)
    assert not case.waiter.is_alive() and case.waiter_done.is_set()
    if case.waiter_errors:
        raise case.waiter_errors[0]
    assert len(case.waiter_results) == 1
    return case.waiter_results[0]


def _held_work(case):
    assert case.put_seen.wait(15), "actual dependency put did not reach its test barrier"
    status = case.owner.status()
    assert status.busy is True and status.attempted is True
    assert status.cleanup_complete is False and case.owner._thread.is_alive()
    assert case.close_calls == 0 and case.release_attempts == case.releases == []
    assert len(case.puts) == 1 and case.proofs == 1
    assert len(_same_application_facts(case.admitted, _snapshot(case.study))) == 1


def _stop_and_join(case):
    case.owner.stop()
    case.owner._thread.join(20)
    assert not case.owner._thread.is_alive()
    return case.owner.status()


def test_actual_configured_empty_b_host_prepares_once_and_releases_original_r1(
    tmp_path, monkeypatch
):
    with _host_case(tmp_path, monkeypatch) as case:
        _start(case)
        _success(case)
        status = _stop_and_join(case)
        assert status.phase == "stopped" and status.cleanup_complete is True
        counts = case.proofs, len(case.puts), case.close_calls
        _unavailable(
            case,
            case.owner.prepare_initial_selection("same-correlation-id"),
            "same-correlation-id",
            "stopped",
        )
        assert (case.proofs, len(case.puts), case.close_calls) == counts == (2, 1, 1)


def test_actual_held_guard_denies_host_startup_without_factory_or_retry(tmp_path, monkeypatch):
    with (
        _host_case(tmp_path, monkeypatch, mode="held-guard") as case,
        LocalInstanceGuard(case.lock_path),
    ):
        status = case.owner.start()
        assert status.phase != "idle"
        case.thread = case.owner._thread
        assert case.thread is not None
        status = _stop_and_join(case)
        assert status.phase == "stopped" and status.primary_failure == "startup_failed"
        trace = tuple(case.trace)
        assert case.owner.start().phase == "stopped"
        assert tuple(case.trace) == trace
        _unavailable(
            case,
            case.owner.prepare_initial_selection("never-dispatch"),
            "never-dispatch",
            "stopped",
        )
        _require_no_entry(case)


def test_actual_selected_b_host_denies_before_dependency_put(tmp_path, monkeypatch):
    with _host_case(tmp_path, monkeypatch, mode="selected") as case:
        _start(case)
        result = case.owner.prepare_initial_selection("selected-b")
        _unavailable(case, result, "selected-b", "preparation_failed")
        status = _stop_and_join(case)
        assert status.attempted is True and status.primary_failure == "preparation_failed"
        assert type(case.owner._primary_error) is ValueError
        assert str(case.owner._primary_error) == "INITIAL_SELECTION_PREPARATION_REQUIRES_EMPTY_B"
        assert case.proofs == 1 and case.puts == []


def test_actual_put_primary_is_retained_privately_with_original_cleanup(tmp_path, monkeypatch):
    with _host_case(tmp_path, monkeypatch, mode="put-failure") as case:
        _start(case)
        result = case.owner.prepare_initial_selection("put-failure")
        _unavailable(case, result, "put-failure", "preparation_failed")
        status = _stop_and_join(case)
        assert status.cleanup_complete is True and status.primary_failure == "preparation_failed"
        assert case.owner._primary_error is case.primary
        assert case.guard_primaries == [case.primary]
        assert case.proofs == 1 and len(case.puts) == 1
        _retained_record(case)


def test_actual_precancelled_call_leaves_one_dispatch_for_a_later_eligible_call(
    tmp_path, monkeypatch
):
    with _host_case(tmp_path, monkeypatch, mode="pre-cancel") as case:
        _start(case)
        cancelled = threading.Event()
        cancelled.set()
        result = case.owner.prepare_initial_selection(
            "cancelled-before-dispatch", cancel_event=cancelled
        )
        _unavailable(case, result, "cancelled-before-dispatch", "cancelled")
        status = case.owner.status()
        assert status.phase == "idle" and status.attempted is False and status.busy is False
        assert case.proofs == 0 and case.puts == []
        assert _same_application_facts(case.admitted, _snapshot(case.study)) == {}
        _success(case, call_id="later-eligible")


def test_actual_caller_cancellation_keeps_held_put_owned_and_never_replays_success(
    tmp_path, monkeypatch
):
    with _host_case(tmp_path, monkeypatch, mode="cancelled") as case:
        _start(case)
        cancel = threading.Event()
        try:
            _launch_call(case, cancel_event=cancel)
            _held_work(case)
            cancel.set()
            result = _join_call(case)
            _unavailable(case, result, "held-call", "cancelled")
            _held_work(case)
            _unavailable(
                case, case.owner.prepare_initial_selection("held-call"), "held-call", "busy"
            )
        finally:
            case.allow_put.set()
        status = _stop_and_join(case)
        assert status.attempted is True
        _unavailable(
            case, case.owner.prepare_initial_selection("held-call"), "held-call", "stopped"
        )
        assert len(case.puts) == 1
        _retained_record(case)


def test_actual_request_deadline_does_not_release_held_work_or_deliver_late_data(
    tmp_path, monkeypatch
):
    with _host_case(tmp_path, monkeypatch, mode="deadline") as case:
        _start(case)
        try:
            _launch_call(case)
            _held_work(case)
            result = _join_call(case)
            _unavailable(case, result, "held-call", "deadline")
            _held_work(case)
            assert not case.allow_put.is_set()
        finally:
            case.allow_put.set()
        status = _stop_and_join(case)
        assert status.attempted is True
        _unavailable(
            case, case.owner.prepare_initial_selection("held-call"), "held-call", "stopped"
        )
        assert len(case.puts) == 1
        _retained_record(case)


def test_actual_busy_and_stop_cutoff_preserve_live_work_until_original_exit(tmp_path, monkeypatch):
    with _host_case(tmp_path, monkeypatch, mode="stop-cutoff") as case:
        _start(case)
        try:
            _launch_call(case)
            _held_work(case)
            _unavailable(
                case,
                case.owner.prepare_initial_selection("concurrent-call"),
                "concurrent-call",
                "busy",
            )
            first = case.owner.stop()
            second = case.owner.stop()
            for status in (first, second):
                assert status.phase == "stopping" and status.busy is True
                assert status.cleanup_complete is False and status.attempted is True
            assert case.close_calls == 0 and case.release_attempts == []
            assert case.owner._thread.is_alive()
            _unavailable(case, _join_call(case), "held-call", "stopping")
        finally:
            case.allow_put.set()
        status = _stop_and_join(case)
        assert status.phase == "stopped" and status.cleanup_complete is True
        assert len(case.puts) == 1
        _retained_record(case)


def test_actual_primary_and_disposal_failure_preserve_the_original_g_group(tmp_path, monkeypatch):
    with _host_case(tmp_path, monkeypatch, mode="cleanup-failure") as case:
        _start(case)
        result = case.owner.prepare_initial_selection("primary-and-cleanup")
        _unavailable(case, result, "primary-and-cleanup")
        assert result.reason in ("preparation_failed", "stopping")
        status = _stop_and_join(case)
        assert status.phase == "stopped" and status.cleanup_complete is False
        assert status.primary_failure == "preparation_failed"
        assert status.cleanup_failure == "cleanup_failed"
        assert case.owner._primary_error is case.primary
        group = case.owner._context_error
        assert type(group) is ExceptionGroup
        assert group.exceptions == (case.primary, case.cleanup_primary)
        assert case.guard_primaries == [group]
        assert case.proofs == 1 and len(case.puts) == 1
        _retained_record(case)


def test_actual_unattempted_idle_lifetime_expires_and_closes_without_another_caller(
    tmp_path, monkeypatch
):
    # Only the host lifetime is shortened. Startup10/request5/shutdown1 and the
    # actual account lease60/5/10 remain unchanged. No fake clock is installed.
    limits = ReadinessOwnerLimits(lifetime_ns=12_000_000_000)
    with _host_case(tmp_path, monkeypatch, mode="idle-expiry", limits=limits) as case:
        _start(case)
        assert case.guard_exited.wait(15), "idle owner did not complete its original guard exit"
        case.thread.join(2)
        assert not case.thread.is_alive()
        # No stop/status/prepare call drove the idle period or initiated cleanup.
        # Observe the terminal state only after the actual exit event and join.
        status = case.owner.status()
        assert status.phase == "stopped" and status.cleanup_complete is True
        assert status.busy is False and status.attempted is False
        assert status.primary_failure == "lifetime_expired" and status.cleanup_failure is None
        assert case.guard_primaries == [None]
        assert case.proofs == 0 and case.puts == [] and case.close_calls == 1
