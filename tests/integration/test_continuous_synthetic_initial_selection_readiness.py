"""Fresh same-owner proofs; original financial work and counters stay separate.

This dedicated fixture does not prepend work to the old F/H fixed-count tests.
Original-code local events observe genuine Runtime/full-schema calls, resource
returns and explicit test faults. No financial verifier or owner is replaced.
"""

import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from apps.api.authenticated_initial_selection_preparation import (
    _prepare_authenticated_initial_selection,
)
from apps.api.initial_selection_request_retention import _retain_initial_selection_request
from apps.trader import initial_selection_preparation_owner as host
from apps.trader.continuous_readiness_owner import _ReadinessRuntime
from apps.trader.continuous_simulation_factory import ContinuousSimulationFactory
from apps.trader.initial_selection_descriptor import copy_initial_selection_descriptor
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionInstallationResult,
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationResult,
    InitialSelectionReadinessResult,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalHead, JournalReceipt
from packages.domain.runtime_owner_dependency_contracts import MAX_OWNER_DEPENDENCIES_BYTES
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.database import DatabaseSchemaNotReady, verify_operational_schema
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from tests.integration import test_continuous_synthetic_initial_selection_installation as original_g
from tests.integration import (
    test_continuous_synthetic_initial_selection_request_retention as original_i,
)
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_initial_state,
    _assert_scopes_closed,
    _seed_phase_zero,
)
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _configuration,
    _retained_record,
    _same_application_facts,
)


def _damage_source(case):
    reference = case.study.genesis.restored.receipt.commit.source_evidence.object_ref
    path = case.study.paths["artifact_root"] / (reference.object_sha256 + ".json")
    payload = path.read_bytes()
    assert (
        len(payload) == reference.byte_count
        and sha256(payload).hexdigest() == reference.object_sha256
    )
    damaged = payload[:-1] + bytes((payload[-1] ^ 1,))
    assert len(damaged) == len(payload) and damaged != payload
    assert path.write_bytes(damaged) == reference.byte_count
    old = case.expected_financial
    objects = dict(old[2][0])
    assert objects[path.name] == payload
    objects[path.name] = damaged
    case.expected_financial = (old[0], old[1], (tuple(sorted(objects.items())), old[2][1]))
    assert _snapshot(case.study).financial == case.expected_financial
    case.damage = (reference, payload, damaged)


@contextmanager
def _observe(case):
    """No monkeypatch of any pinned constructor, verifier, publisher or Engine."""
    labels = {
        ContinuousSimulationFactory.__init__.__code__: "factory",
        ContinuousSimulationFactory.close.__code__: "close",
        ContinuousSimulationFactory.execute.__code__: "execute",
        _ReadinessRuntime.__init__.__code__: "runtime",
        _ReadinessRuntime.verify.__code__: "verify",
        verify_operational_schema.__code__: "schema",
        SqlContinuousIntegrityReader.original_factory_read.__code__: "factory-read",
        SqlAccountCoordinator.acquire.__code__: "acquire",
        SqlAccountCoordinator.release.__code__: "release",
        SqlAccountCoordinator._observe.__code__: "watermark",
        LocalInstanceGuard.__enter__.__code__: "guard-enter",
        LocalInstanceGuard.__exit__.__code__: "guard-exit",
        Engine.connect.__code__: "connect",
        Engine.dispose.__code__: "dispose",
        LocalResearchArtifactStore.put.__code__: "put",
        SqlRuntimeAssignmentPublication.publish.__code__: "publish",
        SqlRuntimeOwnerCommands.prepare.__code__: "request-prepare",
        InitialSelectionPreparationOwner.prepare_initial_selection.__code__: "prepare",
        InitialSelectionPreparationOwner.install_initial_selection.__code__: "install",
        host._proof_result.__code__: "projection",
        threading.Condition.wait.__code__: "condition-wait",
    }
    monitor, tool = sys.monitoring, 3
    prior_profile = sys.getprofile()
    enabled, registered = [], []
    owned, primary = False, None

    def worker():
        actual = threading.current_thread()
        assert actual is case.owner._thread and actual is not case.caller_thread
        if case.thread is None:
            case.thread = actual
        assert actual is case.thread
        return actual

    def observe(frame, event, returned):
        # Observation failures are independently surfaced after natural cleanup;
        # no assertion swallowed by a financial owner can turn into acceptance.
        label = labels[frame.f_code]
        actual = frame.f_locals.get("self")
        try:
            if event == "call":
                if label == "factory":
                    assert case.factory is None
                    case.factory = actual
                    case.trace.append(("factory-call", worker()))
                elif label == "acquire":
                    assert actual is case.factory.coordinator
                    case.account_engine = case.factory.engine
                elif label == "runtime":
                    assert frame.f_locals["reader"] is case.factory.integrity
                    assert frame.f_locals["lease"] is case.acquires[0]
                elif label == "verify":
                    assert actual is case.runtime and actual.lease is case.acquires[0]
                    case.verify_calls.append((actual, frame.f_locals["deadline_ns"], worker()))
                    if case.mode == "r2" and case.renewed is None:
                        remaining = (
                            case.acquires[0].heartbeat_at
                            + timedelta(milliseconds=500)
                            - datetime.now(UTC)
                        ).total_seconds()
                        threading.Event().wait(max(0, remaining))
                        case.renewed = case.factory.coordinator.renew(case.acquires[0].fence)
                        assert case.renewed.revision_number == 2
                        assert case.renewed.fence == case.acquires[0].fence
                        assert case.runtime.lease is case.acquires[0]
                    if (
                        case.mode in ("hold", "deadline", "stop-held", "interrupt")
                        and not case.work_barrier_used
                    ):
                        case.work_barrier_used = True
                        case.at_work.set()
                        assert case.allow_work.wait(15), "test proof barrier was not released"
                elif label == "schema" and frame.f_locals["continuous_integrity"] is not None:
                    assert frame.f_locals["engine"] is case.account_engine
                    assert frame.f_locals["continuous_integrity"] is case.runtime.reader
                    assert frame.f_locals["research_codec"] is personal_codec
                    assert frame.f_locals["require_phase_zero_facts"] is True
                    case.schema_calls.append((case.runtime, worker()))
                    if case.mode in ("source-damage", "primary-cleanup") and case.damage is None:
                        _damage_source(case)
                elif label in ("execute", "factory-read"):
                    case.forbidden.append(label)
                elif label == "release":
                    case.release_attempts.append((actual, frame.f_locals["fence"], worker()))
                elif label == "close":
                    assert actual is case.factory
                    case.close_calls += 1
                    case.trace.append(("close-call", worker()))
                elif label == "dispose" and actual in (case.account_engine, case.venue_engine):
                    case.dispose_calls.append(actual)
                elif label == "guard-exit" and actual is case.guard:
                    case.guard_primaries.append(frame.f_locals["_"][1])
                elif label == "prepare":
                    assert actual is case.owner
                    case.preparation_calls += 1
                elif label == "install":
                    assert actual is case.owner
                    case.install_calls += 1
                elif label == "publish":
                    case.publish_calls += 1
            else:
                if label == "acquire":
                    case.acquires.append(returned)
                    case.trace.append(("acquire-return", worker()))
                elif label == "factory":
                    assert actual is case.factory
                    case.venue_engine = actual.venue_engine
                elif label == "runtime":
                    assert case.runtime is None
                    case.runtime, case.stop_event = actual, actual.stop_event
                    case.condition = case.owner._original[4]
                    assert actual.reader.engine is case.account_engine
                    assert actual.venue_engine is case.venue_engine
                    assert len(actual.reader.journals) == 8
                    case.trace.append(("runtime-return", worker()))
                elif label == "verify":
                    assert type(returned) is int
                    case.verify_returns.append((returned, worker()))
                    _assert_scopes_closed(case.runtime.reader)
                elif label == "schema" and frame.f_locals["continuous_integrity"] is not None:
                    case.schema_returns += 1
                elif label == "watermark" and actual is case.factory.coordinator:
                    at = frame.f_locals["checked_at"]
                    assert type(at) is datetime and at.tzinfo is UTC
                    assert returned.updated_at == at
                    case.watermarks.append(at)
                elif label == "release":
                    case.releases.append(returned)
                    case.trace.append(("release-return", worker()))
                elif label == "close":
                    case.close_returns.append(returned)
                    case.trace.append(("close-return", worker()))
                elif (
                    label == "guard-enter" and threading.current_thread() is not case.caller_thread
                ):
                    case.guard = actual
                    info = os.fstat(actual.fileno())
                    case.lock_identity = info.st_dev, info.st_ino
                elif label == "guard-exit" and actual is case.guard:
                    case.guard_returns += 1
                    case.trace.append(("guard-return", worker()))
                elif label == "dispose":
                    for engine, name in (
                        (case.venue_engine, "venue"),
                        (case.account_engine, "account"),
                    ):
                        if actual is engine and engine is not None:
                            case.dispose_returns.append(name)
                            case.trace.append((name + "-dispose-return", worker()))
                elif label == "connect" and actual in (case.account_engine, case.venue_engine):
                    case.connections.append(returned)
                elif (
                    label == "put"
                    and case.runtime is not None
                    and actual is case.runtime.reader.account.artifacts
                ):
                    assert frame.f_locals["max_bytes"] == MAX_OWNER_DEPENDENCIES_BYTES
                    payload = frame.f_locals["payload"]
                    assert len(case.puts) == 0
                    assert (
                        actual._root / (returned.object_sha256 + ".json")
                    ).read_bytes() == payload
                    case.puts.append((returned, payload))
                elif (
                    label == "request-prepare"
                    and case.issuer is not None
                    and actual is case.issuer.commands
                ):
                    assert case.request_prepared is None
                    case.request_prepared = returned
                elif label == "publish":
                    case.publish_returns.append(returned)
                elif label == "projection" and type(returned) is InitialSelectionReadinessResult:
                    case.projections.append(returned)
            return label
        except BaseException as error:
            case.observer_faults.append(error)
            return label

    def projection_fault(frame, returned):
        if returned.call_id != case.held_id or returned.status != "ready" or case.projection_used:
            return
        case.projection_used = True
        case.held_request = case.owner._slot
        assert case.held_request.completed and case.held_request.dispatched
        assert case.condition._is_owned()
        case.at_projection.set()
        limit = time.monotonic() + 15
        while not case.allow_projection.is_set():
            assert time.monotonic() < limit, "test projection barrier was not released"
            # This native wait releases the actual Condition. Competitors must
            # acquire it and receive BUSY, rather than merely block on a test lock.
            case.condition.wait(0.02)

    def on_start(code, offset):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code
            observe(frame, "call", None)
        finally:
            del frame

    def on_return(code, offset, returned):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code
            label = observe(frame, "return", returned)
            if label == "projection" and case.projection_action is not None:
                case.projection_action(returned)
            if label == "projection" and case.held_id is not None:
                projection_fault(frame, returned)
            if (
                label == "condition-wait"
                and case.mode == "interrupt"
                and case.at_work.is_set()
                and threading.current_thread() is case.caller
                and not case.interrupted
            ):
                case.interrupted = True
                raise case.primary
        finally:
            del frame

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-same-owner-proof")
        owned = True
        for event, callback in (
            (monitor.events.PY_START, on_start),
            (monitor.events.PY_RETURN, on_return),
        ):
            registered.append(event)
            assert monitor.register_callback(tool, event, callback) is None
        for code in labels:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START | monitor.events.PY_RETURN)
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        if owned:
            for code in enabled:
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    errors.append(error)
            for event in registered:
                try:
                    monitor.register_callback(tool, event, None)
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if sys.getprofile() is not prior_profile:
            errors.append(AssertionError("original profile changed"))
        errors.extend(case.observer_faults)
        if errors:
            raise BaseExceptionGroup(
                "proof fixture observation failed", ([primary] if primary else []) + errors
            )


def _watermark_only(before, after, case):
    assert after.financial == before.financial
    assert after.leases == before.leases and after.releases == before.releases
    assert len(before.heads) == len(after.heads) == 1
    expected = dict(before.heads[0])
    assert case.watermarks
    expected["updated_at"] = case.watermarks[-1].replace(tzinfo=None)
    assert after.heads == (expected,)
    assert after.heads[0]["updated_at"] >= before.heads[0]["updated_at"]


def _closed(case):
    status = case.owner.status()
    assert status.phase == "stopped" and not status.busy
    assert case.thread is case.owner._thread and not case.thread.is_alive()
    assert case.close_calls == case.guard_returns == len(case.acquires) == len(case.releases) == 1
    assert case.forbidden == [] and case.guard._descriptor is None
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    _assert_scopes_closed(case.runtime.reader)
    after = _snapshot(case.study)
    assert after.financial == case.expected_financial
    assert all(connection.closed for connection in case.connections)
    before, first = case.before, case.acquires[0]
    new_leases = [row for row in after.leases if row not in before.leases]
    expected_leases = [first] if case.renewed is None else [first, case.renewed]
    assert len(after.leases) == len(before.leases) + len(expected_leases)
    assert all(row in after.leases for row in before.leases)
    actual_leases = [account_lease_from_row(row) for row in new_leases]
    assert sorted(actual_leases, key=lambda lease: lease.revision_number) == expected_leases
    assert first.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert first.account_id == case.study.genesis.scope.account_id
    assert first.revision_number == 1 and first.previous_lease_sha256 is None
    assert first.policy_sha256 == case.configuration.lease_policy().semantic_sha256
    assert first.expires_at - first.acquired_at == timedelta(seconds=60)
    policy = case.configuration.lease_policy()
    assert policy.maximum_in_flight_duration == timedelta(seconds=5)
    assert policy.takeover_safety_interval == timedelta(seconds=10)
    added = [row for row in after.releases if row not in before.releases]
    assert len(after.releases) == len(before.releases) + 1 and len(added) == 1
    assert all(row in after.releases for row in before.releases)
    release = account_lease_release_from_row(added[0])
    latest = expected_leases[-1]
    assert case.releases == [release]
    assert case.release_attempts == [(case.factory.coordinator, first.fence, case.thread)]
    assert release.lease_sha256 == latest.semantic_sha256 and release.fence == first.fence
    assert release.policy_sha256 == first.policy_sha256
    assert latest.acquired_at <= release.released_at < latest.expires_at
    assert after.heads == (
        dict(
            account_id=first.account_id,
            last_fencing_generation=first.fencing_generation,
            current_fencing_generation=None,
            current_lease_sha256=None,
            updated_at=added[0]["released_at"],
        ),
    )
    if case.mode == "primary-cleanup":
        assert status.cleanup_complete is False and status.cleanup_failure == "cleanup_failed"
        assert case.venue_disposal_effect is True
        assert case.dispose_returns == ["account"] and len(case.dispose_calls) == 2
        assert case.close_returns == []
        group = case.owner._context_error
        assert type(group) is ExceptionGroup
        assert group.exceptions == (case.owner._primary_error, case.cleanup_primary)
        assert case.guard_primaries == [group]
    elif case.mode == "r2":
        assert case.close_returns == [release]
        assert status.cleanup_complete is False and status.cleanup_failure == "cleanup_failed"
        assert type(case.owner._context_error) is ExceptionGroup
        assert case.owner._context_error.exceptions[0] is case.owner._primary_error
        assert (
            str(case.owner._context_error.exceptions[1]) == "CONFIGURED_READINESS_RELEASE_INVALID"
        )
        assert case.guard_primaries == [case.owner._context_error]
        assert case.dispose_returns == ["venue", "account"]
    else:
        assert case.close_returns == [release]
        assert status.cleanup_complete is True and status.cleanup_failure is None
        assert case.owner._context_error is None
        assert case.guard_primaries == [case.owner._primary_error]
        assert case.dispose_returns == ["venue", "account"]
    assert all(thread is case.thread for _, thread in case.trace)
    labels = [name for name, _ in case.trace]
    assert labels.index("close-call") < labels.index("release-return")
    assert labels.index("release-return") < labels.index("account-dispose-return")
    if case.mode != "primary-cleanup":
        assert labels.index("account-dispose-return") < labels.index("close-return")
    assert labels[-1] == "guard-return"
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


@contextmanager
def _case(tmp_path, *, mode="normal", limits=None):
    with study_module._study(tmp_path, install=False) as study:
        _assert_initial_state(study, installed=False)
        daily = study.owners.daily.resolve_snapshot(
            study.owners.daily.read_snapshot(
                account_id=study.genesis.scope.account_id,
                fence=study.lease.fence,
            )
        )
        configuration = _configuration(study)
        _seed_phase_zero(study)
        path = study.root / "same-owner-proof.json"
        payload = personal_codec.encode_record(configuration)
        study_module._exclusive_file(path, payload)
        study_module._release_setup(study)
        assert study.lease is None
        before = _snapshot(study)
        study.ports["venue_engine"].dispose()
        study.ports["account_engine"].dispose()
        case = SimpleNamespace(
            study=study,
            setup_daily=daily,
            configuration=configuration,
            configuration_path=path,
            configuration_bytes=payload,
            lock_path=study.root / "same-owner-proof.lock",
            before=before,
            expected_financial=before.financial,
            mode=mode,
            caller_thread=threading.current_thread(),
            owner=None,
            thread=None,
            factory=None,
            runtime=None,
            account_engine=None,
            venue_engine=None,
            stop_event=None,
            condition=None,
            guard=None,
            lock_identity=None,
            acquires=[],
            release_attempts=[],
            releases=[],
            close_returns=[],
            close_calls=0,
            dispose_calls=[],
            dispose_returns=[],
            guard_returns=0,
            guard_primaries=[],
            trace=[],
            connections=[],
            verify_calls=[],
            verify_returns=[],
            schema_calls=[],
            schema_returns=0,
            watermarks=[],
            forbidden=[],
            observer_faults=[],
            puts=[],
            publish_calls=0,
            publish_returns=[],
            preparation_calls=0,
            install_calls=0,
            projections=[],
            damage=None,
            renewed=None,
            issuer=None,
            owned_issuer_engine=None,
            request_prepared=None,
            at_work=threading.Event(),
            allow_work=threading.Event(),
            at_projection=threading.Event(),
            allow_projection=threading.Event(),
            held_id=None,
            held_request=None,
            projection_used=False,
            projection_action=None,
            work_barrier_used=False,
            callers=[],
            caller=None,
            interrupted=False,
            primary=KeyboardInterrupt("test original proof caller interrupted"),
            cleanup_primary=RuntimeError("test original venue disposal event failed"),
            venue_disposal_effect=False,
        )
        primary = None
        try:
            with _observe(case):
                options = {} if limits is None else dict(limits=limits)
                case.owner = InitialSelectionPreparationOwner(
                    configuration_path=str(path),
                    account_id=study.genesis.scope.account_id,
                    instance_lock=str(case.lock_path),
                    **options,
                )
                assert case.owner._thread is None and not case.lock_path.exists()
                assert _snapshot(study).__dict__ == before.__dict__
                body_primary = None
                try:
                    yield case
                except BaseException as error:
                    body_primary = error
                    raise
                finally:
                    case.allow_work.set()
                    case.allow_projection.set()
                    failures = []
                    try:
                        case.owner.stop()
                    except BaseException as error:
                        failures.append(error)
                    for caller in case.callers:
                        caller.join(20)
                        if caller.is_alive():
                            failures.append(AssertionError("proof caller has not returned"))
                    worker_thread = case.owner._thread
                    if worker_thread is not None:
                        worker_thread.join(20)
                        if worker_thread.is_alive():
                            failures.append(AssertionError("original proof worker has not exited"))
                        else:
                            try:
                                _closed(case)
                            except BaseException as error:
                                failures.append(error)
                    if failures:
                        actual_context = case.owner._context_error
                        if (
                            actual_context is not None
                            and actual_context is not body_primary
                            and not any(error is actual_context for error in failures)
                        ):
                            failures.append(actual_context)
                        raise BaseExceptionGroup(
                            "proof fixture and original cleanup failed",
                            ([body_primary] if body_primary else []) + failures,
                        )
        except BaseException as error:
            primary = error
            raise
        finally:
            if case.owned_issuer_engine is not None:
                try:
                    case.owned_issuer_engine.dispose()
                except BaseException as cleanup:
                    if primary is not None:
                        raise BaseExceptionGroup(
                            "proof fixture and owned issuer disposal failed", [primary, cleanup]
                        ) from None
                    raise


def _start(case):
    result = case.owner.start()
    assert result.phase == "idle" and not result.busy and not result.attempted
    assert result.cleanup_complete is False
    assert case.thread is case.owner._thread and case.thread.is_alive()
    assert case.runtime.lease is case.acquires[0]
    assert case.verify_calls == case.schema_calls == case.puts == []
    case.admitted = _snapshot(case.study)
    assert case.admitted.financial == case.before.financial


def _ready(case, value, call_id):
    assert type(value) is InitialSelectionReadinessResult
    assert (value.status, value.reason, value.call_id, value.incarnation) == (
        "ready",
        "verified",
        call_id,
        case.owner._incarnation,
    )
    status = case.owner.status()
    assert status.phase == "idle" and not status.busy and not status.attempted
    assert status.cleanup_complete is False and case.thread.is_alive()
    assert case.owner._slot is case.owner._active_nonce is None
    assert case.owner._preparation_return_admitted is False
    assert case.owner._prepared_proposal_sha256 is None and not case.owner._install_dispatched
    assert case.preparation_calls == case.install_calls == case.publish_calls == 0
    assert case.puts == [] and case.close_calls == 0


def _unavailable(case, value, call_id, reason):
    assert type(value) is InitialSelectionReadinessResult
    assert (value.status, value.reason, value.call_id, value.incarnation) == (
        "unavailable",
        reason,
        call_id,
        case.owner._incarnation,
    )


def _launch(case, call_id, *, cancel_event=None):
    outcome = SimpleNamespace(results=[], errors=[], done=threading.Event(), thread=None)

    def call():
        try:
            outcome.results.append(
                case.owner.check_initial_selection_readiness(
                    call_id,
                    cancel_event=cancel_event,
                )
            )
        except BaseException as error:
            outcome.errors.append(error)
        finally:
            outcome.done.set()

    outcome.thread = threading.Thread(target=call, name="same-owner-proof-caller")
    case.callers.append(outcome.thread)
    case.caller = outcome.thread
    outcome.thread.start()
    return outcome


def _join(outcome):
    outcome.thread.join(10)
    assert not outcome.thread.is_alive() and outcome.done.is_set()
    assert len(outcome.results) + len(outcome.errors) == 1
    return outcome


def _disabled_b(case, before, after):
    original_g._unchanged_except(
        before, after, daily_runtime_assignments, daily_runtime_assignment_heads
    )
    assert original_g._table(before, daily_runtime_assignments) == ()
    assert original_g._table(before, daily_runtime_assignment_heads) == ()
    rows = original_g._mapped(
        original_g._table(after, daily_runtime_assignments), daily_runtime_assignments
    )
    assert len(rows) == 1
    row = rows[0]
    assignment = personal_codec.decode_record(row["payload"], RuntimeRiskAssignment)
    assert assignment == case.dependency_record.proposed
    assert type(assignment) is RuntimeRiskAssignment
    assert personal_codec.encode_record(assignment) == row["payload"]
    assert sha256(row["payload"]).hexdigest() == row["payload_sha256"]
    assert assignment.generation == 1 and assignment.previous_assignment_sha256 is None
    assert assignment.enabled_for_new_exposure is assignment.live_authorized is False
    assert assignment.environment == "stateful_simulation"
    assert assignment.financing_policy == "cash-funded-long-only/1"
    command = case.issued.command
    assert row == dict(
        account_id=assignment.account_id,
        generation=1,
        command_id=command.command_id,
        command_sha256=command.semantic_sha256,
        command_payload=personal_codec.encode_record(command),
        recorded_at=row["recorded_at"],
        previous_sha256=None,
        semantic_sha256=assignment.semantic_sha256,
        payload_sha256=sha256(row["payload"]).hexdigest(),
        payload=personal_codec.encode_record(assignment),
    )
    assert row["recorded_at"].tzinfo is None
    assert command.requested_at <= row["recorded_at"].replace(tzinfo=UTC) < command.expires_at
    assert original_g._mapped(
        original_g._table(after, daily_runtime_assignment_heads), daily_runtime_assignment_heads
    ) == [
        dict(
            account_id=assignment.account_id,
            generation=1,
            semantic_sha256=assignment.semantic_sha256,
        )
    ]


def test_two_same_owner_proofs_then_authenticated_preparation_request_and_terminal_install(
    tmp_path,
):
    with _case(tmp_path) as case:
        _start(case)
        before = _snapshot(case.study)
        first = case.owner.check_initial_selection_readiness("first-proof")
        _ready(case, first, "first-proof")
        _watermark_only(before, _snapshot(case.study), case)
        second = case.owner.check_initial_selection_readiness("first-proof")
        _ready(case, second, "first-proof")
        assert second is not first
        assert (
            len(case.verify_calls)
            == len(case.verify_returns)
            == len(case.schema_calls)
            == case.schema_returns
            == 2
        )
        assert all(
            runtime is case.runtime and thread is case.thread
            for runtime, thread in case.schema_calls
        )
        assert all(
            runtime is case.runtime and thread is case.thread
            for runtime, deadline, thread in case.verify_calls
        )
        _watermark_only(before, _snapshot(case.study), case)
        issuer = original_i._issuer(case)
        prepared = _prepare_authenticated_initial_selection(
            security=issuer.security,
            owner=case.owner,
            account_id=case.study.genesis.scope.account_id,
            call_id="prepare-after-proof",
            session_cookie=issuer.cookie,
            csrf_token=issuer.csrf,
        )
        assert type(prepared) is InitialSelectionPreparationResult and prepared.status == "prepared"
        case.descriptor = copy_initial_selection_descriptor(prepared.descriptor)
        _, case.dependency_record = _retained_record(case)
        assert case.owner._preparation_return_admitted is True
        assert case.preparation_calls == 1 and len(case.puts) == 1
        assert len(case.verify_calls) == len(case.schema_calls) == case.schema_returns == 4
        case.prepared_snapshot = _snapshot(case.study)
        additions = _same_application_facts(before, case.prepared_snapshot)
        assert additions == {case.puts[0][0].object_sha256 + ".json": case.puts[0][1]}
        receipt = _retain_initial_selection_request(
            security=issuer.security,
            commands=issuer.commands,
            engine=issuer.engine,
            account_id=case.study.genesis.scope.account_id,
            descriptor=case.descriptor,
            command_id="request-after-two-proofs",
            session_cookie=issuer.cookie,
            csrf_token=issuer.csrf,
        )
        assert case.request_prepared is not None and receipt == case.request_prepared.append.receipt
        case.issued = SimpleNamespace(
            prepared=case.request_prepared,
            receipt=receipt,
            command=case.request_prepared.record.command,
        )
        case.requested = _snapshot(case.study)
        original_g._request_only(case)
        started = time.monotonic_ns()
        result = case.owner.install_initial_selection(
            "install-after-proof", request_receipt=replace(receipt)
        )
        elapsed = time.monotonic_ns() - started
        assert type(result) is InitialSelectionInstallationResult
        assert result.status == result.reason == "installed"
        assert 0 <= elapsed < 5_000_000_000
        assert not case.thread.is_alive() and case.owner.status().cleanup_complete
        assert (
            len(case.verify_calls)
            == len(case.verify_returns)
            == len(case.schema_calls)
            == case.schema_returns
            == 5
        )
        assert case.publish_calls == len(case.publish_returns) == case.install_calls == 1
        assert (
            result.observation.assignment_sha256 == case.dependency_record.proposed.semantic_sha256
        )
        assert case.owner._install_return_admitted is True
        after = _snapshot(case.study)
        _disabled_b(case, case.requested, after)
        case.expected_financial = after.financial
        _unavailable(
            case,
            case.owner.check_initial_selection_readiness("after-terminal"),
            "after-terminal",
            "stopped",
        )


def test_completed_proof_reservation_makes_real_competitors_busy_until_ack(tmp_path):
    with _case(tmp_path) as case:
        _start(case)
        case.held_id = "held-ready"
        first = _launch(case, case.held_id)
        try:
            assert case.at_projection.wait(10)
            request = case.held_request
            assert case.owner._slot is request and case.owner._active_nonce is request.nonce
            assert request.completed and request.dispatched and case.owner.status().busy
            _unavailable(
                case,
                case.owner.check_initial_selection_readiness("competing-proof"),
                "competing-proof",
                "busy",
            )
            prep = case.owner.prepare_initial_selection("competing-preparation")
            assert (
                prep.status == "unavailable" and prep.reason == "busy" and prep.descriptor is None
            )
            # One-record native transport only: BUSY precedes ownership.
            # This literal receipt is never REQUEST or installation evidence.
            receipt = JournalReceipt(
                command_id="native-busy-request",
                command_sha256="1" * 64,
                append_sha256="2" * 64,
                previous_head=JournalHead("3" * 64, 1, "4" * 64),
                committed_head=JournalHead("3" * 64, 2, "5" * 64),
                record_ids=("native-busy-request",),
                record_hashes=("6" * 64,),
            )
            install = case.owner.install_initial_selection(
                "competing-install",
                request_receipt=receipt,
            )
            assert install.status == "unavailable" and install.reason == "busy"
            assert len(case.verify_calls) == len(case.schema_calls) == 1 and case.puts == []
            assert case.owner._slot is request
        finally:
            case.allow_projection.set()
        _join(first)
        assert first.errors == []
        # The explicit competing prep/install calls are counted, never reset.
        assert first.results[0].status == "ready"
        assert case.preparation_calls == case.install_calls == 1
        assert case.owner._attempted is False and case.puts == []
        second = case.owner.check_initial_selection_readiness("after-ack")
        assert second.status == "ready" and second.reason == "verified"
        assert len(case.verify_calls) == len(case.schema_calls) == 2


def test_completed_expired_caller_cannot_reappear_after_another_fresh_proof(tmp_path):
    with _case(tmp_path) as case:
        _start(case)
        case.held_id = "expired-completed"
        first = _launch(case, case.held_id)
        try:
            assert case.at_projection.wait(10)
            request = case.held_request
            deadline = request.deadline_ns
            remaining = max(0, (deadline - time.monotonic_ns()) / 1_000_000_000)
            assert remaining <= 5
            threading.Event().wait(remaining)
            assert time.monotonic_ns() >= deadline
            # Original worker polls its same completed request. Observe native
            # quiescence; no test clears its slot or changes its deadline.
            limit = time.monotonic() + 1
            with case.condition:
                while case.owner._slot is request and time.monotonic() < limit:
                    case.condition.wait(0.02)
                assert request.abandoned and case.owner._slot is not request
            second = case.owner.check_initial_selection_readiness("expired-completed")
            assert second.status == "ready" and second.reason == "verified"
            assert len(case.verify_calls) == len(case.schema_calls) == 2
        finally:
            case.allow_projection.set()
        _join(first)
        assert first.errors == []
        _unavailable(case, first.results[0], "expired-completed", "deadline")
        assert case.owner._attempted is False and case.puts == []


def _quiescent(case):
    limit = time.monotonic() + 5
    with case.condition:
        while case.owner._slot is not None and time.monotonic() < limit:
            case.condition.wait(0.02)
        assert case.owner._slot is case.owner._active_nonce is None
    assert case.owner.status().phase == "idle" and not case.owner.status().busy


@pytest.mark.parametrize("outcome", ["cancelled", "deadline", "interrupted"])
def test_active_abandonment_retains_actual_work_and_cannot_deliver_late_success(tmp_path, outcome):
    mode = {"cancelled": "hold", "deadline": "deadline", "interrupted": "interrupt"}[outcome]
    with _case(tmp_path, mode=mode) as case:
        _start(case)
        cancel = threading.Event()
        call = _launch(case, "active-proof", cancel_event=cancel)
        try:
            assert case.at_work.wait(10)
            request = case.owner._slot
            assert request.dispatched and not request.completed
            assert request._worker_thread is case.thread
            assert len(case.verify_calls) == 1 and case.schema_calls == []
            if outcome == "cancelled":
                cancel.set()
            _join(call)
            if outcome == "interrupted":
                assert call.results == [] and call.errors == [case.primary]
                assert case.interrupted and case.primary.__traceback__ is not None
            else:
                assert call.errors == []
                _unavailable(case, call.results[0], "active-proof", outcome)
            assert request.abandoned and case.owner._slot is request
            assert case.owner.status().busy and not case.owner.status().cleanup_complete
            assert case.thread.is_alive() and case.close_calls == 0 and case.releases == []
            cancel.clear()  # A caller's later clear cannot revive abandoned work.
            _unavailable(
                case,
                case.owner.check_initial_selection_readiness("active-proof"),
                "active-proof",
                "busy",
            )
            assert len(case.verify_calls) == 1 and case.puts == []
        finally:
            case.allow_work.set()
        _quiescent(case)
        assert request.completed and request.abandoned
        assert case.owner._attempted is False and case.owner._primary_error is None
        assert case.owner._preparation_return_admitted is False
        fresh = case.owner.check_initial_selection_readiness("active-proof")
        _ready(case, fresh, "active-proof")
        assert len(case.verify_calls) == 2
        assert len(case.schema_calls) == (1 if outcome == "deadline" else 2)
        assert len(call.results) == (0 if outcome == "interrupted" else 1)
        assert case.puts == []


@pytest.mark.parametrize("cleanup_fault", [False, True])
def test_original_source_corruption_keeps_primary_and_truthful_cleanup(tmp_path, cleanup_fault):
    mode = "primary-cleanup" if cleanup_fault else "source-damage"
    with _case(tmp_path, mode=mode) as case:
        _start(case)
        if cleanup_fault:

            def fail_after_real_pool_disposal(engine):
                assert engine is case.venue_engine
                case.venue_disposal_effect = True
                raise case.cleanup_primary

            sa.event.listen(case.venue_engine, "engine_disposed", fail_after_real_pool_disposal)
        try:
            result = case.owner.check_initial_selection_readiness("source-damage")
            _unavailable(case, result, "source-damage", "verification_failed")
            case.thread.join(10)
            assert not case.thread.is_alive()
            error = case.owner._primary_error
            assert type(error) is DatabaseSchemaNotReady
            assert str(error) == "continuous retained integrity verification failed"
            assert error.__traceback__ is not None
            assert len(case.verify_calls) == len(case.schema_calls) == 1
            assert case.verify_returns == [] and case.schema_returns == 0
            assert case.damage is not None and case.puts == []
            assert case.owner._attempted is False
            assert case.owner.status().primary_failure == "verification_failed"
            assert _snapshot(case.study).financial == case.expected_financial
        finally:
            if cleanup_fault:
                sa.event.remove(case.venue_engine, "engine_disposed", fail_after_real_pool_disposal)


def test_actual_r2_is_not_adopted_as_original_proof_r1_or_release_receipt(tmp_path):
    with _case(tmp_path, mode="r2") as case:
        _start(case)
        result = case.owner.check_initial_selection_readiness("changed-revision")
        _unavailable(case, result, "changed-revision", "verification_failed")
        case.thread.join(10)
        assert not case.thread.is_alive()
        assert len(case.verify_calls) == 1 and case.schema_calls == []
        assert case.runtime.lease is case.acquires[0]
        assert case.renewed.previous_lease_sha256 == case.acquires[0].semantic_sha256
        assert case.renewed.heartbeat_at - case.acquires[0].heartbeat_at >= timedelta(
            milliseconds=500
        )
        error = case.owner._primary_error
        assert type(error) is ValueError
        assert str(error) == "READINESS_ORIGINAL_LEASE_REVISION_REQUIRED"
        assert case.owner._attempted is False and case.puts == []
        assert case.releases[0].lease_sha256 == case.renewed.semantic_sha256


def test_stop_cutoff_does_not_dispose_or_release_a_held_original_proof(tmp_path):
    with _case(tmp_path, mode="stop-held") as case:
        _start(case)
        call = _launch(case, "stop-held-proof")
        try:
            assert case.at_work.wait(10)
            status = case.owner.stop()
            cutoff = case.owner._shutdown_deadline
            assert status.phase == "stopping" and not status.cleanup_complete
            assert case.thread.is_alive() and case.close_calls == 0
            assert case.release_attempts == case.releases == case.dispose_returns == []
            assert len(case.verify_calls) == 1 and case.schema_calls == []
            again = case.owner.stop()
            assert case.owner._shutdown_deadline == cutoff
            assert again.phase == "stopping" and not again.cleanup_complete
            _join(call)
            assert call.errors == []
            _unavailable(case, call.results[0], "stop-held-proof", "stopping")
        finally:
            case.allow_work.set()
        case.thread.join(10)
        assert not case.thread.is_alive()
        assert case.owner.status().cleanup_complete
        assert case.owner._attempted is False and case.puts == []
        assert len(call.results) == 1 and call.results[0].status == "unavailable"


def test_final_projection_alias_drift_cannot_invoke_substitute_or_deliver_ready(
    tmp_path, monkeypatch
):
    with _case(tmp_path) as case:
        _start(case)
        calls, changed, restored = [], [], []
        original_projection = host._PROOF_RESULT
        entry_code = host._entry.__code__
        previous = sys.getprofile()

        def forbidden(*args, **kwargs):
            calls.append(True)
            raise AssertionError("changed proof projection must not run")

        # This caller already owns the original nonreentrant Condition during
        # projection. Restore only after its real binding checker has failed,
        # before that exception unwinds the lock and lets the worker resume.
        with monkeypatch.context() as patch:

            def change_after_projection(returned):
                if returned.status == "ready" and not changed:
                    changed.append(True)
                    patch.setattr(host, "_PROOF_RESULT", forbidden)

            def after_binding_failure(frame, event, returned):
                if (
                    event == "return"
                    and frame.f_code is entry_code
                    and changed
                    and not restored
                    and frame.f_locals.get("name") == "_PROOF_RESULT"
                ):
                    assert threading.current_thread() is case.caller_thread
                    assert returned is None
                    assert frame.f_locals["original_proof_helper"] is original_projection
                    assert host._PROOF_RESULT is forbidden
                    assert case.condition._is_owned()
                    patch.setattr(host, "_PROOF_RESULT", original_projection)
                    restored.append(True)

            case.projection_action = change_after_projection
            try:
                sys.setprofile(after_binding_failure)
                with pytest.raises(
                    RuntimeError, match=r"^INITIAL_SELECTION_PREPARATION_OWNER_BINDING_CHANGED$"
                ):
                    case.owner.check_initial_selection_readiness("changed-projection")
            finally:
                sys.setprofile(previous)
                patch.setattr(host, "_PROOF_RESULT", original_projection)
                case.projection_action = None
        assert sys.getprofile() is previous and host._PROOF_RESULT is original_projection
        assert changed == restored == [True] and calls == []
        assert len(case.verify_calls) == len(case.schema_calls) == 1
        assert case.owner._attempted is False and case.puts == []
        _quiescent(case)
        fresh = case.owner.check_initial_selection_readiness("changed-projection")
        _ready(case, fresh, "changed-projection")
        assert len(case.verify_calls) == len(case.schema_calls) == 2


def test_actual_precancelled_proof_leaves_original_preparation_eligibility_unchanged(tmp_path):
    with _case(tmp_path) as case:
        _start(case)
        before = _snapshot(case.study)
        cancel = threading.Event()
        cancel.set()
        result = case.owner.check_initial_selection_readiness("pre-cancelled", cancel_event=cancel)
        _unavailable(case, result, "pre-cancelled", "cancelled")
        assert case.verify_calls == case.schema_calls == case.puts == []
        assert case.owner._attempted is False
        assert _snapshot(case.study).__dict__ == before.__dict__
        cancel.clear()
        fresh = case.owner.check_initial_selection_readiness("pre-cancelled", cancel_event=cancel)
        _ready(case, fresh, "pre-cancelled")
        assert len(case.verify_calls) == len(case.schema_calls) == 1
