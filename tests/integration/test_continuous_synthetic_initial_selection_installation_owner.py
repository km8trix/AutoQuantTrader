"""Terminal installation on the actual configured preparation owner's Thread.

Fresh migrated stores, the original F/E/G owners and a separate original REQUEST
issuer are used. Profilers/events only observe original code or introduce an
explicit adverse barrier. They never return a substitute runtime or proof.
"""

import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace

import pytest
import sqlalchemy as sa

from apps.trader import initial_selection_preparation_owner as host_module
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    copy_initial_selection_descriptor,
)
from apps.trader.initial_selection_installation import (
    InitialSelectionInstallationObservation,
    _InitialSelectionInstallation,
)
from apps.trader.initial_selection_preparation import _InitialSelectionPreparation
from apps.trader.initial_selection_preparation_owner import (
    InitialSelectionInstallationResult,
    InitialSelectionPreparationOwner,
    InitialSelectionPreparationOwnerStatus,
    InitialSelectionPreparationResult,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.identifiers import canonical_id
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.database import DatabaseSchemaNotReady
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from tests.integration import (
    test_continuous_synthetic_initial_selection_installation as installation_fixture,
)
from tests.integration import (
    test_continuous_synthetic_initial_selection_preparation_owner as preparation_fixture,
)
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _retained_record,
    _same_application_facts,
)


def _initialize_observations(case):
    case.owner = None
    case.incarnation = None
    case.install_calls = case.install_constructions = 0
    case.g_returned = False
    case.preparation = None
    case.installer = None
    case.dependency_record = None
    case.preparation_returned = threading.Event()
    case.worker_idle = threading.Event()
    case.at_put = threading.Event()
    case.allow_put = threading.Event()
    case.at_write = threading.Event()
    case.allow_write = threading.Event()
    case.at_return = threading.Event()
    case.allow_return = threading.Event()
    case.at_ack = threading.Event()
    case.allow_ack = threading.Event()
    case.ack_barrier_used = False
    case.caller = None
    case.caller_done = threading.Event()
    case.caller_results = []
    case.caller_errors = []
    case.caller_started_ns = None
    case.caller_returned_ns = None
    case.caller_deadline_ns = None
    case.active_nonce = None
    case.profile_previous = None
    case.profile_installed = False
    case.profile_restored = False
    case.monitoring_cleaned = False
    case.caller_profile_restored = False
    case.original_lease = None
    case.committed_snapshot = None
    case.result_at_death = None
    case.sql_observer_installed = False


def _watch_originals(case, monkeypatch):
    put = LocalResearchArtifactStore.put
    guard_exit = LocalInstanceGuard.__exit__
    prepare_code = _InitialSelectionPreparation.prepare.__code__
    construct_code = _InitialSelectionInstallation.__init__.__code__
    install_code = _InitialSelectionInstallation.install.__code__
    publish_code = SqlRuntimeAssignmentPublication.publish.__code__
    now_code = host_module.InitialSelectionPreparationOwner._now.__code__
    monitor = sys.monitoring
    tool = monitor.PROFILER_ID
    tool_name = "aqt-h-original-owner-ports"
    monitored_codes = (prepare_code, now_code, construct_code, install_code, publish_code)
    enabled_codes = []
    registered_events = []
    tool_owned = False

    def profile(frame, event, argument):
        try:
            code = frame.f_code
            # Observe only the five original ports. Unrelated codec/SQL/C events
            # must not pay for Thread lookup inside the original financial budget.
            if (
                code is not prepare_code
                and code is not now_code
                and code is not construct_code
                and code is not install_code
                and code is not publish_code
            ):
                return
            if event not in ("call", "return"):
                return
            if threading.current_thread() is not case.owner._thread:
                raise AssertionError("owner profiler ran on another Thread")
            if (
                code is prepare_code
                and event == "return"
                and type(argument) is InitialSelectionDescriptor
            ):
                case.preparation = frame.f_locals["self"]
                case.preparation_returned.set()
            if (
                code is now_code
                and event == "call"
                and case.preparation_returned.is_set()
                and case.owner._phase == "idle"
            ):
                case.worker_idle.set()
            if code is construct_code and event == "call":
                case.install_constructions += 1
                case.installer = frame.f_locals["self"]
                assert frame.f_locals["preparation"] is case.preparation
                assert case.proofs == 2 and len(case.puts) == 1
                if case.mode == "r2":
                    case.renewed = case.factory.coordinator.renew(case.acquires[0].fence)
                    assert case.renewed.fence == case.acquires[0].fence
                    assert case.renewed.revision_number == 2
                    assert case.renewed.previous_lease_sha256 == case.acquires[0].semantic_sha256
            if code is install_code:
                if event == "call":
                    case.install_calls += 1
                    assert frame.f_locals["self"] is case.installer
                    assert frame.f_locals["request"] == case.issued.receipt
                    case.caller_deadline_ns = frame.f_locals["deadline_ns"]
                    case.active_nonce = case.owner._active_nonce
                    assert type(case.active_nonce) is object
                elif (
                    event == "return" and type(argument) is InitialSelectionInstallationObservation
                ):
                    case.g_returned = True
            if code is publish_code:
                if event == "call":
                    case.pub_calls += 1
                elif event == "return" and type(argument) is RuntimeRiskAssignment:
                    case.pub_return_events += 1
                    assert case.proofs == 3 and case.proof_errors == []
                    case.committed_snapshot = _snapshot(case.study)
                    if case.mode in ("commit-failure", "cleanup-failure"):
                        raise case.primary
                    if case.mode == "late-return":
                        case.at_return.set()
                        assert case.allow_return.wait(15), (
                            "original return barrier was not released"
                        )
        finally:
            del frame

    def on_start(code, offset):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code
            assert any(code is original for original in monitored_codes)
            if code is now_code and threading.current_thread() is not case.owner._thread:
                return
            profile(frame, "call", None)
        finally:
            del frame

    def on_return(code, offset, returned):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code
            assert any(code is original for original in monitored_codes)
            if code is now_code and threading.current_thread() is not case.owner._thread:
                return
            profile(frame, "return", returned)
        finally:
            del frame

    def clear_monitoring():
        nonlocal tool_owned
        if not tool_owned:
            return
        assert monitor.get_tool(tool) == tool_name
        errors = []
        for code in enabled_codes:
            try:
                monitor.set_local_events(tool, code, 0)
                assert monitor.get_local_events(tool, code) == 0
            except BaseException as error:
                errors.append(error)
        for event in registered_events:
            try:
                monitor.register_callback(tool, event, None)
            except BaseException as error:
                errors.append(error)
        try:
            assert monitor.get_events(tool) == 0
            monitor.free_tool_id(tool)
            tool_owned = False
            assert monitor.get_tool(tool) is None
        except BaseException as error:
            errors.append(error)
        case.monitoring_cleaned = not errors and not tool_owned
        if errors:
            raise BaseExceptionGroup("original-code observation cleanup failed", errors)

    def enable_monitoring():
        nonlocal tool_owned
        assert sys.version_info[:2] == (3, 12)
        assert monitor.get_tool(tool) is None
        monitor.use_tool_id(tool, tool_name)
        tool_owned = True
        try:
            assert monitor.get_events(tool) == 0
            for code in monitored_codes:
                assert monitor.get_local_events(tool, code) == 0
            for event, callback in (
                (monitor.events.PY_START, on_start),
                (monitor.events.PY_RETURN, on_return),
            ):
                registered_events.append(event)
                previous = monitor.register_callback(tool, event, callback)
                assert previous is None
            mask = monitor.events.PY_START | monitor.events.PY_RETURN
            for code in monitored_codes:
                enabled_codes.append(code)
                monitor.set_local_events(tool, code, mask)
                assert monitor.get_local_events(tool, code) == mask
            assert sys.getprofile() is case.profile_previous
        except BaseException as primary:
            try:
                clear_monitoring()
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "original-code observation setup and cleanup failed", [primary, cleanup]
                ) from None
            raise

    def actual_put(store, payload, **kwargs):
        result = put(store, payload, **kwargs)
        if case.runtime is not None and store is case.runtime.reader.account.artifacts:
            assert threading.current_thread() is case.owner._thread
            assert not case.profile_installed
            case.profile_previous = sys.getprofile()
            enable_monitoring()
            case.profile_installed = True
            if case.mode == "abandoned-preparation":
                case.at_put.set()
                assert case.allow_put.wait(15), "original dependency put barrier was not released"
        return result

    def actual_guard_exit(guard, kind, error, traceback):
        primary = None
        try:
            return guard_exit(guard, kind, error, traceback)
        except BaseException as actual_error:
            primary = actual_error
            raise
        finally:
            if guard is case.guard and case.profile_installed:
                try:
                    clear_monitoring()
                except BaseException as cleanup:
                    if primary is not None:
                        raise BaseExceptionGroup(
                            "original guard exit and observation cleanup failed", [primary, cleanup]
                        ) from None
                    raise
                finally:
                    case.profile_restored = sys.getprofile() is case.profile_previous

    def after_insert(connection, cursor, statement, parameters, context, executemany):
        if context.compiled is None or not getattr(context.compiled.statement, "is_insert", False):
            return
        if context.compiled.statement.table is not daily_runtime_assignments:
            return
        assert connection.engine is case.account_engine
        assert threading.current_thread() is case.owner._thread
        assert case.proofs == 3 and case.proof_errors == []
        case.sql_inserts += 1
        if case.mode in ("busy", "caller-cancelled", "stop-held"):
            case.at_write.set()
            assert case.allow_write.wait(15), "original SQL write barrier was not released"

    case.after_insert = after_insert
    monkeypatch.setattr(LocalResearchArtifactStore, "put", actual_put)
    monkeypatch.setattr(LocalInstanceGuard, "__exit__", actual_guard_exit)


@contextmanager
def _case(tmp_path, monkeypatch, *, mode="success"):
    with installation_fixture._installation_case(tmp_path, monkeypatch, mode=mode) as case:
        _initialize_observations(case)
        case.owner = InitialSelectionPreparationOwner(
            configuration_path=str(case.configuration_path),
            account_id=case.study.genesis.scope.account_id,
            instance_lock=str(case.lock_path),
        )
        initial = case.owner.status()
        assert type(initial) is InitialSelectionPreparationOwnerStatus
        assert initial.phase == "new" and not initial.busy and not initial.attempted
        assert case.owner._thread is None and case.trace == [] and not case.lock_path.exists()
        assert _snapshot(case.study).__dict__ == case.before.__dict__
        case.incarnation = initial.incarnation
        _watch_originals(case, monkeypatch)
        primary = None
        try:
            yield case
        except BaseException as error:
            primary = error
            raise
        finally:
            for event in (case.allow_put, case.allow_write, case.allow_return, case.allow_ack):
                event.set()
            errors = []
            thread = case.owner._thread
            if thread is not None:
                if not case.owner._finalized and not case.owner._install_dispatched:
                    try:
                        case.owner.stop()
                    except BaseException as error:
                        errors.append(error)
                thread.join(20)
                case.thread = thread
                if thread.is_alive():
                    errors.append(AssertionError("original installation owner has not exited"))
            if case.caller is not None:
                case.caller.join(20)
                if case.caller.is_alive():
                    errors.append(AssertionError("original installation caller has not returned"))
            if case.sql_observer_installed:
                sa.event.remove(case.account_engine, "after_cursor_execute", case.after_insert)
            if thread is not None and not thread.is_alive():
                case.operation_end = _snapshot(case.study)
                case.context_error = case.owner._context_error
                case.operation_error = case.owner._primary_error
            errors.extend(error for error in case.caller_errors if error is not primary)
            if errors:
                if primary is not None:
                    errors.insert(0, primary)
                raise BaseExceptionGroup("installation owner test and cleanup failed", errors)


def _prepare(case):
    started = case.owner.start()
    assert started.phase == "idle" and not started.busy and not started.attempted
    assert not started.cleanup_complete and started.incarnation == case.incarnation
    case.thread = case.owner._thread
    assert case.thread is not None and case.thread.is_alive()
    assert case.stop_event is case.owner._stop_event
    case.original_lease = case.acquires[0]
    case.admitted = _snapshot(case.study)
    assert _same_application_facts(case.before, case.admitted) == {}
    sa.event.listen(case.account_engine, "after_cursor_execute", case.after_insert)
    case.sql_observer_installed = True
    result = case.owner.prepare_initial_selection("actual-preparation")
    assert type(result) is InitialSelectionPreparationResult
    assert result.status == result.reason == "prepared"
    assert result.call_id == "actual-preparation" and result.incarnation == case.incarnation
    assert type(result.descriptor) is InitialSelectionDescriptor
    assert case.preparation_returned.is_set() and case.preparation is not None
    assert case.owner._preparation_return_admitted is True
    case.descriptor = copy_initial_selection_descriptor(result.descriptor)
    _, case.dependency_record = _retained_record(case)
    assert (
        case.descriptor.after_assignment_sha256 == case.dependency_record.proposed.semantic_sha256
    )
    assert case.owner._prepared_proposal_sha256 == case.descriptor.after_assignment_sha256
    object.__setattr__(result.descriptor, "after_assignment_sha256", "0" * 64)
    assert case.owner._prepared_proposal_sha256 == case.descriptor.after_assignment_sha256
    assert case.owner._thread is case.thread and case.close_calls == 0
    assert case.proofs == 2 and len(case.puts) == 1
    case.prepared_snapshot = _snapshot(case.study)
    case.ready.set()
    installation_fixture._issue(case)
    case.install_before = _snapshot(case.study)
    installation_fixture._adverse_delta(case)


def _unavailable(case, result, call_id, reason):
    assert type(result) is InitialSelectionInstallationResult
    assert result.status == "unavailable" and result.reason == reason
    assert result.call_id == call_id and result.incarnation == case.incarnation
    assert result.observation is None


def _facts(case, *, returned, digest):
    expected = (
        True,
        case.pub_calls == 1,
        returned,
        case.issued.receipt.semantic_sha256,
        digest,
    )
    assert case.owner._install_observation == expected
    return expected


def _closed(case, *, cleanup=True):
    case.thread.join(20)
    assert not case.thread.is_alive()
    status = case.owner.status()
    assert type(status) is InitialSelectionPreparationOwnerStatus
    assert status.phase == "stopped" and not status.busy and status.attempted
    assert status.cleanup_complete is cleanup
    assert status.cleanup_failure == (None if cleanup else "cleanup_failed")
    assert case.owner._thread is case.thread and case.profile_restored
    assert case.monitoring_cleaned
    assert case.close_calls == 1 and case.guard_exits == 1
    assert case.disposals == ["dispose-venue", "dispose-account"]
    assert case.runtime.lease is case.original_lease
    case.operation_end = _snapshot(case.study)
    case.context_error = case.owner._context_error
    case.operation_error = case.owner._primary_error
    return status


def _no_replay(case, call_id="terminal-install"):
    counts = case.proofs, len(case.puts), case.pub_calls, case.sql_inserts, case.close_calls
    snapshot = _snapshot(case.study)
    for identifier in (call_id, "another-textual-id"):
        result = case.owner.install_initial_selection(
            identifier, request_receipt=case.issued.receipt
        )
        _unavailable(case, result, identifier, "stopped")
    assert (
        case.proofs,
        len(case.puts),
        case.pub_calls,
        case.sql_inserts,
        case.close_calls,
    ) == counts
    assert _snapshot(case.study).__dict__ == snapshot.__dict__


def _call(case, *, call_id="terminal-install", cancel_event=None, ack_barrier=False):
    def profile(frame, event, argument):
        if (
            ack_barrier
            and not case.ack_barrier_used
            and event == "call"
            and frame.f_code is threading.Condition._acquire_restore.__code__
            and frame.f_locals.get("self") is case.owner._condition
            and case.owner._finalized
        ):
            # This is the original Condition.wait restoration point: its Lock
            # is actually released. Stop can acquire it before the real waiter
            # reacquires; no artificial release of an owned Lock is performed.
            case.ack_barrier_used = True
            case.thread.join(2)
            assert not case.thread.is_alive()
            case.at_ack.set()
            assert case.allow_ack.wait(10), "post-cleanup acknowledgement barrier was not released"

    def caller():
        previous = sys.getprofile()
        sys.setprofile(profile)
        case.caller_started_ns = time.monotonic_ns()
        try:
            case.caller_results.append(
                case.owner.install_initial_selection(
                    call_id, request_receipt=case.request, cancel_event=cancel_event
                )
            )
            case.caller_returned_ns = time.monotonic_ns()
            case.result_at_death = not case.thread.is_alive()
        except BaseException as error:
            case.caller_errors.append(error)
        finally:
            sys.setprofile(previous)
            case.caller_profile_restored = sys.getprofile() is previous
            case.caller_done.set()

    assert case.caller is None
    case.caller = threading.Thread(target=caller, name="actual-terminal-installation-caller")
    case.caller.start()


def _join_caller(case):
    case.caller.join(15)
    assert not case.caller.is_alive() and case.caller_done.is_set()
    if case.caller_errors:
        raise case.caller_errors[0]
    assert len(case.caller_results) == 1 and case.caller_profile_restored
    return case.caller_results[0]


def _installed(case, result):
    assert type(result) is InitialSelectionInstallationResult
    assert result.status == result.reason == "installed"
    assert result.call_id == "terminal-install" and result.incarnation == case.incarnation
    assert type(result.observation) is InitialSelectionInstallationObservation
    expected = InitialSelectionInstallationObservation(
        attempted=True,
        publication_started=True,
        publication_returned=True,
        request_receipt_sha256=case.issued.receipt.semantic_sha256,
        assignment_sha256=case.dependency_record.proposed.semantic_sha256,
    )
    assert result.observation == expected
    assert case.result_at_death is True and not case.thread.is_alive()
    assert case.caller_returned_ns < case.caller_deadline_ns
    assert 0 <= case.caller_returned_ns - case.caller_started_ns < 5_000_000_000
    assert case.owner._install_return_admitted is True
    assert not case.stop_event.is_set() and case.owner._stop_latched is False
    assert case.owner._primary_error is case.owner._context_error is None
    assert case.g_returned and case.install_calls == case.install_constructions == 1
    assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
    retained = _facts(case, returned=True, digest=expected.assignment_sha256)
    object.__setattr__(result.observation, "assignment_sha256", "0" * 64)
    assert case.owner._install_observation == retained
    _closed(case)
    installation_fixture._disabled_b(case, case.requested, case.operation_end)
    _no_replay(case)


def test_actual_same_owner_install_delivers_only_after_original_cleanup_and_thread_death(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch) as case:
        _prepare(case)
        _call(case)
        _installed(case, _join_caller(case))


def test_actual_abandoned_preparation_cannot_be_adopted_by_install(tmp_path, monkeypatch):
    with preparation_fixture._host_case(
        tmp_path, monkeypatch, mode="abandoned-preparation"
    ) as case:
        owner = case.owner
        incarnation = case.incarnation
        _initialize_observations(case)
        case.owner, case.incarnation = owner, incarnation
        case.sql_inserts = case.pub_calls = case.pub_return_events = 0
        _watch_originals(case, monkeypatch)
        preparation_fixture._start(case)
        cancel = threading.Event()
        try:
            preparation_fixture._launch_call(case, cancel_event=cancel)
            assert case.at_put.wait(15), "real preparation did not reach dependency retention"
            cancel.set()
            result = preparation_fixture._join_call(case)
            preparation_fixture._unavailable(case, result, "held-call", "cancelled")
        finally:
            case.allow_put.set()
        assert case.preparation_returned.wait(15)
        assert case.worker_idle.wait(15)
        assert case.owner.status().phase == "idle"
        assert case.owner._preparation_return_admitted is False
        assert case.proofs == 2 and len(case.puts) == 1
        _retained_record(case)
        venue = case.runtime.venue
        # Only the native argument shape is admitted here, never retained
        # authority. Venue record IDs differ from the REQUEST-only ID rule.
        # Copy its native heads/hashes with one request-shaped ID; this is NOT
        # an authenticated retained REQUEST and must never reach the installer.
        locator = venue.journal.read_receipt(
            venue.key, canonical_id("venue-genesis/1", venue.model.semantic_sha256)
        )
        assert locator is not None
        native_argument = replace(locator, record_ids=(locator.command_id,))
        before = _snapshot(case.study)
        denied = case.owner.install_initial_selection(
            "not-adopted", request_receipt=native_argument
        )
        _unavailable(case, denied, "not-adopted", "preparation_unavailable")
        assert _snapshot(case.study).__dict__ == before.__dict__
        assert case.install_calls == case.install_constructions == 0
        assert case.proofs == 2 and len(case.puts) == 1
        assert case.pub_calls == case.sql_inserts == 0


def test_actual_precancelled_install_leaves_the_one_dispatch_available(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        _prepare(case)
        before = _snapshot(case.study)
        cancel = threading.Event()
        cancel.set()
        denied = case.owner.install_initial_selection(
            "pre-cancelled", request_receipt=case.request, cancel_event=cancel
        )
        _unavailable(case, denied, "pre-cancelled", "cancelled")
        assert case.owner.status().phase == "idle"
        assert case.owner._install_dispatched is False
        assert case.install_calls == case.install_constructions == case.pub_calls == 0
        assert case.proofs == 2 and _snapshot(case.study).__dict__ == before.__dict__
        _call(case)
        _installed(case, _join_caller(case))


def test_actual_held_install_has_one_nonce_and_no_same_or_different_id_backlog(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="busy") as case:
        _prepare(case)
        try:
            _call(case)
            assert case.at_write.wait(15)
            slot, nonce = case.owner._slot, case.owner._active_nonce
            assert nonce is case.active_nonce and slot is not None
            counts = case.proofs, case.install_calls, case.pub_calls, case.sql_inserts
            for identifier in ("terminal-install", "concurrent-different-id"):
                denied = case.owner.install_initial_selection(
                    identifier, request_receipt=case.request
                )
                _unavailable(case, denied, identifier, "busy")
            assert case.owner._slot is slot and case.owner._active_nonce is nonce
            assert (case.proofs, case.install_calls, case.pub_calls, case.sql_inserts) == counts
            assert case.thread.is_alive() and case.close_calls == 0
        finally:
            case.allow_write.set()
        _installed(case, _join_caller(case))


def test_actual_install_caller_cancel_keeps_original_work_owned_without_late_delivery(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="caller-cancelled") as case:
        _prepare(case)
        cancel = threading.Event()
        try:
            _call(case, cancel_event=cancel)
            assert case.at_write.wait(15)
            cancel.set()
            _unavailable(case, _join_caller(case), "terminal-install", "cancelled")
            assert case.thread.is_alive() and case.close_calls == 0
            assert case.owner._slot is not None and case.owner._active_nonce is case.active_nonce
            assert case.release_attempts == [] and not case.stop_event.is_set()
        finally:
            case.allow_write.set()
        _closed(case)
        assert case.owner._install_return_admitted is False
        _facts(case, returned=True, digest=case.dependency_record.proposed.semantic_sha256)
        installation_fixture._disabled_b(case, case.requested, case.operation_end)
        _no_replay(case)


def test_actual_post_request_damage_denies_terminal_host_at_original_full_proof(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="request-bytes") as case:
        _prepare(case)
        _call(case)
        _unavailable(case, _join_caller(case), "terminal-install", "installation_failed")
        status = _closed(case)
        assert status.primary_failure == "installation_failed"
        assert type(case.owner._primary_error) is DatabaseSchemaNotReady
        assert str(case.owner._primary_error) == "continuous retained integrity verification failed"
        assert case.proofs == 3 and case.proof_errors == [case.owner._primary_error]
        assert case.pub_calls == case.sql_inserts == 0
        _facts(case, returned=False, digest=None)
        assert case.operation_end.financial == case.install_before.financial
        _no_replay(case)


def test_actual_r2_never_replaces_original_r1_in_terminal_host(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, mode="r2") as case:
        _prepare(case)
        _call(case)
        _unavailable(case, _join_caller(case), "terminal-install", "installation_failed")
        status = _closed(case, cleanup=False)
        assert status.primary_failure == "installation_failed"
        assert type(case.owner._primary_error) is ValueError
        assert str(case.owner._primary_error) == "READINESS_ORIGINAL_LEASE_REVISION_REQUIRED"
        group = case.owner._context_error
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert len(group.exceptions) == 2 and group.exceptions[0] is case.owner._primary_error
        assert str(group.exceptions[1]) == "CONFIGURED_READINESS_RELEASE_INVALID"
        assert case.guard_primaries == [group]
        assert case.runtime.lease is case.original_lease and case.renewed is not case.original_lease
        assert case.releases[0].lease_sha256 == case.renewed.semantic_sha256
        assert case.pub_calls == case.sql_inserts == 0
        _facts(case, returned=False, digest=None)
        assert case.operation_end.financial == case.requested.financial
        _no_replay(case)


def test_actual_post_commit_deadline_retains_private_facts_but_never_delivers_install(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="late-return") as case:
        _prepare(case)
        try:
            _call(case)
            assert case.at_return.wait(15)
            assert case.thread.is_alive() and case.close_calls == 0
            installation_fixture._disabled_b(case, case.requested, case.committed_snapshot)
            _unavailable(case, _join_caller(case), "terminal-install", "deadline")
            assert case.thread.is_alive() and case.release_attempts == []
            assert time.monotonic_ns() >= case.caller_deadline_ns
        finally:
            case.allow_return.set()
        _closed(case)
        assert case.owner._install_return_admitted is False
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        _facts(case, returned=True, digest=case.dependency_record.proposed.semantic_sha256)
        installation_fixture._disabled_b(case, case.requested, case.operation_end)
        _no_replay(case)


def test_actual_commit_then_original_exception_is_not_a_host_install_success(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, mode="commit-failure") as case:
        _prepare(case)
        _call(case)
        _unavailable(case, _join_caller(case), "terminal-install", "installation_failed")
        status = _closed(case)
        assert status.primary_failure == "installation_failed"
        assert case.owner._primary_error is case.primary
        assert case.guard_primaries == [case.primary]
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        _facts(case, returned=False, digest=None)
        installation_fixture._disabled_b(case, case.requested, case.operation_end)
        _no_replay(case)


def test_actual_stop_cutoff_does_not_end_held_install_ownership_or_retry_cleanup(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="stop-held") as case:
        _prepare(case)
        try:
            _call(case)
            assert case.at_write.wait(15)
            first = case.owner.stop()
            cutoff = case.owner._shutdown_deadline
            second = case.owner.stop()
            assert case.owner._shutdown_deadline == cutoff
            for status in (first, second):
                assert status.phase == "stopping" and status.busy
                assert not status.cleanup_complete
            assert case.thread.is_alive() and case.close_calls == 0
            assert case.owner._active_nonce is case.active_nonce
            _unavailable(case, _join_caller(case), "terminal-install", "stopping")
            assert case.release_attempts == [] and case.stop_event.is_set()
        finally:
            case.allow_write.set()
        _closed(case)
        assert type(case.owner._primary_error) is ContinuousAccountConflict
        assert str(case.owner._primary_error) == "CONTINUOUS_COOPERATIVE_STOPPED"
        assert case.sql_inserts == case.pub_calls == 1 and case.pub_return_events == 0
        _facts(case, returned=False, digest=None)
        assert case.operation_end.financial == case.requested.financial
        _no_replay(case)


@pytest.mark.parametrize("interruption", ("normal", "stop", "cancel"))
def test_actual_post_cleanup_pre_ack_interruption_suppresses_install_delivery(
    tmp_path, monkeypatch, interruption
):
    with _case(tmp_path, monkeypatch) as case:
        _prepare(case)
        cancel = threading.Event()
        try:
            _call(case, cancel_event=cancel, ack_barrier=True)
            assert case.at_ack.wait(15), "caller never reached real post-cleanup wait restoration"
            assert not case.thread.is_alive() and case.close_calls == case.guard_exits == 1
            assert case.owner._install_return_admitted is False
            assert case.owner._install_succeeded is True
            if interruption == "stop":
                status = case.owner.stop()
                assert status.phase == "stopped" and status.cleanup_complete
                assert case.stop_event.is_set() and case.owner._stop_latched
            elif interruption == "cancel":
                cancel.set()
                assert not case.stop_event.is_set()
            else:
                assert interruption == "normal"
                assert not case.stop_event.is_set() and not case.owner._stop_latched
        finally:
            case.allow_ack.set()
        if interruption == "normal":
            _installed(case, _join_caller(case))
            return
        reason = "stopping" if interruption == "stop" else "cancelled"
        _unavailable(case, _join_caller(case), "terminal-install", reason)
        _closed(case)
        assert case.owner._install_return_admitted is False
        _facts(case, returned=True, digest=case.dependency_record.proposed.semantic_sha256)
        installation_fixture._disabled_b(case, case.requested, case.operation_end)
        _no_replay(case)


def test_actual_install_primary_and_cleanup_fault_keep_original_ordered_g_group(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, mode="cleanup-failure") as case:
        _prepare(case)
        _call(case)
        _unavailable(case, _join_caller(case), "terminal-install", "installation_failed")
        status = _closed(case, cleanup=False)
        assert status.primary_failure == "installation_failed"
        assert status.cleanup_failure == "cleanup_failed"
        assert case.owner._primary_error is case.primary
        group = case.owner._context_error
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert group.exceptions == (case.primary, case.cleanup_primary)
        assert case.guard_primaries == [group]
        assert case.close_returns == [] and case.close_errors == [case.cleanup_primary]
        assert case.failed_disposals == [case.cleanup_primary]
        _facts(case, returned=False, digest=None)
        installation_fixture._disabled_b(case, case.requested, case.operation_end)
        _no_replay(case)
