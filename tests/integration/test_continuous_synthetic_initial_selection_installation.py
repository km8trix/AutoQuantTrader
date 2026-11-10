"""One terminal disabled installation through genuine fresh configured owners.

The separate fixture issuer uses original session/CSRF and a real REQUEST
transaction. Only its durable receipt crosses to the original G/E worker. SQL
events and an exact original-code profiler observe real publication; no proof,
publisher, prepared token or assignment is substituted. No retained study runs.
"""

import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import Response
from sqlalchemy import Engine

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader import configured_readiness_owner as configured_module
from apps.trader import continuous_readiness_owner as owner_module
from apps.trader import continuous_simulation_factory as factory_module
from apps.trader.initial_selection_descriptor import initial_selection_request_data
from apps.trader.initial_selection_installation import (
    InitialSelectionInstallationObservation,
    _InitialSelectionInstallation,
)
from apps.trader.initial_selection_preparation import _InitialSelectionPreparation
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.account_coordinator import AccountLeaseOwnershipLost
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.runtime_owner_dependency_contracts import MAX_OWNER_DEPENDENCIES_BYTES
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.database import DatabaseSchemaNotReady
from packages.persistence.durable_journal_schema import (
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands, journal_key
from packages.persistence.runtime_owner_dependencies import RuntimeOwnerDependencyError
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


def _table(snapshot, table):
    return dict(snapshot.financial[0])[table.name]


def _mapped(rows, table):
    return [dict(zip((column.name for column in table.columns), row, strict=True)) for row in rows]


def _unchanged_except(before, after, *tables):
    names = {table.name for table in tables}
    assert tuple((name, rows) for name, rows in before.financial[0] if name not in names) == tuple(
        (name, rows) for name, rows in after.financial[0] if name not in names
    )
    assert before.financial[1:] == after.financial[1:]


def _one_added(before, after, table, expected):
    old, new = _table(before, table), _table(after, table)
    assert len(new) == len(old) + 1 and all(row in new for row in old)
    added = [row for row in new if row not in old]
    assert len(added) == 1
    assert _mapped(added, table) == [expected]


def _request_only(case):
    before, after = case.prepared_snapshot, case.requested
    _unchanged_except(before, after, journal_streams, journal_appends, journal_entries)
    prepared, receipt = case.issued.prepared.append, case.issued.receipt
    assert len(prepared.entries) == 1 and receipt == prepared.receipt
    entry = prepared.entries[0]
    _one_added(
        before,
        after,
        journal_streams,
        dict(
            key_sha256=prepared.key.semantic_sha256,
            key_payload=prepared.key_payload,
            last_sequence=receipt.committed_head.sequence,
            last_entry_sha256=receipt.committed_head.entry_sha256,
        ),
    )
    _one_added(
        before,
        after,
        journal_appends,
        dict(
            key_sha256=prepared.key.semantic_sha256,
            command_id=receipt.command_id,
            command_sha256=receipt.command_sha256,
            append_sha256=receipt.append_sha256,
            previous_sequence=receipt.previous_head.sequence,
            previous_entry_sha256=receipt.previous_head.entry_sha256,
            last_sequence=receipt.committed_head.sequence,
            last_entry_sha256=receipt.committed_head.entry_sha256,
            receipt_sha256=receipt.semantic_sha256,
        ),
    )
    _one_added(
        before,
        after,
        journal_entries,
        dict(
            key_sha256=prepared.key.semantic_sha256,
            sequence=entry.sequence,
            command_id=entry.command_id,
            record_id=entry.record.record_id,
            schema_id=entry.record.schema_id,
            payload=entry.record.payload,
            payload_sha256=entry.record.payload_sha256,
            previous_entry_sha256=entry.previous_entry_sha256,
            entry_sha256=entry.semantic_sha256,
        ),
    )
    assert entry.record.payload == personal_codec.encode_record(case.issued.prepared.record)
    assert entry.record.payload_sha256 == sha256(entry.record.payload).hexdigest()
    assert _table(after, daily_runtime_assignments) == ()
    assert _table(after, daily_runtime_assignment_heads) == ()
    assert after.leases == before.leases and after.releases == before.releases
    assert after.heads == before.heads  # REQUEST issuance owns no coordinator operation.


def _disabled_b(case, before, after):
    assert case.proofs == 3 and case.proof_errors == []
    _unchanged_except(before, after, daily_runtime_assignments, daily_runtime_assignment_heads)
    assert _table(before, daily_runtime_assignments) == ()
    assert _table(before, daily_runtime_assignment_heads) == ()
    rows = _mapped(_table(after, daily_runtime_assignments), daily_runtime_assignments)
    assert len(rows) == 1
    row = rows[0]
    record = case.dependency_record
    assignment = personal_codec.decode_record(row["payload"], RuntimeRiskAssignment)
    assert type(assignment) is RuntimeRiskAssignment and assignment == record.proposed
    assert personal_codec.encode_record(assignment) == row["payload"]
    assert row["payload_sha256"] == sha256(row["payload"]).hexdigest()
    assert assignment.generation == 1 and assignment.previous_assignment_sha256 is None
    assert assignment.enabled_for_new_exposure is assignment.live_authorized is False
    assert assignment.policy == case.study.genesis.restored.checkpoint.inputs.spec.risk_policy
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
    # SQLite's native DateTime reader returns naive UTC; compare that known
    # storage representation without changing the actual owners' UTC clocks.
    assert type(row["recorded_at"]) is datetime and row["recorded_at"].tzinfo is None
    assert command.requested_at <= row["recorded_at"].replace(tzinfo=UTC) < command.expires_at
    assert _mapped(
        _table(after, daily_runtime_assignment_heads), daily_runtime_assignment_heads
    ) == [
        dict(
            account_id=assignment.account_id,
            generation=1,
            semantic_sha256=assignment.semantic_sha256,
        )
    ]


def _adverse_delta(case):
    before, after = case.requested, case.install_before
    if case.mode in ("request-bytes", "changed-c1"):
        table = journal_entries if case.mode == "request-bytes" else continuous_account_commits
        _unchanged_except(before, after, table)
        old, new = _mapped(_table(before, table), table), _mapped(_table(after, table), table)
        assert len(new) == len(old)
        removed = [row for row in old if row not in new]
        added = [row for row in new if row not in old]
        assert len(removed) == len(added) == 1
        expected = dict(removed[0])
        if case.mode == "request-bytes":
            payload = expected["payload"]
            assert expected["key_sha256"] == case.issued.receipt.committed_head.key_sha256
            expected["payload"] = bytes([payload[0] ^ 1]) + payload[1:]
        else:
            assert expected["account_id"] == case.study.genesis.scope.account_id
            assert expected["sequence"] == 1
            expected["owner_id"] = "different-retained-owner"
        assert added == [expected]
    elif case.mode == "dependency-bytes":
        assert before.financial[:2] == after.financial[:2]
        assert before.financial[2][1] == after.financial[2][1]
        expected = dict(before.financial[2][0])
        name = case.puts[0][0].object_sha256 + ".json"
        old = expected[name]
        expected[name] = bytes([old[0] ^ 1]) + old[1:]
        assert dict(after.financial[2][0]) == expected
    else:
        assert after.financial == before.financial


def _observe_effects(case, monkeypatch):
    original_put = LocalResearchArtifactStore.put
    original_close = factory_module.ContinuousSimulationFactory.close
    original_dispose = Engine.dispose
    original_exit = LocalInstanceGuard.__exit__
    original_release = SqlAccountCoordinator.release

    def put(store, payload, **kwargs):
        reference = original_put(store, payload, **kwargs)
        if case.runtime is not None and store is case.runtime.reader.account.artifacts:
            assert threading.current_thread() is case.thread
            assert kwargs["max_bytes"] == MAX_OWNER_DEPENDENCIES_BYTES and not case.puts
            case.puts.append((reference, payload))
        return reference

    def close(factory):
        try:
            result = original_close(factory)
        except BaseException as error:
            case.close_errors.append(error)
            raise
        case.close_returns.append(result)
        return result

    def dispose(engine, *args, **kwargs):
        result = original_dispose(engine, *args, **kwargs)
        if engine is case.venue_engine and case.mode == "cleanup-failure":
            case.failed_disposals.append(case.cleanup_primary)
            raise case.cleanup_primary
        return result

    def guard_exit(guard, kind, error, traceback):
        if guard is case.guard:
            case.guard_primaries.append(error)
        return original_exit(guard, kind, error, traceback)

    def release(coordinator, fence):
        try:
            return original_release(coordinator, fence)
        except BaseException as error:
            case.release_errors.append(error)
            raise

    monkeypatch.setattr(LocalResearchArtifactStore, "put", put)
    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "close", close)
    monkeypatch.setattr(Engine, "dispose", dispose)
    monkeypatch.setattr(LocalInstanceGuard, "__exit__", guard_exit)
    monkeypatch.setattr(SqlAccountCoordinator, "release", release)


def _lease_boundary_lifecycle(case):
    """Keep an actual expired head distinct from a returned durable release."""
    before, after = case.before, _snapshot(case.study)
    case.after = after
    assert after.financial == case.operation_end.financial == case.install_before.financial
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    assert _same_application_facts(before, case.admitted) == {}
    assert _same_application_facts(case.admitted, case.prepared_snapshot) == {
        ref.object_sha256 + ".json": payload for ref, payload in case.puts
    }
    assert len(case.puts) == len(case.acquires) == 1 and case.renewed is None
    _request_only(case)
    lease = case.acquires[0]
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    added = [row for row in after.leases if row not in before.leases]
    assert [account_lease_from_row(row) for row in added] == [lease]
    assert after.leases == case.admitted.leases == case.prepared_snapshot.leases
    assert lease.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert lease.revision_number == 1 and lease.previous_lease_sha256 is None
    assert lease.policy_sha256 == case.configuration.lease_policy().semantic_sha256
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
    assert before.heads[0]["current_fencing_generation"] is None
    assert before.heads[0]["current_lease_sha256"] is None
    assert case.admitted.releases == case.prepared_snapshot.releases == before.releases
    assert case.admitted.heads[0]["current_lease_sha256"] == lease.semantic_sha256
    assert case.failed_disposals == []
    labels = [label for label, _ in case.trace]
    close_index = labels.index("close")
    assert labels.index("dispose-venue") < labels.index("dispose-account")
    assert labels.index("dispose-account") < labels.index("guard-exit")
    if case.mode == "released-r1":
        # The fixture's explicit precondition release is separate from the
        # sole original G-close call. Its idempotent release creates no row.
        assert case.fixture_release is not None
        assert case.release_attempts == [lease.fence, lease.fence]
        assert case.releases == [case.fixture_release, case.fixture_release]
        release_indices = [index for index, label in enumerate(labels) if label == "release"]
        assert release_indices[0] < close_index
        assert close_index < release_indices[1] < labels.index("dispose-venue")
        assert case.release_errors == case.close_errors == []
        assert case.close_returns == [case.fixture_release]
        assert len(after.releases) == len(before.releases) + 1
        assert all(row in after.releases for row in before.releases)
        row = next(row for row in after.releases if row not in before.releases)
        assert account_lease_release_from_row(row) == case.fixture_release
        assert case.fixture_release.fence == lease.fence
        assert case.fixture_release.lease_sha256 == lease.semantic_sha256
        assert lease.acquired_at <= case.fixture_release.released_at < lease.expires_at
        assert after.releases == case.install_before.releases
        assert (
            after.heads
            == case.install_before.heads
            == (
                dict(
                    account_id=lease.account_id,
                    last_fencing_generation=lease.fencing_generation,
                    current_fencing_generation=None,
                    current_lease_sha256=None,
                    updated_at=row["released_at"],
                ),
            )
        )
    else:
        assert case.mode == "lease-expired" and case.fixture_release is None
        assert case.expiry_observed_at >= lease.expires_at
        assert case.release_attempts == [lease.fence] and case.releases == []
        assert close_index < labels.index("release") < labels.index("dispose-venue")
        assert len(case.release_errors) == len(case.close_errors) == 1
        assert type(case.release_errors[0]) is AccountLeaseOwnershipLost
        assert str(case.release_errors[0]) == "account coordinator lease has expired"
        assert type(case.close_errors[0]) is factory_module.ContinuousSimulationFactoryError
        assert str(case.close_errors[0]) == "OFFLINE_LEASE_RELEASE_FAILED"
        assert case.close_returns == []
        assert after.releases == case.operation_end.releases == before.releases
        assert case.operation_end.heads == case.install_before.heads
        old_head, retained_head = case.operation_end.heads[0], after.heads[0]
        assert retained_head == {
            **old_head,
            "updated_at": retained_head["updated_at"],
        }
        assert retained_head["current_fencing_generation"] == lease.fencing_generation
        assert retained_head["last_fencing_generation"] == lease.fencing_generation
        assert retained_head["current_lease_sha256"] == lease.semantic_sha256
        assert retained_head["updated_at"] >= old_head["updated_at"]
        assert retained_head["updated_at"].replace(tzinfo=UTC) >= lease.expires_at
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


def _lifecycle(case):
    assert case.thread is not None and not case.thread.is_alive()
    assert case.executions == case.factory_reads == 0 and case.constructor_error is None
    assert case.close_calls == 1 and case.guard_exits == 1 and case.guard._descriptor is None
    assert case.disposals == ["dispose-venue", "dispose-account"]
    assert all(thread is case.thread for _, thread in case.trace)
    labels = [label for label, _ in case.trace]
    assert labels[-1] == "guard-exit"
    if case.mode in ("released-r1", "lease-expired"):
        _lease_boundary_lifecycle(case)
        return
    assert labels.index("close") < labels.index("release") < labels.index("dispose-venue")
    assert labels.index("dispose-account") < labels.index("guard-exit")
    after = _snapshot(case.study)
    case.after = after
    assert after.financial == case.operation_end.financial
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    assert _same_application_facts(case.before, case.admitted) == {}
    assert _same_application_facts(case.admitted, case.prepared_snapshot) == {
        ref.object_sha256 + ".json": payload for ref, payload in case.puts
    }
    assert len(case.puts) == 1
    _request_only(case)
    before = case.before
    expected_leases = [case.acquires[0]] + ([] if case.renewed is None else [case.renewed])
    assert len(case.acquires) == len(case.releases) == 1
    assert len(after.leases) == len(before.leases) + len(expected_leases)
    assert all(row in after.leases for row in before.leases)
    added = [row for row in after.leases if row not in before.leases]
    # Snapshot primary-key order is digest order, not lease revision order.
    added.sort(key=lambda row: row["revision_number"])
    assert [account_lease_from_row(row) for row in added] == expected_leases
    lease = case.acquires[0]
    assert lease.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert lease.revision_number == 1 and lease.previous_lease_sha256 is None
    assert lease.policy_sha256 == case.configuration.lease_policy().semantic_sha256
    assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
    assert case.admitted.leases == case.prepared_snapshot.leases
    assert case.admitted.releases == before.releases
    assert case.admitted.heads == (
        {
            "account_id": lease.account_id,
            "last_fencing_generation": lease.fencing_generation,
            "current_fencing_generation": lease.fencing_generation,
            "current_lease_sha256": lease.semantic_sha256,
            "updated_at": case.admitted.heads[0]["updated_at"],
        },
    )
    assert case.admitted.heads[0]["updated_at"] >= added[0]["acquired_at"]
    assert before.heads[0]["current_fencing_generation"] is None
    assert before.heads[0]["current_lease_sha256"] is None
    assert case.release_attempts == [lease.fence]
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    release_row = next(row for row in after.releases if row not in before.releases)
    release = account_lease_release_from_row(release_row)
    assert release == case.releases[0]
    current = expected_leases[-1]
    assert release.fence == lease.fence and release.lease_sha256 == current.semantic_sha256
    assert current.acquired_at <= release.released_at < current.expires_at
    assert after.heads == (
        {
            "account_id": lease.account_id,
            "last_fencing_generation": lease.fencing_generation,
            "current_fencing_generation": None,
            "current_lease_sha256": None,
            "updated_at": release_row["released_at"],
        },
    )
    if case.mode == "cleanup-failure":
        assert case.close_returns == [] and case.close_errors == [case.cleanup_primary]
        assert case.failed_disposals == [case.cleanup_primary]
    else:
        assert case.close_errors == case.failed_disposals == []
        assert case.close_returns == case.releases
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


@contextmanager
def _installation_case(tmp_path, monkeypatch, *, mode="success"):
    with study_module._study(tmp_path, install=False) as study:
        _assert_initial_state(study, installed=False)
        daily = study.owners.daily.resolve_snapshot(
            study.owners.daily.read_snapshot(
                account_id=study.genesis.scope.account_id, fence=study.lease.fence
            )
        )
        configuration = _configuration(study)
        _seed_phase_zero(study)
        path = study.root / "terminal-installation.json"
        payload = personal_codec.encode_record(configuration)
        study_module._exclusive_file(path, payload)
        study_module._release_setup(study)
        before = _snapshot(study)
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()
        case = SimpleNamespace(
            study=study,
            configuration=configuration,
            configuration_path=path,
            configuration_bytes=payload,
            lock_path=study.root / "terminal-installation.lock",
            before=before,
            admitted=None,
            prepared_snapshot=None,
            requested=None,
            install_before=None,
            operation_end=None,
            after=None,
            mode=mode,
            caller_thread=threading.current_thread(),
            thread=None,
            trace=[],
            factory=None,
            constructor_error=None,
            checkpoints=0,
            close_calls=0,
            executions=0,
            factory_reads=0,
            acquires=[],
            releases=[],
            release_attempts=[],
            release_errors=[],
            fixture_release=None,
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
            close_returns=[],
            close_errors=[],
            failed_disposals=[],
            guard_primaries=[],
            puts=[],
            setup_daily=daily,
            preparation=None,
            descriptor=None,
            installer=None,
            issued=None,
            request=None,
            ready=threading.Event(),
            request_ready=threading.Event(),
            finished=threading.Event(),
            at_return=threading.Event(),
            allow_return=threading.Event(),
            failures=[],
            operation_error=None,
            context_error=None,
            result=None,
            historical=None,
            observation_before=None,
            observed=None,
            deadline_ns=None,
            elapsed_ns=None,
            primary=RuntimeError("test original publication fault"),
            cleanup_primary=RuntimeError("test original venue disposal returned then failed"),
            pub_calls=0,
            pub_return_events=0,
            sql_inserts=0,
            renewed=None,
            profile_restored=False,
            committed_snapshot=None,
            dependency_record=None,
            abort_expiry=threading.Event(),
            expiry_waiting=threading.Event(),
            expiry_observed_at=None,
            returned_assignment=None,
            returned_original=None,
            repeat_error=None,
        )
        _observe(case, monkeypatch)
        _observe_effects(case, monkeypatch)
        primary = None
        try:
            yield case
        except BaseException as error:
            primary = error
            raise
        finally:
            case.request_ready.set()
            case.allow_return.set()
            case.allow_startup.set()
            case.abort_expiry.set()
            errors = []
            if case.thread is not None:
                case.thread.join(20)
                if case.thread.is_alive():
                    errors.append(AssertionError("original installation thread has not exited"))
                else:
                    try:
                        _lifecycle(case)
                    except BaseException as error:
                        errors.append(error)
            if errors:
                if primary is not None:
                    errors.insert(0, primary)
                if case.context_error is not None and case.context_error is not primary:
                    errors.append(case.context_error)
                errors.extend(error for error in case.failures if error is not primary)
                raise BaseExceptionGroup("installation test and original cleanup failed", errors)


def _issue(case):
    assert threading.current_thread() is case.caller_thread and case.ready.is_set()
    scope, heads, reference = initial_selection_request_data(case.descriptor)
    if case.mode == "foreign":
        scope = replace(scope, stream_id="foreign-terminal-installation")
    at = datetime.now(UTC)
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="actual-fixture-issuer",
        configured_secret="test-only-not-an-application-credential",
    )
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=at, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    authenticator = LocalRuntimeOwnerAuthenticator(security)
    api = SqlRuntimeOwnerCommands(
        case.study.ports["account_engine"], codec=personal_codec, authenticator=authenticator
    )
    duration = timedelta(milliseconds=250) if case.mode == "expired" else timedelta(seconds=30)
    command = RuntimeAssignmentCommand(
        "terminal-initial-selection-request",
        "actual-fixture-issuer",
        scope.account_id,
        None,
        case.descriptor.after_assignment_sha256,
        heads,
        case.descriptor.dependency_semantic_sha256,
        at,
        min(at + duration, case.descriptor.valid_until),
    )
    authenticated = authenticator.authenticate(
        command,
        session_cookie=cookies[LOCAL_SESSION_COOKIE].value,
        csrf_token=capability.csrf_token,
        now=at,
    )
    prepared = api.prepare(
        scope,
        command=command,
        authenticated=authenticated,
        dependencies=reference,
        expected_head=api.journal.read_head(journal_key(scope)),
    )
    api.require_prepared(prepared)
    with api.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        receipt = api.append_in_transaction(connection, prepared)
    actual = api.read(scope, command_id=command.command_id, budget=RuntimeReadBudget())
    assert actual is not None
    api.require_resolved(actual)
    assert actual.record == prepared.record and actual.read.receipt == receipt
    assert api is not case.runtime.reader.associations.owner_dependencies.commands
    assert authenticated.authentication.authenticated_at == command.requested_at == at
    assert command.expires_at <= min(
        case.descriptor.valid_until,
        authenticated.authentication.session_expires_at,
        at + timedelta(seconds=60),
    )
    case.issued = SimpleNamespace(api=api, prepared=prepared, receipt=receipt, command=command)
    case.requested = _snapshot(case.study)
    _request_only(case)
    case.request = replace(receipt)  # Equal detached locators are deliberately accepted.
    assert case.request == receipt and case.request is not receipt
    if case.mode == "altered-receipt":
        case.request = replace(receipt, command_sha256="1" * 64)
    if case.mode == "request-bytes":
        entry = prepared.append.entries[0]
        damaged = bytes([entry.record.payload[0] ^ 1]) + entry.record.payload[1:]
        with api.engine.begin() as connection:
            changed = connection.execute(
                sa.update(journal_entries)
                .where(
                    journal_entries.c.key_sha256 == receipt.committed_head.key_sha256,
                    journal_entries.c.sequence == receipt.committed_head.sequence,
                )
                .values(payload=damaged)
            )
            assert changed.rowcount == 1
    if case.mode == "dependency-bytes":
        path = case.study.paths["artifact_root"] / (reference.object_ref.object_sha256 + ".json")
        old = path.read_bytes()
        path.write_bytes(bytes([old[0] ^ 1]) + old[1:])
    if case.mode == "changed-c1":
        with api.engine.begin() as connection:
            changed = connection.execute(
                sa.update(continuous_account_commits)
                .where(
                    continuous_account_commits.c.account_id == scope.account_id,
                    continuous_account_commits.c.sequence == 1,
                )
                .values(owner_id="different-retained-owner")
            )
            assert changed.rowcount == 1
    if case.mode == "expired":
        remaining = max(0, (command.expires_at - datetime.now(UTC)).total_seconds())
        assert not case.finished.wait(remaining)
        assert datetime.now(UTC) >= command.expires_at
    case.request_ready.set()


def _historical(case):
    assert case.guard_exits == 1
    forbidden = {
        owner_module._ReadinessRuntime._require.__code__,
        owner_module._ReadinessRuntime._now.__code__,
        owner_module._ReadinessRuntime.verify.__code__,
        Engine.connect.__code__,
        LocalResearchArtifactStore.read.__code__,
        LocalResearchArtifactStore.put.__code__,
    }
    calls = []

    def profile(frame, event, argument):
        if event == "call" and frame.f_code in forbidden:
            calls.append(frame.f_code.co_name)
        elif event == "c_call" and argument is time.monotonic_ns:
            calls.append("monotonic_ns")

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        first, second = case.installer.observation(), case.installer.observation()
        assert type(first) is type(second) is InitialSelectionInstallationObservation
        assert first == second == case.observed and first is not second
        object.__setattr__(first, "request_receipt_sha256", "0" * 64)
        assert case.installer.observation() == second
        case.historical = second
    finally:
        sys.setprofile(previous)
    assert calls == [] and sys.getprofile() is previous


def _perform(case):
    original_publish_code = SqlRuntimeAssignmentPublication.publish.__code__

    def profile(frame, event, argument):
        if frame.f_code is not original_publish_code:
            return
        assert threading.current_thread() is case.thread
        if event == "call":
            case.pub_calls += 1
        elif event == "return" and type(argument) is RuntimeRiskAssignment:
            case.pub_return_events += 1
            if case.mode == "returned-content":
                # The original method has physically committed and is now
                # returning its actual proposed instance, not a substitute.
                case.committed_snapshot = _snapshot(case.study)
                assert argument is case.preparation._prepared.record.proposed
                case.returned_original = replace(argument)
                case.returned_assignment = argument
                assert argument.configuration_sha256 != "0" * 64
                object.__setattr__(argument, "configuration_sha256", "0" * 64)
            if case.mode in ("late-return", "commit-failure"):
                # The real transaction has exited, but the original method has
                # not returned to the adapter yet. This is not a mocked commit.
                case.committed_snapshot = _snapshot(case.study)
                case.at_return.set()
                if case.mode == "commit-failure":
                    raise case.primary
                assert case.allow_return.wait(15), "test did not release original return barrier"

    def after_insert(connection, cursor, statement, parameters, context, executemany):
        if context.compiled is None or not getattr(context.compiled.statement, "is_insert", False):
            return
        if context.compiled.statement.table is not daily_runtime_assignments:
            return
        case.sql_inserts += 1
        assert connection.engine is case.account_engine
        assert threading.current_thread() is case.thread
        if case.mode == "rollback":
            raise case.primary
        if case.mode == "stop-write":
            case.stop_event.set()

    sa.event.listen(case.account_engine, "after_cursor_execute", after_insert)
    previous = sys.getprofile()
    sys.setprofile(profile)
    started = time.monotonic_ns()
    case.deadline_ns = started + 5_000_000_000
    try:
        try:
            result = case.installer.install(case.request, deadline_ns=case.deadline_ns)
            case.elapsed_ns = time.monotonic_ns() - started
            case.result = result
        except BaseException as error:
            case.operation_error = error
            raise
        finally:
            try:
                case.observed = case.installer.observation()
                case.operation_end = _snapshot(case.study)
                if case.observed.attempted and case.mode == "returned-content":
                    counts = case.proofs, len(case.puts), case.pub_calls, case.sql_inserts
                    unchanged = _snapshot(case.study)
                    # Changed original prepared content may be rejected before
                    # the terminal-attempt diagnostic; it must never retry.
                    with pytest.raises(RuntimeOwnerDependencyError) as caught:
                        case.installer.install(case.request, deadline_ns=case.deadline_ns)
                    case.repeat_error = caught.value
                    assert str(caught.value) == "ORIGINAL_OWNER_DEPENDENCY_FIELDS_CHANGED"
                    assert (case.proofs, len(case.puts), case.pub_calls, case.sql_inserts) == counts
                    assert _snapshot(case.study).financial == unchanged.financial
                    assert case.installer.observation() == case.observed
                elif case.observed.attempted and case.mode not in ("stop-write", "r2"):
                    counts = case.proofs, len(case.puts), case.pub_calls, case.sql_inserts
                    with pytest.raises(
                        ValueError, match=r"^INITIAL_SELECTION_INSTALLATION_ALREADY_ATTEMPTED$"
                    ):
                        case.installer.install(case.request, deadline_ns=case.deadline_ns)
                    assert (case.proofs, len(case.puts), case.pub_calls, case.sql_inserts) == counts
                    assert case.installer.observation() == case.observed
            except BaseException as oracle_error:
                if case.operation_error is not None:
                    raise BaseExceptionGroup(
                        "installation failure and observation failed",
                        [case.operation_error, oracle_error],
                    ) from None
                raise
    finally:
        sys.setprofile(previous)
        sa.event.remove(case.account_engine, "after_cursor_execute", after_insert)
        case.profile_restored = sys.getprofile() is previous


def _launch(case):
    def worker():
        try:
            context = contextmanager(configured_module._CONFIGURED_RUNTIME_GENERATOR)
            with context(
                configuration_file=case.configuration_path,
                lock_path=case.lock_path,
                account_id=case.study.genesis.scope.account_id,
                stop_event=threading.Event(),
            ) as runtime:
                assert runtime is case.runtime
                case.admitted = _snapshot(case.study)
                preparation = _InitialSelectionPreparation(runtime)
                case.preparation = preparation
                case.descriptor = preparation.prepare(
                    deadline_ns=time.monotonic_ns() + 5_000_000_000
                )
                assert case.proofs == 2 and len(case.puts) == 1
                _, case.dependency_record = _retained_record(case)
                case.prepared_snapshot = _snapshot(case.study)
                case.installer = _InitialSelectionInstallation(preparation)
                case.observation_before = case.installer.observation()
                assert case.observation_before == InitialSelectionInstallationObservation(
                    attempted=False,
                    publication_started=False,
                    publication_returned=False,
                    request_receipt_sha256=None,
                    assignment_sha256=None,
                )
                original_state = dict(vars(case.installer))
                with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_INSTALLATION_INVALID$"):
                    case.installer.__init__(preparation)
                assert vars(case.installer) == original_state
                assert case.proofs == 2 and len(case.puts) == 1
                worker_commands = runtime.reader.associations.owner_dependencies.commands
                assert worker_commands.authenticator.security._enabled is False
                case.ready.set()
                assert case.request_ready.wait(15), "fixture issuer did not deliver its receipt"
                assert type(case.request) is JournalReceipt
                if case.mode == "r2":
                    case.renewed = case.factory.coordinator.renew(case.acquires[0].fence)
                    assert case.renewed.fence == case.acquires[0].fence
                    assert case.renewed.revision_number == 2
                    assert case.renewed.previous_lease_sha256 == case.acquires[0].semantic_sha256
                if case.mode == "released-r1":
                    assert case.release_attempts == [] and case.releases == []
                    case.fixture_release = case.factory.coordinator.release(case.acquires[0].fence)
                    assert case.release_attempts == [case.acquires[0].fence]
                    assert case.releases == [case.fixture_release] and case.close_calls == 0
                if case.mode == "lease-expired":
                    lease = case.acquires[0]
                    assert case.descriptor.valid_until == lease.expires_at
                    assert case.issued.command.expires_at <= lease.expires_at
                    case.expiry_waiting.set()
                    # Actual UTC reaches the immutable original R1 expiry;
                    # this wait is outside install's new five-second budget.
                    remaining = max(0, (lease.expires_at - datetime.now(UTC)).total_seconds())
                    assert not case.abort_expiry.wait(remaining), "expiry observation abandoned"
                    case.expiry_observed_at = datetime.now(UTC)
                    assert case.expiry_observed_at >= lease.expires_at
                case.install_before = _snapshot(case.study)
                _adverse_delta(case)
                _perform(case)
                assert worker_commands.authenticator.security._enabled is False
                original_state = dict(vars(case.installer))
                counts = case.proofs, len(case.puts), case.pub_calls
                with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_INSTALLATION_INVALID$"):
                    case.installer.__init__(preparation)
                assert vars(case.installer) == original_state
                assert (case.proofs, len(case.puts), case.pub_calls) == counts
                if case.mode == "cleanup-failure":
                    raise case.primary
                assert case.installer.observation() == case.observed
        except BaseException as error:
            case.context_error = error
        finally:
            if case.installer is not None and case.observed is not None:
                try:
                    _historical(case)
                except BaseException as error:
                    case.failures.append(error)
            case.finished.set()

    assert case.thread is None and case.trace == []
    case.thread = threading.Thread(target=worker, name="fresh-terminal-installation")
    case.thread.start()


def _join(case):
    timeout = 20
    if case.mode == "lease-expired":
        # Observe only to the original absolute expiry plus the same bounded
        # teardown allowance. This does not extend or renew financial authority.
        timeout += max(0, (case.acquires[0].expires_at - datetime.now(UTC)).total_seconds())
    case.thread.join(timeout)
    assert not case.thread.is_alive() and case.finished.is_set()
    if case.failures:
        raise case.failures[0]
    assert case.operation_end is not None, case.context_error
    assert case.profile_restored


def _start_and_issue(case):
    _launch(case)
    assert case.ready.wait(20), ("original E preparation did not return", case.context_error)
    _issue(case)


def _no_publication(case, *, attempted=True):
    assert case.result is None and case.context_error is not None
    assert case.pub_calls == case.pub_return_events == case.sql_inserts == 0
    assert case.operation_end.financial == case.install_before.financial
    assert case.observed == InitialSelectionInstallationObservation(
        attempted=attempted,
        publication_started=False,
        publication_returned=False,
        request_receipt_sha256=case.request.semantic_sha256 if attempted else None,
        assignment_sha256=None,
    )
    assert case.historical == case.observed


def test_actual_request_installs_only_prepared_disabled_b_and_closes_original_r1(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch) as case:
        _start_and_issue(case)
        _join(case)
        assert case.context_error is case.operation_error is None
        assert case.proofs == 3 and case.proof_errors == []
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        assert case.result == case.observed == case.historical
        assert type(case.result) is InitialSelectionInstallationObservation
        assert case.result is not case.observed and case.historical is not case.observed
        assert case.result == InitialSelectionInstallationObservation(
            attempted=True,
            publication_started=True,
            publication_returned=True,
            request_receipt_sha256=case.issued.receipt.semantic_sha256,
            assignment_sha256=case.dependency_record.proposed.semantic_sha256,
        )
        assert 0 <= case.elapsed_ns < 5_000_000_000
        _disabled_b(case, case.requested, case.operation_end)


def test_actual_foreign_stream_receipt_does_not_install_local_b(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="foreign") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert type(case.operation_error) is RuntimeOwnerDependencyError
        assert str(case.operation_error) == "ACTUAL_RETAINED_OWNER_REQUEST_REQUIRED"


def test_actual_altered_receipt_digest_is_not_adopted(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="altered-receipt") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert type(case.operation_error) is RuntimeOwnerDependencyError
        assert str(case.operation_error) == "ACTUAL_RETAINED_OWNER_REQUEST_REQUIRED"


def test_actual_damaged_request_bytes_fail_original_full_proof(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="request-bytes") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert case.proofs == 3 and case.proof_errors == [case.operation_error]
        assert type(case.operation_error) is DatabaseSchemaNotReady
        assert str(case.operation_error) == "continuous retained integrity verification failed"


def test_actual_damaged_dependency_object_is_not_refreshed(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="dependency-bytes") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert case.operation_error is case.context_error
        assert len(case.puts) == 1
        assert case.proofs == 3 and case.proof_errors == [case.operation_error]
        assert type(case.operation_error) is DatabaseSchemaNotReady
        assert str(case.operation_error) == "continuous retained integrity verification failed"


def test_actual_changed_c1_metadata_cannot_replace_preparation_fingerprint(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="changed-c1") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert case.operation_error is case.context_error
        assert case.proofs == 2 and case.proof_errors == []
        assert type(case.operation_error) is ContinuousAccountConflict
        assert str(case.operation_error) == "CONTINUOUS_RETAINED_INDEX_INVALID"


def test_actual_expired_short_command_does_not_extend_dependencies(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="expired") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert type(case.operation_error) is RuntimeOwnerDependencyError
        assert str(case.operation_error) == "OWNER_REQUEST_ORIGINAL_DEPENDENCIES_DIFFER_OR_EXPIRED"
        # The command is deliberately the earlier bound. This does not qualify
        # a 60-second wait, session refresh, or dependency-expiry timing case.
        assert case.issued.command.expires_at < case.descriptor.valid_until


def test_actual_same_fence_r2_is_not_original_r1_and_cleanup_is_truthful(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="r2") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert type(case.operation_error) is ValueError
        assert str(case.operation_error) == "READINESS_ORIGINAL_LEASE_REVISION_REQUIRED"
        group = case.context_error
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert group.exceptions[0] is case.operation_error
        assert len(group.exceptions) == 2
        assert str(group.exceptions[1]) == "CONFIGURED_READINESS_RELEASE_INVALID"
        assert case.guard_primaries == [group]


def test_actual_stop_after_b_write_rolls_back_before_commit(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="stop-write") as case:
        _start_and_issue(case)
        _join(case)
        assert case.stop_event.is_set() and case.sql_inserts == case.pub_calls == 1
        assert case.pub_return_events == 0 and case.result is None
        assert type(case.operation_error) is ContinuousAccountConflict
        assert str(case.operation_error) == "CONTINUOUS_COOPERATIVE_STOPPED"
        assert case.operation_end.financial == case.requested.financial
        assert case.observed.publication_started and not case.observed.publication_returned
        assert case.observed.assignment_sha256 is None


def test_actual_b_write_then_exception_preserves_request_and_rolls_back(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="rollback") as case:
        _start_and_issue(case)
        _join(case)
        assert case.operation_error is case.context_error is case.primary
        assert case.sql_inserts == case.pub_calls == 1 and case.pub_return_events == 0
        assert case.operation_end.financial == case.requested.financial
        assert case.observed.publication_started and not case.observed.publication_returned
        assert case.observed.assignment_sha256 is None and case.result is None


def test_actual_commit_return_after_native_deadline_retains_b_without_delivery(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch, mode="late-return") as case:
        try:
            _start_and_issue(case)
            assert case.at_return.wait(15), "original committed publication did not reach return"
            assert case.thread.is_alive() and case.close_calls == 0
            assert case.release_attempts == []
            _disabled_b(case, case.requested, case.committed_snapshot)
            remaining = max(0, case.deadline_ns - time.monotonic_ns()) / 1_000_000_000
            assert not case.finished.wait(remaining)
            assert time.monotonic_ns() >= case.deadline_ns
        finally:
            case.allow_return.set()
            if case.thread is not None:
                _join(case)
        assert case.result is None and type(case.operation_error) is owner_module._DeadlineExpired
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        assert case.observed.publication_returned is True
        assert case.observed.assignment_sha256 == case.dependency_record.proposed.semantic_sha256
        _disabled_b(case, case.requested, case.operation_end)


def test_actual_commit_then_exception_is_unknown_return_and_never_retried(tmp_path, monkeypatch):
    with _installation_case(tmp_path, monkeypatch, mode="commit-failure") as case:
        _start_and_issue(case)
        _join(case)
        assert case.operation_error is case.context_error is case.primary
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        assert case.result is None and case.observed.publication_started
        assert not case.observed.publication_returned and case.observed.assignment_sha256 is None
        _disabled_b(case, case.requested, case.committed_snapshot)
        _disabled_b(case, case.requested, case.operation_end)


def test_actual_returned_publication_and_primary_survive_original_cleanup_group(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch, mode="cleanup-failure") as case:
        _start_and_issue(case)
        _join(case)
        assert case.result == case.observed == case.historical
        assert case.result.publication_returned is True
        assert case.result.assignment_sha256 == case.dependency_record.proposed.semantic_sha256
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        group = case.context_error
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert group.exceptions == (case.primary, case.cleanup_primary)
        assert case.guard_primaries == [group]
        _disabled_b(case, case.requested, case.operation_end)


def test_actual_released_r1_denies_install_and_g_close_returns_only_original_release(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch, mode="released-r1") as case:
        _start_and_issue(case)
        _join(case)
        _no_publication(case)
        assert case.operation_error is case.context_error
        assert type(case.operation_error) is AccountLeaseOwnershipLost
        assert str(case.operation_error) == "account fence is no longer current"
        assert case.proofs == 2 and case.proof_errors == []
        assert case.fixture_release is not None and case.close_calls == 1
        assert case.release_attempts == [case.acquires[0].fence, case.acquires[0].fence]
        assert case.releases == [case.fixture_release, case.fixture_release]
        assert case.close_returns == [case.fixture_release]
        assert case.close_errors == case.release_errors == []
        assert case.guard_primaries == [case.operation_error]
        assert case.operation_end.releases == case.install_before.releases
        assert case.operation_end.heads == case.install_before.heads


def test_actual_original_sixty_second_r1_expiry_retains_head_and_failed_release(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch, mode="lease-expired") as case:
        _start_and_issue(case)
        assert case.expiry_waiting.wait(15), "worker did not reach actual R1 expiry observation"
        _join(case)
        _no_publication(case)
        lease = case.acquires[0]
        assert case.expiry_observed_at >= lease.expires_at
        assert lease.expires_at - lease.acquired_at == timedelta(seconds=60)
        assert case.descriptor.valid_until == lease.expires_at
        assert case.issued.command.expires_at <= case.descriptor.valid_until
        assert case.proofs == 2 and case.proof_errors == []
        assert type(case.operation_error) is AccountLeaseOwnershipLost
        assert str(case.operation_error) == "account coordinator lease has expired"
        assert len(case.release_errors) == 1
        assert type(case.release_errors[0]) is AccountLeaseOwnershipLost
        assert str(case.release_errors[0]) == "account coordinator lease has expired"
        assert case.release_errors[0] is not case.operation_error
        assert case.release_attempts == [lease.fence] and case.releases == []
        assert case.close_calls == 1 and case.close_returns == []
        assert len(case.close_errors) == 1
        assert type(case.close_errors[0]) is factory_module.ContinuousSimulationFactoryError
        assert str(case.close_errors[0]) == "OFFLINE_LEASE_RELEASE_FAILED"
        group = case.context_error
        assert type(group) is ExceptionGroup
        assert group.message == "configured readiness and factory cleanup failed"
        assert group.exceptions == (case.operation_error, case.close_errors[0])
        assert case.guard_primaries == [group]
        assert not case.abort_expiry.is_set()
        assert case.operation_end.releases == case.before.releases
        assert case.operation_end.heads == case.install_before.heads
        assert case.operation_end.heads[0]["current_lease_sha256"] == lease.semantic_sha256


def test_actual_returned_assignment_content_change_preserves_return_without_digest(
    tmp_path, monkeypatch
):
    with _installation_case(tmp_path, monkeypatch, mode="returned-content") as case:
        _start_and_issue(case)
        _join(case)
        assert case.result is None and case.operation_error is case.context_error
        assert type(case.operation_error) is ValueError
        assert str(case.operation_error) == "INITIAL_SELECTION_INSTALLATION_INVALID"
        assert case.pub_calls == case.pub_return_events == case.sql_inserts == 1
        assert (
            case.observed
            == case.historical
            == InitialSelectionInstallationObservation(
                attempted=True,
                publication_started=True,
                publication_returned=True,
                request_receipt_sha256=case.issued.receipt.semantic_sha256,
                assignment_sha256=None,
            )
        )
        assert case.returned_assignment is case.preparation._prepared.record.proposed
        assert case.returned_assignment.configuration_sha256 == "0" * 64
        assert case.returned_original == case.dependency_record.proposed
        assert (
            replace(
                case.returned_assignment,
                configuration_sha256=case.returned_original.configuration_sha256,
            )
            == case.returned_original
        )
        assert type(case.repeat_error) is RuntimeOwnerDependencyError
        assert str(case.repeat_error) == "ORIGINAL_OWNER_DEPENDENCY_FIELDS_CHANGED"
        _disabled_b(case, case.requested, case.committed_snapshot)
        _disabled_b(case, case.requested, case.operation_end)
