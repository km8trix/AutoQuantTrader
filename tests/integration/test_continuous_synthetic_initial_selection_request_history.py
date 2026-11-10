"""Fresh REQUEST history after original owner cleanup, never another install.

I establishes real committed/ambiguous/rolled-back outcomes. Its unchanged
fixture completes the original lease, engines, guard and Thread before J runs
through a different, explicitly owned Engine. D remains unowned comparison data.
"""

import sys
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, Response

from apps.api import initial_selection_request_history as history
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_SESSION_COOKIE, MetadataAccessSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.initial_selection_descriptor import (
    copy_initial_selection_descriptor,
    initial_selection_request_data,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.domain.durable_journal_contracts import MAX_RECORD_BYTES, JournalReceipt
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import (
    journal_appends,
    journal_entries,
    journal_streams,
)
from packages.persistence.runtime_owner_commands import (
    ResolvedRuntimeOwnerCommand,
    RuntimeOwnerCommandError,
    RuntimeOwnerCommandSnapshot,
    SqlRuntimeOwnerCommands,
    journal_key,
)
from packages.persistence.sqlite_exit_cursor_cleanup import configure_sqlite_exit_cursor_cleanup
from tests.integration import (
    test_continuous_synthetic_initial_selection_installation as original_installation,
)
from tests.integration import (
    test_continuous_synthetic_initial_selection_request_retention as actual_i,
)
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot

_COMMAND_ID = "retained-initial-request"
_INVALID = r"^INITIAL_SELECTION_REQUEST_HISTORY_INVALID$"
_DIFFERS = r"^INITIAL_SELECTION_REQUEST_HISTORY_DIFFERS$"


def _session(security, *, remaining=None):
    at = datetime.now(UTC)
    issued_at = at if remaining is None else at - timedelta(hours=8) + remaining
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=issued_at, session_cookie=None
    )
    # This is test-owned original session issuance, not HTTP/main readiness.
    assert capability.enabled is True
    return actual_i._cookie(response, LOCAL_SESSION_COOKIE), capability.csrf_token


@contextmanager
def _history_case(
    tmp_path,
    monkeypatch,
    *,
    outcome="committed",
    other_operator=False,
    original_remaining=None,
):
    retained = outcome != "rollback"
    with actual_i._case(tmp_path, monkeypatch, retained=retained) as case:
        actual_i._issuer(case, remaining=original_remaining)
        before_i = _snapshot(case.study)
        if outcome == "ambiguous":
            case.i_mode = "copy-fault"
            with actual_i._observe_call(case) as probe, pytest.raises(RuntimeError) as caught:
                actual_i._invoke(case)
            assert caught.value is case.i_copy_primary and probe.after_commit_fault
            assert probe.appends == probe.inserts == probe.commits == 1
            actual_i._adopt_request(case, probe)
            case.expected_receipt = replace(probe.append_receipt)
        elif outcome == "rollback":
            case.i_mode = "rollback-exception"
            with (
                actual_i._observe_call(case) as probe,
                pytest.raises(RuntimeOwnerCommandError) as caught,
            ):
                actual_i._invoke(case)
            assert str(caught.value) == "OWNER_REQUEST_APPEND_FAILED"
            assert probe.appends == probe.inserts == probe.write_rollbacks == 1
            assert probe.commits == 0
            assert _snapshot(case.study).__dict__ == before_i.__dict__
            case.expected_receipt = None
        else:
            with actual_i._observe_call(case) as probe:
                returned = actual_i._invoke(case)
            actual_i._adopt_request(case, probe, returned)
            case.expected_receipt = replace(returned)
        assert case.proofs == 2 and len(case.puts) == 1
        assert case.owner._install_dispatched is False
        case.retention_probe = probe
    # The entire old fixture, including its separate I Engine disposal, exited.
    assert not case.thread.is_alive()
    status = case.owner.status()
    assert status.phase == "stopped" and status.cleanup_complete is True
    assert case.close_calls == case.guard_exits == 1
    assert case.disposals == ["dispose-venue", "dispose-account"]
    assert len(case.acquires) == len(case.releases) == 1
    assert case.release_attempts == [case.acquires[0].fence]
    assert case.releases[0].lease_sha256 == case.acquires[0].semantic_sha256
    case.history_before = _snapshot(case.study)
    assert all(row["current_lease_sha256"] is None for row in case.history_before.heads)
    engine = create_database_engine(str(case.study.ports["account_engine"].url))
    primary = None
    try:
        configure_sqlite_exit_cursor_cleanup(engine)
        security = case.issuer.security
        cookie, csrf = case.issuer.cookie, case.issuer.csrf
        if original_remaining is not None:
            # New current test-owned session, without changing any historical
            # record. The original shorter signed session will genuinely expire.
            cookie, csrf = _session(security)
        if other_operator:
            security = LocalOperatorSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="independent-current-history-reader",
                configured_secret="fresh-history-test-only-configuration",
            )
            cookie, csrf = _session(security)
        commands = SqlRuntimeOwnerCommands(
            engine, codec=personal_codec, authenticator=LocalRuntimeOwnerAuthenticator(security)
        )
        assert engine is not case.owned_issuer_engine
        assert engine is not case.account_engine and engine is not case.venue_engine
        case.history = SimpleNamespace(
            engine=engine,
            commands=commands,
            security=security,
            cookie=cookie,
            csrf=csrf,
        )
        yield case
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            engine.dispose()
        except BaseException as cleanup:
            if primary is not None:
                raise BaseExceptionGroup(
                    "history test and owned Engine cleanup failed", [primary, cleanup]
                ) from None
            raise


def _call(case, **changes):
    port = case.history
    arguments = dict(
        security=port.security,
        commands=port.commands,
        engine=port.engine,
        account_id=case.descriptor.account_id,
        descriptor=case.descriptor,
        command_id=_COMMAND_ID,
        session_cookie=port.cookie,
        csrf_token=port.csrf,
    )
    arguments.update(changes)
    return history._read_initial_selection_request(**arguments)


@contextmanager
def _observe(case, *, expire_after_read=None, mutate_resolved=False):
    port = case.history
    probe = SimpleNamespace(
        reads=0,
        captures=0,
        resolves=0,
        requires=0,
        auth=0,
        command_auth=0,
        budgets=[],
        charges=[],
        resolved=None,
        snapshot=None,
        auth_returns=[],
        begins=0,
        rollbacks=0,
        commits=0,
        writes=0,
        disposed=0,
        connections=[],
        inside=False,
        forbidden=[],
        objects=0,
        appends=0,
        prepares=0,
    )
    labels = {
        LocalOperatorSecurity.authenticate_with_expiry.__code__: "auth",
        LocalRuntimeOwnerAuthenticator.authenticate.__code__: "command-auth",
        SqlRuntimeOwnerCommands.read.__code__: "read",
        SqlRuntimeOwnerCommands.capture_in_transaction.__code__: "capture",
        SqlRuntimeOwnerCommands.resolve_snapshot.__code__: "resolve",
        SqlRuntimeOwnerCommands.require_resolved.__code__: "require",
        SqlRuntimeOwnerCommands._fingerprint.__code__: "fingerprint",
        SqlRuntimeOwnerCommands.prepare.__code__: "prepare",
        SqlRuntimeOwnerCommands.append_in_transaction.__code__: "append",
        RuntimeReadBudget.__init__.__code__: "budget",
        RuntimeReadBudget.charge.__code__: "charge",
        personal_codec.encode_record.__code__: "encode",
        personal_codec.decode_record.__code__: "decode",
        LocalResearchArtifactStore.read.__code__: "object-read",
        LocalResearchArtifactStore.put.__code__: "object-put",
    }
    thread = threading.current_thread()
    monitor, tool = sys.monitoring, 3
    previous_profile = sys.getprofile()
    owned = False
    enabled, registered = [], []

    def observe(frame, event, returned):
        try:
            assert threading.current_thread() is thread and not case.thread.is_alive()
            label = labels[frame.f_code]
            if event == "call":
                if probe.inside and label in {
                    "auth",
                    "command-auth",
                    "resolve",
                    "require",
                    "fingerprint",
                    "encode",
                    "decode",
                    "object-read",
                    "object-put",
                    "prepare",
                    "append",
                }:
                    probe.forbidden.append(label)
                if label == "auth":
                    probe.auth += 1
                elif label == "command-auth":
                    probe.command_auth += 1
                elif label in ("object-read", "object-put"):
                    probe.objects += 1
                elif label == "prepare":
                    probe.prepares += 1
                elif label == "append":
                    probe.appends += 1
                elif label in ("read", "capture", "resolve", "require"):
                    assert frame.f_locals["self"] is port.commands
                    if label == "read":
                        probe.reads += 1
                        assert not probe.inside
                    elif label == "capture":
                        probe.captures += 1
                        assert probe.inside
                    elif label == "resolve":
                        probe.resolves += 1
                        assert not probe.inside
                        assert all(connection.closed for connection in probe.connections)
                    else:
                        probe.requires += 1
                        assert not probe.inside
                elif label == "charge":
                    assert probe.inside and frame.f_locals["self"] is probe.budgets[0]
                    values = tuple(frame.f_locals[name] for name in ("rows", "payload", "metadata"))
                    assert all(type(value) is int and value >= 0 for value in values)
                    assert values[0] <= 4096
                    probe.charges.append(values)
            elif event == "return":
                if label == "auth" and type(returned) is tuple:
                    probe.auth_returns.append(returned)
                elif label == "budget":
                    budget = frame.f_locals["self"]
                    assert type(budget) is RuntimeReadBudget
                    assert (
                        budget.rows,
                        budget.payload_bytes,
                        budget.metadata_bytes,
                        budget.captured,
                    ) == (0, 0, 0, [])
                    probe.budgets.append(budget)
                elif label == "read":
                    assert not probe.inside and all(
                        connection.closed for connection in probe.connections
                    )
                    probe.resolved = returned
                    if mutate_resolved:
                        assert type(returned) is ResolvedRuntimeOwnerCommand
                        object.__setattr__(
                            returned.record.command, "after_assignment_sha256", "f" * 64
                        )
                    if expire_after_read is not None:
                        remaining = max(0, (expire_after_read - datetime.now(UTC)).total_seconds())
                        threading.Event().wait(remaining)
                        assert datetime.now(UTC) >= expire_after_read
                elif label == "capture" and type(returned) is RuntimeOwnerCommandSnapshot:
                    probe.snapshot = returned
        finally:
            del frame

    def on_start(code, offset):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code and code in labels
            observe(frame, "call", None)
        finally:
            del frame

    def on_return(code, offset, returned):
        frame = sys._getframe(1)
        try:
            assert frame.f_code is code and code in labels
            observe(frame, "return", returned)
        finally:
            del frame

    def connected(connection):
        probe.connections.append(connection)

    def sql(connection, cursor, statement, parameters, context, executemany):
        if statement == "BEGIN":
            probe.begins += 1
            probe.inside = True
        if statement == "BEGIN IMMEDIATE" or (
            context.compiled is not None and getattr(context.compiled.statement, "is_dml", False)
        ):
            probe.writes += 1

    def rollback(connection):
        probe.rollbacks += 1
        probe.inside = False

    def commit(connection):
        probe.commits += 1

    def disposed(engine):
        assert engine is port.engine
        probe.disposed += 1

    listeners = (
        ("engine_connect", connected),
        ("after_cursor_execute", sql),
        ("rollback", rollback),
        ("commit", commit),
        ("engine_disposed", disposed),
    )
    primary = None
    installed = []
    try:
        for name, callback in listeners:
            sa.event.listen(port.engine, name, callback)
            installed.append((name, callback))
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-request-history-original-ports")
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
        yield probe
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
                assert monitor.get_tool(tool) == "aqt-request-history-original-ports"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        for name, callback in installed:
            try:
                sa.event.remove(port.engine, name, callback)
            except BaseException as error:
                errors.append(error)
        try:
            assert sys.getprofile() is previous_profile
            assert probe.forbidden == [] and probe.objects == probe.command_auth == 0
            assert (
                probe.appends
                == probe.prepares
                == probe.writes
                == probe.commits
                == probe.disposed
                == 0
            )
            assert all(connection.closed for connection in probe.connections)
        except BaseException as error:
            errors.append(error)
        if errors:
            if primary is not None:
                errors.insert(0, primary)
            raise BaseExceptionGroup("history observation and cleanup failed", errors)


def _unchanged(case, before):
    assert _snapshot(case.study).__dict__ == before.__dict__
    assert case.proofs == 2 and len(case.puts) == 1
    assert case.close_calls == case.guard_exits == 1 and not case.thread.is_alive()
    assert len(case.acquires) == len(case.releases) == 1
    assert case.owner._install_dispatched is False
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    # A separate caller operation after observation, not another J read/retry.
    with case.history.engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT 1")) == 1


def _read_once(probe, *, found=True):
    assert probe.reads == probe.captures == probe.resolves == probe.begins == 1
    assert probe.rollbacks == 1 and len(probe.budgets) == len(probe.charges) == 1
    assert probe.auth == 2 and len(probe.auth_returns) == 2
    assert probe.auth_returns[0] == probe.auth_returns[1]
    assert (probe.resolved is not None) is found
    budget = probe.budgets[0]
    assert (budget.rows, budget.payload_bytes, budget.metadata_bytes) == probe.charges[0]
    assert budget.rows <= 16384 and budget.payload_bytes <= 32 * 1024 * 1024
    assert budget.metadata_bytes <= 2 * 1024 * 1024
    if found:
        assert type(probe.resolved) is ResolvedRuntimeOwnerCommand and probe.requires >= 2
    else:
        assert probe.requires == 0


@pytest.mark.parametrize("outcome", ("committed", "ambiguous", "other-operator"))
def test_actual_committed_or_unknown_return_history_uses_one_original_read(
    tmp_path, monkeypatch, outcome
):
    with _history_case(
        tmp_path,
        monkeypatch,
        outcome="ambiguous" if outcome == "ambiguous" else "committed",
        other_operator=outcome == "other-operator",
    ) as case:
        before = _snapshot(case.study)
        with _observe(case) as probe:
            receipt = _call(case, descriptor=copy_initial_selection_descriptor(case.descriptor))
        _read_once(probe)
        assert type(receipt) is JournalReceipt and receipt == case.expected_receipt
        assert receipt is not case.expected_receipt and receipt is not probe.resolved.read.receipt
        assert receipt.previous_head is not probe.resolved.read.receipt.previous_head
        assert receipt.committed_head is not probe.resolved.read.receipt.committed_head
        historical = probe.resolved.record
        assert historical == case.issued.prepared.record
        if outcome == "other-operator":
            assert case.history.security._operator_id != historical.command.owner_id
        object.__setattr__(receipt.previous_head, "entry_sha256", "0" * 64)
        assert probe.resolved.read.receipt == case.expected_receipt
        _unchanged(case, before)


def test_actual_rolled_back_request_is_missing_not_reissued(tmp_path, monkeypatch):
    with _history_case(tmp_path, monkeypatch, outcome="rollback") as case:
        before = _snapshot(case.study)
        with _observe(case) as probe:
            assert _call(case) is None
        _read_once(probe, found=False)
        assert case.retention_probe.commits == 0
        _unchanged(case, before)


def _append_later_fixture_request(case):
    # A separate explicit fixture intent, not an I retry or historical refresh.
    port = case.history
    scope, heads, reference = initial_selection_request_data(case.descriptor)
    at = datetime.now(UTC)
    operator, session_expiry = port.security.authenticate_with_expiry(
        port.cookie, port.csrf, now=at
    )
    command = RuntimeAssignmentCommand(
        "later-independent-history-fixture",
        operator,
        scope.account_id,
        None,
        case.descriptor.after_assignment_sha256,
        heads,
        reference.semantic_sha256,
        at,
        min(at + timedelta(seconds=60), session_expiry, case.descriptor.valid_until),
    )
    authenticated = port.commands.authenticator.authenticate(
        command, session_cookie=port.cookie, csrf_token=port.csrf, now=at
    )
    prepared = port.commands.prepare(
        scope,
        command=command,
        authenticated=authenticated,
        dependencies=reference,
        expected_head=port.commands.journal.read_head(journal_key(scope)),
    )
    port.commands.require_prepared(prepared)
    before = _snapshot(case.study)
    with port.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        receipt = port.commands.append_in_transaction(connection, prepared)
    after = _snapshot(case.study)
    original_installation._unchanged_except(
        before, after, journal_streams, journal_appends, journal_entries
    )
    assert (
        before.leases == after.leases
        and before.releases == after.releases
        and before.heads == after.heads
    )
    original_installation._one_added(
        before,
        after,
        journal_entries,
        dict(
            key_sha256=prepared.append.key.semantic_sha256,
            sequence=prepared.append.entries[0].sequence,
            command_id=command.command_id,
            record_id=command.command_id,
            schema_id=prepared.append.entries[0].record.schema_id,
            payload=personal_codec.encode_record(prepared.record),
            payload_sha256=prepared.append.entries[0].record.payload_sha256,
            previous_entry_sha256=prepared.append.entries[0].previous_entry_sha256,
            entry_sha256=prepared.append.entries[0].semantic_sha256,
        ),
    )
    original_installation._one_added(
        before,
        after,
        journal_appends,
        dict(
            key_sha256=prepared.append.key.semantic_sha256,
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
    streams = original_installation._mapped(
        original_installation._table(before, journal_streams), journal_streams
    )
    expected_streams = [
        dict(
            row,
            last_sequence=receipt.committed_head.sequence,
            last_entry_sha256=receipt.committed_head.entry_sha256,
        )
        if row["key_sha256"] == prepared.append.key.semantic_sha256
        else row
        for row in streams
    ]
    assert (
        original_installation._mapped(
            original_installation._table(after, journal_streams), journal_streams
        )
        == expected_streams
    )
    assert receipt.previous_head == case.expected_receipt.committed_head
    assert receipt.committed_head.sequence == case.expected_receipt.committed_head.sequence + 1
    return prepared, receipt


def test_actual_expired_history_and_later_append_keep_original_times_after_r1_release(
    tmp_path, monkeypatch
):
    with _history_case(tmp_path, monkeypatch, original_remaining=timedelta(seconds=12)) as case:
        original = case.issued.prepared.record
        old_bytes = personal_codec.encode_record(original)
        later, later_receipt = _append_later_fixture_request(case)
        assert later.record.command.requested_at > original.command.requested_at
        assert later.record.command.expires_at > original.command.expires_at
        assert later_receipt != case.expected_receipt
        assert case.descriptor.valid_until == case.dependency_record.valid_until
        assert original.command.expires_at <= case.descriptor.valid_until
        assert not case.thread.is_alive() and len(case.releases) == 1
        # No live owner or lease is prolonged. This is ordinary test elapsed time
        # after actual original cleanup, never a larger host/request time budget.
        remaining = max(0, (case.descriptor.valid_until - datetime.now(UTC)).total_seconds())
        threading.Event().wait(remaining)
        assert datetime.now(UTC) >= case.descriptor.valid_until
        assert datetime.now(UTC) >= original.authentication.session_expires_at
        before = _snapshot(case.study)
        with _observe(case) as probe:
            receipt = _call(case)
        _read_once(probe)
        assert receipt == case.expected_receipt
        assert probe.resolved.record == original
        assert personal_codec.encode_record(probe.resolved.record) == old_bytes
        assert probe.resolved.record.command.requested_at == original.command.requested_at
        assert probe.resolved.record.command.expires_at == original.command.expires_at
        assert (
            probe.resolved.record.authentication.session_expires_at
            == original.authentication.session_expires_at
        )
        assert probe.resolved.read.head == later_receipt.committed_head
        _unchanged(case, before)


@pytest.mark.parametrize(
    "kind", ("missing", "expired", "foreign", "csrf", "operational", "metadata")
)
def test_actual_current_authentication_denies_before_history_sql(tmp_path, monkeypatch, kind):
    with _history_case(tmp_path, monkeypatch) as case:
        port = case.history
        cookie, csrf = port.cookie, port.csrf
        at = datetime.now(UTC)
        if kind == "missing":
            cookie = None
        elif kind == "expired":
            cookie, csrf = _session(port.security, remaining=timedelta(seconds=-2))
        elif kind == "foreign":
            foreign = LocalOperatorSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="actual-request-operator",
                configured_secret="fresh-test-only-session-configuration",
            )
            cookie, csrf = _session(foreign)
            assert (
                foreign.authenticate(cookie, csrf, now=datetime.now(UTC))
                == "actual-request-operator"
            )
        elif kind == "csrf":
            csrf = "wrong-current-csrf"
        elif kind == "operational":
            security = ContinuousReadAccessSecurity(
                configuration=ContinuousReadAccessConfiguration(
                    enabled=True,
                    transport_is_loopback_scoped=True,
                    operator_id="actual-request-operator",
                    configured_secret="test-only-operational-read",
                ),
                account_id=case.descriptor.account_id,
            )
            security.open()
            response = Response()
            capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
            cookie, csrf = (
                actual_i._cookie(response, CONTINUOUS_READ_SESSION_COOKIE),
                capability.csrf_token,
            )
            assert security.authenticate(cookie, csrf, now=at) == "actual-request-operator"
            security.close()
        else:
            security = MetadataAccessSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="actual-request-operator",
                configured_secret="test-only-metadata-read",
            )
            response = Response()
            capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
            cookie, csrf = (
                actual_i._cookie(response, METADATA_SESSION_COOKIE),
                capability.csrf_token,
            )
            assert security.authenticate(cookie, csrf, now=at) == "actual-request-operator"
        before = _snapshot(case.study)
        with _observe(case) as probe, pytest.raises(HTTPException) as caught:
            _call(case, session_cookie=cookie, csrf_token=csrf)
        assert caught.value.status_code == (403 if kind == "csrf" else 401)
        assert caught.value.detail == (
            "backtest launch CSRF validation failed"
            if kind == "csrf"
            else "a current local operator session is required"
        )
        assert probe.auth == 1 and probe.reads == probe.captures == probe.begins == 0
        assert probe.budgets == [] and probe.connections == []
        _unchanged(case, before)


def test_actual_session_expiry_after_original_closed_read_denies_delivery(tmp_path, monkeypatch):
    with _history_case(tmp_path, monkeypatch) as case:
        port = case.history
        port.cookie, port.csrf = _session(port.security, remaining=timedelta(seconds=3))
        _, expiry = port.security.authenticate_with_expiry(
            port.cookie, port.csrf, now=datetime.now(UTC)
        )
        before = _snapshot(case.study)
        with (
            _observe(case, expire_after_read=expiry) as probe,
            pytest.raises(HTTPException) as caught,
        ):
            _call(case)
        assert caught.value.status_code == 401
        assert caught.value.detail == "a current local operator session is required"
        assert probe.auth == 2 and len(probe.auth_returns) == 1
        assert (
            probe.reads == probe.captures == probe.resolves == probe.begins == probe.rollbacks == 1
        )
        assert type(probe.resolved) is ResolvedRuntimeOwnerCommand
        _unchanged(case, before)


@pytest.mark.parametrize(
    "field",
    (
        "after_assignment_sha256",
        "ledger_sha256",
        "dependency_object_sha256",
        "dependency_byte_count",
        "dependency_semantic_sha256",
    ),
)
def test_actual_found_record_must_match_unowned_comparison_data(tmp_path, monkeypatch, field):
    with _history_case(tmp_path, monkeypatch) as case:
        count = case.descriptor.dependency_byte_count
        changed = (count - 1 if count > 1 else 2) if field == "dependency_byte_count" else "f" * 64
        descriptor = replace(case.descriptor, **{field: changed})
        assert getattr(descriptor, field) != getattr(case.descriptor, field)
        before = _snapshot(case.study)
        with _observe(case) as probe, pytest.raises(ValueError, match=_DIFFERS):
            _call(case, descriptor=descriptor)
        assert probe.reads == probe.captures == probe.resolves == 1
        assert type(probe.resolved) is ResolvedRuntimeOwnerCommand
        _unchanged(case, before)


def test_actual_alternate_valid_scope_is_missing_not_a_foreign_receipt(tmp_path, monkeypatch):
    with _history_case(tmp_path, monkeypatch) as case:
        descriptor = replace(case.descriptor, account_binding_sha256="f" * 64)
        before = _snapshot(case.study)
        with _observe(case) as probe:
            assert _call(case, descriptor=descriptor) is None
        _read_once(probe, found=False)
        _unchanged(case, before)


def test_actual_explicit_account_mismatch_denies_before_auth_or_sql(tmp_path, monkeypatch):
    with _history_case(tmp_path, monkeypatch) as case:
        before = _snapshot(case.study)
        with _observe(case) as probe, pytest.raises(ValueError, match=_INVALID):
            _call(case, account_id="other-explicit-account")
        assert probe.auth == probe.reads == probe.captures == probe.begins == 0
        assert probe.connections == []
        _unchanged(case, before)


def test_actual_owned_resolved_mutation_is_rejected_without_changing_retained_rows(
    tmp_path, monkeypatch
):
    with _history_case(tmp_path, monkeypatch) as case:
        before = _snapshot(case.study)
        with (
            _observe(case, mutate_resolved=True) as probe,
            pytest.raises(RuntimeOwnerCommandError) as caught,
        ):
            _call(case)
        assert str(caught.value) == "ORIGINAL_OWNER_REQUEST_FIELDS_CHANGED"
        assert probe.reads == probe.captures == probe.resolves == probe.requires == 1
        assert probe.auth == 1
        assert probe.resolved.record.command.after_assignment_sha256 == "f" * 64
        assert (
            case.issued.prepared.record.command.after_assignment_sha256
            == case.descriptor.after_assignment_sha256
        )
        _unchanged(case, before)


@pytest.mark.parametrize("damage", ("payload", "oversize", "missing-entry-table"))
def test_actual_corrupt_or_unreadable_history_is_an_error_never_missing(
    tmp_path, monkeypatch, damage
):
    with _history_case(tmp_path, monkeypatch) as case:
        entry = case.issued.prepared.append.entries[0]
        key = case.issued.prepared.append.key.semantic_sha256
        if damage == "missing-entry-table":
            journal_entries.drop(case.history.engine)
        else:
            payload = entry.record.payload
            broken = (
                bytes([payload[0] ^ 1]) + payload[1:]
                if damage == "payload"
                else b"x" * (MAX_RECORD_BYTES + 1)
            )
            with case.history.engine.begin() as connection:
                count = connection.execute(
                    sa.update(journal_entries)
                    .where(
                        journal_entries.c.key_sha256 == key,
                        journal_entries.c.sequence == entry.sequence,
                    )
                    .values(payload=broken)
                ).rowcount
                assert count == 1
        # This exact independently damaged state, not the pristine state, is the
        # immutable no-effects baseline. No deletion/repair of an old store.
        before = _snapshot(case.study)
        expected = (
            "OWNER_REQUEST_CAPTURE_FAILED"
            if damage == "missing-entry-table"
            else "OWNER_REQUEST_RESOLUTION_FAILED"
        )
        with _observe(case) as probe, pytest.raises(RuntimeOwnerCommandError) as caught:
            _call(case)
        assert str(caught.value) == expected
        assert probe.reads == probe.captures == probe.begins == probe.rollbacks == 1
        if damage == "oversize":
            assert type(probe.snapshot) is RuntimeOwnerCommandSnapshot
            assert len(probe.snapshot.journal.head_anchor["payload"]) == MAX_RECORD_BYTES + 1
            assert (
                len(probe.snapshot.journal.requested_receipt.entries[0]["payload"])
                == MAX_RECORD_BYTES + 1
            )
            assert len(probe.charges) == 1
            assert probe.charges[0][1] == MAX_RECORD_BYTES + 1 + len(
                case.issued.prepared.append.key_payload
            )
        _unchanged(case, before)
