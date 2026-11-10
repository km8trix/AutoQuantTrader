"""Fresh shared-session REQUEST retention, independently from installation.

The H/F owners are real. A small preparation-only prefix deliberately omits H's
old fixture issuer. SQL events and local original-code events observe the new
operation; no pinned financial/authentication method is replaced for success.
"""

import sqlite3
import sys
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException, Response

from apps.api import initial_selection_request_retention as retention
from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import (
    METADATA_SESSION_COOKIE,
    MetadataAccessSecurity,
)
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    copy_initial_selection_descriptor,
    initial_selection_request_data,
)
from apps.trader.initial_selection_preparation_owner import InitialSelectionPreparationResult
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.runtime_owner_commands import (
    OWNER_COMMAND_SCHEMA,
    PreparedRuntimeOwnerCommand,
    RuntimeOwnerCommandError,
    RuntimeOwnerCommandRecord,
    SqlRuntimeOwnerCommands,
    journal_key,
)
from packages.persistence.sqlite_exit_cursor_cleanup import configure_sqlite_exit_cursor_cleanup
from tests.integration import (
    test_continuous_synthetic_initial_selection_installation as original_installation,
)
from tests.integration import (
    test_continuous_synthetic_initial_selection_installation_owner as actual_host,
)
from tests.integration import (
    test_continuous_synthetic_initial_selection_preparation_owner as original_preparation,
)
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_initial_selection_preparation import (
    _retained_record,
)

_INVALID = r"^INITIAL_SELECTION_REQUEST_INVALID$"
_CHANGED = r"^INITIAL_SELECTION_REQUEST_BINDING_CHANGED$"


def _prepare_only(case, *, retained):
    """Original host preparation; no REQUEST issuer is called by this prefix."""
    case.owned_issuer_engine = None
    original_preparation._start(case)
    case.original_lease = case.acquires[0]
    if retained:
        sa.event.listen(case.account_engine, "after_cursor_execute", case.after_insert)
        case.sql_observer_installed = True
    result = case.owner.prepare_initial_selection("request-retention-preparation")
    assert type(result) is InitialSelectionPreparationResult
    assert result.status == result.reason == "prepared"
    assert type(result.descriptor) is InitialSelectionDescriptor
    assert result.incarnation == case.incarnation
    assert case.owner._preparation_return_admitted is True
    case.descriptor = copy_initial_selection_descriptor(result.descriptor)
    _, case.dependency_record = _retained_record(case)
    assert (
        case.descriptor.after_assignment_sha256 == case.dependency_record.proposed.semantic_sha256
    )
    assert case.owner._prepared_proposal_sha256 == case.descriptor.after_assignment_sha256
    assert case.proofs == 2 and len(case.puts) == 1 and case.close_calls == 0
    assert case.owner._thread.is_alive() and not case.stop_event.is_set()
    case.prepared_snapshot = _snapshot(case.study)
    case.issued = None
    case.i_mode = "success"
    case.i_primary = KeyboardInterrupt("actual REQUEST append interrupted")
    case.i_exception = RuntimeError("actual REQUEST append failed")
    case.i_copy_primary = RuntimeError("actual committed REQUEST copy failed")
    case.fixture_headmove = False
    case.headmove_prepared = case.headmove_receipt = None
    case.headmove_snapshot = None
    case.expiry_observed = None


@contextmanager
def _case(tmp_path, monkeypatch, *, retained=False):
    # The original F teardown is intentionally only used for zero REQUEST.
    # Original H/G teardown independently accepts the exact retained REQUEST
    # write set, whether or not the separate host installation is dispatched.
    fixture = actual_host._case if retained else original_preparation._host_case
    case = None
    primary = None
    try:
        with fixture(tmp_path, monkeypatch) as case:
            _prepare_only(case, retained=retained)
            yield case
    except BaseException as failure:
        primary = failure
        # The original oracle runs before its cleanup-error assertions. Preserve
        # that exact failure and observe the already-finished owner only; never
        # repeat stop, close, release, join or any other cleanup operation here.
        context_error = None if case is None else case.owner._context_error
        if context_error is None:
            raise
        cause = context_error.__context__
        summary = [
            "original owner context type="
            + type(context_error).__module__
            + "."
            + type(context_error).__qualname__
        ]
        if cause is not None:
            summary.append(
                "context type=" + type(cause).__module__ + "." + type(cause).__qualname__
            )
            if isinstance(cause, sa.exc.DBAPIError) and isinstance(cause.orig, sqlite3.Error):
                code = getattr(cause.orig, "sqlite_errorcode", None)
                name = getattr(cause.orig, "sqlite_errorname", None)
                if type(code) is int:
                    summary.append("sqlite_errorcode=" + str(code))
                if type(name) is str and name.startswith("SQLITE_") and name.isidentifier():
                    summary.append("sqlite_errorname=" + name)
        # Do not serialize exception graphs, SQL, parameters, session data or
        # arbitrary exception messages. The actual errors stay in these locals.
        observation = AssertionError("; ".join(summary))
        primary = BaseExceptionGroup(
            "original request fixture failure and sanitized owner observation",
            [failure, observation],
        )
        raise primary from None
    finally:
        # This separate issuer Engine belongs to this fixture. Original H/F/G
        # cleanup and its observation have finished before this sole disposal;
        # it is never a rescue action on the original study/factory Engines.
        issuer_engine = None if case is None else getattr(case, "owned_issuer_engine", None)
        if issuer_engine is not None:
            try:
                issuer_engine.dispose()
            except BaseException as cleanup:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "original request fixture and owned issuer disposal failed",
                        [primary, cleanup],
                    ) from None
                raise


def _cookie(response, name):
    jar = SimpleCookie()
    jar.load(response.headers["set-cookie"])
    return jar[name].value


def _issuer(case, *, remaining=None):
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="actual-request-operator",
        configured_secret="fresh-test-only-session-configuration",
    )
    at = datetime.now(UTC)
    issued_at = at if remaining is None else at - timedelta(hours=8) + remaining
    response = Response()
    # Fresh fixture-owned issuance, not a default-main/HTTP readiness claim.
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=issued_at, session_cookie=None
    )
    assert capability.enabled is True
    cookie, csrf = _cookie(response, LOCAL_SESSION_COOKIE), capability.csrf_token
    assert type(cookie) is type(csrf) is str
    assert case.owned_issuer_engine is None
    engine = create_database_engine(str(case.study.ports["account_engine"].url))
    case.owned_issuer_engine = engine
    configure_sqlite_exit_cursor_cleanup(engine)
    authenticator = LocalRuntimeOwnerAuthenticator(security)
    commands = SqlRuntimeOwnerCommands(engine, codec=personal_codec, authenticator=authenticator)
    assert commands is not case.runtime.reader.associations.owner_dependencies.commands
    case.issuer = SimpleNamespace(
        security=security, commands=commands, engine=commands.engine, cookie=cookie, csrf=csrf
    )
    return case.issuer


@contextmanager
def _observe_call(case):
    """Only fixed original local code/SQL events for this synchronous call."""
    api, engine = case.issuer.commands, case.issuer.engine
    probe = SimpleNamespace(
        heads=0,
        prepares=[],
        appends=0,
        append_receipt=None,
        authentication=[],
        auth_calls=0,
        authenticator_calls=0,
        begins=0,
        commits=0,
        rollbacks=0,
        inserts=0,
        disposed=0,
        connections=[],
        inside_sql=False,
        forbidden=[],
        write_rollbacks=0,
        commit_snapshot=None,
        after_commit_fault=False,
        headmove_done=False,
        object_reads=0,
        object_puts=0,
    )
    labels = {
        LocalOperatorSecurity.authenticate_with_expiry.__code__: "session",
        LocalRuntimeOwnerAuthenticator.authenticate.__code__: "authenticate",
        LocalRuntimeOwnerAuthenticator.require_authenticated.__code__: "require-authenticated",
        SqlRuntimeOwnerCommands.prepare.__code__: "prepare",
        SqlRuntimeOwnerCommands.require_prepared.__code__: "require-prepared",
        SqlRuntimeOwnerCommands.append_in_transaction.__code__: "append",
        SqlRuntimeOwnerCommands._fingerprint.__code__: "fingerprint",
        SqlDurableJournal.read_head.__code__: "head",
        personal_codec.encode_record.__code__: "encode",
        personal_codec.decode_record.__code__: "decode",
        LocalResearchArtifactStore.read.__code__: "object-read",
        LocalResearchArtifactStore.put.__code__: "object-put",
        engine.dialect.do_commit.__func__.__code__: "physical-commit",
        retention._receipt_from_values.__code__: "receipt-copy",
    }
    monitor, tool = sys.monitoring, 3
    owned = False
    enabled, registered = [], []
    previous_profile = sys.getprofile()

    def observe(frame, event, returned):
        try:
            code = frame.f_code
            label = labels[code]
            if case.fixture_headmove:
                return
            assert threading.current_thread() is case.caller_thread
            if event == "call":
                if probe.inside_sql and label in {
                    "session",
                    "authenticate",
                    "require-authenticated",
                    "prepare",
                    "require-prepared",
                    "fingerprint",
                    "encode",
                    "decode",
                    "object-read",
                    "object-put",
                }:
                    probe.forbidden.append(label)
                if label == "session":
                    probe.auth_calls += 1
                elif label == "authenticate":
                    probe.authenticator_calls += 1
                elif label == "object-read":
                    probe.object_reads += 1
                elif label == "object-put":
                    probe.object_puts += 1
                elif label == "head" and frame.f_locals["self"] is api.journal:
                    probe.heads += 1
                elif label == "append" and frame.f_locals["self"] is api:
                    probe.appends += 1
                    assert probe.inside_sql
                    assert frame.f_locals["connection"].engine is engine
                    assert frame.f_locals["prepared"] is probe.prepares[-1]
                elif label == "receipt-copy" and case.i_mode == "copy-fault" and probe.commits:
                    # The original DBAPI commit has actually returned; inspect the
                    # retained rows before denying this original copy operation.
                    probe.commit_snapshot = _snapshot(case.study)
                    probe.after_commit_fault = True
                    raise case.i_copy_primary
            elif event == "return":
                if label == "session" and type(returned) is tuple:
                    probe.authentication.append(returned)
                elif label == "prepare" and type(returned) is PreparedRuntimeOwnerCommand:
                    assert frame.f_locals["self"] is api
                    probe.prepares.append(returned)
                elif label == "append" and type(returned) is JournalReceipt:
                    assert frame.f_locals["self"] is api
                    probe.append_receipt = returned
                elif label == "physical-commit" and frame.f_locals["self"] is engine.dialect:
                    probe.commits += 1
                    probe.inside_sql = False
                elif label == "require-prepared" and frame.f_locals["self"] is api:
                    if case.i_mode == "head-move" and not probe.headmove_done:
                        probe.headmove_done = True
                        case.fixture_headmove = True
                        try:
                            with engine.begin() as connection:
                                connection.exec_driver_sql("BEGIN IMMEDIATE")
                                case.headmove_receipt = api.append_in_transaction(
                                    connection, case.headmove_prepared
                                )
                            case.headmove_snapshot = _snapshot(case.study)
                        finally:
                            case.fixture_headmove = False
                    elif case.i_mode == "expire-before-sql":
                        expiry = probe.prepares[-1].record.command.expires_at
                        remaining = max(0, (expiry - datetime.now(UTC)).total_seconds())
                        threading.Event().wait(remaining)
                        case.expiry_observed = datetime.now(UTC)
                        assert case.expiry_observed >= expiry

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
        if not case.fixture_headmove:
            probe.connections.append(connection)

    def after_sql(connection, cursor, statement, parameters, context, executemany):
        if case.fixture_headmove:
            return
        if statement == "BEGIN IMMEDIATE":
            probe.begins += 1
            probe.inside_sql = True
            assert connection.connection.driver_connection.in_transaction
        if (
            context.compiled is not None
            and getattr(context.compiled.statement, "is_insert", False)
            and context.compiled.statement.table is journal_entries
        ):
            probe.inserts += 1
            if case.i_mode == "rollback-base":
                raise case.i_primary
            if case.i_mode == "rollback-exception":
                raise case.i_exception

    def rollback(connection):
        if not case.fixture_headmove:
            probe.rollbacks += 1
            if probe.inside_sql:
                probe.write_rollbacks += 1
            probe.inside_sql = False

    def disposed(actual_engine):
        assert actual_engine is engine
        probe.disposed += 1

    listeners = (
        ("engine_connect", connected),
        ("after_cursor_execute", after_sql),
        ("rollback", rollback),
        ("engine_disposed", disposed),
    )
    for event, callback in listeners:
        sa.event.listen(engine, event, callback)
    primary = None
    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-request-original-ports")
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
        failures = []
        if owned:
            for code in enabled:
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    failures.append(error)
            for event in registered:
                try:
                    monitor.register_callback(tool, event, None)
                except BaseException as error:
                    failures.append(error)
            try:
                assert monitor.get_tool(tool) == "aqt-request-original-ports"
                assert monitor.get_events(tool) == 0
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                failures.append(error)
        for event, callback in listeners:
            try:
                sa.event.remove(engine, event, callback)
            except BaseException as error:
                failures.append(error)
        try:
            assert sys.getprofile() is previous_profile
            assert probe.forbidden == [] and probe.disposed == 0
            assert probe.object_reads == probe.object_puts == 0
            assert all(connection.closed for connection in probe.connections)
        except BaseException as error:
            failures.append(error)
        if failures:
            if primary is not None:
                failures.insert(0, primary)
            raise BaseExceptionGroup("request observation and cleanup failed", failures)


def _invoke(case, *, command_id="retained-initial-request", **changes):
    arguments = dict(
        security=case.issuer.security,
        commands=case.issuer.commands,
        engine=case.issuer.engine,
        account_id=case.study.genesis.scope.account_id,
        descriptor=case.descriptor,
        command_id=command_id,
        session_cookie=case.issuer.cookie,
        csrf_token=case.issuer.csrf,
    )
    arguments.update(changes)
    return retention._retain_initial_selection_request(**arguments)


def _adopt_request(case, probe, returned=None, *, prepared=None, receipt=None):
    api = case.issuer.commands
    prepared = probe.prepares[-1] if prepared is None else prepared
    receipt = probe.append_receipt if receipt is None else receipt
    assert type(prepared) is PreparedRuntimeOwnerCommand and type(receipt) is JournalReceipt
    api.require_prepared(prepared)
    record = prepared.record
    scope, heads, reference = initial_selection_request_data(case.descriptor)
    actual = api.read(scope, command_id=record.command.command_id, budget=RuntimeReadBudget())
    assert actual is not None
    api.require_resolved(actual)
    assert actual.record == record and actual.read.receipt == receipt
    assert type(record) is RuntimeOwnerCommandRecord
    assert record.scope == scope and record.dependencies == reference
    assert record.command.expected_heads == heads
    assert record.command.before_assignment_sha256 is None
    assert record.command.after_assignment_sha256 == case.descriptor.after_assignment_sha256
    assert record.command.quiescence_sha256 == case.descriptor.dependency_semantic_sha256
    assert record.command.owner_id == case.issuer.security._operator_id
    assert record.command.runtime_environment == "stateful_simulation"
    assert record.command.requested_at == record.authentication.authenticated_at
    assert record.command.expires_at == min(
        record.command.requested_at + timedelta(seconds=60),
        record.authentication.session_expires_at,
        case.descriptor.valid_until,
    )
    assert record.command.requested_at < record.command.expires_at
    if returned is not None:
        assert type(returned) is JournalReceipt and returned == receipt
        assert returned is not receipt
        assert returned.previous_head is not receipt.previous_head
        assert returned.committed_head is not receipt.committed_head
    case.issued = SimpleNamespace(
        api=api, prepared=prepared, receipt=receipt, command=record.command
    )
    case.requested = _snapshot(case.study)
    original_installation._request_only(case)
    assert case.requested.leases == case.prepared_snapshot.leases
    assert case.requested.heads == case.prepared_snapshot.heads
    assert case.requested.releases == case.prepared_snapshot.releases
    case.request = replace(receipt if returned is None else returned)
    case.install_before = case.requested
    return record


def _zero_request(case, before, probe, *, authenticated=False):
    assert _snapshot(case.study).__dict__ == before.__dict__
    assert probe.heads == probe.appends == probe.begins == probe.commits == 0
    assert probe.prepares == [] and probe.inserts == 0
    assert case.proofs == 2 and len(case.puts) == 1 and case.close_calls == 0
    assert case.owner._install_dispatched is False
    if not authenticated:
        assert probe.authenticator_calls == 0


def test_actual_shared_request_retention_then_only_receipt_to_same_h_owner(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, retained=True) as case:
        _issuer(case)
        with _observe_call(case) as probe:
            receipt = _invoke(case)
        assert probe.heads == probe.appends == probe.begins == probe.commits == probe.inserts == 1
        assert probe.auth_calls == 2 and probe.authenticator_calls == 1
        assert len(probe.prepares) == 1 and len(probe.authentication) == 2
        record = _adopt_request(case, probe, receipt)
        assert (
            probe.authentication
            == [(record.command.owner_id, record.authentication.session_expires_at)] * 2
        )
        assert case.owner._thread.is_alive() and case.close_calls == 0
        assert (
            case.issuer.commands is not case.runtime.reader.associations.owner_dependencies.commands
        )
        actual_host._call(case)
        actual_host._installed(case, actual_host._join_caller(case))


@pytest.mark.parametrize(
    "kind", ("malformed", "expired", "foreign", "csrf", "operational", "metadata")
)
def test_actual_session_or_other_purpose_denial_precedes_head_and_sql(tmp_path, monkeypatch, kind):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case, remaining=timedelta(seconds=-2) if kind == "expired" else None)
        cookie, csrf = case.issuer.cookie, case.issuer.csrf
        at = datetime.now(UTC)
        if kind == "malformed":
            cookie = "not-a-signed-local-session"
        elif kind == "foreign":
            foreign = LocalOperatorSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="actual-request-operator",
                configured_secret="fresh-test-only-session-configuration",
            )
            response = Response()
            capability = foreign.bootstrap_capability(
                response, persistence_ready=True, issued_at=at, session_cookie=None
            )
            cookie, csrf = _cookie(response, LOCAL_SESSION_COOKIE), capability.csrf_token
            assert foreign.authenticate(cookie, csrf, now=at) == "actual-request-operator"
        elif kind == "csrf":
            csrf = "x" * 43
            assert csrf != case.issuer.csrf
        elif kind == "operational":
            security = ContinuousReadAccessSecurity(
                configuration=ContinuousReadAccessConfiguration(
                    enabled=True,
                    transport_is_loopback_scoped=True,
                    operator_id="actual-request-operator",
                    configured_secret="test-only-read-configuration",
                ),
                account_id=case.study.genesis.scope.account_id,
            )
            security.open()
            response = Response()
            capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
            cookie, csrf = _cookie(response, CONTINUOUS_READ_SESSION_COOKIE), capability.csrf_token
            assert security.authenticate(cookie, csrf, now=at) == "actual-request-operator"
            security.close()
        elif kind == "metadata":
            security = MetadataAccessSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="actual-request-operator",
                configured_secret="test-only-metadata-configuration",
            )
            response = Response()
            capability = security.bootstrap_capability(response, issued_at=at, session_cookie=None)
            cookie, csrf = _cookie(response, METADATA_SESSION_COOKIE), capability.csrf_token
            assert security.authenticate(cookie, csrf, now=at) == "actual-request-operator"
        before = _snapshot(case.study)
        with _observe_call(case) as probe, pytest.raises(HTTPException) as caught:
            _invoke(case, session_cookie=cookie, csrf_token=csrf)
        assert caught.value.status_code == (403 if kind == "csrf" else 401)
        assert caught.value.detail == (
            "backtest launch CSRF validation failed"
            if kind == "csrf"
            else "a current local operator session is required"
        )
        assert probe.auth_calls == 1
        _zero_request(case, before, probe)


def test_actual_shorter_shared_session_expiry_clips_the_retained_command(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, retained=True) as case:
        _issuer(case, remaining=timedelta(seconds=12))
        _, expiry = case.issuer.security.authenticate_with_expiry(
            case.issuer.cookie, case.issuer.csrf, now=datetime.now(UTC)
        )
        assert expiry < case.descriptor.valid_until
        with _observe_call(case) as probe:
            receipt = _invoke(case)
        record = _adopt_request(case, probe, receipt)
        assert record.command.expires_at == record.authentication.session_expires_at == expiry
        assert record.command.requested_at < expiry < case.descriptor.valid_until
        assert probe.appends == probe.begins == probe.commits == 1
        assert case.owner._install_dispatched is False and case.proofs == 2


def test_actual_configured_account_mismatch_is_denied_before_auth_or_sql(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case)
        before = _snapshot(case.study)
        with _observe_call(case) as probe, pytest.raises(ValueError, match=_INVALID):
            _invoke(case, account_id="different-configured-account")
        assert probe.auth_calls == 0
        _zero_request(case, before, probe)


@pytest.mark.parametrize("kind", ("engine", "security", "journal-engine"))
def test_actual_wrong_issuer_graph_is_denied_before_any_auth_or_sql(tmp_path, monkeypatch, kind):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case)
        changes = {}
        original = case.issuer.commands.journal
        if kind == "engine":
            changes["engine"] = case.study.ports["venue_engine"]
        elif kind == "security":
            changes["security"] = LocalOperatorSecurity(
                enabled=True,
                transport_is_loopback_scoped=True,
                operator_id="actual-request-operator",
                configured_secret="test-only-other-security",
            )
        else:
            case.issuer.commands.journal = SqlDurableJournal(
                case.study.ports["venue_engine"],
                codec=personal_codec,
                record_types={OWNER_COMMAND_SCHEMA: RuntimeOwnerCommandRecord},
            )
        before = _snapshot(case.study)
        try:
            with _observe_call(case) as probe, pytest.raises(ValueError, match=_CHANGED):
                _invoke(case, **changes)
        finally:
            case.issuer.commands.journal = original
        assert probe.auth_calls == 0
        _zero_request(case, before, probe)


def _head_mover(case):
    api, security = case.issuer.commands, case.issuer.security
    scope, heads, reference = initial_selection_request_data(case.descriptor)
    at = datetime.now(UTC)
    operator, expiry = security.authenticate_with_expiry(
        case.issuer.cookie, case.issuer.csrf, now=at
    )
    command = RuntimeAssignmentCommand(
        "fixture-head-movement",
        operator,
        scope.account_id,
        None,
        case.descriptor.after_assignment_sha256,
        heads,
        reference.semantic_sha256,
        at,
        min(at + timedelta(seconds=60), expiry, case.descriptor.valid_until),
    )
    authenticated = api.authenticator.authenticate(
        command, session_cookie=case.issuer.cookie, csrf_token=case.issuer.csrf, now=at
    )
    case.headmove_prepared = api.prepare(
        scope,
        command=command,
        authenticated=authenticated,
        dependencies=reference,
        expected_head=api.journal.read_head(journal_key(scope)),
    )
    api.require_prepared(case.headmove_prepared)


def test_actual_head_movement_keeps_only_the_independent_request_not_a_rebased_target(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, retained=True) as case:
        _issuer(case)
        _head_mover(case)
        case.i_mode = "head-move"
        with _observe_call(case) as probe, pytest.raises(RuntimeOwnerCommandError) as caught:
            _invoke(case)
        assert str(caught.value) == "OWNER_REQUEST_APPEND_FAILED"
        assert probe.headmove_done and case.headmove_receipt is not None
        assert probe.appends == probe.begins == 1 and probe.commits == 0
        assert probe.write_rollbacks == 1
        _adopt_request(case, probe, prepared=case.headmove_prepared, receipt=case.headmove_receipt)
        assert case.requested.__dict__ == case.headmove_snapshot.__dict__
        scope = initial_selection_request_data(case.descriptor)[0]
        assert (
            case.issuer.commands.read(
                scope, command_id="retained-initial-request", budget=RuntimeReadBudget()
            )
            is None
        )
        assert case.proofs == 2 and case.owner._install_dispatched is False


def test_actual_same_id_new_time_conflict_never_rewrites_the_first_request(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch, retained=True) as case:
        _issuer(case)
        with _observe_call(case) as first:
            receipt = _invoke(case)
        original = _adopt_request(case, first, receipt)
        before = _snapshot(case.study)
        with _observe_call(case) as second, pytest.raises(RuntimeOwnerCommandError) as caught:
            _invoke(case)
        assert str(caught.value) == "OWNER_REQUEST_APPEND_FAILED"
        assert len(second.prepares) == 1
        assert second.prepares[0].record.command.requested_at > original.command.requested_at
        assert second.prepares[0].record.command.semantic_sha256 != original.command.semantic_sha256
        assert second.appends == second.begins == 1 and second.commits == 0
        assert second.write_rollbacks == 1
        assert _snapshot(case.study).__dict__ == before.__dict__
        assert case.proofs == 2 and case.owner._install_dispatched is False


@pytest.mark.parametrize("kind", ("rollback-exception", "rollback-base"))
def test_actual_physical_request_insert_rolls_back_on_original_exception_or_baseexception(
    tmp_path, monkeypatch, kind
):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case)
        case.i_mode = kind
        before = _snapshot(case.study)
        expected = RuntimeOwnerCommandError if kind == "rollback-exception" else KeyboardInterrupt
        with _observe_call(case) as probe, pytest.raises(expected) as caught:
            _invoke(case)
        if kind == "rollback-base":
            assert caught.value is case.i_primary
        else:
            assert str(caught.value) == "OWNER_REQUEST_APPEND_FAILED"
        assert probe.appends == probe.begins == probe.inserts == 1 and probe.commits == 0
        assert probe.write_rollbacks == 1
        assert _snapshot(case.study).__dict__ == before.__dict__
        assert case.proofs == 2 and len(case.puts) == 1 and case.owner._install_dispatched is False


def test_actual_commit_then_receipt_copy_fault_retains_request_without_return_or_retry(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch, retained=True) as case:
        _issuer(case)
        case.i_mode = "copy-fault"
        with _observe_call(case) as probe, pytest.raises(RuntimeError) as caught:
            _invoke(case)
        assert caught.value is case.i_copy_primary and probe.after_commit_fault
        assert probe.appends == probe.begins == probe.commits == probe.inserts == 1
        assert probe.commit_snapshot is not None
        _adopt_request(case, probe)
        assert case.requested.__dict__ == probe.commit_snapshot.__dict__
        assert case.proofs == 2 and case.owner._install_dispatched is False


def test_actual_session_bound_expiry_before_sql_never_enters_the_retention_transaction(
    tmp_path, monkeypatch
):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case, remaining=timedelta(seconds=3))
        case.i_mode = "expire-before-sql"
        before = _snapshot(case.study)
        with _observe_call(case) as probe, pytest.raises(ValueError, match=_INVALID):
            _invoke(case)
        assert len(probe.prepares) == 1 and probe.heads == 1
        assert probe.auth_calls == 2 and probe.authenticator_calls == 1
        assert case.expiry_observed >= probe.prepares[0].record.command.expires_at
        assert probe.begins == probe.appends == probe.commits == probe.inserts == 0
        assert _snapshot(case.study).__dict__ == before.__dict__
        assert case.proofs == 2 and len(case.puts) == 1 and case.owner._install_dispatched is False


def test_actual_late_exit_alias_drift_uses_original_transaction_unwind(tmp_path, monkeypatch):
    with _case(tmp_path, monkeypatch) as case:
        _issuer(case)
        before = _snapshot(case.study)
        calls = []

        def substituted(*args, **kwargs):
            calls.append("exit")
            raise AssertionError("substituted transaction cleanup was invoked")

        with _observe_call(case) as probe, monkeypatch.context() as patch:

            def drift(connection, cursor, statement, parameters, context, executemany):
                if statement == "BEGIN IMMEDIATE":
                    patch.setattr(retention, "_EXIT", substituted)

            sa.event.listen(case.issuer.engine, "after_cursor_execute", drift)
            try:
                with pytest.raises(ValueError, match=_CHANGED):
                    _invoke(case)
            finally:
                sa.event.remove(case.issuer.engine, "after_cursor_execute", drift)
        assert calls == []
        assert len(probe.prepares) == probe.heads == probe.begins == 1
        assert probe.auth_calls == 2 and probe.authenticator_calls == 1
        assert probe.appends == probe.inserts == probe.commits == 0
        assert probe.write_rollbacks == 1
        assert _snapshot(case.study).__dict__ == before.__dict__
        assert case.proofs == 2 and len(case.puts) == 1
        assert case.owner._install_dispatched is False
