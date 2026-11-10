"""Existing I/J/B/R1 observations, without a production consumer or publication.

Valid D/control mismatches and current R2 are deliberately accepted by separate
original components. Explicit test comparisons expose the remaining join; they
are not a new production verifier. Actual C account binding remains unqualified.
"""

import hashlib
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import fields, is_dataclass, replace
from datetime import timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import Response

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.operational_control_operator_authentication import (
    LocalOperationalControlOperatorStatementAuthenticator,
)
from apps.api.operational_control_operator_preparation import OperatorStatementRecordPreparer
from apps.trader.operational_control_operator_evidence import OperatorStatementEvidenceReader
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.operational_control_operator_journal import (
    operator_statement_journal_append,
    operator_statement_journal_key,
)
from packages.application.operational_control_operator_preparation import (
    PreparedOperationalControlOperatorStatementRecord,
)
from packages.domain.continuous_persistence_contracts import ContinuousAccountScope
from packages.domain.durable_journal_contracts import (
    MAX_APPEND_BYTES,
    MAX_APPEND_RECORDS,
    MAX_RECORD_BYTES,
    MAX_SEQUENCE,
    empty_head,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlCommandKind,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)
from packages.domain.operational_control_operator_record import (
    OPERATOR_STATEMENT_RECORD_SCHEMA,
    OperationalControlOperatorStatementRecord,
    copy_operational_control_operator_statement_record,
)
from packages.domain.operational_control_operator_statement import (
    OperationalControlOperatorStatement,
)
from packages.domain.research_job_contracts import MAX_OBJECT_BYTES, ObjectRef
from packages.persistence import daily_runtime_risk as daily
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_leases,
    phase2_batch_reservations,
)
from tests.integration import test_bounded_daily_control_capture as control_component
from tests.integration.test_bounded_daily_control_capture import case as case

_OWNER = "current-context-test-operator"
_AUTHORITY = "a" * 64
_SECRET = "synthetic-test-only-current-context-configuration"
_PAYLOAD = b"\x00synthetic current-context evidence\xff\n"
_AUTH_CODE = LocalOperatorSecurity.authenticate_with_expiry.__code__
_F_CODE = OperatorStatementEvidenceReader.read.__code__
_READ_CODE = LocalResearchArtifactStore.read.__code__
_PUT_CODE = LocalResearchArtifactStore.put.__code__
_INSTALL_CODE = LocalResearchArtifactStore.install_file.__code__
_ENCODE_CODE = codec.encode_record.__code__
_DECODE_CODE = codec.decode_record.__code__
_PREPARE_CODE = SqlDurableJournal.prepare_append.__code__
_APPEND_CODE = SqlDurableJournal.append.__code__
_APPEND_TX_CODE = SqlDurableJournal.append_in_transaction.__code__
_CODES = (
    (_AUTH_CODE, "authenticate"),
    (_F_CODE, "evidence"),
    (_READ_CODE, "read"),
    (_PUT_CODE, "put"),
    (_INSTALL_CODE, "install"),
    (_ENCODE_CODE, "encode"),
    (_DECODE_CODE, "decode"),
    (_PREPARE_CODE, "prepare"),
    (_APPEND_CODE, "append"),
    (_APPEND_TX_CODE, "append_in_transaction"),
)


def _projection(value):
    if is_dataclass(value) and not isinstance(value, type):
        return type(value), tuple(
            (field.name, _projection(getattr(value, field.name))) for field in fields(value)
        )
    if type(value) is tuple:
        return tuple(_projection(item) for item in value)
    return value


def _artifact_inventory(root):
    directory = root.lstat()
    result = []
    for path in sorted(root.iterdir()):
        information = path.lstat()
        assert stat.S_ISREG(information.st_mode)
        result.append(
            (
                path.name,
                information.st_mode,
                information.st_uid,
                information.st_ino,
                information.st_size,
                information.st_mtime_ns,
                information.st_ctime_ns,
                path.read_bytes(),
            )
        )
    return directory.st_mode, directory.st_uid, directory.st_ino, tuple(result)


@contextmanager
def _observe(value):
    """Use a distinct tool; inherited B owns tool3 for the whole fixture."""
    monitor, tool = sys.monitoring, 4
    enabled = []
    owned = registered = False
    primary = None

    def start(code, offset):
        label = next(label for original, label in _CODES if code is original)
        thread = threading.current_thread()
        value.entries.append((label, thread))
        if label in ("put", "install", "append", "append_in_transaction"):
            raise AssertionError("current-context qualification attempted an excluded write")
        if value.final_connection is not None and thread is value.final_thread:
            raise AssertionError("auth/evidence/codec/preparation ran in final B account scope")
        if code is _READ_CODE and value.read_barrier is not None:
            entered, release, completed = value.read_barrier
            assert thread is value.preparing_thread
            assert all(connection.closed for connection in value.case.connections)
            entered.set()
            if not release.wait(10):
                raise AssertionError("test did not release original file read")
            assert completed.is_set()

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-operator-current-context")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        registered = True
        for code, _ in _CODES:
            assert monitor.get_local_events(tool, code) == 0
            enabled.append(code)
            monitor.set_local_events(tool, code, monitor.events.PY_START)
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
            if registered:
                try:
                    monitor.register_callback(tool, monitor.events.PY_START, None)
                except BaseException as error:
                    errors.append(error)
            try:
                assert monitor.get_events(tool) == 0
                assert monitor.get_tool(tool) == "aqt-operator-current-context"
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup(
                "current-context observation cleanup failed",
                ([primary] if primary else []) + errors,
            )


@contextmanager
def _account_interval(value, connection):
    """Observe this thread/Connection only; this is no admission wrapper."""
    assert value.final_connection is None and value.final_thread is None
    value.final_connection, value.final_thread = connection, threading.current_thread()
    try:
        yield
    finally:
        value.final_connection = value.final_thread = None


def _inert_rows(value):
    case = value.case
    assert all(rows == () for rows in control_component._rows(case, JOURNAL_TABLES).values())
    assert control_component._empty_financial_rows(case) == case.initial_financial
    assert control_component._rows(case, (phase2_batch_reservations,)) == {
        phase2_batch_reservations.name: ()
    }
    assert control_component._rows(case, daily.CONTROL_TABLES) == case.expected_control
    assert case.producer.calls == [] and case.accounting_calls == []


def _finish(value, primary):
    """Quiesce the inherited fixture's workers before observer/resource cleanup."""
    errors = []
    for release in value.case.barriers:
        try:
            release.set()
        except BaseException as error:
            errors.append(error)
    for thread in value.case.threads:
        try:
            if thread.ident is not None:
                thread.join(10)
        except BaseException as error:
            errors.append(error)
    active = [thread for thread in value.case.threads if thread.is_alive()]
    if active:
        errors.append(AssertionError("current-context worker remains active; resources retained"))
    else:
        errors.extend(value.case.worker_errors)
        try:
            _inert_rows(value)
            assert _artifact_inventory(value.root) == value.inventory
            assert value.final_connection is value.final_thread is None
            assert not any(
                label in ("put", "install", "append", "append_in_transaction")
                for label, _ in value.entries
            )
        except BaseException as error:
            errors.append(error)
        for engine, connections, listener in value.extra_engines:
            try:
                assert all(connection.closed for connection in connections)
            except BaseException as error:
                errors.append(error)
                continue
            try:
                sa.event.remove(engine, "engine_connect", listener)
                engine.dispose()
            except BaseException as error:
                errors.append(error)
    if errors:
        raise BaseExceptionGroup(
            "current-context fixture cleanup failed", ([primary] if primary else []) + errors
        )


@pytest.fixture
def current(case, tmp_path):
    # JOURNAL_TABLES was registered at module import before original B setup.
    raw = control_component._capture(case)
    resolved = control_component._resolve(case, raw)
    assert resolved.control == case.initial
    assert resolved.control.effective_state is OperationalControlState.HALTED
    assert len(resolved.control.blocking_events) == 1
    assert raw.receipt.lease_sha256 == case.r1.semantic_sha256
    assert case.r1.revision_number == 1 and case.r1.previous_lease_sha256 is None
    assert case.r1.expires_at - case.r1.heartbeat_at == timedelta(seconds=60)
    assert case.policy.maximum_in_flight_duration == timedelta(seconds=5)
    assert case.policy.takeover_safety_interval == timedelta(seconds=10)
    artifacts = LocalResearchArtifactStore(tmp_path / "operator-evidence")
    reference = artifacts.put(_PAYLOAD)
    assert reference.byte_count == len(_PAYLOAD) <= MAX_OBJECT_BYTES == 64 * 1024 * 1024
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id=_OWNER,
        configured_secret=_SECRET,
    )
    # Original session wire times are integer seconds; do not invent precision.
    case.clock.advance(timedelta(seconds=1))
    operation = case.clock.instant
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=operation, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    issuer = LocalOperationalControlOperatorStatementAuthenticator(
        security, scope_id=raw.account_id, actor_authority_sha256=_AUTHORITY
    )
    reader = OperatorStatementEvidenceReader(artifacts, max_bytes=len(_PAYLOAD))
    clock_port = case.clock.now
    value = SimpleNamespace(
        case=case,
        tmp_path=tmp_path,
        raw=raw,
        resolved=resolved,
        retained_receipt_sha256=raw.receipt.semantic_sha256,
        operation=operation,
        artifacts=artifacts,
        reference=reference,
        root=tmp_path / "operator-evidence",
        inventory=_artifact_inventory(tmp_path / "operator-evidence"),
        issuer=issuer,
        reader=reader,
        clock_port=clock_port,
        preparer=OperatorStatementRecordPreparer(issuer, reader, clock=clock_port),
        cookie=cookies[LOCAL_SESSION_COOKIE].value,
        csrf=capability.csrf_token,
        journal=SqlDurableJournal(
            case.engine,
            codec=codec,
            record_types={
                OPERATOR_STATEMENT_RECORD_SCHEMA: OperationalControlOperatorStatementRecord
            },
        ),
        scope=ContinuousAccountScope(raw.account_id, "c" * 64, "current-context-deployment"),
        entries=[],
        read_barrier=None,
        preparing_thread=threading.current_thread(),
        final_connection=None,
        final_thread=None,
        extra_engines=[],
    )
    with _observe(value):
        primary = None
        try:
            _inert_rows(value)
            yield value
        except BaseException as error:
            primary = error
            raise
        finally:
            _finish(value, primary)


def _statement(value, kind=None):
    control = value.resolved.control
    blocker = control.blocking_events[0]
    if kind == "blocker":
        blocker = OperationalControlBlockingEvent(
            scope_id=blocker.scope_id,
            sequence_number=blocker.sequence_number,
            command_id="different-declared-blocker-command",
            command_sha256="d" * 64,
            state=blocker.state,
            occurred_at=blocker.occurred_at,
        )
    return OperationalControlOperatorStatement(
        scope_id=value.raw.account_id,
        control_transition_id=(
            "different-declared-transition" if kind == "head-id" else control.transition_id
        ),
        control_transition_sha256="e" * 64 if kind == "head-sha" else control.semantic_sha256,
        control_sequence_number=control.sequence_number + (1 if kind == "sequence" else 0),
        control_state=(
            OperationalControlState.PAUSED if kind == "state" else control.effective_state
        ),
        control_state_epoch_id=(
            "different-declared-epoch" if kind == "epoch" else control.state_epoch_id
        ),
        blocking_event=blocker,
        actor=OperationalControlActor(
            actor_id=_OWNER,
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256=_AUTHORITY,
            authenticated_at=value.operation,
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=blocker.event_id,
            event_sha256=blocker.semantic_sha256,
            resolution_code="operator-reviewed",
            resolution_evidence_sha256=value.reference.object_sha256,
            resolved_at=value.operation,
        ),
        authentication_checked_at=value.operation,
        attested_at=value.operation,
        idempotency_key="current-context-statement-0001",
    )


def _prepare(value, kind=None):
    """Drive actual separate APIs; compare no control/R1 authority here."""
    case = value.case
    statement = _statement(value, kind)
    authenticated = value.issuer.authenticate(
        statement,
        session_cookie=value.cookie,
        csrf_token=value.csrf,
        now=value.operation,
    )
    case.clock.advance(timedelta(milliseconds=100))
    prepared = value.preparer.prepare(
        authenticated,
        value.reference,
        session_cookie=value.cookie,
        csrf_token=value.csrf,
    )
    assert type(prepared) is PreparedOperationalControlOperatorStatementRecord
    record = prepared.record
    assert type(record) is OperationalControlOperatorStatementRecord
    assert type(record.statement) is OperationalControlOperatorStatement
    assert type(record.evidence) is ObjectRef
    assert prepared.authenticated is authenticated
    assert record.statement is not authenticated.statement
    assert record.evidence is not value.reference
    assert _projection(record.statement) == _projection(authenticated.statement)
    assert record.evidence == value.reference
    assert record.session_expires_at == authenticated.session_expires_at
    assert record.session_expires_at == value.operation + timedelta(hours=8)
    assert (
        record.statement.actor.authenticated_at
        == record.statement.authentication_checked_at
        == record.statement.attested_at
        == value.operation
    )
    assert value.operation <= prepared.before_read_at <= prepared.checked_at
    key = operator_statement_journal_key(value.scope)
    head = value.journal.read_head(key)
    assert head == empty_head(key)
    offset = len(case.sql)
    returned_key, request = operator_statement_journal_append(
        value.scope, record, expected_head=head
    )
    journal_prepared = value.journal.prepare_append(returned_key, request)
    assert case.sql[offset:] == []
    assert returned_key == key
    assert key.account_scope == record.statement.scope_id == value.raw.account_id
    assert key.source_scope_sha256 == value.scope.semantic_sha256
    assert key.stream_id == "operational-control-operator-statements/1"
    assert key.source_provider == "local-operator-statement"
    assert (
        key.source_environment == "synthetic" and key.runtime_environment == "stateful_simulation"
    )
    assert request.command_id == record.record_id == record.statement.statement_id
    assert request.command_sha256 == record.semantic_sha256
    assert request.expected_head == head and request.expected_head is not head
    assert len(request.records) == 1 <= MAX_APPEND_RECORDS == 64
    stored = request.records[0]
    assert stored.record_id == request.command_id
    assert stored.schema_id == OPERATOR_STATEMENT_RECORD_SCHEMA
    assert type(stored.payload) is bytes
    assert 0 < len(stored.payload) <= MAX_RECORD_BYTES == 256 * 1024
    assert sum(len(item.payload) for item in request.records) <= MAX_APPEND_BYTES == 1024 * 1024
    assert stored.payload == codec.encode_record(
        copy_operational_control_operator_statement_record(record)
    )
    decoded = codec.decode_record(stored.payload, OperationalControlOperatorStatementRecord)
    assert _projection(decoded) == _projection(record)
    assert decoded.record_id == request.command_id
    assert decoded.semantic_sha256 == request.command_sha256
    assert journal_prepared.key is returned_key and journal_prepared.request is request
    assert journal_prepared.receipt.command_id == request.command_id
    assert journal_prepared.receipt.command_sha256 == request.command_sha256
    assert journal_prepared.receipt.previous_head == request.expected_head
    assert journal_prepared.receipt.record_ids == (stored.record_id,)
    assert journal_prepared.receipt.record_hashes == (hashlib.sha256(stored.payload).hexdigest(),)
    assert len(journal_prepared.entries) == 1
    assert journal_prepared.entries[0].record is stored
    assert journal_prepared.entries[0].head == journal_prepared.receipt.committed_head
    assert journal_prepared.receipt.committed_head.sequence == 1 < MAX_SEQUENCE
    case.clock.advance(timedelta(milliseconds=100))
    assert value.preparer.clock is value.clock_port
    assert (
        value.preparer.require_prepared(
            prepared, session_cookie=value.cookie, csrf_token=value.csrf
        )
        is None
    )
    assert prepared.checked_at <= case.clock.instant < record.session_expires_at
    assert tuple(
        sum(label == expected for label, _ in value.entries)
        for expected in ("authenticate", "evidence", "read", "prepare")
    ) == (4, 1, 1, 1)
    assert _artifact_inventory(value.root) == value.inventory
    _inert_rows(value)
    return prepared, journal_prepared


def test_real_prepared_metadata_and_original_control_have_exact_r1_agreement(current):
    prepared, journal_prepared = _prepare(current)
    case, control = current.case, current.resolved.control
    statement = prepared.record.statement
    assert (
        statement.control_transition_id,
        statement.control_transition_sha256,
        statement.control_sequence_number,
        statement.control_state,
        statement.control_state_epoch_id,
    ) == (
        control.transition_id,
        control.semantic_sha256,
        control.sequence_number,
        control.effective_state,
        control.state_epoch_id,
    )
    blocker = statement.blocking_event
    assert (blocker.event_id, blocker.semantic_sha256, _projection(blocker)) in tuple(
        (item.event_id, item.semantic_sha256, _projection(item)) for item in control.blocking_events
    )
    assert current.raw.receipt.semantic_sha256 == current.retained_receipt_sha256
    case.clock.advance(timedelta(milliseconds=100))
    with _write_transaction(case.engine) as connection:
        assert connection.engine is case.engine and connection.in_transaction()
        assert connection.connection.driver_connection.in_transaction is True
        with _account_interval(current, connection):
            receipt = case.store.recheck_snapshot_in_transaction(
                connection, current.resolved, fence=case.r1.fence
            )
    control_component._receipt(receipt, case.r1, not_before=current.raw.receipt.validated_at)
    assert (
        (receipt.fence, receipt.lease_sha256, receipt.policy_sha256, receipt.valid_until)
        == (
            current.raw.receipt.fence,
            current.raw.receipt.lease_sha256,
            current.raw.receipt.policy_sha256,
            current.raw.receipt.valid_until,
        )
        == (case.r1.fence, case.r1.semantic_sha256, case.r1.policy_sha256, case.r1.expires_at)
    )
    assert current.raw.receipt.validated_at < receipt.validated_at == case.clock.instant
    assert current.raw.receipt.semantic_sha256 == current.retained_receipt_sha256
    assert prepared.checked_at < receipt.validated_at < prepared.record.session_expires_at
    assert journal_prepared.receipt.committed_head != current.journal.read_head(
        journal_prepared.key
    )
    case.store.require_resolved_snapshot(current.resolved)
    assert current.resolved.raw is current.raw
    _inert_rows(current)


@pytest.mark.parametrize("kind", ["head-id", "head-sha", "sequence", "state", "epoch", "blocker"])
def test_valid_statement_mismatch_exposes_missing_consumer_binding_without_api_denial(
    current, kind
):
    prepared, _ = _prepare(current, kind)
    case, control = current.case, current.resolved.control
    statement = prepared.record.statement
    actual = (
        statement.control_transition_id,
        statement.control_transition_sha256,
        statement.control_sequence_number,
        statement.control_state,
        statement.control_state_epoch_id,
    )
    expected = (
        control.transition_id,
        control.semantic_sha256,
        control.sequence_number,
        control.effective_state,
        control.state_epoch_id,
    )
    names = ("head-id", "head-sha", "sequence", "state", "epoch")
    differences = {
        name
        for name, declared, captured in zip(names, actual, expected, strict=True)
        if declared != captured
    }
    assert differences == (set() if kind == "blocker" else {kind})
    event = statement.blocking_event
    member = (event.event_id, event.semantic_sha256, _projection(event)) in tuple(
        (item.event_id, item.semantic_sha256, _projection(item)) for item in control.blocking_events
    )
    assert member is (kind != "blocker")
    assert statement.resolution_claim.event_id == event.event_id
    assert statement.resolution_claim.event_sha256 == event.semantic_sha256
    with _write_transaction(case.engine) as connection, _account_interval(current, connection):
        receipt = case.store.recheck_snapshot_in_transaction(
            connection, current.resolved, fence=case.r1.fence
        )
    control_component._receipt(receipt, case.r1, not_before=current.raw.receipt.validated_at)
    assert (actual == expected and member) is False
    assert case.controls.load(current.raw.account_id) == control
    _inert_rows(current)


@pytest.mark.parametrize("kind", ["raw-copy", "raw-foreign", "resolved-copy", "resolved-foreign"])
def test_actual_preparation_cannot_confer_b_snapshot_ownership(current, kind):
    _prepare(current)
    case = current.case
    foreign = control_component._store(case)
    tables = (*daily.CONTROL_TABLES, phase2_account_leases, phase2_account_lease_heads)
    before = control_component._rows(case, tables)
    if kind == "raw-copy":
        with pytest.raises(daily.DailyRuntimeRiskConflict, match=control_component._OWNER_ERROR):
            case.store.resolve_snapshot(replace(current.raw))
    elif kind == "raw-foreign":
        with pytest.raises(daily.DailyRuntimeRiskConflict, match=control_component._OWNER_ERROR):
            foreign.resolve_snapshot(current.raw)
    else:
        owner, snapshot = (
            (case.store, replace(current.resolved))
            if kind == "resolved-copy"
            else (foreign, current.resolved)
        )
        # Catch outside: any original observation updates must roll back on denial.
        with (
            pytest.raises(daily.DailyRuntimeRiskConflict, match=control_component._OWNER_ERROR),
            _write_transaction(case.engine) as connection,
            _account_interval(current, connection),
        ):
            owner.recheck_snapshot_in_transaction(connection, snapshot, fence=case.r1.fence)
    assert control_component._rows(case, tables) == before
    _inert_rows(current)


@pytest.mark.parametrize("kind", ["foreign-engine", "logical-only", "wrong-fence"])
def test_original_b_transaction_and_fence_guards_remain_required(current, kind):
    _prepare(current)
    case = current.case
    tables = (*daily.CONTROL_TABLES, phase2_account_leases, phase2_account_lease_heads)
    before = control_component._rows(case, tables)
    if kind == "foreign-engine":
        engine = create_database_engine(
            f"sqlite+pysqlite:///{current.tmp_path / 'foreign-context.sqlite'}"
        )
        connections = []

        def connected(connection):
            connections.append(connection)

        current.extra_engines.append((engine, connections, connected))
        sa.event.listen(engine, "engine_connect", connected)
        with (
            pytest.raises(
                daily.DailyRuntimeRiskConflict,
                match=r"^same-engine active caller transaction required$",
            ),
            _write_transaction(engine) as connection,
            _account_interval(current, connection),
        ):
            assert connection.engine is engine and connection.engine is not case.engine
            assert connection.connection.driver_connection.in_transaction is True
            case.store.recheck_snapshot_in_transaction(
                connection, current.resolved, fence=case.r1.fence
            )
        assert connections and all(connection.closed for connection in connections)
    elif kind == "logical-only":
        with (
            pytest.raises(
                daily.DailyRuntimeRiskConflict, match=r"^SQLite requires an explicit outer BEGIN$"
            ),
            case.engine.connect() as connection,
            connection.begin(),
            _account_interval(current, connection),
        ):
            assert connection.in_transaction()
            assert connection.connection.driver_connection.in_transaction is False
            case.store.recheck_snapshot_in_transaction(
                connection, current.resolved, fence=case.r1.fence
            )
    else:
        different = replace(case.r1.fence, owner_id="different-declared-owner")
        with (
            pytest.raises(
                daily.DailyRuntimeRiskConflict, match=r"^prepared snapshot/fence differs$"
            ),
            _write_transaction(case.engine) as connection,
            _account_interval(current, connection),
        ):
            assert connection.connection.driver_connection.in_transaction is True
            case.store.recheck_snapshot_in_transaction(
                connection, current.resolved, fence=different
            )
    assert control_component._rows(case, tables) == before
    _inert_rows(current)


def test_real_halt_writer_during_original_file_read_leaves_prepared_head_stale(current):
    case = current.case
    entered, release, completed = (threading.Event() for _ in range(3))
    case.barriers.append(release)
    current.read_barrier = (entered, release, completed)
    changed = []

    def write():
        try:
            if not entered.wait(5):
                raise AssertionError("original file read did not enter")
            assert not release.is_set()
            case.clock.advance(timedelta(milliseconds=100))
            changed.append(
                case.controls.apply(
                    control_component._command(
                        case, OperationalControlCommandKind.HALT, "halt-during-evidence-read"
                    )
                )
            )
            # Commit is complete before read resumes; retain the actual new
            # allowed inventory for both preparation and inherited cleanup.
            case.expected_control = control_component._rows(case, daily.CONTROL_TABLES)
        except BaseException as error:
            case.worker_errors.append(error)
        finally:
            completed.set()
            release.set()

    writer = threading.Thread(target=write, name="current-context-halt-writer")
    case.threads.append(writer)
    writer.start()
    try:
        prepared, _ = _prepare(current)
    finally:
        release.set()
        writer.join(10)
        current.read_barrier = None
        if not writer.is_alive() and changed:
            case.expected_control = control_component._rows(case, daily.CONTROL_TABLES)
    assert not writer.is_alive() and case.worker_errors == []
    assert entered.is_set() and completed.is_set()
    assert len(changed) == 1
    assert changed[0].sequence_number == current.resolved.control.sequence_number + 1
    assert changed[0].effective_state is OperationalControlState.HALTED
    assert len(changed[0].blocking_events) == len(current.resolved.control.blocking_events) + 1
    assert prepared.record.statement.control_transition_id == current.resolved.control.transition_id
    assert case.controls.load(current.raw.account_id) == changed[0]
    before = control_component._rows(case, (phase2_account_leases, phase2_account_lease_heads))
    with (
        pytest.raises(daily.DailyRuntimeRiskConflict, match="captured row inventory changed"),
        _write_transaction(case.engine) as connection,
        _account_interval(current, connection),
    ):
        case.store.recheck_snapshot_in_transaction(
            connection, current.resolved, fence=case.r1.fence
        )
    assert (
        control_component._rows(case, (phase2_account_leases, phase2_account_lease_heads)) == before
    )
    assert current.raw.receipt.semantic_sha256 == current.retained_receipt_sha256
    _inert_rows(current)


def test_original_b_can_return_same_fence_r2_while_retained_r1_agreement_is_false(current):
    prepared, _ = _prepare(current)
    case = current.case
    retained = current.raw.receipt
    case.clock.advance(timedelta(milliseconds=500))
    r2 = case.coordinator.renew(case.r1.fence)
    case.expected_lease = r2
    case.expected_leases.append(r2)
    assert r2.revision_number == 2 and r2.previous_lease_sha256 == case.r1.semantic_sha256
    assert r2.fence == case.r1.fence and r2.policy_sha256 == case.r1.policy_sha256
    assert r2.expires_at - r2.heartbeat_at == case.policy.lease_ttl == timedelta(seconds=60)
    with _write_transaction(case.engine) as connection, _account_interval(current, connection):
        receipt = case.store.recheck_snapshot_in_transaction(
            connection, current.resolved, fence=case.r1.fence
        )
    control_component._receipt(receipt, r2, not_before=retained.validated_at)
    assert receipt.fence == retained.fence == case.r1.fence
    assert receipt.lease_sha256 == r2.semantic_sha256 != retained.lease_sha256
    assert (receipt.fence, receipt.lease_sha256, receipt.policy_sha256, receipt.valid_until) != (
        case.r1.fence,
        case.r1.semantic_sha256,
        case.r1.policy_sha256,
        case.r1.expires_at,
    )
    assert (
        retained.fence,
        retained.lease_sha256,
        retained.policy_sha256,
        retained.valid_until,
    ) == (case.r1.fence, case.r1.semantic_sha256, case.r1.policy_sha256, case.r1.expires_at)
    assert current.raw.receipt is retained
    assert retained.semantic_sha256 == current.retained_receipt_sha256
    assert retained.validated_at <= receipt.validated_at < case.r1.expires_at
    assert prepared.record.statement.control_state is OperationalControlState.HALTED
    _inert_rows(current)
