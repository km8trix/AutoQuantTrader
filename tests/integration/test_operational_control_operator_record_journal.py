"""Fresh generic journal reuse, never authenticated or current control authority."""

import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import Connection
from sqlalchemy.engine.default import DefaultDialect

from packages.application import personal_codec as codec
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
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
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict, SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import metadata

AT = datetime(2026, 10, 28, 14, 0, tzinfo=UTC)


def _record(number=1):
    blocker = OperationalControlBlockingEvent(
        scope_id="synthetic-operator-account",
        sequence_number=1,
        command_id="declared-control-command",
        command_sha256="b" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=AT - timedelta(seconds=2),
    )
    statement = OperationalControlOperatorStatement(
        scope_id=blocker.scope_id,
        control_transition_id="declared-control-head",
        control_transition_sha256="a" * 64,
        control_sequence_number=1,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="declared-control-epoch",
        blocking_event=blocker,
        actor=OperationalControlActor(
            actor_id="declared-operator",
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256="c" * 64,
            authenticated_at=AT,
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=blocker.event_id,
            event_sha256=blocker.semantic_sha256,
            resolution_code="reviewed",
            resolution_evidence_sha256="d" * 64,
            resolved_at=AT - timedelta(seconds=1),
        ),
        authentication_checked_at=AT,
        attested_at=AT,
        idempotency_key=f"statement-key-{number:04}",
    )
    return OperationalControlOperatorStatementRecord(
        statement=statement,
        evidence=ObjectRef("d" * 64, 17),
        session_expires_at=AT + timedelta(hours=8),
    )


def _projection(value):
    if is_dataclass(value) and not isinstance(value, type):
        return type(value), tuple(
            (field.name, _projection(getattr(value, field.name))) for field in fields(value)
        )
    if type(value) is tuple:
        return tuple(_projection(item) for item in value)
    return value


def _payload(record):
    return codec.encode_record(copy_operational_control_operator_statement_record(record))


def _request(case, record=None, *, head=None):
    record = _record() if record is None else record
    payload = _payload(record)
    return JournalAppend(
        record.record_id,
        record.semantic_sha256,
        empty_head(case.key) if head is None else head,
        (JournalRecord(record.record_id, OPERATOR_STATEMENT_RECORD_SCHEMA, payload),),
    )


def _new_engine(case):
    engine = create_database_engine(case.url)
    case.engines.append(engine)

    def connected(connection):
        case.connections.append(connection)

    sa.event.listen(engine, "engine_connect", connected)
    case.listeners.append((engine, connected))
    return engine


def _journal(engine):
    return SqlDurableJournal(
        engine,
        codec=codec,
        record_types={OPERATOR_STATEMENT_RECORD_SCHEMA: OperationalControlOperatorStatementRecord},
    )


@pytest.fixture
def case(tmp_path):
    case = SimpleNamespace(
        url=f"sqlite+pysqlite:///{tmp_path}/operator-record-journal.sqlite",
        engines=[],
        connections=[],
        listeners=[],
        disposal_attempted=set(),
    )
    primary = None
    try:
        case.engine = _new_engine(case)
        metadata.create_all(case.engine, tables=JOURNAL_TABLES)
        case.store = _journal(case.engine)
        case.key = JournalKey(
            "coordinator",
            "operator-statement-test-stream",
            "synthetic-operator-account",
            "fixture",
            "synthetic",
            "e" * 64,
        )
        yield case
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for engine, callback in reversed(case.listeners):
            try:
                sa.event.remove(engine, "engine_connect", callback)
            except BaseException as error:
                errors.append(error)
        for engine in reversed(case.engines):
            if id(engine) in case.disposal_attempted:
                continue
            try:
                assert all(c.closed for c in case.connections if c.engine is engine)
                case.disposal_attempted.add(id(engine))
                engine.dispose()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup(
                "journal fixture cleanup failed", ([] if primary is None else [primary]) + errors
            )


def _contents(engine):
    with engine.connect() as connection:
        return tuple(
            tuple(connection.execute(sa.select(table).order_by(*table.primary_key.columns)))
            for table in JOURNAL_TABLES
        )


def _commit_prepared(case, prepared):
    with case.engine.connect() as connection:
        assert connection.engine is case.engine
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        assert connection.in_transaction() is True
        assert type(connection.connection.driver_connection) is sqlite3.Connection
        assert connection.connection.driver_connection.in_transaction is True
        receipt = case.store.append_in_transaction(connection, prepared)
        connection.commit()
        assert connection.connection.driver_connection.in_transaction is False
    assert connection.closed
    return receipt


def _reopen(case):
    original = case.engine
    assert all(c.closed for c in case.connections if c.engine is original)
    case.disposal_attempted.add(id(original))
    original.dispose()
    case.engine = _new_engine(case)
    assert case.engine is not original
    case.store = _journal(case.engine)


def _assert_payload(payload, expected):
    assert type(payload) is bytes and payload == _payload(expected)
    decoded = codec.decode_record(payload, OperationalControlOperatorStatementRecord)
    assert type(decoded) is OperationalControlOperatorStatementRecord
    assert type(decoded.statement) is OperationalControlOperatorStatement
    assert type(decoded.evidence) is ObjectRef
    assert _projection(decoded) == _projection(expected)
    assert decoded.record_id == expected.record_id
    assert decoded.semantic_sha256 == expected.semantic_sha256
    assert _payload(decoded) == payload


def test_prepared_record_commits_exact_payload_receipt_head_and_page(case):
    record = _record()
    request = _request(case, record)
    prepared = case.store.prepare_append(case.key, request)
    receipt = _commit_prepared(case, prepared)
    assert receipt == prepared.receipt
    assert receipt.command_id == record.record_id == request.records[0].record_id
    assert receipt.command_sha256 == record.semantic_sha256
    assert receipt.record_hashes == (sha256(request.records[0].payload).hexdigest(),)
    assert receipt.append_sha256 == request.semantic_sha256
    assert receipt.previous_head == empty_head(case.key)
    assert receipt.committed_head.sequence == 1
    streams, appends, entries = _contents(case.engine)
    assert len(streams) == len(appends) == len(entries) == 1
    entry = entries[0]._mapping
    assert entry["schema_id"] == OPERATOR_STATEMENT_RECORD_SCHEMA
    assert entry["record_id"] == entry["command_id"] == record.record_id
    assert entry["payload"] == request.records[0].payload
    assert entry["payload_sha256"] == receipt.record_hashes[0]
    assert entry["entry_sha256"] == receipt.committed_head.entry_sha256
    assert streams[0]._mapping["last_entry_sha256"] == receipt.committed_head.entry_sha256
    assert appends[0]._mapping["receipt_sha256"] == receipt.semantic_sha256
    assert case.store.read_receipt(case.key, record.record_id) == receipt
    assert case.store.read_head(case.key) == receipt.committed_head
    page = case.store.read_page(case.key, through_head=receipt.committed_head, limit=1)
    assert page.previous_head == receipt.previous_head and page.next_head == receipt.committed_head
    assert page.complete and len(page.entries) == 1
    assert page.entries[0].head == receipt.committed_head
    assert (
        record.evidence.object_sha256
        == record.statement.resolution_claim.resolution_evidence_sha256
    )
    assert (
        len(
            {
                record.evidence.object_sha256,
                record.statement.semantic_sha256,
                record.semantic_sha256,
                receipt.record_hashes[0],
                receipt.append_sha256,
                receipt.committed_head.entry_sha256,
            }
        )
        == 6
    )
    _assert_payload(page.entries[0].record.payload, record)


@pytest.mark.parametrize("kind", ["allowlist", "noncanonical", "wrong-root"])
def test_invalid_typed_preparation_never_starts_a_transaction(case, kind):
    request = _request(case)
    original = request.records[0]
    if kind == "allowlist":
        bad = replace(original, schema_id="unallowlisted-record/1")
    elif kind == "noncanonical":
        bad = replace(original, payload=original.payload + b" ")
    else:
        bad = replace(original, payload=codec.encode_record("different-root"))
    request = replace(request, records=(bad,))
    before = _contents(case.engine)
    begins = []

    def begun(connection):
        begins.append(connection)

    sa.event.listen(case.engine, "begin", begun)
    try:
        with pytest.raises(JournalConflict):
            case.store.prepare_append(case.key, request)
    finally:
        sa.event.remove(case.engine, "begin", begun)
    assert begins == []
    assert _contents(case.engine) == before


def test_original_prepared_retry_keeps_historical_receipt_after_head_advances(case):
    first = _request(case)
    prepared = case.store.prepare_append(case.key, first)
    first_receipt = _commit_prepared(case, prepared)
    second_record = _record(2)
    assert second_record.record_id != first.command_id
    second_receipt = case.store.append(
        case.key, _request(case, second_record, head=first_receipt.committed_head)
    )
    before = _contents(case.engine)
    retried = _commit_prepared(case, prepared)
    assert retried == first_receipt
    assert case.store.read_receipt(case.key, first.command_id) == first_receipt
    assert case.store.read_head(case.key) == second_receipt.committed_head
    assert _contents(case.engine) == before
    page = case.store.read_page(case.key, through_head=first_receipt.committed_head, limit=1)
    _assert_payload(page.entries[0].record.payload, _record())


@pytest.mark.parametrize("kind", ["content", "command-hash", "expected-head"])
def test_same_command_conflict_preserves_every_journal_row(case, kind):
    original = _request(case)
    receipt = case.store.append(case.key, original)
    if kind == "content":
        changed_record = replace(_record(), session_expires_at=AT + timedelta(hours=7))
        assert changed_record.record_id == original.command_id
        changed = replace(
            original, records=(replace(original.records[0], payload=_payload(changed_record)),)
        )
    elif kind == "command-hash":
        changed = replace(original, command_sha256="f" * 64)
    else:
        changed = replace(original, expected_head=receipt.committed_head)
    before = _contents(case.engine)
    with pytest.raises(JournalConflict, match="COMMAND_CONFLICT"):
        case.store.append(case.key, changed)
    assert _contents(case.engine) == before


def test_new_command_with_stale_expected_head_cannot_append(case):
    case.store.append(case.key, _request(case))
    stale = _request(case, _record(2))
    before = _contents(case.engine)
    with pytest.raises(JournalConflict, match="HEAD_CONFLICT"):
        case.store.append(case.key, stale)
    assert _contents(case.engine) == before
    assert case.store.read_receipt(case.key, stale.command_id) is None


@pytest.mark.parametrize("kind", ["outer-id", "command-hash", "account-scope"])
def test_generic_journal_does_not_supply_domain_id_hash_or_account_binding(case, kind):
    record = _record()
    key, request = case.key, _request(case, record)
    if kind == "outer-id":
        request = replace(
            request,
            command_id="unrelated-outer-id",
            records=(replace(request.records[0], record_id="unrelated-outer-id"),),
        )
        assert request.command_id != record.record_id
    elif kind == "command-hash":
        request = replace(request, command_sha256="f" * 64)
        assert request.command_sha256 != record.semantic_sha256
    else:
        key = replace(key, account_scope="foreign-syntactic-account")
        request = replace(request, expected_head=empty_head(key))
        assert key.account_scope != record.statement.scope_id
    receipt = case.store.append(key, request)
    assert receipt.command_id == request.command_id
    assert receipt.command_sha256 == request.command_sha256
    page = case.store.read_page(key, through_head=receipt.committed_head, limit=1)
    assert page.entries[0].record.record_id == request.records[0].record_id
    _assert_payload(page.entries[0].record.payload, record)
    assert tuple(map(len, _contents(case.engine))) == (1, 1, 1)


def test_fresh_engine_reads_original_receipt_and_complete_fixed_prefix(case):
    first, second = _record(), _record(2)
    first_receipt = case.store.append(case.key, _request(case, first))
    second_receipt = case.store.append(
        case.key, _request(case, second, head=first_receipt.committed_head)
    )
    before = _contents(case.engine)
    through = second_receipt.committed_head
    _reopen(case)
    assert case.store.read_receipt(case.key, first.record_id) == first_receipt
    assert case.store.read_head(case.key) == through
    cursor, seen = empty_head(case.key), []
    for index, expected in enumerate((first, second)):
        page = case.store.read_page(case.key, through_head=through, after_head=cursor, limit=1)
        assert page.previous_head == cursor and page.through_head == through
        assert (
            len(page.entries) == 1 and page.entries[0].previous_entry_sha256 == cursor.entry_sha256
        )
        assert page.entries[0].sequence == index + 1
        _assert_payload(page.entries[0].record.payload, expected)
        seen.append(page.entries[0].record.record_id)
        cursor = page.next_head
        assert page.complete is (index == 1)
    assert cursor == through and seen == [first.record_id, second.record_id]
    assert _contents(case.engine) == before


@contextmanager
def _interrupt_after_actual_commit(case, marker):
    monitor, tool = sys.monitoring, 3
    assert case.engine.dialect.do_commit.__func__ is DefaultDialect.do_commit
    commit_code = DefaultDialect.do_commit.__code__
    append_code = SqlDurableJournal.append.__code__
    inside_code = SqlDurableJournal.append_in_transaction.__code__
    codes = (inside_code, commit_code, append_code)
    probe = SimpleNamespace(
        appends=0,
        commits=0,
        connection=None,
        proxy=None,
        driver=None,
        receipt=None,
        interrupted=False,
        source_files=(commit_code.co_filename, Connection._commit_impl.__code__.co_filename),
    )
    owned, registered, enabled = False, [], []
    primary = None

    def observe(code, returning, returned=None):
        frame = sys._getframe(2)
        try:
            assert frame.f_code is code
            if code is inside_code and not returning and frame.f_locals["self"] is case.store:
                assert probe.appends == 0
                probe.appends += 1
                connection = frame.f_locals["connection"]
                assert type(connection) is Connection and connection.engine is case.engine
                assert connection.in_transaction() is True and not connection.closed
                probe.connection = connection
                probe.proxy = connection.connection
                probe.driver = probe.proxy.driver_connection
                assert type(probe.driver) is sqlite3.Connection
                assert probe.driver.in_transaction is True
            elif code is commit_code and frame.f_locals["self"] is case.engine.dialect:
                assert probe.appends == 1
                assert frame.f_locals["dbapi_connection"] is probe.proxy
                assert probe.proxy.driver_connection is probe.driver
                if returning:
                    assert returned is None and probe.driver.in_transaction is False
                    probe.commits += 1
                else:
                    assert probe.commits == 0 and probe.driver.in_transaction is True
            elif code is append_code and returning and frame.f_locals["self"] is case.store:
                assert probe.appends == probe.commits == 1
                assert type(returned) is JournalReceipt and probe.connection.closed
                assert probe.proxy.dbapi_connection is None
                assert probe.proxy.driver_connection is None
                assert probe.driver.in_transaction is False
                probe.receipt = returned
                probe.interrupted = True
                raise marker
        finally:
            del frame

    def on_start(code, _offset):
        observe(code, False)

    def on_return(code, _offset, returned):
        observe(code, True, returned)

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-journal-commit-delivery")
        owned = True
        for event, callback in (
            (monitor.events.PY_START, on_start),
            (monitor.events.PY_RETURN, on_return),
        ):
            assert monitor.register_callback(tool, event, callback) is None
            registered.append((event, callback))
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            monitor.set_local_events(tool, code, monitor.events.PY_START | monitor.events.PY_RETURN)
            enabled.append(code)
        yield probe
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        if owned:
            try:
                assert monitor.get_tool(tool) == "aqt-journal-commit-delivery"
                assert monitor.get_events(tool) == 0
            except BaseException as error:
                errors.append(error)
            for code in reversed(enabled):
                try:
                    monitor.set_local_events(tool, code, 0)
                    assert monitor.get_local_events(tool, code) == 0
                except BaseException as error:
                    errors.append(error)
            for event, callback in reversed(registered):
                try:
                    assert monitor.register_callback(tool, event, None) is callback
                except BaseException as error:
                    errors.append(error)
            try:
                monitor.free_tool_id(tool)
                assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup(
                "journal observation cleanup failed",
                ([] if primary is None else [primary]) + errors,
            )


def test_actual_commit_can_retain_record_without_delivering_append_return(case):
    record = _record()
    request = _request(case, record)
    marker = RuntimeError("synthetic post-commit delivery interruption")
    missing = object()
    delivered = missing
    with (
        pytest.raises(RuntimeError) as caught,
        _interrupt_after_actual_commit(case, marker) as probe,
    ):
        delivered = case.store.append(case.key, request)
    assert caught.value is marker and delivered is missing
    assert probe.interrupted and probe.appends == probe.commits == 1
    assert probe.connection.closed and probe.driver.in_transaction is False
    assert probe.receipt.command_id == record.record_id
    assert tuple(map(len, _contents(case.engine))) == (1, 1, 1)
    receipt = probe.receipt
    _reopen(case)
    assert case.store.read_receipt(case.key, record.record_id) == receipt
    page = case.store.read_page(case.key, through_head=receipt.committed_head, limit=1)
    assert page.complete
    _assert_payload(page.entries[0].record.payload, record)
    assert tuple(map(len, _contents(case.engine))) == (1, 1, 1)
